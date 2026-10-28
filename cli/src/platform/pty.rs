//! The PTY the shell server spawns into. Everywhere but Android this is
//! portable-pty. Android goes without: the crate pulls in `serial`/`termios`,
//! which do not build there, and a phone never serves shells
//! (docs/android-app-spec.md). The Android stand-in has the same surface and
//! refuses at `openpty`, so the caller's existing failure path sends the reason.

#[cfg(not(target_os = "android"))]
pub use portable_pty::{native_pty_system, CommandBuilder, PtySize};

#[cfg(target_os = "android")]
pub use android::{native_pty_system, CommandBuilder, PtySize};

#[cfg(target_os = "android")]
mod android {
    use std::ffi::OsStr;

    #[derive(Clone, Copy, Debug)]
    pub struct PtySize {
        pub rows: u16,
        pub cols: u16,
        pub pixel_width: u16,
        pub pixel_height: u16,
    }

    pub struct CommandBuilder;

    impl CommandBuilder {
        pub fn new<S: AsRef<OsStr>>(_program: S) -> Self {
            CommandBuilder
        }
        pub fn arg<S: AsRef<OsStr>>(&mut self, _arg: S) {}
        pub fn env<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, _key: K, _val: V) {}
        pub fn cwd<D: AsRef<OsStr>>(&mut self, _dir: D) {}
    }

    /// Uninhabited: `openpty` never succeeds, so no master, slave or child exists.
    pub enum Never {}

    impl Never {
        pub fn spawn_command(&self, _cmd: CommandBuilder) -> anyhow::Result<Never> {
            match *self {}
        }
        pub fn try_clone_reader(&self) -> anyhow::Result<Box<dyn std::io::Read + Send>> {
            match *self {}
        }
        pub fn take_writer(&self) -> anyhow::Result<Box<dyn std::io::Write + Send>> {
            match *self {}
        }
        pub fn resize(&self, _size: PtySize) -> anyhow::Result<()> {
            match *self {}
        }
        pub fn kill(&mut self) -> std::io::Result<()> {
            match *self {}
        }
        pub fn wait(&mut self) -> std::io::Result<()> {
            match *self {}
        }
    }

    pub struct PtyPair {
        pub master: Never,
        pub slave: Never,
    }

    pub struct NoPty;

    impl NoPty {
        pub fn openpty(&self, _size: PtySize) -> anyhow::Result<PtyPair> {
            anyhow::bail!("this device runs Android and does not serve shells")
        }
    }

    pub fn native_pty_system() -> NoPty {
        NoPty
    }
}

/// What the shell server drives once a session's pseudoterminal is up: a
/// window resize and the end of the shell. Platform-neutral; the backend that
/// made it is chosen in [`spawn_shell`], so the session loop has no platform
/// branches of its own.
pub struct ShellControl {
    resize: Box<dyn FnMut(u16, u16) + Send>,
    end: Box<dyn FnMut() + Send>,
}

impl ShellControl {
    /// Resize the pseudoterminal (zero is clamped to one).
    pub fn resize(&mut self, cols: u16, rows: u16) {
        (self.resize)(cols.max(1), rows.max(1))
    }

    /// Kill the shell and reap it.
    pub fn end(&mut self) {
        (self.end)()
    }
}

/// A shell's pseudoterminal: output reader, input writer, and its control.
pub type ShellPty = (Box<dyn std::io::Read + Send>, Box<dyn std::io::Write + Send>, ShellControl);

/// Start `argv` on a pseudoterminal of `cols` x `rows` with `term`, or say why
/// not (the text goes to the peer as the l2-close reason).
///
/// Everywhere but Windows, portable-pty opens the pseudoterminal and spawns the
/// shell directly. On Windows `portable-pty 0.8.1` hardcodes CreateProcessW, so
/// it cannot start a shell under a different token; the daemon goes through
/// `crate::win_pty` instead, which launches this executable as a hidden
/// pseudoconsole relay under the desired token. There is deliberately NO
/// portable-pty fallback on Windows: falling back would silently serve the
/// daemon's own (possibly elevated) token.
pub fn spawn_shell(argv: &[String], cols: u16, rows: u16, term: &str) -> Result<ShellPty, String> {
    #[cfg(not(windows))]
    {
        let size = PtySize { rows: rows.max(1), cols: cols.max(1), pixel_width: 0, pixel_height: 0 };
        let pair = native_pty_system().openpty(size).map_err(|e| format!("pty: {e}"))?;
        let mut cmd = CommandBuilder::new(&argv[0]);
        for a in &argv[1..] {
            cmd.arg(a);
        }
        // Like sshd: the account's default environment and identity, never
        // the daemon's process environment; the login shell's profile files
        // build the rest. (`runuser -l` for --shell-user resets it again for
        // the target account.)
        let daemon: Vec<(String, String)> = std::env::vars_os()
            .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
            .collect();
        let user = crate::platform::Paths::exec_user_context(None)?;
        let env = filament_peerloop::shell::user_env::child_env(
            false,
            &user,
            false,
            crate::platform::account_environment(),
            &daemon,
            &[],
        )?;
        cmd.env_clear();
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.env("TERM", term);
        // Advertise 24-bit color. opentui-based TUIs (e.g. opencode) downgrade to a
        // 256-color palette when COLORTERM is unset; the web-shell xterm.js renders
        // truecolor fine, so set this to get full-color output (verified: opencode
        // emits 38;2;R;G;B with this set, 38;5;N without).
        cmd.env("COLORTERM", "truecolor");
        cmd.cwd(crate::platform::Paths::home_dir());
        let mut child = pair.slave.spawn_command(cmd).map_err(|e| format!("spawn: {e}"))?;
        drop(pair.slave); // close our copy so the shell owns the only slave
        let master = pair.master;
        let reader = master.try_clone_reader().map_err(|e| format!("pty: {e}"))?;
        let writer = master.take_writer().map_err(|e| format!("pty: {e}"))?;
        let control = ShellControl {
            resize: Box::new(move |cols, rows| {
                let _ = master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 });
            }),
            end: Box::new(move || {
                let _ = child.kill();
                let _ = child.wait();
            }),
        };
        Ok((reader, writer, control))
    }
    #[cfg(windows)]
    {
        // The relay owns the shell's environment: it fixes TERM/COLORTERM and
        // the cwd itself, so the requested terminal name is not forwarded here.
        let _ = term;
        // Refuse the session exactly like the portable-pty spawn failure; never
        // fall back to the daemon's own token.
        let pty = crate::platform::win_pty::spawn(argv, cols, rows).map_err(|e| format!("spawn: {e}"))?;
        // The resize pipe is a *synchronous* Windows pipe: `write_all` blocks once
        // its buffer fills (a relay that stopped draining it, or a wedged shell),
        // and the caller resizes from its session task, which also drives the
        // output, input and revocation paths. A dedicated writer thread keeps the
        // loop non-blocking and preserves resize order. The pipe closes when the
        // control is dropped, which is how the relay sees its parent go.
        let (tx, rx) = std::sync::mpsc::channel::<(u16, u16)>();
        let mut pipe = pty.resize;
        std::thread::spawn(move || {
            while let Ok((c, r)) = rx.recv() {
                if write_pty_resize(&mut pipe, c, r).is_err() {
                    // The relay's read end closed: the session is ending.
                    break;
                }
            }
        });
        let mut child = pty.child;
        let control = ShellControl {
            // Unbounded send, so this never blocks the session loop. A failed
            // send means the relay's resize pipe is gone; the reader thread hits
            // EOF and ends the session, so the lost resize needs no handling.
            resize: Box::new(move |cols, rows| {
                let _ = tx.send((cols, rows));
            }),
            end: Box::new(move || {
                let _ = child.kill();
                let _ = child.wait();
            }),
        };
        Ok((pty.reader, pty.writer, control))
    }
}

/// Hand a window size to the Windows pseudoconsole relay.
///
/// The relay's resize pipe carries exactly four bytes: `cols` then `rows`, each
/// little-endian `u16` (`win_pty::relay` decodes the same layout). A pipe write
/// is a `WriteFile` on a synchronous handle, so this can BLOCK once the pipe
/// buffer is full; it runs on the session's dedicated resize thread. `Err`
/// means the relay's read end is gone (session teardown), not something to
/// retry.
#[cfg(windows)]
fn write_pty_resize(resize: &mut std::fs::File, cols: u16, rows: u16) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut buf = [0u8; 4];
    buf[..2].copy_from_slice(&cols.max(1).to_le_bytes());
    buf[2..].copy_from_slice(&rows.max(1).to_le_bytes());
    resize.write_all(&buf)
}
