//! Interactive flows driven through a real terminal.
//!
//! Everything else we test drives tunlion as a program: arguments in, exit
//! code and bytes out. That cannot see the class of bug the owner keeps hitting
//! on Windows, because those bugs are about what the *terminal* is left looking
//! like after tunlion has finished with it. #197 is the current example: after
//! Ctrl-C out of the picker, PowerShell draws its prompt twice.
//!
//! So these tests open a pty, start a real shell inside it, run tunlion from
//! that shell the way a person does, and then read what the terminal shows.
//! portable-pty gives the same interface on ConPTY, so the identical test runs
//! on Windows in CI, which is the only reason this layer is worth building.
//!
//! IGNORED BY DEFAULT. The Ctrl-C cell is expected to FAIL on Windows right now
//! - that is the open bug - and a red board while we are still diagnosing tells
//! nobody anything new. Run them deliberately:
//!
//!   cargo test --test pty_flows -- --ignored --nocapture
//!
//! Read the two cells together. They differ in one thing only: Esc leaves the
//! picker through the same teardown as Ctrl-C but sends no console signal. So
//! if BOTH double, the fault is our teardown and the fix belongs in the raw
//! mode guard. If ONLY Ctrl-C doubles, Windows is delivering the interrupt
//! twice, once as a key event to the raw-mode reader and once as a CTRL_C_EVENT
//! to the console group, and the fix belongs in signal handling. Those are
//! different repairs, and running one cell alone cannot tell them apart.

// portable-pty is already a normal dependency (src/l2.rs uses it for `shell`),
// and integration tests link the crate's [dependencies] as well as its
// dev-dependencies, so there is nothing to add. Adding it as a dev-dependency
// at a different 0.x range is what produced E0464 "multiple candidates for
// rlib dependency portable_pty": 0.8 and 0.9 are separate compatibility
// ranges, so cargo built both and rustc refused to choose.
//
// No `PtySystem` import: openpty is called on a trait object, whose methods
// resolve through the vtable, so importing the trait would be an unused import
// and the warning ratchet would reject it. src/l2.rs does the same.
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Deliberately not a shell metacharacter and not a word tunlion prints. The
/// whole test is a count of this string, so anything that could appear for
/// another reason would silently change the answer.
const MARK: &str = "PMARKQ7";

struct Term {
    writer: Box<dyn Write + Send>,
    out: Arc<Mutex<Vec<u8>>>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Term {
    /// A shell in a pty, with a prompt we can count.
    fn shell(cfg_dir: &std::path::Path) -> Term {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize { rows: 30, cols: 100, pixel_width: 0, pixel_height: 0 })
            .expect("openpty");

        let mut cmd = if cfg!(windows) {
            let mut c = CommandBuilder::new("pwsh");
            c.arg("-NoLogo");
            c.arg("-NoProfile");
            c.arg("-NoExit");
            // -NoExit keeps the session interactive after -Command runs, which
            // is what makes the prompt observable at all.
            c.arg("-Command");
            c.arg(format!("function prompt {{ '{MARK}> ' }}"));
            c
        } else {
            let mut c = CommandBuilder::new("bash");
            c.arg("--norc");
            c.arg("--noprofile");
            c.arg("-i");
            c.env("PS1", format!("{MARK}> "));
            c
        };
        // Never touch a real store.
        cmd.env("TUNLION_CONFIG_DIR", cfg_dir);
        cmd.env("HOME", cfg_dir);
        cmd.env("USERPROFILE", cfg_dir);
        cmd.cwd(cfg_dir);

        let child = pair.slave.spawn_command(cmd).expect("spawn shell");
        drop(pair.slave);

        let out = Arc::new(Mutex::new(Vec::new()));
        let mut reader = pair.master.try_clone_reader().expect("reader");
        let sink = Arc::clone(&out);
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });

        let writer = pair.master.take_writer().expect("writer");
        Term { writer, out, child, _master: pair.master }
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().unwrap()).to_string()
    }

    fn send(&mut self, s: &str) {
        self.writer.write_all(s.as_bytes()).expect("write");
        self.writer.flush().expect("flush");
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        self._master
            .resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .expect("resize");
    }

    /// Wait for `needle`, returning false on timeout rather than panicking, so
    /// a caller can report what it did see. A bare unwrap here would turn "the
    /// picker never drew" into a stack trace that hides the actual screen.
    /// Wait for `needle` to appear in output produced AFTER byte offset `from`.
    /// Searching the whole buffer would match the prompt that was already on
    /// screen before the keypress and return instantly.
    fn wait_for_from(&self, from: usize, needle: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let t = self.text();
            if t.len() > from && t[from.min(t.len())..].contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn wait_for(&self, needle: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Let output settle: return once nothing new has arrived for `quiet_ms`.
    /// A fixed sleep would either race the second prompt or hide it.
    fn settle(&self, quiet_ms: u64, max_secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(max_secs);
        let mut last = self.out.lock().unwrap().len();
        let mut stable = Instant::now();
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(50));
            let now = self.out.lock().unwrap().len();
            if now != last {
                last = now;
                stable = Instant::now();
            } else if stable.elapsed() >= Duration::from_millis(quiet_ms) {
                return;
            }
        }
    }
}

impl Drop for Term {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Drive `tunlion add --for` to the picker, then leave it with `leave_key`.
/// Returns how many prompts were drawn after the picker was dismissed.
fn prompts_after_leaving_picker(leave_key: &str, label: &str) -> usize {
    let dir = std::env::temp_dir().join(format!("filament-pty-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("cfg dir");
    let mut t = Term::shell(&dir);

    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());

    let exe = env!("CARGO_BIN_EXE_tunlion");
    // The call operator is required on PowerShell. A line that STARTS with a
    // quoted string is parsed as a string expression, not a command, so
    //   "C:\...\tunlion.exe" add --for
    // fails with "Unexpected token 'add' in expression or statement" and the
    // program never runs. That, not any product bug, is why the Windows cell
    // reported "picker never drew" three runs in a row.
    let invoke = if cfg!(windows) { format!("& \"{exe}\" add --for\r") } else { format!("\"{exe}\" add --for\r") };
    t.send(&invoke);

    // The picker's own heading. If this never appears the test has not reached
    // the thing it claims to measure, and saying so beats asserting on a
    // prompt count from a screen that never happened.
    if !t.wait_for("WHO IS JOINING", 30) {
        panic!("picker never drew for {label}; screen was:\n{}", t.text());
    }

    // Everything from here is what the interrupt produced.
    let before = t.text().len();
    t.send(leave_key);

    // Wait for the shell to come back BEFORE settling. The first version
    // settled on 1.2s of quiet and then counted, which returned ~1.25s after
    // the keypress with nothing on screen yet: tunlion had not finished
    // exiting, so every platform reported 0 prompts and the two cells could not
    // be told apart. A quiet terminal is not the same as a finished one.
    let returned = t.wait_for_from(before, &format!("{MARK}> "), 25);
    // Only now let a possible SECOND prompt land.
    t.settle(1500, 15);

    let full = t.text();
    let after = &full[before.min(full.len())..];
    let count = after.matches(&format!("{MARK}> ")).count();
    if !returned {
        eprintln!("--- {label}: shell never returned within 25s; screen tail:\n{}\n---", tail(after));
    }
    eprintln!("--- {label}: {count} prompt(s) after leaving the picker ---\n{}\n---", tail(after));
    count
}

/// Bounded, escape-stripped view. A raw pty dump is mostly control bytes and
/// gets truncated by the log viewer, which is how the first Windows failure
/// told me the picker never drew without letting me see what did.
fn tail(s: &str) -> String {
    let stripped: String = {
        let mut out = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                // Drop CSI/OSC sequences up to a plausible terminator.
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() || n == '\u{7}' {
                        break;
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    };
    let mut start = stripped.len().saturating_sub(2500);
    while !stripped.is_char_boundary(start) { start += 1; }
    stripped[start..].to_string()
}

#[test]
#[ignore = "#197 discriminator; expected to fail on Windows today. Run with --ignored"]
fn ctrl_c_out_of_the_picker_draws_one_prompt() {
    let n = prompts_after_leaving_picker("\u{3}", "ctrl-c");
    assert_eq!(n, 1, "Ctrl-C out of the picker drew {n} prompts, expected 1 (#197)");
}

#[test]
#[ignore = "#197 discriminator control. Run with --ignored"]
fn esc_out_of_the_picker_draws_one_prompt() {
    let n = prompts_after_leaving_picker("\u{1b}", "esc");
    assert_eq!(n, 1, "Esc out of the picker drew {n} prompts, expected 1");
}

// ---------------------------------------------------------------------------
// Eval item 1: a fresh device holding a pairing code, driven the way a person
// drives it. NOT ignored (unlike the #197 cells above): these are regressions,
// and they run wherever a bash pty exists. They stop at the first line that
// proves which ceremony was chosen, before any network, then Ctrl-C out.
// ---------------------------------------------------------------------------

/// A shell in a pty over a fresh config dir, with tunlion's path.
#[cfg(unix)]
fn fresh_term(label: &str) -> (Term, String) {
    let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("cfg dir");
    let t = Term::shell(&dir);
    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());
    (t, env!("CARGO_BIN_EXE_tunlion").to_string())
}

/// The guided menu's accept entry takes a CODE and runs the join path. It
/// used to be "Pair with a code I was given", which ran `add` and minted a
/// second code from the typed one ("press enter to create comic-otter-NNNN").
#[cfg(unix)]
#[test]
fn the_menu_accept_entry_takes_a_code_and_joins_with_it() {
    let (mut t, exe) = fresh_term("menu-accept");
    // The menu is the BARE form (no arguments at all), so no --server here:
    // the test stops at the line that names the ceremony, before any network.
    let before = t.text().len();
    t.send(&format!("\"{exe}\"\r"));
    assert!(
        t.wait_for_from(before, "I have a code or an invitation", 30),
        "the fresh-device menu has no single accept entry; screen:\n{}",
        tail(&t.text())
    );
    let screen = t.text();
    assert!(!screen.contains("Pair with a code I was given"), "the old offering entry is back:\n{}", tail(&screen));
    // Entry 0 offers add/temporary access; the accept entry is next.
    t.send("\u{1b}[B");
    t.settle(300, 3);
    t.send("\r");
    assert!(
        t.wait_for_from(before, "code or invitation:", 20),
        "the accept entry did not open the accept prompt; screen:\n{}",
        tail(&t.text())
    );
    let typed_at = t.text().len();
    t.send("comic-otter-1950\r");
    assert!(
        t.wait_for_from(typed_at, "tunlion join comic-otter-1950", 20),
        "a code typed at the accept prompt was not accepted as a code; screen:\n{}",
        tail(&t.text())
    );
    let after = t.text()[typed_at..].to_string();
    assert!(!after.contains("unknown format"), "answered a code as a bad invitation:\n{}", tail(&after));
    assert!(!after.contains("press enter to create"), "minted a new code:\n{}", tail(&after));
    t.send("\u{3}");
}

/// The OFFERING entry (`tunlion add`) given a code someone read out: it
/// recognizes the code and accepts it, instead of minting
/// `<their words>-<our number>` that nobody is waiting on.
#[cfg(unix)]
#[test]
fn a_code_typed_into_add_is_accepted_not_reminted() {
    let (mut t, exe) = fresh_term("add-code");
    let before = t.text().len();
    t.send(&format!("\"{exe}\" --server http://127.0.0.1:9 add\r"));
    assert!(t.wait_for_from(before, "Connect a remembered device", 30), "add menu missing:\n{}", tail(&t.text()));
    t.send("\r");
    assert!(
        t.wait_for_from(before, "press Enter for a generated pair", 30),
        "add never opened its word entry; screen:\n{}",
        tail(&t.text())
    );
    t.send("comic otter 1950");
    assert!(
        t.wait_for_from(before, "code you were given", 10),
        "the entry did not recognize a received code; screen:\n{}",
        tail(&t.text())
    );
    let at = t.text().len();
    t.send("\r");
    assert!(
        t.wait_for_from(at, "accepting the code you were given:  tunlion join comic-otter-1950", 20),
        "Enter on a received code did not accept it; screen:\n{}",
        tail(&t.text())
    );
    assert!(!t.text()[at..].contains("comic-otter-1950-"), "a second code was minted:\n{}", tail(&t.text()));
    t.send("\u{3}");
}

// Temporary drafting runs before pairing, key generation, and any network use.
#[cfg(unix)]
#[test]
fn temporary_access_cancel_and_failed_connect_do_not_remember_device() {
    for activate in [false, true] {
        let label = if activate { "access-unavailable" } else { "access-cancel" };
        let (mut t, exe) = fresh_term(label);
        t.send(&format!("\"{exe}\" --server http://127.0.0.1:9 add\r"));
        assert!(t.wait_for("Temporary access", 20), "{}", tail(&t.text()));
        t.send("\x1b[B\r");
        assert!(t.wait_for("Folders (0)", 20), "{}", tail(&t.text()));
        // Add the current temporary folder, read-only by default.
        t.send("\r");
        assert!(t.wait_for("Add folder", 20), "{}", tail(&t.text()));
        t.send("\r");
        assert!(t.wait_for("folder path:", 20), "{}", tail(&t.text()));
        t.send(".\r");
        assert!(t.wait_for("read-only", 20), "{}", tail(&t.text()));
        let at = t.text().len();
        t.send("\x1b[A\r"); // Continue (wrap to last row).
        assert!(t.wait_for_from(at, "Folders (1)", 20), "{}", tail(&t.text()));
        t.send("\x1b[B\r"); // Services.
        assert!(t.wait_for("Add port", 20), "{}", tail(&t.text()));
        t.send("\x1b[B\r");
        assert!(t.wait_for("port or IP:port:", 20), "{}", tail(&t.text()));
        t.send("3000\r");
        assert!(t.wait_for("Choose services (1)", 20), "{}", tail(&t.text()));
        // Exercise the actual inline multi-select, not just menu navigation.
        t.send("\r");
        assert!(t.wait_for("Space toggle", 20), "{}", tail(&t.text()));
        let at = t.text().len();
        t.send("  \r"); // Toggle off, on, then continue.
        assert!(t.wait_for_from(at, "Choose services (1)", 20), "{}", tail(&t.text()));
        let at = t.text().len();
        t.send("\x1b[A\r"); // Services Continue.
        assert!(t.wait_for_from(at, "Services (1)", 20), "{}", tail(&t.text()));
        t.send("\x1b[B\x1b[B\r"); // One final scope review.
        assert!(t.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&t.text()));
        assert!(t.text().contains("until ended"));
        assert!(t.text().contains("Service 127.0.0.1:3000"));
        let at = t.text().len();
        t.send(if activate { "\r" } else { "\x1b[A\r" });
        assert!(t.wait_for_from(at, &format!("{MARK}> "), 20), "{}", tail(&t.text()));
        let screen = t.text();
        assert!(!screen.contains("pair-create"));
        assert!(!screen.contains("Code:"));
        assert!(!screen.contains("\x1b[?1049h"), "temporary access used alternate screen");
        assert!(!screen.contains("mutually remembered"));
        assert!(!screen.contains("Temporary access active"));
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for entry in ["identity.ed25519", "identity/device-cert.json", "devices.json", "capabilities.json"] {
            assert!(!dir.join(entry).exists(), "drafting wrote {entry}");
        }
        if !activate { assert!(!dir.join("overlay.ed25519").exists(), "cancel created transport keys"); }
    }
}

// ---------------------------------------------------------------------------
// RC lab item 1: `tunlion receive <code>` in a real terminal printed
// "done (1 file)." and then never exited. Its terminal reader was tokio's
// stdin, an uncancellable read on the runtime's blocking pool, and dropping
// the runtime waits for every blocking task; the signal tasks had died with
// the runtime, so Ctrl-C and SIGTERM were caught and ignored. Only Enter (or
// SIGKILL) ended it. Non-TTY runs never showed it: their stdin hits EOF.
//
// These run against a real signaling backend (../backend, the one every gate
// uses). CI installs its Python deps for this job; elsewhere, without them,
// the cells say so and skip, but under CI a missing backend is a failure, so
// a green run cannot mean "never ran".
// ---------------------------------------------------------------------------

/// A local signaling backend, killed on drop.
#[cfg(unix)]
struct Backend {
    child: std::process::Child,
    url: String,
}

#[cfg(unix)]
impl Drop for Backend {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn health_ok(port: u16) -> bool {
    use std::net::TcpStream;
    let Ok(mut s) = TcpStream::connect(("127.0.0.1", port)) else { return false };
    let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
    if s.write_all(b"GET /api/health HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n").is_err() {
        return false;
    }
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).contains(" 200 ")
}

/// Start ../backend on a free port, or None (skipped) when it cannot run
/// here. Under CI (the `CI` variable GitHub sets) it must run.
#[cfg(unix)]
fn backend() -> Option<Backend> {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .expect("free port");
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../backend");
    let python = std::env::var("TUNLION_TEST_VENV").unwrap_or_else(|_| "python3".to_string());
    let log_path = std::env::temp_dir().join(format!("tunlion-pty-backend-{}-{port}.log", std::process::id()));
    let log = std::fs::File::create(&log_path).expect("backend diagnostic log");
    eprintln!("PTY backend log: {}", log_path.display());
    let spawned = std::process::Command::new(&python)
        .arg("app.py")
        .current_dir(&dir)
        .env("PORT", port.to_string())
        .env("FIL_ASYNC_MODE", "eventlet")
        .env("FIL_SELF_MONKEYPATCH", "1")
        .env("FIL_CLAIM_LIMIT", "1000000")
        .env("FIL_PING_TIMEOUT", "120")
        .env("FIL_PING_INTERVAL", "25")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone().expect("backend stdout log")))
        .stderr(std::process::Stdio::from(log))
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            assert!(std::env::var_os("CI").is_none(), "CI must run the backend for the receive pty cells: {e}");
            eprintln!("SKIP: cannot start the backend ({e})");
            return None;
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if health_ok(port) {
            return Some(Backend { child, url: format!("http://127.0.0.1:{port}") });
        }
        if let Ok(Some(st)) = child.try_wait() {
            let diagnostic = std::fs::read_to_string(&log_path).unwrap_or_default();
            assert!(std::env::var_os("CI").is_none(), "the backend exited ({st}); CI must run it for the receive pty cells\n{}\n{diagnostic}", log_path.display());
            eprintln!("SKIP: the backend exited ({st}); install its Python deps to run these cells");
            return None;
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("the backend never answered /api/health on port {port}");
}

/// Two real CLI processes, existing signaling/PAKE/DataChannel and scoped Mux.
/// No installed daemon, production account, permanent contact or mock invitation.
#[cfg(unix)]
#[test]
fn temporary_service_pairing_uses_real_transport_and_end_closes_the_socket() {
    let Some(backend) = backend() else { return; };
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let target = listener.local_addr().unwrap();
    listener.set_nonblocking(true).unwrap();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let thread_stop = stop.clone();
    let echo = thread::spawn(move || {
        while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                    let mut data = [0; 1024];
                    while !thread_stop.load(std::sync::atomic::Ordering::Acquire) {
                        match socket.read(&mut data) {
                            Ok(0) => break,
                            Ok(n) => { if socket.write_all(&data[..n]).is_err() { break; } }
                            Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
                            Err(_) => break,
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(20)),
                Err(_) => break,
            }
        }
    });
    struct StopEcho(Arc<std::sync::atomic::AtomicBool>);
    impl Drop for StopEcho { fn drop(&mut self) { self.0.store(true, std::sync::atomic::Ordering::Release); } }
    let echo_guard = StopEcho(stop);
    let (mut host, exe) = fresh_term("temporary-live-host");
    let (mut recipient, _) = fresh_term("temporary-live-recipient");
    host.send(&format!("\"{exe}\" --server {} add\r", backend.url));
    assert!(host.wait_for("Temporary access", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Folders (0)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Add port", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("port or IP:port:", 20), "{}", tail(&host.text()));
    host.send(&format!("{target}\r"));
    assert!(host.wait_for("Choose services (1)", 20), "{}", tail(&host.text()));
    let at = host.text().len();
    host.send("\x1b[A\r");
    assert!(host.wait_for_from(at, "Services (1)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r");
    assert!(host.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("on the other device:", 60), "host never created a real code:\n{}", tail(&host.text()));
    let screen = host.text();
    let code = screen.split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .find(|token| token.rsplit_once('-').is_some_and(|(words, number)|
            !words.is_empty() && words.contains('-') && number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit())))
        .expect("real host pairing code").to_ascii_lowercase();
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "authenticated scope review missing:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(!recipient.text().contains("Local service"), "listener activated before acceptance");
    recipient.send("\r");
    assert!(recipient.wait_for("Local service service-0 at ", 60), "real endpoint missing:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    let text = recipient.text();
    let address = text.split("Local service service-0 at ").nth(1).unwrap().split_whitespace().next().unwrap();
    let mut socket = std::net::TcpStream::connect(address).unwrap_or_else(|error| panic!(
        "temporary endpoint connect failed: {error}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())));
    socket.set_read_timeout(Some(Duration::from_secs(15))).unwrap();
    socket.write_all(b"temporary-service-real-payload").unwrap_or_else(|error| panic!(
        "temporary endpoint write failed: {error}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())));
    let mut reply = [0; 30];
    let expected = b"temporary-service-real-payload";
    socket.read_exact(&mut reply[..expected.len()]).unwrap_or_else(|error| panic!(
        "temporary service echo failed before End: {error}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())));
    assert_eq!(&reply[..expected.len()], expected);
    let at = host.text().len();
    host.send("\x1b[A\r"); // End access, without a shell/daemon/config operation.
    assert!(recipient.wait_for("Temporary access ended", 30), "end did not reach recipient:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let mut byte = [0];
    match socket.read(&mut byte) {
        Ok(0) => {},
        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe) => {},
        outcome => panic!("revocation did not close the active service socket: {outcome:?}"),
    }
    assert!(host.wait_for_from(at, &format!("{MARK}> "), 30), "host did not exit:\n{}", tail(&host.text()));
    assert!(host.text()[at..].contains("peer acknowledged"), "host exited without an End receipt:\n{}", tail(&host.text()));
    for label in ["temporary-live-host", "temporary-live-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        assert!(dir.join("overlay.ed25519").exists(), "confirmed mutation did not persist the internal device key");
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json", "capabilities.json", "up.pid"] {
            assert!(!dir.join(file).exists(), "temporary access wrote standing state: {file}");
        }
    }
    eprintln!("REAL TEMPORARY E2E PASS: PAKE -> authenticated scope -> explicit accept -> TCP echo -> End -> socket closed; no permanent records");
    drop(echo_guard);
    echo.join().unwrap();
}

#[cfg(unix)]
struct EchoService {
    address: std::net::SocketAddr,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

#[cfg(unix)]
impl EchoService {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            let mut streams = Vec::new();
            while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let stop = worker_stop.clone();
                        streams.push(thread::spawn(move || {
                            socket.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
                            let mut data = [0;1024];
                            while !stop.load(std::sync::atomic::Ordering::Acquire) {
                                match socket.read(&mut data) {
                                    Ok(0) => break,
                                    Ok(n) => if socket.write_all(&data[..n]).is_err() { break; },
                                    Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {},
                                    Err(_) => break,
                                }
                            }
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(10)),
                    Err(_) => break,
                }
            }
            for stream in streams { stream.join().unwrap(); }
        });
        Self { address, stop, worker: Some(worker) }
    }
}

#[cfg(unix)]
impl Drop for EchoService {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() { let _ = worker.join(); }
    }
}

#[cfg(unix)]
fn offer_temporary_services(host: &mut Term, exe: &str, server: &str, targets: &[std::net::SocketAddr]) -> String {
    host.send(&format!("\"{exe}\" --server {server} add\r"));
    assert!(host.wait_for("Temporary access", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Folders (0)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Add port", 20), "{}", tail(&host.text()));
    for (index, target) in targets.iter().enumerate() {
        let at = host.text().len();
        host.send("\x1b[B\r");
        assert!(host.wait_for_from(at, "port or IP:port:", 20), "{}", tail(&host.text()));
        host.send(&format!("{target}\r"));
        assert!(host.wait_for_from(at, &format!("Choose services ({})", index + 1), 20), "{}", tail(&host.text()));
    }
    let at = host.text().len();
    host.send("\x1b[A\r");
    assert!(host.wait_for_from(at, &format!("Services ({})", targets.len()), 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r");
    assert!(host.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("on the other device:", 60), "{}", tail(&host.text()));
    host.text().split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .find(|token| token.rsplit_once('-').is_some_and(|(words, number)|
            !words.is_empty() && words.contains('-') && number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit())))
        .expect("actual PAKE code").to_ascii_lowercase()
}

#[cfg(unix)]
fn offer_temporary_shell(host: &mut Term, exe: &str, server: &str) -> String {
    host.send(&format!("\"{exe}\" --server {server} add\r"));
    assert!(host.wait_for("Temporary access", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r"); // Choose temporary access.
    assert!(host.wait_for("Folders (0)", 20), "{}", tail(&host.text()));
    // Main rows: Folders, Services, Review, Shell, Cancel.
    host.send("\x1b[B\x1b[B\x1b[B\r");
    assert!(host.wait_for("Shell: on (interactive terminal)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r"); // Review / create code.
    assert!(host.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&host.text()));
    assert!(host.text().contains("interactive terminal on this machine's existing account"), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("on the other device:", 60), "host never created a real code:\n{}", tail(&host.text()));
    host.text().split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .find(|token| token.rsplit_once('-').is_some_and(|(words, number)|
            !words.is_empty() && words.contains('-') && number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit())))
        .expect("actual PAKE code").to_ascii_lowercase()
}

#[cfg(unix)]
fn temporary_endpoint(recipient: &Term, resource: &str) -> std::net::SocketAddr {
    recipient.text().split(&format!("Local service {resource} at ")).nth(1)
        .and_then(|rest| rest.split_whitespace().next()).and_then(|text| text.parse().ok())
        .unwrap_or_else(|| panic!("missing activated {resource}:\n{}", tail(&recipient.text())))
}

#[cfg(unix)]
fn assert_echo(socket: &mut std::net::TcpStream, text: &[u8], host: &Term, recipient: &Term) {
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    socket.write_all(text).unwrap_or_else(|error| panic!("service write failed: {error}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())));
    let mut reply = vec![0;text.len()];
    socket.read_exact(&mut reply).unwrap_or_else(|error| panic!("service read failed: {error}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())));
    assert_eq!(reply, text);
}

#[cfg(unix)]
#[test]
fn temporary_service_revisions_remove_only_the_selected_resource_and_require_acceptance_for_additions() {
    let Some(backend) = backend() else { return; };
    let first = EchoService::start();
    let retained = EchoService::start();
    let (mut host, exe) = fresh_term("temporary-revision-host");
    let (mut recipient, _) = fresh_term("temporary-revision-recipient");
    let code = offer_temporary_services(&mut host, &exe, &backend.url, &[first.address, retained.address]);
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(!recipient.text().contains("Local service"));
    recipient.send("\r");
    assert!(recipient.wait_for("Local service service-1 at ", 60), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    let removed_address = temporary_endpoint(&recipient, "service-0");
    let retained_address = temporary_endpoint(&recipient, "service-1");
    let mut removed_socket = std::net::TcpStream::connect(removed_address).unwrap();
    let mut retained_socket = std::net::TcpStream::connect(retained_address).unwrap();
    assert_echo(&mut removed_socket, b"first-port", &host, &recipient);
    assert_echo(&mut retained_socket, b"second-port", &host, &recipient);

    // Remove service-0 through the actual host controls; keep service-1 live.
    let host_at = host.text().len();
    let recipient_at = recipient.text().len();
    host.send("\r");
    assert!(host.wait_for_from(host_at, "CHANGE ACCESS", 20), "{}", tail(&host.text()));
    let at = host.text().len();
    host.send("\r"); // Remove first service row.
    assert!(host.wait_for_from(at, "Review change", 20), "{}", tail(&host.text()));
    host.send("\x1b[A\x1b[A\r"); // Review, immediately before Cancel.
    assert!(host.wait_for_from(at, "APPLY CHANGE?", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(recipient.wait_for_from(recipient_at, "revision 2", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.wait_for_from(recipient_at, "ACCEPT THIS SCOPE?", 20), "{}", tail(&recipient.text()));
    assert_echo(&mut retained_socket, b"same-live-stream-during-narrowing-review", &host, &recipient);
    removed_socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut byte = [0];
    match removed_socket.read(&mut byte) {
        Ok(0) => {},
        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::BrokenPipe) => {},
        result => panic!("removed stream remained usable: {result:?}\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text())),
    }
    assert!(std::net::TcpStream::connect(removed_address).is_err(), "removed resource still has a local listener");
    let at = recipient.text().len();
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "Temporary access active", 30), "{}", tail(&recipient.text()));
    assert_eq!(temporary_endpoint(&recipient, "service-1"), retained_address, "unchanged resource moved endpoint");
    assert_echo(&mut retained_socket, b"same-live-stream-after-narrowing", &host, &recipient);

    // Add the first port back as a NEW resource revision, without a new code.
    let at = host.text().len();
    host.send("\r");
    assert!(host.wait_for_from(at, "CHANGE ACCESS", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r"); // Add port after retained row and Add folder.
    assert!(host.wait_for_from(at, "port or IP:port:", 20), "{}", tail(&host.text()));
    host.send(&format!("{}\r", first.address));
    let recipient_at = recipient.text().len();
    let at = host.text().len();
    host.send("\x1b[A\x1b[A\r");
    assert!(host.wait_for_from(at, "APPLY CHANGE?", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(recipient.wait_for_from(recipient_at, "revision 3", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.wait_for_from(recipient_at, "ACCEPT THIS SCOPE?", 20), "{}", tail(&recipient.text()));
    assert!(!recipient.text()[recipient_at..].contains("Local service service-2"), "addition activated without recipient acceptance");
    recipient.send("\r");
    assert!(recipient.wait_for_from(recipient_at, "Local service service-2 at ", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let mut added_socket = std::net::TcpStream::connect(temporary_endpoint(&recipient, "service-2")).unwrap();
    assert_echo(&mut added_socket, b"accepted-added-resource", &host, &recipient);
    let mut new_retained_socket = std::net::TcpStream::connect(retained_address).unwrap();
    assert_echo(&mut new_retained_socket, b"retained-resource-new-revision", &host, &recipient);
    // Close the test's service sockets before End. The host still revokes
    // first, but no aborted stream is mid-write, so the bounded receipt has a
    // quiet control path to travel on. (A receipt that cannot arrive is a
    // defined timeout outcome; this cell asserts the normal one.)
    drop(added_socket);
    drop(new_retained_socket);
    drop(retained_socket);
    // The control thread redraws revision 3 asynchronously; End must be typed
    // into the RUNNING ACCESS picker, not the APPLY CHANGE picker that the
    // previous revision just left.
    assert!(host.wait_for("revision 3", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    host.settle(500, 5);
    let at = recipient.text().len();
    host.send("\x1b[A\r");
    assert!(recipient.wait_for_from(at, "Temporary access ended", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("peer acknowledged", 15), "host did not receive the teardown receipt:\n{}", tail(&host.text()));
    for label in ["temporary-revision-host", "temporary-revision-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json"] { assert!(!dir.join(file).exists(), "temporary revision wrote {file}"); }
    }
    eprintln!("REAL MULTI-SERVICE REVISION PASS: both ports used; removal closes one while retained stream lives; addition waits for signed review acceptance; End received");
}

#[cfg(unix)]
#[test]
fn declining_a_temporary_service_offer_never_activates_a_listener_or_contact() {
    let Some(backend) = backend() else { return; };
    let service = EchoService::start();
    let (mut host, exe) = fresh_term("temporary-decline-host");
    let (mut recipient, _) = fresh_term("temporary-decline-recipient");
    let code = offer_temporary_services(&mut host, &exe, &backend.url, &[service.address]);
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let at = recipient.text().len();
    recipient.send("\x1b[B\r");
    assert!(recipient.wait_for_from(at, &format!("{MARK}> "), 30), "{}", tail(&recipient.text()));
    assert!(host.wait_for("Temporary access declined", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(!recipient.text().contains("Local service"));
    assert!(!recipient.text().contains("Temporary access active"));
    for label in ["temporary-decline-host", "temporary-decline-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json"] { assert!(!dir.join(file).exists(), "decline wrote {file}"); }
    }
}

#[cfg(unix)]
#[test]
fn ending_while_a_revised_scope_is_being_reviewed_cancels_the_review_and_closes_endpoints() {
    let Some(backend) = backend() else { return; };
    let original = EchoService::start();
    let addition = EchoService::start();
    let (mut host, exe) = fresh_term("temporary-review-end-host");
    let (mut recipient, _) = fresh_term("temporary-review-end-recipient");
    let code = offer_temporary_services(&mut host, &exe, &backend.url, &[original.address]);
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for("Local service service-0 at ", 30), "{}", tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    let address = temporary_endpoint(&recipient, "service-0");
    let mut socket = std::net::TcpStream::connect(address).unwrap();
    assert_echo(&mut socket, b"before-revision", &host, &recipient);
    let at = host.text().len();
    host.send("\r");
    assert!(host.wait_for_from(at, "CHANGE ACCESS", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r");
    assert!(host.wait_for_from(at, "port or IP:port:", 20), "{}", tail(&host.text()));
    host.send(&format!("{}\r", addition.address));
    let at = host.text().len();
    host.send("\x1b[A\x1b[A\r");
    assert!(host.wait_for_from(at, "APPLY CHANGE?", 20), "{}", tail(&host.text()));
    let recipient_at = recipient.text().len();
    host.send("\r");
    assert!(recipient.wait_for_from(recipient_at, "revision 2", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.wait_for_from(recipient_at, "ACCEPT THIS SCOPE?", 20), "{}", tail(&recipient.text()));
    let end_at = host.text().len();
    host.send("\x1b[A\r"); // End wins while the recipient has not accepted.
    assert!(recipient.wait_for_from(recipient_at, "Temporary access ended", 15), "End blocked behind the review:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for_from(end_at, "peer acknowledged", 15), "{}", tail(&host.text()));
    assert!(!recipient.text()[recipient_at..].contains("Local service service-1"), "unaccepted resource activated");
    assert!(std::net::TcpStream::connect(address).is_err(), "End left the old listener open");
    assert!(recipient.wait_for_from(recipient_at, &format!("{MARK}> "), 15), "recipient review thread survived End:\n{}", tail(&recipient.text()));
    let after_end = recipient.text().len();
    recipient.send("\r"); // Late Enter belongs to the shell, never the cancelled review.
    recipient.settle(200, 2);
    assert!(!recipient.text()[after_end..].contains("Temporary access active"));
    for label in ["temporary-review-end-host", "temporary-review-end-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json"] {
            assert!(!dir.join(file).exists(), "review/End race wrote standing state: {file}");
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn temporary_folder_browse_binary_read_and_download_use_the_scoped_real_endpoint_without_fake_mounts() {
    use sha2::Digest;
    let Some(backend) = backend() else { return; };
    let (mut host, exe) = fresh_term("temporary-folder-host");
    let (mut recipient, _) = fresh_term("temporary-folder-recipient");
    let host_dir = std::env::temp_dir().join(format!("tunlion-pty-temporary-folder-host-{}", std::process::id()));
    let share = host_dir.join("share");
    std::fs::create_dir(&share).unwrap();
    let binary = (0..65549).map(|i| (i % 251) as u8).collect::<Vec<_>>();
    std::fs::write(share.join("binary.bin"), &binary).unwrap();
    std::fs::write(share.join("empty.bin"), []).unwrap();
    std::fs::write(host_dir.join("outside.bin"), b"outside-secret-payload").unwrap();
    std::os::unix::fs::symlink(host_dir.join("outside.bin"), share.join("evil-link")).unwrap();

    host.send(&format!("\"{exe}\" --server {} add\r", backend.url));
    assert!(host.wait_for("Temporary access", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Folders (0)", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("Add folder", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("folder path:", 20), "{}", tail(&host.text()));
    host.send("share\r");
    assert!(host.wait_for("read-only", 20), "{}", tail(&host.text()));
    let at = host.text().len();
    host.send("\x1b[A\r");
    assert!(host.wait_for_from(at, "Folders (1)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r");
    assert!(host.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&host.text()));
    host.send("\r");
    assert!(host.wait_for("on the other device:", 60), "{}", tail(&host.text()));
    let screen = host.text();
    let code = screen.split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .find(|token| token.rsplit_once('-').is_some_and(|(words, number)| words.contains('-') && number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit())))
        .unwrap().to_ascii_lowercase();
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(!recipient.text().contains("Folder endpoint ready"));
    recipient.send("\r");
    assert!(recipient.wait_for("FOLDERS · endpoint checked on use", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let at = recipient.text().len();
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "FOLDER ACTION", 20), "{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "relative path", 20), "{}", tail(&recipient.text()));
    recipient.send(".\r");
    assert!(recipient.wait_for_from(at, "Folder entries (3)", 30), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.text()[at..].contains("binary.bin"));
    assert!(recipient.text()[at..].contains("empty.bin"));
    assert!(recipient.text()[at..].contains("Folder endpoint ready"));
    assert!(recipient.text()[at..].contains("folder-0"));

    for (name, count, total, expected) in [
        ("binary.bin", 4096, binary.len(), hex::encode(sha2::Sha256::digest(&binary[..4096]))),
        ("empty.bin", 0, 0, hex::encode(sha2::Sha256::digest([]))),
    ] {
        let at = recipient.text().len();
        recipient.send("\r");
        assert!(recipient.wait_for_from(at, "FOLDER ACTION", 20), "{}", tail(&recipient.text()));
        recipient.send("\x1b[B\r");
        assert!(recipient.wait_for_from(at, "relative path", 20), "{}", tail(&recipient.text()));
        recipient.send(&format!("{name}\r"));
        assert!(recipient.wait_for_from(at, &format!("Read preview: {count} of {total} bytes"), 30),
            "byte-preserving read failed:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
        assert!(recipient.text()[at..].contains(&expected), "preview hash missing: {}", tail(&recipient.text()));
    }
    let recipient_dir = std::env::temp_dir().join(format!("tunlion-pty-temporary-folder-recipient-{}", std::process::id()));
    assert!(!recipient_dir.join("binary.bin").exists(), "preview fabricated a downloaded local file");
    std::fs::write(recipient_dir.join("binary.bin"), b"preserve-existing-file").unwrap();
    for (remote, saved, expected) in [("binary.bin", "binary.bin-1", binary.as_slice()), ("empty.bin", "empty.bin", &[][..])] {
        let at = recipient.text().len();
        recipient.send("\r");
        assert!(recipient.wait_for_from(at, "FOLDER ACTION", 20), "{}", tail(&recipient.text()));
        recipient.send("\x1b[B\x1b[B\r");
        assert!(recipient.wait_for_from(at, "relative path", 20), "{}", tail(&recipient.text()));
        recipient.send(&format!("{remote}\r"));
        assert!(recipient.wait_for_from(at, "existing local destination directory", 20), "{}", tail(&recipient.text()));
        recipient.send(".\r");
        assert!(recipient.wait_for_from(at, "local filename", 20), "{}", tail(&recipient.text()));
        assert!(!recipient.text()[at..].contains("Download complete"), "download reported complete before destination confirmation");
        recipient.send("\r");
        let published = recipient_dir.join(saved);
        assert!(recipient.wait_for_from(at, &format!("Download complete: {}", published.display()), 30),
            "owned publication failed:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
        assert!(recipient.text()[at..].contains(&format!("{} bytes", expected.len())), "download byte count missing: {}", tail(&recipient.text()));
        assert_eq!(std::fs::read(&published).unwrap(), expected, "download lost or changed binary bytes");
        assert!(recipient.text()[at..].contains(&hex::encode(sha2::Sha256::digest(expected))));
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&published).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(std::fs::read(recipient_dir.join("binary.bin")).unwrap(), b"preserve-existing-file", "download overwrote an existing destination");
    assert!(!std::fs::read_dir(&recipient_dir).unwrap().any(|entry| entry.unwrap().file_name().to_string_lossy().starts_with(".tunlion-download-")), "successful download left private staging");
    let at = recipient.text().len();
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "FOLDER ACTION", 20), "{}", tail(&recipient.text()));
    recipient.send("\x1b[B\r");
    assert!(recipient.wait_for_from(at, "relative path", 20), "{}", tail(&recipient.text()));
    recipient.send("evil-link\r");
    assert!(recipient.wait_for_from(at, "Folder unavailable:", 30), "{}", tail(&recipient.text()));
    assert!(!recipient.text().contains("outside-secret-payload"));
    assert!(!recipient.text().contains("Mounted at"));
    assert!(!recipient.text().contains("mount ready"));
    let at = recipient.text().len();
    assert!(host.wait_for("RUNNING ACCESS", 20));
    host.settle(200, 5);
    host.send("\x1b[A\r");
    assert!(recipient.wait_for_from(at, "Temporary access ended", 15), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("peer acknowledged", 15), "{}", tail(&host.text()));
    for dir in [&host_dir, &recipient_dir] {
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json"] { assert!(!dir.join(file).exists(), "folder access wrote standing state: {file}"); }
    }
    eprintln!("REAL FOLDER DOWNLOAD PASS: authenticated RO browse, binary/empty reads and exact private no-clobber publication, symlink escape refused, acknowledged End; no mount claim");
}

/// A fresh scratch dir for one cell.
#[cfg(unix)]
#[test]
fn temporary_shell_pty_io_resize_and_end_teardown_are_scoped_and_never_use_standing_shell() {
    let Some(backend) = backend() else { return; };
    let (mut host, exe) = fresh_term("temporary-shell-host");
    let (mut recipient, _) = fresh_term("temporary-shell-recipient");
    let code = offer_temporary_shell(&mut host, &exe, &backend.url);
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "HOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.text().contains("interactive terminal on this machine's existing account"), "shell scope was not offered:\n{}", tail(&recipient.text()));
    assert!(!recipient.text().contains("Local service"), "a service listener appeared for a shell-only scope");
    recipient.send("\r");
    assert!(recipient.wait_for("SHELL · shared terminal", 60), "recipient shell menu missing:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let at = recipient.text().len();
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "Shared terminal · host accepted revision", 30), "terminal did not activate:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    let at = recipient.text().len();
    recipient.send("echo REMOTE_PTY_$((6*7))\r");
    assert!(recipient.wait_for_from(at, "REMOTE_PTY_42", 30), "remote shell did not execute:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    recipient.resize(120, 40);
    thread::sleep(Duration::from_millis(600));
    let at = recipient.text().len();
    recipient.send("stty size\r");
    assert!(recipient.wait_for_from(at, "40 120", 20), "resize did not reach the remote pty:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    host.send("\x1b[A\r"); // End access.
    assert!(recipient.wait_for("Shared terminal ended", 30), "end did not tear down the terminal:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("peer acknowledged", 20), "host did not receive the End receipt:\n{}", tail(&host.text()));
    for label in ["temporary-shell-host", "temporary-shell-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        assert!(dir.join("overlay.ed25519").exists(), "confirmed temporary mutation did not persist the internal key");
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json", "capabilities.json", "up.pid"] {
            assert!(!dir.join(file).exists(), "temporary shell wrote standing state: {file}");
        }
    }
    eprintln!("REAL TEMPORARY SHELL PASS: PAKE -> accepted shell scope -> remote PTY I/O -> resize -> End teardown; no standing records");
}

#[cfg(unix)]
#[test]
fn removing_shell_from_the_live_scope_ends_the_remote_pty_without_a_standing_session() {
    let Some(backend) = backend() else { return; };
    let (mut host, exe) = fresh_term("temporary-shell-remove-host");
    let (mut recipient, _) = fresh_term("temporary-shell-remove-recipient");
    // A service remains in the revised scope: an empty scope is invalid, and
    // this also proves removal does not disturb an unrelated resource.
    host.send(&format!("\"{exe}\" --server {} add\r", backend.url));
    assert!(host.wait_for("Temporary access", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("Folders (0)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\x1b[B\r"); // Shell on.
    assert!(host.wait_for("Shell: on (interactive terminal)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\r"); // Services.
    assert!(host.wait_for("Add port", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\r");
    assert!(host.wait_for("port or IP:port:", 20), "{}", tail(&host.text()));
    host.send("3000\r");
    assert!(host.wait_for("Choose services (1)", 20), "{}", tail(&host.text()));
    host.send("\x1b[A\r"); // Continue.
    assert!(host.wait_for("Services (1)", 20), "{}", tail(&host.text()));
    host.send("\x1b[B\x1b[B\r"); // Review.
    assert!(host.wait_for("SHARE THIS SCOPE?", 20), "{}", tail(&host.text()));
    assert!(host.text().contains("interactive terminal on this machine's existing account"));
    host.send("\r");
    assert!(host.wait_for("on the other device:", 60), "{}", tail(&host.text()));
    let code = host.text().split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'))
        .find(|token| token.rsplit_once('-').is_some_and(|(words, number)|
            !words.is_empty() && words.contains('-') && number.len() == 4 && number.bytes().all(|b| b.is_ascii_digit())))
        .expect("actual PAKE code").to_ascii_lowercase();
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for("SHELL · shared terminal", 60), "{}", tail(&recipient.text()));
    assert!(recipient.wait_for("Local service service-0 at ", 60), "{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for("Shared terminal · host accepted revision", 30), "{}", tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    let at = host.text().len();
    host.send("\r"); // Change access.
    assert!(host.wait_for_from(at, "CHANGE ACCESS", 20), "{}", tail(&host.text()));
    let at = host.text().len();
    host.send("\x1b[B\x1b[B\x1b[B\r"); // Service row, Add folder, Add port, then Shell: on.
    assert!(host.wait_for_from(at, "Shell: off", 20), "{}", tail(&host.text()));
    host.send("\x1b[A\x1b[A\r"); // Review change (immediately before Cancel).
    assert!(host.wait_for_from(at, "APPLY CHANGE?", 20), "{}", tail(&host.text()));
    let at = recipient.text().len();
    host.send("\r");
    assert!(recipient.wait_for_from(at, "Shared terminal ended", 30), "removal did not end the PTY:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(recipient.wait_for_from(at, "ACCEPT THIS SCOPE?", 30), "narrowed revision was not reviewed:\n{}", tail(&recipient.text()));
    assert!(!recipient.text()[at..].contains("interactive terminal"), "removed shell still advertised:\n{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for_from(at, "Temporary access active", 30), "{}", tail(&recipient.text()));
    let active_at = at + recipient.text()[at..].find("Temporary access active").expect("activation marker");
    recipient.settle(300, 2);
    assert!(!recipient.text()[active_at..].contains("Open shared terminal"), "shell menu returned after shell removal");
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    host.send("\x1b[A\r");
    assert!(host.wait_for("peer acknowledged", 20), "{}", tail(&host.text()));
    for label in ["temporary-shell-remove-host", "temporary-shell-remove-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json", "exec.groups"] {
            assert!(!dir.join(file).exists(), "removed temporary shell left standing state: {file}");
        }
    }
    eprintln!("REAL TEMPORARY SHELL REMOVAL PASS: live PTY ended by signed revision narrowing; no standing session or contact");
}

#[cfg(unix)]
#[test]
fn temporary_shell_expiry_tears_down_the_pty_and_the_agreement() {
    let Some(backend) = backend() else { return; };
    let (mut host, exe) = fresh_term("temporary-shell-expiry-host");
    let (mut recipient, _) = fresh_term("temporary-shell-expiry-recipient");
    let code = offer_temporary_shell(&mut host, &exe, &backend.url);
    recipient.send(&format!("\"{exe}\" --server {} join {code}\r", backend.url));
    assert!(recipient.wait_for("ACCEPT THIS SCOPE?", 90), "{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for("SHELL · shared terminal", 60), "{}", tail(&recipient.text()));
    recipient.send("\r");
    assert!(recipient.wait_for("Shared terminal · host accepted revision", 30), "{}", tail(&recipient.text()));
    let at = recipient.text().len();
    recipient.send("echo EXPIRY_ALIVE\r");
    assert!(recipient.wait_for_from(at, "EXPIRY_ALIVE", 20), "{}", tail(&recipient.text()));
    assert!(host.wait_for("RUNNING ACCESS", 30), "{}", tail(&host.text()));
    host.send("\x1b[B\r"); // Set expiry.
    assert!(host.wait_for("expiry (30m / 2h; blank = until ended):", 20), "{}", tail(&host.text()));
    let at = recipient.text().len();
    host.send("1s\r");
    assert!(recipient.wait_for_from(at, "Shared terminal ended", 20), "expiry did not end the PTY:\nHOST:\n{}\nRECIPIENT:\n{}", tail(&host.text()), tail(&recipient.text()));
    assert!(host.wait_for("peer acknowledged", 25), "expiry did not close the agreement:\n{}", tail(&host.text()));
    for label in ["temporary-shell-expiry-host", "temporary-shell-expiry-recipient"] {
        let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
        for file in ["devices.json", "identity.ed25519", "identity/device-cert.json", "armed.json", "exec.groups"] {
            assert!(!dir.join(file).exists(), "expired temporary shell left standing state: {file}");
        }
    }
    eprintln!("REAL TEMPORARY SHELL EXPIRY PASS: 1s lifetime closed the remote PTY and the agreement; no standing records");
}

/// A fresh scratch dir for one cell.
#[cfg(unix)]
fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A bare `receive` at a terminal first offers a code entry (Enter there
/// means "listen on the local network") and then a review (Enter waits).
/// The listen that follows is the long wait these cells interrupt.
#[cfg(unix)]
fn start_listening(t: &mut Term, at: usize) {
    assert!(
        t.wait_for_from(at, "enter a code", 30),
        "receive never offered its code entry; screen:\n{}",
        tail(&t.text())
    );
    t.settle(300, 3);
    t.send("\r");
    // Then the review screen: "Press Enter to wait, or type cancel".
    assert!(
        t.wait_for_from(at, "Press Enter to wait", 30),
        "receive never showed its review; screen:\n{}",
        tail(&t.text())
    );
    t.settle(300, 3);
    t.send("\r");
    assert!(
        t.wait_for_from(at, "listening", 30),
        "receive never started listening; screen:\n{}",
        tail(&t.text())
    );
}

/// The `RC=<n>` the shell printed after `want` appeared, within `secs`.
#[cfg(unix)]
fn rc_after(t: &Term, from: usize, secs: u64) -> Option<i32> {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        let text = t.text();
        let tail = &text[from.min(text.len())..];
        // The echoed command line carries "RC=$?"; only digits count.
        for (i, _) in tail.match_indices("RC=") {
            let digits: String = tail[i + 3..].chars().take_while(|c| c.is_ascii_digit()).collect();
            let after = &tail[i + 3 + digits.len()..];
            if !digits.is_empty() && after.starts_with(|c: char| c == '\r' || c == '\n') {
                return digits.parse().ok();
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

#[cfg(unix)]
#[test]
#[cfg_attr(debug_assertions, ignore = "needs a release build: a debug establish is too slow for the exit bound; runs in test.yml's cargo test --release")]
fn receive_by_code_in_a_terminal_exits_right_after_done() {
    let Some(b) = backend() else { return };
    let exe = env!("CARGO_BIN_EXE_tunlion");
    let root = scratch("recv-done");
    let (sdir, rdir, drop) = (root.join("s"), root.join("r"), root.join("drop"));
    for d in [&sdir, &rdir, &drop] {
        std::fs::create_dir_all(d).unwrap();
    }
    let file = root.join("payload.txt");
    std::fs::write(&file, b"rc lab item 1\n").unwrap();
    let send_log = root.join("send.log");
    let mut sender = std::process::Command::new(exe)
        .env("TUNLION_CONFIG_DIR", &sdir)
        .env("TUNLION_NONINTERACTIVE", "1")
        .args(["--server", &b.url, "send"])
        .arg(&file)
        .args(["--word", "gigantic-element"])
        .stdin(std::process::Stdio::null())
        .stdout(std::fs::File::create(&send_log).unwrap())
        .stderr(std::fs::File::create(root.join("send.err")).unwrap())
        .spawn()
        .expect("spawn sender");
    // The code the sender minted.
    let deadline = Instant::now() + Duration::from_secs(30);
    let code = loop {
        let text = (std::fs::read_to_string(&send_log).unwrap_or_default()
            + &std::fs::read_to_string(root.join("send.err")).unwrap_or_default())
            .to_lowercase();
        if let Some(i) = text.find("gigantic-element-") {
            let n: String = text[i + 17..].chars().take_while(|c| c.is_ascii_digit()).collect();
            if n.len() >= 3 {
                break format!("gigantic-element-{n}");
            }
        }
        assert!(Instant::now() < deadline, "the sender minted no code:\n{text}");
        thread::sleep(Duration::from_millis(100));
    };

    let mut t = Term::shell(&rdir);
    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());
    let at = t.text().len();
    t.send(&format!(
        "\"{exe}\" --server {} receive {code} -y --dir \"{}\"; echo RC=$?\r",
        b.url,
        drop.display()
    ));
    assert!(
        t.wait_for_from(at, "done (1 file", 60),
        "the receive never finished; screen:\n{}",
        tail(&t.text())
    );
    let done_at = t.text().len();
    // Before the fix this waited for Enter forever. The bound is generous for
    // a loaded runner and far below "forever".
    let rc = rc_after(&t, at, 8);
    let _ = sender.kill();
    let _ = sender.wait();
    assert_eq!(
        rc,
        Some(0),
        "receive did not exit within 8s of \"done\" (exit {rc:?}); screen after done:\n{}",
        tail(&t.text()[done_at.min(t.text().len())..])
    );
    assert_eq!(std::fs::read(drop.join("payload.txt")).ok().as_deref(), Some(&b"rc lab item 1\n"[..]));
    let _ = std::fs::remove_dir_all(&root);
}

/// Ctrl-C while a receive waits in a terminal (its terminal reader live)
/// ends it at once with 130.
#[cfg(unix)]
#[test]
#[cfg_attr(debug_assertions, ignore = "needs a release build: a debug establish is too slow for the exit bound; runs in test.yml's cargo test --release")]
fn ctrl_c_ends_a_waiting_receive_in_a_terminal_with_130() {
    let Some(b) = backend() else { return };
    let exe = env!("CARGO_BIN_EXE_tunlion");
    let root = scratch("recv-int");
    let drop = root.join("drop");
    std::fs::create_dir_all(&drop).unwrap();
    let mut t = Term::shell(&root);
    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());
    let at = t.text().len();
    t.send(&format!("\"{exe}\" --server {} receive --dir \"{}\"; echo RC=$?\r", b.url, drop.display()));
    start_listening(&mut t, at);
    t.settle(500, 3);
    t.send("\u{3}");
    let rc = rc_after(&t, at, 8);
    assert_eq!(rc, Some(130), "Ctrl-C did not end the waiting receive with 130 within 8s; screen:\n{}", tail(&t.text()));
    let _ = std::fs::remove_dir_all(&root);
}

/// SIGTERM while a receive waits in a terminal ends it at once with 143 (it
/// used to report 130, the SIGINT code, for a SIGTERM).
#[cfg(target_os = "linux")]
#[test]
#[cfg_attr(debug_assertions, ignore = "needs a release build: a debug establish is too slow for the exit bound; runs in test.yml's cargo test --release")]
fn sigterm_ends_a_waiting_receive_in_a_terminal_with_143() {
    let Some(b) = backend() else { return };
    let exe = env!("CARGO_BIN_EXE_tunlion");
    let root = scratch("recv-term");
    let drop = root.join("drop");
    std::fs::create_dir_all(&drop).unwrap();
    let mut t = Term::shell(&root);
    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());
    let at = t.text().len();
    t.send(&format!("\"{exe}\" --server {} receive --dir \"{}\"; echo RC=$?\r", b.url, drop.display()));
    start_listening(&mut t, at);
    // The receive's pid, found by its unique --dir.
    let marker = drop.display().to_string();
    let pid = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()))
        .find(|pid| {
            std::fs::read(format!("/proc/{pid}/cmdline"))
                .map(|c| {
                    let c = String::from_utf8_lossy(&c);
                    c.contains("receive") && c.contains(&marker) && !c.contains("echo RC")
                })
                .unwrap_or(false)
        })
        .expect("the receive's pid");
    let killed = std::process::Command::new("kill").args(["-TERM", &pid.to_string()]).status().expect("kill");
    assert!(killed.success());
    let rc = rc_after(&t, at, 8);
    assert_eq!(rc, Some(143), "SIGTERM did not end the waiting receive with 143 within 8s; screen:\n{}", tail(&t.text()));
    let _ = std::fs::remove_dir_all(&root);
}

// ---------------------------------------------------------------------------
// Concurrent-code lab pass: the guided code prompt of a bare `receive`.
// No network is reached before the prompt, so these need no backend.
// ---------------------------------------------------------------------------

/// Ctrl-C at the guided code prompt is an interrupt: exit 130, as a shell
/// reports one. It exited 1 with "Error: cancelled", because raw mode turns
/// Ctrl-C into a key and the prompt treated it like Esc.
#[cfg(unix)]
#[test]
fn ctrl_c_at_the_receive_code_prompt_exits_130() {
    let (mut t, exe) = fresh_term("recv-prompt-int");
    let at = t.text().len();
    t.send(&format!("\"{exe}\" --server http://127.0.0.1:9 receive; echo RC=$?\r"));
    assert!(
        t.wait_for_from(at, "enter a code", 30),
        "receive never offered its code entry; screen:\n{}",
        tail(&t.text())
    );
    t.settle(300, 3);
    t.send("\u{3}");
    let rc = rc_after(&t, at, 8);
    assert_eq!(rc, Some(130), "Ctrl-C at the code prompt did not exit 130; screen:\n{}", tail(&t.text()));
    assert!(!t.text()[at..].contains("Error: cancelled"), "an interrupt reported as a cancel:\n{}", tail(&t.text()));
}

/// `receive --room X` already says where to meet: no code prompt. It opened
/// "enter a code ... or press enter to use the local network" anyway.
#[cfg(unix)]
#[test]
fn receive_with_an_explicit_room_skips_the_code_prompt() {
    let (mut t, exe) = fresh_term("recv-room");
    let at = t.text().len();
    t.send(&format!("\"{exe}\" --server http://127.0.0.1:9 receive --room lab-room-7; echo RC=$?\r"));
    // The review screen is the first thing it asks now.
    assert!(
        t.wait_for_from(at, "Press Enter to wait", 30),
        "receive --room never reached its review; screen:\n{}",
        tail(&t.text())
    );
    assert!(
        !t.text()[at..].contains("enter a code"),
        "receive --room still opened the code prompt:\n{}",
        tail(&t.text())
    );
    t.send("cancel\r");
    assert!(rc_after(&t, at, 8).is_some(), "receive --room did not end on cancel; screen:\n{}", tail(&t.text()));
}
