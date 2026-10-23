//! Windows-only: the interactive entry point must survive the Clap command
//! tree and the temporary-access draft menu must stay up.
//!
//! This is the regression the 16 MB entry-point stack wrapper exists for: on
//! Windows, constructing the command tree overflowed the default 1 MB main
//! thread before the menu could draw. The unit `--version` parse exercises the
//! tree, but only a real console shows the menu, so this test runs the actual
//! binary inside a ConPTY and drives the pickers the way a person does.
//!
//! No network, no identity: the config dir is a fresh temp directory, the first
//! screen offers "Connect a device or share temporary access", and the draft
//! menu stops before minting anything.

#![cfg(windows)]

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Screen {
    out: Arc<Mutex<Vec<u8>>>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
    _master: Box<dyn portable_pty::MasterPty + Send>,
}

impl Screen {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.out.lock().expect("screen lock")).to_string()
    }

    fn wait_for(&self, needle: &str, secs: u64) -> bool {
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end {
            if self.text().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.text().contains(needle)
    }

    fn send(&mut self, s: &str) {
        self.writer.write_all(s.as_bytes()).expect("write to ConPTY");
        self.writer.flush().expect("flush ConPTY");
    }
}

#[test]
fn interactive_startup_and_temporary_access_menus_stay_up() {
    let dir = std::env::temp_dir().join(format!("tunlion-win-menu-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("temp config dir");

    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 30,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open ConPTY");

    let mut cmd = CommandBuilder::new(env!("CARGO_BIN_EXE_tunlion"));
    // Hermetic: never read or write the real identity/config.
    cmd.env("TUNLION_CONFIG_DIR", &dir);
    cmd.env("USERPROFILE", &dir);
    cmd.env("APPDATA", &dir);
    cmd.env("LOCALAPPDATA", &dir);
    cmd.cwd(&dir);

    let child = pair.slave.spawn_command(cmd).expect("spawn tunlion");
    drop(pair.slave);

    let out = Arc::new(Mutex::new(Vec::new()));
    let mut reader = pair.master.try_clone_reader().expect("ConPTY reader");
    let sink = Arc::clone(&out);
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        while let Ok(n) = reader.read(&mut buf) {
            if n == 0 {
                break;
            }
            sink.lock().expect("screen lock").extend_from_slice(&buf[..n]);
        }
    });
    let writer = pair.master.take_writer().expect("ConPTY writer");

    let mut screen = Screen {
        out,
        writer,
        child,
        _master: pair.master,
    };

    assert!(
        screen.wait_for("TUNLION", 30),
        "the startup screen never drew; got:\n{}",
        screen.text()
    );
    assert!(
        screen.wait_for("Connect a device or share temporary access", 10),
        "the fresh-device first action is missing; got:\n{}",
        screen.text()
    );
    assert!(
        !screen.text().contains("overflowed its stack"),
        "startup stack overflow:\n{}",
        screen.text()
    );

    // First action -> `add` menu, second item -> the temporary-access draft.
    screen.send("\r");
    assert!(
        screen.wait_for("Temporary access", 15),
        "the add menu never offered temporary access; got:\n{}",
        screen.text()
    );
    screen.send("\u{1b}[B\r");
    assert!(
        screen.wait_for("Folders (0)", 15),
        "the temporary-access menu never drew; got:\n{}",
        screen.text()
    );

    assert!(
        screen.child.try_wait().expect("try_wait").is_none(),
        "the temporary-access menu exited on its own; got:\n{}",
        screen.text()
    );
    assert!(
        !screen.text().contains("overflowed its stack"),
        "menu stack overflow:\n{}",
        screen.text()
    );

    let _ = screen.child.kill();
    let _ = screen.child.wait();
    let _ = std::fs::remove_dir_all(&dir);
}
