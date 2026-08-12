//! Interactive flows driven through a real terminal.
//!
//! Everything else we test drives filament as a program: arguments in, exit
//! code and bytes out. That cannot see the class of bug the owner keeps hitting
//! on Windows, because those bugs are about what the *terminal* is left looking
//! like after filament has finished with it. #197 is the current example: after
//! Ctrl-C out of the picker, PowerShell draws its prompt twice.
//!
//! So these tests open a pty, start a real shell inside it, run filament from
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

use portable_pty::{native_pty_system, CommandBuilder, PtySize, PtySystem};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Deliberately not a shell metacharacter and not a word filament prints. The
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
        cmd.env("FILAMENT_CONFIG_DIR", cfg_dir);
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

    /// Wait for `needle`, returning false on timeout rather than panicking, so
    /// a caller can report what it did see. A bare unwrap here would turn "the
    /// picker never drew" into a stack trace that hides the actual screen.
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

/// Drive `filament add --for` to the picker, then leave it with `leave_key`.
/// Returns how many prompts were drawn after the picker was dismissed.
fn prompts_after_leaving_picker(leave_key: &str, label: &str) -> usize {
    let dir = std::env::temp_dir().join(format!("filament-pty-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("cfg dir");
    let mut t = Term::shell(&dir);

    assert!(t.wait_for(&format!("{MARK}> "), 20), "shell never prompted:\n{}", t.text());

    let exe = env!("CARGO_BIN_EXE_filament");
    t.send(&format!("\"{exe}\" add --for\r"));

    // The picker's own heading. If this never appears the test has not reached
    // the thing it claims to measure, and saying so beats asserting on a
    // prompt count from a screen that never happened.
    if !t.wait_for("WHO IS JOINING", 30) {
        panic!("picker never drew for {label}; screen was:\n{}", t.text());
    }

    // Everything from here is what the interrupt produced.
    let before = t.text().len();
    t.send(leave_key);
    t.settle(1200, 20);

    let after = &t.text()[before.min(t.text().len())..];
    let count = after.matches(&format!("{MARK}> ")).count();
    eprintln!("--- {label}: {count} prompt(s) after leaving the picker ---\n{after}\n---");
    count
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
