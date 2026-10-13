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
    let start = stripped.len().saturating_sub(2500);
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
    // Entry 0 is "Set up this first device"; the accept entry is next.
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
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
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
            assert!(std::env::var_os("CI").is_none(), "the backend exited ({st}); CI must run it for the receive pty cells");
            eprintln!("SKIP: the backend exited ({st}); install its Python deps to run these cells");
            return None;
        }
        thread::sleep(Duration::from_millis(200));
    }
    let _ = child.kill();
    panic!("the backend never answered /api/health on port {port}");
}

/// A fresh scratch dir for one cell.
#[cfg(unix)]
fn scratch(label: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tunlion-pty-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// A bare `receive` at a terminal first offers a code entry; Enter there
/// means "listen on the local network", the long wait these cells interrupt.
#[cfg(unix)]
fn start_listening(t: &mut Term, at: usize) {
    assert!(
        t.wait_for_from(at, "enter a code", 30),
        "receive never offered its code entry; screen:\n{}",
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
