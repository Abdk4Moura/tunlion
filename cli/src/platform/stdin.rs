//! The stdin reader for an interactive receive.
//!
//! Unix is owned and cancellable: poll stdin, check an atomic stop flag, and
//! report `Joined`/`Detached`. Windows is the CLI's process-lifetime detached
//! reader (the pre-#542 behavior): a blocking thread the engine does not own or
//! join, reported as `External`. Android has no terminal composition and
//! returns `None`.

use filament_peerloop::present::Presentation;
use filament_peerloop::recv::ports::{StdinOutcome, StdinOwner};
use filament_transport::net::Ev;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Feed one decoded character into the line/consent state. Shared by both OS
/// readers so their semantics cannot drift.
#[cfg(any(all(unix, not(target_os = "android")), windows))]
fn feed_char(
    c: char,
    tx: &mpsc::UnboundedSender<Ev>,
    question_open: &AtomicBool,
    present: &dyn Presentation,
    line: &mut String,
) {
    if question_open.load(Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
        present.answer_echo(c);
        let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
        return;
    }
    match c {
        '\n' | '\r' => {
            crate::ui::say("");
            let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
            line.clear();
        }
        '\u{7f}' | '\u{8}' => {
            if line.pop().is_some() {
                crate::ui::erase_one();
            }
        }
        c if !c.is_control() => {
            crate::ui::echo_char(c);
            line.push(c);
        }
        _ => {}
    }
}

#[cfg(all(unix, not(target_os = "android")))]
pub fn spawn_stdin(
    tx: mpsc::UnboundedSender<Ev>,
    question_open: Arc<AtomicBool>,
    present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let handle = std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin();
        let mut buf = [0u8; 1];
        let mut line = String::new();
        while !stop_thread.load(Ordering::Relaxed) {
            if !input_ready(100) {
                continue;
            }
            if stdin.read(&mut buf).map(|n| n != 1).unwrap_or(true) {
                break;
            }
            feed_char(
                buf[0] as char,
                &tx,
                &question_open,
                present.as_ref(),
                &mut line,
            );
        }
    });
    Some(Box::new(CliStdin {
        stop,
        handle: Some(handle),
    }))
}

#[cfg(all(unix, not(target_os = "android")))]
fn input_ready(timeout_ms: i32) -> bool {
    use std::os::fd::AsRawFd;
    input_ready_fd(std::io::stdin().as_raw_fd(), timeout_ms)
}

#[cfg(all(unix, not(target_os = "android")))]
fn input_ready_fd(fd: i32, timeout_ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, no ownership transferred.
    let n = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    n > 0 && (p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

#[cfg(all(unix, not(target_os = "android")))]
struct CliStdin {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(unix, not(target_os = "android")))]
impl StdinOwner for CliStdin {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
    fn join(&mut self) -> StdinOutcome {
        match self.handle.take() {
            None => StdinOutcome::NotStarted,
            Some(handle) => {
                if handle.join().is_ok() {
                    StdinOutcome::Joined
                } else {
                    StdinOutcome::Detached("stdin reader panicked")
                }
            }
        }
    }
}

#[cfg(all(unix, not(target_os = "android")))]
impl Drop for CliStdin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
pub fn spawn_stdin(
    _tx: mpsc::UnboundedSender<Ev>,
    _question_open: Arc<AtomicBool>,
    _present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    None
}

// ---------------------------------------------------------------- Windows --
// Windows stdin stays the CLI's process-lifetime reader (the behavior main had
// before #542). The engine does not own or join it; cleanup reports External.
#[cfg(windows)]
mod win {
    use super::*;

    pub struct WindowsStdin {
        handle: Option<std::thread::JoinHandle<()>>,
    }

    impl StdinOwner for WindowsStdin {
        fn stop(&mut self) {
            // Deliberately no-op: this is a CLI process-lifetime reader, not
            // engine-owned work.
        }
        fn join(&mut self) -> StdinOutcome {
            // Drop the handle to detach; never claim a join.
            let _ = self.handle.take();
            StdinOutcome::External("windows stdin is a CLI process-lifetime reader")
        }
    }

    impl Drop for WindowsStdin {
        fn drop(&mut self) {
            let _ = self.handle.take();
        }
    }

    pub fn spawn(
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<Box<dyn StdinOwner>> {
        use std::io::Read;
        let handle = std::thread::spawn(move || {
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while stdin.read(&mut buf).map(|n| n == 1).unwrap_or(false) {
                feed_char(
                    buf[0] as char,
                    &tx,
                    &question_open,
                    present.as_ref(),
                    &mut line,
                );
            }
        });
        Some(Box::new(WindowsStdin {
            handle: Some(handle),
        }))
    }
}

#[cfg(windows)]
pub fn spawn_stdin(
    tx: mpsc::UnboundedSender<Ev>,
    question_open: Arc<AtomicBool>,
    present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    win::spawn(tx, question_open, present)
}

#[cfg(all(test, unix, not(target_os = "android")))]
mod unix_pipe_tests {
    use super::input_ready_fd;

    #[test]
    fn a_closed_pipe_is_ready_for_both_eof_and_hup() {
        let mut fds = [0i32; 2];
        // SAFETY: two-int array for pipe(2).
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (r, w) = (fds[0], fds[1]);
        unsafe {
            assert_eq!(libc::write(w, b"x".as_ptr() as *const _, 1), 1);
            libc::close(w);
        }
        assert!(input_ready_fd(r, 100), "a byte is ready");
        let mut b = 0u8;
        unsafe {
            assert_eq!(libc::read(r, &mut b as *mut _ as *mut _, 1), 1);
        }
        // After the write end closes, POLLHUP must still wake the poll; the
        // reader's subsequent read(2) returns 0 and exits.
        assert!(input_ready_fd(r, 100), "HUP is readiness, not a spin");
        let mut b = 0u8;
        unsafe {
            assert_eq!(libc::read(r, &mut b as *mut _ as *mut _, 1), 0);
            libc::close(r);
        }
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    #[test]
    fn windows_stdin_is_an_explicit_external_reader() {
        use super::spawn_stdin;
        use filament_peerloop::present::NoScreen;
        use filament_peerloop::recv::ports::StdinOutcome;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let mut owner = spawn_stdin(tx, Arc::new(AtomicBool::new(false)), Arc::new(NoScreen))
            .expect("Windows has the CLI process-lifetime reader");
        assert_eq!(
            owner.join(),
            StdinOutcome::External("windows stdin is a CLI process-lifetime reader")
        );
    }
}
