//! The owned stdin reader for an interactive receive.
//!
//! The library asks for an owner and retains it; this adapter owns the OS
//! thread and can stop it. On unix the read is pollable, so stop wakes within
//! one poll interval and join is real. On targets without a pollable stdin the
//! reader is detached and `join` returns false: an explicit CLI-only lifetime
//! policy, never an embedded-engine ownership claim.

use filament_peerloop::present::Presentation;
use filament_peerloop::recv::ports::{RawMode, StdinOwner};
use filament_transport::net::Ev;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn spawn_stdin(
    tx: mpsc::UnboundedSender<Ev>,
    question_open: Arc<AtomicBool>,
    present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    #[cfg(all(unix, not(target_os = "android")))]
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let handle = std::thread::spawn(move || {
            use std::io::Read;
            let mut stdin = std::io::stdin();
            let mut buf = [0u8; 1];
            let mut line = String::new();
            while !stop_thread.load(Ordering::Relaxed) {
                if !stdin_poll_ready(100) {
                    continue;
                }
                if stdin.read(&mut buf).map(|n| n != 1).unwrap_or(true) {
                    break;
                }
                let c = buf[0] as char;
                if question_open.load(Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
                    present.answer_echo(c);
                    let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
                    continue;
                }
                match buf[0] {
                    b'\n' | b'\r' => {
                        crate::ui::say("");
                        let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
                        line.clear();
                    }
                    0x7f | 0x08 => {
                        if line.pop().is_some() {
                            crate::ui::erase_one();
                        }
                    }
                    _ if !c.is_control() => {
                        crate::ui::echo_char(c);
                        line.push(c);
                    }
                    _ => {}
                }
            }
        });
        return Some(Box::new(CliStdin {
            stop,
            handle: Some(handle),
        }));
    }
    #[cfg(not(all(unix, not(target_os = "android"))))]
    {
        let _ = (tx, question_open, present);
        None
    }
}

#[cfg(all(unix, not(target_os = "android")))]
fn stdin_poll_ready(timeout_ms: i32) -> bool {
    use std::os::fd::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, no ownership transferred.
    let n = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    n > 0 && (p.revents & libc::POLLIN) != 0
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
    fn join(&mut self) -> bool {
        self.handle.take().map(|h| h.join().is_ok()).unwrap_or(true)
    }
}

#[cfg(all(unix, not(target_os = "android")))]
impl Drop for CliStdin {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(dead_code)]
fn _raw(_: &dyn RawMode) {}
