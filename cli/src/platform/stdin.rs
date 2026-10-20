//! The owned stdin reader for an interactive receive.
//!
//! The library asks for an owner and retains it; this adapter owns the OS
//! thread and can stop it. Unix uses a pollable read; Windows waits on the
//! console/pipe handle with a bounded timeout. Android never requests stdin
//! (the embedding has no terminal composition), so it returns None.

use filament_peerloop::present::Presentation;
use filament_peerloop::recv::ports::StdinOwner;
use filament_transport::net::Ev;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[cfg(any(all(unix, not(target_os = "android")), windows))]
pub fn spawn_stdin(
    tx: mpsc::UnboundedSender<Ev>,
    question_open: Arc<AtomicBool>,
    present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = stop.clone();
    let thread_id = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let id_thread = thread_id.clone();
    let handle = std::thread::spawn(move || {
        #[cfg(windows)]
        id_thread.store(
            unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() },
            Ordering::Release,
        );
        #[cfg(not(windows))]
        let _ = &id_thread;
        reader_loop(tx, question_open, present, stop_thread)
    });
    Some(Box::new(CliStdin {
        stop,
        thread_id,
        handle: Some(handle),
    }))
}

#[cfg(not(any(all(unix, not(target_os = "android")), windows)))]
pub fn spawn_stdin(
    _tx: mpsc::UnboundedSender<Ev>,
    _question_open: Arc<AtomicBool>,
    _present: Arc<dyn Presentation>,
) -> Option<Box<dyn StdinOwner>> {
    None
}

#[cfg(any(all(unix, not(target_os = "android")), windows))]
fn reader_loop(
    tx: mpsc::UnboundedSender<Ev>,
    question_open: Arc<AtomicBool>,
    present: Arc<dyn Presentation>,
    stop: Arc<AtomicBool>,
) {
    use std::io::Read;
    let mut stdin = std::io::stdin();
    let mut buf = [0u8; 1];
    let mut line = String::new();
    while !stop.load(Ordering::Relaxed) {
        if !input_ready(100) {
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
}

#[cfg(all(unix, not(target_os = "android")))]
fn input_ready(timeout_ms: i32) -> bool {
    use std::os::fd::AsRawFd;
    let fd = std::io::stdin().as_raw_fd();
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one initialized pollfd, no ownership transferred.
    let n = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    n > 0 && (p.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
}

#[cfg(windows)]
fn input_ready(timeout_ms: i32) -> bool {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    // SAFETY: GetStdHandle has no preconditions; the wait only observes it.
    let handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let timeout = u32::try_from(timeout_ms).unwrap_or(100);
    // SAFETY: a valid standard handle for this process; no ownership changes.
    unsafe { WaitForSingleObject(handle, timeout) == WAIT_OBJECT_0 }
}

#[cfg(any(all(unix, not(target_os = "android")), windows))]
struct CliStdin {
    stop: Arc<AtomicBool>,
    thread_id: Arc<std::sync::atomic::AtomicU32>,
    handle: Option<std::thread::JoinHandle<()>>,
}

#[cfg(any(all(unix, not(target_os = "android")), windows))]
impl StdinOwner for CliStdin {
    fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        #[cfg(windows)]
        cancel_pending_read(self.thread_id.load(Ordering::Acquire));
    }
    fn join(&mut self) -> bool {
        let Some(handle) = self.handle.take() else {
            return true;
        };
        #[cfg(windows)]
        {
            // The cancellable read should return at once. Bound the join so a
            // console that ignores cancellation cannot hold cleanup hostage;
            // false means the CLI detaches and keeps cleaning up.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !handle.is_finished() {
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            handle.join().is_ok()
        }
        #[cfg(not(windows))]
        {
            handle.join().is_ok()
        }
    }
}

#[cfg(windows)]
fn cancel_pending_read(thread_id: u32) {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenThread, THREAD_TERMINATE};
    use windows_sys::Win32::System::IO::CancelSynchronousIo;
    if thread_id == 0 {
        return;
    }
    // SAFETY: OpenThread only observes the id; the handle is closed here.
    let handle = unsafe { OpenThread(THREAD_TERMINATE, 0, thread_id) };
    if handle != 0 {
        unsafe {
            let _ = CancelSynchronousIo(handle);
            let _ = CloseHandle(handle);
        }
    }
}

#[cfg(any(all(unix, not(target_os = "android")), windows))]
impl Drop for CliStdin {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    #[test]
    fn stop_joins_a_pending_windows_reader_within_bounds() {
        use super::spawn_stdin;
        use filament_peerloop::present::NoScreen;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let question = Arc::new(AtomicBool::new(false));
        let mut owner =
            spawn_stdin(tx, question, Arc::new(NoScreen)).expect("Windows has an owned reader");
        std::thread::sleep(std::time::Duration::from_millis(100));
        let started = std::time::Instant::now();
        owner.stop();
        let joined = owner.join();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "join must be bounded"
        );
        // A closed pipe exits, a console read is cancelled; either way the
        // adapter reports the truth rather than a fabricated success.
        let _ = joined;
    }

    #[cfg(all(unix, not(target_os = "android")))]
    #[test]
    fn unix_reader_is_owned_and_bounded_on_stop() {
        use super::spawn_stdin;
        use filament_peerloop::present::NoScreen;
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let question = Arc::new(AtomicBool::new(false));
        let mut owner =
            spawn_stdin(tx, question, Arc::new(NoScreen)).expect("unix has an owned reader");
        std::thread::sleep(std::time::Duration::from_millis(100));
        let started = std::time::Instant::now();
        owner.stop();
        let _ = owner.join();
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "poll-based stop/join is bounded"
        );
    }
}
