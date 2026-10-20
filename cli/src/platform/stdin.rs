//! The owned stdin reader for an interactive receive.
//!
//! Unix polls stdin and checks an atomic stop flag. Windows uses two explicit
//! strategies: console input is read with `ReadConsoleInputW` only after
//! `WaitForMultipleObjects` says an event (or stop) is ready; redirected stdin
//! uses overlapped `ReadFile` and waits on the stop event, so cancellation
//! completes the I/O before the buffer is released. Android has no terminal
//! composition and returns `None`.

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
#[cfg(windows)]
mod win {
    use super::*;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{GetFileType, ReadFile, FILE_TYPE_CHAR};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetNumberOfConsoleInputEvents, GetStdHandle, ReadConsoleInputW,
        INPUT_RECORD, KEY_EVENT, STD_INPUT_HANDLE,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};

    /// One owned stdin reader. The stop event is owned here and closed only
    /// after a normal joined finish; a detached reader leaks the event rather
    /// than closing a handle another thread may still be waiting on.
    pub struct WindowsStdin {
        stop_event: usize,
        handle: Option<std::thread::JoinHandle<()>>,
        detach_reason: Arc<std::sync::Mutex<Option<&'static str>>>,
        detached: bool,
    }

    impl StdinOwner for WindowsStdin {
        fn stop(&mut self) {
            // SAFETY: the event is owned by this struct.
            unsafe {
                let _ = SetEvent(self.stop_event as HANDLE);
            }
        }
        fn join(&mut self) -> StdinOutcome {
            self.stop();
            let Some(handle) = self.handle.take() else {
                return StdinOutcome::NotStarted;
            };
            // A real bound on the thread, without a cross-thread OS handle:
            // poll is_finished, then consume the JoinHandle only when done.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !handle.is_finished() {
                if std::time::Instant::now() >= deadline {
                    self.detached = true;
                    self.handle = Some(handle);
                    return StdinOutcome::Detached("stdin reader did not stop within 2s");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = handle.join();
            if let Some(reason) = *self.detach_reason.lock().unwrap() {
                return StdinOutcome::External(reason);
            }
            StdinOutcome::Joined
        }
    }

    impl Drop for WindowsStdin {
        fn drop(&mut self) {
            self.stop();
            if !self.detached {
                // SAFETY: only closed after a joined/normal finish.
                unsafe {
                    let _ = CloseHandle(self.stop_event as HANDLE);
                }
            }
            // A detached reader keeps the event handle alive on purpose; the
            // process is ending and closing it would race its wait.
        }
    }

    pub fn spawn(
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<Box<dyn StdinOwner>> {
        // SAFETY: standard handle; the reader only observes it.
        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
        spawn_on_handle(input, tx, question_open, present)
    }

    pub(super) fn spawn_on_handle(
        input: HANDLE,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<Box<dyn StdinOwner>> {
        if input.is_null() {
            return None;
        }
        let mut mode = 0u32;
        // SAFETY: GetConsoleMode writes one u32 and fails for a pipe.
        let console = unsafe {
            GetFileType(input) == FILE_TYPE_CHAR && GetConsoleMode(input, &mut mode) != 0
        };
        // SAFETY: anonymous manual-reset event owned by this reader.
        let stop = unsafe { CreateEventW(std::ptr::null_mut(), 1, 0, std::ptr::null_mut()) };
        if stop.is_null() {
            return None;
        }
        let stop_usize = stop as usize;
        let input_usize = input as usize;
        let detach_reason = Arc::new(std::sync::Mutex::new(None));
        let reason = detach_reason.clone();
        let handle = std::thread::spawn(move || {
            let input = input_usize as HANDLE;
            let stop = stop_usize as HANDLE;
            let outcome = if console {
                console_loop(input, stop, tx, question_open, present)
            } else {
                pipe_loop(input, stop, tx, question_open, present)
            };
            if let Some(text) = outcome {
                if let Ok(mut slot) = reason.lock() {
                    *slot = Some(text);
                }
            }
        });
        Some(Box::new(WindowsStdin {
            stop_event: stop_usize,
            handle: Some(handle),
            detach_reason: reason,
            detached: false,
        }))
    }

    /// Wait for the stop event for a short slice, checking stop every iteration.
    fn stopped(stop: HANDLE) -> bool {
        // SAFETY: event handle owned by WindowsStdin; wait only observes.
        unsafe { WaitForSingleObject(stop, 75) == WAIT_OBJECT_0 }
    }

    fn console_loop(
        input: HANDLE,
        stop: HANDLE,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<&'static str> {
        let mut line = String::new();
        let mut high_surrogate: Option<u16> = None;
        loop {
            if stopped(stop) {
                return None;
            }
            let mut available = 0u32;
            // SAFETY: writes one count.
            unsafe {
                let _ = GetNumberOfConsoleInputEvents(input, &mut available);
            }
            if available == 0 {
                continue;
            }
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read = 0u32;
            // SAFETY: one record buffer, one record requested; only called
            // when the console reports an event available.
            let ok = unsafe { ReadConsoleInputW(input, &mut record, 1, &mut read) };
            if ok == 0 || read == 0 {
                return None;
            }
            if record.EventType as u32 == KEY_EVENT {
                let key = unsafe { record.Event.KeyEvent };
                if key.bKeyDown != 0 {
                    let unit = unsafe { key.uChar.UnicodeChar };
                    if (0xD800..=0xDBFF).contains(&unit) {
                        high_surrogate = Some(unit);
                    } else if (0xDC00..=0xDFFF).contains(&unit) {
                        if let Some(high) = high_surrogate.take() {
                            if let Some(ch) =
                                char::decode_utf16([high, unit]).next().and_then(|r| r.ok())
                            {
                                feed_char(ch, &tx, &question_open, present.as_ref(), &mut line);
                            }
                        }
                    } else {
                        high_surrogate = None;
                        if let Some(ch) = char::from_u32(unit as u32).filter(|c| *c != '\0') {
                            feed_char(ch, &tx, &question_open, present.as_ref(), &mut line);
                        }
                    }
                }
            }
        }
    }

    fn pipe_loop(
        input: HANDLE,
        stop: HANDLE,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<&'static str> {
        let mut line = String::new();
        let mut pending: Vec<u8> = Vec::new();
        loop {
            if stopped(stop) {
                return None;
            }
            let mut available = 0u32;
            // SAFETY: PeekNamedPipe writes the count; no buffer is requested.
            let ok = unsafe {
                PeekNamedPipe(
                    input,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // Not a pipe (redirected file, unusual handle): keep the CLI's
                // process-lifetime policy instead of blocking an engine thread.
                return Some("stdin is not a pipe; CLI process-lifetime reader not owned");
            }
            if available == 0 {
                continue;
            }
            let mut buf = [0u8; 512];
            let want = available.min(buf.len() as u32);
            let mut read = 0u32;
            // SAFETY: PeekNamedPipe said at least `want` bytes are available;
            // ReadFile cannot block for an anonymous pipe with data.
            let ok = unsafe {
                ReadFile(
                    input,
                    buf.as_mut_ptr(),
                    want,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 || read == 0 {
                return None;
            }
            pending.extend_from_slice(&buf[..read as usize]);
            loop {
                match std::str::from_utf8(&pending) {
                    Ok(text) => {
                        for ch in text.chars() {
                            feed_char(ch, &tx, &question_open, present.as_ref(), &mut line);
                        }
                        pending.clear();
                        break;
                    }
                    Err(error) => {
                        let valid = error.valid_up_to();
                        if valid > 0 {
                            let text = unsafe { std::str::from_utf8_unchecked(&pending[..valid]) };
                            for ch in text.chars() {
                                feed_char(ch, &tx, &question_open, present.as_ref(), &mut line);
                            }
                            pending.drain(..valid);
                            continue;
                        }
                        if pending.len() >= 4 {
                            let ch = char::REPLACEMENT_CHARACTER;
                            feed_char(ch, &tx, &question_open, present.as_ref(), &mut line);
                            pending.clear();
                            break;
                        }
                        break; // incomplete UTF-8; wait for more bytes
                    }
                }
            }
        }
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

#[cfg(all(test, windows))]
mod windows_tests {
    use super::win::spawn_on_handle;
    use filament_peerloop::present::NoScreen;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    #[test]
    fn stop_joins_a_pending_overlapped_pipe_read() {
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        // SAFETY: default security, anonymous pipe; handles checked below.
        let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) };
        assert_ne!(ok, 0, "CreatePipe");
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let q = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut owner = spawn_on_handle(read, tx, q, std::sync::Arc::new(NoScreen))
            .expect("reader for the pipe");
        // No writer data: the ReadFile is pending on the pipe.
        std::thread::sleep(std::time::Duration::from_millis(150));
        let started = std::time::Instant::now();
        owner.stop();
        let outcome = owner.join();
        assert_eq!(
            outcome,
            filament_peerloop::recv::ports::StdinOutcome::Joined,
            "the overlapped read must cancel and join"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(3),
            "join must be prompt"
        );
        unsafe {
            let _ = CloseHandle(read);
            let _ = CloseHandle(write);
        }
    }
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
