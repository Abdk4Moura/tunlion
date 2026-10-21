//! The stdin reader for an interactive receive.
//!
//! Both Unix and Windows are owned and cancellable: readers poll input, check
//! an atomic stop flag, and report `Joined` or a named `Detached`. `External`
//! is reserved for an adapter that deliberately keeps a process-lifetime
//! reader; this file does not use it. Android has no terminal composition and
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
    last_was_cr: &mut bool,
) {
    if question_open.load(Ordering::Relaxed) && "yYnN".contains(c) && line.is_empty() {
        present.answer_echo(c);
        let _ = tx.send(Ev::StdinLine(c.to_lowercase().to_string()));
        return;
    }
    match c {
        '\r' => {
            crate::ui::say("");
            let _ = tx.send(Ev::StdinLine(line.trim().to_string()));
            line.clear();
            *last_was_cr = true;
        }
        '\n' => {
            if *last_was_cr {
                *last_was_cr = false;
                return;
            }
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
            *last_was_cr = false;
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
        let mut last_was_cr = false;
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
                &mut last_was_cr,
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
// Windows stdin is owned now. Polling avoids blocking reads on pipes and the
// console, so stop is exact without overlapped I/O or cross-thread cancels.
#[cfg(windows)]
mod win {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_BROKEN_PIPE, HANDLE};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileType, ReadFile, FILE_TYPE_CHAR, FILE_TYPE_DISK, FILE_TYPE_PIPE,
    };
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetNumberOfConsoleInputEvents, GetStdHandle, ReadConsoleInputW,
        SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, INPUT_RECORD, KEY_EVENT,
        STD_INPUT_HANDLE,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeInfo, PeekNamedPipe};

    pub struct WindowsStdin {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
        reason: Arc<std::sync::Mutex<Option<&'static str>>>,
    }

    #[cfg(test)]
    impl WindowsStdin {
        pub(super) fn reader_finished(&self) -> bool {
            self.handle
                .as_ref()
                .is_none_or(|handle| handle.is_finished())
        }
    }

    impl StdinOwner for WindowsStdin {
        fn stop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
        fn join(&mut self) -> StdinOutcome {
            self.stop();
            let Some(handle) = self.handle.take() else {
                return StdinOutcome::NotStarted;
            };
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !handle.is_finished() {
                if std::time::Instant::now() >= deadline {
                    self.handle = Some(handle);
                    return StdinOutcome::Detached("windows stdin reader did not stop within 2s");
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if handle.join().is_err() {
                return StdinOutcome::Detached("windows stdin reader panicked");
            }
            if let Some(reason) = *self.reason.lock().unwrap() {
                return StdinOutcome::Detached(reason);
            }
            StdinOutcome::Joined
        }
    }

    impl Drop for WindowsStdin {
        fn drop(&mut self) {
            // Safe while the reader is running: set the flag and detach. No
            // unbounded join in Drop, and no handle owned by the thread.
            self.stop.store(true, Ordering::Relaxed);
            let _ = self.handle.take();
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
        spawn_on_handle_raw(input, tx, question_open, present)
            .map(|owner| Box::new(owner) as Box<dyn StdinOwner>)
    }

    pub(super) fn spawn_on_handle_raw(
        input: HANDLE,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Option<WindowsStdin> {
        if input.is_null() {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = stop.clone();
        let reason = Arc::new(std::sync::Mutex::new(None));
        let reason_thread = reason.clone();
        let input_usize = input as usize;
        let handle = std::thread::spawn(move || {
            let input = input_usize as HANDLE;
            if let Err(why) = reader(input, stop_thread, tx, question_open, present) {
                if let Ok(mut slot) = reason_thread.lock() {
                    *slot = Some(why);
                }
            }
        });
        Some(WindowsStdin {
            stop,
            handle: Some(handle),
            reason,
        })
    }

    fn reader(
        input: HANDLE,
        stop: Arc<AtomicBool>,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Result<(), &'static str> {
        // SAFETY: GetFileType has no preconditions.
        let kind = unsafe { GetFileType(input) };
        if kind == FILE_TYPE_CHAR {
            let mut mode = 0u32;
            // A character device may be NUL or a serial port. Only a real
            // console has a console mode; anything else is named, not spun.
            if unsafe { GetConsoleMode(input, &mut mode) } == 0 {
                return Err("windows stdin is a non-console character device");
            }
            return console_reader(input, mode, stop, tx, question_open, present);
        }
        if kind == FILE_TYPE_PIPE {
            // GetFileType also reports sockets as pipes. Probe the pipe
            // attributes so a socket is a named failure, not an idle reader.
            // Anonymous pipes are named-pipe-backed and succeed here.
            if unsafe {
                GetNamedPipeInfo(
                    input,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } == 0
            {
                return Err("windows stdin is a socket, not a pipe");
            }
            return byte_reader(input, kind, stop, tx, question_open, present);
        }
        if kind == FILE_TYPE_DISK {
            return byte_reader(input, kind, stop, tx, question_open, present);
        }
        Err("windows stdin handle is neither console, pipe, nor disk")
    }

    fn flush_pending(
        pending: &mut Vec<u8>,
        tx: &mpsc::UnboundedSender<Ev>,
        question_open: &AtomicBool,
        present: &dyn Presentation,
        line: &mut String,
        last_was_cr: &mut bool,
    ) {
        if pending.is_empty() {
            return;
        }
        let text = String::from_utf8_lossy(pending);
        for ch in text.chars() {
            feed_char(ch, tx, question_open, present, line, last_was_cr);
        }
        pending.clear();
    }

    fn byte_reader(
        input: HANDLE,
        kind: u32,
        stop: Arc<AtomicBool>,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Result<(), &'static str> {
        let mut line = String::new();
        let mut pending: Vec<u8> = Vec::new();
        let mut last_was_cr = false;
        loop {
            if stop.load(Ordering::Relaxed) {
                flush_pending(
                    &mut pending,
                    &tx,
                    &question_open,
                    present.as_ref(),
                    &mut line,
                    &mut last_was_cr,
                );
                return Ok(());
            }
            let mut available = 0u32;
            if kind == FILE_TYPE_PIPE {
                // SAFETY: PeekNamedPipe writes only the available count.
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
                    // A closed writer is EOF; any other error is named.
                    if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                        flush_pending(
                            &mut pending,
                            &tx,
                            &question_open,
                            present.as_ref(),
                            &mut line,
                            &mut last_was_cr,
                        );
                        return Ok(());
                    }
                    return Err("windows stdin pipe query failed");
                }
                if available == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(25));
                    continue;
                }
            }
            let mut buf = [0u8; 4096];
            let want = if kind == FILE_TYPE_PIPE {
                available.min(buf.len() as u32)
            } else {
                buf.len() as u32
            };
            let mut read = 0u32;
            // SAFETY: for a pipe PeekNamedPipe proved data; for a disk read it
            // is a normal synchronous file read, never a pending overlapped I/O.
            let ok = unsafe {
                ReadFile(
                    input,
                    buf.as_mut_ptr(),
                    want,
                    &mut read,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                if kind == FILE_TYPE_PIPE && unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                    flush_pending(
                        &mut pending,
                        &tx,
                        &question_open,
                        present.as_ref(),
                        &mut line,
                        &mut last_was_cr,
                    );
                    return Ok(());
                }
                return Err("windows stdin read failed");
            }
            if read == 0 {
                flush_pending(
                    &mut pending,
                    &tx,
                    &question_open,
                    present.as_ref(),
                    &mut line,
                    &mut last_was_cr,
                );
                return Ok(());
            }
            pending.extend_from_slice(&buf[..read as usize]);
            loop {
                match std::str::from_utf8(&pending) {
                    Ok(text) => {
                        for ch in text.chars() {
                            feed_char(
                                ch,
                                &tx,
                                &question_open,
                                present.as_ref(),
                                &mut line,
                                &mut last_was_cr,
                            );
                        }
                        pending.clear();
                        break;
                    }
                    Err(error) => {
                        let valid = error.valid_up_to();
                        if valid > 0 {
                            let text = unsafe { std::str::from_utf8_unchecked(&pending[..valid]) };
                            for ch in text.chars() {
                                feed_char(
                                    ch,
                                    &tx,
                                    &question_open,
                                    present.as_ref(),
                                    &mut line,
                                    &mut last_was_cr,
                                );
                            }
                            pending.drain(..valid);
                            continue;
                        }
                        match error.error_len() {
                            Some(invalid) => {
                                feed_char(
                                    '\u{fffd}',
                                    &tx,
                                    &question_open,
                                    present.as_ref(),
                                    &mut line,
                                    &mut last_was_cr,
                                );
                                pending.drain(..invalid);
                                continue;
                            }
                            // Incomplete trailing sequence: keep it for the
                            // next read or EOF flush.
                            None => break,
                        }
                    }
                }
            }
        }
    }

    pub(super) struct ConsoleModeGuard {
        input: HANDLE,
        saved: u32,
        #[cfg(test)]
        restore: Option<Box<dyn FnMut(u32)>>,
    }

    impl ConsoleModeGuard {
        fn new(input: HANDLE, saved: u32) -> Self {
            let raw = saved & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT);
            // SAFETY: valid console handle and saved mode.
            unsafe {
                let _ = SetConsoleMode(input, raw);
            }
            Self {
                input,
                saved,
                #[cfg(test)]
                restore: None,
            }
        }

        #[cfg(test)]
        pub(super) fn with_restore(saved: u32, restore: impl FnMut(u32) + 'static) -> Self {
            Self {
                input: std::ptr::null_mut(),
                saved,
                restore: Some(Box::new(restore)),
            }
        }
    }

    impl Drop for ConsoleModeGuard {
        fn drop(&mut self) {
            #[cfg(test)]
            if let Some(restore) = self.restore.as_mut() {
                restore(self.saved);
                return;
            }
            // SAFETY: restore the exact saved console mode, including unwind.
            unsafe {
                let _ = SetConsoleMode(self.input, self.saved);
            }
        }
    }

    fn console_reader(
        input: HANDLE,
        saved_mode: u32,
        stop: Arc<AtomicBool>,
        tx: mpsc::UnboundedSender<Ev>,
        question_open: Arc<AtomicBool>,
        present: Arc<dyn Presentation>,
    ) -> Result<(), &'static str> {
        // RAII: restore even if the reader panics or the JoinHandle is retained
        // after a timeout and only finishes later.
        let _mode = ConsoleModeGuard::new(input, saved_mode);
        let mut line = String::new();
        let mut last_was_cr = false;
        let mut high_surrogate: Option<u16> = None;
        let result = loop {
            if stop.load(Ordering::Relaxed) {
                break Ok(());
            }
            let mut available = 0u32;
            // SAFETY: writes one count.
            if unsafe { GetNumberOfConsoleInputEvents(input, &mut available) } == 0 {
                break Err("windows console event query failed");
            }
            if available == 0 {
                std::thread::sleep(std::time::Duration::from_millis(25));
                continue;
            }
            let mut record: INPUT_RECORD = unsafe { std::mem::zeroed() };
            let mut read = 0u32;
            // SAFETY: one record buffer, one record requested, only after the
            // console reports an event available.
            let ok = unsafe { ReadConsoleInputW(input, &mut record, 1, &mut read) };
            if ok == 0 {
                break Err("windows console read failed");
            }
            if read == 0 {
                break Ok(());
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
                                feed_char(
                                    ch,
                                    &tx,
                                    &question_open,
                                    present.as_ref(),
                                    &mut line,
                                    &mut last_was_cr,
                                );
                            }
                        }
                    } else {
                        high_surrogate = None;
                        if let Some(ch) = char::from_u32(unit as u32).filter(|c| *c != '\0') {
                            feed_char(
                                ch,
                                &tx,
                                &question_open,
                                present.as_ref(),
                                &mut line,
                                &mut last_was_cr,
                            );
                        }
                    }
                }
            }
        };
        result
    }
    #[cfg(test)]
    pub(super) fn spawn_stuck_for_test() -> Box<dyn StdinOwner> {
        let stop = Arc::new(AtomicBool::new(false));
        let reason = Arc::new(std::sync::Mutex::new(None));
        let handle = std::thread::spawn(|| {
            std::thread::sleep(std::time::Duration::from_secs(10));
        });
        Box::new(WindowsStdin {
            stop,
            handle: Some(handle),
            reason,
        })
    }

    #[cfg(test)]
    pub(super) fn spawn_panicking_for_test() -> Box<dyn StdinOwner> {
        let stop = Arc::new(AtomicBool::new(false));
        let reason = Arc::new(std::sync::Mutex::new(None));
        let handle = std::thread::spawn(|| panic!("stdin test panic"));
        Box::new(WindowsStdin {
            stop,
            handle: Some(handle),
            reason,
        })
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
    use super::win::{
        spawn_on_handle, spawn_on_handle_raw, spawn_panicking_for_test, spawn_stuck_for_test,
        ConsoleModeGuard,
    };
    use filament_peerloop::present::NoScreen;
    use filament_peerloop::recv::ports::StdinOutcome;
    use filament_transport::net::Ev;
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Storage::FileSystem::WriteFile;
    use windows_sys::Win32::System::Pipes::CreatePipe;

    static CONSOLE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn console_marker(state: &str, test: &str) {
        use std::io::Write;
        // Raw stderr bypasses libtest's per-test capture, so CI logs show
        // whether a console test executed or skipped.
        let _ = writeln!(std::io::stderr(), "{state}: {test}");
    }

    fn pipe() -> (usize, usize) {
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        // SAFETY: two out pointers and default security.
        assert_ne!(
            unsafe { CreatePipe(&mut read, &mut write, std::ptr::null_mut(), 0) },
            0
        );
        (read as usize, write as usize)
    }

    fn write_all(handle: usize, bytes: &[u8]) {
        let mut wrote = 0u32;
        // SAFETY: caller keeps the write handle open.
        assert_ne!(
            unsafe {
                WriteFile(
                    handle as *mut _,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut wrote,
                    std::ptr::null_mut(),
                )
            },
            0
        );
        assert_eq!(wrote as usize, bytes.len());
    }

    fn owner(
        handle: usize,
    ) -> (
        Box<dyn filament_peerloop::recv::ports::StdinOwner>,
        tokio::sync::mpsc::UnboundedReceiver<Ev>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            spawn_on_handle(
                handle as *mut _,
                tx,
                Arc::new(AtomicBool::new(false)),
                Arc::new(NoScreen),
            )
            .expect("reader"),
            rx,
        )
    }

    fn next_line(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Ev>) -> String {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Ok(Ev::StdinLine(line)) = rx.try_recv() {
                return line;
            }
            assert!(std::time::Instant::now() < deadline, "no line delivered");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    #[test]
    fn pipe_eof_without_data_joins() {
        let (read, write) = pipe();
        let (mut owner, _rx) = owner(read);
        // SAFETY: closing the only write end produces EOF.
        unsafe {
            CloseHandle(write as *mut _);
        }
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn pipe_eof_is_observed_without_stop() {
        let (read, write) = pipe();
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let owner = spawn_on_handle_raw(
            read as *mut _,
            tx,
            Arc::new(AtomicBool::new(false)),
            Arc::new(NoScreen),
        )
        .expect("reader");
        // SAFETY: closing the only write end produces EOF.
        unsafe { CloseHandle(write as *mut _) };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while !owner.reader_finished() {
            assert!(
                std::time::Instant::now() < deadline,
                "reader did not observe pipe EOF without stop"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut owner = Box::new(owner) as Box<dyn filament_peerloop::recv::ports::StdinOwner>;
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe { CloseHandle(read as *mut _) };
    }

    #[test]
    fn pipe_data_is_utf8_and_joins() {
        let (read, write) = pipe();
        write_all(write, b"hi\n");
        let (mut owner, mut rx) = owner(read);
        assert_eq!(next_line(&mut rx), "hi");
        unsafe {
            CloseHandle(write as *mut _);
        }
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn regular_file_redirect_is_read_to_eof() {
        let path =
            std::env::temp_dir().join(format!("tunlion-stdin-file-{}.txt", std::process::id()));
        std::fs::write(&path, b"file line\n").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let handle = file.as_raw_handle() as usize;
        let (mut owner, mut rx) = owner(handle);
        assert_eq!(next_line(&mut rx), "file line");
        assert_eq!(owner.join(), StdinOutcome::Joined);
        drop(file);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn continuous_pipe_data_still_stops() {
        let (read, write) = pipe();
        let (mut owner, _rx) = owner(read);
        let writer = std::thread::spawn(move || {
            for _ in 0..10_000 {
                write_all(write, b"x\n");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        let started = std::time::Instant::now();
        assert_eq!(owner.join(), StdinOutcome::Joined);
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        unsafe {
            CloseHandle(write as *mut _);
        }
        let _ = writer.join();
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn drop_while_reader_is_running_does_not_block() {
        let (read, write) = pipe();
        let (owner, _rx) = owner(read);
        let started = std::time::Instant::now();
        drop(owner);
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        // The detached reader may still be polling: leak both handles rather
        // than close one under it. Process exit reclaims them.
        let _ = (read, write);
    }

    #[test]
    fn panic_is_reported_as_detached() {
        let mut owner = spawn_panicking_for_test();
        assert_eq!(
            owner.join(),
            StdinOutcome::Detached("windows stdin reader panicked")
        );
    }

    #[test]
    fn idle_pipe_stops_without_eof() {
        let (read, write) = pipe();
        let (mut owner, _rx) = owner(read);
        std::thread::sleep(std::time::Duration::from_millis(100));
        let started = std::time::Instant::now();
        assert_eq!(owner.join(), StdinOutcome::Joined);
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        unsafe {
            CloseHandle(write as *mut _);
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn timeout_returns_detached_and_retains_thread() {
        let mut owner = spawn_stuck_for_test();
        let started = std::time::Instant::now();
        match owner.join() {
            StdinOutcome::Detached(reason) => assert!(reason.contains("did not stop")),
            other => panic!("expected detached, got {other:?}"),
        }
        assert!(started.elapsed() >= std::time::Duration::from_secs(2));
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        // The timed-out handle must still be retained: a second join times out
        // again rather than reporting NotStarted or Joined.
        match owner.join() {
            StdinOutcome::Detached(reason) => assert!(reason.contains("did not stop")),
            other => panic!("expected retained detached handle, got {other:?}"),
        }
    }

    #[test]
    fn socket_reported_as_pipe_is_named_not_joined() {
        use std::os::windows::io::AsRawSocket;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let (mut owner, _rx) = owner(listener.as_raw_socket() as usize);
        match owner.join() {
            StdinOutcome::Detached(reason) => assert!(
                reason.contains("socket, not a pipe")
                    || reason.contains("pipe query failed")
                    || reason.contains("neither console"),
                "expected a named failure, got {reason}"
            ),
            other => panic!("expected detached, got {other:?}"),
        }
    }

    #[test]
    fn crlf_is_one_line_not_two() {
        let (read, write) = pipe();
        write_all(write, b"a\r\nb\r\n");
        let (mut owner, mut rx) = owner(read);
        assert_eq!(next_line(&mut rx), "a");
        assert_eq!(next_line(&mut rx), "b");
        unsafe {
            CloseHandle(write as *mut _);
        }
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn invalid_utf8_consumes_only_the_bad_byte() {
        let (read, write) = pipe();
        write_all(write, b"\xffhi\nq\n");
        let (mut owner, mut rx) = owner(read);
        assert_eq!(next_line(&mut rx), "\u{fffd}hi");
        assert_eq!(next_line(&mut rx), "q");
        unsafe {
            CloseHandle(write as *mut _);
        }
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn multibyte_utf8_split_across_reads_is_preserved() {
        let (read, write) = pipe();
        // "é" = C3 A9, then a newline.
        write_all(write, &[0xC3]);
        std::thread::sleep(std::time::Duration::from_millis(50));
        write_all(write, &[0xA9, b'\n']);
        let (mut owner, mut rx) = owner(read);
        assert_eq!(next_line(&mut rx), "é");
        unsafe {
            CloseHandle(write as *mut _);
        }
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe {
            CloseHandle(read as *mut _);
        }
    }

    #[test]
    fn nul_is_named_as_a_non_console_character_device() {
        use windows_sys::Win32::Foundation::GENERIC_READ;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, OPEN_EXISTING,
        };
        let name: Vec<u16> = "NUL\0".encode_utf16().collect();
        // SAFETY: NUL device is always present.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            handle as isize, -1,
            "CreateFileW(NUL) must succeed: NUL exists on every Windows system"
        );
        let (mut owner, _rx) = owner(handle as usize);
        assert_eq!(
            owner.join(),
            StdinOutcome::Detached("windows stdin is a non-console character device")
        );
        unsafe {
            CloseHandle(handle);
        }
    }

    #[test]
    fn console_mode_guard_restores_once_on_unwind() {
        use std::panic::{catch_unwind, AssertUnwindSafe};
        use std::sync::atomic::AtomicUsize;
        let restored = Arc::new(AtomicUsize::new(0));
        let count = restored.clone();
        let saved = 0x1234_5678u32;
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _guard = ConsoleModeGuard::with_restore(saved, move |mode| {
                assert_eq!(mode, saved);
                count.fetch_add(1, Ordering::SeqCst);
            });
            panic!("panic inside console mode guard");
        }));
        assert!(result.is_err(), "the test must unwind");
        assert_eq!(
            restored.load(Ordering::SeqCst),
            1,
            "the fake restore must run exactly once"
        );
    }

    #[test]
    fn console_mode_is_restored_when_a_console_is_available() {
        let _serial = CONSOLE_TEST_LOCK.lock().unwrap();
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Console::GetConsoleMode;
        let name: Vec<u16> = "CONIN$\0".encode_utf16().collect();
        // SAFETY: opens the console input device if this process has one.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x8000_0000 | 0x4000_0000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            console_marker(
                "SKIP(console unavailable)",
                "console_mode_is_restored_when_a_console_is_available",
            );
            return;
        }
        let mut before = 0u32;
        if unsafe { GetConsoleMode(handle, &mut before) } == 0 {
            unsafe { CloseHandle(handle) };
            console_marker(
                "SKIP(console unavailable)",
                "console_mode_is_restored_when_a_console_is_available",
            );
            return;
        }
        console_marker(
            "CONSOLE(executed)",
            "console_mode_is_restored_when_a_console_is_available",
        );
        let (mut owner, _rx) = owner(handle as usize);
        assert_eq!(owner.join(), StdinOutcome::Joined);
        let mut after = 0u32;
        assert_ne!(unsafe { GetConsoleMode(handle, &mut after) }, 0);
        assert_eq!(before, after, "console mode must be restored");
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn console_surrogate_pair_is_one_line() {
        let _serial = CONSOLE_TEST_LOCK.lock().unwrap();
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
        };
        use windows_sys::Win32::System::Console::{
            FlushConsoleInputBuffer, WriteConsoleInputW, INPUT_RECORD, KEY_EVENT,
        };
        let name: Vec<u16> = "CONIN$\0".encode_utf16().collect();
        // SAFETY: opens the console input device if this process has one.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x8000_0000 | 0x4000_0000, // GENERIC_READ | GENERIC_WRITE
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            console_marker(
                "SKIP(console unavailable)",
                "console_surrogate_pair_is_one_line (console injection unavailable)",
            );
            return;
        }
        // SAFETY: console handle; flush and inject three key-down records.
        let (mut events, written) = unsafe {
            let _ = FlushConsoleInputBuffer(handle);
            let mut events: [INPUT_RECORD; 3] = std::mem::zeroed();
            for (slot, unit) in events.iter_mut().zip([0xD83Du16, 0xDE00, b'\r' as u16]) {
                slot.EventType = KEY_EVENT as u16;
                slot.Event.KeyEvent.bKeyDown = 1;
                slot.Event.KeyEvent.wRepeatCount = 1;
                slot.Event.KeyEvent.uChar.UnicodeChar = unit;
            }
            let mut written = 0u32;
            let ok = WriteConsoleInputW(handle, events.as_ptr(), 3, &mut written);
            (ok, written)
        };
        if events == 0 || written != 3 {
            unsafe { CloseHandle(handle) };
            console_marker(
                "SKIP(console unavailable)",
                "console_surrogate_pair_is_one_line (console injection unavailable)",
            );
            return;
        }
        console_marker("CONSOLE(executed)", "console_surrogate_pair_is_one_line");
        let (mut owner, mut rx) = owner(handle as usize);
        assert_eq!(next_line(&mut rx), "😀");
        assert_eq!(owner.join(), StdinOutcome::Joined);
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn invalid_handle_is_named_not_joined() {
        let (mut owner, _rx) = owner(!0usize);
        match owner.join() {
            StdinOutcome::Detached(reason) => {
                assert!(reason.contains("neither console, pipe, nor disk"))
            }
            other => panic!("expected detached, got {other:?}"),
        }
    }
}
