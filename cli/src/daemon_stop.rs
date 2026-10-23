//! Stopping the daemon, and telling the truth about who holds it.
//!
//! WHY THIS EXISTS. A blind test stopped a daemon with SIGSTOP and ran
//! `tunlion down --yes`: it printed "stopped (pid 2219)" and exited 0 in 6 ms
//! while the process still existed (state T). `down` sent SIGTERM, which a
//! stopped process cannot act on, deleted the pidfile and declared success. The
//! stopped daemon still held the single-instance lock, so `up --detach` then
//! said "daemon already running (starting); nothing to do", and `status` said
//! "not running". The same happened to a daemon busy in a reconnect loop: `down`
//! returned before it exited, the next `up` lost the election to it, and when it
//! finally exited nothing was running at all.
//!
//! Two rules close it:
//! - `down` says stopped only after the process is GONE ([`await_exit`]): it
//!   resumes a stopped daemon so it can act on SIGTERM, waits a bounded time,
//!   then SIGKILLs, and says which of those it had to do.
//! - `up` names the process that holds the election ([`lock_holder`]) and
//!   refuses to call a stopped one "running". The lock itself cannot be stale
//!   (the kernel drops it when the holder exits); what was stale was the claim.
//!
//! It also leaves a stop marker, so an `up --detach` whose new daemon died
//! during startup can say that a `tunlion down` stopped it ([`stopped_by_down_since`]).

use crate::platform::{self, Escalate};
use anyhow::{Result, bail};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// How long a daemon gets to exit after SIGTERM before it is killed. Its own
/// shutdown force-exits after `shutdown::DEFAULT_GRACE_MS` (3 s), so this only
/// runs out for a daemon that cannot run at all.
pub(crate) const TERM_GRACE: Duration = Duration::from_secs(10);

/// How long to wait for the kernel to reap a SIGKILLed daemon.
pub(crate) const KILL_GRACE: Duration = Duration::from_secs(3);

/// What `down` had to do beyond asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// It exited on SIGTERM (or its service manager stopped it).
    Asked,
    /// It was stopped (SIGSTOP); it was resumed so it could exit.
    Resumed,
    /// It did not exit within [`TERM_GRACE`] and was killed.
    Killed,
}

impl Stopped {
    /// The words `down` appends to "stopped (pid N)".
    pub(crate) fn note(self) -> &'static str {
        match self {
            Stopped::Asked => "",
            Stopped::Resumed => "; it was suspended (SIGSTOP), so it was resumed to let it exit",
            Stopped::Killed => {
                "; it did not exit within 10s, so it was force-terminated"
            }
        }
    }
}

/// One pid can name three different things after the daemon was signalled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
    /// Still the exact process we recorded.
    Ours,
    /// The process is gone.
    Gone,
    /// The pid now names a DIFFERENT incarnation/executable.
    Replaced,
    /// The process exists but we cannot verify the recorded start token. Never
    /// treat this as gone: fail closed and keep the pidfile.
    Unknown,
}

/// Pure identity decision, testable without processes.
fn classify_identity(
    exists: bool,
    want_token: Option<&str>,
    live_token: Option<&str>,
    exe_matches: bool,
) -> Identity {
    if !exists {
        return Identity::Gone;
    }
    if let Some(want) = want_token {
        match live_token {
            Some(live) if live == want => {}
            Some(_) => return Identity::Replaced,
            None => return Identity::Unknown,
        }
    }
    if !exe_matches {
        return Identity::Replaced;
    }
    Identity::Ours
}

/// Is `pid` still the daemon whose executable was `exe` and whose process start
/// token was `start`? A pid that died and was reused is NOT ours, so `down`
/// never kills a stranger.
fn identity_of(pid: u32, exe: Option<&Path>, start: Option<&str>) -> Identity {
    let exists = platform::process_exists(pid);
    let live_token = if start.is_some() {
        platform::process_start_token(pid)
    } else {
        None
    };
    let exe_matches = match (platform::process_exe_path(pid), exe) {
        (Some(live), Some(exe)) => crate::same_executable(&live, exe),
        _ => true,
    };
    classify_identity(exists, start, live_token.as_deref(), exe_matches)
}

fn still_ours(pid: u32, exe: Option<&Path>, start: Option<&str>) -> bool {
    identity_of(pid, exe, start) == Identity::Ours
}

/// Wait until the original process is gone OR its pid was replaced. `Unknown`
/// keeps waiting (never success).
fn wait_identity(pid: u32, exe: Option<&Path>, start: Option<&str>, within: Duration) -> Identity {
    let until = Instant::now() + within;
    loop {
        match identity_of(pid, exe, start) {
            Identity::Ours | Identity::Unknown => {}
            other => return other,
        }
        if Instant::now() >= until {
            return identity_of(pid, exe, start);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// After SIGTERM (or a service-manager stop) went to `pid`: make sure it exits,
/// and only return Ok once it has. Resumes it first if it is stopped, kills it
/// after [`TERM_GRACE`], and errors if even force-termination does not end it.
/// The bool says the pid now names a DIFFERENT process (so the pidfile belongs
/// to that one and must not be deleted).
pub(crate) fn await_exit(
    pid: u32,
    exe: Option<&Path>,
    start: Option<&str>,
) -> Result<(Stopped, bool)> {
    let was_stopped = platform::process_stopped(pid) == Some(true);
    let _ = platform::escalate(pid, Escalate::Continue);
    let politely = if was_stopped { Stopped::Resumed } else { Stopped::Asked };
    match wait_identity(pid, exe, start, TERM_GRACE) {
        Identity::Gone => return Ok((politely, false)),
        Identity::Replaced => return Ok((politely, true)),
        Identity::Unknown => {
            bail!(
                "the daemon (pid {pid}) is still running but its process start token cannot be read, so it cannot be safely verified or force-terminated. The pidfile is kept."
            );
        }
        Identity::Ours => {}
    }
    // Forced termination only if this is STILL the exact daemon we recorded.
    if identity_of(pid, exe, start) == Identity::Ours {
        if let Err(e) = platform::escalate(pid, Escalate::Kill) {
            if identity_of(pid, exe, start) == Identity::Ours {
                bail!(
                    "the daemon (pid {pid}) did not exit within {}s, and force-termination failed ({e}); it is still running. The pidfile is kept.",
                    TERM_GRACE.as_secs()
                );
            }
        }
    }
    match wait_identity(pid, exe, start, KILL_GRACE) {
        Identity::Gone => Ok((Stopped::Killed, false)),
        Identity::Replaced => Ok((Stopped::Killed, true)),
        Identity::Unknown => bail!(
            "the daemon (pid {pid}) is still running but its process start token cannot be read after force-termination. The pidfile is kept."
        ),
        Identity::Ours => bail!(
            "the daemon (pid {pid}) is still running {}s after force-termination{}. The pidfile is kept so `tunlion status` still sees it.",
            KILL_GRACE.as_secs(),
            match platform::process_stopped(pid) {
                Some(true) => " (it is stopped by a debugger or tracer)",
                _ => "",
            }
        ),
    }
}

/// Does `pidfile` still name the daemon we stopped? A replacement that wrote
/// its own pid (or reused the same pid as a new incarnation) must keep it.
pub(crate) fn pidfile_names_stopped(
    pidfile: &Path,
    stopped_pid: u32,
    stopped_start: Option<&str>,
) -> bool {
    let Ok(raw) = std::fs::read_to_string(pidfile) else { return false };
    let named = raw
        .lines()
        .next()
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse::<u32>().ok());
    if named != Some(stopped_pid) {
        return false;
    }
    match stopped_start {
        Some(want) => match platform::process_start_token(stopped_pid) {
            // Still the old incarnation (a zombie not yet reaped): keeping the
            // file is harmless; the caller only removes after exit.
            Some(live) => live == want,
            // Gone: the pidfile names the daemon we stopped.
            None => true,
        },
        None => true,
    }
}

/// Did this daemon receive a stop request? The request names a PID, so a
/// marker left by an older process is ignored. Consumed on match: one request
/// stops one daemon.
pub(crate) fn stop_requested() -> bool {
    let path = platform::daemon_stop_request_path();
    let Ok(raw) = std::fs::read_to_string(&path) else { return false };
    let mut lines = raw.lines();
    let requested = lines.next().and_then(|s| s.trim().parse::<u32>().ok());
    let token = lines.next().map(|s| s.trim().to_string());
    let my_pid = std::process::id();
    if requested != Some(my_pid) {
        // Another instance's request (or a malformed one) is not ours. Leave a
        // foreign pid alone; a startup clear handles leftovers.
        return false;
    }
    let mine = platform::process_start_token(my_pid);
    if token.is_none() || token != mine {
        // Same pid, different process incarnation: a recycled Windows pid.
        // Refuse it and remove the stale request.
        let _ = std::fs::remove_file(&path);
        return false;
    }
    let _ = std::fs::remove_file(&path);
    true
}


fn marker_path() -> PathBuf {
    platform::Paths::config_path("down.marker")
}

/// `down` is about to stop the daemon. Best effort: a read-only config dir
/// only costs the startup message its hint.
pub(crate) fn mark_down(pid: u32) {
    // Owner-only like everything else in the config dir: under umask 0000 a
    // plain write left it 0666 (hostile-env gate U).
    let _ = platform::SecretFile::write_str(&marker_path(), &format!("{pid}\n"));
}

/// Did a `tunlion down` run at or after `since`? An `up --detach` asks this
/// when the daemon it just spawned died during startup.
pub(crate) fn stopped_by_down_since(since: SystemTime) -> bool {
    std::fs::metadata(marker_path())
        .and_then(|m| m.modified())
        .map(|t| t >= since)
        .unwrap_or(false)
}

/// Who holds the daemon's single-instance election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Holder {
    /// A daemon is up and wrote its pidfile.
    Serving(u32),
    /// A daemon holds the election and has not written its pidfile yet.
    Starting(u32),
    /// The holder exists but is stopped (SIGSTOP): it serves nothing.
    Stopped(u32),
    /// The lock is held but no process could be named.
    Unknown,
}

/// The pure decision behind [`lock_holder`], so every combination is testable.
/// `pidfile` is the daemon the pidfile names (if alive and ours); `recorded` is
/// the pid the lock holder wrote into the lock (if alive and ours); `stopped`
/// says whether a pid is stopped.
pub(crate) fn classify(
    pidfile: Option<u32>,
    recorded: Option<u32>,
    stopped: impl Fn(u32) -> bool,
) -> Holder {
    match (pidfile, recorded) {
        (Some(p), _) if stopped(p) => Holder::Stopped(p),
        (Some(p), _) => Holder::Serving(p),
        (None, Some(r)) if stopped(r) => Holder::Stopped(r),
        (None, Some(r)) => Holder::Starting(r),
        (None, None) => Holder::Unknown,
    }
}

/// Name the process holding the election at `lock_path`, waiting briefly for a
/// winner that has just taken the lock to record itself.
pub(crate) fn lock_holder(lock_path: &Path) -> Holder {
    let exe = std::env::current_exe().ok();
    let ours = |pid: u32| still_ours(pid, exe.as_deref(), None);
    let stopped = |pid: u32| platform::process_stopped(pid) == Some(true);
    let mut last = Holder::Unknown;
    for _ in 0..20 {
        let recorded = holder_pid(lock_path).filter(|p| ours(*p));
        last = classify(crate::daemon_alive(), recorded, stopped);
        if matches!(last, Holder::Serving(_) | Holder::Stopped(_)) {
            return last;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    last
}

/// The daemon holding the election when the pidfile names nobody: the state an
/// older `down` left behind when it deleted the pidfile of a daemon that never
/// exited. Only a holder that recorded its pid, and is still this executable,
/// is returned; `down` stops it like any other.
pub(crate) fn orphaned_lock_holder() -> Option<u32> {
    let lock_path = platform::Paths::config_path("up.lock");
    let exe = std::env::current_exe().ok();
    holder_pid(&lock_path).filter(|p| still_ours(*p, exe.as_deref(), None))
}

/// The pid holding the election lock at `lock_path`, read without taking it.
/// The kernel's answer (/proc/locks) where there is one; elsewhere the pid the
/// holder recorded in the lock file, trusted only while the lock is held.
fn holder_pid(lock_path: &Path) -> Option<u32> {
    match platform::instance_lock_holder(lock_path) {
        platform::LockHolder::Held(Some(pid)) => Some(pid),
        platform::LockHolder::Free => None,
        platform::LockHolder::Held(None) => platform::InstanceLock::recorded_owner(lock_path),
        // The platform cannot say who holds it. Ask the lock itself: if it can
        // be taken nobody holds it (we drop it at once); if not, the holder's
        // own record names it.
        platform::LockHolder::Unknown => match platform::InstanceLock::try_acquire(lock_path) {
            Ok(None) => platform::InstanceLock::recorded_owner(lock_path),
            _ => None,
        },
    }
}

/// What `up` says when it lost the election. Ok only when a daemon that can
/// serve holds it; a stopped holder or an unnamed one is an error, because
/// "already running" would be false.
pub(crate) fn report_holder(h: Holder, lock_path: &Path) -> Result<()> {
    match h {
        Holder::Serving(pid) => {
            crate::up_logs::already_running(Some(pid));
            Ok(())
        }
        Holder::Starting(pid) => {
            crate::ui::say(&format!(
                "  {} daemon already running (pid {pid}, still starting); nothing to do",
                crate::ui::paint(crate::ui::Tone::Ok, crate::ui::glyph_ok())
            ));
            Ok(())
        }
        Holder::Stopped(pid) => bail!(
            "a daemon (pid {pid}) holds the lock but is suspended (SIGSTOP), so nothing is serving. `tunlion down` stops it (or `kill -CONT {pid}` resumes it); then `tunlion up`."
        ),
        Holder::Unknown => bail!(
            "another process holds the daemon lock {} but no running daemon could be identified. If `tunlion status` says not running, find the holder with `fuser {}` and stop it, then `tunlion up`.",
            lock_path.display(),
            lock_path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_stopped_holder_is_never_called_running() {
        assert_eq!(classify(Some(7), None, |_| true), Holder::Stopped(7));
        assert_eq!(classify(None, Some(9), |p| p == 9), Holder::Stopped(9));
    }

    #[test]
    fn holders_are_named_not_guessed() {
        assert_eq!(classify(Some(7), Some(7), |_| false), Holder::Serving(7));
        assert_eq!(classify(None, Some(9), |_| false), Holder::Starting(9));
        // The defect: no pidfile and no recorded owner used to print
        // "already running (starting)". Now it is Unknown, which `up` refuses.
        assert_eq!(classify(None, None, |_| false), Holder::Unknown);
    }

    #[test]
    fn only_serving_or_starting_is_success() {
        let p = Path::new("/x/up.lock");
        assert!(report_holder(Holder::Stopped(3), p).unwrap_err().to_string().contains("suspended"));
        assert!(report_holder(Holder::Unknown, p).unwrap_err().to_string().contains("/x/up.lock"));
    }

    #[test]
    fn stop_notes_say_what_was_done() {
        assert_eq!(Stopped::Asked.note(), "");
        assert!(Stopped::Resumed.note().contains("resumed"));
        assert!(Stopped::Killed.note().contains("force-terminated"));
    }

    struct ConfigDir(Option<std::ffi::OsString>, PathBuf);
    impl Drop for ConfigDir {
        fn drop(&mut self) {
            unsafe {
                match self.0.take() {
                    Some(v) => std::env::set_var("TUNLION_CONFIG_DIR", v),
                    None => std::env::remove_var("TUNLION_CONFIG_DIR"),
                }
            }
            let _ = std::fs::remove_dir_all(&self.1);
        }
    }

    /// The Windows stop path is a PID-scoped request file the daemon consumes.
    /// This runs everywhere (the reader is portable), so the exact logic that
    /// replaces `taskkill` is tested on every runner.
    #[test]
    fn a_stop_request_is_pid_scoped_and_consumed_once() {
        let _guard = crate::tests::lock_test_config();
        let dir = std::env::temp_dir().join(format!("tunlion-stop-req-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let previous = std::env::var_os("TUNLION_CONFIG_DIR");
        unsafe { std::env::set_var("TUNLION_CONFIG_DIR", &dir) };
        let _restore = ConfigDir(previous, dir);

        let path = platform::daemon_stop_request_path();
        let my_pid = std::process::id();
        let Some(token) = platform::process_start_token(my_pid) else { return };
        std::fs::write(&path, format!("{my_pid}\n{token}\n")).unwrap();
        assert!(stop_requested(), "our pid+incarnation must be accepted");
        assert!(!stop_requested(), "one request stops one daemon");

        // Same PID, different process start token: a recycled Windows pid.
        std::fs::write(&path, format!("{my_pid}\n{token}-other\n")).unwrap();
        assert!(!stop_requested(), "a recycled pid must be refused");
        assert!(!path.exists(), "the stale request is removed");

        std::fs::write(&path, "424242\n1\n").unwrap();
        assert!(!stop_requested(), "another pid is not ours");
    }

    /// The forced path must require the recorded process incarnation, not only
    /// the executable path: a recycled pid running the same tunlion binary is
    /// a different process.
    #[test]
    fn a_reused_pid_is_not_ours_even_with_the_same_executable() {
        let pid = std::process::id();
        if let Some(token) = platform::process_start_token(pid) {
            assert!(still_ours(pid, None, Some(&token)), "this incarnation is ours");
            assert!(
                !still_ours(pid, None, Some("0")),
                "same pid, different start token must never be ours"
            );
        }
    }

    #[test]
    fn identity_distinguishes_gone_replaced_and_unreadable_token() {
        assert_eq!(classify_identity(false, None, None, true), Identity::Gone);
        assert_eq!(
            classify_identity(true, Some("a"), Some("b"), true),
            Identity::Replaced
        );
        assert_eq!(
            classify_identity(true, Some("a"), None, true),
            Identity::Unknown,
            "an unreadable token must fail closed, not look gone"
        );
        assert_eq!(
            classify_identity(true, Some("a"), Some("a"), false),
            Identity::Replaced
        );
        assert_eq!(
            classify_identity(true, Some("a"), Some("a"), true),
            Identity::Ours
        );
    }

    /// `down` must not delete a pidfile that a replacement wrote while the old
    /// daemon exited.
    #[test]
    fn a_replacement_pidfile_is_not_removed() {
        let dir = std::env::temp_dir().join(format!("tunlion-pidfile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("up.pid");
        std::fs::write(&p, "4242\n").unwrap();
        assert!(pidfile_names_stopped(&p, 4242, None), "old pid still named");
        assert!(!pidfile_names_stopped(&p, 4243, None), "replacement pid differs");
        // Same pid but a different incarnation: process_start_token(current) is
        // not the recorded token.
        std::fs::write(&p, format!("{}\n", std::process::id())).unwrap();
        if let Some(t) = platform::process_start_token(std::process::id()) {
            assert!(!pidfile_names_stopped(&p, std::process::id(), Some("0")));
            assert!(pidfile_names_stopped(&p, std::process::id(), Some(&t)));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pid with no process behind it is gone, whatever executable we expected.
    #[test]
    fn a_dead_pid_is_not_ours() {
        // pid_max on Linux is at most 2^22; this one cannot exist.
        assert!(!still_ours(u32::MAX - 1, None, None));
        assert_eq!(
            wait_identity(u32::MAX - 1, None, None, Duration::from_millis(1)),
            Identity::Gone
        );
    }
}
