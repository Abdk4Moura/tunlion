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
            Stopped::Killed => "; it did not exit within 10s of SIGTERM, so it was killed (SIGKILL)",
        }
    }
}

/// Is `pid` still the daemon whose executable was `exe`? A pid that died and
/// was reused by an unrelated process is NOT, so `down` never kills a stranger.
fn still_ours(pid: u32, exe: Option<&Path>) -> bool {
    match (platform::process_exe_path(pid), exe) {
        (Some(live), Some(exe)) => crate::same_executable(&live, exe),
        (Some(_), None) => true,
        (None, _) => false,
    }
}

fn wait_gone(pid: u32, exe: Option<&Path>, within: Duration) -> bool {
    let until = Instant::now() + within;
    loop {
        if !still_ours(pid, exe) {
            return true;
        }
        if Instant::now() >= until {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// After SIGTERM (or a service-manager stop) went to `pid`: make sure it exits,
/// and only return Ok once it has. Resumes it first if it is stopped, kills it
/// after [`TERM_GRACE`], and errors if even SIGKILL does not end it.
pub(crate) fn await_exit(pid: u32, exe: Option<&Path>) -> Result<Stopped> {
    let was_stopped = platform::process_stopped(pid) == Some(true);
    // Always resume: a stopped process cannot act on the SIGTERM it was sent,
    // and SIGCONT to a running one is harmless. Platforms that cannot tell us
    // whether it was stopped still get it resumed.
    let _ = platform::escalate(pid, Escalate::Continue);
    let politely = if was_stopped { Stopped::Resumed } else { Stopped::Asked };
    if wait_gone(pid, exe, TERM_GRACE) {
        return Ok(politely);
    }
    if let Err(e) = platform::escalate(pid, Escalate::Kill) {
        if still_ours(pid, exe) {
            bail!(
                "the daemon (pid {pid}) did not exit within {}s of SIGTERM, and SIGKILL failed ({e}); it is still running. The pidfile is kept.",
                TERM_GRACE.as_secs()
            );
        }
    }
    if wait_gone(pid, exe, KILL_GRACE) {
        return Ok(Stopped::Killed);
    }
    bail!(
        "the daemon (pid {pid}) is still running {}s after SIGKILL{}. The pidfile is kept so `tunlion status` still sees it.",
        KILL_GRACE.as_secs(),
        match platform::process_stopped(pid) {
            Some(true) => " (it is stopped by a debugger or tracer)",
            _ => "",
        }
    )
}

fn marker_path() -> PathBuf {
    platform::Paths::config_path("down.marker")
}

/// `down` is about to stop the daemon. Best effort: a read-only config dir
/// only costs the startup message its hint.
pub(crate) fn mark_down(pid: u32) {
    let _ = std::fs::write(marker_path(), format!("{pid}\n"));
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
    let ours = |pid: u32| still_ours(pid, exe.as_deref());
    let stopped = |pid: u32| platform::process_stopped(pid) == Some(true);
    let mut last = Holder::Unknown;
    for _ in 0..20 {
        let recorded = platform::InstanceLock::recorded_owner(lock_path).filter(|p| ours(*p));
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
    match platform::InstanceLock::try_acquire(&lock_path) {
        Ok(None) => {
            let exe = std::env::current_exe().ok();
            platform::InstanceLock::recorded_owner(&lock_path)
                .filter(|p| still_ours(*p, exe.as_deref()))
        }
        // Free (we just held and dropped it) or unreadable: nobody to stop.
        _ => None,
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
        assert!(Stopped::Killed.note().contains("SIGKILL"));
    }

    /// A pid with no process behind it is gone, whatever executable we expected.
    #[test]
    fn a_dead_pid_is_not_ours() {
        // pid_max on Linux is at most 2^22; this one cannot exist.
        assert!(!still_ours(u32::MAX - 1, None));
        assert!(wait_gone(u32::MAX - 1, None, Duration::from_millis(1)));
    }
}
