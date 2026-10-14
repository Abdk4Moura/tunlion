//! The `up` daemon's signaling link: when to re-dial, what to log, and the
//! health `status` and `doctor` report.
//!
//! WHY THIS EXISTS. After a long SIGSTOP (80 s, then SIGCONT) a daemon never
//! recovered: daemon.log repeated "signaling link closed, reconnecting..." and
//! "signaling reconnected, re-announcing presence" about 2.5 times a second for
//! as long as it ran, while `status` said "up" and `doctor` said healthy. Three
//! separate defects made that possible, and each is closed here or at its use:
//!
//! 1. A close of a connection the loop had ALREADY replaced was treated as the
//!    loss of the current one. Every connection shares the loop's event channel,
//!    and a freeze longer than twice the silence threshold arms both triggers at
//!    once: the silence watchdog re-dials, then the old socket's close arrives
//!    and tears the fresh one down. Its own close then lands after the next
//!    re-dial, so the cycle feeds itself forever. The loop now acts only on a
//!    close carrying the current connection's id (`filament_signal::Client::id`).
//! 2. The backoff could never grow: the new connection's own `welcome` reset
//!    the attempt counter, and every close set the last try 60 s into the past,
//!    so each re-dial went out at once. The counter now resets only after a
//!    connection has stayed up for [`STABLE_AFTER`].
//! 3. Each cycle logged two lines, unconditionally: about 20 MB a day on a box
//!    whose home was 24 MB. Repeats are now collapsed ([`LogCollapse`]).
//!
//! The health record is what the control socket's `cap-status` reply carries as
//! `signaling`, so a daemon that answers but is not connected (or keeps
//! dropping) is reported degraded instead of "up".

use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A connection that stayed up this long has earned a fresh backoff ladder.
/// Anything shorter counts as part of the same outage, so a link that drops
/// right after every re-dial backs off instead of re-dialing at full speed.
pub(crate) const STABLE_AFTER: Duration = Duration::from_secs(30);

/// How long the silence watchdog's forced `sync` probe gets to be answered,
/// counted from when it was sent, before the link is declared dead. The same
/// as the probe's own ack timeout (`net::heartbeat`).
pub(crate) const PROBE_WINDOW: Duration = Duration::from_secs(5);

/// First re-dial delay, doubled per attempt.
const BASE_MS: u64 = 500;

/// Ceiling for the doubled delay (before jitter).
pub(crate) const MAX_BACKOFF: Duration = Duration::from_secs(15);

/// Re-dials within [`FLAP_WINDOW`] at or above which a connected link is
/// reported as flapping rather than healthy.
pub(crate) const FLAP_THRESHOLD: usize = 4;
pub(crate) const FLAP_WINDOW: Duration = Duration::from_secs(120);

/// A run of identical log lines prints once per window, then once more with
/// the count of what it swallowed.
pub(crate) const COLLAPSE_WINDOW: Duration = Duration::from_secs(60);

/// The wait before re-dial `attempt` (0-based): 0.5 s doubling to a 15 s cap,
/// with +/-25% jitter taken from `unit` in [0, 1). Never below 0.375 s, so no
/// sequence of attempts is a tight loop, and never above 18.75 s, so recovery
/// after the cause clears is bounded. Pure; the caller supplies the randomness.
pub(crate) fn reconnect_delay(attempt: u32, unit: f64) -> Duration {
    let base = BASE_MS
        .saturating_mul(1u64 << attempt.min(6))
        .min(MAX_BACKOFF.as_millis() as u64) as f64;
    let unit = if unit.is_finite() { unit.clamp(0.0, 1.0) } else { 0.5 };
    let jittered = base * (0.75 + 0.5 * unit);
    Duration::from_millis(jittered.max(BASE_MS as f64 * 0.75) as u64)
}

/// A uniform value in [0, 1) for [`reconnect_delay`]. Two daemons that lost the
/// same server at the same moment must not re-dial in lockstep.
pub(crate) fn jitter_unit() -> f64 {
    let mut b = [0u8; 4];
    if getrandom::getrandom(&mut b).is_err() {
        return 0.5;
    }
    u32::from_le_bytes(b) as f64 / (u32::MAX as f64 + 1.0)
}

/// The attempt counter to use for the re-dial after a close. `up_for` is how
/// long the connection that just closed had been up (None if it never came up).
/// Only a connection that proved itself stable resets the ladder.
pub(crate) fn attempt_after_close(attempt: u32, up_for: Option<Duration>) -> u32 {
    match up_for {
        Some(d) if d >= STABLE_AFTER => 0,
        _ => attempt,
    }
}

/// Is a close for connection `closed` the loss of the CURRENT connection?
/// A close of any earlier connection is history: the loop already replaced it.
pub(crate) fn close_is_current(closed: u64, current: u64) -> bool {
    closed == current
}

/// Collapses repeats of the same log line. See the module docs, defect 3.
#[derive(Default)]
pub(crate) struct LogCollapse {
    runs: HashMap<&'static str, (Instant, u32)>,
}

impl LogCollapse {
    /// The line to print for this occurrence of `key`, or None to swallow it.
    /// The first occurrence prints; later ones within [`COLLAPSE_WINDOW`] are
    /// counted; the first after the window prints with that count.
    pub(crate) fn admit(&mut self, key: &'static str, line: &str, now: Instant) -> Option<String> {
        match self.runs.get_mut(key) {
            None => {
                self.runs.insert(key, (now, 0));
                Some(line.to_string())
            }
            Some((start, n)) if now.saturating_duration_since(*start) < COLLAPSE_WINDOW => {
                *n += 1;
                None
            }
            Some((start, n)) => {
                let swallowed = *n;
                let over = now.saturating_duration_since(*start).as_secs();
                *start = now;
                *n = 0;
                Some(if swallowed == 0 {
                    line.to_string()
                } else {
                    format!("{line} (and {swallowed} more like it in the last {over}s)")
                })
            }
        }
    }
}

/// What the daemon knows about its signaling link right now.
#[derive(Default)]
struct Health {
    /// False until the daemon's serving loop starts tracking.
    tracked: bool,
    connected: bool,
    /// When the current state (connected or not) began.
    since: Option<Instant>,
    /// Successful re-dials, newest last, pruned to [`FLAP_WINDOW`].
    redials: VecDeque<Instant>,
    last_reason: Option<String>,
}

static HEALTH: Mutex<Option<Health>> = Mutex::new(None);

fn with_health<R>(f: impl FnOnce(&mut Health) -> R) -> R {
    let mut g = HEALTH.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Health::default))
}

/// The serving loop starts with a connected link.
pub(crate) fn note_serving() {
    with_health(|h| {
        h.tracked = true;
        h.connected = true;
        h.since = Some(Instant::now());
    });
}

/// The current link is down (closed, or silent past the watchdog).
pub(crate) fn note_down(reason: &str) {
    with_health(|h| {
        h.tracked = true;
        if h.connected {
            h.since = Some(Instant::now());
        }
        h.connected = false;
        h.last_reason = Some(reason.to_string());
    });
}

/// A re-dial connected.
pub(crate) fn note_redialed() {
    with_health(|h| {
        let now = Instant::now();
        h.tracked = true;
        h.connected = true;
        h.since = Some(now);
        h.redials.push_back(now);
        while h.redials.front().is_some_and(|t| now.saturating_duration_since(*t) > FLAP_WINDOW) {
            h.redials.pop_front();
        }
    });
}

/// The word for a link's state. Pure, so the thresholds are testable.
pub(crate) fn state_word(tracked: bool, connected: bool, redials_in_window: usize) -> &'static str {
    match (tracked, connected) {
        (false, _) => "unknown",
        (true, false) => "reconnecting",
        (true, true) if redials_in_window >= FLAP_THRESHOLD => "flapping",
        (true, true) => "connected",
    }
}

/// The `signaling` object of the daemon's `cap-status` reply.
pub(crate) fn snapshot_json() -> Value {
    with_health(|h| {
        let now = Instant::now();
        let recent = h
            .redials
            .iter()
            .filter(|t| now.saturating_duration_since(**t) <= FLAP_WINDOW)
            .count();
        json!({
            "state": state_word(h.tracked, h.connected, recent),
            "connected": h.connected,
            "for_secs": h.since.map(|s| now.saturating_duration_since(s).as_secs()),
            "redials_window_secs": FLAP_WINDOW.as_secs(),
            "redials": recent,
            "last_reason": h.last_reason,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The storm's mechanism, as a sequence: connection 1 is replaced by 2, then
    /// 1's close arrives. It must not count as 2 going down.
    #[test]
    fn a_late_close_of_a_replaced_connection_is_not_the_current_one() {
        assert!(!close_is_current(1, 2));
        assert!(close_is_current(2, 2));
    }

    #[test]
    fn backoff_grows_is_bounded_and_never_tight() {
        let mid: Vec<u64> = (0..10).map(|a| reconnect_delay(a, 0.5).as_millis() as u64).collect();
        assert_eq!(mid, vec![500, 1000, 2000, 4000, 8000, 15000, 15000, 15000, 15000, 15000]);
        for a in [0, 1, 5, 40, u32::MAX] {
            for u in [0.0, 0.25, 0.999, 1.0, f64::NAN, -3.0] {
                let d = reconnect_delay(a, u);
                assert!(d >= Duration::from_millis(375), "attempt {a} unit {u}: {d:?}");
                assert!(d <= Duration::from_millis(18_750), "attempt {a} unit {u}: {d:?}");
            }
        }
        // Jitter actually spreads the delay.
        assert!(reconnect_delay(3, 0.0) < reconnect_delay(3, 0.99));
    }

    #[test]
    fn jitter_is_in_range() {
        for _ in 0..100 {
            let u = jitter_unit();
            assert!((0.0..1.0).contains(&u));
        }
    }

    /// The defect: a reconnect's own welcome reset the ladder, so a link that
    /// dropped right after each re-dial was re-dialed at full speed forever.
    #[test]
    fn only_a_stable_connection_resets_the_ladder() {
        assert_eq!(attempt_after_close(5, Some(Duration::from_millis(400))), 5);
        assert_eq!(attempt_after_close(5, None), 5);
        assert_eq!(attempt_after_close(5, Some(STABLE_AFTER)), 0);
        // Simulate the storm's cadence: close 0.4 s after every re-dial. The
        // delays must climb to the cap, not stay at the first rung.
        let mut attempt = 0;
        let mut waits = Vec::new();
        for _ in 0..8 {
            attempt = attempt_after_close(attempt, Some(Duration::from_millis(400)));
            waits.push(reconnect_delay(attempt, 0.5));
            attempt += 1;
        }
        assert_eq!(*waits.last().unwrap(), MAX_BACKOFF);
    }

    #[test]
    fn repeats_collapse_and_report_their_count() {
        let mut c = LogCollapse::default();
        let t0 = Instant::now();
        assert_eq!(c.admit("k", "down", t0).as_deref(), Some("down"));
        for i in 1..=140u64 {
            assert!(c.admit("k", "down", t0 + Duration::from_millis(400 * i)).is_none());
        }
        let after = c.admit("k", "down", t0 + COLLAPSE_WINDOW + Duration::from_secs(1)).unwrap();
        assert!(after.starts_with("down (and 140 more like it in the last "), "{after}");
        // Another key is independent.
        assert_eq!(c.admit("other", "up", t0).as_deref(), Some("up"));
        // A quiet window prints plainly.
        let later = t0 + COLLAPSE_WINDOW * 3;
        assert_eq!(c.admit("k", "down", later).as_deref(), Some("down"));
    }

    #[test]
    fn state_words() {
        assert_eq!(state_word(false, true, 0), "unknown");
        assert_eq!(state_word(true, false, 0), "reconnecting");
        assert_eq!(state_word(true, true, FLAP_THRESHOLD - 1), "connected");
        assert_eq!(state_word(true, true, FLAP_THRESHOLD), "flapping");
    }
}
