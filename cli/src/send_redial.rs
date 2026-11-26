//! Bringing a one-shot send's signaling back after the server was unreachable.
//!
//! A send to a paired device that starts while the server is down runs on an
//! offline client (`filament_signal::Client::offline`) and meets its target on
//! the local network. A send whose server drops mid-transfer keeps a client
//! whose socket is gone. Either way, if the data link then dies, the only
//! re-dials left (the stall ladder's direct QUIC, a fresh offer, the target's
//! presence) all ride signaling, so the send printed "trying to reconnect"
//! while nothing could reconnect, and outlived the server's return
//! (chaos finding 22b3f2a918). The daemon loop re-dials its signaling; this is
//! the same re-dial, paced the same way, for the send.
//!
//! The local network is retried as well while the server is unreachable, so
//! a send whose LAN link dropped is not left waiting for the sweep (minutes)
//! to find its target again.

use std::time::{Duration, Instant};

use filament_peerloop::recv::signaling_health;

/// How often a send with no live link re-dials its target's remembered
/// addresses while the server is unreachable. Shorter than the daemon's 15 s:
/// a send has a person (or a script) waiting on it.
pub(crate) const LAN_REDIAL_EVERY: Duration = Duration::from_secs(5);

/// The bound on one signaling connect attempt, so a server that accepts TCP
/// and never answers cannot park the re-dial.
pub(crate) const CONNECT_BOUND: Duration = Duration::from_secs(10);

/// Whether the send's signaling is down, and when to try it again.
#[derive(Debug)]
pub(crate) struct Redial {
    down_since: Option<Instant>,
    attempt: u32,
    wait: Duration,
    last_try: Instant,
    last_lan: Option<Instant>,
}

impl Redial {
    /// `started_offline`: the send never reached the server, so its client is
    /// the offline stand-in and must be replaced as soon as the server answers.
    pub(crate) fn new(started_offline: bool, now: Instant) -> Redial {
        Redial {
            down_since: started_offline.then_some(now),
            attempt: 0,
            wait: signaling_health::reconnect_delay(0, signaling_health::jitter_unit()),
            last_try: now,
            last_lan: None,
        }
    }

    pub(crate) fn is_down(&self) -> bool {
        self.down_since.is_some()
    }

    /// The close of connection `closed` arrived; `current` is the client the
    /// send holds. A close of a client already replaced is history.
    pub(crate) fn on_close(&mut self, closed: u64, current: u64, now: Instant) -> bool {
        if !signaling_health::close_is_current(closed, current) || self.down_since.is_some() {
            return false;
        }
        self.down_since = Some(now);
        self.wait = signaling_health::reconnect_delay(self.attempt, signaling_health::jitter_unit());
        self.last_try = now;
        true
    }

    /// Time for another connect attempt? `in_flight`: one is still running.
    pub(crate) fn due(&self, in_flight: bool, now: Instant) -> bool {
        self.down_since.is_some() && !in_flight && now.saturating_duration_since(self.last_try) >= self.wait
    }

    /// A connect attempt starts now; the next one waits longer.
    pub(crate) fn tried(&mut self, now: Instant) {
        self.last_try = now;
        self.attempt = self.attempt.saturating_add(1);
        self.wait = signaling_health::reconnect_delay(self.attempt, signaling_health::jitter_unit());
    }

    /// The server answered: signaling is up again.
    pub(crate) fn up(&mut self) {
        self.down_since = None;
        self.attempt = 0;
    }

    /// Re-dial the target on the local network now? Only while the server is
    /// unreachable (`lan_offline`), the send has a local-discovery service, no
    /// live link to the target exists, and the last re-dial is old enough.
    pub(crate) fn lan_due(&mut self, lan_offline: bool, has_service: bool, linked: bool, now: Instant) -> bool {
        if !lan_offline || !has_service || linked {
            return false;
        }
        if self.last_lan.is_some_and(|t| now.saturating_duration_since(t) < LAN_REDIAL_EVERY) {
            return false;
        }
        // The first dial at start already went out; a link that was never
        // up is still being dialed, so the clock starts at the first check.
        let first = self.last_lan.is_none();
        self.last_lan = Some(now);
        !first
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_send_started_while_the_server_was_down_redials_it() {
        let t0 = Instant::now();
        let r = Redial::new(true, t0);
        assert!(r.is_down());
        assert!(!r.due(false, t0), "not in a tight loop at start");
        assert!(r.due(false, t0 + Duration::from_secs(1)), "the first re-dial is within the base backoff");
        assert!(!r.due(true, t0 + Duration::from_secs(1)), "never two connects at once");
    }

    #[test]
    fn a_send_that_reached_the_server_does_not_redial_until_it_closes() {
        let t0 = Instant::now();
        let mut r = Redial::new(false, t0);
        assert!(!r.due(false, t0 + Duration::from_secs(60)));
        assert!(!r.on_close(3, 4, t0), "a replaced client's close is history");
        assert!(!r.is_down());
        assert!(r.on_close(4, 4, t0));
        assert!(r.due(false, t0 + Duration::from_secs(1)));
    }

    #[test]
    fn re_dials_back_off_and_recovery_ends_them() {
        let t0 = Instant::now();
        let mut r = Redial::new(true, t0);
        let mut now = t0;
        for _ in 0..8 {
            now += Duration::from_secs(20);
            assert!(r.due(false, now), "the backoff is capped below 20 s, so the server's return is always seen");
            r.tried(now);
            assert!(!r.due(false, now + Duration::from_millis(300)));
        }
        r.up();
        assert!(!r.is_down());
        assert!(!r.due(false, now + Duration::from_secs(60)));
    }

    #[test]
    fn the_local_network_is_retried_only_while_offline_and_unlinked() {
        let t0 = Instant::now();
        let mut r = Redial::new(true, t0);
        assert!(!r.lan_due(true, true, false, t0), "the start dial is the first");
        assert!(!r.lan_due(true, true, false, t0 + Duration::from_secs(1)));
        assert!(r.lan_due(true, true, false, t0 + LAN_REDIAL_EVERY));
        let later = t0 + LAN_REDIAL_EVERY * 3;
        assert!(!r.lan_due(true, true, true, later), "a live link needs no re-dial");
        assert!(!r.lan_due(false, true, false, later), "with the server up, signaling re-dials");
        assert!(!r.lan_due(true, false, false, later), "no local discovery, nothing to dial");
        assert!(r.lan_due(true, true, false, later));
    }
}
