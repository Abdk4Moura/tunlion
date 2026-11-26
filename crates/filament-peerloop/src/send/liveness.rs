//! What `send` says, and how long it really waits, when its receiver goes away.
//!
//! The blind run found three untrue sentences here: "the other device
//! disconnected, waiting up to 120s" (the wait was the 45 s unannounced rejoin
//! window, and the sender gave up after ~15 s anyway, through the delivery-ack
//! fallback), a roster line that read as an empty name ("the other device
//! disconnected"), and a wait for a code receiver that could never return
//! because its code had burned. The sentences are built here, from the window
//! the sender actually enforces.

/// The line when the receiver disconnects mid-transfer. `who` is its name when
/// it has a real one; `by_code` is a send to a one-time code.
pub fn disconnect_line(who: Option<&str>, secs: u64, by_code: bool) -> String {
    let who = who
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map(|n| format!("'{n}'"))
        .unwrap_or_else(|| "the receiver".to_string());
    let mut line = format!("  {who} disconnected; waiting up to {secs}s for it to come back");
    if by_code {
        line.push_str(
            ". The code is used up, so `receive <code>` cannot rejoin: if it does not come back, \
             run the same `tunlion send` again for a new code",
        );
    }
    line
}

/// The error when the receiver did not come back within the window. Says
/// "unreachable" (exit 6 under the taxonomy) and the one way on that works.
pub fn receiver_gone_message(secs: u64, by_code: bool) -> String {
    let way_on = if by_code {
        "The code is used up: run the same `tunlion send` again for a new code. A receiver that \
         kept a partial and receives into the same folder continues from it"
    } else {
        "Run the same `tunlion send` again once it is back; it continues from any partial the \
         receiver kept"
    };
    format!("the receiver is unreachable: it disconnected and did not come back within {secs}s. {way_on}")
}

/// The error when the stall ladder runs out of attempts on the active link.
/// Pure. `down_secs` is how long the link has been down when a channel had
/// been up, None when none ever was.
///
/// Once a channel was up, the receiver went away mid-send, and the end says
/// so the way the link-down clock does: unreachable, with the way on for a
/// spent code. When a dead channel started counting as a stall (so the ladder
/// re-dials it), a frozen receiver used up the re-dials well inside the rejoin
/// window, and the send ended with "lost the receiving peer ... re-run the same
/// `tunlion send`", which for a code send is advice that cannot work: the code
/// is spent (gate 11). Before any channel came up, nothing was ever reached
/// and the attempt count is the honest account.
pub fn ladder_exhausted_message(down_secs: Option<u64>, attempts: u32, by_code: bool) -> String {
    match down_secs {
        Some(secs) => receiver_gone_message(secs, by_code),
        None => format!(
            "lost the receiving peer after {attempts} attempts; the partial is kept, re-run the same `tunlion send` to resume"
        ),
    }
}

/// How often a send that is waiting says so. `exec` uses the same 7 s.
pub const HEARTBEAT: std::time::Duration = std::time::Duration::from_secs(7);

/// How long a send keeps looking for its receiver once the link it had is
/// gone, when the receiver neither left the server nor said it was stepping
/// away. Before this the bound was the 120 s `REJOIN_WINDOW` (the window is
/// only shortened when a peer-left arrives), so a send whose link died while
/// the receiver stayed on the server ran past any bound a caller could hold:
/// chaos findings 22b3f2a918 and 83e2d5588e, a warm send whose daemon link
/// died and whose re-dials never landed, still "trying to reconnect" at 90 s.
/// Long enough for the daemon's repair (`WARM_RETRY_WINDOW`, 30 s) and a dial
/// of the send's own after it; with the time to notice a dead link (at most
/// about 20 s) it ends a send well inside 90 s.
pub const LINK_DOWN_WINDOW: std::time::Duration = std::time::Duration::from_secs(45);

/// How long a link that came back must stay up before the down clock restarts.
/// A dial that connects and dies again within seconds is not the receiver
/// back: when each such flap restarted the clock, a send kept re-dialing past
/// any bound (the debug replay of 83e2d5588e: a local-network link up for 7 s,
/// then three more dials).
pub const LINK_UP_CONFIRM: std::time::Duration = std::time::Duration::from_secs(10);

/// The window the down clock enforces. A receiver that left the server
/// (`receiver_left`) or announced that it steps away (`away`) gets the rejoin
/// window opened for it (`rejoin_window`, the one the send printed). Otherwise
/// the shorter of that window and [`LINK_DOWN_WINDOW`]. Pure.
pub fn link_down_window(
    rejoin_window: std::time::Duration,
    receiver_left: bool,
    away: bool,
) -> std::time::Duration {
    if receiver_left || away {
        rejoin_window
    } else {
        rejoin_window.min(LINK_DOWN_WINDOW)
    }
}

/// How long the send's link to its receiver has been down, across every way
/// it can be: no transport, a dead one, or one whose receiver (a peer that
/// keepalives) has been silent for the whole window. One clock for the warm
/// link, the wait for the daemon's repaired link and the send's own dials, so
/// moving between them never restarts it; only a link that stays up for
/// [`LINK_UP_CONFIRM`] does.
#[derive(Debug, Default, Clone)]
pub struct DownClock {
    down_since: Option<std::time::Instant>,
    up_since: Option<std::time::Instant>,
}

impl DownClock {
    /// Feed one observation at `now`. `down`: there is no live link. `silent`:
    /// how long a receiver that keepalives has sent nothing on the link that
    /// reads up (None when its silence means nothing). Returns true when the
    /// link counts as down. Silence of at least `window` is down, and dates
    /// the clock from the last time the receiver was heard.
    pub fn observe(
        &mut self,
        now: std::time::Instant,
        down: bool,
        silent: Option<std::time::Duration>,
        window: std::time::Duration,
    ) -> bool {
        let silent_out = silent.filter(|s| *s >= window);
        if down || silent_out.is_some() {
            self.up_since = None;
            let since = self.down_since.get_or_insert(now);
            if let Some(last_heard) = silent_out.and_then(|s| now.checked_sub(s)) {
                if last_heard < *since {
                    *since = last_heard;
                }
            }
            return true;
        }
        let up = *self.up_since.get_or_insert(now);
        if now.saturating_duration_since(up) >= LINK_UP_CONFIRM {
            self.down_since = None;
        }
        false
    }

    /// Since when the link has been down (kept while a link that came back is
    /// not yet confirmed).
    pub fn down_since(&self) -> Option<std::time::Instant> {
        self.down_since
    }

    /// Nothing is owed any more: forget the episode.
    pub fn clear(&mut self) {
        self.down_since = None;
        self.up_since = None;
    }

    /// Down for longer than `window`.
    pub fn expired(&self, now: std::time::Instant, window: std::time::Duration) -> bool {
        self.down_since
            .is_some_and(|s| now.saturating_duration_since(s) > window)
    }
}

/// The progress line for a send that is waiting on its peer, or None when
/// there is nothing to say. A peer frozen or killed mid-send used to mean a
/// minute of silence before the error. `heard_ms` is how long since the peer
/// last sent anything (None when the link does not track it). Pure.
pub fn still_waiting_line(
    peer: &str,
    established: bool,
    elapsed: std::time::Duration,
    heard_ms: Option<u64>,
    unfinished: bool,
) -> Option<String> {
    if !unfinished {
        return None;
    }
    if !established {
        return Some(format!("  still waiting for {peer} to connect ({}s)", elapsed.as_secs()));
    }
    match heard_ms? {
        h if h < HEARTBEAT.as_millis() as u64 => None,
        u64::MAX => Some(format!(
            "  still waiting for {peer}: the link is down, trying to reconnect ({}s)",
            elapsed.as_secs()
        )),
        h => Some(format!("  still waiting for {peer}: no answer for {}s", h / 1000)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_waiting_send_says_so_and_a_flowing_one_does_not() {
        let s = std::time::Duration::from_secs(21);
        let l = still_waiting_line("bravo", false, s, None, true).unwrap();
        assert!(l.contains("still waiting for bravo") && l.contains("21s"), "{l}");
        let l = still_waiting_line("bravo", true, s, Some(14_200), true).unwrap();
        assert!(l.contains("no answer for 14s"), "{l}");
        assert!(still_waiting_line("bravo", true, s, Some(800), true).is_none());
        assert!(still_waiting_line("bravo", true, s, Some(14_200), false).is_none());
        assert!(still_waiting_line("bravo", true, s, None, true).is_none());
    }

    /// The window printed is the window passed in (the one enforced), and an
    /// empty name is never printed as a name.
    #[test]
    fn the_disconnect_line_states_the_real_window_and_a_real_name() {
        let l = disconnect_line(Some(""), 25, false);
        assert!(l.starts_with("  the receiver disconnected; waiting up to 25s"), "{l}");
        assert!(!l.contains("120s") && !l.contains("  disconnected"), "{l}");
        let named = disconnect_line(Some("laptop"), 25, false);
        assert!(named.contains("'laptop' disconnected"), "{named}");
        let code = disconnect_line(None, 25, true);
        assert!(code.contains("code is used up") && code.contains("new code"), "{code}");
    }

    /// A send that had a channel says the receiver is unreachable and, for a
    /// spent code, that a new code is the way on; one that never connected
    /// keeps the attempt count.
    #[test]
    fn an_exhausted_ladder_after_a_link_says_unreachable() {
        let m = ladder_exhausted_message(Some(41), 5, true);
        assert!(m.contains("receiver is unreachable") && m.contains("within 41s"), "{m}");
        assert!(m.contains("new code") && !m.contains("lost the receiving peer"), "{m}");
        let n = ladder_exhausted_message(None, 5, true);
        assert!(n.starts_with("lost the receiving peer after 5 attempts"), "{n}");
    }

    /// Chaos 22b3f2a918 / 83e2d5588e: a send whose receiver never left the
    /// server waited out the 120 s rejoin window; it gets LINK_DOWN_WINDOW. A
    /// receiver that left, or said it steps away, keeps the window it got.
    #[test]
    fn a_receiver_that_did_not_leave_gets_the_link_down_window() {
        use std::time::Duration;
        let rejoin = Duration::from_secs(120);
        assert_eq!(link_down_window(rejoin, false, false), LINK_DOWN_WINDOW);
        assert_eq!(link_down_window(rejoin, true, false), rejoin);
        assert_eq!(link_down_window(rejoin, false, true), rejoin);
        // A shorter window already in force stays.
        let short = Duration::from_secs(10);
        assert_eq!(link_down_window(short, false, false), short);
        // With the time to notice a dead link, the bound ends a send inside
        // the 90 s every chaos send is held to.
        assert!(LINK_DOWN_WINDOW + Duration::from_secs(21) + Duration::from_secs(15) < Duration::from_secs(90));
    }

    /// The 83e2d5588e debug replay: the link went down, a local-network link
    /// came up for 7 s and died, then more dials. Each flap restarted the
    /// clock, so it never ran out. A flap shorter than LINK_UP_CONFIRM keeps
    /// it running; a link that stays up restarts it.
    #[test]
    fn a_flapping_link_does_not_restart_the_down_clock() {
        use std::time::{Duration, Instant};
        let w = LINK_DOWN_WINDOW;
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let mut c = DownClock::default();
        assert!(c.observe(at(20), true, None, w));
        assert!(!c.observe(at(25), false, None, w));
        assert!(!c.observe(at(31), false, None, w));
        assert_eq!(c.down_since(), Some(at(20)), "a 6 s flap is not the receiver back");
        assert!(c.observe(at(32), true, None, w));
        assert!(!c.expired(at(64), w));
        assert!(c.expired(at(66), w), "down since 20 s, window 45 s");
        // A link that stays up for the confirm time restarts the clock.
        let mut c = DownClock::default();
        c.observe(at(20), true, None, w);
        c.observe(at(25), false, None, w);
        c.observe(at(25) + LINK_UP_CONFIRM, false, None, w);
        assert_eq!(c.down_since(), None);
    }

    /// A link that reads up while its receiver has said nothing for the whole
    /// window is down, dated from when the receiver was last heard, so the
    /// send ends now instead of one window later.
    #[test]
    fn a_silent_receiver_counts_as_down_from_when_it_was_last_heard() {
        use std::time::{Duration, Instant};
        let w = LINK_DOWN_WINDOW;
        let t0 = Instant::now();
        let mut c = DownClock::default();
        assert!(!c.observe(t0, false, Some(w - Duration::from_secs(1)), w));
        let now = t0 + Duration::from_secs(1);
        assert!(c.observe(now, false, Some(w + Duration::from_secs(1)), w));
        assert!(c.expired(now, w));
        c.clear();
        assert_eq!(c.down_since(), None);
    }

    #[test]
    fn giving_up_says_unreachable_and_the_way_on() {
        let m = receiver_gone_message(25, true);
        assert!(m.contains("unreachable") && m.contains("within 25s"), "{m}");
        assert!(m.contains("new code"), "{m}");
        assert!(!m.contains("partial state kept"), "{m}");
        let k = receiver_gone_message(25, false);
        assert!(!k.contains("code"), "{k}");
    }
}
