//! One pairing code's single-winner state.
//!
//! A code can be advertised by two carriers at once (signaling and LAN). Both
//! are untrusted until the PAKE confirms, and only one may ever store a device.
//! This object is the one place that decides: every attempt takes a fresh token
//! before its first frame, and only a token that is still current and inside
//! BOTH the code deadline and its own ceremony deadline may confirm.
//!
//! No lock is held across an await: the callers use short synchronous
//! transitions and do their I/O outside.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The code's lifetime, the same 10 minutes the signaling server uses.
pub const CODE_TTL: Duration = Duration::from_secs(600);
/// One ceremony's budget once a carrier starts it.
pub const CEREMONY_BUDGET: Duration = Duration::from_secs(60);
/// Backoff between failed attempts. It never closes the code; the deadline does.
const BACKOFF_BASE_MS: u64 = 500;
const BACKOFF_MAX_MS: u64 = 8_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Carrier {
    Signaling,
    Lan,
}

impl Carrier {
    pub fn as_str(self) -> &'static str {
        match self {
            Carrier::Signaling => "signaling",
            Carrier::Lan => "lan",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Begin {
    Started(u64),
    Busy,
    Closed,
}

#[derive(Debug)]
struct Active {
    token: u64,
    carrier: Carrier,
    attempt_deadline: Instant,
}

#[derive(Debug)]
enum Phase {
    Open,
    Active(Active),
    Consumed(Carrier),
    Closed(&'static str),
}

struct State {
    pairing_id: [u8; 16],
    deadline: Instant,
    phase: Phase,
    failures: u32,
    next_attempt_at: Instant,
}

/// Shared by the signaling and LAN carriers of one code.
#[derive(Clone)]
pub struct PairCode {
    inner: Arc<Mutex<State>>,
}

impl PairCode {
    pub fn new(pairing_id: [u8; 16], now: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                pairing_id,
                deadline: now + CODE_TTL,
                phase: Phase::Open,
                failures: 0,
                next_attempt_at: now,
            })),
        }
    }

    /// The four-digit label both screens show beside the code. It derives from
    /// the pairing id, never from the code.
    pub fn label(&self) -> String {
        tunlion_lan::wire::pairing_label(&self.inner.lock().unwrap().pairing_id)
    }

    pub fn pairing_id(&self) -> [u8; 16] {
        self.inner.lock().unwrap().pairing_id
    }

    pub fn deadline(&self) -> Instant {
        self.inner.lock().unwrap().deadline
    }

    /// Start a ceremony. The caller must send no PAKE frame and store nothing
    /// before this returns `Started`.
    pub fn begin(&self, carrier: Carrier, now: Instant) -> Begin {
        let mut g = self.inner.lock().unwrap();
        if matches!(g.phase, Phase::Consumed(_) | Phase::Closed(_)) {
            return Begin::Closed;
        }
        if now >= g.deadline {
            g.phase = Phase::Closed("code expired");
            return Begin::Closed;
        }
        if now < g.next_attempt_at {
            return Begin::Busy;
        }
        if matches!(g.phase, Phase::Active(_)) {
            return Begin::Busy;
        }
        let token = fresh_token();
        let attempt_deadline = (now + CEREMONY_BUDGET).min(g.deadline);
        g.phase = Phase::Active(Active { token, carrier, attempt_deadline });
        Begin::Started(token)
    }

    /// The single compare-and-set. `now` is checked against the code deadline
    /// and this attempt's deadline under the same lock, so a select timer that
    /// fires late cannot let an expired ceremony win.
    pub fn confirm(&self, token: u64, now: Instant) -> bool {
        let mut g = self.inner.lock().unwrap();
        let Active { token: current, carrier, attempt_deadline } = match &g.phase {
            Phase::Active(a) => a,
            _ => return false,
        };
        if *current != token || now >= *attempt_deadline || now >= g.deadline {
            return false;
        }
        let carrier = *carrier;
        g.phase = Phase::Consumed(carrier);
        true
    }

    /// A failed attempt releases the slot without consuming the code. The
    /// backoff uses saturating math and never disables the code.
    pub fn fail(&self, token: u64, now: Instant) {
        let mut g = self.inner.lock().unwrap();
        let current = match &g.phase {
            Phase::Active(a) => a.token,
            _ => return,
        };
        if current != token {
            return;
        }
        g.failures = g.failures.saturating_add(1);
        let shift = g.failures.min(4);
        let backoff_ms = BACKOFF_BASE_MS.saturating_mul(1u64 << shift).min(BACKOFF_MAX_MS);
        g.next_attempt_at = now + Duration::from_millis(backoff_ms);
        g.phase = Phase::Open;
    }

    /// Stop this code. Reached by expiry, Ctrl-C and after a confirmed winner.
    pub fn close(&self, reason: &'static str) {
        let mut g = self.inner.lock().unwrap();
        if !matches!(g.phase, Phase::Consumed(_) | Phase::Closed(_)) {
            g.phase = Phase::Closed(reason);
        }
    }

    pub fn winner(&self) -> Option<Carrier> {
        match &self.inner.lock().unwrap().phase {
            Phase::Consumed(c) => Some(*c),
            _ => None,
        }
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.inner.lock().unwrap().phase, Phase::Consumed(_) | Phase::Closed(_))
    }

    #[cfg(test)]
    fn failures(&self) -> u32 {
        self.inner.lock().unwrap().failures
    }
}

/// Process-unique, non-repeating attempt tokens. They are not secrets; they
/// only make a stale carrier's outcome distinguishable from the current one.
fn fresh_token() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code() -> PairCode {
        PairCode::new([7; 16], Instant::now())
    }

    #[test]
    fn one_winner_and_only_before_both_deadlines() {
        let c = code();
        let t0 = Instant::now();
        let token = match c.begin(Carrier::Lan, t0) {
            Begin::Started(t) => t,
            other => panic!("{other:?}"),
        };
        assert!(c.confirm(token, t0 + Duration::from_secs(1)));
        assert_eq!(c.winner(), Some(Carrier::Lan));
        assert!(!c.confirm(token, t0 + Duration::from_secs(2)), "second confirm");
        assert_eq!(c.begin(Carrier::Signaling, t0 + Duration::from_secs(2)), Begin::Closed);
    }

    #[test]
    fn a_late_confirm_does_not_win() {
        let c = code();
        let t0 = Instant::now();
        let token = match c.begin(Carrier::Signaling, t0) {
            Begin::Started(t) => t,
            other => panic!("{other:?}"),
        };
        assert!(!c.confirm(token, t0 + CEREMONY_BUDGET + Duration::from_millis(1)));
        assert_eq!(c.winner(), None);
    }

    #[test]
    fn failed_attempts_release_without_consuming() {
        let c = code();
        let t0 = Instant::now();
        for i in 0..10 {
            let token = match c.begin(Carrier::Lan, t0 + Duration::from_secs(i * 10)) {
                Begin::Started(t) => t,
                other => panic!("attempt {i}: {other:?}"),
            };
            c.fail(token, t0 + Duration::from_secs(i * 10));
        }
        assert_eq!(c.failures(), 10);
        assert!(!c.is_closed());
        // Still open after the backoff, and the deadline is the only closer.
        assert!(matches!(c.begin(Carrier::Signaling, t0 + Duration::from_secs(200)), Begin::Started(_)));
    }

    #[test]
    fn busy_while_active() {
        let c = code();
        let t0 = Instant::now();
        assert!(matches!(c.begin(Carrier::Lan, t0), Begin::Started(_)));
        assert_eq!(c.begin(Carrier::Signaling, t0), Begin::Busy);
    }

    #[test]
    fn tokens_do_not_repeat() {
        let c = code();
        let t0 = Instant::now();
        let a = match c.begin(Carrier::Lan, t0) { Begin::Started(t) => t, _ => panic!() };
        c.fail(a, t0);
        let b = match c.begin(Carrier::Lan, t0 + Duration::from_secs(5)) { Begin::Started(t) => t, _ => panic!() };
        assert_ne!(a, b);
    }
}
