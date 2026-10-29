//! The stuck-link retry ladder's timing: how long to wait, and the armed timer.
//!
//! The ladder itself lives in `Conn::on_stuck`/`Conn::on_retry_due`; these two
//! are the parts with no host in them. `schedule_retry` is here rather than in the
//! caller because the mistake it fixes is a timing one that recurred: sleeping the
//! backoff inline on the event loop froze every control request, peer exec and
//! signaling event behind it (measured: ctl latency up to 4008ms against 7-10ms
//! normal, the loop frozen ~30% of the time with 2-3 ladders). The wait happens on
//! a spawned task; the loop only receives the `Ev::RetryLink` when it is due.

use std::time::Duration;

use filament_transport::net::Ev;
use tokio::sync::mpsc;

/// Backoff before retry `attempts` of the stuck-link ladder: 1, 2, 4, 8s,
/// capped at 10s.
pub fn stuck_backoff(attempts: u32) -> Duration {
    std::cmp::min(
        Duration::from_secs(2u64.pow(attempts.saturating_sub(1).min(16))),
        Duration::from_secs(10),
    )
}

/// Arm the retry-ladder timer: after `backoff`, post `Ev::RetryLink(pid,
/// generation)` to the event loop. Returns immediately; the wait happens on
/// a spawned task, never on the loop.
pub fn schedule_retry(
    tx: &mpsc::UnboundedSender<Ev>,
    pid: &str,
    generation: u32,
    backoff: Duration,
) {
    let tx = tx.clone();
    let pid = pid.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(backoff).await;
        let _ = tx.send(Ev::RetryLink(pid, generation));
    });
}

/// First re-send of a code-ceremony message, and the cap its backoff doubles to.
pub(crate) const RESEND_FIRST: Duration = Duration::from_millis(250);
pub(crate) const RESEND_CAP: Duration = Duration::from_secs(2);

/// Re-send pacing for a code ceremony's current outbound message (our SPAKE2
/// element, then our confirmation). C30: no single emit may be load-bearing, and
/// these went out exactly once, so one dropped relay frame left both sides
/// waiting out the whole ceremony budget. The ceremony re-sends the SAME bytes
/// at 250ms, 500ms, 1s, then every 2s until the next step is observed; it never
/// mints anything per retry, so a re-send is never another password guess.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Resend {
    next: Option<std::time::Instant>,
    step: u32,
}

impl Resend {
    /// A new message just went out: its first re-send is `RESEND_FIRST` away.
    pub(crate) fn arm(&mut self, now: std::time::Instant) {
        self.step = 0;
        self.next = Some(now + RESEND_FIRST);
    }

    /// Whether a re-send is due at `now`. Advances the backoff when it is.
    pub(crate) fn due(&mut self, now: std::time::Instant) -> bool {
        match self.next {
            Some(at) if now >= at => {
                self.step = self.step.saturating_add(1);
                let wait = RESEND_FIRST
                    .saturating_mul(1u32 << self.step.min(8))
                    .min(RESEND_CAP);
                self.next = Some(now + wait);
                true
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod resend_tests {
    use super::*;

    #[test]
    fn ceremony_resend_backs_off_and_caps() {
        let t0 = std::time::Instant::now();
        let mut r = Resend::default();
        assert!(!r.due(t0 + Duration::from_secs(60)), "never armed: never due");
        r.arm(t0);
        assert!(!r.due(t0 + Duration::from_millis(249)));
        let mut at = t0 + RESEND_FIRST;
        let mut gaps = Vec::new();
        for _ in 0..6 {
            assert!(r.due(at));
            assert!(!r.due(at), "one re-send per due slot");
            let next = r.next.unwrap();
            gaps.push(next - at);
            at = next;
        }
        let ms: Vec<u128> = gaps.iter().map(|d| d.as_millis()).collect();
        assert_eq!(ms, vec![500, 1000, 2000, 2000, 2000, 2000]);
    }
}
