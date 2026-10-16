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
