//! Process adapters owned by one CLI receive invocation. Not library lifecycle.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};

use filament_peerloop::host::LogSink;

pub(super) use crate::platform::recv_signals::Signals;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ControlReadyError {
    SenderDropped,
    TimedOut,
}

/// This checks only the existing CLI control-listener edge, not driver readiness.
pub(super) async fn control_ready(
    ready: tokio::sync::oneshot::Receiver<()>,
    timeout: std::time::Duration,
) -> Result<(), ControlReadyError> {
    match tokio::time::timeout(timeout, ready).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(ControlReadyError::SenderDropped),
        Err(_) => Err(ControlReadyError::TimedOut),
    }
}

#[derive(Default)]
pub(super) struct Tasks(Vec<tokio::task::JoinHandle<()>>);

impl Tasks {
    pub(super) fn push(&mut self, task: tokio::task::JoinHandle<()>) {
        self.0.push(task);
    }

    pub(super) async fn stop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
        for task in self.0.drain(..) {
            let _ = task.await;
        }
    }
}

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// How often an idle watchdog observes the loop's heartbeat.
const WATCHDOG_OBSERVE_EVERY: std::time::Duration = std::time::Duration::from_secs(1);
/// Upper bound on joining the watchdog in cleanup. Dropping its stop sender
/// wakes it immediately; this is only a backstop for a blocking log sink.
const WATCHDOG_STOP_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// The receive loop's stall watchdog, owned by one invocation.
///
/// A plain OS thread, deliberately not a runtime task: a task cannot run while
/// the loop it watches is wedged. `tick` stamps the heartbeat and starts the
/// observer once; `stop` asks it to exit and joins it. Dropping without `stop`
/// also asks it to exit (dropping the channel disconnects it) but does not
/// wait, so the cleanup epilogue must call `stop`.
pub(super) struct LoopWatchdog {
    last_tick_ms: Arc<AtomicU64>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    observe_every: std::time::Duration,
    threshold_secs: u64,
}

impl Default for LoopWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopWatchdog {
    pub(super) fn new() -> Self {
        Self::with_limits(WATCHDOG_OBSERVE_EVERY, threshold_secs())
    }

    /// Test seam: the production limits are one second and the env threshold.
    fn with_limits(observe_every: std::time::Duration, threshold_secs: u64) -> Self {
        Self {
            last_tick_ms: Arc::new(AtomicU64::new(0)),
            stop: None,
            thread: None,
            observe_every,
            threshold_secs,
        }
    }

    /// Stamp this iteration. The first call starts the observer; later calls
    /// only move the heartbeat.
    pub(super) fn tick(&mut self, log: Arc<dyn LogSink>) {
        self.last_tick_ms.store(now_ms(), Ordering::Relaxed);
        if self.thread.is_some() {
            return;
        }
        let (stop, stopped) = mpsc::channel();
        let last_tick_ms = Arc::clone(&self.last_tick_ms);
        let observe_every = self.observe_every;
        let threshold_secs = self.threshold_secs;
        let spawned = std::thread::Builder::new()
            .name("loop-watchdog".into())
            .spawn(move || {
                observe(last_tick_ms, stopped, observe_every, threshold_secs, log);
            });
        if let Ok(thread) = spawned {
            self.stop = Some(stop);
            self.thread = Some(thread);
        }
        // A failed spawn leaves the heartbeat stamped but no observer, as
        // before: this is a diagnostic, not a serving guarantee.
    }

    /// Ask the observer to exit and join it with a bounded wait. Returns
    /// whether the thread was joined; on timeout it has still been asked to
    /// stop and the detached thread exits as soon as its log sink returns.
    /// Repeated calls are harmless.
    pub(super) async fn stop(&mut self) -> bool {
        // Dropping the sender disconnects the receiver, so a sleeping observer
        // wakes at once instead of waiting out `observe_every`.
        self.stop.take();
        let Some(thread) = self.thread.take() else {
            return true;
        };
        matches!(
            tokio::time::timeout(
                WATCHDOG_STOP_BOUND,
                tokio::task::spawn_blocking(move || thread.join()),
            )
            .await,
            Ok(Ok(_))
        )
    }
}

impl Drop for LoopWatchdog {
    fn drop(&mut self) {
        // Non-blocking fallback: wake the observer and detach its handle.
        // `stop` is the path that proves the thread has terminated.
        self.stop.take();
    }
}

fn observe(
    last_tick_ms: Arc<AtomicU64>,
    stopped: mpsc::Receiver<()>,
    observe_every: std::time::Duration,
    threshold_secs: u64,
    log: Arc<dyn LogSink>,
) {
    let mut reported = false;
    loop {
        match stopped.recv_timeout(observe_every) {
            Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        let last = last_tick_ms.load(Ordering::Relaxed);
        let stalled = now_ms().saturating_sub(last) / 1000;
        if stalled >= threshold_secs && !reported {
            log.critical(&format!(
                "event loop stalled: no iteration for {stalled}s (an await inside the daemon loop never completed); the daemon is not serving until it recovers"
            ));
            reported = true;
        } else if stalled < threshold_secs && reported {
            log.critical("event loop recovered");
            reported = false;
        }
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Seconds without a tick before the watchdog speaks.
/// `TUNLION_LOOP_STALL_SECS` overrides (gates).
fn threshold_secs() -> u64 {
    std::env::var("TUNLION_LOOP_STALL_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(20)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_peerloop::driver::{Cancellation, DriverOutcome};

    #[tokio::test]
    async fn control_readiness_requires_success_not_drop_or_timeout() {
        use std::time::Duration;
        let (tx, rx) = tokio::sync::oneshot::channel();
        tx.send(()).unwrap();
        assert_eq!(control_ready(rx, Duration::from_secs(1)).await, Ok(()));
        let (tx, rx) = tokio::sync::oneshot::channel();
        drop(tx);
        assert_eq!(
            control_ready(rx, Duration::from_secs(1)).await,
            Err(ControlReadyError::SenderDropped)
        );
        let (_tx, rx) = tokio::sync::oneshot::channel();
        assert_eq!(
            control_ready(rx, Duration::ZERO).await,
            Err(ControlReadyError::TimedOut)
        );
    }

    struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }

    #[tokio::test]
    async fn completion_waits_for_owned_task_cleanup_after_cancellation() {
        let stop = Cancellation::default();
        let request = stop.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (dropped_tx, dropped_rx) = tokio::sync::oneshot::channel();
        let invocation = tokio::spawn(async move {
            let mut tasks = Tasks::default();
            tasks.push(tokio::spawn(async move {
                let _guard = OnDrop(Some(dropped_tx));
                entered_tx.send(()).unwrap();
                std::future::pending::<()>().await;
            }));
            let outcome = stop.run(std::future::pending::<()>()).await;
            tasks.stop().await;
            outcome
        });
        entered_rx.await.unwrap();
        request.cancel();
        assert_eq!(invocation.await.unwrap(), DriverOutcome::Cancelled);
        // try_recv (not await): completion already guarantees the destructor ran.
        let mut dropped_rx = dropped_rx;
        assert_eq!(dropped_rx.try_recv(), Ok(()));
    }

    #[tokio::test]
    async fn watchdog_stop_wakes_and_joins_its_observer() {
        use filament_peerloop::host::NoLog;
        use std::time::Duration;
        // A 30 s observation interval makes the join meaningful: only the
        // disconnect wake can let stop return within its one-second bound.
        let mut watchdog = LoopWatchdog::with_limits(Duration::from_secs(30), 20);
        watchdog.tick(Arc::new(NoLog));
        assert!(watchdog.stop().await);
        // Repeated stop shares the completion and does not spawn again.
        assert!(watchdog.stop().await);
    }

    #[tokio::test]
    async fn watchdog_stop_before_first_tick_is_thread_free() {
        let mut watchdog = LoopWatchdog::new();
        assert!(watchdog.stop().await);
    }
}
