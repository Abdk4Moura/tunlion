//! Process adapters owned by one CLI receive invocation. Not library lifecycle.

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
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

/// The single linearized readiness edge for one receive invocation.
///
/// Published exactly once, immediately before the driver dispatches, after
/// every required initialization. It is deliberately distinct from the console
/// banner and from optional post-dispatch work such as mount restoration:
/// nothing awaited and optional may sit between this edge and entering the
/// loop. The systemd notifier and the `up --detach` ready marker both consume
/// this one edge, so they can no longer disagree about when the daemon became
/// ready. The console banner is still printed earlier, before Conn/sector setup,
/// and is NOT yet unified with this edge.
///
/// A one-shot receive does not publish it: that path has its own
/// transfer-completion and deadline semantics, not an "engine is serving" edge.
#[derive(Default)]
pub(super) struct Readiness {
    published: bool,
}

impl Readiness {
    /// Publish the ready edge and run `announce` exactly once. Returns `true`
    /// only for the publishing call; later calls are no-ops, so a stray
    /// second publication cannot re-announce readiness after startup.
    pub(super) fn publish(&mut self, announce: impl FnOnce()) -> bool {
        if self.published {
            return false;
        }
        self.published = true;
        announce();
        true
    }

    #[cfg(test)]
    pub(super) fn is_published(&self) -> bool {
        self.published
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
/// Best-effort bound on the normal cleanup join. Dropping the stop sender wakes
/// a sleeping observer at once; the bound only matters when the observer is
/// already inside a blocking `LogSink` call.
const WATCHDOG_STOP_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// What happened when an owner asked the observer to stop.
///
/// `Detached` is a real outcome, not success: the observer thread and the
/// blocking waiter joining it may still be alive. The observer retains the
/// `LogSink` Arc until it finally returns from the blocking call and exits;
/// the waiter stays registered until that join completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WatchdogStop {
    /// The observer was never started; no thread or waiter exists.
    NotStarted,
    /// The observer thread was joined.
    Joined,
    /// The join bound expired (or the blocking waiter could not run). The
    /// observer was asked to stop but its thread and waiter were detached.
    Detached,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Idle,
    Running,
    Stopped,
    Detached,
}

/// The daemon loop's stall watchdog: one OS thread plus its stop handle.
///
/// This is a diagnostic thread started by the receive loop, not an owner of
/// receive-driver work. A plain OS thread is deliberate: a runtime task cannot
/// run while the loop it watches is wedged. `tick` stamps the heartbeat and
/// starts the observer once. `stop` drops a wake channel and makes a
/// best-effort bounded join; a timeout detaches the thread and its blocking
/// waiter and retains the `LogSink` Arc until the thread exits. `Drop` asks the
/// observer to exit by disconnecting the channel but never joins it.
pub(super) struct LoopWatchdog {
    phase: Phase,
    last_tick_ms: Arc<AtomicU64>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
    observe_every: std::time::Duration,
    threshold_secs: u64,
    join_bound: std::time::Duration,
    #[cfg(test)]
    join_waiters: Arc<AtomicUsize>,
}

impl Default for LoopWatchdog {
    fn default() -> Self {
        Self::new()
    }
}

impl LoopWatchdog {
    pub(super) fn new() -> Self {
        Self::with_limits(
            WATCHDOG_OBSERVE_EVERY,
            threshold_secs(),
            WATCHDOG_STOP_BOUND,
        )
    }

    /// Test seam: production uses one second, the env threshold, and a
    /// one-second join bound.
    fn with_limits(
        observe_every: std::time::Duration,
        threshold_secs: u64,
        join_bound: std::time::Duration,
    ) -> Self {
        Self {
            phase: Phase::Idle,
            last_tick_ms: Arc::new(AtomicU64::new(0)),
            stop: None,
            thread: None,
            observe_every,
            threshold_secs,
            join_bound,
            #[cfg(test)]
            join_waiters: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A generous join bound for cleanup-order tests, where the point is that
    /// cleanup awaited the stop rather than racing the production 1 s budget.
    #[cfg(test)]
    pub(super) fn for_test() -> Self {
        Self::with_limits(
            std::time::Duration::from_secs(30),
            20,
            std::time::Duration::from_secs(5),
        )
    }

    /// Stamp this iteration. The first call starts the observer; later calls
    /// only move the heartbeat. Once stopped, this is a no-op: a stale tick
    /// must not start a second observer.
    pub(super) fn tick(&mut self, log: Arc<dyn LogSink>) {
        if !matches!(self.phase, Phase::Idle | Phase::Running) {
            return;
        }
        self.last_tick_ms.store(now_ms(), Ordering::Relaxed);
        if self.phase == Phase::Running {
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
            self.phase = Phase::Running;
        }
        // A failed spawn leaves the heartbeat stamped but no observer, as
        // before: this is a diagnostic, not a serving guarantee.
    }

    /// Ask the observer to exit and make one bounded join attempt.
    ///
    /// Returns `Detached` when the join bound expires: the observer thread and
    /// the `spawn_blocking` waiter joining it are left to finish on their own.
    /// The observer still retains the log sink and the waiter stays registered
    /// until the observer exits. Repeated calls do not register another waiter.
    pub(super) async fn stop(&mut self) -> WatchdogStop {
        match self.phase {
            Phase::Idle => {
                self.phase = Phase::Stopped;
                return WatchdogStop::NotStarted;
            }
            Phase::Stopped => return WatchdogStop::Joined,
            Phase::Detached => return WatchdogStop::Detached,
            Phase::Running => {}
        }
        // Dropping the sender disconnects the receiver, so a sleeping observer
        // wakes at once instead of waiting out `observe_every`.
        self.stop.take();
        let Some(thread) = self.thread.take() else {
            self.phase = Phase::Stopped;
            return WatchdogStop::Joined;
        };
        #[cfg(test)]
        self.join_waiters.fetch_add(1, Ordering::Relaxed);
        let joined = tokio::time::timeout(
            self.join_bound,
            tokio::task::spawn_blocking(move || thread.join()),
        )
        .await;
        match joined {
            Ok(Ok(_)) => {
                self.phase = Phase::Stopped;
                WatchdogStop::Joined
            }
            // Timeout, or the blocking waiter itself could not run: either way
            // the thread handle was moved into detached work. Say so.
            Err(_) | Ok(Err(_)) => {
                self.phase = Phase::Detached;
                WatchdogStop::Detached
            }
        }
    }

    #[cfg(test)]
    fn join_waiters(&self) -> usize {
        self.join_waiters.load(Ordering::Relaxed)
    }
}

impl Drop for LoopWatchdog {
    fn drop(&mut self) {
        // Non-blocking fallback: disconnect-wake the observer and detach both
        // handles. `stop` is the only path that attempts a join; an outer drop
        // or a panic never reaches `RecvCleanup::finish`.
        self.stop.take();
        self.thread.take();
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
    use std::time::Duration;

    #[tokio::test]
    async fn control_readiness_requires_success_not_drop_or_timeout() {
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

    #[test]
    fn readiness_publishes_the_single_edge_exactly_once() {
        let mut readiness = Readiness::default();
        assert!(!readiness.is_published());
        let mut announced = 0;
        assert!(readiness.publish(|| announced += 1));
        // A late second publication must not re-announce readiness.
        assert!(!readiness.publish(|| announced += 1));
        assert_eq!(announced, 1);
        assert!(readiness.is_published());
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

    struct BlockingSink {
        entered: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<mpsc::Receiver<()>>,
    }

    impl BlockingSink {
        fn new() -> (
            Arc<Self>,
            tokio::sync::oneshot::Receiver<()>,
            mpsc::Sender<()>,
        ) {
            let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = mpsc::channel();
            (
                Arc::new(Self {
                    entered: std::sync::Mutex::new(Some(entered_tx)),
                    release: std::sync::Mutex::new(release_rx),
                }),
                entered_rx,
                release_tx,
            )
        }
    }

    impl LogSink for BlockingSink {
        fn debug(&self, _line: &str) {}
        fn trace(&self, _line: &str) {}
        fn say(&self, _line: &str) {}
        fn critical(&self, _line: &str) {
            if let Some(tx) = self
                .entered
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                let _ = tx.send(());
            }
            // Deliberately block: this is the one case the bounded join cannot
            // complete, so tests do not have to race a slow machine.
            let _ = self
                .release
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .recv();
        }
        fn paint(&self, _tone: filament_peerloop::host::Tone, s: &str) -> String {
            s.to_string()
        }
        fn glyph_ok(&self) -> &'static str {
            "ok"
        }
        fn glyph_warn(&self) -> &'static str {
            "!"
        }
        fn enabled(&self, _level: filament_peerloop::host::Level) -> bool {
            true
        }
    }

    async fn wait_until_sink_dropped(weak: std::sync::Weak<BlockingSink>) {
        for _ in 0..200 {
            if weak.upgrade().is_none() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("blocked observer did not exit after its log sink was released");
    }

    #[tokio::test]
    async fn watchdog_stop_wakes_and_joins_its_observer() {
        use filament_peerloop::host::NoLog;
        // A 30 s observation interval makes the join meaningful: only the
        // disconnect wake can let stop return before the generous 5 s test
        // bound (production uses 1 s; the forced-block test covers timeout).
        let mut watchdog =
            LoopWatchdog::with_limits(Duration::from_secs(30), 20, Duration::from_secs(5));
        let log = Arc::new(NoLog);
        let weak = Arc::downgrade(&log);
        watchdog.tick(log);
        assert_eq!(watchdog.stop().await, WatchdogStop::Joined);
        assert_eq!(watchdog.join_waiters(), 1);
        // Repeated stop shares the completion and registers no second waiter.
        assert_eq!(watchdog.stop().await, WatchdogStop::Joined);
        assert_eq!(watchdog.join_waiters(), 1);
        assert_eq!(watchdog.phase, Phase::Stopped);
        assert!(
            weak.upgrade().is_none(),
            "joined observer released its sink"
        );
    }

    #[tokio::test]
    async fn watchdog_stop_before_first_tick_is_thread_free_and_terminal() {
        let mut watchdog = LoopWatchdog::new();
        assert_eq!(watchdog.stop().await, WatchdogStop::NotStarted);
        assert_eq!(watchdog.join_waiters(), 0);
        // A late tick must not create an observer after the terminal stop.
        watchdog.tick(Arc::new(filament_peerloop::host::NoLog));
        assert_eq!(watchdog.phase, Phase::Stopped);
        assert!(watchdog.thread.is_none());
    }

    #[tokio::test]
    async fn watchdog_tick_after_stop_does_not_restart_the_observer() {
        use filament_peerloop::host::NoLog;
        let mut watchdog =
            LoopWatchdog::with_limits(Duration::from_secs(30), 20, Duration::from_secs(5));
        watchdog.tick(Arc::new(NoLog));
        assert_eq!(watchdog.stop().await, WatchdogStop::Joined);
        watchdog.tick(Arc::new(NoLog));
        watchdog.tick(Arc::new(NoLog));
        assert_eq!(watchdog.phase, Phase::Stopped);
        assert!(watchdog.thread.is_none());
        assert_eq!(watchdog.join_waiters(), 1);
    }

    #[tokio::test]
    async fn watchdog_drop_wakes_but_does_not_join_a_blocked_observer() {
        let (sink, entered, release) = BlockingSink::new();
        let weak = Arc::downgrade(&sink);
        let mut watchdog =
            LoopWatchdog::with_limits(Duration::from_millis(1), 0, Duration::from_secs(1));
        watchdog.tick(sink);
        entered.await.unwrap();
        // Drop from a blocking worker: joining the blocked observer here would
        // hang the test, proving Drop did not wait.
        let dropped = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::task::spawn_blocking(move || drop(watchdog)),
        )
        .await;
        if dropped.is_err() {
            // Let a regressed, joining Drop unblock before panicking so the
            // blocking worker cannot keep the test runtime alive.
            release.send(()).unwrap();
        }
        assert!(dropped.is_ok(), "Drop must not join a blocked observer");
        assert!(
            weak.upgrade().is_some(),
            "detached observer still retains the log sink"
        );
        release.send(()).unwrap();
        wait_until_sink_dropped(weak).await;
    }

    #[tokio::test]
    async fn watchdog_timeout_detaches_and_does_not_register_another_waiter() {
        let (sink, entered, release) = BlockingSink::new();
        let weak = Arc::downgrade(&sink);
        // The observer is provably inside a blocking sink call, so the 50 ms
        // join bound cannot succeed; no wall-clock race is involved.
        let mut watchdog =
            LoopWatchdog::with_limits(Duration::from_millis(1), 0, Duration::from_millis(50));
        watchdog.tick(sink);
        entered.await.unwrap();
        assert_eq!(watchdog.stop().await, WatchdogStop::Detached);
        assert_eq!(watchdog.phase, Phase::Detached);
        assert_eq!(watchdog.join_waiters(), 1);
        assert!(
            weak.upgrade().is_some(),
            "timed-out stop retains the sink until the observer exits"
        );
        // Repeated stop must not register a second blocking waiter.
        assert_eq!(watchdog.stop().await, WatchdogStop::Detached);
        assert_eq!(watchdog.join_waiters(), 1);
        release.send(()).unwrap();
        wait_until_sink_dropped(weak).await;
        assert_eq!(watchdog.stop().await, WatchdogStop::Detached);
        assert_eq!(watchdog.join_waiters(), 1);
    }
}
