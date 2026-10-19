//! The engine driver: one task, one cancellation latch, one readiness edge.
//!
//! A receive/daemon dispatch is a long-running future. This module owns the
//! *runtime* around it, so a caller does not have to re-implement the same
//! spawn/join/readiness bookkeeping:
//!
//! - [`Cancellation`] is a latched, per-call stop request. Dropping a handle
//!   does not request stop and there is no process-global latch.
//! - [`Readiness`] is a publish-once edge the dispatch raises after required
//!   setup. [`ReadyWatch`] is the awaitable half a supervisor may poll.
//! - [`Engine`] spawns exactly one dispatch task, owns its `JoinHandle`, and
//!   exposes `ready`, `stop` and `wait`. No signals, no exit, no process state:
//!   the CLI keeps its own signal/exit adapter above this, and an embedder
//!   (Core) supplies its own runtime and host.
//!
//! ## What the guarantees are
//!
//! `Engine::wait` / `Engine::stop` resolve only when the dispatch future has
//! returned; they therefore prove the dispatch's **own** epilogue ran. They do
//! not abort it, and they do not prove that work the dispatch detached has
//! stopped. `Engine::drop` requests stop (the latch) and detaches the task; it
//! does not join. A dispatch that never observes the latch keeps running.
//!
//! Readiness is published by the dispatch, never guessed here. If the dispatch
//! returns without publishing, [`ReadyWatch`] reports [`ReadyError::NotPublished`]
//! instead of treating "the task ended" as "the engine is serving".

use std::fmt;
use std::future::Future;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};

#[derive(Clone, Debug)]
pub struct Cancellation {
    stop: watch::Sender<bool>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DriverOutcome<T> {
    Returned(T),
    Cancelled,
}

impl Default for Cancellation {
    fn default() -> Self {
        let (stop, _) = watch::channel(false);
        Self { stop }
    }
}

impl Cancellation {
    /// A latched, idempotent request. Dropping a handle does not request stop.
    pub fn cancel(&self) {
        self.stop.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.stop.borrow()
    }

    /// Cancellation wins if both branches are ready, including before first poll.
    /// This races every yielding await in `driver`, not just its event receiver.
    pub async fn run<F: Future>(&self, driver: F) -> DriverOutcome<F::Output> {
        let mut stop = self.stop.subscribe();
        tokio::select! {
            biased;
            _ = stop.wait_for(|stop| *stop) => DriverOutcome::Cancelled,
            value = driver => DriverOutcome::Returned(value),
        }
    }
}

/// Why waiting for the readiness edge failed.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadyError {
    /// Every [`Readiness`] handle was dropped before the edge was published.
    /// The dispatch returned (or dropped its publisher) without getting ready.
    NotPublished,
    /// The caller's bound elapsed while the edge was still unpublished.
    TimedOut,
}

impl fmt::Display for ReadyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadyError::NotPublished => {
                f.write_str("the dispatch ended without publishing readiness")
            }
            ReadyError::TimedOut => f.write_str("readiness was not published within the bound"),
        }
    }
}

impl std::error::Error for ReadyError {}

/// Readiness is a three-state edge, not a boolean: `Unpublished`, then
/// `Announcing` while the publish call's side effects run, then `Ready`.
/// Observers see only the last state, so `is_ready` / `wait` can never return
/// before `announce` has returned.
const UNPUBLISHED: u8 = 0;
const ANNOUNCING: u8 = 1;
const READY: u8 = 2;

/// The publish-once half of the readiness edge. Clone it into the dispatch and
/// any required setup it owns; publish exactly once, after required setup and
/// immediately before the serving loop.
#[derive(Clone)]
pub struct Readiness {
    state: Arc<AtomicU8>,
    tx: watch::Sender<bool>,
}

/// The awaitable half of the readiness edge. A supervisor may clone it; clones
/// observe the same latch and the same notification.
#[derive(Clone)]
pub struct ReadyWatch {
    state: Arc<AtomicU8>,
    rx: watch::Receiver<bool>,
}

impl Readiness {
    /// Create the two halves. The dispatch keeps the [`Readiness`]; the
    /// supervisor keeps the [`ReadyWatch`].
    pub fn new() -> (Self, ReadyWatch) {
        let state = Arc::new(AtomicU8::new(UNPUBLISHED));
        let (tx, rx) = watch::channel(false);
        (
            Self {
                state: Arc::clone(&state),
                tx,
            },
            ReadyWatch { state, rx },
        )
    }

    /// Publish the ready edge and run `announce` exactly once. Returns `true`
    /// only for the publishing call; later calls are no-ops, so a stray second
    /// publication cannot re-announce readiness after startup.
    ///
    /// The edge becomes observable only after `announce` returns. While the
    /// announcement is still running the state is `Announcing`, which both
    /// `is_ready` and `wait` treat as not ready; only then is the watch
    /// notified. Observing `Ready` therefore implies the edge's own side
    /// effects ran.
    pub fn publish(&self, announce: impl FnOnce()) -> bool {
        if self
            .state
            .compare_exchange(UNPUBLISHED, ANNOUNCING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        announce();
        // Release: everything `announce` did happens-before an Acquire reader
        // that observes `READY`.
        self.state.store(READY, Ordering::Release);
        let _ = self.tx.send(true);
        true
    }

    /// Whether this invocation already completed the edge (announcement done).
    pub fn is_published(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }
}

impl Default for Readiness {
    fn default() -> Self {
        Self::new().0
    }
}

impl ReadyWatch {
    /// True only once the publisher's `announce` has returned. `Announcing`
    /// (the announcement is in progress) is deliberately not ready.
    pub fn is_ready(&self) -> bool {
        self.state.load(Ordering::Acquire) == READY
    }

    /// Wait for the dispatch to publish readiness.
    ///
    /// `None` waits without a bound. A dispatch that returns without
    /// publishing resolves with [`ReadyError::NotPublished`] as soon as its
    /// [`Readiness`] handles are gone, rather than hanging until the bound.
    pub async fn wait(&mut self, bound: Option<Duration>) -> Result<(), ReadyError> {
        let wait = async {
            if self.is_ready() {
                return Ok(());
            }
            loop {
                match self.rx.changed().await {
                    Ok(()) => {
                        if self.is_ready() {
                            return Ok(());
                        }
                    }
                    // All publishers dropped and the edge was never raised.
                    Err(_) => return Err(ReadyError::NotPublished),
                }
            }
        };
        match bound {
            Some(bound) => match tokio::time::timeout(bound, wait).await {
                Ok(result) => result,
                Err(_) => Err(ReadyError::TimedOut),
            },
            None => wait.await,
        }
    }
}

/// Why a bounded stop did not resolve with the dispatch's value.
#[derive(Debug)]
pub enum StopError {
    /// The dispatch task panicked or was aborted.
    Panicked(JoinError),
    /// The dispatch did not return within the caller's bound. The task is
    /// **retained** by the caller's `Engine` (the handle was not dropped) and
    /// may still be running; cancellation had already been requested.
    TimedOut,
}

impl fmt::Display for StopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StopError::Panicked(error) => write!(f, "the engine dispatch failed: {error}"),
            StopError::TimedOut => f.write_str("the engine dispatch did not stop within the bound"),
        }
    }
}

impl std::error::Error for StopError {}

/// One running dispatch, owned by the caller.
///
/// The engine must be started from inside a Tokio runtime; it spawns one task
/// on that runtime. The runtime itself is owned by the caller (the CLI's
/// process runtime, or a Core's instance runtime), never by this type.
pub struct Engine<T> {
    cancel: Cancellation,
    ready: ReadyWatch,
    task: JoinHandle<T>,
}

impl<T: Send + 'static> Engine<T> {
    /// Spawn `dispatch` as the one owned engine task.
    ///
    /// `dispatch` receives the cancellation latch and the readiness publisher.
    /// It must return only after its own cleanup epilogue; `Engine::stop` and
    /// `Engine::wait` await exactly that return.
    pub fn start<F, Fut>(cancel: Cancellation, dispatch: F) -> Self
    where
        F: FnOnce(Cancellation, Readiness) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
    {
        let (readiness, ready) = Readiness::new();
        let dispatch_stop = cancel.clone();
        let task = tokio::spawn(dispatch(dispatch_stop, readiness));
        Self {
            cancel,
            ready,
            task,
        }
    }

    /// The same latch the dispatch holds, for a caller-owned signal adapter.
    pub fn cancellation(&self) -> &Cancellation {
        &self.cancel
    }

    /// Cloneable readiness handle, for a supervisor that polls without owning
    /// the engine.
    pub fn ready_watch(&self) -> ReadyWatch {
        self.ready.clone()
    }

    pub fn is_ready(&self) -> bool {
        self.ready.is_ready()
    }

    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Ask the dispatch to stop. This does not join; use [`Engine::stop`].
    pub fn request_stop(&self) {
        self.cancel.cancel();
    }

    pub async fn ready(&mut self, bound: Option<Duration>) -> Result<(), ReadyError> {
        self.ready.wait(bound).await
    }

    /// Wait for the dispatch to return on its own. Does not request stop.
    pub async fn wait(mut self) -> Result<T, JoinError> {
        (&mut self.task).await
    }

    /// Request stop and wait for the dispatch to return.
    ///
    /// This proves the dispatch's own epilogue completed, not that every piece
    /// of work it detached has stopped.
    pub async fn stop(mut self) -> Result<T, JoinError> {
        self.cancel.cancel();
        (&mut self.task).await
    }

    /// Request stop and wait at most `bound` for the dispatch to return.
    ///
    /// Borrows the engine rather than consuming it, so a `TimedOut` outcome
    /// **retains the task**: the `JoinHandle` is not dropped and the caller can
    /// observe [`Engine::is_finished`] or retry the bounded join later. This is
    /// what lets `Core` refuse to claim `Stopped` or permit a restart while a
    /// task may still be running.
    ///
    /// Cancellation is requested first but cooperation belongs to the dispatch.
    /// Once this returns `Ok`, the task has completed and the handle must not be
    /// awaited again; drop the engine (or use the consuming [`Engine::stop`]).
    pub async fn stop_within(&mut self, bound: Duration) -> Result<T, StopError> {
        self.cancel.cancel();
        match tokio::time::timeout(bound, &mut self.task).await {
            Ok(result) => result.map_err(StopError::Panicked),
            Err(_) => Err(StopError::TimedOut),
        }
    }
}

impl<T> Drop for Engine<T> {
    fn drop(&mut self) {
        // Non-blocking fallback. `stop` / `stop_within` are the join paths.
        // The task is detached; the latch is still set, so a cooperative
        // dispatch winds down on its own.
        self.cancel.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[tokio::test]
    async fn cancellation_is_latched_and_wins_before_driver_is_polled() {
        let stop = Cancellation::default();
        stop.cancel();
        stop.cancel();
        assert_eq!(stop.run(ready(42)).await, DriverOutcome::Cancelled);
        assert_eq!(stop.run(pending::<()>()).await, DriverOutcome::Cancelled);
    }

    #[tokio::test]
    async fn invocations_cancel_independently_while_awaiting_work() {
        let first = Cancellation::default();
        let second = Cancellation::default();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (finish_tx, finish_rx) = tokio::sync::oneshot::channel();
        let second_task = tokio::spawn(async move {
            second
                .run(async move {
                    entered_tx.send(()).unwrap();
                    finish_rx.await.unwrap()
                })
                .await
        });
        entered_rx.await.unwrap();
        let request = first.clone();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let first_task = tokio::spawn(async move {
            first
                .run(async move {
                    entered_tx.send(()).unwrap();
                    pending::<()>().await;
                })
                .await
        });
        entered_rx.await.unwrap();
        request.cancel();
        assert_eq!(first_task.await.unwrap(), DriverOutcome::Cancelled);
        assert!(!second_task.is_finished());
        finish_tx.send(7).unwrap();
        assert_eq!(second_task.await.unwrap(), DriverOutcome::Returned(7));
    }

    #[tokio::test]
    async fn ordinary_errors_are_returned_not_cancellation() {
        let stop = Cancellation::default();
        assert_eq!(
            stop.run(ready(Err::<(), _>("setup failed"))).await,
            DriverOutcome::Returned(Err("setup failed"))
        );
    }

    #[tokio::test]
    async fn readiness_publishes_once_and_wakes_a_waiter() {
        let (publish, mut watch) = Readiness::new();
        assert!(!watch.is_ready());
        let mut announced = 0;
        assert!(publish.publish(|| announced += 1));
        assert!(!publish.publish(|| announced += 1));
        assert_eq!(announced, 1);
        assert!(watch.is_ready());
        assert_eq!(watch.wait(Some(Duration::ZERO)).await, Ok(()));
    }

    /// `publish` must not make the edge observable until `announce` returns.
    /// The publisher blocks inside `announce` on a std channel (so a current
    /// thread runtime is not stalled); the watcher and a concurrent waiter are
    /// both live in the Tokio runtime during that window.
    #[tokio::test]
    async fn readiness_is_not_observable_while_announce_is_blocked() {
        let (publish, mut watch) = Readiness::new();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let publisher = std::thread::spawn(move || {
            publish.publish(|| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
            });
        });

        // The publisher is now inside `announce` and cannot return until we
        // release it. The watcher is not ready, and a zero-bound wait times
        // out rather than observing a premature edge.
        entered_rx.await.unwrap();
        assert!(!watch.is_ready());
        assert_eq!(
            watch.wait(Some(Duration::ZERO)).await,
            Err(ReadyError::TimedOut)
        );

        // A concurrent waiter is also blocked: it must not finish while the
        // announcement is still running. Yield until it has had a poll.
        let mut waiter_watch = watch.clone();
        let waiter =
            tokio::spawn(async move { waiter_watch.wait(Some(Duration::from_secs(1))).await });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !waiter.is_finished(),
            "readiness became observable before announce returned"
        );
        assert!(!watch.is_ready());

        release_tx.send(()).unwrap();
        assert_eq!(waiter.await.unwrap(), Ok(()));
        publisher.join().unwrap();
        assert!(watch.is_ready());
        assert_eq!(watch.wait(Some(Duration::ZERO)).await, Ok(()));
    }

    #[tokio::test]
    async fn readiness_from_another_task_is_observed() {
        let (publish, mut watch) = Readiness::new();
        let task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            publish.publish(|| {});
        });
        assert_eq!(watch.wait(Some(Duration::from_secs(1))).await, Ok(()));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn readiness_reports_not_published_when_the_dispatch_returns_first() {
        let (publish, mut watch) = Readiness::new();
        drop(publish);
        assert_eq!(
            watch.wait(Some(Duration::from_secs(1))).await,
            Err(ReadyError::NotPublished)
        );
    }

    #[tokio::test]
    async fn readiness_times_out_without_a_publisher_closing() {
        let (publish, mut watch) = Readiness::new();
        assert_eq!(
            watch.wait(Some(Duration::from_millis(10))).await,
            Err(ReadyError::TimedOut)
        );
        // The publisher is still alive, so the waiter can still be satisfied.
        publish.publish(|| {});
        assert_eq!(watch.wait(Some(Duration::ZERO)).await, Ok(()));
    }

    #[tokio::test]
    async fn engine_ready_then_stop_joins_the_dispatch_epilogue() {
        let cancel = Cancellation::default();
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_in_dispatch = Arc::clone(&dropped);
        let mut engine = Engine::start(cancel.clone(), move |stop, readiness| async move {
            readiness.publish(|| {});
            stop.run(pending::<()>()).await;
            // The dispatch's own epilogue.
            dropped_in_dispatch.store(true, Ordering::SeqCst);
            7
        });
        engine
            .ready(Some(Duration::from_secs(1)))
            .await
            .expect("readiness published");
        assert_eq!(engine.stop().await.unwrap(), 7);
        assert!(dropped.load(Ordering::SeqCst), "stop awaited the epilogue");
    }

    #[tokio::test]
    async fn engine_pre_cancelled_dispatch_returns_without_publishing() {
        let cancel = Cancellation::default();
        cancel.cancel();
        let mut engine = Engine::start(cancel.clone(), move |stop, _readiness| async move {
            assert!(stop.is_cancelled());
            1
        });
        // The dispatch ended before publishing; readiness says so, not "ready".
        assert_eq!(
            engine.ready(Some(Duration::from_secs(1))).await,
            Err(ReadyError::NotPublished)
        );
        assert_eq!(engine.stop().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn engines_are_independent_instances() {
        let first_cancel = Cancellation::default();
        let second_cancel = Cancellation::default();
        let mut first = Engine::start(first_cancel.clone(), move |stop, readiness| async move {
            readiness.publish(|| {});
            stop.run(pending::<()>()).await;
            "first"
        });
        let mut second = Engine::start(second_cancel.clone(), move |stop, readiness| async move {
            readiness.publish(|| {});
            stop.run(pending::<()>()).await;
            "second"
        });
        first.ready(Some(Duration::from_secs(1))).await.unwrap();
        second.ready(Some(Duration::from_secs(1))).await.unwrap();
        assert_eq!(first.stop().await.unwrap(), "first");
        assert!(!second.is_finished(), "stopping one engine left the other");
        assert_eq!(second.stop().await.unwrap(), "second");
    }

    #[tokio::test]
    async fn bound_expiry_retains_a_dispatch_that_ignores_cancellation() {
        let started = Arc::new(AtomicUsize::new(0));
        let started_in_dispatch = Arc::clone(&started);
        let release = Arc::new(tokio::sync::Notify::new());
        let release_in_dispatch = Arc::clone(&release);
        let mut engine = Engine::start(
            Cancellation::default(),
            move |_stop, _readiness| async move {
                started_in_dispatch.fetch_add(1, Ordering::SeqCst);
                release_in_dispatch.notified().await;
                "late"
            },
        );
        // Observe the dispatch entered before asking it to stop.
        for _ in 0..100 {
            if started.load(Ordering::SeqCst) == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(matches!(
            engine.stop_within(Duration::from_millis(10)).await,
            Err(StopError::TimedOut)
        ));
        // Retained, not detached: the handle is still owned and not finished.
        assert!(!engine.is_finished());
        release.notify_one();
        // The retained engine can still be joined.
        match engine.stop_within(Duration::from_secs(1)).await {
            Ok(value) => assert_eq!(value, "late"),
            Err(error) => panic!("expected the retained dispatch to join, got {error:?}"),
        }
    }

    #[tokio::test]
    async fn dropping_the_engine_requests_stop_without_joining() {
        let cancel = Cancellation::default();
        let observed = Arc::new(tokio::sync::Notify::new());
        let observed_in_dispatch = Arc::clone(&observed);
        let entering = Arc::new(tokio::sync::Notify::new());
        let entering_in_dispatch = Arc::clone(&entering);
        let engine = Engine::start(cancel.clone(), move |stop, _readiness| async move {
            entering_in_dispatch.notify_one();
            while !stop.is_cancelled() {
                tokio::task::yield_now().await;
            }
            observed_in_dispatch.notify_one();
        });
        entering.notified().await;
        drop(engine);
        tokio::time::timeout(Duration::from_secs(1), observed.notified())
            .await
            .expect("drop requested stop");
        assert!(cancel.is_cancelled());
    }
}
