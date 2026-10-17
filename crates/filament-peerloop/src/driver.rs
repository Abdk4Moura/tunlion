//! Invocation-local cancellation, not an engine or a process shutdown policy.
//!
//! Dropping the interrupted future only stops its inline work. Its caller must
//! retain owned resources outside that future and await cleanup before returning.
//! No readiness or all-task/durable-shutdown guarantee is implied here.

use std::future::Future;
use tokio::sync::watch;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::{pending, ready};

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
}
