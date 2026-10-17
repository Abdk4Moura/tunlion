//! Process adapters owned by one CLI receive invocation. Not library lifecycle.

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
}
