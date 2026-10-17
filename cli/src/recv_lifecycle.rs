//! Process adapters owned by one CLI receive invocation. Not library lifecycle.

use filament_peerloop::driver::Cancellation;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};

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

pub(super) struct Signals {
    tasks: Tasks,
    code: Arc<AtomicI32>,
}

impl Signals {
    /// Register before the first network await, including patient startup.
    pub(super) fn install(stop: Cancellation) -> std::io::Result<Self> {
        let mut signals = Self {
            tasks: Tasks::default(),
            code: Arc::new(AtomicI32::new(crate::exit_codes::INTERRUPTED)),
        };
        #[cfg(unix)]
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let code = signals.code.clone();
        signals.tasks.push(tokio::spawn(async move {
            #[cfg(unix)]
            let received = tokio::select! {
                result = tokio::signal::ctrl_c() => result.map(|_| crate::exit_codes::INTERRUPTED),
                _ = term.recv() => Ok(crate::exit_codes::TERMINATED),
            };
            #[cfg(not(unix))]
            let received = tokio::signal::ctrl_c()
                .await
                .map(|_| crate::exit_codes::INTERRUPTED);
            if let Ok(received) = received {
                code.store(received, Ordering::SeqCst);
                // This emergency policy remains CLI-only. The graceful path
                // below returns through cleanup before the adapter exits.
                crate::shutdown::arm_force_exit(received, crate::shutdown::grace());
                stop.cancel();
            }
        }));
        Ok(signals)
    }

    pub(super) fn code(&self) -> i32 {
        self.code.load(Ordering::SeqCst)
    }

    pub(super) async fn stop(&mut self) {
        self.tasks.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_peerloop::driver::DriverOutcome;

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
