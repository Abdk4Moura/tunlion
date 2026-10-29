//! Portable receive-invocation signal adapter. Process policy stays in the CLI.

use crate::recv_lifecycle::Tasks;
use filament_peerloop::driver::Cancellation;
use std::sync::{
    atomic::{AtomicI32, Ordering},
    Arc,
};

pub(crate) struct Signals {
    tasks: Tasks,
    code: Arc<AtomicI32>,
}

impl Signals {
    /// Register before the first network await, including patient startup.
    pub(crate) fn install(stop: Cancellation) -> std::io::Result<Self> {
        let mut signals = Self {
            tasks: Tasks::default(),
            code: Arc::new(AtomicI32::new(crate::exit_codes::INTERRUPTED)),
        };
        #[cfg(unix)]
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        // Windows has no SIGTERM: `tunlion down` sets a named event this
        // process waits on (platform::ask_daemon_to_stop), and that ends it
        // the same graceful way.
        #[cfg(windows)]
        let stop_request = crate::platform::listen_for_stop_request();
        let code = signals.code.clone();
        signals.tasks.push(tokio::spawn(async move {
            #[cfg(unix)]
            let received = tokio::select! {
                result = tokio::signal::ctrl_c() => result.map(|_| crate::exit_codes::INTERRUPTED),
                _ = term.recv() => Ok(crate::exit_codes::TERMINATED),
            };
            #[cfg(windows)]
            let received = {
                let requested = async {
                    let fired = match stop_request {
                        Some(rx) => rx.await.is_ok(),
                        None => false,
                    };
                    if !fired {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {
                    result = tokio::signal::ctrl_c() => result.map(|_| crate::exit_codes::INTERRUPTED),
                    _ = requested => Ok(crate::exit_codes::TERMINATED),
                }
            };
            #[cfg(not(any(unix, windows)))]
            let received = tokio::signal::ctrl_c()
                .await
                .map(|_| crate::exit_codes::INTERRUPTED);
            if let Ok(received) = received {
                code.store(received, Ordering::SeqCst);
                // This emergency policy remains CLI-only. The graceful path
                // returns through cleanup before the adapter exits.
                crate::shutdown::arm_force_exit(received, crate::shutdown::grace());
                stop.cancel();
            }
        }));
        Ok(signals)
    }

    pub(crate) fn code(&self) -> i32 {
        self.code.load(Ordering::SeqCst)
    }

    pub(crate) async fn stop(&mut self) {
        self.tasks.stop().await;
    }
}
