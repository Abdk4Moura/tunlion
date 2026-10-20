//! The receive command's process adapter.
//!
//! The production loop lives in `filament_peerloop::recv::dispatch`. This file
//! owns only what is genuinely the CLI's: argument/env resolution, signal
//! installation, the engine task, the 130/143 exit policy, the pid/ready
//! markers and the terminal adapters. It builds a [`RecvPorts`] and calls the
//! one library dispatch.

use crate::exit_codes;
use crate::recv_lifecycle::Signals;
use crate::recv_report::RecvReport;
use crate::{display_name, host_impl, mk_uid, ShellPolicy};
use anyhow::Result;
use filament_peerloop::driver::{Cancellation, DriverOutcome, Engine};
use filament_peerloop::host::{HostServices, LogSink, Tone};
use filament_peerloop::recv::dispatch::{drive, RecvCleanup};
use filament_peerloop::recv::ports::{RecvEnv, RecvPorts};
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) use crate::recv_ports::cli_park_on_deny as park_on_deny;
/// Re-exported so the CLI's host-side server implementations (and the existing
/// `exec_recv`/`sync_cmd`/`ssh_ca` modules) share the one parked-open type.
pub(crate) use filament_peerloop::recv::dispatch::{settle_timeout_reason, ParkKind, ParkedOpen};

/// CLI process adapter. Returns only after the library dispatch and its owned
/// cleanup have completed; cancellation is translated into the CLI exit policy.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn recv_cmd(
    server: &str,
    code: Option<String>,
    dir: PathBuf,
    yes: bool,
    room: Option<String>,
    to: Option<String>,
    keep_open: bool,
    timeout: Option<u64>,
    expect_sha256: Option<String>,
    relay: bool,
    remember: Option<String>,
    daemon: bool,
    output: Option<String>,
    shell_policy: ShellPolicy,
    shell_user: Option<String>,
    no_proxy_fallback: bool,
    transport_context: filament_transport::TransportContext,
    log: Arc<dyn LogSink>,
    host: Arc<dyn HostServices>,
    report: &RecvReport,
) -> Result<()> {
    let stop = Cancellation::default();
    let mut signals = Signals::install(stop.clone())?;
    let server = server.to_string();
    let engine_log = log.clone();
    let engine_report = RecvReport::clone(report);
    let l2_launch = shell_policy.enables_l2() || crate::any_shell_grant();
    let env = RecvEnv {
        display_name: display_name(),
        uid: mk_uid("r"),
        interactive_allowed: crate::interactive_allowed(),
        interactive_requested: crate::interactive_requested(),
        config_name: crate::config_get("name"),
        consent_token: crate::consent_token(),
        direct_ok: crate::direct_ok_for(daemon, l2_launch),
        quiet_window: crate::quiet_exit_window(),
        l2_forced: std::env::var("TUNLION_L2")
            .map(|x| x == "1")
            .unwrap_or(false),
        daemon_ready: false,
    };
    let engine = Engine::start(stop.clone(), move |stop, readiness| async move {
        let cli = Arc::new(crate::recv_ports::CliRecv::new(engine_log.clone()));
        let ports = RecvPorts::new(
            cli.clone(),
            cli.clone(),
            Box::new(crate::recv_ports::CliRecv::new(engine_log.clone())),
            Box::new(crate::recv_ports::CliRecv::new(engine_log.clone())),
            Arc::new(crate::recv_ports::CliPrompt),
            crate::host_impl::cli_screen(),
            env,
        );
        let mut cleanup = RecvCleanup::default();
        drive(
            &server,
            code,
            dir,
            yes,
            room,
            to,
            keep_open,
            timeout,
            expect_sha256,
            relay,
            remember,
            daemon,
            output,
            shell_policy,
            shell_user,
            no_proxy_fallback,
            transport_context,
            engine_log,
            host,
            ports,
            engine_report,
            &stop,
            &readiness,
            &mut cleanup,
        )
        .await
    });
    let outcome = match engine.wait().await {
        Ok(outcome) => outcome,
        Err(error) => {
            signals.stop().await;
            return Err(anyhow::anyhow!("the receive engine task failed: {error}"));
        }
    };
    signals.stop().await;
    match outcome {
        DriverOutcome::Returned(result) => result.map_err(|e| {
            match e.downcast::<filament_peerloop::recv::report::RefusedFailure>() {
                Ok(refused) => crate::recv_report::as_error(crate::recv_report::RefusedOutcome {
                    kind: refused.kind,
                    message: refused.message,
                }),
                Err(e) => e,
            }
        }),
        DriverOutcome::Cancelled => {
            if daemon {
                log.say(&format!(
                    "  {} stopped serving; `tunlion up` starts again",
                    log.paint(Tone::Dim, "·")
                ));
                crate::file_io::remove_pidfile();
            } else {
                log.say(&format!(
                    "  {} interrupted, partials kept; run the same command to resume",
                    log.paint(Tone::Warn, "!")
                ));
            }
            exit_codes::interrupted_exit(signals.code());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_library_owns_the_single_dispatch() {
        // The adapter must not contain a second event loop: the only reference
        // to `Ev` is the library import path.
        let source = include_str!("recv_cmd.rs");
        assert!(source.lines().count() < 500, "the adapter is thin");
        assert!(source.contains("recv::dispatch"));
        assert!(!source.contains(concat!("Ev::", "Chunk(")));
    }

    #[test]
    fn parked_open_aliases_resolve() {
        let _ = std::mem::size_of::<ParkedOpen>();
        let _ = ParkKind::Exec;
        let _ = host_impl::cli_screen;
        let _ = exit_codes::ExitKind::Usage;
    }
}
