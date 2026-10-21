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

/// Explicit received-code surface: reserve non-code material before cleanup,
/// then lowercase/separate/collapse and reject (never truncate) over 48. Runs
/// before the engine starts, so a pasted invitation cannot reach the network.
fn checked_recv_code(raw: &str) -> Result<String> {
    crate::join_input::PairingCode::checked_text(raw)
        .map_err(|error| anyhow::anyhow!("{}", error.message()))
}

fn checked_recv_code_option(value: Option<String>) -> Result<Option<String>> {
    value.map(|raw| checked_recv_code(&raw)).transpose()
}

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
    // Explicit argv/env code crosses the typed boundary before signals, engine
    // start or any network setup. Guided entry stays on the shared code entry.
    let code = checked_recv_code_option(code)?;
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
        consent_token: crate::consent_token().to_string(),
        direct_ok: crate::direct_ok_for(daemon, l2_launch),
        quiet_window: crate::quiet_exit_window(),
        l2_forced: std::env::var("TUNLION_L2")
            .map(|x| x == "1")
            .unwrap_or(false),
        daemon_ready: false,
        pid: std::process::id(),
        interactive_terminal: std::io::IsTerminal::is_terminal(&std::io::stdin()),
        pair_grace: std::env::var("TUNLION_PAIR_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(60)),
        fleet_offer_grace: std::env::var("TUNLION_FLEET_OFFER_GRACE_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(std::time::Duration::from_secs)
            .unwrap_or(std::time::Duration::from_secs(8)),
        trace_throughput: std::env::var("TUNLION_TRACE_THROUGHPUT").is_ok(),
        supervised: std::env::var("INVOCATION_ID").is_ok(),
        loop_stall_secs: std::env::var("TUNLION_LOOP_STALL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(20),
        remember_stored: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        delivery: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
    };
    let remember_stored = env.remember_stored.clone();
    let engine = Engine::start(stop.clone(), move |stop, readiness| async move {
        let cli = Arc::new(crate::recv_ports::CliRecv::new(engine_log.clone()));
        let ports = RecvPorts::new(
            cli.clone(),
            cli.clone(),
            Box::new(crate::recv_ports::CliRecv::new(engine_log.clone())),
            Box::new(crate::recv_ports::CliRecv::new(engine_log.clone())),
            Arc::new(crate::recv_ports::CliPrompt),
            crate::recv_ports::pty_backend(cli.pty_sessions.clone()),
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
    if remember_stored.load(std::sync::atomic::Ordering::Relaxed) {
        crate::shared_defs::REMEMBER_STORED.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    match outcome {
        DriverOutcome::Returned(result) => result.map_err(map_dispatch_error),
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

/// Coerce the library's typed failures onto the CLI exit taxonomy. The chain
/// is preserved when the error is not one of the library types.
pub(crate) fn map_dispatch_error(error: anyhow::Error) -> anyhow::Error {
    let error = match error.downcast::<filament_peerloop::recv::report::RefusedFailure>() {
        Ok(refused) => {
            return crate::recv_report::as_error(crate::recv_report::RefusedOutcome {
                kind: refused.kind,
                message: refused.message,
            });
        }
        Err(error) => error,
    };
    match error.downcast::<filament_peerloop::recv::dispatch::DispatchFailure>() {
        Ok(failure) => {
            let kind = match failure.kind {
                filament_peerloop::recv::dispatch::DispatchFailureKind::Usage => {
                    exit_codes::ExitKind::Usage
                }
                filament_peerloop::recv::dispatch::DispatchFailureKind::Unreachable => {
                    exit_codes::ExitKind::Unreachable
                }
            };
            exit_codes::err(kind, &failure.message)
        }
        Err(error) => error,
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
    fn invalid_expect_pin_maps_to_usage_exit_and_json() {
        let error =
            filament_peerloop::recv::dispatch::validate_expect_sha256(Some("bad")).unwrap_err();
        let mapped = map_dispatch_error(error);
        assert_eq!(
            crate::exit_codes::classify(&mapped),
            crate::exit_codes::ExitKind::Usage
        );
        assert_eq!(crate::exit_codes::classify(&mapped).code(), 2);
        assert_eq!(crate::exit_codes::json_code(&mapped), "usage");
    }

    #[test]
    fn empty_timeout_maps_to_unreachable_exit_and_json() {
        let error = anyhow::Error::new(filament_peerloop::recv::dispatch::receive_timeout_failure(
            0,
        ));
        let mapped = map_dispatch_error(error);
        assert_eq!(
            crate::exit_codes::classify(&mapped),
            crate::exit_codes::ExitKind::Unreachable
        );
        assert_eq!(crate::exit_codes::classify(&mapped).code(), 6);
        assert_eq!(crate::exit_codes::json_code(&mapped), "unreachable");
    }

    #[test]
    fn parked_open_aliases_resolve() {
        let _ = std::mem::size_of::<ParkedOpen>();
        let _ = ParkKind::Exec;
        let _ = host_impl::cli_screen;
        let _ = exit_codes::ExitKind::Usage;
    }

    #[test]
    fn explicit_code_surface_cleans_separators_and_refuses_material() {
        assert_eq!(
            super::checked_recv_code("Brave.Otter..3141").unwrap(),
            "brave-otter-3141"
        );
        assert!(super::checked_recv_code("filament-invite:v2:hidden").is_err());
        assert!(super::checked_recv_code("\"brave-otter-3141\"").is_err());
        assert_eq!(super::checked_recv_code(&"a".repeat(48)).unwrap().len(), 48);
        assert!(super::checked_recv_code(&"a".repeat(49)).is_err());
    }
}
