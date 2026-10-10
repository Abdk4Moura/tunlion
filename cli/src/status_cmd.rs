//! The inspect commands (`tour`, `status`, `requests`) and the state helpers they share.
//!
//! These are the read-mostly commands: what this daemon is doing (`status_cmd`), a
//! guided first look (`tour_cmd`), and approving or denying what others asked for
//! (`requests_cmd`). Alongside them sit the pieces of mesh state those views depend
//! on: `delegated_device_state`, `mesh_enrolment`, and `detach_up`.
//!
//! NO CFG ANYWHERE: no member carries a definition- or statement-level attribute,
//! and no dependency this group calls is gated (checked with cfg-pair awareness).
//! No spawns and no nested fns either. All six are called from non-test modules, so
//! the crate-root re-export is a single unconditional group.
use crate::DeadlineClock;
use crate::PRINCIPAL_STATE_LAPSED;
use crate::PRINCIPAL_STATE_REVOKED;
use crate::cli_def::RequestsAction;
use crate::daemon_alive;
use crate::devices_store::devices_load;
use crate::effective_principal_deadline;
use crate::expose;
use crate::fleet;
use crate::fleet_ui;
use crate::format_approval_expiry;
use crate::identity;
use crate::identity_flow::local_device_cert;
use crate::local_request;
use crate::owner_cap_header;
use crate::owner_signed_cap_ops;
use crate::parse_duration_secs;
use crate::pidfile;
use crate::request_entries;
use crate::ui;
use crate::up_log;
use anyhow::{Result, anyhow};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::Duration;

/// Bare-command tour: what tunlion is, the current state, and the two or three
/// things you'd actually do next, adapted to whether you've paired anyone yet. No
/// flags to learn; `--help` still has the full surface. (CLI-UX work, point #2.)
pub(crate) fn tour_cmd() -> Result<()> {
    let color = ui::stdout_color();
    ui::say(&format!(
        "  {}  {}",
        ui::paint_when(color, ui::Tone::Brand, "tunlion"),
        ui::paint_when(color, ui::Tone::Dim, "/ one thread across every device"),
    ));
    ui::say("");
    match daemon_alive() {
        Some(pid) => ui::say(&format!(
            "  {} daemon up (pid {pid})",
            ui::paint_when(color, ui::Tone::Ok, ui::glyph_ok())
        )),
        None => ui::say(&format!(
            "  {} daemon not running",
            ui::paint_when(color, ui::Tone::Dim, "·")
        )),
    }
    let n = devices_load().len();
    let identity = identity::UserKey::load(&crate::platform::PlatformKeyStore)?;
    ui::say(&format!("  {n} device{}", if n == 1 { "" } else { "s" }));
    // U1: this screen READS the identity, it does not mint one. Bare `tunlion`
    // is the command people run to see what tunlion is, and it must not write
    // a private key as a side effect of being looked at, nor fail on the two
    // devices that cannot mint (joined, opt-out set). What U1 changes here is
    // the verdict: a missing identity stopped being a warning, because `init`
    // stopped being a precondition and the next verb creates the key itself.
    match identity {
        Some(key) => ui::say(&format!(
            "  identity {}",
            ui::paint_when(color, ui::Tone::Bold, &key.fingerprint())
        )),
        None if local_device_cert().is_some() => ui::say(&format!(
            "  identity {}",
            ui::paint_when(color, ui::Tone::Dim, "joined device (owner holds the key)")
        )),
        None => ui::say(&format!(
            "  identity {}",
            ui::paint_when(color, ui::Tone::Dim, "created when you first use one")
        )),
    }
    ui::say("");
    ui::say(&ui::paint_when(color, ui::Tone::Dim, "  do this:"));
    let act = |cmd: &str, desc: &str| ui::say(&format!("    {:<24} {}", cmd, desc));
    act("tunlion send <file>", "send something");
    if n == 0 {
        act("tunlion add", "add a device or person");
    } else {
        act("tunlion mount", "open files from another device");
        act("tunlion shell <device>", "open an authorized terminal");
    }
    act("tunlion receive", "receive once");
    act("tunlion up", "serve: receive, mount (shell with --shell)");
    act("tunlion up --install", "the same, always-on");
    ui::say(&ui::paint_when(
        color,
        ui::Tone::Dim,
        "  more:  tunlion --help  /  tunlion devices  /  tunlion id",
    ));
    Ok(())
}

/// How long `status` waits for the daemon to answer on its control socket.
const STATUS_PROBE: Duration = Duration::from_millis(1500);

pub(crate) async fn status_cmd(json: bool) -> Result<()> {
    // A live pid is not a working daemon. Ask it something, briefly: a stopped
    // (SIGSTOP) or wedged daemon, or one whose control socket could not be
    // created, keeps its pid and used to be reported "up".
    let pid_alive = daemon_alive();
    let responding = match pid_alive {
        Some(_) => crate::ctl::daemon_responds(STATUS_PROBE).await,
        None => Some(false),
    };
    // Suspended (SIGSTOP) is told apart from wedged where the kernel says so.
    let suspended = pid_alive.is_some_and(|p| crate::platform::process_stopped(p) == Some(true));
    // Answering is not serving either: a daemon whose signaling link is down
    // or flapping answers here while no peer can reach it. It reports its link.
    let signaling = if responding == Some(true) {
        crate::daemon_health::signaling().await
    } else {
        None
    };
    let degraded = signaling.as_ref().and_then(crate::daemon_health::degraded_reason);
    if json {
        let pid = pid_alive;
        let exposed: Vec<Value> = expose::load()
            .iter()
            .map(|b| json!({ "port": b.port, "target": b.target, "peers": b.peers.clone().unwrap_or_default() }))
            .collect();
        let mut recent: Vec<String> = std::fs::read_to_string(up_log())
            .map(|log| log.lines().rev().take(8).map(str::to_string).collect())
            .unwrap_or_default();
        recent.reverse();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "running": pid.is_some(),
                "pid": pid,
                // false: a process holds the pidfile but does not answer on its
                // control socket. null: this platform cannot ask.
                "responding": responding,
                "suspended": suspended,
                // The daemon's own view of its signaling link, and the reason
                // it is degraded (null when healthy or not running).
                "signaling": signaling,
                "degraded": degraded,
                "devices": devices_load().len(),
                "exposed": exposed,
                "recent": recent,
            }))?
        );
        return Ok(());
    }
    match pid_alive {
        Some(pid) if responding == Some(false) && suspended => ui::say(&format!(
            "  {} running but not responding (pid {pid}): it is suspended (SIGSTOP), so it serves nothing. `kill -CONT {pid}` resumes it; `tunlion down` stops it",
            ui::paint(ui::Tone::Err, ui::glyph_err()),
        )),
        Some(pid) if responding == Some(false) => {
            let sock = crate::ctl::control_sock_path();
            // Say which: no socket at all (it was never bound, or was removed)
            // is a different fault from a socket nobody answers on.
            let at = if sock.exists() {
                format!("it did not answer on its control socket ({}) within {}s", sock.display(), STATUS_PROBE.as_secs_f32())
            } else {
                format!("its control socket ({}) does not exist", sock.display())
            };
            ui::say(&format!(
                "  {} running but not responding (pid {pid}): {at}. It may be stopped (SIGSTOP) or wedged; `tunlion down` then `tunlion up` restarts it",
                ui::paint(ui::Tone::Err, ui::glyph_err()),
            ))
        }
        Some(pid) if degraded.is_some() => ui::say(&format!(
            "  {} up but degraded (pid {pid}): {}",
            ui::paint(ui::Tone::Warn, "!"),
            degraded.as_deref().unwrap_or_default()
        )),
        Some(pid) => ui::say(&format!(
            "  {} up (pid {pid})",
            ui::paint(ui::Tone::Ok, ui::glyph_ok())
        )),
        None => ui::say(&format!(
            "  {} not running, start with: tunlion up",
            ui::paint(ui::Tone::Dim, "·")
        )),
    }
    let n = devices_load().len();
    ui::say(&format!(
        "  {} known device{}",
        n,
        if n == 1 { "" } else { "s" }
    ));
    let exposed = expose::load();
    if !exposed.is_empty() {
        ui::say(&ui::paint(ui::Tone::Dim, "  exposed on .mesh:"));
        for b in exposed {
            let scope = match &b.peers {
                Some(p) if !p.is_empty() => p.join(","),
                _ => "any".into(),
            };
            ui::say(&format!(
                "    :{} {} {}  ({})",
                b.port,
                ui::glyph_arrow(),
                b.target,
                scope
            ));
        }
    }
    if let Ok(log) = std::fs::read_to_string(up_log()) {
        let recent: Vec<&str> = log.lines().rev().take(8).collect();
        if !recent.is_empty() {
            ui::say(&ui::paint(ui::Tone::Dim, "  recent receives:"));
            for l in recent.iter().rev() {
                ui::say(&format!("    {l}"));
            }
        }
    }
    match status_exit_code(pid_alive.is_some(), responding) {
        0 => Ok(()),
        code => std::process::exit(code),
    }
}

/// `status` exits 0 only when a daemon serves this config dir and answers.
/// Otherwise a script branches on the code instead of parsing prose (it exited
/// 0 for both of these):
///
/// - 11 (`STATUS_NOT_RUNNING`): no daemon serves this config dir.
/// - 6 (`unreachable` in the exit-code taxonomy): a daemon holds this config
///   dir but did not answer on its control socket in time (suspended, wedged,
///   or no socket).
///
/// `status --json` keeps exit 0 and reports both in `running`/`responding`:
/// the JSON is the answer, and its reader asked for data, not a verdict.
/// A platform that cannot ask the daemon (`responding` null) is not a failure.
pub(crate) fn status_exit_code(running: bool, responding: Option<bool>) -> i32 {
    match (running, responding) {
        (false, _) => STATUS_NOT_RUNNING,
        (true, Some(false)) => STATUS_NOT_RESPONDING,
        _ => 0,
    }
}

/// No daemon serves this config dir. A status-only code (like `up`'s 10),
/// listed under EXIT CODES in `tunlion --help`.
pub(crate) const STATUS_NOT_RUNNING: i32 = 11;
/// A daemon runs but did not answer in time: the taxonomy's 6, `unreachable`
/// ("did not answer in time"), so one number keeps one meaning across verbs.
pub(crate) const STATUS_NOT_RESPONDING: i32 = 6;

#[cfg(test)]
mod status_exit_tests {
    use super::status_exit_code;

    #[test]
    fn status_exits_nonzero_unless_a_daemon_serves_and_answers() {
        assert_eq!(status_exit_code(true, Some(true)), 0);
        assert_eq!(status_exit_code(true, None), 0, "a platform that cannot ask is not a failure");
        assert_eq!(status_exit_code(true, Some(false)), 6);
        assert_eq!(status_exit_code(false, Some(false)), 11);
        assert_eq!(status_exit_code(false, None), 11);
    }
}

/// Human state text for a DELEGATED device's row, quoting the binding clock
/// from effective_principal_deadline (never restating a bound we do not compute).
/// Returns None for owner devices (they keep the existing cert countdown).
pub(crate) fn delegated_device_state(
    name: &str,
    cert: Option<&identity::DeviceCert>,
    now: u64,
    records: &[Value],
) -> Option<(String, ui::Tone)> {
    let cert = cert?;
    let record = records.iter().find(|d| d["name"].as_str() == Some(name))?;
    // REVOCATION FIRST, before the principal-kind gate. Revoking is a decision
    // about a device, not about a principal kind, and it applies to any record we
    // hold. A fleet sibling is indexed WITHOUT a delegated principal, so gating
    // this behind "delegated" meant `devices revoke <sibling>` succeeded, wrote
    // certRevoked, correctly denied the device on reconnect, and then listed it
    // as perfectly healthy. A revocation you cannot see is one you cannot trust.
    if record["certRevoked"].as_bool() == Some(true)
        || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
    {
        return Some(("revoked".to_string(), ui::Tone::Err));
    }
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    let not_after = record["principalExpires"].as_u64();
    let last_seen = record["lastSeen"].as_u64();
    let max_offline = record["principalMaxOffline"].as_u64();
    let (deadline, clock) =
        effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
    if record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED) || deadline <= now {
        return Some(("lapsed".to_string(), ui::Tone::Warn));
    }
    let secs = deadline - now;
    let (n, unit) = if secs < 3600 {
        (secs / 60, "m")
    } else if secs < 86400 {
        (secs / 3600, "h")
    } else {
        (secs / 86400, "d")
    };
    let clock_label = match clock {
        DeadlineClock::CertExpiry => "cert expires",
        DeadlineClock::AbsoluteStop => "stop time",
        DeadlineClock::LivenessBudget => "offline budget",
    };
    Some((format!("{n}{unit} left ({clock_label})"), ui::Tone::Dim))
}

/// CLI handler for `tunlion requests`
pub(crate) async fn requests_cmd(action: Option<RequestsAction>) -> Result<()> {
    match action {
        None | Some(RequestsAction::List { all: false }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(
                    &v, false,
                ))),
                // `None` means the control socket did not answer, which is not
                // the same as "no daemon". Saying "not running" while `status`
                // shows it up is the contradiction a first-time-user test hit.
                None => match crate::shell_support::daemon_alive() {
                    Some(pid) => ui::say(&format!(
                        "  the daemon is running (pid {pid}) but did not answer on its control socket at {}; \
                         check `tunlion up`'s output for why",
                        crate::ctl::control_sock_path().display()
                    )),
                    None => ui::say("  daemon not running; no pending request state"),
                },
            }
        }
        Some(RequestsAction::List { all: true }) => {
            let reply = crate::ctl::try_list_pending().await;
            match reply {
                Some(v) => ui::say(&fleet_ui::requests::render_requests(&request_entries(
                    &v, true,
                ))),
                None => ui::say("  daemon not running; no request state"),
            }
        }
        Some(RequestsAction::Approve {
            id,
            allow,
            duration,
        }) => {
            let expires =
                crate::capability::now_secs().saturating_add(parse_duration_secs(&duration)?);
            let reply = crate::ctl::try_approve_request(id, &allow, expires).await;
            match reply {
                Some(v) => {
                    if let Some(peer) = v.get("peer").and_then(|v| v.as_str()) {
                        if let Some(cap) = v.get("capability").and_then(|v| v.as_str()) {
                            if let Some(granted_expires) = v.get("expires").and_then(|v| v.as_u64())
                            {
                                let expiry = format_approval_expiry(granted_expires);
                                ui::say(&fleet_ui::requests::render_approve_success(
                                    peer, cap, &expiry,
                                ));
                            } else {
                                ui::say(&format!(
                                    "  {} approval succeeded but the grant expiry was missing",
                                    ui::paint(ui::Tone::Err, ui::glyph_err()),
                                ));
                            }
                        }
                    }
                }
                None => ui::say(&format!(
                    "  {} request {id} not found or daemon not running",
                    ui::paint(ui::Tone::Warn, "x")
                )),
            }
        }
        Some(RequestsAction::Deny { id }) => {
            let peer = local_request(id).map(|request| request.peer);
            let reply = crate::ctl::try_deny_request(id).await;
            match reply {
                Some(_) => {
                    if let Some(peer) = peer {
                        ui::say(&fleet_ui::requests::render_deny_success(&peer));
                    } else {
                        ui::say(&format!(
                            "  {} request {id} denied",
                            ui::paint(ui::Tone::Ok, ui::glyph_ok())
                        ));
                    }
                }
                None => ui::say(&format!(
                    "  {} request {id} not found or daemon not running",
                    ui::paint(ui::Tone::Warn, "x")
                )),
            }
        }
    }
    Ok(())
}

/// The owner-signed artifact that makes a peer a member of this mesh.
///
/// A certificate for the peer's device key, our own certificate so it can verify
/// the chain, and (for a PERSISTENT member) the fleet meeting point plus the
/// capability header and signed policy.
///
/// This exists as ONE function because it is the only place a DeviceCert is
/// minted for somebody else. It was written inline in the enrol handler, and the
/// pairing ceremony could not produce one, which is why `tunlion add` left a
/// device paired but not on the mesh. Hand-writing it a second time is how the
/// fleet handshake ended up with four per-peer bugs in copies that had drifted.
///
/// `persistent` is the whole distinction between a member and a borrower: an
/// ephemeral peer holds a certificate for one session and never receives
/// `fleet_rv`, so it cannot take part in the fleet's standing presence.
pub(crate) fn mesh_enrolment(
    owner_key: &identity::UserKey,
    device_pub: [u8; 32],
    caps: &[String],
    expires: u64,
    persistent: bool,
) -> Result<(identity::DeviceCert, Value)> {
    let now = identity::now_secs();
    let cert =
        identity::DeviceCert::certify(owner_key, device_pub, now, expires.saturating_sub(now))
            .map_err(|e| anyhow!("could not certify the device: {e}"))?;
    let payload = json!({
        "device_cert": cert.to_json(),
        "owner_cert": local_device_cert().map(|c| c.to_json()),
        // Only a persistent member joins the fleet meeting point.
        "fleet_rv": persistent.then(|| fleet::rv_load_or_create().ok()).flatten(),
        // A joined device cannot make its own header: ensure_self_genesis_header
        // SIGNS it with the owner's UserKey, which the joiner does not hold. So
        // the owner hands it over. It carries no secret, being signed and
        // self-certifying, and naming owner_pub and a nonce.
        "cap_header": persistent.then(owner_cap_header).flatten(),
        // Owner-authored policy, relayed. The joiner verifies every op against
        // the owner key in the header above, so this is not a trust decision
        // handed to whoever transmits it.
        "cap_ops": persistent.then(|| json!(owner_signed_cap_ops())).unwrap_or(Value::Null),
        "ceiling": caps,
        "expires": expires,
        "persistent": persistent,
    });
    Ok((cert, payload))
}

/// this terminal. The detached child writes the pidfile and serves; its console
/// output goes to {config}/daemon.log so `tunlion logs` can follow it. The
/// detach itself is one portable operation in `platform::spawn_detached`, whose
/// two arms ship together (#215 was the half-written version: the Windows arm
/// computed the log path and threw it away).
pub(crate) async fn detach_up(server: &str, dir: Option<PathBuf>) -> Result<()> {
    let exe = std::env::current_exe()?;
    let log_path = crate::platform::Paths::config_path("daemon.log");
    let dir_arg: Option<String> = dir.as_deref().and_then(|d| d.to_str()).map(str::to_string);
    let mut args: Vec<&str> = vec!["up", "--server", server];
    if let Some(d) = dir_arg.as_deref() {
        args.push("--dir");
        args.push(d);
    }
    // Elect before spawning: if a daemon holds the lock, there is nothing to
    // start. (The children elect again, atomically, for the race this check
    // cannot see: two `up --detach` that both pass it at the same instant.)
    let lock_path = crate::platform::Paths::config_path("up.lock");
    match crate::platform::InstanceLock::try_acquire(&lock_path) {
        Ok(Some(lock)) => drop(lock),
        Ok(None) => {
            return crate::daemon_stop::report_holder(
                crate::daemon_stop::lock_holder(&lock_path),
                &lock_path,
            );
        }
        Err(e) => return Err(crate::up_logs::lock_error(e, &lock_path)),
    }
    // For the startup-death message below: a `down` that ran after this
    // moment is the likely reason a fresh daemon died by a signal.
    let spawned_at = std::time::SystemTime::now();
    let mut child = crate::platform::spawn_detached(&exe, &args, &log_path)?;
    let pid = child.id();
    // Wait for THIS child to become the daemon (its pid in the pidfile), or to
    // exit. "Some daemon is alive" is not enough: with a concurrent start, the
    // daemon alive may be another one, and claiming this one detached was false.
    let mut outcome = None;
    for _ in 0..50 {
        if let Ok(Some(status)) = child.try_wait() {
            outcome = Some(Err(status.code()));
            break;
        }
        if daemon_alive() == Some(pid) {
            outcome = Some(Ok(()));
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    match outcome {
        // Re-check before claiming anything: a `down` racing this start can stop
        // the daemon between the poll above and the sentence below.
        Some(Ok(())) if child.try_wait().ok().flatten().is_none() && daemon_alive() == Some(pid) => {
            ui::say(&format!(
                "  {} daemon detached (pid {pid}, pidfile at {}) - output: {}",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                pidfile().display(),
                log_path.display()
            ));
            Ok(())
        }
        Some(Ok(())) => Err(anyhow!(
            "the daemon (pid {pid}) stopped right after starting{}; see {}",
            if crate::daemon_stop::stopped_by_down_since(spawned_at) {
                ". A `tunlion down` ran while it was starting and stopped it"
            } else {
                ""
            },
            log_path.display()
        )),
        Some(Err(Some(code))) if code == crate::up_logs::UP_LOST_ELECTION_EXIT => {
            // Another `up` won the election at the same instant. Say which
            // process holds it; a suspended or unnamed holder is not "running".
            crate::daemon_stop::report_holder(
                crate::daemon_stop::lock_holder(&lock_path),
                &lock_path,
            )
        }
        Some(Err(code)) => Err(anyhow!(
            "the daemon exited during startup ({}){}; its output is in {}",
            code.map(|c| format!("exit {c}")).unwrap_or_else(|| "killed by a signal".into()),
            if crate::daemon_stop::stopped_by_down_since(spawned_at) {
                ". A `tunlion down` ran while it was starting and stopped it"
            } else {
                ""
            },
            log_path.display()
        )),
        None => {
            ui::say(&format!(
                "  {} spawned the daemon (pid {pid}) but it did not come up within 5s - output: {}",
                ui::paint(ui::Tone::Warn, "!"),
                log_path.display()
            ));
            Ok(())
        }
    }
}
