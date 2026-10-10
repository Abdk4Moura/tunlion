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
            ui::paint_when(
                color,
                ui::Tone::Dim,
                "none yet: tunlion init, or tunlion join <invitation>"
            )
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

/// The identity as `--json` reports it, as two fields that each mean one
/// thing: `identity` is always the owner fingerprint (the same 8 hex `id`
/// shows) or null with none yet, and `role` is "owner" (holds the signing
/// key), "joined-device" (`id --json`'s spelling) or null. `identity` used to be
/// a fingerprint on one device and the string "joined" on another.
pub(crate) fn identity_fields() -> (Value, Value) {
    match identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        Ok(Some(key)) => (json!(key.fingerprint()), json!("owner")),
        _ => match local_device_cert() {
            Some(cert) => (json!(owner_fingerprint(&cert.user_pub)), json!("joined-device")),
            None => (Value::Null, Value::Null),
        },
    }
}

/// The fingerprint of an owner public key, as `UserKey::fingerprint` renders
/// it. Pure.
pub(crate) fn owner_fingerprint(user_pub: &[u8; 32]) -> String {
    hex::encode(user_pub).chars().take(8).collect()
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
        // Structured transfer records from both directions, newest last.
        let recent = crate::transfer_history::recent(RECENT);
        let (identity, role) = identity_fields();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "verb": "status",
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
                // Always the owner fingerprint or null; `role` says whether
                // this device is the owner or a joined one. Read only; status
                // never mints.
                "identity": identity,
                "role": role,
                // The SOCKS proxy the daemon auto-starts without a TUN: its
                // address and how to use it (the token's PATH, never the
                // token), or null when none is running.
                "proxy": crate::proxy_state::to_json(crate::proxy_state::current().as_ref()),
            }))?
        );
        return Ok(());
    }
    if !crate::identity_flow::has_identity() {
        ui::say(&format!(
            "  {} {}",
            ui::paint(ui::Tone::Dim, "·"),
            crate::identity_flow::NO_IDENTITY_MSG
        ));
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
    if let Some(p) = crate::proxy_state::current() {
        for line in crate::proxy_state::status_lines(&p) {
            ui::say(&line);
        }
    }
    let recent = crate::transfer_history::recent(RECENT);
    if !recent.is_empty() {
        ui::say(&ui::paint(ui::Tone::Dim, "  recent transfers:"));
        for r in &recent {
            ui::say(&format!("    {}", crate::transfer_history::human_line(r)));
        }
    } else if let Ok(log) = std::fs::read_to_string(up_log()) {
        // A daemon from before the structured history only has its log.
        let recent: Vec<&str> = log.lines().rev().take(RECENT).collect();
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
pub(crate) const STATUS_NOT_RUNNING: i32 = crate::exit_codes::STATUS_NOT_RUNNING;
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

/// How many transfers `status` shows.
const RECENT: usize = 8;

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
                    let peer = v.get("peer").and_then(|v| v.as_str());
                    let cap = v.get("capability").and_then(|v| v.as_str());
                    let granted = v.get("expires").and_then(|v| v.as_u64());
                    match (peer, cap, granted) {
                        (Some(peer), Some(cap), Some(granted_expires)) => {
                            let expiry = format_approval_expiry(granted_expires);
                            ui::say(&fleet_ui::requests::render_approve_success(
                                peer, cap, &expiry,
                            ));
                        }
                        // The daemon said ok but the reply does not say what
                        // was granted to whom, or until when. Printing nothing
                        // and exiting 0 read as success with no evidence.
                        _ => {
                            return Err(anyhow!(
                                "the daemon accepted request {id} but its reply is missing {}; \
                                 check `tunlion devices --caps` for what was granted",
                                [("peer", peer.is_none()), ("capability", cap.is_none()), ("expiry", granted.is_none())]
                                    .iter()
                                    .filter(|(_, missing)| *missing)
                                    .map(|(f, _)| *f)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));
                        }
                    }
                }
                None => return Err(request_reply_missing(id, "approve")),
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
                None => return Err(request_reply_missing(id, "deny")),
            }
        }
    }
    Ok(())
}

/// Why an approve/deny got no ok reply, as an error (nonzero exit). The two
/// causes are told apart, because one is fixed by `tunlion up` and the other
/// by picking an id from `tunlion requests`.
fn request_reply_missing(id: u64, verb: &str) -> anyhow::Error {
    match daemon_alive() {
        None => anyhow!(
            "could not {verb} request {id}: the daemon is not running (pending requests live in the daemon; start it with `tunlion up`)"
        ),
        Some(pid) => anyhow!(
            "could not {verb} request {id}: the daemon (pid {pid}) has no pending request with that id, or refused it; `tunlion requests` lists the pending ones"
        ),
    }
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
///
/// `daemon_argv` is the whole `up` argv from `up_logs::DaemonOpts`, so the
/// detached daemon gets every flag this `up --detach` was given (it used to get
/// `--server` and `--dir` only, and silently lost `--shell`, `--relay`,
/// `--userspace` and the rest).
pub(crate) async fn detach_up(daemon_argv: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let log_path = crate::platform::Paths::config_path("daemon.log");
    let args: Vec<&str> = daemon_argv.iter().map(String::as_str).collect();
    // daemon.log is appended to, so remember where THIS run's output starts:
    // a failure report must quote this daemon, not the last one.
    let log_start = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
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
    // "ok daemon detached" used to mean only "a pidfile appeared", and `up`
    // writes its pidfile before it has done anything, so a daemon that died a
    // moment later (no network, a bad --dir) was reported as running and this
    // exited 0. Wait, bounded, for the daemon to say it is SERVING (the ready
    // marker it writes beside sd_notify READY=1, or its control socket), or to
    // exit, whichever comes first.
    let deadline = std::time::Instant::now() + DETACH_READY_WAIT;
    let outcome = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break DetachOutcome::Exited(status.code());
        }
        if crate::file_io::ready_marker_pid() == Some(pid)
            || (crate::ctl::daemon_present().await && daemon_alive() == Some(pid))
        {
            break DetachOutcome::Ready;
        }
        if std::time::Instant::now() >= deadline {
            break DetachOutcome::NotReadyYet;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    // Re-check before claiming "serving": a `down` racing this start can stop
    // the daemon after it signalled ready (the ready marker outlives it), and
    // "detached and serving (pid N)" was then printed for a pid already gone.
    let outcome = match outcome {
        DetachOutcome::Ready => match child.try_wait() {
            Ok(Some(status)) => DetachOutcome::Exited(status.code()),
            _ if daemon_alive() != Some(pid) => DetachOutcome::Exited(None),
            _ => DetachOutcome::Ready,
        },
        other => other,
    };
    let tail = log_tail_since(&log_path, log_start, DETACH_LOG_LINES);
    match outcome {
        // Another `up` won the single-instance election at the same instant: a
        // daemon is running, which is what was asked for.
        // Say which process holds it; a suspended or unnamed holder is not
        // "running".
        DetachOutcome::Exited(Some(code)) if code == crate::up_logs::UP_LOST_ELECTION_EXIT => {
            crate::daemon_stop::report_holder(
                crate::daemon_stop::lock_holder(&lock_path),
                &lock_path,
            )
        }
        DetachOutcome::Ready => {
            ui::say(&format!(
                "  {} daemon detached and serving (pid {pid}, pidfile at {}) - output: {}",
                ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                pidfile().display(),
                log_path.display()
            ));
            Ok(())
        }
        DetachOutcome::NotReadyYet => {
            // Alive, not serving yet: it is still waiting for the network (the
            // daemon retries by design rather than exit), so this is not a
            // failure, but it must not read as "serving" either.
            ui::say(&format!(
                "  {} daemon started (pid {pid}) but is not connected yet; it keeps retrying in the background. Check with `tunlion status`. Output: {}",
                ui::paint(ui::Tone::Warn, "!"),
                log_path.display()
            ));
            if let Some(last) = tail.last() {
                ui::say(&format!("    last: {last}"));
            }
            Ok(())
        }
        DetachOutcome::Exited(code) => {
            let kind = detach_failure_kind(&tail);
            ui::critical(&format!(
                "{} the daemon exited during startup ({}){}. Its last output ({}):",
                ui::paint(ui::Tone::Err, ui::glyph_err()),
                code.map(|c| format!("exit {c}")).unwrap_or_else(|| "killed by a signal".into()),
                if crate::daemon_stop::stopped_by_down_since(spawned_at) {
                    "; a `tunlion down` ran while it was starting and stopped it"
                } else {
                    ""
                },
                log_path.display()
            ));
            if tail.is_empty() {
                ui::critical("    (nothing was written)");
            }
            for line in &tail {
                ui::critical(&format!("    {line}"));
            }
            Err(crate::exit_codes::reported(kind))
        }
    }
}

/// How long `up --detach` waits for the daemon to report it is serving.
const DETACH_READY_WAIT: Duration = Duration::from_secs(10);
/// How many lines of the daemon's own output a failed `up --detach` quotes.
const DETACH_LOG_LINES: usize = 12;

/// What became of a detached daemon within `DETACH_READY_WAIT`.
enum DetachOutcome {
    Ready,
    NotReadyYet,
    Exited(Option<i32>),
}

/// The last `n` non-empty lines written to `path` after byte `start`, without
/// terminal colour codes. Pure apart from the read.
pub(crate) fn log_tail_since(path: &std::path::Path, start: u64, n: usize) -> Vec<String> {
    let Ok(bytes) = std::fs::read(path) else {
        return Vec::new();
    };
    let from = usize::try_from(start).unwrap_or(0).min(bytes.len());
    tail_lines(&String::from_utf8_lossy(&bytes[from..]), n)
}

/// The last `n` non-empty lines of `text`, ANSI escapes removed.
pub(crate) fn tail_lines(text: &str, n: usize) -> Vec<String> {
    let lines: Vec<String> = text
        .lines()
        .map(strip_ansi)
        .map(|l| l.trim_end().to_string())
        .filter(|l| !l.trim().is_empty())
        .collect();
    lines[lines.len().saturating_sub(n)..].to_vec()
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// The exit kind for a daemon that died during `up --detach`, read from what
/// it printed: the network if that is what it said, otherwise "other".
pub(crate) fn detach_failure_kind(tail: &[String]) -> crate::exit_codes::ExitKind {
    let text = tail.join("\n");
    match crate::exit_codes::classify_text(&text) {
        crate::exit_codes::ExitKind::Network => crate::exit_codes::ExitKind::Network,
        _ => crate::exit_codes::ExitKind::Other,
    }
}
