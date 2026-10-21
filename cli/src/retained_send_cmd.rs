//! Process adapter for explicit retained sends. Waiting is a distinct outcome,
//! never passed through the ordinary send-success/history path.
//!
//! Exit 0 on `--defer` means "accepted and retained", not "delivered". The
//! `--json` result always makes that explicit with `queued:true`,
//! `delivered:false`, and `state:"waiting"`. Ordinary sends keep their existing
//! exit-0 = every-file-delivered contract.
//!
//! Cancel is explicitly LOCAL-ONLY: it stops retries and removes the private
//! sender snapshot. It does not claim the receiver withdrew an already-pending
//! durable request; that request is bounded by the receiver's 7-day expiry.
use anyhow::{anyhow, bail, Context, Result};
use filament_peerloop::driver::{Cancellation, DriverOutcome};
use filament_peerloop::host::HostServices;
use filament_peerloop::retained_send::{
    RetainedError, RetainedSend, RetainedStore, SendState, SUBDIR,
};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn now() -> u64 {
    crate::identity::now_secs()
}
fn store() -> Result<RetainedStore> {
    Ok(RetainedStore::open(crate::settings::config_dir())?)
}

fn peer_key(name: &str) -> Result<String> {
    let cert = crate::device_cert_for(name).ok_or_else(|| {
        anyhow!("retained sends require a paired device with a stored certificate")
    })?;
    let key = hex::encode(cert.device_pub);
    filament_peerloop::recv::request_delivery::current_sender(&crate::host_impl::CliHost, &key)?;
    Ok(key)
}

pub(crate) fn check_stream(id: &str, expected_rev: u64) -> Result<()> {
    let record = store()?
        .get(id)?
        .ok_or_else(|| anyhow!("retained offer was removed"))?;
    // The revision is the claim owner. A takeover after expiry bumps it, so an
    // old suspended writer cannot keep streaming under the new claim.
    if record.rev != expected_rev {
        bail!("retained offer was superseded by another attempt");
    }
    if record.state != SendState::Waiting
        || record.claim_until <= now()
        || record.expires_at <= now()
    {
        bail!("retained offer no longer authorizes this attempt");
    }
    Ok(())
}

struct Bounded<W> {
    inner: W,
    left: u64,
}
impl<W: Write> Write for Bounded<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() as u64 > self.left {
            return Err(std::io::Error::other(
                "retained snapshot exceeds its byte limit",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.left -= count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn prepare(
    path: &str,
    name: Option<&str>,
    guard: &mut Option<crate::send_cmd::SpoolDir>,
    limit: u64,
) -> Result<(PathBuf, String)> {
    if path == "-" {
        let spool = crate::send_cmd::SpoolDir::path_in(guard, "stdin")?;
        let mut file = crate::send_cmd::SpoolDir::create(&spool)?;
        let bytes = std::io::copy(
            &mut std::io::stdin().lock().take(limit.saturating_add(1)),
            &mut file,
        )?;
        if bytes > limit {
            bail!("retained stdin exceeds its byte limit");
        }
        file.sync_all()?;
        return Ok((spool, name.unwrap_or("stdin.bin").to_owned()));
    }
    let source = PathBuf::from(path);
    let metadata = std::fs::symlink_metadata(&source)?;
    if metadata.file_type().is_symlink() {
        bail!("retained sources must not be symlinks");
    }
    let basename = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow!("source must have a UTF-8 file name"))?;
    if metadata.is_dir() {
        let spool = crate::send_cmd::SpoolDir::path_in(guard, "directory.tar")?;
        let file = crate::send_cmd::SpoolDir::create(&spool)?;
        let mut archive = tar::Builder::new(Bounded {
            inner: file,
            left: limit,
        });
        archive.append_dir_all(basename, &source)?;
        archive.finish()?;
        return Ok((spool, format!("{basename}.tar")));
    }
    if !metadata.is_file() {
        bail!("retained sources must be regular files or directories");
    }
    let offered = name.unwrap_or(basename).to_owned();
    Ok((source, offered))
}

async fn attempt(
    inbox: &RetainedStore,
    record: RetainedSend,
    timeout: Option<u64>,
) -> Result<RetainedSend> {
    if record.state != SendState::Waiting {
        return Ok(record);
    }
    // A name can be rebound after enqueue. Never follow that new name/key.
    if !peer_key(&record.peer_name).is_ok_and(|key| key == record.peer_device_id) {
        return Ok(inbox.terminal(&record.id, record.rev, SendState::Stale, now())?);
    }
    if inbox.verify_source(&record).is_err() {
        return Ok(inbox.terminal(&record.id, record.rev, SendState::Stale, now())?);
    }
    let peer_device: [u8; 32] = match hex::decode(&record.peer_device_id)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
    {
        Some(device) => device,
        None => {
            return Ok(inbox.terminal(&record.id, record.rev, SendState::Stale, now())?);
        }
    };

    let claimed = match inbox.mark_attempt(&record.id, record.rev, now()) {
        Ok(claimed) => claimed,
        Err(RetainedError::Busy { .. }) | Err(RetainedError::RevisionConflict { .. }) => {
            // A daemon child or another manual CLI already owns (or just
            // advanced) this offer. Return the current truth as waiting/terminal;
            // a live lease is not an invocation failure.
            return inbox
                .get(&record.id)?
                .ok_or_else(|| anyhow!("retained offer was removed"));
        }
        Err(RetainedError::Expired(_)) => {
            inbox.expire(now())?;
            return inbox
                .get(&record.id)?
                .ok_or_else(|| anyhow!("retained offer was removed"));
        }
        Err(error) => return Err(error.into()),
    };

    // History is armed only for an actual sender attempt. A waiting/deferred
    // offer must never be persisted as a successful send.
    crate::send_report::arm_history(
        Some(claimed.peer_name.as_str()),
        vec![claimed.name().to_owned()],
    );

    let result = tokio::time::timeout(
        Duration::from_secs(90),
        crate::send_cmd::send_retained_attempt(
            &claimed.server,
            claimed.source_path().to_string_lossy().into_owned(),
            claimed.peer_name.clone(),
            claimed.manifest.entries[0].path.clone(),
            claimed.relay_only,
            timeout.or(Some(15)),
            crate::send_cmd::RetainedSeed {
                id: claimed.id.clone(),
                peer_device,
                manifest: claimed.manifest.clone(),
                rev: claimed.rev,
            },
        ),
    )
    .await;
    match result {
        Ok(Ok(())) => {
            let done = inbox.terminal(&claimed.id, claimed.rev, SendState::Delivered, now())?;
            crate::send_report::persist_outcome(None);
            Ok(done)
        }
        Ok(Err(error)) if error.is::<crate::send_cmd::RetainedDeclined>() => {
            Ok(inbox.terminal(&claimed.id, claimed.rev, SendState::Denied, now())?)
        }
        Ok(Err(error)) if error.is::<crate::send_cmd::RetainedSourceChanged>() => {
            Ok(inbox.terminal(&claimed.id, claimed.rev, SendState::Stale, now())?)
        }
        Ok(Err(error)) if error.is::<crate::send_cmd::RetainedManifestMismatch>() => {
            Ok(inbox.terminal(&claimed.id, claimed.rev, SendState::Failed, now())?)
        }
        Ok(Err(error)) => {
            let (delay, request_id) = error
                .downcast_ref::<crate::send_cmd::WaitingForReceiver>()
                .map(|waiting| (waiting.retry_after, waiting.request_id.as_deref()))
                .unwrap_or((30, None));
            crate::ui::debug(&format!(
                "retained attempt ended without a delivery receipt: {error}"
            ));
            Ok(inbox.defer(&claimed.id, claimed.rev, delay, request_id, now())?)
        }
        Err(_) => Ok(inbox.defer(&claimed.id, claimed.rev, 30, None, now())?),
    }
}

fn outcome(records: &[RetainedSend]) -> Value {
    let delivered = !records.is_empty()
        && records
            .iter()
            .all(|record| record.state == SendState::Delivered);
    let waiting = records
        .iter()
        .any(|record| record.state == SendState::Waiting);
    let state = if delivered {
        "delivered"
    } else if waiting {
        "waiting"
    } else {
        "closed"
    };
    json!({
        "ok": delivered || waiting,
        "verb": "send",
        // Exit 0 in this opt-in mode means "accepted and retained", not
        // "delivered". A waiting offer is explicitly false here.
        "queued": waiting && !delivered,
        "delivered": delivered,
        "state": state,
        "files": records.iter().map(|record| json!({
            "file": record.name(),
            "bytes": record.size(),
            "sha256": record.sha256(),
            "delivered": record.state == SendState::Delivered,
            "state": record.state,
            "offer": record.id,
        })).collect::<Vec<_>>(),
        "offers": records.iter().map(|record| json!({
            "id": record.id, "state": record.state, "peer": record.peer_name,
            "manifest": record.manifest.digest, "next_attempt_at": record.next_attempt_at,
            "expires_at": record.expires_at, "relay_only": record.relay_only,
        })).collect::<Vec<_>>()
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn command(
    server: &str,
    paths: Vec<String>,
    to: Option<String>,
    name: Option<String>,
    relay: bool,
    timeout: Option<u64>,
    defer: bool,
    resume: Option<String>,
    cancel: Option<String>,
    json_out: bool,
) -> Result<()> {
    let inbox = store()?;
    inbox.expire(now())?;
    if let Some(id) = cancel {
        let record = inbox
            .get(&id)?
            .ok_or_else(|| anyhow!("no retained outgoing offer {id}"))?;
        if record.claim_until > now() {
            bail!("this offer has an active attempt; cancellation was not recorded, retry after it finishes");
        }
        let closed = inbox.terminal(&id, record.rev, SendState::Cancelled, now())?;
        if json_out {
            crate::ui::json_out(&json!({
                "ok": true,
                "verb": "send",
                "queued": false,
                "delivered": false,
                "state": "cancelled",
                "files": [],
                "offers": [{"id": closed.id.clone(), "state": closed.state}],
            }));
        } else {
            crate::ui::say(&format!(
                "cancelled outgoing offer {id} locally; retries stopped and the private snapshot was removed. \
                 This does not claim the receiver withdrew its durable request; if it was already pending \
                 or approved there, it expires within 7 days (or when the receiver cancels it)."
            ));
        }
        return Ok(());
    }
    let mut records = Vec::new();
    if let Some(id) = resume {
        let record = inbox
            .get(&id)?
            .ok_or_else(|| anyhow!("no retained outgoing offer {id}"))?;
        if to
            .as_deref()
            .is_some_and(|name| !record.peer_name.eq_ignore_ascii_case(name))
        {
            bail!("retained offer belongs to a different named device");
        }
        records.push(attempt(&inbox, record, timeout).await?);
    } else {
        if !defer || paths.is_empty() {
            bail!("pass a source and a named device with --defer --to");
        }
        let peer = to.ok_or_else(|| anyhow!("retained offers require --to"))?;
        let canonical_peer = crate::devices_store::devices_load()
            .into_iter()
            .find(|(known, _)| known.eq_ignore_ascii_case(&peer))
            .map(|(name, _)| name)
            .ok_or_else(|| anyhow!("retained offers require an already paired named device"))?;
        let key = peer_key(&canonical_peer)?;
        let mut queued: Vec<RetainedSend> = Vec::new();
        for path in &paths {
            let mut guard = None;
            let single_name = (paths.len() == 1).then_some(name.as_deref()).flatten();
            let prepared = prepare(
                path,
                single_name,
                &mut guard,
                inbox.limits().max_single_bytes,
            )
            .and_then(|(source, name)| {
                let safe_name = filament_transfer::safe_incoming_name(&name);
                inbox
                    .enqueue_file_with_relay(
                        &canonical_peer,
                        &key,
                        server,
                        &source,
                        &safe_name,
                        relay,
                        now(),
                    )
                    .map_err(Into::into)
            });
            match prepared {
                Ok(record) => queued.push(record),
                Err(error) => {
                    for record in queued {
                        let _ = inbox.terminal(&record.id, record.rev, SendState::Cancelled, now());
                    }
                    return Err(error
                        .context("could not retain all requested sources; no send was attempted"));
                }
            }
        }
        for record in queued {
            records.push(attempt(&inbox, record, timeout).await?);
        }
    }
    let result = outcome(&records);
    if json_out {
        crate::ui::json_out(&result);
    } else {
        for record in &records {
            let state = if record.state == SendState::Waiting {
                "retained; waiting for the receiver (retries while serving)"
            } else if record.state == SendState::Delivered {
                "delivered and verified"
            } else {
                "closed without delivery"
            };
            crate::ui::say(&format!("outgoing {}: {state}", record.id));
        }
    }
    if result["delivered"] == json!(false) && result["state"] == json!("closed") {
        let denied = records.iter().any(|record| record.state == SendState::Denied);
        let kind = if denied {
            crate::exit_codes::ExitKind::Denied
        } else {
            crate::exit_codes::ExitKind::Other
        };
        return Err(crate::exit_codes::err(
            kind,
            "the retained offer closed without a delivery receipt",
        ));
    }
    Ok(())
}

pub(crate) fn say_section(all: bool) -> Result<()> {
    if !crate::settings::config_dir().join(SUBDIR).exists() {
        return Ok(());
    }
    let inbox = store()?;
    inbox.expire(now())?;
    let records: Vec<_> = inbox
        .snapshot()?
        .into_iter()
        .filter(|record| all || record.state == SendState::Waiting)
        .collect();
    if records.is_empty() {
        return Ok(());
    }
    crate::ui::say("\n  Outgoing retained offers:");
    for record in records {
        crate::ui::say(&format!(
            "  {}  to {}  {:?}  {} bytes  next retry {}",
            record.id,
            record.peer_name,
            record.state,
            record.manifest.total_bytes,
            record.next_attempt_at
        ));
        if record.state == SendState::Waiting {
            crate::ui::say(&format!("    retry: tunlion send --resume {}", record.id));
            crate::ui::say(&format!("    cancel: tunlion send --cancel {}", record.id));
        }
    }
    Ok(())
}

/// Kill only this child's process group (the group is created below). Never a
/// broad process-name match.
async fn terminate_child(child: &mut tokio::process::Child) {
    if let Some(pid) = child.id() {
        let _ = crate::platform::signal_process_group(pid, crate::platform::TreeSignal::Kill);
    }
    let _ = child.start_kill();
    let _ = child.wait().await;
}

/// The CLI daemon reuses the existing sender driver in a child of the same
/// isolated executable/config. No shell, separate queue or unowned task. Each
/// child is reaped on completion or shutdown; the outbox lease survives a crash.
pub(crate) async fn retry_loop(stop: Cancellation) {
    while !stop.is_cancelled() {
        if crate::settings::config_dir().join(SUBDIR).exists() {
            if let Ok(inbox) = store() {
                let _ = inbox.expire(now());
                if let Ok(records) = inbox.due(now()) {
                    for record in records {
                        if stop.is_cancelled() {
                            break;
                        }
                        let Ok(executable) = std::env::current_exe() else {
                            break;
                        };
                        let mut command = crate::platform::tokio_command(executable);
                        let mut args: Vec<String> = vec![
                            "--server".into(),
                            record.server.clone(),
                            "--no-interactive".into(),
                            "--quiet".into(),
                        ];
                        if record.relay_only {
                            args.push("--relay".into());
                        }
                        args.extend([
                            "send".into(),
                            "--resume".into(),
                            record.id.clone(),
                            "--timeout".into(),
                            "15".into(),
                        ]);
                        command
                            .args(&args)
                            .env("TUNLION_CONFIG_DIR", crate::settings::config_dir())
                            .stdin(std::process::Stdio::null())
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .kill_on_drop(true);
                        crate::platform::own_process_group(&mut command);
                        crate::platform::die_with_daemon(&mut command);
                        if let Ok(mut child) = command.spawn() {
                            crate::platform::contain_with_daemon(&child);
                            let waited = tokio::time::timeout(
                                Duration::from_secs(100),
                                stop.run(child.wait()),
                            )
                            .await;
                            match waited {
                                Ok(DriverOutcome::Cancelled) => {
                                    terminate_child(&mut child).await;
                                    return;
                                }
                                Err(_) => {
                                    // A wedged child must not hold the whole due
                                    // queue hostage; kill its own group and reap.
                                    terminate_child(&mut child).await;
                                }
                                Ok(DriverOutcome::Returned(_)) => {}
                            }
                        }
                    }
                }
            }
        }
        let _ = stop.run(tokio::time::sleep(Duration::from_secs(5))).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_snapshot_writer_refuses_oversized_input() {
        let mut writer = Bounded {
            inner: Vec::new(),
            left: 3,
        };
        writer.write_all(b"abc").unwrap();
        assert!(writer.write_all(b"d").is_err());
    }
    #[test]
    fn no_empty_result_claims_delivery() {
        assert_eq!(outcome(&[])["delivered"], false);
    }
}
