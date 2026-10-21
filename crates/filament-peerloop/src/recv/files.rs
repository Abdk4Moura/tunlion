//! Receive-side file placement, delivery acknowledgement and partial/inbox
//! policy. The byte mechanics already live in [`crate::recv`]; this child owns
//! the invocation-level decisions that used to be the CLI's `recv_files` half.
//!
//! All terminal output goes through [`LogSink`]; all host effects (publish
//! mode, archive extraction, history, daemon upload log, private directories)
//! go through [`HostServices`]. There is no CLI call here.

use crate::host::{HostServices, LogSink, StorageFailure, Tone};
use crate::present::human;
use crate::recv::request_delivery::PermitError;
use crate::recv::{
    age_words, expire_partials, resumable_partials, unique_path, IncomingFile, RecvReport,
    PARTIAL_TTL_SECS,
};
use anyhow::Result;
use filament_proto as protocol;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;

/// One structured receive-history row. The host maps it onto its own store.
pub struct ReceivedFileRecord {
    pub time: u64,
    pub peer: Option<String>,
    pub file: String,
    pub stored: Option<String>,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub ok: bool,
}

/// The delivery-ack for transfer `id`, carrying the name it was stored under
/// when this invocation knows it. `stored` is additive: an older sender ignores
/// it. The map is per invocation, never a process global.
pub fn delivery_ack(
    id: &str,
    sid: u32,
    stored: &std::sync::Arc<Mutex<HashMap<String, String>>>,
) -> serde_json::Value {
    let mut m = protocol::delivery_ack_msg(id, sid);
    let name = stored.lock().ok().and_then(|mut s| s.remove(id));
    if let Some(name) = name {
        m["stored"] = serde_json::json!(name);
    }
    m
}

/// A refusal's stable wire token and the sentence both ends show, for a file
/// this receiver cannot store.
pub fn storage_refusal(
    kind: Option<StorageFailure>,
    name: &str,
    detail: &str,
    need: Option<u64>,
    free: Option<u64>,
) -> (&'static str, String) {
    match kind {
        Some(StorageFailure::NoSpace) => (
            "no_space",
            match (need, free) {
                (Some(n), Some(f)) => format!(
                    "receiver is out of disk space for {name} (needs {}, has {})",
                    human(n),
                    human(f)
                ),
                _ => format!("receiver is out of disk space for {name} ({detail})"),
            },
        ),
        Some(StorageFailure::NameTooLong) => (
            "name_too_long",
            format!("receiver's filesystem refuses the name {name} ({detail})"),
        ),
        Some(StorageFailure::ReadOnly) => (
            "read_only",
            format!("receiver's download folder is read-only, cannot save {name} ({detail})"),
        ),
        Some(StorageFailure::Permission) => (
            "permission",
            format!("receiver has no permission to write {name} in its download folder ({detail})"),
        ),
        None => ("io", format!("receiver could not save {name}: {detail}")),
    }
}

/// The inbox a daemon serves can be deleted while it runs. Recreate it before
/// a file is accepted. `Ok(true)` when it had to be recreated.
pub fn ensure_inbox(host: &dyn HostServices, dir: &Path) -> std::io::Result<bool> {
    if dir.is_dir() {
        return Ok(false);
    }
    host.create_private_dir(dir)?;
    if !dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "something that is not a directory is in its place",
        ));
    }
    Ok(true)
}

/// The typed refusal for an inbox that is missing and cannot be recreated.
pub fn inbox_refusal(dir: &Path, name: &str, e: &std::io::Error) -> (&'static str, String) {
    (
        "inbox_missing",
        format!(
            "receiver's inbox {} is missing and could not be recreated, so it cannot save {name} ({e})",
            dir.display()
        ),
    )
}

/// Expire old partials at receiver start and say what went.
pub fn expire_partials_and_say(dir: &Path, log: &dyn LogSink) {
    for p in expire_partials(dir, std::time::SystemTime::now()) {
        log.say(&format!(
            "  removed an interrupted transfer's partial of {} ({}), unresumed for {} days",
            p.name,
            human(p.bytes),
            p.age_secs / 86_400
        ));
    }
}

/// `status`'s human lines for the partials (none when there are none).
pub fn partial_status_lines(dir: &Path) -> Vec<String> {
    let parts = resumable_partials(dir, std::time::SystemTime::now());
    if parts.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "  interrupted transfers in {} (resume by sending again; removed after {} days):",
        dir.display(),
        PARTIAL_TTL_SECS / 86_400
    )];
    for p in parts {
        lines.push(format!(
            "    {}  {} so far, {} old",
            p.name,
            human(p.bytes),
            age_words(p.age_secs)
        ));
    }
    lines
}

/// Finalize a fully-received incoming file: sync, rename `.part` to final,
/// clean up the meta sidecar, and record it. Returns true if placed.
pub async fn finalize_incoming(
    host: &dyn HostServices,
    log: &dyn LogSink,
    inc: IncomingFile,
    dir: &Path,
    rename_to: Option<&str>,
    daemon: bool,
    from_name: &str,
    report: &RecvReport,
    delivery: &std::sync::Arc<Mutex<HashMap<String, String>>>,
) -> Result<bool> {
    let durable = inc.durable.clone();
    if let Some(permit) = &durable {
        match permit.check(host) {
            Ok(_) => {}
            Err(PermitError::Authority(error)) => {
                log.say(&format!("  delivery stopped: {error}"));
                let _ = permit.fail(host);
                permit.clean_staged();
                drop(inc.file);
                crate::recv::discard_partial(&inc.part_path);
                return Ok(false);
            }
            Err(PermitError::Transient(error)) => {
                log.say(&format!("  delivery paused: {error}"));
                return Ok(false);
            }
        }
        if !matches!(crate::recv::verify_incoming(&inc).await, protocol::VerifyResult::Match) {
            log.say("  delivery stopped: staged bytes do not match the approved manifest");
            let _ = permit.fail(host);
            permit.clean_staged();
            drop(inc.file);
            crate::recv::discard_partial(&inc.part_path);
            return Ok(false);
        }
    }
    let f = inc.file.clone();
    let synced = tokio::task::spawn_blocking(move || f.sync_all()).await;
    if durable.is_some() {
        match synced {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                // A sync failure means the bytes may not be durable. Keep the
                // staged artifact for a retry; do not terminalize the request.
                log.critical(&format!("  cannot sync the received file: {error}"));
                return Ok(false);
            }
            Err(error) => {
                log.critical(&format!("  sync task failed for the received file: {error}"));
                return Ok(false);
            }
        }
    } else {
        let _ = synced;
    }
    if !inc.part_path.as_os_str().is_empty() {
        let _ = host.publish_received_file(&inc.file);
    }
    drop(inc.file);
    let final_path = durable.as_ref().map(|permit| permit.destination.clone())
        .unwrap_or_else(|| unique_path(dir, rename_to.unwrap_or(&inc.name)));
    // A durable approval binds this exact destination. Never silently choose
    // another name or replace a file someone created after approval.
    if let Some(permit) = &durable {
        // Authority can change while the file is being hashed/synced. Recheck
        // immediately before placement, not only at function entry.
        match permit.check(host) {
            Ok(_) => {}
            Err(PermitError::Authority(error)) => {
                log.say(&format!("  delivery stopped: {error}"));
                let _ = permit.fail(host);
                permit.clean_staged();
                crate::recv::discard_partial(&inc.part_path);
                return Ok(false);
            }
            Err(PermitError::Transient(error)) => {
                log.say(&format!("  delivery paused: {error}"));
                return Ok(false);
            }
        }
    }
    let placed = if durable.is_some() {
        tokio::fs::hard_link(&inc.part_path, &final_path).await
    } else {
        tokio::fs::rename(&inc.part_path, &final_path).await
    };
    if let Err(error) = placed {
        if let Some(permit) = &durable {
            // A crash after hard_link but before the receipt leaves the final
            // link already in place. Only that exact artifact counts; a foreign
            // file at the destination is a terminal collision.
            if permit.same_artifact() && permit.verify_final().is_ok() {
                // Continue to the receipt commit below.
            } else {
                log.critical(&format!(
                    "  refused placement for {}: destination is not this request's artifact ({error})",
                    inc.name
                ));
                let _ = permit.remove_final_if_own();
                let _ = permit.fail(host);
                permit.clean_staged();
                crate::recv::discard_partial(&inc.part_path);
                return Ok(false);
            }
        } else {
            log.say(&log.paint(
                Tone::Dim,
                &format!(
                    "  (stream for {} already finalized, duplicate discarded: {error})",
                    inc.name
                ),
            ));
            return Ok(false);
        }
    }
    if let Some(permit) = &durable {
        if let Err(error) = permit.verify_final() {
            log.critical(&format!(
                "  refused final placement for {}: {error}",
                inc.name
            ));
            let _ = permit.remove_final_if_own();
            let _ = permit.fail(host);
            permit.clean_staged();
            crate::recv::discard_partial(&inc.part_path);
            return Ok(false);
        }
        #[cfg(unix)]
        if let Err(error) = std::fs::File::open(&permit.receive_root)
            .and_then(|directory| directory.sync_all())
        {
            // The bytes and the final name exist but the receipt has not
            // committed. Keep both artifacts for the sender's retry; never
            // unwind the whole receive loop for a directory fsync failure.
            log.critical(&format!(
                "  final directory sync failed; receipt awaits retry: {error}"
            ));
            return Ok(false);
        }
        // Commit the receipt before acknowledging delivery. A crash between
        // placement and commit is recovered by matching the request-specific
        // staged artifact on the sender's retry, never by re-delivering under
        // another name.
        match permit.complete(host) {
            Ok(()) => {
                permit.clean_staged();
                crate::recv::discard_partial(&inc.part_path);
            }
            Err(PermitError::Authority(error)) => {
                log.critical(&format!(
                    "  delivery stopped after placement: {error}"
                ));
                let _ = permit.remove_final_if_own();
                let _ = permit.fail(host);
                permit.clean_staged();
                crate::recv::discard_partial(&inc.part_path);
                return Ok(false);
            }
            Err(PermitError::Transient(error)) => {
                // A store write/read failure is retryable: keep the final link
                // and the staged part so the next offer can recover the receipt.
                log.critical(&format!(
                    "  file placed; delivery receipt awaits retry: {error}"
                ));
                return Ok(false);
            }
        }
    }
    let mut meta_path = inc.part_path.as_os_str().to_owned();
    meta_path.push(".meta");
    let _ = tokio::fs::remove_file(PathBuf::from(meta_path)).await;
    let recvd = inc.received.load(Ordering::Relaxed);
    let ok = recvd == inc.size;
    inc.bar.done(recvd);
    let shown = final_path.display().to_string();
    log.say(&format!(
        "    {} {}{}",
        log.paint(Tone::Dim, log.glyph_arrow()),
        shown,
        if ok {
            String::new()
        } else {
            log.paint(Tone::Err, "  SIZE MISMATCH")
        },
    ));
    if ok {
        let lname = final_path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_archive =
            lname.ends_with(".tar") || lname.ends_with(".tar.gz") || lname.ends_with(".tgz");
        let peer = (!from_name.is_empty()).then_some(from_name);
        if is_archive && durable.is_none() && host.settings_get_bool_for("auto-extract", peer) {
            match host.extract_received_archive(&final_path, dir) {
                Ok(n) => log.say(&format!(
                    "    {} extracted {n} file{} into {}",
                    log.paint(Tone::Ok, log.glyph_ok()),
                    if n == 1 { "" } else { "s" },
                    dir.display()
                )),
                Err(e) => log.say(&log.paint(
                    Tone::Warn,
                    &format!("    auto-extract skipped ({e}); the archive is kept as-is"),
                )),
            }
        }
    }
    let stored_name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Ok(mut m) = delivery.lock() {
        m.insert(inc.id.clone(), stored_name.clone());
    }
    if !daemon && ok {
        report.note_stored(&inc.name, recvd, inc.full.as_deref(), &stored_name);
    }
    host.record_received_file(&ReceivedFileRecord {
        time: host.now_secs(),
        peer: (!from_name.is_empty()).then(|| from_name.to_string()),
        file: inc.name.clone(),
        stored: Some(shown.clone()),
        bytes: recvd,
        sha256: inc.full.clone(),
        ok,
    });
    if daemon {
        host.append_receive_log(&format!(
            "{}  {}  {}  from {}",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S"),
            inc.name,
            human(recvd),
            from_name
        ));
    }
    Ok(true)
}

/// Flush every by_sid entry to disk before the loop reports done.
pub async fn flush_inflight(by_sid: &mut HashMap<(String, u32), IncomingFile>) {
    for (_, inc) in by_sid.drain() {
        let f = inc.file.clone();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = f.sync_all();
        })
        .await;
    }
}

/// Finalize streams whose bytes are complete but whose sender left before
/// file-end. `received == size` is exactly the bar the file-end handler uses.
#[allow(clippy::too_many_arguments)]
pub async fn sweep_completed_streams(
    host: &dyn HostServices,
    log: &dyn LogSink,
    by_sid: &mut HashMap<(String, u32), IncomingFile>,
    conn: &crate::conn::Conn,
    dir: &Path,
    output: &Option<String>,
    to_stdout: bool,
    daemon: bool,
    report: &RecvReport,
    completed: &mut usize,
    delivery: &std::sync::Arc<Mutex<HashMap<String, String>>>,
) -> Result<()> {
    let done_sids: Vec<(String, u32)> = by_sid
        .iter()
        .filter(|((pid, _), inc)| {
            inc.received.load(Ordering::Relaxed) == inc.size && !conn.links.contains_key(pid)
        })
        .map(|(k, _)| k.clone())
        .collect();
    for key in done_sids {
        if let Some(inc) = by_sid.remove(&key) {
            if to_stdout {
                let f = inc.file.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = f.sync_all();
                })
                .await;
                *completed += 1;
                continue;
            }
            let rename_to = if *completed == 0 {
                output.clone()
            } else {
                None
            };
            log.say(&log.paint(
                Tone::Dim,
                &format!(
                    "  ({} fully received, sender left before file-end; finalizing)",
                    inc.name
                ),
            ));
            if finalize_incoming(
                host,
                log,
                inc,
                dir,
                rename_to.as_deref(),
                daemon,
                "",
                report,
                delivery,
            )
            .await?
            {
                *completed += 1;
            }
        }
    }
    Ok(())
}

/// The inbox marker the daemon writes beside its pidfile.
pub fn daemon_inbox_marker() -> PathBuf {
    PathBuf::from("up.inbox")
}
