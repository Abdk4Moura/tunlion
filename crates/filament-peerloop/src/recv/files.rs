//! Receive-side file placement, delivery acknowledgement and partial/inbox
//! policy. The byte mechanics already live in [`crate::recv`]; this child owns
//! the invocation-level decisions that used to be the CLI's `recv_files` half.
//!
//! All terminal output goes through [`LogSink`]; all host effects (publish
//! mode, archive extraction, history, daemon upload log, private directories)
//! go through [`HostServices`]. There is no CLI call here.

use crate::host::{HostServices, LogSink, StorageFailure, Tone};
use crate::present::human;
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

/// Transfer id -> the final name a finished file was stored under, read once
/// by the delivery-ack that follows.
static STORED: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn note_stored(id: &str, name: &str) {
    if let Ok(mut m) = STORED.lock() {
        m.get_or_insert_with(Default::default)
            .insert(id.to_string(), name.to_string());
    }
}

/// The delivery-ack for transfer `id`, carrying the name it was stored under
/// when this side knows it. `stored` is additive: an older sender ignores it.
pub fn delivery_ack(id: &str, sid: u32) -> serde_json::Value {
    let mut m = protocol::delivery_ack_msg(id, sid);
    let stored = STORED.lock().ok().and_then(|mut s| s.as_mut()?.remove(id));
    if let Some(name) = stored {
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
) -> Result<bool> {
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = f.sync_all();
    })
    .await;
    if !inc.part_path.as_os_str().is_empty() {
        let _ = host.publish_received_file(&inc.file);
    }
    drop(inc.file);
    let final_path = unique_path(dir, rename_to.unwrap_or(&inc.name));
    if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
        log.say(&log.paint(
            Tone::Dim,
            &format!(
                "  (stream for {} already finalized, duplicate discarded: {e})",
                inc.name
            ),
        ));
        return Ok(false);
    }
    let _ = tokio::fs::remove_file(dir.join(format!("{}.part.meta", inc.name))).await;
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
        if is_archive && host.settings_get_bool_for("auto-extract", peer) {
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
    note_stored(&inc.id, &stored_name);
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
