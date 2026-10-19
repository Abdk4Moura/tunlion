//! Receive-side file mechanics: the CLI half.
//!
//! The host-free leaves moved to `filament-peerloop::recv` (issue #465-style
//! extraction, receive slice): the name-collision rule, the whole-file digest,
//! the `PartMeta` sidecar, the resumable-partial lifecycle, the storage-failure
//! vocabulary, the `StdoutSink`/`IncomingFile` state, the whole-file verify and
//! the confinement-safe `.part` open. This file re-exports them so every
//! `crate::recv_files::…` call site keeps resolving, and keeps only what is
//! genuinely the CLI's:
//!
//!   * `finalize_incoming` — UI, settings, transfer history and the daemon log;
//!   * the inbox helpers — they read the machine's config and filesystem layout;
//!   * `storage_refusal` — a rendered sentence to the peer and the user;
//!   * `delivery_ack` — per-session state riding the wire vocabulary;
//!   * `expire_partials_and_say` / `partial_status_lines` — terminal output.
//!
//! Nothing here re-implements a moved mechanism: the library owns the single
//! implementation and the CLI calls it.
#![allow(unused_imports)]

use crate::protocol;
use crate::settings;
use crate::ui;
use crate::{chrono_now, human, up_log};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

// The moved receive leaves. Re-exported so `crate::recv_files::…` (and the
// crate-root re-exports in `main.rs`) keep resolving to the ONE implementation
// in the peer-loop crate.
pub(crate) use filament_peerloop::recv::{
    IncomingFile, PARTIAL_TTL_SECS, PartMeta, Partial, RecvReport, StdoutSink, WriteFailure,
    age_words, discard_partial, expire_partials, full_hash, numbered_name, partials_json,
    resumable_partials, stdout_put, unique_path, verify_incoming,
};
// The confined `.part` open needs the beneath-root primitive the `mount-server`
// feature owns; the CLI always builds with it (its `mount_proto` shim is
// likewise unconditional).
#[cfg(feature = "mount-server")]
pub(crate) use filament_peerloop::recv::{safe_create_part, safe_resume_part};

/// Transfer id -> the final name a finished file was stored under, read once
/// by the delivery-ack that follows.
static STORED: std::sync::Mutex<Option<std::collections::HashMap<String, String>>> =
    std::sync::Mutex::new(None);

fn note_stored(id: &str, name: &str) {
    if let Ok(mut m) = STORED.lock() {
        m.get_or_insert_with(Default::default).insert(id.to_string(), name.to_string());
    }
}

/// The delivery-ack for transfer `id`, carrying the name it was stored under
/// when this side knows it. `stored` is additive: an older sender ignores it.
pub(crate) fn delivery_ack(id: &str, sid: u32) -> serde_json::Value {
    let mut m = protocol::delivery_ack_msg(id, sid);
    let stored = STORED.lock().ok().and_then(|mut s| s.as_mut()?.remove(id));
    if let Some(name) = stored {
        m["stored"] = serde_json::json!(name);
    }
    m
}

/// A refusal's stable wire token and the sentence both ends show, for a file
/// this receiver cannot store. `need`/`free` are bytes, named when known so
/// "out of disk space" says by how much.
pub(crate) fn storage_refusal(
    kind: Option<crate::platform::StorageFailure>,
    name: &str,
    detail: &str,
    need: Option<u64>,
    free: Option<u64>,
) -> (&'static str, String) {
    use crate::platform::StorageFailure as F;
    match kind {
        Some(F::NoSpace) => (
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
        Some(F::NameTooLong) => (
            "name_too_long",
            format!("receiver's filesystem refuses the name {name} ({detail})"),
        ),
        Some(F::ReadOnly) => (
            "read_only",
            format!("receiver's download folder is read-only, cannot save {name} ({detail})"),
        ),
        Some(F::Permission) => (
            "permission",
            format!("receiver has no permission to write {name} in its download folder ({detail})"),
        ),
        None => ("io", format!("receiver could not save {name}: {detail}")),
    }
}

/// The inbox a daemon serves can be deleted while it runs; every file sent
/// after that was refused "receiver could not save notes.txt: No such file or
/// directory (os error 2)". Recreate it (owner-only, as it was made at start)
/// before a file is accepted. `Ok(true)` when it had to be recreated.
pub(crate) fn ensure_inbox(dir: &Path) -> std::io::Result<bool> {
    if dir.is_dir() {
        return Ok(false);
    }
    crate::platform::create_private_dir_all(dir)?;
    // Something other than a directory (a file) can sit at the path; creating
    // "succeeds" around it without making a directory.
    if !dir.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "something that is not a directory is in its place",
        ));
    }
    Ok(true)
}

/// The typed refusal for an inbox that is missing and cannot be recreated
/// (its parent is read-only, a file sits where it should be).
pub(crate) fn inbox_refusal(dir: &Path, name: &str, e: &std::io::Error) -> (&'static str, String) {
    (
        "inbox_missing",
        format!(
            "receiver's inbox {} is missing and could not be recreated, so it cannot save {name} ({e})",
            dir.display()
        ),
    )
}

/// Free space under which `inbox_problem` calls the inbox's disk full.
const INBOX_FULL_BELOW: u64 = 1024 * 1024;

/// What `status` and `doctor` say about an inbox, when something is wrong with
/// it: missing, not a directory, or on a full disk. `None` otherwise.
pub(crate) fn inbox_problem(dir: &Path) -> Option<String> {
    match std::fs::metadata(dir) {
        // A full disk refuses every file as surely as a missing inbox: say it
        // here too (it was not flagged at 100%).
        Ok(m) if m.is_dir() => crate::platform::free_space(dir)
            .filter(|free| *free < INBOX_FULL_BELOW)
            .map(|free| {
                format!(
                    "the disk holding inbox {} is full ({} free): files sent here are refused until space is freed",
                    dir.display(),
                    human(free)
                )
            }),
        Ok(_) => Some(format!(
            "inbox {} is not a directory: files sent here are refused until it is",
            dir.display()
        )),
        Err(_) => Some(format!(
            "inbox {} is missing: the daemon recreates it when the next file arrives (or create it: mkdir -p {})",
            dir.display(),
            dir.display()
        )),
    }
}

/// Where the running daemon keeps its inbox, beside its pidfile: `status` and
/// `doctor` check that directory, which `up --dir` may have set.
pub(crate) fn daemon_inbox_marker() -> PathBuf {
    crate::pidfile().with_file_name("up.inbox")
}

/// The inbox to check: the running daemon's, else the configured one.
pub(crate) fn inbox_to_check(daemon_running: bool) -> PathBuf {
    daemon_running
        .then(|| std::fs::read_to_string(daemon_inbox_marker()).ok())
        .flatten()
        .map(|s| PathBuf::from(s.trim()))
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| crate::drop_dir(None))
}

/// Expire old partials at receiver start and say what went.
pub(crate) fn expire_partials_and_say(dir: &Path) {
    for p in expire_partials(dir, std::time::SystemTime::now()) {
        ui::say(&format!(
            "  removed an interrupted transfer's partial of {} ({}), unresumed for {} days",
            p.name,
            human(p.bytes),
            p.age_secs / 86_400
        ));
    }
}

/// `status`'s human lines for the partials (none when there are none).
pub(crate) fn partial_status_lines(dir: &Path) -> Vec<String> {
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

/// Finalize a fully-received incoming file: sync, rename `.part` → final,
/// clean up the meta sidecar, and (in daemon mode) append to the upload log.
/// Returns true if the file was placed. Takes `IncomingFile` by value and drops it.
pub(crate) async fn finalize_incoming(
    inc: IncomingFile,
    dir: &Path,
    rename_to: Option<&str>,
    daemon: bool,
    from_name: &str,
    report: &RecvReport,
) -> Result<bool> {
    // Sync then drop file handle before rename (file is closed for the rename on Linux).
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = f.sync_all();
    })
    .await;
    // The partial was assembled owner-only; the delivered file gets the mode
    // an ordinary create would have given it, set through the handle (never a
    // path someone could swap for a symlink) before it is renamed into place.
    if !inc.part_path.as_os_str().is_empty() {
        let _ = crate::platform::publish_received_file(&inc.file);
    }
    drop(inc.file);
    let final_path = unique_path(dir, rename_to.unwrap_or(&inc.name));
    if let Err(e) = tokio::fs::rename(&inc.part_path, &final_path).await {
        ui::say(&ui::paint(
            ui::Tone::Dim,
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
    ui::say(&format!(
        "    {} {}{}",
        ui::paint(ui::Tone::Dim, ui::glyph_arrow()),
        ui::link(&format!("file://{shown}"), &shown),
        if ok {
            String::new()
        } else {
            ui::paint(ui::Tone::Err, "  SIZE MISMATCH")
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
        if is_archive && settings::get_bool("auto-extract", peer) {
            match settings::extract_archive(&final_path, dir) {
                Ok(n) => ui::say(&format!(
                    "    {} extracted {n} file{} into {}",
                    ui::paint(ui::Tone::Ok, ui::glyph_ok()),
                    if n == 1 { "" } else { "s" },
                    dir.display()
                )),
                Err(e) => ui::say(&ui::paint(
                    ui::Tone::Warn,
                    &format!("    auto-extract skipped ({e}); the archive is kept as-is"),
                )),
            }
        }
    }
    // The receiver's half of the structured history (both modes), and the
    // stored name its delivery-ack reports back to the sender.
    let stored_name = final_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    note_stored(&inc.id, &stored_name);
    if !daemon && ok {
        report.note_stored(&inc.name, recvd, inc.full.as_deref(), &stored_name);
    }
    crate::transfer_history::append(&[crate::transfer_history::Record {
        time: crate::transfer_history::now_secs(),
        direction: "in",
        peer: (!from_name.is_empty()).then(|| from_name.to_string()),
        file: inc.name.clone(),
        stored: Some(shown.clone()),
        bytes: recvd,
        sha256: inc.full.clone(),
        ok,
    }]);
    if daemon {
        use std::io::Write as _;
        if let Ok(mut f) = crate::platform::open_private_log(&up_log(), false) {
            let _ = writeln!(
                f,
                "{}  {}  {}  from {}",
                chrono_now(),
                inc.name,
                human(recvd),
                from_name
            );
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("filament-test-partmode-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A fresh `.part` is owner-only from the create itself: the bytes of a
    /// download in progress are not readable by other accounts. Exercises the
    /// re-exported library implementation through the CLI's own name.
    #[tokio::test]
    async fn fresh_part_is_owner_only() {
        let d = mode_dir("fresh");
        let p = d.join("data.bin.part");
        drop(super::safe_create_part(&p).await.unwrap());
        if let Some(m) = crate::platform::file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a fresh .part must be 0600, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Resuming a partial an older build left group/world readable tightens it.
    #[tokio::test]
    async fn resumed_part_is_tightened_to_owner_only() {
        let d = mode_dir("resume");
        let p = d.join("data.bin.part");
        let f = std::fs::File::create(&p).unwrap();
        crate::platform::fs_at::set_mode_via_handle(&f, 0o666).unwrap();
        drop(f);
        drop(super::safe_resume_part(&p).await.unwrap());
        if let Some(m) = crate::platform::file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a resumed .part must be 0600, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The inbox deleted under a running daemon: the next offer recreates it
    /// (status and doctor say it is missing until then); one that cannot be
    /// recreated is a typed refusal naming the inbox, not a bare ENOENT.
    #[test]
    fn a_deleted_inbox_is_recreated_or_refused_by_name() {
        let base = std::env::temp_dir().join(format!("tunlion-inbox-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let inbox = base.join("Tunlion");
        assert!(super::inbox_problem(&inbox).unwrap().contains("is missing"));
        assert!(super::ensure_inbox(&inbox).unwrap(), "recreated");
        assert!(inbox.is_dir());
        assert_eq!(super::inbox_problem(&inbox), None);
        assert!(!super::ensure_inbox(&inbox).unwrap(), "already there: nothing to do");
        // A file where the inbox should be cannot be turned into one.
        let blocked = base.join("blocked");
        std::fs::write(&blocked, b"x").unwrap();
        assert!(super::inbox_problem(&blocked).unwrap().contains("not a directory"));
        let e = super::ensure_inbox(&blocked).unwrap_err();
        let (token, msg) = super::inbox_refusal(&blocked, "notes.txt", &e);
        assert_eq!(token, "inbox_missing");
        assert!(msg.contains(&blocked.display().to_string()) && msg.contains("notes.txt"), "{msg}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// `status` renders the library's partial listing: the TTL header, each
    /// interrupted transfer by name, its size, and an age word. This restores
    /// the CLI-rendering assertions that travelled out of the old partial test
    /// when its data half moved to peerloop::recv.
    #[test]
    fn partial_status_lines_render_the_library_listing() {
        let d = mode_dir("partial-lines");
        assert!(
            super::partial_status_lines(&d).is_empty(),
            "no partials, no lines"
        );

        let old = d.join("old.bin.part");
        std::fs::write(&old, vec![0u8; 4096]).unwrap();
        std::fs::write(d.join("old.bin.part.meta"), b"{}").unwrap();
        std::fs::write(d.join("new.bin.part"), vec![0u8; 10]).unwrap();
        std::fs::write(d.join("new.bin.part.meta"), b"{}").unwrap();
        // A received file that merely ends in `.part` has no meta and is not ours.
        std::fs::write(d.join("notes.part"), b"a file the user received").unwrap();

        // Age the old partial past two days so the rendered age word is stable.
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(
                std::time::SystemTime::now()
                    - std::time::Duration::from_secs(2 * 86_400 + 60),
            )
            .unwrap();

        let lines = super::partial_status_lines(&d);
        assert!(lines[0].contains("removed after 7 days"), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("old.bin")), "{lines:?}");
        assert!(lines.iter().any(|l| l.contains("new.bin")), "{lines:?}");
        assert!(!lines.iter().any(|l| l.contains("notes.part")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("4.0 KiB")),
            "size is rendered: {lines:?}"
        );
        let old_line = lines.iter().find(|l| l.contains("old.bin")).unwrap();
        assert!(old_line.contains("2d old"), "{old_line}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The CLI adapter expires through the library and keeps fresh partials:
    /// the side effect startup relies on. The library's expiry rules keep
    /// their own peerloop tests; this one proves the host adapter + its line.
    #[test]
    fn expire_partials_and_say_removes_only_expired_partials() {
        let d = mode_dir("expire-say");
        let old = d.join("old.bin.part");
        std::fs::write(&old, vec![0u8; 64]).unwrap();
        std::fs::write(d.join("old.bin.part.meta"), b"{}").unwrap();
        std::fs::write(d.join("new.bin.part"), vec![0u8; 8]).unwrap();
        std::fs::write(d.join("new.bin.part.meta"), b"{}").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&old)
            .unwrap()
            .set_modified(
                std::time::SystemTime::now()
                    - std::time::Duration::from_secs(PARTIAL_TTL_SECS + 60),
            )
            .unwrap();

        super::expire_partials_and_say(&d);

        assert!(!old.exists(), "the expired .part is removed");
        assert!(
            !d.join("old.bin.part.meta").exists(),
            "its sidecar is removed"
        );
        assert!(d.join("new.bin.part").exists(), "a fresh .part is kept");
        assert!(
            d.join("new.bin.part.meta").exists(),
            "its sidecar is kept"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `age_words` moved to the library; this proves the CLI re-export resolves
    /// and still renders the boundaries the partial table uses.
    #[test]
    fn age_words_renders_through_the_cli_re_export() {
        assert_eq!(super::age_words(59), "0m");
        assert_eq!(super::age_words(60), "1m");
        assert_eq!(super::age_words(3_599), "59m");
        assert_eq!(super::age_words(3_600), "1h");
        assert_eq!(super::age_words(86_399), "23h");
        assert_eq!(super::age_words(86_400), "1d");
    }
}
