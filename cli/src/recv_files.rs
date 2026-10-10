//! Receive-side file assembly and whole-file verification, lifted out of
//! `main.rs` (goal: shrink `main.rs` without touching the receive loop).
//!
//! Everything here is a leaf: each item takes its inputs explicitly
//! (`&Path`, `&IncomingFile`, `IncomingFile`) and returns a value. None of it
//! reads a `recv_cmd` local, opens a channel, or spawns work of its own, which
//! is why the move needs no context struct and no ownership reshaping.
//!
//! cfg discipline: `safe_create_part` and `safe_resume_part` each exist twice
//! (`#[cfg(unix)]` / `#[cfg(not(unix))]`) and both halves moved together with
//! their attributes; their platform `use` statements are function-local and
//! travelled inside the bodies.
use crate::dlog;
use crate::protocol;
use crate::settings;
use crate::test_hooks;
use crate::ui;
use crate::{chrono_now, human, up_log};
use anyhow::Result;
use filament_transfer::{coverage_complete, first_gap};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// P4 (GAP-5): sha256 over the WHOLE file, the end-to-end content digest the
/// receiver compares against on completion so a truncated/corrupt transfer can
/// never be declared "done" (the runner had to bolt this above the transport;
/// P4 makes it a core guarantee). Streamed in 1 MiB reads so a large payload
/// doesn't have to be slurped into RAM. `None` if the file can't be read, the
/// offer then omits `full` and the receiver degrades to the legacy size-only
/// check (backward-compat; bounded, never a hang).
pub(crate) fn full_hash(path: &Path) -> Option<String> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => h.update(&buf[..n]),
            Err(_) => return None,
        }
    }
    Some(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// Where a received `name` lands in `dir` without replacing anything already
/// there: `name` itself when free, else `stem (1).ext`, `stem (2).ext`, ...
///
/// The counter goes BEFORE the extension. It used to be appended after it
/// (`report.pdf.1`), which nothing opens as a PDF and which a file manager
/// shows as an unknown type. A compound archive extension stays whole
/// (`backup (1).tar.gz`). The result never exceeds the 255-byte name limit:
/// the stem is shortened (on a character boundary) to make room for the
/// counter, so a name already at the limit still gets a free slot rather than
/// an ENAMETOOLONG.
pub(crate) fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    for i in 1..1000 {
        let c = dir.join(numbered_name(name, &format!(" ({i})")));
        if !c.exists() {
            return c;
        }
    }
    dir.join(numbered_name(name, " (dup)"))
}

/// The longest file name we create, in bytes (NAME_MAX on Linux and macOS).
const NAME_LIMIT: usize = 255;

/// `name` with `tag` inserted between its stem and its extension, the stem
/// shortened if the whole would pass NAME_LIMIT. Pure.
pub(crate) fn numbered_name(name: &str, tag: &str) -> String {
    let (stem, ext) = split_extension(name);
    let room = NAME_LIMIT.saturating_sub(tag.len() + ext.len());
    let mut cut = stem.len().min(room);
    while cut > 0 && !stem.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}{tag}{ext}", &stem[..cut])
}

/// (stem, extension-with-dot). A leading dot is part of the stem (`.bashrc`
/// has no extension), a trailing dot is not an extension, and `.tar.<x>` is
/// kept together.
fn split_extension(name: &str) -> (&str, &str) {
    let Some(dot) = name.rfind('.') else { return (name, "") };
    if dot == 0 || dot + 1 == name.len() {
        return (name, "");
    }
    let lower = name.to_ascii_lowercase();
    if let Some(tar) = lower[..dot].rfind(".tar") {
        if tar > 0 && tar + 4 == dot {
            return (&name[..tar], &name[tar..]);
        }
    }
    (&name[..dot], &name[dot..])
}

/// Create a FRESH .part file. Uses RESOLVE_BENEATH on Linux (TOCTOU-safe,
/// protects symlinked parents too), O_NOFOLLOW on other Unix, create_new
/// (O_EXCL) on non-Unix. O_EXCL means "fail if exists" — correct for fresh,
/// WRONG for resume (use safe_resume_part for that).
///
/// Windows (since 0.7.3): opens with FILE_FLAG_OPEN_REPARSE_POINT so a
/// symlink/junction at the .part path is NOT followed. Rejects reparse points
/// after open. This closes the Windows half that 0.7.2/0.7.3 explicitly deferred.
#[cfg(unix)]
pub(crate) async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    // On Linux: use safe_open_beneath with O_CREAT|O_EXCL for one-primitive guarantee
    #[cfg(target_os = "linux")]
    {
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let rel = path.strip_prefix(parent).unwrap_or(path);
        // deny_symlinks=true: this is the final component of a file we are
        // creating. It must never be a symlink, so an attacker who can write
        // into the download directory cannot plant one that redirects an
        // incoming transfer to a different file in that same directory. The
        // mount path uses false because a symlink beneath the share root is
        // legitimate content; do not unify these without the security entry.
        crate::mount_proto::safe_open_beneath(
            parent,
            rel,
            (libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY) as i32,
            true,
        )
        .map_err(|e| std::io::Error::new(e.kind(), format!("safe create .part: {e}")))
        .map(|f| tokio::fs::File::from_std(f))
    }
    // Non-Linux Unix: O_NOFOLLOW + O_EXCL (only protects final component)
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await
    }
}

/// Resume an EXISTING .part file. NO O_EXCL (must open existing), but
/// RESOLVE_BENEATH on Linux (or O_NOFOLLOW on other Unix) AND an explicit
/// fstat check that what you opened is a REGULAR file — because O_NOFOLLOW
/// alone will happily open a FIFO or device node someone dropped at that path.
///
/// Windows (since 0.7.3): opens with FILE_FLAG_OPEN_REPARSE_POINT so a
/// symlink/junction at the .part path is NOT followed. Rejects reparse points
/// and non-regular files after open. This closes the Windows half that
/// 0.7.2/0.7.3 explicitly deferred.
#[cfg(unix)]
pub(crate) async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    // On Linux: use safe_open_beneath (RESOLVE_BENEATH)
    // Add O_NONBLOCK to prevent blocking on FIFOs/special files
    #[cfg(target_os = "linux")]
    {
        let parent = path.parent().unwrap_or(std::path::Path::new("."));
        let rel = path.strip_prefix(parent).unwrap_or(path);
        // deny_symlinks=true, same reason as safe_create_part: the .part final
        // component must never be a symlink planted inside the download
        // directory. The mount path uses false; keep them distinct.
        let file = crate::mount_proto::safe_open_beneath(
            parent,
            rel,
            libc::O_WRONLY | libc::O_NONBLOCK as i32,
            true,
        )
        .map_err(|e| std::io::Error::new(e.kind(), format!("safe resume .part: {e}")))?;
        // Verify what we opened is a regular file (not FIFO, device, etc.)
        let meta = file.metadata()?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to resume: .part is not a regular file (type: {:?})",
                    meta.file_type()
                ),
            ));
        }
        Ok(tokio::fs::File::from_std(file))
    }
    // Non-Linux Unix: open with O_NOFOLLOW, then fstat the opened fd
    // (not stat the path before open — that races a swap)
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .await?;

        // fstat on the opened fd — no TOCTOU
        let meta = file.metadata().await?;
        if !meta.file_type().is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "refusing to resume: .part is not a regular file (type: {:?})",
                    meta.file_type()
                ),
            ));
        }
        Ok(file)
    }
}

/// Windows: create a FRESH .part file, refusing to follow symlinks/junctions.
/// Opens with FILE_FLAG_OPEN_REPARSE_POINT so a reparse point at the path
/// is NOT followed, then rejects if the opened file is a reparse point.
/// FILE_FLAG_BACKUP_SEMANTICS allows opening a directory junction for the
/// handle-based attribute check.
/// This closes the Windows half deferred in 0.7.2/0.7.3.
#[cfg(not(unix))]
pub(crate) async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem as WinFs;

    // Open with FILE_FLAG_OPEN_REPARSE_POINT so CreateFile does NOT follow
    // a symlink/junction at the path. CREATE_NEW = fail if exists.
    // FILE_FLAG_BACKUP_SEMANTICS allows opening a directory junction.
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(WinFs::FILE_FLAG_OPEN_REPARSE_POINT | WinFs::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .await?;

    // Post-open check via handle (fstat, not stat-the-path — no TOCTOU).
    let handle = file.as_raw_handle();
    let mut info: WinFs::BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { WinFs::GetFileInformationByHandle(handle as *mut _, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    if (info.dwFileAttributes & WinFs::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to create .part: path is a reparse point (symlink/junction)",
        ));
    }

    Ok(file)
}

/// Windows: resume an EXISTING .part file, refusing symlinks/junctions and
/// non-regular files. Opens with FILE_FLAG_OPEN_REPARSE_POINT so a reparse
/// point at the path is NOT followed, then rejects reparse points and
/// non-regular files after open.
/// FILE_FLAG_BACKUP_SEMANTICS allows opening a directory junction for the
/// handle-based attribute check.
/// This closes the Windows half deferred in 0.7.2/0.7.3.
#[cfg(not(unix))]
pub(crate) async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem as WinFs;

    // Open with FILE_FLAG_OPEN_REPARSE_POINT so CreateFile does NOT follow
    // a symlink/junction at the path. OPEN_EXISTING = must exist.
    // FILE_FLAG_BACKUP_SEMANTICS allows opening a directory junction.
    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .custom_flags(WinFs::FILE_FLAG_OPEN_REPARSE_POINT | WinFs::FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .await?;

    // Post-open check via handle (fstat, not stat-the-path — no TOCTOU).
    let handle = file.as_raw_handle();
    let mut info: WinFs::BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { WinFs::GetFileInformationByHandle(handle as *mut _, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Reject reparse points (symlinks, junctions)
    if (info.dwFileAttributes & WinFs::FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "refusing to resume .part: path is a reparse point (symlink/junction)",
        ));
    }

    // Reject non-regular files (directories, devices, etc.)
    if (info.dwFileAttributes & WinFs::FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "refusing to resume: .part is a directory (attrs: {:#x})",
                info.dwFileAttributes
            ),
        ));
    }

    Ok(file)
}

pub(crate) struct IncomingFile {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) size: u64,
    /// Atomic counter so background writer tasks can publish received bytes
    /// without locking. The event loop polls this for progress updates.
    pub(crate) received: Arc<AtomicU64>,
    /// Disjoint sorted byte intervals [start, end) received so far, for
    /// out-of-order reassembly from multi-stream transports. Shared via
    /// Mutex so concurrent spawn_blocking writer tasks can update safely.
    pub(crate) ranges: Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// Raw file handle shared across concurrent spawn_blocking writer tasks.
    /// Positional writes go through `pwrite_at` (write_at on Unix, seek_write on
    /// Windows) which is atomic per call — no seek needed, safe for concurrent
    /// access.
    pub(crate) file: Arc<std::fs::File>,
    pub(crate) part_path: PathBuf,
    /// P4 (GAP-5): the whole-file sha256 the SENDER offered (`full`). On
    /// completion we hash the received `.part` and compare, only a match
    /// finalizes + acks. `None` = the sender offered no digest (old peer / an
    /// un-hashable source); we fall back to the legacy size-only acceptance and
    /// do NOT ack (nothing to verify), which the sender's bounded fallback covers.
    pub(crate) full: Option<String>,
    /// Number of inflight spawn_blocking write tasks. The event loop uses
    /// this to decide when a file is ready for finalization:
    ///   inflight == 0 && end_seen → finalize
    pub(crate) inflight: Arc<AtomicI64>,
    /// Set by the file-end handler when the sender reports end-of-file, even
    /// if inflight writes are still pending. The last finishing writer checks
    /// this flag and emits Ev::MaybeComplete if both conditions are met.
    pub(crate) end_seen: Arc<AtomicBool>,
    /// The sid to use in the delivery-ack message. Set from the file-end
    /// control frame; read by the MaybeComplete handler for the ack.
    pub(crate) ack_sid: u32,
    /// Tracks the last received value used for progress display (to avoid
    /// re-ticking the same value). Not atomic — only accessed from the event loop.
    pub(crate) last_tick: u64,
    pub(crate) bar: ui::Progress,
}

/// P4 (GAP-5): recompute the whole-file sha256 of the received `.part` and
/// compare against the digest the sender offered (`inc.full`, guaranteed Some by
/// the caller). Flushes first so every buffered byte is on disk. This is the
/// CORE whole-file integrity guarantee the runner used to bolt on above the
/// transport, now every `recv` gets it.
///
/// Test hook (the truncation/ack gate): `FILAMENT_TEST_CORRUPT_RECV=<id>` flips
/// a byte of the on-disk `.part` for the matching transfer id right before the
/// hash is computed, deterministically inducing the corrupt-receive case so the
/// gate can prove reject + recover. `FILAMENT_TEST_CORRUPT_ONCE=1` makes it fire
/// exactly once (the re-fetch then succeeds), proving auto-recovery.
/// Recompute the whole-file sha256 and compare against the sender's offered
/// digest. Flushes (syncs) first. This is the receiver-side core of P4 integrity.
pub(crate) async fn verify_incoming(inc: &IncomingFile) -> protocol::VerifyResult {
    let want = match &inc.full {
        Some(w) => w.clone(),
        None => return protocol::VerifyResult::Match,
    };
    // Sync file to disk before hashing.
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = f.sync_all();
    })
    .await;

    let recvd = inc.received.load(Ordering::Relaxed);

    // Test-only corruption injection (deterministic; gate proof). Compiled out
    // entirely on default/release builds, the `corrupt_recv_target` twin returns
    // None there, so this whole block strips to nothing.
    if let Some(target) = test_hooks::corrupt_recv_target() {
        #[cfg(feature = "test-hooks")]
        {
            let once = test_hooks::corrupt_recv_once();
            let already = test_hooks::corrupt_already_fired();
            if target == inc.id && recvd == inc.size && !(once && already) {
                if let Ok(mut bytes) = std::fs::read(&inc.part_path) {
                    if let Some(b) = bytes.last_mut() {
                        *b ^= 0xFF;
                        let _ = std::fs::write(&inc.part_path, &bytes);
                        eprintln!(
                            "[test] CORRUPT-RECV: flipped the last byte of {} (id {})",
                            inc.name, inc.id
                        );
                        if once {
                            test_hooks::corrupt_mark_fired();
                        }
                    }
                }
            }
        }
        let _ = &target;
    }

    if recvd < inc.size {
        return protocol::decide_verify(recvd, inc.size, None);
    }

    // Contiguity guard: before hashing, verify coverage is one contiguous
    // [0,size) interval. Any gap means the file has unwritten bytes even
    // though received == size. Report WHERE the first gap is.
    {
        let r = inc.ranges.lock().unwrap();
        if !coverage_complete(&r, inc.size) {
            let _gap = first_gap(&r, inc.size);
            dlog!(
                "[recv] INCOMPLETE at verify: {} ranges, received {}/{}, first gap at {:?}",
                r.len(),
                recvd,
                inc.size,
                gap
            );
            drop(r);
            return protocol::decide_verify(recvd, inc.size, None); // re-fetch, never a false Match
        }
    }

    let path = inc.part_path.clone();
    let got = tokio::task::spawn_blocking(move || full_hash(&path))
        .await
        .ok()
        .flatten();
    protocol::decide_verify(recvd, inc.size, Some(got.as_deref() == Some(want.as_str())))
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
) -> Result<bool> {
    // Sync then drop file handle before rename (file is closed for the rename on Linux).
    let f = inc.file.clone();
    let _ = tokio::task::spawn_blocking(move || {
        let _ = f.sync_all();
    })
    .await;
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
    if daemon {
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(up_log())
        {
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
    use crate::{HEAD_BYTES, full_hash, head_hash, sha256_hex, unique_path};
    use super::numbered_name;

    #[test]
    fn full_hash_whole_file_integrity() {
        // P4 (GAP-5): full_hash digests the WHOLE file (not just the 256 KiB
        // head), so a difference PAST the head, exactly the truncation/corrupt
        // case the head-hash can't see, produces a different digest.
        let dir = std::env::temp_dir().join(format!("filament-test-fh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let mut base = vec![3u8; (HEAD_BYTES + 4096) as usize];
        std::fs::write(&a, &base).unwrap();
        // identical head, byte flipped well PAST the head: head_hash agrees but
        // full_hash MUST differ (this is the whole-file guarantee).
        base[(HEAD_BYTES + 2048) as usize] = 4;
        std::fs::write(&b, &base).unwrap();
        assert_eq!(
            head_hash(&a),
            head_hash(&b),
            "tails past the head don't change the head hash"
        );
        assert_ne!(
            full_hash(&a),
            full_hash(&b),
            "full_hash sees the whole file"
        );
        // a truncated file (same prefix, shorter) also differs.
        std::fs::write(&b, &base[..base.len() - 100]).unwrap();
        assert_ne!(
            full_hash(&a),
            full_hash(&b),
            "truncation changes the full hash"
        );
        // full_hash matches a one-shot sha256 of the bytes.
        assert_eq!(
            full_hash(&a),
            Some(sha256_hex(&vec![3u8; (HEAD_BYTES + 4096) as usize]))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unique_path_suffixes() {
        let dir = std::env::temp_dir().join(format!("filament-test-u-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f.txt"));
        std::fs::write(dir.join("f.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f (1).txt"));
        std::fs::write(dir.join("f (1).txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "f.txt"), dir.join("f (2).txt"));
        // A name at the 255-byte limit still gets a free slot, at the limit,
        // with its extension intact (the report: "...xxx.txt.1", 257 bytes).
        let long = format!("{}.txt", "x".repeat(251));
        assert_eq!(long.len(), 255);
        std::fs::write(dir.join(&long), b"x").unwrap();
        let next = unique_path(&dir, &long);
        let got = next.file_name().unwrap().to_str().unwrap().to_string();
        assert!(got.ends_with(" (1).txt"), "{got}");
        assert!(got.len() <= 255, "{} bytes", got.len());
        std::fs::write(&next, b"x").unwrap();
        assert!(!dir.join(&long).with_extension("txt.1").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_collision_counter_goes_before_the_extension() {
        assert_eq!(numbered_name("report.pdf", " (1)"), "report (1).pdf");
        assert_eq!(numbered_name("backup.tar.gz", " (3)"), "backup (3).tar.gz");
        assert_eq!(numbered_name("Backup.TAR.XZ", " (1)"), "Backup (1).TAR.XZ");
        assert_eq!(numbered_name(".bashrc", " (1)"), ".bashrc (1)");
        assert_eq!(numbered_name("noext", " (2)"), "noext (2)");
        assert_eq!(numbered_name("trailing.", " (1)"), "trailing. (1)");
        assert_eq!(numbered_name(".tar.gz", " (1)"), ".tar (1).gz");
        // Multi-byte stems are cut on a character boundary, never mid-char.
        let wide = format!("{}.txt", "\u{e9}".repeat(200));
        let out = numbered_name(&wide, " (1)");
        assert!(out.len() <= 255 && out.ends_with(" (1).txt"), "{}", out.len());
    }
}
