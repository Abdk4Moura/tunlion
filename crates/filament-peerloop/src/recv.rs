//! RECEIVE FILE MECHANICS: the host-free leaves of the receive path.
//!
//! This is the first slice of the receive-dispatch extraction from
//! `cli/src/recv_files.rs`: the pieces that decide how a received byte range
//! becomes a file on disk, with NO opinion about how a peer was found,
//! authenticated or named, where the inbox lives, or how anything is rendered.
//! Everything here is a leaf or a state type: inputs in, values out, and this
//! crate never calls back into the CLI.
//!
//! What moved here, single-sourced so the CLI is a thin re-export:
//!
//!   * the untrusted-name collision rule (`unique_path` / `numbered_name`);
//!   * the whole-file content digest (`full_hash`);
//!   * the partial sidecar state (`PartMeta`) and its owner-only create;
//!   * the resumable-partial lifecycle (`Partial`, list / expire / json);
//!   * the storage-failure vocabulary a receiver reports (`WriteFailure`,
//!     `storage_failure`);
//!   * the in-order stdout sink (`StdoutSink`) and the `IncomingFile` state;
//!   * the whole-file verify (`verify_incoming`) and the confinement-safe
//!     `.part` open (`safe_create_part` / `safe_resume_part`, behind the
//!     `mount-server` feature that owns the beneath-root open primitive);
//!   * the transfer truth (`transfer_truth`, moved out of
//!     `cli/src/transfer_truth.rs`): the sequential-accept decision, the
//!     resume line, the partials a receive recorded (`SessionPart`,
//!     `note_part`), the ones actually on disk (`KeptPartial`,
//!     `kept_partials`; an empty partial is deleted, not reported), and the
//!     sender-gone sentence;
//!   * the invocation report (`report`): the per-file record, the
//!     invocation-owned `RecvReport` (files and last-refusal stamp), the
//!     refusal outcome aggregation, and the `receive --json` result object.
//!     It replaces the CLI's process-global `FILES`/`LAST_REFUSAL`, so two
//!     concurrent receives cannot see or overwrite each other.
//!
//! What stays in the CLI, because it is bound to the host, the filesystem
//! layout or the terminal: `finalize_incoming` (UI, settings, history, the
//! daemon log), the inbox helpers (`ensure_inbox`, `inbox_problem`, ...; config
//! paths), `storage_refusal` (a rendered sentence), `delivery_ack` (session
//! state), `partial_status_lines` (a rendered table), the exit-code/UI adapter
//! over the report (`recv_report::finish`/`emit`) and every call that emits
//! a truth sentence to the user.
//!
//! The moved mechanics print nothing. `verify_incoming`'s old debug line and
//! its test-hook `eprintln!` are gone rather than reaching for stderr: the
//! library never renders to a terminal (the same rule that made `pwrite_at`
//! return its iteration count instead of printing a diagnostic).

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use filament_proto::{decide_verify, VerifyResult};
use filament_transfer::coverage_complete;
use sha2::{Digest, Sha256};

use crate::host::StorageFailure;
use crate::present::{human, Progress as ProgressBar};

#[cfg(feature = "dispatch")]
pub mod ceremony;
#[cfg(feature = "dispatch")]
pub mod dispatch;
#[cfg(all(feature = "dispatch", feature = "mesh"))]
pub mod enrollment;
#[cfg(feature = "dispatch")]
pub mod events;
#[cfg(feature = "dispatch")]
pub mod files;
#[cfg(feature = "dispatch")]
pub mod fleet;
#[cfg(all(feature = "dispatch", feature = "mesh"))]
pub mod identity;
#[cfg(feature = "dispatch")]
pub mod lifecycle;
#[cfg(not(feature = "mesh"))]
pub mod mesh_stub;
#[cfg(feature = "dispatch")]
pub mod ports;
pub mod renewal;
pub mod report;
#[cfg(feature = "dispatch")]
pub mod revocation;
#[cfg(feature = "dispatch")]
pub mod servers;
#[cfg(feature = "dispatch")]
pub mod signaling_health;
pub mod store;
pub mod transfer_truth;

#[cfg(feature = "mesh")]
pub use crate::mesh::MeshTunnel;
#[cfg(not(feature = "mesh"))]
pub use mesh_stub::MeshTunnel;

// Re-exported at the receive module root so the CLI shim (and library callers)
// can name `recv::accept_is_sequential` without reaching through the child.
pub use transfer_truth::{
    accept_is_sequential, kept_partials, note_part, resume_line, sender_gone_message, KeptPartial,
    SessionPart,
};
// The per-invocation receive report (files, last refusal, outcome, JSON
// object). Re-exported here so callers can name it without the child path.
pub use report::{
    refused_error, result_object, storage_kind, OutcomeKind, RecvFile, RecvReport, Refusal,
    RefusalClass, RefusedOutcome, ReportError,
};

/// P4 (GAP-5): sha256 over the WHOLE file, the end-to-end content digest the
/// receiver compares against on completion so a truncated/corrupt transfer can
/// never be declared "done" (the runner had to bolt this above the transport;
/// P4 makes it a core guarantee). Streamed in 1 MiB reads so a large payload
/// doesn't have to be slurped into RAM. `None` if the file can't be read, the
/// offer then omits `full` and the receiver degrades to the legacy size-only
/// check (backward-compat; bounded, never a hang).
pub fn full_hash(path: &Path) -> Option<String> {
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
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
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
pub const NAME_LIMIT: usize = 255;

/// `name` with `tag` inserted between its stem and its extension, the stem
/// shortened if the whole would pass NAME_LIMIT. Pure.
pub fn numbered_name(name: &str, tag: &str) -> String {
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
    let Some(dot) = name.rfind('.') else {
        return (name, "");
    };
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

/// Remove what a refused file left behind: its `.part` and `.part.meta`. A
/// refused partial is not resumable (the cause was the disk or the name, not the
/// link), and on a full disk it is holding the very space that ran out.
pub fn discard_partial(part_path: &Path) {
    let _ = std::fs::remove_file(part_path);
    let meta = {
        let mut m = part_path.as_os_str().to_owned();
        m.push(".meta");
        PathBuf::from(m)
    };
    let _ = std::fs::remove_file(meta);
}

/// Create a NEW file for writing that is owner-only (0600 on unix) from the
/// moment it exists: the mode is passed to the create itself, so there is no
/// window in which another account could open it, and it does not depend on
/// the process umask (a daemon started with umask 0 made 0666 sidecars).
/// Fails if anything (a file, a planted symlink) already sits at `path`.
/// Windows: files take the containing directory's ACL; nothing to set here.
///
/// Used for the `.part.meta` sidecar (moved here with `PartMeta::store`).
pub fn create_new_private(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Sidecar metadata for a partial receive (`<name>.part.meta`).
/// JSON {"size":N,"head":"hex","full":"hex"}; legacy files hold a bare size
/// string. `full` is the whole-file sha256 the sender offered (P4), persisted so
/// a resume after a process restart can still verify-on-completion.
pub struct PartMeta {
    pub size: u64,
    pub head: Option<String>,
    pub full: Option<String>,
}

impl PartMeta {
    pub fn load(path: &Path) -> Option<PartMeta> {
        let raw = std::fs::read_to_string(path).ok()?;
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(size) = v["size"].as_u64() {
                return Some(PartMeta {
                    size,
                    head: v["head"].as_str().map(|s| s.to_string()),
                    full: v["full"].as_str().map(|s| s.to_string()),
                });
            }
        }
        raw.trim().parse::<u64>().ok().map(|size| PartMeta {
            size,
            head: None,
            full: None,
        })
    }

    /// Write the sidecar WITHOUT following a symlink at `path`: the download
    /// dir may be writable by others, and `std::fs::write` through a planted
    /// `x.part.meta -> ~/.bashrc` would overwrite the link's target. Unlink
    /// first (removes a link, never its target), then create exclusively, so a
    /// link re-planted in between makes this fail instead of writing through.
    /// Created owner-only (0600) regardless of umask: it names the file, its
    /// size and digests, and sits in a download dir others may read.
    pub fn store(&self, path: &Path) -> std::io::Result<()> {
        use std::io::Write;
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let mut f = create_new_private(path)?;
        f.write_all(
            serde_json::json!({ "size": self.size, "head": self.head, "full": self.full })
                .to_string()
                .as_bytes(),
        )
    }
}

/// How long an interrupted transfer's partial (`<name>.part` plus its
/// `<name>.part.meta`) waits in the inbox for its resume before the receiver
/// removes it: 7 days, stated wherever `tunlion status` lists partials.
/// Before this a partial of up to the chunk size stayed forever, and nothing
/// mentioned it.
pub const PARTIAL_TTL_SECS: u64 = 7 * 86_400;

/// One resumable partial left in the inbox by an interrupted transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partial {
    /// The file it will become (`<name>` of `<name>.part`).
    pub name: String,
    pub bytes: u64,
    pub age_secs: u64,
}

/// The resumable partials in `dir` (not recursive): a regular `<name>.part`
/// WITH its `<name>.part.meta`. The meta is what makes it ours: a received
/// file that merely ends in `.part` has none, so it is never listed and never
/// expired. Sorted by name.
pub fn resumable_partials(dir: &Path, now: std::time::SystemTime) -> Vec<Partial> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut out: Vec<Partial> = entries
        .flatten()
        .filter_map(|e| {
            let file = e.file_name().to_string_lossy().into_owned();
            let name = file.strip_suffix(".part")?.to_string();
            if name.is_empty() {
                return None;
            }
            let md = std::fs::symlink_metadata(e.path()).ok()?;
            if !md.is_file() || !dir.join(format!("{file}.meta")).is_file() {
                return None;
            }
            let age_secs = md
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            Some(Partial {
                name,
                bytes: md.len(),
                age_secs,
            })
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Remove the partials in `dir` older than [`PARTIAL_TTL_SECS`] (the `.part`
/// and its `.part.meta`). Returns what was removed.
pub fn expire_partials(dir: &Path, now: std::time::SystemTime) -> Vec<Partial> {
    let mut gone = Vec::new();
    for p in resumable_partials(dir, now) {
        if p.age_secs < PARTIAL_TTL_SECS {
            continue;
        }
        let part = dir.join(format!("{}.part", p.name));
        if std::fs::remove_file(&part).is_ok() {
            let _ = std::fs::remove_file(dir.join(format!("{}.part.meta", p.name)));
            gone.push(p);
        }
    }
    gone
}

/// A compact age word for a partial (`45m`, `3h`, `2d`).
pub fn age_words(secs: u64) -> String {
    match secs {
        s if s < 3_600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h", s / 3_600),
        s => format!("{}d", s / 86_400),
    }
}

/// `status --json`'s view of the partials: name, size, age, and when each
/// will be removed if nobody resumes it.
pub fn partials_json(dir: &Path) -> serde_json::Value {
    let now = std::time::SystemTime::now();
    serde_json::Value::Array(
        resumable_partials(dir, now)
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "name": p.name,
                    "bytes": p.bytes,
                    "ageSecs": p.age_secs,
                    "expiresInSecs": PARTIAL_TTL_SECS.saturating_sub(p.age_secs),
                })
            })
            .collect(),
    )
}

/// Classify an io error as a storage failure, or `None` for anything else.
///
/// The vocabulary ([`StorageFailure`]) lives in `crate::host`, because the host
/// trait classifies its own io errors with it; this is the portable
/// classifier the receive path uses as its default.
pub fn storage_failure(e: &std::io::Error) -> Option<StorageFailure> {
    #[cfg(unix)]
    {
        match e.raw_os_error() {
            Some(libc::ENOSPC) | Some(libc::EDQUOT) => return Some(StorageFailure::NoSpace),
            Some(libc::ENAMETOOLONG) => return Some(StorageFailure::NameTooLong),
            Some(libc::EROFS) => return Some(StorageFailure::ReadOnly),
            Some(libc::EACCES) | Some(libc::EPERM) => return Some(StorageFailure::Permission),
            _ => {}
        }
    }
    #[cfg(windows)]
    {
        // ERROR_DISK_FULL / ERROR_HANDLE_DISK_FULL, ERROR_FILENAME_EXCED_RANGE,
        // ERROR_WRITE_PROTECT, ERROR_ACCESS_DENIED.
        match e.raw_os_error() {
            Some(112) | Some(39) => return Some(StorageFailure::NoSpace),
            Some(206) => return Some(StorageFailure::NameTooLong),
            Some(19) => return Some(StorageFailure::ReadOnly),
            Some(5) => return Some(StorageFailure::Permission),
            _ => {}
        }
    }
    // The kind, for an error that was re-wrapped on its way here and lost its
    // OS code (safe_create_part adds context that way).
    match e.kind() {
        std::io::ErrorKind::StorageFull | std::io::ErrorKind::QuotaExceeded => {
            Some(StorageFailure::NoSpace)
        }
        std::io::ErrorKind::InvalidFilename => Some(StorageFailure::NameTooLong),
        std::io::ErrorKind::ReadOnlyFilesystem => Some(StorageFailure::ReadOnly),
        std::io::ErrorKind::PermissionDenied => Some(StorageFailure::Permission),
        _ => None,
    }
}

/// The first write that failed on a file (disk full, a filesystem gone
/// read-only), recorded by the writer task that hit it. The event loop turns
/// it into a typed refusal to the sender. Before this a failed write only
/// left a hole, the whole-file digest then failed three times, and the user
/// was told the file was CORRUPT when the disk was full.
#[derive(Clone, Debug)]
pub struct WriteFailure {
    pub kind: Option<StorageFailure>,
    pub detail: String,
}

impl WriteFailure {
    pub fn from_io(e: &std::io::Error) -> Self {
        WriteFailure {
            kind: storage_failure(e),
            detail: e.to_string(),
        }
    }
}

/// How many bytes `-o -` may hold back while it waits for an earlier gap to
/// arrive. The receiver asks the sender for one in-order stream, so the only
/// reordering left is between concurrent writer tasks; this bounds what an
/// older sender that still splits the file across links can make it hold.
pub const STDOUT_REORDER_LIMIT: usize = 64 * 1024 * 1024;

/// `receive -o -` into a pipe. A pipe cannot seek, so positional writes (what a
/// `.part` file gets) fail with ESPIPE: every `-o - | reader` used to end in
/// "Invalid seek (os error 29)". This writes strictly in order, holding a chunk
/// that arrives early until the bytes before it have been written, and hashes
/// what it writes, so the stream can still be verified against the sender's
/// whole-file digest (and acked) although it can never be re-read.
pub struct StdoutSink<W: std::io::Write> {
    out: W,
    next: u64,
    pending: std::collections::BTreeMap<u64, Vec<u8>>,
    pending_bytes: usize,
    hasher: Sha256,
}

impl<W: std::io::Write> StdoutSink<W> {
    pub fn new(out: W) -> Self {
        StdoutSink {
            out,
            next: 0,
            pending: Default::default(),
            pending_bytes: 0,
            hasher: Sha256::new(),
        }
    }

    /// Bytes written to the output so far (always a contiguous prefix).
    pub fn written(&self) -> u64 {
        self.next
    }

    /// Hex SHA-256 of everything written so far.
    pub fn digest(&self) -> String {
        self.hasher
            .clone()
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    fn emit(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.out.write_all(data)?;
        self.hasher.update(data);
        self.next += data.len() as u64;
        Ok(())
    }

    /// Accept `data` at absolute offset `pos`. Bytes already written are
    /// skipped (a re-sent range), bytes ahead of a gap are held, and anything
    /// that closes a gap is written together with what it unblocks.
    pub fn put(&mut self, pos: u64, data: &[u8]) -> std::io::Result<()> {
        let end = pos + data.len() as u64;
        if end <= self.next {
            return Ok(()); // all of it is already out
        }
        if pos > self.next {
            if self.pending_bytes + data.len() > STDOUT_REORDER_LIMIT {
                return Err(std::io::Error::other(format!(
                    "data arrived {} ahead of the stream written to stdout; more than {} would have to be held",
                    human(pos - self.next),
                    human(STDOUT_REORDER_LIMIT as u64)
                )));
            }
            self.pending_bytes += data.len();
            if let Some(old) = self.pending.insert(pos, data.to_vec()) {
                self.pending_bytes -= old.len();
            }
            return Ok(());
        }
        let skip = (self.next - pos) as usize;
        self.emit(&data[skip..])?;
        loop {
            let Some(p) = self.pending.keys().next().copied() else {
                break;
            };
            if p > self.next {
                break;
            }
            let chunk = self.pending.remove(&p).unwrap_or_default();
            self.pending_bytes -= chunk.len();
            let end = p + chunk.len() as u64;
            if end > self.next {
                let skip = (self.next - p) as usize;
                self.emit(&chunk[skip..])?;
            }
        }
        self.out.flush()
    }

    /// The verdict once the sender said the stream ended: every byte out, and
    /// (when the sender offered one) the digest of what was written matches.
    pub fn verdict(&self, size: u64, full: Option<&str>) -> std::result::Result<(), String> {
        if self.next != size {
            return Err(format!(
                "the stream to stdout ended after {} of {}",
                human(self.next),
                human(size)
            ));
        }
        match full {
            Some(want) if want != self.digest() => Err(
                "the bytes written to stdout do not match the sender's whole-file SHA-256 \
                 (they cannot be re-fetched: stdout cannot be rewound)"
                    .to_string(),
            ),
            _ => Ok(()),
        }
    }
}

/// One positional chunk into a `-o -` sink, shaped like `pwrite_at` (the count
/// is write iterations, always 1 here) so the writer task treats both alike.
pub fn stdout_put(
    sink: &std::sync::Mutex<StdoutSink<std::fs::File>>,
    pos: u64,
    data: &[u8],
) -> std::io::Result<u32> {
    let mut s = sink
        .lock()
        .map_err(|_| std::io::Error::other("stdout writer poisoned"))?;
    s.put(pos, data).map(|()| 1)
}

/// Exactly-once completion handshake between a stream's `file-end` control
/// frame and its last background writer.
///
/// `inflight` and `end_seen` alone have a lost-wakeup window: the last writer
/// can drop `inflight` to zero and read `end_seen == false` after file-end read
/// `inflight > 0` but before it stored `end_seen = true`. Both sides then defer
/// to the other and the sid never completes.
///
/// File-end observes `inflight` on arrival; when writers were present it
/// publishes `end_seen` and then takes a fresh observation instead of trusting
/// the arrival one. The last writer decrements `inflight` and then re-reads
/// `end_seen` (the classic Dekker store/load order, here with `SeqCst`).
/// Whichever side observes the completed state claims the single completion
/// through `queued`. File-end still returns `true` on the no-writer fast path;
/// `false` means it deferred to the last writer or another side already
/// claimed.
#[derive(Default)]
pub struct CompletionGate {
    queued: AtomicBool,
}

impl CompletionGate {
    /// File-end arrival. Observes the writers once, publishes `end_seen`, and
    /// then takes a fresh observation before claiming. The second observation
    /// is what closes the old read-then-store lost wakeup: a last writer may
    /// have drained and checked `end_seen` between the arrival observation and
    /// the publish.
    pub fn file_end(&self, inflight: &AtomicI64, end_seen: &AtomicBool) -> bool {
        self.file_end_with(inflight, end_seen, || {})
    }

    /// [`Self::file_end`] with a scheduling seam between the arrival
    /// observation and the publish. Production passes a no-op. The regression
    /// test uses it to run the last writer in the exact old window; reverting
    /// to trusting the first observation makes that test claim zero.
    fn file_end_with(
        &self,
        inflight: &AtomicI64,
        end_seen: &AtomicBool,
        between_observation_and_publish: impl FnOnce(),
    ) -> bool {
        let observed = inflight.load(Ordering::SeqCst);
        if observed == 0 {
            // No writer existed when file-end arrived: publish and claim the
            // inline fast path without a second observation.
            end_seen.store(true, Ordering::SeqCst);
            return self.claim();
        }
        between_observation_and_publish();
        // Publish before the decisive check. The old order trusted `observed`
        // and deferred, so a writer that drained in between saw end_seen still
        // false and never queued a completion.
        end_seen.store(true, Ordering::SeqCst);
        if inflight.load(Ordering::SeqCst) != 0 {
            return false;
        }
        self.claim()
    }

    /// Last-writer arrival, after `inflight.fetch_sub(1, SeqCst)` returned
    /// `prev`. Claims only when that writer was the last and file-end had
    /// already been observed.
    pub fn last_writer(&self, prev: i64, end_seen: &AtomicBool) -> bool {
        if prev != 1 || !end_seen.load(Ordering::SeqCst) {
            return false;
        }
        self.claim()
    }

    /// Reset for a verify re-request that puts the stream back into `by_sid`:
    /// the next file-end/last-writer pair is a new completion opportunity.
    pub fn reset(&self, end_seen: &AtomicBool) {
        end_seen.store(false, Ordering::SeqCst);
        self.queued.store(false, Ordering::SeqCst);
    }

    fn claim(&self) -> bool {
        self.queued
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }
}

/// One incoming file being assembled on this side.
///
/// Field-by-field the state the receive loop manipulates: the counters a
/// background writer task can publish without locking, the disjoint received
/// ranges for out-of-order reassembly, the shared raw handle positional writes
/// go through, the offered whole-file digest, the inflight/end/ack markers the
/// event loop polls, and the injected progress bar and stdout sink.
pub struct IncomingFile {
    pub id: String,
    pub name: String,
    pub size: u64,
    /// Atomic counter so background writer tasks can publish received bytes
    /// without locking. The event loop polls this for progress updates.
    pub received: Arc<AtomicU64>,
    /// Disjoint sorted byte intervals [start, end) received so far, for
    /// out-of-order reassembly from multi-stream transports. Shared via
    /// Mutex so concurrent spawn_blocking writer tasks can update safely.
    pub ranges: Arc<std::sync::Mutex<Vec<(u64, u64)>>>,
    /// Raw file handle shared across concurrent spawn_blocking writer tasks.
    /// Positional writes go through `pwrite_at` (write_at on Unix, seek_write on
    /// Windows) which is atomic per call — no seek needed, safe for concurrent
    /// access.
    pub file: Arc<std::fs::File>,
    pub part_path: PathBuf,
    /// P4 (GAP-5): the whole-file sha256 the SENDER offered (`full`). On
    /// completion we hash the received `.part` and compare, only a match
    /// finalizes + acks. `None` = the sender offered no digest (old peer / an
    /// un-hashable source); we fall back to the legacy size-only acceptance and
    /// do NOT ack (nothing to verify), which the sender's bounded fallback covers.
    pub full: Option<String>,
    /// Number of inflight spawn_blocking write tasks. The event loop uses
    /// this to decide when a file is ready for finalization:
    ///   inflight == 0 && end_seen → finalize
    pub inflight: Arc<AtomicI64>,
    /// Set by the file-end handler when the sender reports end-of-file, even
    /// if inflight writes are still pending. The last finishing writer checks
    /// this flag and emits Ev::MaybeComplete if both conditions are met.
    pub end_seen: Arc<AtomicBool>,
    /// Shared with writer tasks: makes the file-end/last-writer completion
    /// decision exactly-once even when both sides observe the other as
    /// not-yet-arrived. See [`CompletionGate`].
    pub completion: Arc<CompletionGate>,
    /// The sid to use in the delivery-ack message. Set from the file-end
    /// control frame; read by the MaybeComplete handler for the ack.
    pub ack_sid: u32,
    /// Tracks the last received value used for progress display (to avoid
    /// re-ticking the same value). Not atomic — only accessed from the event loop.
    pub last_tick: u64,
    pub bar: Box<dyn ProgressBar>,
    /// The first write that failed on this file (disk full, a filesystem gone
    /// read-only), recorded by the writer task that hit it. The event loop turns
    /// it into a typed refusal to the sender. Before this a failed write only
    /// left a hole, the whole-file digest then failed three times, and the user
    /// was told the file was CORRUPT when the disk was full.
    pub write_err: Arc<std::sync::Mutex<Option<WriteFailure>>>,
    /// `receive -o -`: the in-order writer to stdout. `None` for a file.
    pub stdout: Option<Arc<std::sync::Mutex<StdoutSink<std::fs::File>>>>,
}

/// P4 (GAP-5): recompute the whole-file sha256 of the received `.part` and
/// compare against the digest the sender offered (`inc.full`, guaranteed Some by
/// the caller). Flushes first so every buffered byte is on disk. This is the
/// CORE whole-file integrity guarantee the runner used to bolt on above the
/// transport, now every `recv` gets it.
///
/// Test hook (the truncation/ack gate): `TUNLION_TEST_CORRUPT_RECV=<id>` flips
/// a byte of the on-disk `.part` for the matching transfer id right before the
/// hash is computed, deterministically inducing the corrupt-receive case so the
/// gate can prove reject + recover. `TUNLION_TEST_CORRUPT_ONCE=1` makes it fire
/// exactly once (the re-fetch then succeeds), proving auto-recovery.
pub async fn verify_incoming(inc: &IncomingFile) -> VerifyResult {
    let want = match &inc.full {
        Some(w) => w.clone(),
        None => return VerifyResult::Match,
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
    // None there, so this whole block strips to nothing. The diagnostic line the
    // CLI used to print is gone: the library never writes to stderr.
    if let Some(target) = crate::test_hooks::corrupt_recv_target() {
        #[cfg(feature = "test-hooks")]
        {
            let once = crate::test_hooks::corrupt_recv_once();
            let already = crate::test_hooks::corrupt_already_fired();
            if target == inc.id && recvd == inc.size && !(once && already) {
                if let Ok(mut bytes) = std::fs::read(&inc.part_path) {
                    if let Some(b) = bytes.last_mut() {
                        *b ^= 0xFF;
                        let _ = std::fs::write(&inc.part_path, &bytes);
                        if once {
                            crate::test_hooks::corrupt_mark_fired();
                        }
                    }
                }
            }
        }
        let _ = &target;
    }

    if recvd < inc.size {
        return decide_verify(recvd, inc.size, None);
    }

    // Contiguity guard: before hashing, verify coverage is one contiguous
    // [0,size) interval. Any gap means the file has unwritten bytes even
    // though received == size. A gap re-fetches; never a false Match.
    {
        let r = inc.ranges.lock().unwrap();
        if !coverage_complete(&r, inc.size) {
            return decide_verify(recvd, inc.size, None);
        }
    }

    let path = inc.part_path.clone();
    let got = tokio::task::spawn_blocking(move || full_hash(&path))
        .await
        .ok()
        .flatten();
    decide_verify(recvd, inc.size, Some(got.as_deref() == Some(want.as_str())))
}

/// Create a FRESH .part file. Uses RESOLVE_BENEATH on Linux (TOCTOU-safe,
/// protects symlinked parents too), O_NOFOLLOW on other Unix, create_new
/// (O_EXCL) on non-Unix. O_EXCL means "fail if exists" — correct for fresh,
/// WRONG for resume (use safe_resume_part for that).
///
/// Windows (since 0.7.3): opens with FILE_FLAG_OPEN_REPARSE_POINT so a
/// symlink/junction at the .part path is NOT followed. Rejects reparse points
/// after open. This closes the Windows half that 0.7.2/0.7.3 explicitly deferred.
#[cfg(all(unix, feature = "mount-server"))]
pub async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
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
            // Owner-only from creation: a partial is not yet a delivered file
            // and the download dir may be readable by others.
            0o600,
        )
        .map_err(|e| std::io::Error::new(e.kind(), format!("safe create .part: {e}")))
        .map(|f| tokio::fs::File::from_std(f))
    }
    // Non-Linux Unix: O_NOFOLLOW + O_EXCL (only protects final component)
    #[cfg(not(target_os = "linux"))]
    {
        tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
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
/// and non-regular files after open.
#[cfg(all(unix, feature = "mount-server"))]
pub async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
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
            0,
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
        // A partial left by an older build may be group/world readable.
        let _ = crate::fs_at::set_mode_via_handle(&file, 0o600);
        Ok(tokio::fs::File::from_std(file))
    }
    // Non-Linux Unix: open with O_NOFOLLOW, then fstat the opened fd
    // (not stat the path before open — that races a swap)
    #[cfg(not(target_os = "linux"))]
    {
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
        let file = file.into_std().await;
        let _ = crate::fs_at::set_mode_via_handle(&file, 0o600);
        Ok(tokio::fs::File::from_std(file))
    }
}

/// Windows: create a FRESH .part file, refusing to follow symlinks/junctions.
/// Opens with FILE_FLAG_OPEN_REPARSE_POINT so a reparse point at the path
/// is NOT followed, then rejects if the opened file is a reparse point.
/// FILE_FLAG_BACKUP_SEMANTICS allows opening a directory junction for the
/// handle-based attribute check.
#[cfg(all(not(unix), feature = "mount-server"))]
pub async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
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
#[cfg(all(not(unix), feature = "mount-server"))]
pub async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
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

    // Portable tighten-through-the-handle (a no-op on this platform, where
    // the file takes the directory's ACL); kept so every resume does it.
    let file = file.into_std().await;
    let _ = crate::fs_at::set_mode_via_handle(&file, 0o600);
    Ok(tokio::fs::File::from_std(file))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn mode_dir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("filament-recv-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Permission bits of the file at `path` (the link itself), or None where
    /// the platform has no POSIX modes.
    fn file_mode(path: &Path) -> Option<u32> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::symlink_metadata(path)
                .ok()
                .map(|m| m.permissions().mode() & 0o7777)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            None
        }
    }

    fn sha256_hex(data: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(data);
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Regression for the file-end/last-writer lost wakeup. In the old order
    /// file-end observed `inflight == 1`, the last writer drained to zero and
    /// read `end_seen == false` (so it emitted nothing), then file-end stored
    /// `end_seen` and returned "deferred": zero completions, and the SID hung.
    ///
    /// The seam runs the writer in exactly that window. New ordering publishes
    /// end_seen before taking the decisive observation, so it must claim here;
    /// reverting to trusting the arrival observation makes this assertion fail.
    #[test]
    fn completion_gate_does_not_lose_file_end_when_last_writer_finishes() {
        let inflight = AtomicI64::new(1);
        let end_seen = AtomicBool::new(false);
        let gate = CompletionGate::default();

        let mut completions = 0;
        let file_end_claimed = gate.file_end_with(&inflight, &end_seen, || {
            // Old file-end's arrival observation was inflight == 1. The last
            // writer drains and checks end_seen while it is still unpublished.
            let prev = inflight.fetch_sub(1, Ordering::SeqCst);
            assert_eq!(prev, 1, "one last writer drains");
            if gate.last_writer(prev, &end_seen) {
                completions += 1;
            }
            assert_eq!(
                completions, 0,
                "the writer cannot complete before end_seen is published"
            );
        });
        if file_end_claimed {
            completions += 1;
        }
        assert!(
            file_end_claimed,
            "file-end must claim after the last writer drained in the old window"
        );
        assert!(
            end_seen.load(Ordering::SeqCst),
            "file-end published end_seen"
        );
        // The writer side cannot claim a second completion for the same end.
        if gate.last_writer(1, &end_seen) {
            completions += 1;
        }
        assert_eq!(completions, 1, "exactly one completion");
    }

    /// End-before-write fast path: file-end arrives with no writer, publishes
    /// end_seen and claims inline exactly once.
    #[test]
    fn completion_gate_claims_end_before_write_inline() {
        let inflight = AtomicI64::new(0);
        let end_seen = AtomicBool::new(false);
        let gate = CompletionGate::default();
        assert!(gate.file_end(&inflight, &end_seen));
        assert!(end_seen.load(Ordering::SeqCst));
        assert!(!gate.last_writer(1, &end_seen), "no second completion");
    }

    const HEAD_BYTES: u64 = 256 * 1024;

    #[test]
    fn full_hash_whole_file_integrity() {
        // P4 (GAP-5): full_hash digests the WHOLE file (not just a head window),
        // so a difference PAST the head, exactly the truncation/corrupt case a
        // head-hash can't see, produces a different digest.
        let dir = mode_dir("fh");
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        let mut base = vec![3u8; (HEAD_BYTES + 4096) as usize];
        std::fs::write(&a, &base).unwrap();
        // identical head, byte flipped well PAST the head: full_hash must differ.
        base[(HEAD_BYTES + 2048) as usize] = 4;
        std::fs::write(&b, &base).unwrap();
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
        let dir = mode_dir("unique");
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
        assert!(
            out.len() <= 255 && out.ends_with(" (1).txt"),
            "{}",
            out.len()
        );
    }

    /// E4: an interrupted transfer left `<name>.part` and `.part.meta` in the
    /// inbox forever, and `status` never mentioned them. They are listed with
    /// size and age, expire after PARTIAL_TTL_SECS, and a received file that
    /// merely ends in `.part` (no meta) is never touched.
    #[test]
    fn partials_are_listed_and_expire_and_a_plain_dot_part_file_is_left_alone() {
        let d = mode_dir("partials");
        std::fs::write(d.join("old.bin.part"), vec![0u8; 4096]).unwrap();
        std::fs::write(d.join("old.bin.part.meta"), b"{}").unwrap();
        std::fs::write(d.join("new.bin.part"), vec![0u8; 10]).unwrap();
        std::fs::write(d.join("new.bin.part.meta"), b"{}").unwrap();
        std::fs::write(d.join("notes.part"), b"a file the user received").unwrap();
        let now = std::time::SystemTime::now();
        let later = now + std::time::Duration::from_secs(PARTIAL_TTL_SECS - 3_600);
        // Age `old` past the bound by moving "now", not the file clock.
        std::fs::File::options()
            .write(true)
            .open(d.join("old.bin.part"))
            .unwrap()
            .set_modified(now - std::time::Duration::from_secs(2 * 3_600))
            .unwrap();
        let listed = resumable_partials(&d, now);
        let names: Vec<&str> = listed.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["new.bin", "old.bin"]);
        assert_eq!(listed[1].bytes, 4096);
        assert!(listed[1].age_secs >= 2 * 3_600 - 5, "{:?}", listed[1]);
        let json = partials_json(&d);
        assert_eq!(json.as_array().unwrap().len(), 2, "{json}");

        let gone = expire_partials(&d, later);
        assert_eq!(
            gone.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(),
            ["old.bin"]
        );
        assert!(!d.join("old.bin.part").exists() && !d.join("old.bin.part.meta").exists());
        assert!(d.join("new.bin.part").exists() && d.join("new.bin.part.meta").exists());
        assert!(
            d.join("notes.part").exists(),
            "a received file named *.part was removed"
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The age word the CLI's partial table renders: minutes under an hour,
    /// hours under a day, days beyond. Boundaries are asserted exactly.
    #[test]
    fn age_words_formats_minutes_hours_days() {
        assert_eq!(age_words(0), "0m");
        assert_eq!(age_words(59), "0m");
        assert_eq!(age_words(60), "1m");
        assert_eq!(age_words(3_599), "59m");
        assert_eq!(age_words(3_600), "1h");
        assert_eq!(age_words(86_399), "23h");
        assert_eq!(age_words(86_400), "1d");
        assert_eq!(age_words(2 * 86_400 + 5), "2d");
    }

    #[test]
    fn part_meta_roundtrip_and_legacy() {
        let dir = mode_dir("meta");
        let p = dir.join("x.part.meta");
        PartMeta {
            size: 42,
            head: Some("abc".into()),
            full: Some("deadbeef".into()),
        }
        .store(&p)
        .unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 42);
        assert_eq!(m.head.as_deref(), Some("abc"));
        // P4: the whole-file digest survives the round-trip too.
        assert_eq!(m.full.as_deref(), Some("deadbeef"));
        // legacy plain-size format still parses
        std::fs::write(&p, "1234").unwrap();
        let m = PartMeta::load(&p).unwrap();
        assert_eq!(m.size, 1234);
        assert!(m.head.is_none());
        assert!(m.full.is_none());
        // garbage does not
        std::fs::write(&p, "{not json").unwrap();
        assert!(PartMeta::load(&p).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The sidecar names the file, its size and digests, and sits in a
    /// download dir others may read: it is created owner-only (0600) whatever
    /// the umask, and a looser leftover is replaced rather than reused.
    #[test]
    fn part_meta_is_owner_only() {
        let dir = mode_dir("meta-mode");
        let p = dir.join("z.part.meta");
        std::fs::write(&p, "1").unwrap();
        PartMeta {
            size: 9,
            head: Some("ab".into()),
            full: Some("cd".into()),
        }
        .store(&p)
        .unwrap();
        if let Some(mode) = file_mode(&p) {
            assert_eq!(mode & 0o777, 0o600, ".part.meta must be 0600, got {mode:o}");
        }
        assert_eq!(PartMeta::load(&p).unwrap().size, 9);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Try to create a file symlink, returning the OS's refusal when the
    /// platform does not allow one (Windows without Developer Mode or the
    /// SeCreateSymbolicLink privilege). The security test below skips only on
    /// that refusal, never merely because the platform is Windows.
    fn try_symlink_file(target: &Path, link: &Path) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_file(target, link)
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "this platform has no file symlinks",
            ))
        }
    }

    /// A `.part.meta` planted as a symlink must not redirect the sidecar write
    /// onto the link's target. Runs on every platform that can actually plant
    /// the link (including Windows with symlink rights), exactly as the old
    /// portable CLI test did.
    #[test]
    fn part_meta_store_does_not_write_through_a_symlink() {
        let dir = mode_dir("meta-link");
        let victim = dir.join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        let p = dir.join("y.part.meta");
        // The OS may refuse a Windows file symlink without Developer Mode /
        // SeCreateSymbolicLink. Skip only then; never silently skip the arm.
        if try_symlink_file(&victim, &p).is_err() {
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        PartMeta {
            size: 7,
            head: None,
            full: None,
        }
        .store(&p)
        .unwrap();
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"precious",
            "the link target is untouched"
        );
        assert!(
            !std::fs::symlink_metadata(&p)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the sidecar is a real file now"
        );
        assert_eq!(PartMeta::load(&p).unwrap().size, 7);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The partial-receive sidecars are created through this; it must be
    /// owner-only at creation, never umask-dependent.
    #[test]
    fn create_new_private_is_owner_only() {
        let d = mode_dir("private");
        let p = d.join("x.part.meta");
        drop(create_new_private(&p).unwrap());
        if let Some(m) = file_mode(&p) {
            assert_eq!(
                m & 0o777,
                0o600,
                "a new private file must be 0600, got {m:o}"
            );
        }
        // create_new: it never reuses (or writes through) what is already there.
        assert!(create_new_private(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A writer that refuses to seek, like a pipe: `-o -` must never need to.
    struct Pipe(Vec<u8>);
    impl std::io::Write for Pipe {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            // Short writes, as a slow pipe gives them.
            let n = b.len().min(7);
            self.0.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// `receive -o - | slow-reader`: chunks arriving out of order, re-sent and
    /// overlapping still come out as exactly the original bytes, in order, and
    /// the digest of what was written is the whole-file digest.
    #[test]
    fn stdout_sink_writes_in_order_without_seeking() {
        let data: Vec<u8> = (0..10_000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut s = StdoutSink::new(Pipe(Vec::new()));
        // Second half first, then a duplicate of an early range, then the rest.
        s.put(5_000, &data[5_000..]).unwrap();
        assert_eq!(s.written(), 0, "nothing past a gap may be written");
        s.put(0, &data[..3_000]).unwrap();
        s.put(1_000, &data[1_000..2_000]).unwrap(); // already out: skipped
        s.put(2_500, &data[2_500..5_000]).unwrap(); // overlaps what is out
        assert_eq!(s.written(), 10_000);
        assert_eq!(s.out.0, data, "byte-exact and in order");
        assert_eq!(s.digest(), sha256_hex(&data));
        assert_eq!(s.verdict(10_000, Some(&sha256_hex(&data))), Ok(()));
        assert!(s
            .verdict(10_000, Some("00"))
            .unwrap_err()
            .contains("SHA-256"));
        assert!(s.verdict(20_000, None).unwrap_err().contains("ended after"));
    }

    /// An early chunk is held only up to the bound, never without limit.
    #[test]
    fn stdout_sink_bounds_what_it_holds() {
        let mut s = StdoutSink::new(Pipe(Vec::new()));
        let big = vec![0u8; STDOUT_REORDER_LIMIT];
        s.put(1, &big).unwrap();
        let e = s.put(1 + big.len() as u64, &[1u8]).unwrap_err();
        assert!(e.to_string().contains("ahead of the stream"), "{e}");
    }

    /// A fresh `.part` is owner-only from the create itself: the bytes of a
    /// download in progress are not readable by other accounts. The confined
    /// open primitive lives with the mount server, so this arm requires it.
    #[cfg(all(unix, feature = "mount-server"))]
    #[tokio::test]
    async fn fresh_part_is_owner_only() {
        let d = mode_dir("fresh");
        let p = d.join("data.bin.part");
        drop(safe_create_part(&p).await.unwrap());
        if let Some(m) = file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a fresh .part must be 0600, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Resuming a partial an older build left group/world readable tightens it.
    #[cfg(all(unix, feature = "mount-server"))]
    #[tokio::test]
    async fn resumed_part_is_tightened_to_owner_only() {
        let d = mode_dir("resume");
        let p = d.join("data.bin.part");
        let f = std::fs::File::create(&p).unwrap();
        crate::fs_at::set_mode_via_handle(&f, 0o666).unwrap();
        drop(f);
        drop(safe_resume_part(&p).await.unwrap());
        if let Some(m) = file_mode(&p) {
            assert_eq!(m & 0o777, 0o600, "a resumed .part must be 0600, got {m:o}");
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Transfer resume: `safe_resume_part` must refuse to open a symlink.
    #[cfg(all(unix, feature = "mount-server"))]
    #[tokio::test]
    async fn transfer_open_part_refuses_symlink() {
        let tmp = mode_dir("resume-link");
        let part_path = tmp.join("data.tar.part");
        std::fs::write(&part_path, b"partial data").unwrap();
        // Opens normally for resume.
        assert!(
            safe_resume_part(&part_path).await.is_ok(),
            "regular file must open normally for resume"
        );
        // Now replace with a symlink: must refuse.
        std::fs::remove_file(&part_path).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", &part_path).unwrap();
        assert!(
            safe_resume_part(&part_path).await.is_err(),
            "must refuse to resume through a symlink"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}

// A reduced profile omits the mount server's confined (`*at`) open. The
// receive loop still compiles and still stores files: the fallback opens the
// same `.part` with ordinary create/append semantics. The hardened
// beneath-root traversal is a mount-server property, not a receive one.
#[cfg(not(feature = "mount-server"))]
pub async fn safe_create_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await
}

#[cfg(not(feature = "mount-server"))]
pub async fn safe_resume_part(path: &std::path::Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}
