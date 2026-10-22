//! Durable sender-side outbox for asynchronous transfer offers.
//!
//! This is the sender counterpart of [`crate::recv::requests`]. It owns no
//! transport and no scheduling policy: it snapshots a source into a private
//! spool, records the exact one-entry manifest that will be offered, and lets a
//! caller later claim, defer, or terminate that offer without ever reading the
//! mutable original again.
//!
//! Design rules:
//!
//! * The store root is explicit. [`RetainedStore::open`] takes the config root
//!   and owns only `<config>/retained-sends`, never an access/incoming store.
//! * A source is copied into a private per-offer spool *before* its metadata is
//!   published. The manifest is computed from the copy, not from the original
//!   path, so a source that changes or disappears after enqueue cannot alter
//!   the offer.
//! * Offer ids are stable across restarts: a random 32-byte root seed is stored
//!   under the same cross-process lock as the records, and
//!   `id = hex(sha256("tunlion-retained-send-v1" || seed || sequence_be))`.
//!   The sequence is monotonic and never reused after a terminal prune.
//! * Every mutation is revision-checked and written atomically under
//!   [`StoreLock`]. A stale caller cannot overwrite a newer decision.
//! * `mark_attempt` also takes a separate `claim_until` reservation, so a
//!   second CLI that read the same fresh revision cannot start a parallel
//!   attempt; `due` excludes a live claim, while a manual resume may still see
//!   the record and be refused with `Busy` rather than stealing it.
//! * Active records are bounded and are never evicted. Terminal records may be
//!   pruned only to keep the metadata file inside its byte bound.
//! * The spool is removed only on a terminal transition. Staging crash orphans
//!   are cleaned only inside the narrow `staging/` subdirectory; no broad
//!   deletion ever runs.
//! * No pair secret is stored here. The target is bound by its cryptographic
//!   device id and a UI name, not by a reusable secret.

use crate::recv::requests::{
    canonical_manifest, CanonicalManifest, Limits as ManifestLimits, ManifestEntry,
};
use crate::recv::store::StoreLock;
use filament_transfer::safe_incoming_name;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Directory owned below the caller's config root.
pub const SUBDIR: &str = "retained-sends";
const DATA_FILE: &str = "retained-sends.json";
const LOCK_FILE: &str = "retained-sends.json.lock";
const SPOOL_DIR: &str = "spool";
const STAGING_DIR: &str = "staging";
const SCHEMA: u32 = 1;
const ID_DOMAIN: &[u8] = b"tunlion-retained-send-v1\0";
const STAGING_ORPHAN_AGE_SECS: u64 = 24 * 60 * 60;

/// A retained offer may not outlive the receiver's request window.
pub const MAX_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// An attempt is excluded from [`RetainedStore::due`] for this long, so two
/// processes cannot claim the same offer merely because they both polled just
/// before either persisted a terminal/defer. This is a bounded in-flight
/// reservation, not a credential.
pub const IN_FLIGHT_SECS: u64 = 120;

pub const DEFAULT_MAX_ACTIVE: usize = 100;
pub const DEFAULT_MAX_METADATA_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_SINGLE_BYTES: u64 = 1024 * 1024 * 1024;

/// Bounds for the queue. Active records are never evicted; [`enqueue`] fails
/// instead. Terminal records are pruned oldest-first only when the metadata
/// file would otherwise exceed `max_metadata_bytes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_active: usize,
    pub max_metadata_bytes: usize,
    pub max_total_bytes: u64,
    pub max_single_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_active: DEFAULT_MAX_ACTIVE,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_single_bytes: DEFAULT_MAX_SINGLE_BYTES,
        }
    }
}

/// The durable state of one retained offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SendState {
    Waiting,
    Delivered,
    Denied,
    Cancelled,
    Expired,
    Failed,
    Stale,
}

impl SendState {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Waiting)
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Delivered => "delivered",
            Self::Denied => "denied",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::Failed => "failed",
            Self::Stale => "stale",
        }
    }
}

/// One exact retained offer. The source path is intentionally private: it names
/// the store's immutable snapshot, never the user's mutable input path. Use
/// [`RetainedSend::source_path`] only to stream the spooled bytes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedSend {
    pub id: String,
    pub peer_name: String,
    /// Cryptographic device public key (lower-case 64-hex), not a petname.
    pub peer_device_id: String,
    pub server: String,
    /// The original attempt forced the TURN relay. Retries must preserve this;
    /// `--no-relay` remains the process-global forbidden-fallback policy.
    #[serde(default)]
    pub relay_only: bool,
    pub manifest: CanonicalManifest,
    /// The private per-offer spool file, never the user's mutable input path.
    /// Serialization persists it; `Debug` deliberately redacts it.
    source_path: PathBuf,
    pub created_at: u64,
    pub expires_at: u64,
    pub attempts: u32,
    pub next_attempt_at: u64,
    /// When the current attempt's reservation ends. Zero means unclaimed.
    /// This is distinct from `next_attempt_at`, which is the retry schedule:
    /// a manual `--resume` may ignore the schedule but must not steal a live
    /// claim.
    #[serde(default)]
    pub claim_until: u64,
    pub state: SendState,
    pub rev: u64,
    #[serde(default)]
    pub receiver_request_id: Option<String>,
}

impl RetainedSend {
    /// The immutable spool file to stream. It is not the original input path.
    pub fn source_path(&self) -> &Path {
        &self.source_path
    }

    /// The safe basename the receiver will see.
    pub fn name(&self) -> &str {
        self.manifest
            .entries
            .first()
            .map(|entry| entry.path.as_str())
            .unwrap_or("")
    }

    pub fn size(&self) -> u64 {
        self.manifest.total_bytes
    }

    pub fn sha256(&self) -> Option<&str> {
        self.manifest
            .entries
            .first()
            .map(|entry| entry.sha256.as_str())
    }

    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

impl fmt::Debug for RetainedSend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The spool path is private local state; do not make it easy to copy
        // into logs. The peer name and digest are safe display facts.
        f.debug_struct("RetainedSend")
            .field("id", &self.id)
            .field("peer_name", &self.peer_name)
            .field("peer_device_id", &self.peer_device_id)
            .field("server", &self.server)
            .field("relay_only", &self.relay_only)
            .field("manifest", &self.manifest)
            .field("source_path", &"<retained-spool>")
            .field("created_at", &self.created_at)
            .field("expires_at", &self.expires_at)
            .field("attempts", &self.attempts)
            .field("next_attempt_at", &self.next_attempt_at)
            .field("claim_until", &self.claim_until)
            .field("state", &self.state)
            .field("rev", &self.rev)
            .field("receiver_request_id", &self.receiver_request_id)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedError {
    Storage(String),
    Corrupt(String),
    InvalidArgument(&'static str),
    InvalidManifest(String),
    LimitExceeded(&'static str),
    NotFound(String),
    RevisionConflict {
        id: String,
        expected: u64,
        current: u64,
    },
    InvalidState {
        id: String,
        state: &'static str,
    },
    Busy {
        id: String,
        until: u64,
    },
    Expired(String),
    SourceMissing(String),
    SourceChanged(String),
    OutsideSpool(String),
}

impl fmt::Display for RetainedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(message) => write!(f, "retained send store: {message}"),
            Self::Corrupt(message) => write!(f, "retained send store is corrupt: {message}"),
            Self::InvalidArgument(message) => f.write_str(message),
            Self::InvalidManifest(message) => write!(f, "retained send manifest: {message}"),
            Self::LimitExceeded(message) => f.write_str(message),
            Self::NotFound(id) => write!(f, "no retained send {id}"),
            Self::RevisionConflict {
                id,
                expected,
                current,
            } => write!(
                f,
                "retained send {id} revision conflict: expected {expected}, current {current}"
            ),
            Self::InvalidState { id, state } => {
                write!(
                    f,
                    "retained send {id} is {state}, not a valid state for this action"
                )
            }
            Self::Busy { id, until } => {
                write!(f, "retained send {id} is claimed until {until}")
            }
            Self::Expired(id) => write!(f, "retained send {id} has expired"),
            Self::SourceMissing(id) => write!(f, "retained send {id} has no readable spool"),
            Self::SourceChanged(id) => {
                write!(f, "retained send {id} spool no longer matches its manifest")
            }
            Self::OutsideSpool(id) => {
                write!(f, "retained send {id} source is outside its private spool")
            }
        }
    }
}

impl std::error::Error for RetainedError {}

#[derive(Clone, Serialize, Deserialize)]
struct Disk {
    schema: u32,
    seed: String,
    next_id: u64,
    sends: Vec<RetainedSend>,
}

/// A durable outbox rooted at `<config_root>/retained-sends`.
#[derive(Clone)]
pub struct RetainedStore {
    root: PathBuf,
    limits: Limits,
}

impl fmt::Debug for RetainedStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetainedStore")
            .field("root", &"<config>/retained-sends")
            .field("limits", &self.limits)
            .finish()
    }
}

impl RetainedStore {
    /// Open the store at `<config_root>/retained-sends`, creating its private
    /// directories and, on first use, a root seed. It never reads or writes an
    /// access/incoming store.
    pub fn open(config_root: impl Into<PathBuf>) -> Result<Self, RetainedError> {
        Self::open_with_limits(config_root, Limits::default())
    }

    pub fn open_with_limits(
        config_root: impl Into<PathBuf>,
        limits: Limits,
    ) -> Result<Self, RetainedError> {
        validate_limits(&limits)?;
        let config_root = config_root.into();
        std::fs::create_dir_all(&config_root)
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let root = config_root.join(SUBDIR);
        create_private_dir(&root)?;
        create_private_dir(&root.join(SPOOL_DIR))?;
        create_private_dir(&root.join(STAGING_DIR))?;
        // Store an absolute root so a resumed process with a different cwd can
        // still find the private spool.
        let root = std::fs::canonicalize(&root)
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let store = Self { root, limits };
        store.cleanup_staging();
        // Initialise the seed now, under the same lock every mutation uses.
        store.read_locked()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Snapshot an exact regular source and publish it as a waiting offer.
    ///
    /// The original `path` is opened without following a symlink and copied to
    /// a private spool. The size and SHA-256 in the manifest are measured from
    /// that copy. The original may then be changed or deleted; the retained
    /// offer is unaffected.
    pub fn enqueue(
        &self,
        peer_name: &str,
        peer_device_id: &str,
        server: &str,
        path: &Path,
        name: &str,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        self.enqueue_with_relay(peer_name, peer_device_id, server, path, name, false, now)
    }

    /// Enqueue while preserving the original attempt's forced-relay policy.
    /// `relay_only` is stored and reused by every later `--resume`/daemon retry.
    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_with_relay(
        &self,
        peer_name: &str,
        peer_device_id: &str,
        server: &str,
        path: &Path,
        name: &str,
        relay_only: bool,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        self.enqueue_file_with_relay(
            peer_name,
            peer_device_id,
            server,
            path,
            name,
            relay_only,
            now,
        )
    }

    /// The same operation as [`RetainedStore::enqueue`], named for callers that
    /// already staged stdin/directory content into a regular spool file.
    pub fn enqueue_file(
        &self,
        peer_name: &str,
        peer_device_id: &str,
        server: &str,
        path: &Path,
        name: &str,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        self.enqueue_file_with_relay(peer_name, peer_device_id, server, path, name, false, now)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn enqueue_file_with_relay(
        &self,
        peer_name: &str,
        peer_device_id: &str,
        server: &str,
        path: &Path,
        name: &str,
        relay_only: bool,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        let peer_name = valid_peer_name(peer_name)?;
        let peer_device_id = valid_device_id(peer_device_id)?;
        let server = valid_server(server)?;
        let name = valid_offer_name(name)?;

        // Reject a symlink/non-regular source before reserving a sequence.
        let source_meta = std::fs::symlink_metadata(path)
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        if source_meta.file_type().is_symlink() || !source_meta.file_type().is_file() {
            return Err(RetainedError::InvalidArgument(
                "the retained source must be a regular file, not a symlink or directory",
            ));
        }
        if source_meta.len() > self.limits.max_single_bytes
            || source_meta.len() > self.limits.max_total_bytes
        {
            return Err(RetainedError::LimitExceeded(
                "the retained source exceeds the single-file byte limit",
            ));
        }

        let id = self.reserve_id()?;
        let staging = self.staging_dir().join(format!(
            "{}.{}.{}",
            id,
            std::process::id(),
            random_suffix()?
        ));
        create_private_dir(&staging)?;
        let staged_source = staging.join("source");

        let result = (|| {
            let (size, sha256) = copy_exact_source(path, &staged_source)?;
            if size > self.limits.max_single_bytes || size > self.limits.max_total_bytes {
                return Err(RetainedError::LimitExceeded(
                    "the retained source exceeds the single-file byte limit",
                ));
            }
            let manifest = canonical_manifest(
                &[ManifestEntry {
                    path: name.clone(),
                    size,
                    sha256,
                    mtime: 0,
                }],
                &ManifestLimits::default(),
            )
            .map_err(|error| RetainedError::InvalidManifest(error.to_string()))?;
            self.publish(
                id,
                peer_name,
                peer_device_id,
                server,
                relay_only,
                manifest,
                &staging,
                now,
            )
        })();

        if result.is_err() {
            let _ = std::fs::remove_dir_all(&staging);
        }
        result
    }

    /// All records, including terminal history retained for idempotence.
    pub fn snapshot(&self) -> Result<Vec<RetainedSend>, RetainedError> {
        let disk = self.read_locked()?;
        Ok(disk.sends)
    }

    pub fn get(&self, id: &str) -> Result<Option<RetainedSend>, RetainedError> {
        validate_lookup_id(id)?;
        let disk = self.read_locked()?;
        Ok(disk.sends.into_iter().find(|record| record.id == id))
    }

    /// Waiting, unexpired offers whose retry time has arrived. An offer in the
    /// middle of [`RetainedStore::mark_attempt`]'s 120 s reservation is excluded.
    pub fn due(&self, now: u64) -> Result<Vec<RetainedSend>, RetainedError> {
        let disk = self.read_locked()?;
        let mut due: Vec<RetainedSend> = disk
            .sends
            .into_iter()
            .filter(|record| {
                record.state == SendState::Waiting
                    && record.claim_until <= now
                    && record.expires_at > now
                    && record.next_attempt_at <= now
            })
            .collect();
        due.sort_by_key(|record| (record.next_attempt_at, record.created_at, record.id.clone()));
        Ok(due)
    }

    /// Mark one attempt and reserve the offer for [`IN_FLIGHT_SECS`]. A process
    /// that dies before calling `defer`/`terminal` leaves the record claimable
    /// again after the reservation, without a separate lease table.
    pub fn mark_attempt(
        &self,
        id: &str,
        rev: u64,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        self.transition(id, rev, |record| {
            if record.state != SendState::Waiting {
                return Err(RetainedError::InvalidState {
                    id: id.to_string(),
                    state: record.state.as_str(),
                });
            }
            if record.claim_until > now {
                return Err(RetainedError::Busy {
                    id: id.to_string(),
                    until: record.claim_until,
                });
            }
            if now >= record.expires_at {
                return Err(RetainedError::Expired(id.to_string()));
            }
            let claim_until = now.saturating_add(IN_FLIGHT_SECS);
            record.attempts = record.attempts.saturating_add(1);
            record.next_attempt_at = claim_until;
            record.claim_until = claim_until;
            Ok(())
        })
    }

    /// Record the receiver's answer or a local retry delay. `request_id` is the
    /// receiver's optional durable request id (`transfer:<n>` from its
    /// `file-pending`), not this store's opaque offer id.
    pub fn defer(
        &self,
        id: &str,
        rev: u64,
        retry_after: u64,
        request_id: Option<&str>,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        let request_id = match request_id {
            Some(value) => Some(valid_request_id(value)?),
            None => None,
        };
        self.transition(id, rev, |record| {
            if record.state != SendState::Waiting {
                return Err(RetainedError::InvalidState {
                    id: id.to_string(),
                    state: record.state.as_str(),
                });
            }
            if now >= record.expires_at {
                return Err(RetainedError::Expired(id.to_string()));
            }
            let delay = retry_after.clamp(1, MAX_TTL_SECS);
            record.next_attempt_at = now.saturating_add(delay);
            // The revision owner has answered for this attempt: release the
            // in-flight reservation before scheduling the retry.
            record.claim_until = 0;
            if request_id.is_some() {
                record.receiver_request_id = request_id.clone();
            }
            Ok(())
        })
    }

    /// Terminal transition. Repeating the *same* terminal state is idempotent
    /// and does not bump the revision. A different terminal state or a stale
    /// revision is refused, so a slow sender cannot turn a denial into a
    /// delivery claim.
    pub fn terminal(
        &self,
        id: &str,
        rev: u64,
        state: SendState,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        if !state.is_terminal() {
            return Err(RetainedError::InvalidArgument(
                "terminal requires a terminal SendState",
            ));
        }
        validate_lookup_id(id)?;
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let mut disk = self.load_or_init()?;
        let index = disk
            .sends
            .iter()
            .position(|record| record.id == id)
            .ok_or_else(|| RetainedError::NotFound(id.to_string()))?;

        // Same terminal state: idempotent even if the caller's revision is old.
        if disk.sends[index].state == state {
            let result = disk.sends[index].clone();
            let cleanup_id = result.id.clone();
            drop(_lock);
            // Retry the best-effort cleanup: a previous process may have
            // committed the receipt and died before removing the spool.
            let _ = std::fs::remove_dir_all(self.spool_dir().join(cleanup_id));
            return Ok(result);
        }
        if disk.sends[index].state.is_terminal() {
            return Err(RetainedError::InvalidState {
                id: id.to_string(),
                state: disk.sends[index].state.as_str(),
            });
        }
        if disk.sends[index].rev != rev {
            return Err(RetainedError::RevisionConflict {
                id: id.to_string(),
                expected: rev,
                current: disk.sends[index].rev,
            });
        }

        let record = &mut disk.sends[index];
        record.state = state;
        record.rev = record.rev.saturating_add(1);
        record.next_attempt_at = now;
        record.claim_until = 0;
        let result = record.clone();
        let cleanup_id = result.id.clone();
        self.write_disk(&disk)?;
        drop(_lock);
        // The metadata is the authority. Cleanup is deliberately best-effort:
        // a failed unlink must not make a committed receipt look failed.
        let _ = std::fs::remove_dir_all(self.spool_dir().join(cleanup_id));
        Ok(result)
    }

    /// Transition every expired waiting record to `Expired` and clean its spool.
    /// Returns the records that changed.
    pub fn expire(&self, now: u64) -> Result<Vec<RetainedSend>, RetainedError> {
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let mut disk = self.load_or_init()?;
        let mut expired = Vec::new();
        for record in disk.sends.iter_mut() {
            if record.state == SendState::Waiting && now >= record.expires_at {
                record.state = SendState::Expired;
                record.rev = record.rev.saturating_add(1);
                record.next_attempt_at = now;
                record.claim_until = 0;
                expired.push(record.clone());
            }
        }
        if !expired.is_empty() {
            self.write_disk(&disk)?;
            drop(_lock);
            for record in &expired {
                let _ = std::fs::remove_dir_all(self.spool_dir().join(&record.id));
            }
        }
        Ok(expired)
    }

    /// Verify the retained spool is still the exact file recorded in the
    /// manifest. This refuses a missing spool, a symlink, a replacement, a
    /// wrong size, and a byte change. It never reads the original input path.
    pub fn verify_source(&self, record: &RetainedSend) -> Result<(), RetainedError> {
        validate_lookup_id(&record.id)?;
        let checked = canonical_manifest(&record.manifest.entries, &ManifestLimits::default())
            .map_err(|error| {
                RetainedError::Corrupt(format!("recorded manifest is invalid: {error}"))
            })?;
        if checked != record.manifest {
            return Err(RetainedError::Corrupt(
                "recorded manifest summary does not match its entries".to_string(),
            ));
        }
        if checked.entries.len() != 1 {
            return Err(RetainedError::Corrupt(
                "a retained send must have exactly one manifest entry".to_string(),
            ));
        }

        let canonical_spool = std::fs::canonicalize(self.spool_dir())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let expected_dir = self.spool_dir().join(&record.id);
        let canonical_dir = std::fs::canonicalize(&expected_dir)
            .map_err(|_| RetainedError::SourceMissing(record.id.clone()))?;
        if canonical_dir.parent() != Some(canonical_spool.as_path())
            || canonical_dir.file_name() != Some(std::ffi::OsStr::new(&record.id))
        {
            return Err(RetainedError::OutsideSpool(record.id.clone()));
        }
        let metadata =
            std::fs::symlink_metadata(&record.source_path).map_err(|error| match error.kind() {
                io::ErrorKind::NotFound => RetainedError::SourceMissing(record.id.clone()),
                _ => RetainedError::Storage(error.to_string()),
            })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(RetainedError::SourceChanged(record.id.clone()));
        }
        let canonical_source = std::fs::canonicalize(&record.source_path)
            .map_err(|_| RetainedError::SourceMissing(record.id.clone()))?;
        if canonical_source.parent() != Some(canonical_dir.as_path())
            || canonical_source.file_name() != Some(std::ffi::OsStr::new("source"))
        {
            return Err(RetainedError::OutsideSpool(record.id.clone()));
        }

        let (sha256, size) = hash_file(&canonical_source)?;
        let entry = &checked.entries[0];
        if size != entry.size || sha256 != entry.sha256 {
            return Err(RetainedError::SourceChanged(record.id.clone()));
        }
        Ok(())
    }

    fn reserve_id(&self) -> Result<String, RetainedError> {
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let mut disk = self.load_or_init()?;
        let active = disk
            .sends
            .iter()
            .filter(|record| !record.state.is_terminal())
            .count();
        if active >= self.limits.max_active {
            return Err(RetainedError::LimitExceeded(
                "the active retained-send limit is reached",
            ));
        }
        if disk.next_id == u64::MAX {
            return Err(RetainedError::LimitExceeded(
                "the retained-send sequence is exhausted",
            ));
        }
        let seed = decode_seed(&disk.seed)?;
        let sequence = disk.next_id;
        disk.next_id = sequence.saturating_add(1);
        // Persist the reservation so two enqueues can never allocate the same
        // id, and a crash cannot make the sequence reuse one. A failed snapshot
        // may leave a harmless gap in the sequence.
        self.prune_terminal_metadata(&mut disk)?;
        self.write_disk(&disk)?;
        Ok(allocate_id(&seed, sequence))
    }

    #[allow(clippy::too_many_arguments)]
    fn publish(
        &self,
        id: String,
        peer_name: String,
        peer_device_id: String,
        server: String,
        relay_only: bool,
        manifest: CanonicalManifest,
        staging: &Path,
        now: u64,
    ) -> Result<RetainedSend, RetainedError> {
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let mut disk = self.load_or_init()?;

        let active = disk
            .sends
            .iter()
            .filter(|record| !record.state.is_terminal())
            .count();
        if active >= self.limits.max_active {
            return Err(RetainedError::LimitExceeded(
                "the active retained-send limit is reached",
            ));
        }
        let retained_bytes = disk
            .sends
            .iter()
            .filter(|record| !record.state.is_terminal())
            .fold(0u64, |total, record| {
                total.saturating_add(record.manifest.total_bytes)
            });
        if retained_bytes.saturating_add(manifest.total_bytes) > self.limits.max_total_bytes {
            return Err(RetainedError::LimitExceeded(
                "the retained-send byte limit is reached",
            ));
        }
        if manifest.total_bytes > self.limits.max_single_bytes {
            return Err(RetainedError::LimitExceeded(
                "the retained source exceeds the single-file byte limit",
            ));
        }

        let record = RetainedSend {
            id: id.clone(),
            peer_name,
            peer_device_id,
            server,
            relay_only,
            manifest,
            source_path: self.spool_dir().join(&id).join("source"),
            created_at: now,
            expires_at: now.saturating_add(MAX_TTL_SECS),
            attempts: 0,
            next_attempt_at: now,
            claim_until: 0,
            state: SendState::Waiting,
            rev: 1,
            receiver_request_id: None,
        };
        disk.sends.push(record.clone());
        self.prune_terminal_metadata(&mut disk)?;
        let metadata_len = serde_json::to_vec(&disk)
            .map_err(|error| RetainedError::Storage(error.to_string()))?
            .len();
        if metadata_len > self.limits.max_metadata_bytes {
            // The caller drops the staging directory; nothing was published.
            return Err(RetainedError::LimitExceeded(
                "the retained-send metadata limit is reached",
            ));
        }

        let final_dir = self.spool_dir().join(&id);
        if final_dir.exists() {
            // A reserved id should be new. A leftover directory means a crash
            // after reservation but before metadata; never overwrite it.
            return Err(RetainedError::Storage(
                "the retained spool slot is already occupied".to_string(),
            ));
        }
        std::fs::rename(staging, &final_dir)
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        // Make the spool directory entry durable before metadata can point at
        // it. Best effort, exactly as the secret writer does for its rename.
        if let Ok(dir) = std::fs::OpenOptions::new()
            .read(true)
            .open(self.spool_dir())
        {
            let _ = dir.sync_all();
        }
        if let Err(error) = self.write_disk(&disk) {
            let _ = std::fs::remove_dir_all(&final_dir);
            return Err(error);
        }
        Ok(record)
    }

    fn transition<F>(&self, id: &str, rev: u64, change: F) -> Result<RetainedSend, RetainedError>
    where
        F: FnOnce(&mut RetainedSend) -> Result<(), RetainedError>,
    {
        validate_lookup_id(id)?;
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        let mut disk = self.load_or_init()?;
        let index = disk
            .sends
            .iter()
            .position(|record| record.id == id)
            .ok_or_else(|| RetainedError::NotFound(id.to_string()))?;
        if disk.sends[index].rev != rev {
            return Err(RetainedError::RevisionConflict {
                id: id.to_string(),
                expected: rev,
                current: disk.sends[index].rev,
            });
        }
        change(&mut disk.sends[index])?;
        disk.sends[index].rev = disk.sends[index].rev.saturating_add(1);
        let record = disk.sends[index].clone();
        self.write_disk(&disk)?;
        Ok(record)
    }

    fn read_locked(&self) -> Result<Disk, RetainedError> {
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        self.load_or_init()
    }

    fn load_or_init(&self) -> Result<Disk, RetainedError> {
        match std::fs::read_to_string(self.data_path()) {
            Ok(raw) => {
                if raw.trim().is_empty() {
                    return Err(RetainedError::Corrupt(
                        "the retained-send store is empty; refusing to overwrite it".to_string(),
                    ));
                }
                let disk: Disk = serde_json::from_str(&raw).map_err(|_| {
                    RetainedError::Corrupt("the retained-send store does not parse".to_string())
                })?;
                if disk.schema != SCHEMA {
                    return Err(RetainedError::Corrupt(
                        "the retained-send schema is not supported".to_string(),
                    ));
                }
                if disk.next_id == 0 {
                    return Err(RetainedError::Corrupt(
                        "the retained-send sequence is missing".to_string(),
                    ));
                }
                decode_seed(&disk.seed)?;
                for record in &disk.sends {
                    if !is_hex_64(&record.id)
                        || !is_hex_64(&record.peer_device_id)
                        || record.rev == 0
                        || record.manifest.entries.len() != 1
                        || record.expires_at > record.created_at.saturating_add(MAX_TTL_SECS)
                    {
                        return Err(RetainedError::Corrupt(
                            "a retained-send record is malformed".to_string(),
                        ));
                    }
                }
                Ok(disk)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let disk = Disk {
                    schema: SCHEMA,
                    seed: new_seed()?,
                    next_id: 1,
                    sends: Vec::new(),
                };
                self.write_disk(&disk)?;
                Ok(disk)
            }
            Err(error) => Err(RetainedError::Storage(error.to_string())),
        }
    }

    fn write_disk(&self, disk: &Disk) -> Result<(), RetainedError> {
        let body =
            serde_json::to_vec(disk).map_err(|error| RetainedError::Storage(error.to_string()))?;
        if body.len() > self.limits.max_metadata_bytes {
            return Err(RetainedError::LimitExceeded(
                "the retained-send metadata limit is reached",
            ));
        }
        secret_write::SecretFile::write(self.data_path(), &body)
            .map_err(|error| RetainedError::Storage(error.to_string()))
    }

    fn prune_terminal_metadata(&self, disk: &mut Disk) -> Result<(), RetainedError> {
        loop {
            let len = serde_json::to_vec(disk)
                .map_err(|error| RetainedError::Storage(error.to_string()))?
                .len();
            if len <= self.limits.max_metadata_bytes {
                return Ok(());
            }
            let oldest_terminal = disk
                .sends
                .iter()
                .enumerate()
                .filter(|(_, record)| record.state.is_terminal())
                .min_by_key(|(_, record)| (record.created_at, record.rev, record.id.clone()))
                .map(|(index, _)| index);
            match oldest_terminal {
                Some(index) => {
                    disk.sends.remove(index);
                }
                None => {
                    return Err(RetainedError::LimitExceeded(
                        "the retained-send metadata limit is reached",
                    ));
                }
            }
        }
    }

    fn cleanup_staging(&self) {
        let Ok(entries) = std::fs::read_dir(self.staging_dir()) else {
            return;
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            let modified = metadata
                .modified()
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map(|duration| duration.as_secs())
                .unwrap_or(now);
            if now.saturating_sub(modified) < STAGING_ORPHAN_AGE_SECS {
                continue;
            }
            // This loop is confined to `staging/` and never touches `spool/`
            // or the data file. `file_type` does not follow a symlink, so a
            // planted link is removed as a link, never traversed.
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                let _ = std::fs::remove_dir_all(entry.path());
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }

    fn data_path(&self) -> PathBuf {
        self.root.join(DATA_FILE)
    }

    fn lock_path(&self) -> PathBuf {
        self.root.join(LOCK_FILE)
    }

    fn spool_dir(&self) -> PathBuf {
        self.root.join(SPOOL_DIR)
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join(STAGING_DIR)
    }
}

fn validate_limits(limits: &Limits) -> Result<(), RetainedError> {
    if limits.max_active == 0
        || limits.max_metadata_bytes == 0
        || limits.max_total_bytes == 0
        || limits.max_single_bytes == 0
    {
        return Err(RetainedError::InvalidArgument(
            "retained-send limits must be positive",
        ));
    }
    if limits.max_single_bytes > limits.max_total_bytes {
        return Err(RetainedError::InvalidArgument(
            "the single-file limit cannot exceed the total byte limit",
        ));
    }
    Ok(())
}

fn valid_peer_name(value: &str) -> Result<String, RetainedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(RetainedError::InvalidArgument(
            "a retained send needs a non-empty peer name without control characters",
        ));
    }
    Ok(value.to_string())
}

fn is_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Every public id is opaque 64-hex. This also makes an id safe as the single
/// path component used for terminal spool cleanup.
fn validate_lookup_id(id: &str) -> Result<(), RetainedError> {
    if is_hex_64(id) {
        Ok(())
    } else {
        Err(RetainedError::InvalidArgument(
            "a retained send id must be 64 lower-case hex characters",
        ))
    }
}

fn valid_device_id(value: &str) -> Result<String, RetainedError> {
    let value = value.trim().to_ascii_lowercase();
    if !is_hex_64(&value) {
        return Err(RetainedError::InvalidArgument(
            "a retained send target needs a 64-hex device public key",
        ));
    }
    Ok(value)
}

fn valid_server(value: &str) -> Result<String, RetainedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 || value.chars().any(char::is_control) {
        return Err(RetainedError::InvalidArgument(
            "a retained send needs a non-empty server without control characters",
        ));
    }
    Ok(value.to_string())
}

fn valid_offer_name(value: &str) -> Result<String, RetainedError> {
    if value.is_empty() {
        return Err(RetainedError::InvalidArgument(
            "a retained send needs a file name",
        ));
    }
    let safe = safe_incoming_name(value);
    if safe != value {
        return Err(RetainedError::InvalidArgument(
            "a retained send file name must already be a safe basename",
        ));
    }
    Ok(value.to_string())
}

fn valid_request_id(value: &str) -> Result<String, RetainedError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(RetainedError::InvalidArgument(
            "a receiver request id must be non-empty, bounded and control-free",
        ));
    }
    Ok(value.to_string())
}

fn decode_seed(value: &str) -> Result<[u8; 32], RetainedError> {
    let bytes = hex::decode(value)
        .map_err(|_| RetainedError::Corrupt("the retained-send seed is not hex".to_string()))?;
    bytes.as_slice().try_into().map_err(|_| {
        RetainedError::Corrupt("the retained-send seed has the wrong length".to_string())
    })
}

fn new_seed() -> Result<String, RetainedError> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)
        .map_err(|error| RetainedError::Storage(format!("root seed: {error}")))?;
    Ok(hex::encode(seed))
}

fn allocate_id(seed: &[u8; 32], sequence: u64) -> String {
    let mut digest = Sha256::new();
    digest.update(ID_DOMAIN);
    digest.update(seed);
    digest.update(sequence.to_be_bytes());
    hex::encode(digest.finalize())
}

fn random_suffix() -> Result<String, RetainedError> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| RetainedError::Storage(format!("staging nonce: {error}")))?;
    Ok(hex::encode(bytes))
}

fn create_private_dir(path: &Path) -> Result<(), RetainedError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() => {
            return Err(RetainedError::InvalidArgument(
                "a retained-send directory is not a real directory",
            ));
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)
                .map_err(|error| RetainedError::Storage(error.to_string()))?;
        }
        Err(error) => return Err(RetainedError::Storage(error.to_string())),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
    }
    Ok(())
}

fn create_private_file(path: &Path) -> Result<std::fs::File, RetainedError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| RetainedError::Storage(error.to_string()))
}

fn open_regular_nofollow(path: &Path) -> Result<std::fs::File, RetainedError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
        return Err(RetainedError::InvalidArgument(
            "the retained source must be a regular file, not a symlink or directory",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    if !opened.is_file() {
        return Err(RetainedError::InvalidArgument(
            "the retained source is not a regular file",
        ));
    }
    Ok(file)
}

fn copy_exact_source(source: &Path, destination: &Path) -> Result<(u64, String), RetainedError> {
    let mut input = open_regular_nofollow(source)?;
    let mut output = create_private_file(destination)?;
    let copied = io::copy(&mut input, &mut output)
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    output
        .flush()
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    output
        .sync_all()
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    drop(output);

    let metadata = std::fs::metadata(destination)
        .map_err(|error| RetainedError::Storage(error.to_string()))?;
    if !metadata.is_file() || metadata.len() != copied {
        return Err(RetainedError::Storage(
            "the retained snapshot changed while it was being copied".to_string(),
        ));
    }
    let (hashed, size) = hash_file(destination)?;
    if size != copied {
        return Err(RetainedError::Storage(
            "the retained snapshot changed while it was being hashed".to_string(),
        ));
    }
    Ok((size, hashed))
}

fn hash_file(path: &Path) -> Result<(String, u64), RetainedError> {
    // The spool is private, but a local replacement must still fail closed:
    // refuse a symlink or a non-regular file at verify time as well.
    let mut file = open_regular_nofollow(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| RetainedError::Storage(error.to_string()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        total = total.saturating_add(read as u64);
    }
    Ok((hex::encode(digest.finalize()), total))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "tunlion-retained-send-{}-{}-{}",
                std::process::id(),
                label,
                random_suffix().expect("nonce")
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("temp root");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn device_id() -> String {
        "ab".repeat(32)
    }

    fn source(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        std::fs::write(&path, bytes).expect("source file");
        path
    }

    const NOW: u64 = 1_700_000_000;

    fn open(root: &TempRoot) -> RetainedStore {
        RetainedStore::open(root.path()).expect("store")
    }

    fn enqueue(store: &RetainedStore, source: &Path, name: &str) -> RetainedSend {
        store
            .enqueue(
                "laptop",
                &device_id(),
                "https://signal.test",
                source,
                name,
                NOW,
            )
            .expect("enqueue")
    }

    #[test]
    fn ids_are_stable_across_restart_and_sequence_never_repeats() {
        let root = TempRoot::new("restart");
        let file = source(root.path(), "a.txt", b"hello retained");
        let first = {
            let store = open(&root);
            let first = enqueue(&store, &file, "a.txt");
            assert_eq!(first.id.len(), 64);
            first
        };
        let second = {
            let store = open(&root);
            let same = store.get(&first.id).expect("get").expect("record");
            assert_eq!(same.id, first.id);
            assert_eq!(same.manifest, first.manifest);
            enqueue(&store, &file, "a.txt")
        };
        assert_ne!(first.id, second.id);
        let store = open(&root);
        assert_eq!(store.snapshot().expect("snapshot").len(), 2);
    }

    #[test]
    fn the_immutable_snapshot_survives_a_changed_original() {
        let root = TempRoot::new("original");
        let file = source(root.path(), "a.txt", b"first exact bytes");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");

        // The original is mutable user state. Changing it must not alter the
        // retained offer, and the spool must still verify.
        std::fs::write(&file, b"totally different").expect("mutate original");
        store.verify_source(&record).expect("snapshot still exact");
        let retained = std::fs::read(record.source_path()).expect("spool bytes");
        assert_eq!(retained, b"first exact bytes");

        // Only a terminal transition removes the private spool.
        let delivered = store
            .terminal(&record.id, record.rev, SendState::Delivered, NOW + 1)
            .expect("terminal");
        assert_eq!(delivered.state, SendState::Delivered);
        assert!(!record.source_path().exists());
    }

    #[test]
    fn changed_or_deleted_spool_is_refused() {
        let root = TempRoot::new("source");
        let file = source(root.path(), "a.txt", b"exact bytes");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");
        store.verify_source(&record).expect("initial spool matches");

        let spool = record.source_path().to_path_buf();
        std::fs::write(&spool, b"different bytes").expect("tamper spool");
        assert!(matches!(
            store.verify_source(&record),
            Err(RetainedError::SourceChanged(_))
        ));

        std::fs::remove_file(&spool).expect("delete spool");
        assert!(matches!(
            store.verify_source(&record),
            Err(RetainedError::SourceMissing(_))
        ));
    }

    #[test]
    fn terminal_is_idempotent_and_never_infers_delivery() {
        let root = TempRoot::new("terminal");
        let file = source(root.path(), "a.txt", b"payload");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");
        assert_eq!(record.state, SendState::Waiting);

        let attempted = store
            .mark_attempt(&record.id, record.rev, NOW)
            .expect("attempt");
        assert_eq!(attempted.state, SendState::Waiting);
        assert!(!attempted.is_terminal());

        let delivered = store
            .terminal(&attempted.id, attempted.rev, SendState::Delivered, NOW + 1)
            .expect("delivered");
        assert_eq!(delivered.state, SendState::Delivered);
        assert_eq!(delivered.rev, attempted.rev + 1);
        assert_eq!(delivered.claim_until, 0);

        let again = store
            .terminal(&delivered.id, delivered.rev, SendState::Delivered, NOW + 2)
            .expect("idempotent");
        assert_eq!(again.rev, delivered.rev);
        assert_eq!(again.state, SendState::Delivered);

        assert!(matches!(
            store.terminal(&delivered.id, delivered.rev, SendState::Denied, NOW + 3),
            Err(RetainedError::InvalidState { .. })
        ));
        assert!(matches!(
            store.terminal(&delivered.id, delivered.rev, SendState::Waiting, NOW + 3),
            Err(RetainedError::InvalidArgument(_))
        ));
    }

    #[test]
    fn stale_revisions_cannot_overwrite_a_newer_decision() {
        let root = TempRoot::new("revision");
        let file = source(root.path(), "a.txt", b"payload");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");

        let deferred = store
            .defer(&record.id, record.rev, 30, Some("transfer:7"), NOW)
            .expect("defer");
        assert_eq!(deferred.rev, record.rev + 1);
        assert_eq!(deferred.receiver_request_id.as_deref(), Some("transfer:7"));

        assert!(matches!(
            store.defer(&record.id, record.rev, 60, None, NOW + 1),
            Err(RetainedError::RevisionConflict { .. })
        ));
        assert!(matches!(
            store.mark_attempt(&record.id, record.rev, NOW + 1),
            Err(RetainedError::RevisionConflict { .. })
        ));
    }

    #[test]
    fn active_queue_is_bounded_and_never_evicted() {
        let root = TempRoot::new("bounded");
        let store = RetainedStore::open_with_limits(
            root.path(),
            Limits {
                max_active: 2,
                max_metadata_bytes: 8 * 1024 * 1024,
                max_total_bytes: 1024 * 1024,
                max_single_bytes: 1024 * 1024,
            },
        )
        .expect("store");
        let first = source(root.path(), "a.txt", b"a");
        let second = source(root.path(), "b.txt", b"b");
        let third = source(root.path(), "c.txt", b"c");

        enqueue(&store, &first, "a.txt");
        enqueue(&store, &second, "b.txt");
        assert!(matches!(
            store.enqueue(
                "laptop",
                &device_id(),
                "https://signal.test",
                &third,
                "c.txt",
                NOW
            ),
            Err(RetainedError::LimitExceeded(_))
        ));
        assert_eq!(store.snapshot().expect("snapshot").len(), 2);
    }

    #[test]
    fn concurrent_enqueues_are_bounded_by_the_active_limit() {
        let root = TempRoot::new("concurrent");
        let mut sources = Vec::new();
        for index in 0..8 {
            sources.push(source(
                root.path(),
                &format!("f{index}.txt"),
                format!("payload {index}").as_bytes(),
            ));
        }
        let mut handles = Vec::new();
        for (index, file) in sources.into_iter().enumerate() {
            let root = root.path().to_path_buf();
            handles.push(std::thread::spawn(move || {
                let store = RetainedStore::open_with_limits(
                    root,
                    Limits {
                        max_active: 4,
                        max_metadata_bytes: 8 * 1024 * 1024,
                        max_total_bytes: 1024 * 1024,
                        max_single_bytes: 1024 * 1024,
                    },
                )
                .expect("store");
                store
                    .enqueue(
                        "laptop",
                        &device_id(),
                        "https://signal.test",
                        &file,
                        &format!("f{index}.txt"),
                        NOW,
                    )
                    .is_ok()
            }));
        }
        let accepted = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(accepted, 4);
        let store = open(&root);
        assert_eq!(store.snapshot().expect("snapshot").len(), 4);
    }

    #[test]
    fn a_live_claim_cannot_be_stolen_by_a_fresh_revision() {
        let root = TempRoot::new("claim");
        let file = source(root.path(), "a.txt", b"payload");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");

        let first = store
            .mark_attempt(&record.id, record.rev, NOW)
            .expect("first claim");
        assert_eq!(first.claim_until, NOW + IN_FLIGHT_SECS);
        assert_eq!(first.next_attempt_at, first.claim_until);

        // A second manual CLI reads the fresh revision while the first attempt
        // is still live. The fresh revision alone must not be enough.
        let fresh = store.get(&record.id).expect("get").expect("record");
        assert_eq!(fresh.rev, first.rev);
        assert!(matches!(
            store.mark_attempt(&record.id, fresh.rev, NOW + 1),
            Err(RetainedError::Busy { .. })
        ));
        assert!(store
            .due(NOW + 1)
            .expect("due")
            .iter()
            .all(|record| record.id != first.id));

        // The claim expires and a takeover gets a new revision.
        let takeover = store
            .mark_attempt(&record.id, fresh.rev, NOW + IN_FLIGHT_SECS)
            .expect("takeover");
        assert_eq!(takeover.attempts, 2);
        assert_eq!(takeover.rev, fresh.rev + 1);

        // The first process's old revision can no longer defer or claim
        // delivery after the takeover.
        assert!(matches!(
            store.defer(&record.id, first.rev, 30, None, NOW + IN_FLIGHT_SECS + 1),
            Err(RetainedError::RevisionConflict { .. })
        ));
        assert!(matches!(
            store.terminal(
                &record.id,
                first.rev,
                SendState::Delivered,
                NOW + IN_FLIGHT_SECS + 1
            ),
            Err(RetainedError::RevisionConflict { .. })
        ));

        // The takeover owner can defer; that releases the live claim and
        // schedules the retry.
        let deferred = store
            .defer(&record.id, takeover.rev, 30, None, NOW + IN_FLIGHT_SECS + 1)
            .expect("defer");
        assert_eq!(deferred.claim_until, 0);
        assert!(store
            .due(NOW + IN_FLIGHT_SECS + 31)
            .expect("due")
            .iter()
            .any(|record| record.id == deferred.id));
    }

    #[test]
    fn expire_releases_a_claim_and_removes_only_that_spool() {
        let root = TempRoot::new("expire-claim");
        let file = source(root.path(), "a.txt", b"payload");
        let store = open(&root);
        let record = enqueue(&store, &file, "a.txt");
        let claimed = store
            .mark_attempt(&record.id, record.rev, NOW)
            .expect("claim");
        assert!(claimed.claim_until > NOW);

        let expired = store.expire(NOW + MAX_TTL_SECS).expect("expire");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].claim_until, 0);
        assert_eq!(expired[0].state, SendState::Expired);
        assert!(!record.source_path().exists());
        assert!(store.due(NOW + MAX_TTL_SECS).expect("due").is_empty());
    }

    #[test]
    fn due_excludes_in_flight_and_expired_offers() {
        let root = TempRoot::new("due");
        let file = source(root.path(), "a.txt", b"payload");
        let store = open(&root);
        let first = enqueue(&store, &file, "a.txt");
        let second = enqueue(&store, &file, "a.txt");

        assert_eq!(store.due(NOW).expect("due").len(), 2);
        let claimed = store
            .mark_attempt(&first.id, first.rev, NOW)
            .expect("attempt");
        let due = store.due(NOW).expect("due");
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, second.id);
        assert!(due.iter().all(|record| record.id != claimed.id));
        assert!(!store.due(NOW + IN_FLIGHT_SECS - 1).expect("due").is_empty());
    }
}
