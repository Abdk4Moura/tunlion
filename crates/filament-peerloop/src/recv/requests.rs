//! Durable inbound transfer-request inbox.
//!
//! This is the engine-side record for an asynchronous file offer: the exact
//! manifest the sender proposed, the current decision, and a revisioned
//! snapshot a client can read after a restart. It deliberately owns no
//! transport, no file placement and no authorization engine. Callers supply a
//! *fresh* [`SenderIdentity`] observation for every write; a stored snapshot is
//! never treated as current authority.
//!
//! Design rules encoded here:
//!
//! * a transfer offer is not a standing capability, so the record contains no
//!   grant list and completing it mutates nothing else;
//! * the manifest is canonical: relative safe paths, mandatory lower-case
//!   SHA-256, sorted entries, stable digest, bounded entries/bytes/metadata;
//! * acceptance binds that exact digest and a destination string;
//! * every mutation is revision-checked, written atomically under a
//!   cross-process lock, and returns its notification event *after* commit;
//! * terminal records are bounded, and a fulfilled offer leaves a tombstone so
//!   an old offer id cannot be replayed after pruning;
//! * snapshots are authoritative full snapshots. A cursor below the retained
//!   terminal floor reports `resync_required` instead of pretending to replay an
//!   event log that does not exist.
//!
//! No network retry lives here. "Approved" means waiting for the sender to
//! re-offer; this module never claims offline delivery.

use crate::recv::store::StoreLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// Request store file name, relative to the inbox directory.
pub const REQUESTS_FILE: &str = "requests.json";
/// Cross-process lock sidecar for the request store.
pub const REQUESTS_LOCK_FILE: &str = "requests.json.lock";
/// On-disk schema version.
pub const REQUESTS_SCHEMA: u64 = 1;

const MAX_OFFER_ID: usize = 128;
const MAX_DESTINATION: usize = 4096;
const TOMBSTONE_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// A request-store failure. Messages never include file bytes or paths from a
/// peer's manifest beyond the invalid path itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Manifest(&'static str),
    ManifestDetail(String),
    UnsafePath(String),
    DuplicatePath(String),
    LimitExceeded(&'static str),
    InvalidSender(&'static str),
    SenderRefused(&'static str),
    InvalidOfferId,
    InvalidDestination,
    NotFound(u64),
    RevisionConflict { expected: u64, current: u64 },
    InvalidState { id: u64, state: &'static str },
    OfferExpired(u64),
    OfferIdReused(String),
    OfferChanged(u64),
    Storage(String),
    Corrupt(String),
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manifest(message) => write!(f, "{message}"),
            Self::ManifestDetail(message) => write!(f, "{message}"),
            Self::UnsafePath(path) => write!(f, "unsafe manifest path: {path:?}"),
            Self::DuplicatePath(path) => write!(f, "duplicate manifest path: {path:?}"),
            Self::LimitExceeded(what) => write!(f, "{what}"),
            Self::InvalidSender(what) => write!(f, "invalid sender: {what}"),
            Self::SenderRefused(why) => write!(f, "sender refused: {why}"),
            Self::InvalidOfferId => f.write_str("invalid offer id"),
            Self::InvalidDestination => f.write_str("invalid destination"),
            Self::NotFound(id) => write!(f, "no request {id}"),
            Self::RevisionConflict { expected, current } => {
                write!(f, "revision conflict: expected {expected}, current {current}")
            }
            Self::InvalidState { id, state } => {
                write!(f, "request {id} is {state}, not a valid state for this action")
            }
            Self::OfferExpired(id) => write!(f, "request {id} has expired"),
            Self::OfferIdReused(offer) => write!(f, "offer id {offer:?} was already used"),
            Self::OfferChanged(id) => write!(f, "request {id} no longer matches its exact offer"),
            Self::Storage(message) => write!(f, "request store: {message}"),
            Self::Corrupt(message) => write!(f, "request store is corrupt: {message}"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Limits for manifests, queues and retained terminal records.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_name_bytes: usize,
    pub max_metadata_bytes: usize,
    pub max_total_bytes: u64,
    /// Aggregate serialized manifest bytes retained in the queue.
    pub max_queue_bytes: usize,
    pub max_pending: usize,
    pub max_terminal: usize,
    pub max_tombstones: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 256,
            max_path_bytes: 1024,
            max_name_bytes: 255,
            max_metadata_bytes: 256 * 1024,
            max_total_bytes: 10 * 1024 * 1024 * 1024,
            max_queue_bytes: 8 * 1024 * 1024,
            max_pending: 1000,
            max_terminal: 100,
            max_tombstones: 1000,
        }
    }
}

/// One file in an offered manifest. `mtime` is optional metadata and is not
/// part of the digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub mtime: u64,
}

/// Sorted, validated manifest with its stable digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalManifest {
    pub digest: String,
    pub count: usize,
    pub total_bytes: u64,
    pub serialized_bytes: usize,
    pub entries: Vec<ManifestEntry>,
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(path: &str, limits: &Limits) -> Result<(), RequestError> {
    if path.is_empty() {
        return Err(RequestError::UnsafePath(path.to_string()));
    }
    if path.len() > limits.max_path_bytes {
        return Err(RequestError::LimitExceeded("manifest path is too long"));
    }
    if path.starts_with('/') || path.ends_with('/') {
        return Err(RequestError::UnsafePath(path.to_string()));
    }
    if path.contains('\\') || path.contains(':') {
        return Err(RequestError::UnsafePath(path.to_string()));
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return Err(RequestError::UnsafePath(path.to_string()));
    }
    if path.split('/').any(|segment| {
        segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || windows_reserved(segment)
    }) {
        return Err(RequestError::UnsafePath(path.to_string()));
    }
    let name = path.rsplit('/').next().unwrap_or(path);
    if name.len() > limits.max_name_bytes {
        return Err(RequestError::LimitExceeded("manifest file name is too long"));
    }
    Ok(())
}

/// Windows device names stay reserved even with an extension
/// (`CON.txt` is still `CON`). Refusing them here keeps a later placement from
/// creating an unreadable or device-bound path.
fn windows_reserved(segment: &str) -> bool {
    let stem = segment
        .split('.')
        .next()
        .unwrap_or(segment)
        .trim_end_matches([' ', '.'])
        .to_ascii_lowercase();
    matches!(stem.as_str(), "con" | "prn" | "aux" | "nul")
        || stem
            .strip_prefix("com")
            .or_else(|| stem.strip_prefix("lpt"))
            .is_some_and(|digits| {
                digits.len() == 1 && matches!(digits.as_bytes()[0], b'1'..=b'9')
            })
}

/// Validate, sort and digest a manifest. The digest covers `path`, `size` and
/// `sha256` only, so an mtime change cannot alter the reviewed agreement.
pub fn canonical_manifest(
    entries: &[ManifestEntry],
    limits: &Limits,
) -> Result<CanonicalManifest, RequestError> {
    if entries.is_empty() {
        return Err(RequestError::Manifest("a manifest must contain an entry"));
    }
    if entries.len() > limits.max_entries {
        return Err(RequestError::LimitExceeded("manifest has too many entries"));
    }
    let mut seen = HashSet::new();
    let mut folded = HashSet::new();
    let mut total = 0u64;
    for entry in entries {
        validate_relative_path(&entry.path, limits)?;
        if !seen.insert(entry.path.clone()) {
            return Err(RequestError::DuplicatePath(entry.path.clone()));
        }
        if !folded.insert(entry.path.to_lowercase()) {
            return Err(RequestError::DuplicatePath(entry.path.clone()));
        }
        if !valid_sha256(&entry.sha256) {
            return Err(RequestError::Manifest(
                "each manifest entry needs a lower-case 64-hex sha256",
            ));
        }
        total = total
            .checked_add(entry.size)
            .ok_or(RequestError::LimitExceeded("manifest size overflow"))?;
    }
    if total > limits.max_total_bytes {
        return Err(RequestError::LimitExceeded("manifest total bytes exceeds the limit"));
    }
    let mut ordered = entries.to_vec();
    ordered.sort_by(|a, b| a.path.cmp(&b.path));
    let digest_payload = Value::Array(
        ordered
            .iter()
            .map(|entry| {
                json!({
                    "path": entry.path,
                    "sha256": entry.sha256,
                    "size": entry.size,
                })
            })
            .collect(),
    );
    let digest_bytes = serde_json::to_vec(&digest_payload)
        .map_err(|error| RequestError::ManifestDetail(error.to_string()))?;
    let metadata = serde_json::to_vec(&ordered)
        .map_err(|error| RequestError::ManifestDetail(error.to_string()))?;
    if metadata.len() > limits.max_metadata_bytes {
        return Err(RequestError::LimitExceeded("serialized manifest is too large"));
    }
    Ok(CanonicalManifest {
        digest: hex_sha256(&digest_bytes),
        count: ordered.len(),
        total_bytes: total,
        serialized_bytes: metadata.len(),
        entries: ordered,
    })
}

/// How the sender relates to this owner. This is a fresh observation supplied
/// by the caller, not a token stored from an earlier decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderRelation {
    SameOwner,
    PairedExternal,
}

/// A caller-supplied observation about the sender at the time of a write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderIdentity {
    pub device_id: String,
    pub user_id: String,
    pub relation: SenderRelation,
    pub verified: bool,
    pub known: bool,
    pub revoked: bool,
    #[serde(default)]
    pub expires_at: Option<u64>,
    #[serde(default)]
    pub is_primary: bool,
}

impl SenderIdentity {
    fn validate(&self) -> Result<(), RequestError> {
        for (name, value) in [("device_id", &self.device_id), ("user_id", &self.user_id)] {
            if value.is_empty()
                || value.len() > 256
                || value.chars().any(|c| c.is_control())
            {
                return Err(RequestError::InvalidSender(name));
            }
        }
        Ok(())
    }

    /// A fresh authority check for this write. Returns the refusal reason.
    fn refusal(&self, now: u64, owner_user_id: &str) -> Option<&'static str> {
        if !self.known {
            return Some("unknown sender");
        }
        if !self.verified {
            return Some("unverified sender");
        }
        if self.revoked {
            return Some("revoked sender");
        }
        if self.expires_at.is_some_and(|expires| expires <= now) {
            return Some("expired sender");
        }
        match self.relation {
            SenderRelation::SameOwner if self.user_id != owner_user_id => {
                Some("same-owner claim does not match this owner")
            }
            SenderRelation::PairedExternal if self.user_id == owner_user_id => {
                Some("external sender claimed the owner identity")
            }
            _ => None,
        }
    }
}

/// Request lifecycle. `Approved` means the exact offer was accepted and the
/// receiver is waiting for the sender; it never means bytes were delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    Pending,
    Approved,
    Delivering,
    Denied,
    Expired,
    Fulfilled,
    Failed,
    Withdrawn,
}

impl RequestState {
    fn is_active(self) -> bool {
        matches!(self, Self::Pending | Self::Approved | Self::Delivering)
    }

    fn is_terminal(self) -> bool {
        !self.is_active()
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Delivering => "delivering",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Fulfilled => "fulfilled",
            Self::Failed => "failed",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One durable inbound offer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    pub id: u64,
    pub offer_id: String,
    pub kind: String,
    pub sender: SenderIdentity,
    pub manifest: CanonicalManifest,
    pub state: RequestState,
    #[serde(default)]
    pub destination: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub expires_at: u64,
    pub rev: u64,
}

/// Post-commit hint. Delivery order is not an event log; clients still read a
/// full snapshot for authority and exact-manifest facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEvent {
    pub rev: u64,
    pub request_id: u64,
    pub offer_id: String,
    pub status: String,
    pub at: u64,
}

/// Authoritative full snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub rev: u64,
    pub terminal_floor: u64,
    pub resync_required: bool,
    pub requests: Vec<RequestRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Tombstone {
    offer_id: String,
    digest: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskState {
    schema: u64,
    rev: u64,
    next_id: u64,
    requests: Vec<RequestRecord>,
    tombstones: Vec<Tombstone>,
    terminal_floor: u64,
}

impl DiskState {
    fn empty() -> Self {
        Self {
            schema: REQUESTS_SCHEMA,
            rev: 0,
            next_id: 1,
            requests: Vec::new(),
            tombstones: Vec::new(),
            terminal_floor: 0,
        }
    }
}

/// Durable request inbox on an explicit directory. No process-global path is
/// read here; the caller chooses the root.
pub struct RequestStore {
    directory: PathBuf,
    owner_user_id: String,
    limits: Limits,
}

impl RequestStore {
    pub fn open(
        directory: impl Into<PathBuf>,
        owner_user_id: impl Into<String>,
        limits: Limits,
    ) -> Result<Self, RequestError> {
        let owner_user_id = owner_user_id.into();
        if owner_user_id.is_empty() {
            return Err(RequestError::InvalidSender("owner_user_id"));
        }
        if limits.max_terminal == 0 || limits.max_tombstones == 0 {
            return Err(RequestError::LimitExceeded(
                "terminal and tombstone retention must be positive",
            ));
        }
        let directory = directory.into();
        std::fs::create_dir_all(&directory)
            .map_err(|error| RequestError::Storage(error.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                .map_err(|error| RequestError::Storage(error.to_string()))?;
        }
        Ok(Self {
            directory,
            owner_user_id,
            limits,
        })
    }

    pub fn store_path(&self) -> PathBuf {
        self.directory.join(REQUESTS_FILE)
    }

    fn lock_path(&self) -> PathBuf {
        self.directory.join(REQUESTS_LOCK_FILE)
    }

    fn load(&self) -> Result<DiskState, RequestError> {
        let path = self.store_path();
        let raw = match std::fs::read_to_string(&path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DiskState::empty())
            }
            Err(error) => return Err(RequestError::Storage(error.to_string())),
        };
        let state: DiskState = serde_json::from_str(&raw)
            .map_err(|error| RequestError::Corrupt(error.to_string()))?;
        if state.schema != REQUESTS_SCHEMA {
            return Err(RequestError::Corrupt(format!(
                "unsupported schema {}",
                state.schema
            )));
        }
        let mut ids = HashSet::new();
        let mut offers = HashSet::new();
        for record in &state.requests {
            if !ids.insert(record.id) || !offers.insert(record.offer_id.clone()) {
                return Err(RequestError::Corrupt("duplicate request id or offer id".into()));
            }
            if record.rev > state.rev || record.expires_at < record.created_at {
                return Err(RequestError::Corrupt("request revision/lifetime is inconsistent".into()));
            }
            if matches!(record.state, RequestState::Approved | RequestState::Delivering)
                && record.destination.is_none()
            {
                return Err(RequestError::Corrupt(
                    "accepted request has no destination".into(),
                ));
            }
            let checked = canonical_manifest(&record.manifest.entries, &self.limits)?;
            if checked != record.manifest {
                return Err(RequestError::Corrupt(
                    "stored manifest does not match its digest".into(),
                ));
            }
        }
        if state.next_id <= ids.iter().copied().max().unwrap_or(0) {
            return Err(RequestError::Corrupt("next_id is behind a stored request".into()));
        }
        if state.terminal_floor > state.rev {
            return Err(RequestError::Corrupt("terminal floor is ahead of the store".into()));
        }
        Ok(state)
    }

    fn save(&self, state: &DiskState) -> Result<(), RequestError> {
        let text = serde_json::to_string(state)
            .map_err(|error| RequestError::Storage(error.to_string()))?;
        secret_write::SecretFile::write_str(self.store_path(), &text)
            .map_err(|error| RequestError::Storage(error.to_string()))
    }

    fn locked<T>(
        &self,
        mutate: impl FnOnce(&mut DiskState) -> Result<T, RequestError>,
    ) -> Result<T, RequestError> {
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RequestError::Storage(error.to_string()))?;
        let mut state = self.load()?;
        let value = mutate(&mut state)?;
        self.save(&state)?;
        Ok(value)
    }

    /// Read a full snapshot. `since` is only a resynchronization cursor: the
    /// response is always authoritative, and a cursor below the retained
    /// terminal floor asks the caller to resync.
    pub fn snapshot(&self, since: Option<u64>) -> Result<Snapshot, RequestError> {
        // A read holds the same lock as writes. Atomic rename already prevents
        // torn reads; the lock also stops a Windows reader from making the
        // writer exhaust its bounded replace retries.
        let _lock = StoreLock::acquire(&self.lock_path())
            .map_err(|error| RequestError::Storage(error.to_string()))?;
        let state = self.load()?;
        let resync_required = since.is_some_and(|cursor| {
            cursor > state.rev || cursor < state.terminal_floor
        });
        Ok(Snapshot {
            rev: state.rev,
            terminal_floor: state.terminal_floor,
            resync_required,
            requests: state.requests,
        })
    }

    /// Propose an exact offer. Unknown, unverified, revoked or expired senders
    /// are refused before anything is written. Same-owner offers auto-approve
    /// only when the caller supplied the destination; external offers stay
    /// pending for review.
    pub fn propose(
        &self,
        offer_id: &str,
        sender: &SenderIdentity,
        manifest: &CanonicalManifest,
        ttl_secs: u64,
        auto_destination: Option<&str>,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        if offer_id.is_empty()
            || offer_id.len() > MAX_OFFER_ID
            || offer_id.chars().any(|c| c.is_control())
        {
            return Err(RequestError::InvalidOfferId);
        }
        sender.validate()?;
        if let Some(reason) = sender.refusal(now, &self.owner_user_id) {
            return Err(RequestError::SenderRefused(reason));
        }
        if ttl_secs == 0 {
            return Err(RequestError::Manifest("request ttl must be positive"));
        }
        if let Some(destination) = auto_destination {
            validate_destination(destination)?;
        }
        // A CanonicalManifest is a public value; recompute it from its entries
        // so a caller cannot pair a reviewed digest with different files.
        let checked = canonical_manifest(&manifest.entries, &self.limits)?;
        if checked != *manifest {
            return Err(RequestError::Manifest(
                "manifest summary does not match its entries",
            ));
        }

        self.locked(|state| {
            // Drop expired tombstones before deciding whether this id is new;
            // otherwise an idle inbox blocks that id past its retention.
            prune_state(state, &self.limits, now);
            if let Some(existing) = state
                .requests
                .iter()
                .find(|record| record.offer_id == offer_id)
            {
                if existing.sender.device_id == sender.device_id
                    && existing.sender.user_id == sender.user_id
                    && existing.sender.relation == sender.relation
                    && existing.manifest.digest == manifest.digest
                {
                    require_same_sender(existing, sender, now, &self.owner_user_id)?;
                    return Ok((existing.clone(), None));
                }
                return Err(RequestError::OfferIdReused(offer_id.to_string()));
            }
            if state
                .tombstones
                .iter()
                .any(|tombstone| tombstone.offer_id == offer_id)
            {
                return Err(RequestError::OfferIdReused(offer_id.to_string()));
            }
            let active = state
                .requests
                .iter()
                .filter(|record| record.state.is_active())
                .count();
            if active >= self.limits.max_pending {
                return Err(RequestError::LimitExceeded("request queue is full"));
            }
            let queued_bytes: usize = state
                .requests
                .iter()
                .map(|record| record.manifest.serialized_bytes)
                .sum();
            if queued_bytes.saturating_add(manifest.serialized_bytes)
                > self.limits.max_queue_bytes
            {
                return Err(RequestError::LimitExceeded("request queue bytes are full"));
            }

            let expires_at = now
                .saturating_add(ttl_secs)
                .min(sender.expires_at.unwrap_or(u64::MAX));
            let auto_approve = sender.relation == SenderRelation::SameOwner
                && auto_destination.is_some();
            let mut record = RequestRecord {
                id: state.next_id,
                offer_id: offer_id.to_string(),
                kind: "transfer".to_string(),
                sender: sender.clone(),
                manifest: manifest.clone(),
                state: if auto_approve {
                    RequestState::Approved
                } else {
                    RequestState::Pending
                },
                destination: if auto_approve {
                    auto_destination.map(str::to_string)
                } else {
                    None
                },
                created_at: now,
                updated_at: now,
                expires_at,
                rev: 0,
            };
            state.next_id = state.next_id.saturating_add(1);
            let initial_state = record.state;
            let event = touch(&mut state.rev, &mut record, initial_state, now);
            state.requests.push(record.clone());
            prune_state(state, &self.limits, now);
            Ok((record, Some(event)))
        })
    }

    /// Accept the exact offer at a known record revision with a fresh sender
    /// observation. The destination is stored verbatim; confinement is the
    /// caller's receive-root policy.
    pub fn accept(
        &self,
        id: u64,
        expected_rev: u64,
        destination: &str,
        sender: &SenderIdentity,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        validate_destination(destination)?;
        sender.validate()?;
        self.locked(|state| {
            let index = find_index(state, id)?;
            let current = state.requests[index].rev;
            if current != expected_rev {
                return Err(RequestError::RevisionConflict {
                    expected: expected_rev,
                    current,
                });
            }
            if state.requests[index].state == RequestState::Approved
                && state.requests[index].destination.as_deref() == Some(destination)
            {
                if now >= state.requests[index].expires_at {
                    return Err(RequestError::OfferExpired(id));
                }
                require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
                return Ok((state.requests[index].clone(), None));
            }
            let state_name = state.requests[index].state;
            if state_name != RequestState::Pending {
                return Err(RequestError::InvalidState {
                    id,
                    state: state_name.as_str(),
                });
            }
            if now >= state.requests[index].expires_at {
                return Err(RequestError::OfferExpired(id));
            }
            require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
            state.requests[index].destination = Some(destination.to_string());
            let event = touch(
                &mut state.rev,
                &mut state.requests[index],
                RequestState::Approved,
                now,
            );
            let record = state.requests[index].clone();
            prune_state(state, &self.limits, now);
            Ok((record, Some(event)))
        })
    }

    /// Decline a pending or approved offer. No sender observation is needed:
    /// the owner is closing their own inbox entry.
    pub fn decline(
        &self,
        id: u64,
        expected_rev: u64,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        self.locked(|state| {
            let index = find_index(state, id)?;
            let current = state.requests[index].rev;
            if current != expected_rev {
                return Err(RequestError::RevisionConflict {
                    expected: expected_rev,
                    current,
                });
            }
            if state.requests[index].state == RequestState::Denied {
                return Ok((state.requests[index].clone(), None));
            }
            let state_name = state.requests[index].state;
            if !matches!(state_name, RequestState::Pending | RequestState::Approved) {
                return Err(RequestError::InvalidState {
                    id,
                    state: state_name.as_str(),
                });
            }
            let event = touch(
                &mut state.rev,
                &mut state.requests[index],
                RequestState::Denied,
                now,
            );
            let record = state.requests[index].clone();
            prune_state(state, &self.limits, now);
            Ok((record, Some(event)))
        })
    }

    /// Mark a delivery that failed locally. The request stays in the snapshot
    /// as a terminal record until retention prunes it.
    pub fn fail(
        &self,
        id: u64,
        expected_rev: u64,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        terminal_transition(self, id, expected_rev, RequestState::Failed, &[RequestState::Delivering], now)
    }

    /// Withdraw a request before delivery starts. This is local owner action,
    /// not a declining sender message.
    pub fn withdraw(
        &self,
        id: u64,
        expected_rev: u64,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        terminal_transition(
            self,
            id,
            expected_rev,
            RequestState::Withdrawn,
            &[RequestState::Pending, RequestState::Approved],
            now,
        )
    }

    /// The sender re-offered and the receiver is starting to write bytes. A
    /// fresh authority observation is required here, not the one stored at
    /// acceptance.
    pub fn begin_delivery(
        &self,
        id: u64,
        expected_rev: u64,
        sender: &SenderIdentity,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        sender.validate()?;
        self.locked(|state| {
            let index = find_index(state, id)?;
            let current = state.requests[index].rev;
            if current != expected_rev {
                return Err(RequestError::RevisionConflict {
                    expected: expected_rev,
                    current,
                });
            }
            if state.requests[index].state == RequestState::Delivering {
                require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
                return Ok((state.requests[index].clone(), None));
            }
            let state_name = state.requests[index].state;
            if state_name != RequestState::Approved {
                return Err(RequestError::InvalidState {
                    id,
                    state: state_name.as_str(),
                });
            }
            if now >= state.requests[index].expires_at {
                return Err(RequestError::OfferExpired(id));
            }
            require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
            let event = touch(
                &mut state.rev,
                &mut state.requests[index],
                RequestState::Delivering,
                now,
            );
            let record = state.requests[index].clone();
            Ok((record, Some(event)))
        })
    }

    /// Finish an exact delivery. This is a durable receipt, not proof that a
    /// remote party placed the bytes; the caller verifies staged bytes first.
    pub fn complete(
        &self,
        id: u64,
        expected_rev: u64,
        sender: &SenderIdentity,
        now: u64,
    ) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
        sender.validate()?;
        self.locked(|state| {
            let index = find_index(state, id)?;
            let current = state.requests[index].rev;
            if current != expected_rev {
                return Err(RequestError::RevisionConflict {
                    expected: expected_rev,
                    current,
                });
            }
            if state.requests[index].state == RequestState::Fulfilled {
                require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
                return Ok((state.requests[index].clone(), None));
            }
            let state_name = state.requests[index].state;
            if state_name != RequestState::Delivering {
                return Err(RequestError::InvalidState {
                    id,
                    state: state_name.as_str(),
                });
            }
            // Already-delivering transfers may finish after the acceptance
            // deadline; only starting a delivery is gated by expiry.
            require_same_sender(&state.requests[index], sender, now, &self.owner_user_id)?;
            let event = touch(
                &mut state.rev,
                &mut state.requests[index],
                RequestState::Fulfilled,
                now,
            );
            let record = state.requests[index].clone();
            prune_state(state, &self.limits, now);
            Ok((record, Some(event)))
        })
    }

    /// Expire every active offer whose deadline has passed. One revision bump
    /// per record keeps cursors honest.
    pub fn expire(&self, now: u64) -> Result<Vec<RequestEvent>, RequestError> {
        self.locked(|state| {
            let mut events = Vec::new();
            for index in 0..state.requests.len() {
                if matches!(
                    state.requests[index].state,
                    RequestState::Pending | RequestState::Approved
                ) && now >= state.requests[index].expires_at
                {
                    let event = touch(
                        &mut state.rev,
                        &mut state.requests[index],
                        RequestState::Expired,
                        now,
                    );
                    events.push(event);
                }
            }
            prune_state(state, &self.limits, now);
            Ok(events)
        })
    }

    /// Drop expired tombstones. Called by mutations; exposed for a housekeeping
    /// tick.
    pub fn prune(&self, now: u64) -> Result<(), RequestError> {
        self.locked(|state| {
            prune_state(state, &self.limits, now);
            Ok(())
        })
    }
}

fn terminal_transition(
    store: &RequestStore,
    id: u64,
    expected_rev: u64,
    next: RequestState,
    allowed: &[RequestState],
    now: u64,
) -> Result<(RequestRecord, Option<RequestEvent>), RequestError> {
    store.locked(|state| {
        let index = find_index(state, id)?;
        let current = state.requests[index].rev;
        if current != expected_rev {
            return Err(RequestError::RevisionConflict {
                expected: expected_rev,
                current,
            });
        }
        if state.requests[index].state == next {
            return Ok((state.requests[index].clone(), None));
        }
        let state_name = state.requests[index].state;
        if !allowed.contains(&state_name) {
            return Err(RequestError::InvalidState {
                id,
                state: state_name.as_str(),
            });
        }
        let event = touch(&mut state.rev, &mut state.requests[index], next, now);
        let record = state.requests[index].clone();
        prune_state(state, &store.limits, now);
        Ok((record, Some(event)))
    })
}

fn validate_destination(destination: &str) -> Result<(), RequestError> {
    if destination.is_empty()
        || destination.len() > MAX_DESTINATION
        || destination.chars().any(char::is_control)
    {
        return Err(RequestError::InvalidDestination);
    }
    Ok(())
}

fn find_index(state: &DiskState, id: u64) -> Result<usize, RequestError> {
    state
        .requests
        .iter()
        .position(|record| record.id == id)
        .ok_or(RequestError::NotFound(id))
}

fn require_same_sender(
    record: &RequestRecord,
    sender: &SenderIdentity,
    now: u64,
    owner: &str,
) -> Result<(), RequestError> {
    if let Some(reason) = sender.refusal(now, owner) {
        return Err(RequestError::SenderRefused(reason));
    }
    if record.sender.device_id != sender.device_id
        || record.sender.user_id != sender.user_id
        || record.sender.relation != sender.relation
    {
        return Err(RequestError::SenderRefused(
            "sender identity changed since acceptance",
        ));
    }
    Ok(())
}

fn touch(
    rev: &mut u64,
    record: &mut RequestRecord,
    next: RequestState,
    now: u64,
) -> RequestEvent {
    *rev = rev.saturating_add(1);
    record.rev = *rev;
    record.state = next;
    record.updated_at = now;
    RequestEvent {
        rev: *rev,
        request_id: record.id,
        offer_id: record.offer_id.clone(),
        status: next.as_str().to_string(),
        at: now,
    }
}

fn prune_state(state: &mut DiskState, limits: &Limits, now: u64) {
    state
        .tombstones
        .retain(|tombstone| tombstone.expires_at > now);
    while state.tombstones.len() > limits.max_tombstones {
        state.tombstones.remove(0);
    }

    let mut terminal: Vec<(u64, u64)> = state
        .requests
        .iter()
        .filter(|record| record.state.is_terminal())
        .map(|record| (record.updated_at, record.rev))
        .collect();
    // Revision is the monotonic terminal sequence. A wall clock can step back,
    // which would otherwise prune the record just written and lose its receipt.
    terminal.sort_unstable_by_key(|(_, rev)| *rev);
    if terminal.len() <= limits.max_terminal {
        return;
    }
    let remove = terminal.len() - limits.max_terminal;
    let doomed: HashSet<u64> = terminal
        .iter()
        .take(remove)
        .map(|(_, rev)| *rev)
        .collect();
    let removed: Vec<(String, String, u64)> = state
        .requests
        .iter()
        .filter(|record| record.state.is_terminal() && doomed.contains(&record.rev))
        .map(|record| {
            (
                record.offer_id.clone(),
                record.manifest.digest.clone(),
                record.rev,
            )
        })
        .collect();
    let mut floor = state.terminal_floor;
    state.requests.retain(|record| {
        !(record.state.is_terminal() && doomed.contains(&record.rev))
    });
    for (offer_id, digest, rev) in removed {
        floor = floor.max(rev);
        if limits.max_tombstones > 0
            && !state
                .tombstones
                .iter()
                .any(|tombstone| tombstone.offer_id == offer_id)
        {
            if state.tombstones.len() >= limits.max_tombstones {
                state.tombstones.remove(0);
            }
            state.tombstones.push(Tombstone {
                offer_id,
                digest,
                expires_at: now.saturating_add(TOMBSTONE_TTL_SECS),
            });
        }
    }
    state.terminal_floor = floor;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn temp_dir() -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "tunlion-requests-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn entry(path: &str, size: u64, byte: char) -> ManifestEntry {
        ManifestEntry {
            path: path.to_string(),
            size,
            sha256: digest(byte),
            mtime: 0,
        }
    }

    fn manifest(path: &str, size: u64) -> CanonicalManifest {
        canonical_manifest(&[entry(path, size, 'a')], &Limits::default()).unwrap()
    }

    fn sender(device: &str, user: &str, relation: SenderRelation) -> SenderIdentity {
        SenderIdentity {
            device_id: device.to_string(),
            user_id: user.to_string(),
            relation,
            verified: true,
            known: true,
            revoked: false,
            expires_at: None,
            is_primary: false,
        }
    }

    fn owner() -> SenderIdentity {
        sender("dev-owner", "user-owner", SenderRelation::SameOwner)
    }

    fn external() -> SenderIdentity {
        sender("dev-ext", "user-ext", SenderRelation::PairedExternal)
    }

    fn store(dir: &TempDir) -> RequestStore {
        RequestStore::open(dir.0.as_path(), "user-owner", Limits::default()).unwrap()
    }

    #[test]
    fn manifest_is_canonical_and_binds_exact_paths_sizes_and_hashes() {
        let limits = Limits::default();
        let a = entry("b.txt", 3, 'b');
        let b = entry("a.txt", 4, 'a');
        let first = canonical_manifest(&[a.clone(), b.clone()], &limits).unwrap();
        let second = canonical_manifest(&[b, a], &limits).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.count, 2);
        assert_eq!(first.total_bytes, 7);
        assert_eq!(first.entries[0].path, "a.txt");
        assert_eq!(first.digest.len(), 64);
        assert_eq!(first.digest, first.digest.to_lowercase());
    }

    #[test]
    fn manifest_refuses_traversal_missing_digests_and_duplicates() {
        let limits = Limits::default();
        for bad in ["../x", "/x", "a/../b", "a//b", "a\\b", "C:x", "a/"] {
            assert!(
                canonical_manifest(&[entry(bad, 1, 'a')], &limits).is_err(),
                "{bad}"
            );
        }
        let mut missing = entry("a", 1, 'a');
        missing.sha256 = String::new();
        assert!(canonical_manifest(&[missing], &limits).is_err());
        assert!(canonical_manifest(
            &[entry("A", 1, 'a'), entry("a", 1, 'b')],
            &limits
        )
        .is_err());
        assert!(canonical_manifest(&[], &limits).is_err());
    }

    #[test]
    fn a_manifest_summary_that_does_not_match_its_entries_is_refused() {
        let dir = temp_dir();
        let store = store(&dir);
        let mut forged = manifest("a.txt", 1);
        forged.entries[0].size = 999;
        assert!(matches!(
            store.propose("forged", &external(), &forged, 60, None, 10),
            Err(RequestError::Manifest(_))
        ));
        assert!(!store.store_path().exists());
    }

    #[test]
    fn unknown_unverified_revoked_and_expired_senders_are_refused() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        for sender in [
            SenderIdentity {
                known: false,
                ..owner()
            },
            SenderIdentity {
                verified: false,
                ..owner()
            },
            SenderIdentity {
                revoked: true,
                ..owner()
            },
            SenderIdentity {
                expires_at: Some(9),
                ..owner()
            },
        ] {
            assert!(matches!(
                store.propose("offer-1", &sender, &manifest, 60, Some("/inbox"), 10),
                Err(RequestError::SenderRefused(_))
            ));
        }
        assert!(!store.store_path().exists(), "nothing was written");
    }

    #[test]
    fn same_owner_auto_approves_with_a_destination_but_external_waits() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (record, event) = store
            .propose("owner-offer", &owner(), &manifest, 60, Some("/inbox"), 10)
            .unwrap();
        assert_eq!(record.state, RequestState::Approved);
        assert_eq!(record.destination.as_deref(), Some("/inbox"));
        assert_eq!(event.unwrap().status, "approved");

        let (external_record, external_event) = store
            .propose("ext-offer", &external(), &manifest, 60, Some("/inbox"), 10)
            .unwrap();
        assert_eq!(external_record.state, RequestState::Pending);
        assert!(external_record.destination.is_none());
        assert_eq!(external_event.unwrap().status, "pending");
    }

    #[test]
    fn accept_binds_the_exact_manifest_revision_and_destination() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (pending, _) = store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        assert_eq!(pending.state, RequestState::Pending);
        let (accepted, event) = store
            .accept(
                pending.id,
                pending.rev,
                "/inbox/a.txt",
                &external(),
                11,
            )
            .unwrap();
        assert_eq!(accepted.state, RequestState::Approved);
        assert_eq!(accepted.destination.as_deref(), Some("/inbox/a.txt"));
        assert_eq!(accepted.manifest.digest, manifest.digest);
        assert_eq!(event.unwrap().status, "approved");
        let serialized = serde_json::to_string(&accepted).unwrap();
        assert!(!serialized.contains("grant"), "{serialized}");
        assert!(!serialized.contains("\"caps\""), "{serialized}");
    }

    #[test]
    fn stale_revision_and_changed_identity_are_refused() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (pending, _) = store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        assert!(matches!(
            store.accept(pending.id, pending.rev + 1, "/inbox", &external(), 11),
            Err(RequestError::RevisionConflict { .. })
        ));
        let other = sender("dev-other", "user-ext", SenderRelation::PairedExternal);
        assert!(matches!(
            store.accept(pending.id, pending.rev, "/inbox", &other, 11),
            Err(RequestError::SenderRefused(_))
        ));
    }

    #[test]
    fn restart_preserves_pending_and_approved_state_without_a_grant() {
        let dir = temp_dir();
        let manifest = manifest("a.txt", 1);
        let id;
        {
            let store = store(&dir);
            let (pending, _) = store
                .propose("ext-offer", &external(), &manifest, 60, None, 10)
                .unwrap();
            id = pending.id;
            store
                .accept(pending.id, pending.rev, "/inbox", &external(), 11)
                .unwrap();
        }
        let reopened = RequestStore::open(dir.0.as_path(), "user-owner", Limits::default()).unwrap();
        let snapshot = reopened.snapshot(None).unwrap();
        assert_eq!(snapshot.requests.len(), 1);
        let record = &snapshot.requests[0];
        assert_eq!(record.id, id);
        assert_eq!(record.state, RequestState::Approved);
        assert_eq!(record.manifest.digest, manifest.digest);
        assert!(record.destination.is_some());
    }

    #[test]
    fn decline_is_idempotent_and_replay_after_prune_fails_closed() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (pending, _) = store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        let (denied, event) = store.decline(pending.id, pending.rev, 11).unwrap();
        assert_eq!(denied.state, RequestState::Denied);
        assert!(event.is_some());
        let (again, event) = store.decline(pending.id, denied.rev, 12).unwrap();
        assert_eq!(again.state, RequestState::Denied);
        assert!(event.is_none());

        // A pruned terminal record leaves a tombstone: the same offer id must
        // still not resurrect.
        let dir = temp_dir();
        let limits = Limits {
            max_terminal: 1,
            ..Limits::default()
        };
        let store = RequestStore::open(dir.0.as_path(), "user-owner", limits).unwrap();
        let (first, _) = store
            .propose("offer-a", &external(), &manifest, 60, None, 10)
            .unwrap();
        store.decline(first.id, first.rev, 11).unwrap();
        let (second, _) = store
            .propose("offer-b", &external(), &manifest, 60, None, 12)
            .unwrap();
        store.decline(second.id, second.rev, 13).unwrap();
        assert_eq!(store.snapshot(None).unwrap().requests.len(), 1);
        assert!(matches!(
            store.propose("offer-a", &external(), &manifest, 60, None, 14),
            Err(RequestError::OfferIdReused(_))
        ));
    }

    #[test]
    fn exact_delivery_requires_fresh_authority_and_leaves_a_receipt() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (pending, _) = store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        let (approved, _) = store
            .accept(pending.id, pending.rev, "/inbox", &external(), 11)
            .unwrap();
        let revoked = SenderIdentity {
            revoked: true,
            ..external()
        };
        assert!(matches!(
            store.begin_delivery(approved.id, approved.rev, &revoked, 12),
            Err(RequestError::SenderRefused(_))
        ));
        let (delivering, _) = store
            .begin_delivery(approved.id, approved.rev, &external(), 12)
            .unwrap();
        assert_eq!(delivering.state, RequestState::Delivering);
        let (done, event) = store
            .complete(delivering.id, delivering.rev, &external(), 13)
            .unwrap();
        assert_eq!(done.state, RequestState::Fulfilled);
        assert_eq!(event.unwrap().status, "fulfilled");
    }

    #[test]
    fn expiry_is_durable_and_snapshot_cursors_report_resync_after_prune() {
        let dir = temp_dir();
        let limits = Limits {
            max_terminal: 1,
            ..Limits::default()
        };
        let store = RequestStore::open(dir.0.as_path(), "user-owner", limits).unwrap();
        let manifest = manifest("a.txt", 1);
        store
            .propose("offer-a", &external(), &manifest, 5, None, 10)
            .unwrap();
        store
            .propose("offer-b", &external(), &manifest, 5, None, 10)
            .unwrap();
        let events = store.expire(16).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].status, "expired");
        let snapshot = store.snapshot(Some(0)).unwrap();
        assert_eq!(snapshot.requests.len(), 1);
        assert!(snapshot.resync_required);
        assert!(!store.snapshot(Some(snapshot.rev)).unwrap().resync_required);
        let reopened = RequestStore::open(dir.0.as_path(), "user-owner", Limits::default()).unwrap();
        assert_eq!(reopened.snapshot(None).unwrap().rev, snapshot.rev);
    }

    #[test]
    fn zero_retention_caps_are_rejected_at_open() {
        let dir = temp_dir();
        for limits in [
            Limits {
                max_terminal: 0,
                ..Limits::default()
            },
            Limits {
                max_tombstones: 0,
                ..Limits::default()
            },
        ] {
            assert!(RequestStore::open(dir.0.as_path(), "user-owner", limits).is_err());
        }
    }

    #[test]
    fn idempotent_fast_paths_still_require_fresh_authority() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (approved, _) = store
            .propose("owner-offer", &owner(), &manifest, 60, Some("/inbox"), 10)
            .unwrap();
        let revoked = SenderIdentity {
            revoked: true,
            ..owner()
        };
        assert!(matches!(
            store.accept(approved.id, approved.rev, "/inbox", &revoked, 11),
            Err(RequestError::SenderRefused(_))
        ));

        let (pending, _) = store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        let (accepted, _) = store
            .accept(pending.id, pending.rev, "/inbox", &external(), 11)
            .unwrap();
        let (delivering, _) = store
            .begin_delivery(accepted.id, accepted.rev, &external(), 12)
            .unwrap();
        let revoked_ext = SenderIdentity {
            revoked: true,
            ..external()
        };
        assert!(matches!(
            store.begin_delivery(delivering.id, delivering.rev, &revoked_ext, 13),
            Err(RequestError::SenderRefused(_))
        ));
        let (done, _) = store
            .complete(delivering.id, delivering.rev, &external(), 14)
            .unwrap();
        assert!(matches!(
            store.complete(done.id, done.rev, &revoked_ext, 15),
            Err(RequestError::SenderRefused(_))
        ));
    }

    #[test]
    fn a_rebound_or_changed_identity_cannot_reuse_the_offer_id() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        store
            .propose("ext-offer", &external(), &manifest, 60, None, 10)
            .unwrap();
        let rebound = sender("dev-ext", "user-other", SenderRelation::PairedExternal);
        assert!(matches!(
            store.propose("ext-offer", &rebound, &manifest, 60, None, 11),
            Err(RequestError::OfferIdReused(_))
        ));
        let same_owner = sender("dev-ext", "user-owner", SenderRelation::SameOwner);
        assert!(matches!(
            store.propose("ext-offer", &same_owner, &manifest, 60, None, 12),
            Err(RequestError::OfferIdReused(_))
        ));
    }

    #[test]
    fn windows_reserved_names_and_forbidden_characters_are_refused_paths() {
        let limits = Limits::default();
        for bad in ["CON", "con.txt", "a/NUL", "a.", "a ", "a<b", "a?b", "a|b"] {
            assert!(
                canonical_manifest(&[entry(bad, 1, 'a')], &limits).is_err(),
                "{bad}"
            );
        }
        assert!(canonical_manifest(&[entry("normal/name.txt", 1, 'a')], &limits).is_ok());
    }

    #[test]
    fn fail_and_withdraw_are_terminal_and_bounded() {
        let dir = temp_dir();
        let store = store(&dir);
        let manifest = manifest("a.txt", 1);
        let (pending, _) = store
            .propose("withdraw-me", &external(), &manifest, 60, None, 10)
            .unwrap();
        let (withdrawn, event) = store.withdraw(pending.id, pending.rev, 11).unwrap();
        assert_eq!(withdrawn.state, RequestState::Withdrawn);
        assert_eq!(event.unwrap().status, "withdrawn");

        let (pending, _) = store
            .propose("fail-me", &external(), &manifest, 60, None, 12)
            .unwrap();
        let (accepted, _) = store
            .accept(pending.id, pending.rev, "/inbox", &external(), 13)
            .unwrap();
        let (delivering, _) = store
            .begin_delivery(accepted.id, accepted.rev, &external(), 14)
            .unwrap();
        let (failed, event) = store.fail(delivering.id, delivering.rev, 15).unwrap();
        assert_eq!(failed.state, RequestState::Failed);
        assert_eq!(event.unwrap().status, "failed");
    }

    #[test]
    fn aggregate_queue_bytes_are_bounded() {
        let dir = temp_dir();
        let limits = Limits {
            max_queue_bytes: 1,
            ..Limits::default()
        };
        let store = RequestStore::open(dir.0.as_path(), "user-owner", limits).unwrap();
        let manifest = manifest("a.txt", 1);
        assert!(matches!(
            store.propose("too-big", &external(), &manifest, 60, None, 10),
            Err(RequestError::LimitExceeded(_))
        ));
    }
}
