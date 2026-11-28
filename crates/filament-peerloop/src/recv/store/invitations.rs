//! Invitation arming, durable replay/withdrawal tracking, and ledger queries.

use super::{create_private_dir_all, keep_backup, DeviceStore, StoreLock};
use anyhow::{Context, Result};
use filament_cap::capability::now_secs as cap_now_secs;
use filament_cap::ephemeral::Reuse;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};

/// Durable invitation-use file, kept apart from device records.
pub const USED_INVITATIONS_FILE: &str = "used-invitations.json";
/// The cross-process lock sidecar used for the invitation-use read/modify/write.
/// It is derived from the data file's own path (append `.lock`), so every
/// caller of [`record_invitation_use_at`] for one file locks the same sidecar.
pub const USED_INVITATIONS_LOCK_FILE: &str = "used-invitations.json.lock";

/// Why an invitation use was refused. The wire reason is what the joiner sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationRefusal {
    AlreadyUsed,
    UseLimitReached,
    Unverifiable,
    /// The owner withdrew the invitation (`tunlion add --withdraw`). Durable:
    /// it lives in the same locked file as the use count.
    Withdrawn,
}

/// The wire reason for a withdrawn invitation. A 0.9.1 joiner prints any
/// reason it does not know as `enrollment denied: <reason>`, so this is a
/// whole sentence that reads correctly there too.
pub const WITHDRAWN_WIRE_REASON: &str = "the owner withdrew this invitation";


impl InvitationRefusal {
    pub fn wire_reason(self) -> &'static str {
        match self {
            InvitationRefusal::AlreadyUsed => "already used",
            InvitationRefusal::UseLimitReached => "use limit reached",
            InvitationRefusal::Unverifiable => "enrollment denied",
            InvitationRefusal::Withdrawn => WITHDRAWN_WIRE_REASON,
        }
    }
}

/// One invitation's line in the durable use file, as the owner's listing
/// needs it: how many claims were admitted and whether it was withdrawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationLedgerEntry {
    pub key_id: String,
    pub uses: u64,
    pub expires: u64,
    pub withdrawn: bool,
}

/// The armed-invitation record. `key_id` is the enrollment PUBLIC key (hex),
/// never its private half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArmedInvitation {
    pub key_id: String,
    pub expires: u64,
    pub name: Option<String>,
    pub kind: Option<String>,
    pub allow: Option<Vec<String>>,
    /// The mint's reuse shape as JSON (`"once"`, a number, `"forever"`).
    /// Presentation only: admission reads the signed invitation and the
    /// durable use count, never this field.
    pub reuse: Option<Value>,
    pub created: Option<u64>,
}

impl ArmedInvitation {
    /// The short id the owner can name it by: the first 12 hex digits of the
    /// public key, unique in practice and never secret.
    pub fn id(&self) -> &str {
        &self.key_id[..self.key_id.len().min(12)]
    }

    /// The name shown and matched, `(unnamed)` when the mint gave none.
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| format!("({})", self.id()))
    }
}


/// May this use be admitted, given `uses` already recorded? Pure.
pub fn admit_invitation_use(
    uses: u64,
    reuse: &Reuse,
) -> std::result::Result<(), InvitationRefusal> {
    match reuse {
        Reuse::Once if uses >= 1 => Err(InvitationRefusal::AlreadyUsed),
        Reuse::N(max) if uses >= u64::from(*max) => Err(InvitationRefusal::UseLimitReached),
        _ => Ok(()),
    }
}

/// The lock sidecar for a use file: the data file's name with `.lock` appended.
/// It lives beside the data file, so the lock is per root and every caller that
/// names the same data file names the same lock.
pub(super) fn invitation_use_lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    path.with_file_name(name)
}

/// Parse the durable use list, refusing anything that is not the exact shape
/// this store writes. A malformed entry must not be read as `uses: 0` (which
/// would reset a consumed invitation), so the whole file is `Unverifiable`
/// rather than silently rewritten. Extra fields are kept: the legacy format is
/// the object keys `keyId`, `uses` and `expires`, and unknown keys do not make
/// an otherwise valid count ambiguous.
fn parse_invitation_uses(raw: &str) -> std::result::Result<Vec<Value>, InvitationRefusal> {
    let entries: Vec<Value> =
        serde_json::from_str(raw).map_err(|_| InvitationRefusal::Unverifiable)?;
    {
        let mut key_ids = HashSet::with_capacity(entries.len());
        for entry in &entries {
            let object = entry.as_object().ok_or(InvitationRefusal::Unverifiable)?;
            let key_id = object
                .get("keyId")
                .and_then(Value::as_str)
                .ok_or(InvitationRefusal::Unverifiable)?;
            object
                .get("uses")
                .and_then(Value::as_u64)
                .ok_or(InvitationRefusal::Unverifiable)?;
            object
                .get("expires")
                .and_then(Value::as_u64)
                .ok_or(InvitationRefusal::Unverifiable)?;
            // `withdrawn` is optional (older files never wrote it), but when it
            // is present it must be a boolean: a value this store cannot read
            // must not be taken as "not withdrawn".
            if object.get("withdrawn").is_some_and(|w| !w.is_boolean()) {
                return Err(InvitationRefusal::Unverifiable);
            }
            if !key_ids.insert(key_id) {
                // Two counts for one invitation are ambiguous. Refusing is safer
                // than picking one and overwriting the other (which could reset a
                // consumed count).
                return Err(InvitationRefusal::Unverifiable);
            }
        }
    }
    Ok(entries)
}

/// Count one use of `key_id` at an explicit path. The use is written BEFORE the
/// caller admits anything, so a crash can lose a use but never grant an extra
/// one. A file that exists but cannot be parsed (or contains an entry whose
/// `uses`/`keyId`/`expires` is missing or is the wrong type) is `Unverifiable`
/// (fail closed), and such a file is never overwritten.
///
/// The ENTIRE read/admit/write runs under an exclusive sidecar lock beside
/// `path`. The in-memory burn is per process, so without this lock two
/// `DeviceStore` instances over one root could both read `uses: 0` and both
/// write `uses: 1`, admitting a one-use invitation twice. A lock that cannot be
/// taken is `Unverifiable`: "I could not check whether this was used" is not
/// "it was not used".
pub fn record_invitation_use_at(
    path: &Path,
    key_id: &str,
    reuse: &Reuse,
    expires: u64,
    now: u64,
) -> std::result::Result<(), InvitationRefusal> {
    if let Some(dir) = path.parent() {
        create_private_dir_all(dir).map_err(|_| InvitationRefusal::Unverifiable)?;
    }
    // Bind the guard before the read: it is released only after the atomic
    // write below, so the whole read-modify-write is one critical section.
    let _lock = StoreLock::acquire(&invitation_use_lock_path(path))
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    let mut entries = match std::fs::read_to_string(path) {
        Ok(raw) => parse_invitation_uses(&raw)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(InvitationRefusal::Unverifiable),
    };
    entries.retain(|e| e["expires"].as_u64().map_or(true, |x| x > now));
    let existing = entries.iter().find(|e| e["keyId"].as_str() == Some(key_id));
    // A withdrawn invitation is refused before its count is even consulted:
    // `--reuse forever` has no count to run out, and a bounded one may have
    // uses left. Withdrawal is the owner's word that none of them remain.
    if existing.is_some_and(|e| e["withdrawn"].as_bool() == Some(true)) {
        return Err(InvitationRefusal::Withdrawn);
    }
    let uses = existing.and_then(|e| e["uses"].as_u64()).unwrap_or(0);
    admit_invitation_use(uses, reuse)?;
    let next = uses.checked_add(1).ok_or(InvitationRefusal::Unverifiable)?;
    entries.retain(|e| e["keyId"].as_str() != Some(key_id));
    entries.push(json!({
        "keyId": key_id,
        "uses": next,
        "expires": expires,
        "lastUsed": now,
    }));
    let body =
        serde_json::to_string_pretty(&entries).map_err(|_| InvitationRefusal::Unverifiable)?;
    keep_backup(path);
    secret_write::SecretFile::write_str(path, &body)
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    Ok(())
}

fn read_invitation_uses(path: &Path) -> std::result::Result<Vec<Value>, InvitationRefusal> {
    match std::fs::read_to_string(path) {
        Ok(raw) => parse_invitation_uses(&raw),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(InvitationRefusal::Unverifiable),
    }
}

/// Withdraw `key_id` at an explicit path: from now on every claim of it is
/// refused with [`InvitationRefusal::Withdrawn`], by any process over this
/// root, across restarts, until the invitation's own expiry (after which it
/// cannot verify at all, so the line is pruned like a use count).
///
/// Runs under the same sidecar lock as [`record_invitation_use_at`], so a
/// claim and a withdrawal are ordered: a claim either counted before the
/// withdrawal (and the enrolment path re-checks before it admits anything), or
/// it reads the withdrawal and is refused. The use count already recorded is
/// kept, and `expires` is never shortened. An unreadable file is
/// `Unverifiable` and is left untouched, so the caller can say the withdrawal
/// did NOT happen rather than overwrite a count.
pub fn withdraw_invitation_at(
    path: &Path,
    key_id: &str,
    expires: u64,
    now: u64,
) -> std::result::Result<(), InvitationRefusal> {
    if let Some(dir) = path.parent() {
        create_private_dir_all(dir).map_err(|_| InvitationRefusal::Unverifiable)?;
    }
    let _lock = StoreLock::acquire(&invitation_use_lock_path(path))
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    let mut entries = read_invitation_uses(path)?;
    entries.retain(|e| e["expires"].as_u64().map_or(true, |x| x > now));
    let (uses, kept_expires) = entries
        .iter()
        .find(|e| e["keyId"].as_str() == Some(key_id))
        .map(|e| (e["uses"].as_u64().unwrap_or(0), e["expires"].as_u64().unwrap_or(0)))
        .unwrap_or((0, 0));
    entries.retain(|e| e["keyId"].as_str() != Some(key_id));
    entries.push(json!({
        "keyId": key_id,
        "uses": uses,
        "expires": expires.max(kept_expires),
        "withdrawn": true,
        "withdrawnAt": now,
    }));
    let body =
        serde_json::to_string_pretty(&entries).map_err(|_| InvitationRefusal::Unverifiable)?;
    keep_backup(path);
    secret_write::SecretFile::write_str(path, &body)
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    Ok(())
}

/// Is `key_id` withdrawn at an explicit path? Read under the same lock as the
/// writers, so the answer is ordered against a withdrawal in progress.
pub fn invitation_withdrawn_at(
    path: &Path,
    key_id: &str,
    now: u64,
) -> std::result::Result<bool, InvitationRefusal> {
    let _lock = match StoreLock::acquire(&invitation_use_lock_path(path)) {
        Ok(lock) => lock,
        // No directory yet means no file: nothing was ever withdrawn here.
        Err(_) if !path.exists() && path.parent().is_some_and(|d| !d.exists()) => {
            return Ok(false)
        }
        Err(_) => return Err(InvitationRefusal::Unverifiable),
    };
    let entries = read_invitation_uses(path)?;
    Ok(entries.iter().any(|e| {
        e["keyId"].as_str() == Some(key_id)
            && e["expires"].as_u64().is_some_and(|x| x > now)
            && e["withdrawn"].as_bool() == Some(true)
    }))
}

/// Every unexpired line of the use file at an explicit path. Read-only.
pub fn invitation_ledger_at(
    path: &Path,
    now: u64,
) -> std::result::Result<Vec<InvitationLedgerEntry>, InvitationRefusal> {
    Ok(read_invitation_uses(path)?
        .iter()
        .filter_map(|e| {
            let expires = e["expires"].as_u64()?;
            (expires > now).then(|| InvitationLedgerEntry {
                key_id: e["keyId"].as_str().unwrap_or_default().to_string(),
                uses: e["uses"].as_u64().unwrap_or(0),
                expires,
                withdrawn: e["withdrawn"].as_bool() == Some(true),
            })
        })
        .collect())
}


impl DeviceStore {
    pub fn armed_path(&self) -> PathBuf {
        self.root.join("armed.json")
    }

    fn armed_lock_path(&self) -> PathBuf {
        self.root.join("armed.json.lock")
    }

    /// Record an outstanding invitation in `armed.json`. The whole
    /// read/modify/write runs under `armed.json.lock`, so two mints (or a
    /// mint and the daemon's pruning pass) cannot lose each other's entry.
    /// Dedupes by key id and drops entries whose expiry has passed.
    pub fn arm_invitation(&self, entry: ArmedInvitation, now: u64) -> Result<()> {
        create_private_dir_all(&self.root)
            .with_context(|| format!("create config dir {}", self.root.display()))?;
        let _lock = StoreLock::acquire(&self.armed_lock_path())
            .with_context(|| format!("lock {}", self.armed_lock_path().display()))?;
        let mut entries = self.read_armed_strict()?;
        entries.retain(|e| e.expires > now && e.key_id != entry.key_id);
        entries.push(entry);
        self.write_armed(&entries)
    }

    /// Every unexpired armed invitation, oldest first. Expired entries are
    /// pruned under the lock, so the file self-cleans and a stale entry never
    /// keeps the enrollment room open. A corrupt file is reported rather than
    /// silently replaced: an owner must be able to see that arming failed.
    pub fn armed_invitations(&self, now: u64) -> Result<Vec<ArmedInvitation>> {
        if !self.armed_path().exists() {
            return Ok(Vec::new());
        }
        create_private_dir_all(&self.root)
            .with_context(|| format!("create config dir {}", self.root.display()))?;
        let _lock = StoreLock::acquire(&self.armed_lock_path())
            .with_context(|| format!("lock {}", self.armed_lock_path().display()))?;
        let before = self.read_armed_strict()?;
        let mut entries: Vec<ArmedInvitation> =
            before.iter().filter(|e| e.expires > now).cloned().collect();
        if entries.len() != before.len() {
            self.write_armed(&entries)?;
        }
        entries.sort_by(|a, b| a.created.cmp(&b.created).then(a.expires.cmp(&b.expires)));
        Ok(entries)
    }

    /// Drop one key from the armed set now. Withdrawal deliberately does NOT
    /// call this: a withdrawn entry stays armed until expiry so a late claimer
    /// hears "withdrawn" instead of waiting on a silent room.
    pub fn disarm_invitation(&self, key_id: &str) -> Result<()> {
        if !self.armed_path().exists() {
            return Ok(());
        }
        let _lock = StoreLock::acquire(&self.armed_lock_path())
            .with_context(|| format!("lock {}", self.armed_lock_path().display()))?;
        let mut entries = self.read_armed_strict()?;
        entries.retain(|e| e.key_id != key_id);
        self.write_armed(&entries)
    }

    fn read_armed_strict(&self) -> Result<Vec<ArmedInvitation>> {
        let raw = match std::fs::read_to_string(self.armed_path()) {
            Ok(raw) => raw,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(anyhow::anyhow!("read armed.json: {e}")),
        };
        let value: Value = serde_json::from_str(&raw)
            .map_err(|e| anyhow::anyhow!("armed.json is corrupt: {e}"))?;
        let arr = value
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("armed.json is not a JSON array"))?;
        let mut out = Vec::with_capacity(arr.len());
        for e in arr {
            let key_id = e["key_id"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("armed.json entry has no key_id"))?
                .to_string();
            let expires = e["expires"]
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("armed.json entry has no expiry"))?;
            out.push(ArmedInvitation {
                key_id,
                expires,
                name: e["name"].as_str().map(str::to_string),
                kind: e["kind"].as_str().map(str::to_string),
                allow: e["allow"].as_array().map(|a| {
                    a.iter().filter_map(|c| c.as_str().map(str::to_string)).collect()
                }),
                reuse: e.get("reuse").cloned().filter(|v| !v.is_null()),
                created: e["created"].as_u64(),
            });
        }
        Ok(out)
    }

    fn write_armed(&self, entries: &[ArmedInvitation]) -> Result<()> {
        let arr: Vec<Value> = entries
            .iter()
            .map(|e| {
                let mut v = json!({ "key_id": e.key_id, "expires": e.expires });
                if let Some(n) = &e.name {
                    v["name"] = json!(n);
                }
                if let Some(k) = &e.kind {
                    v["kind"] = json!(k);
                }
                if let Some(a) = &e.allow {
                    v["allow"] = json!(a);
                }
                if let Some(r) = &e.reuse {
                    v["reuse"] = r.clone();
                }
                if let Some(c) = e.created {
                    v["created"] = json!(c);
                }
                v
            })
            .collect();
        let body = serde_json::to_string_pretty(&arr)?;
        secret_write::SecretFile::write_str(&self.armed_path(), &body)
            .context("atomic write armed.json")
    }

    /// Any unexpired armed invitation? Prunes expired entries under the lock,
    /// so a stale entry never keeps the enrollment room open.
    pub fn is_armed(&self) -> bool {
        self.armed_invitations(cap_now_secs())
            .map(|entries| !entries.is_empty())
            .unwrap_or(false)
    }

    /// The `invitee_name` field recorded for an outstanding invitation, while
    /// it is unexpired. Read under the same lock as the writers.
    pub fn invitee_name(&self, key_id: &str) -> Option<String> {
        self.armed_invitations(cap_now_secs())
            .ok()?
            .into_iter()
            .find(|e| e.key_id == key_id)
            .and_then(|e| e.name)
            .filter(|n| !n.trim().is_empty())
    }

    /// The `invitee_kind` (`person`/`device`) recorded for an outstanding
    /// invitation, while it is unexpired.
    pub fn invitee_kind(&self, key_id: &str) -> Option<String> {
        self.armed_invitations(cap_now_secs())
            .ok()?
            .into_iter()
            .find(|e| e.key_id == key_id)
            .and_then(|e| e.kind)
    }

    /// Durable invitation-use count, keyed by the enrolment public key. This is
    /// the cross-restart replay guard; the in-memory burn is only the live
    /// engine's fast path. The whole read/modify/write is serialized across
    /// processes by the per-root sidecar lock, so two stores over the same root
    /// cannot both admit the same one-use invitation.
    pub fn record_invitation_use(
        &self,
        key_id: &str,
        reuse: &Reuse,
        expires: u64,
        now: u64,
    ) -> std::result::Result<(), InvitationRefusal> {
        record_invitation_use_at(
            &self.root.join(USED_INVITATIONS_FILE),
            key_id,
            reuse,
            expires,
            now,
        )
    }

    /// Withdraw an outstanding invitation so it can never be claimed again.
    /// See [`withdraw_invitation_at`].
    pub fn withdraw_invitation(
        &self,
        key_id: &str,
        expires: u64,
        now: u64,
    ) -> std::result::Result<(), InvitationRefusal> {
        withdraw_invitation_at(&self.root.join(USED_INVITATIONS_FILE), key_id, expires, now)
    }

    /// Is this invitation withdrawn? `Err` when the file cannot be read: the
    /// caller decides how to fail (the enrolment path refuses).
    pub fn invitation_withdrawn(
        &self,
        key_id: &str,
        now: u64,
    ) -> std::result::Result<bool, InvitationRefusal> {
        invitation_withdrawn_at(&self.root.join(USED_INVITATIONS_FILE), key_id, now)
    }

    /// Every unexpired line of the durable use file, for the owner's listing.
    /// An unreadable file lists nothing (the listing is advisory; admission
    /// fails closed on its own).
    pub fn invitation_ledger(&self, now: u64) -> Vec<InvitationLedgerEntry> {
        invitation_ledger_at(&self.root.join(USED_INVITATIONS_FILE), now).unwrap_or_default()
    }

}
