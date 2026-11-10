//! The shared device-removal service: one ordering for forget, cut off and
//! restore.
//!
//! Before this module the ordering lived only in the CLI (`devices forget`,
//! `demote --to cut`). A second client that re-implemented "remove the record"
//! could drop the record before writing the key block, or drop it without
//! revoking the grants that are keyed by the device key, and no test in one
//! caller could see the other. This service is the one place the ordering is
//! written down:
//!
//! * **key is identity, name is presentation.** The block written by a forget
//!   and the grants revoked by it name the certificate's device key. A name is
//!   used only to find the record and (for a restore of an already-forgotten
//!   device) as the documented fallback. Every write re-checks that the record
//!   under the name still holds the planned key before touching it, so a reused
//!   petname cannot be used to remove a different device.
//! * **revocation first.** Forget writes the `revoked-keys.json` block before
//!   it revokes grants, removes the SSH key hook or removes the record. If the
//!   process stops halfway, the refusal is already durable and the remaining
//!   state is still there to retry.
//! * **fail closed.** A missing store is empty, but an existing store that
//!   cannot be read or parsed is an error. Nothing is written over damage, and a
//!   refusal that cannot be recorded leaves the record in place.
//! * **idempotent.** Re-running the same plan leaves the same state: an absent
//!   record is already removed, an already-revoked `certRevoked` is still
//!   revoked, and an already-lifted key block is still lifted.
//! * **local only.** The receipt is about this machine's stores. Nothing here
//!   contacts the peer, deletes anything on it, or claims a live session ended.
//!
//! Cut off is deliberately not a forget: it writes `certRevoked` on the kept
//! record and leaves grants alone, because a device revoked in place must still
//! be told *why* on its next open. Restore lifts the key block and the
//! `certRevoked` marker; it does not restore a record that a forget removed.
//!
//! The host-specific SSH key hook is injected by the caller: this crate does not
//! know where a client keeps its `authorized_keys`. A client that has no such
//! hook passes a no-op closure, which is honest: this service then claims only
//! the stores it wrote.

use crate::recv::store::{keep_backup, record_is_revoked, DeviceStore, PRINCIPAL_STATE_REVOKED};
use anyhow::{bail, Context, Result};
use filament_cap::capability::{
    apply_cap_op, hlc_next, latest_op_version, now_ms, sign_cap_op, CapHeader, CapOp, CapOpKind,
    CapTarget,
};
use filament_id::{DeviceCert, UserKey};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

pub use crate::recv::store::KEY_REVOCATIONS_FILE;

/// What a removal request does to the local stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalMode {
    /// Drop the record and keep the device's key refused until its certificate
    /// could no longer pass anyway. Revokes grants and the managed SSH key too.
    Forget,
    /// Revoke the certificate in place: keep the record, its grants and the
    /// managed SSH key. Live links stay up to carry the refusal.
    CutOff,
    /// Lift the local refusal: clear `certRevoked` and the key block.
    Restore,
}

impl RemovalMode {
    /// The stable token for a receipt or a client switch. Display text is the
    /// caller's, never the policy's.
    pub fn as_str(self) -> &'static str {
        match self {
            RemovalMode::Forget => "forget",
            RemovalMode::CutOff => "cut-off",
            RemovalMode::Restore => "restore",
        }
    }
}

/// What this call did, and did not do, about live sessions.
///
/// This is a typed summary so a client cannot turn "the next liveness re-check
/// will cut it" into "the service terminated the session". This service does not
/// own session lifetimes; the daemon's live re-check does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionsSummary {
    /// Nothing was examined or changed. Restore never ends a session.
    NotTouched,
    /// Future opens and the daemon's next liveness re-check will refuse the
    /// device. No session was terminated by this call.
    EndsOnRecheck,
}

impl SessionsSummary {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionsSummary::NotTouched => "not-touched",
            SessionsSummary::EndsOnRecheck => "ends-on-recheck",
        }
    }
}

/// The pure result of deciding what a removal would do. The store writer runs
/// exactly this plan; no caller re-derives which steps to take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalPlan {
    pub mode: RemovalMode,
    /// Presentation only. The applier refuses a Forget/CutOff plan without one.
    pub name: String,
    /// The identity the plan is keyed by: the certificate's device key.
    pub device_key: Option<[u8; 32]>,
    /// The certifying user key, written into the key block for readers.
    pub user_key: Option<[u8; 32]>,
    /// The instant the key refusal lasts to. `Some` only for a Forget of a
    /// live certificate from this device's owner.
    pub refused_until: Option<u64>,
    /// Forget: write/refresh the block in `revoked-keys.json`.
    pub write_key_block: bool,
    /// Forget: revoke the owner-signed grants that name `device_key`.
    pub revoke_grants: bool,
    /// Forget: remove the device record LAST.
    pub remove_record: bool,
    /// CutOff: `Some(true)` writes the `certRevoked` marker. Restore:
    /// `Some(false)` clears it. Forget leaves the record for removal and
    /// therefore has no marker to write.
    pub set_cert_revoked: Option<bool>,
    /// Restore: lift the key block.
    pub lift_key_block: bool,
    /// Restore without a record or certificate: match the block by name. This
    /// is the one legacy name-only path, used only when no identity exists.
    pub lift_by_name: bool,
    /// The record was already revoked when the plan was made. Presentation
    /// only (the forget line says the same thing either way).
    pub already_revoked: bool,
    /// The clock the plan was made at. The key block stamps this as `revokedAt`.
    pub now: u64,
}

impl RemovalPlan {
    /// Whole days between `now` and `refused_until`, the part a person acts on.
    /// `None` when the plan keeps no key block.
    pub fn refused_days(&self) -> Option<u64> {
        self.refused_until.map(|until| days_until(until, self.now))
    }
}

/// One key block a Restore lifted, in the shape the CLI's report and re-add
/// notice already print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiftedKeyBlock {
    pub name: String,
    pub revoked_at: u64,
    /// Hex, because the block is a file format and this value is carried
    /// through to a reader, not matched against.
    pub device_key: String,
}

/// The facts a caller may print or branch on after the store is written.
///
/// `local_only` is always `true` and is deliberately a field, not an inference:
/// this receipt says nothing about the peer's copy of the record, the peer's
/// grants, or a live session. See the module docs and
/// `docs/removal-service.md` for the full non-claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovalReceipt {
    pub mode: RemovalMode,
    pub name: String,
    pub device_key: Option<[u8; 32]>,
    /// The key block's horizon, when one was written. `None` for CutOff
    /// (indefinite until Restore), Restore, and a Forget with no live cert.
    pub refused_until: Option<u64>,
    /// How many resources had owner-signed grants revoked by this call.
    pub grants_revoked: usize,
    /// True only when this call removed the record. A retry that finds the
    /// record already gone is a successful idempotent no-op with `false`.
    pub record_removed: bool,
    pub sessions: SessionsSummary,
    /// Always true. This operation writes this machine's stores only.
    pub local_only: bool,
    /// True when this call wrote/refreshed the key block.
    pub key_block_written: bool,
    /// Key blocks lifted by a Restore, in file order.
    pub key_blocks_lifted: Vec<LiftedKeyBlock>,
}

/// The horizon a forget may refuse a key to: the certificate's expiry, but only
/// when the certificate is from the owner this device trusts and is still live.
/// A foreign or expired certificate cannot pass fleet-hello anyway, so it keeps
/// no block. Pure.
pub fn refusal_horizon(
    cert: Option<&DeviceCert>,
    owner: Option<[u8; 32]>,
    now: u64,
) -> Option<u64> {
    let (Some(cert), Some(owner)) = (cert, owner) else {
        return None;
    };
    if cert.user_pub != owner || cert.expires <= now {
        return None;
    }
    Some(cert.expires)
}

fn days_until(until: u64, now: u64) -> u64 {
    until.saturating_sub(now).div_ceil(86_400)
}

/// The whole days a forget would keep the key refused, in the same calculation
/// [`RemovalPlan::refused_days`] uses. Pure. `None` when there is no live
/// owner certificate to block.
pub fn refusal_days(
    cert: Option<&DeviceCert>,
    owner: Option<[u8; 32]>,
    now: u64,
) -> Option<u64> {
    refusal_horizon(cert, owner, now).map(|until| days_until(until, now))
}

/// Decide what removing `record` means. Pure: the same inputs always produce
/// the same plan, and no store is read or written.
///
/// `record` is the stored JSON (for its name and current revocation state),
/// `cert` is the certificate already parsed from that record, and `owner` is the
/// owner key this device trusts. The device key in `cert`, never the name,
/// decides which grants and key block the plan names.
pub fn plan_removal(
    record: &Value,
    cert: Option<&DeviceCert>,
    owner: Option<[u8; 32]>,
    mode: RemovalMode,
    now: u64,
) -> RemovalPlan {
    let name = record["name"].as_str().unwrap_or_default().to_string();
    let device_key = cert.map(|cert| cert.device_pub);
    let user_key = cert.map(|cert| cert.user_pub);
    let already_revoked = record_is_revoked(record);
    let refused_until = match mode {
        RemovalMode::Forget => refusal_horizon(cert, owner, now),
        RemovalMode::CutOff | RemovalMode::Restore => None,
    };
    match mode {
        RemovalMode::Forget => RemovalPlan {
            mode,
            name,
            device_key,
            user_key,
            refused_until,
            write_key_block: refused_until.is_some(),
            revoke_grants: device_key.is_some(),
            remove_record: true,
            set_cert_revoked: None,
            lift_key_block: false,
            lift_by_name: false,
            already_revoked,
            now,
        },
        RemovalMode::CutOff => RemovalPlan {
            mode,
            name,
            device_key,
            user_key,
            refused_until: None,
            write_key_block: false,
            revoke_grants: false,
            remove_record: false,
            set_cert_revoked: Some(true),
            lift_key_block: false,
            lift_by_name: false,
            already_revoked,
            now,
        },
        RemovalMode::Restore => RemovalPlan {
            mode,
            name,
            device_key,
            user_key,
            refused_until: None,
            write_key_block: false,
            revoke_grants: false,
            remove_record: false,
            set_cert_revoked: Some(false),
            lift_key_block: true,
            // With no certificate the block can only be found by the name it
            // was recorded under. This is the documented presentation fallback.
            lift_by_name: cert.is_none(),
            already_revoked,
            now,
        },
    }
}

/// The Restore plan for a name whose record is already gone. Used by
/// `promote <name>` after a forget: only the name is left, so the key block is
/// matched by its recorded name. No record is created or restored.
pub fn plan_restore_by_name(name: &str, now: u64) -> RemovalPlan {
    RemovalPlan {
        mode: RemovalMode::Restore,
        name: name.to_string(),
        device_key: None,
        user_key: None,
        refused_until: None,
        write_key_block: false,
        revoke_grants: false,
        remove_record: false,
        set_cert_revoked: None,
        lift_key_block: true,
        lift_by_name: true,
        already_revoked: false,
        now,
    }
}

/// The key block's path below a config root.
pub fn key_revocations_path(root: &Path) -> PathBuf {
    root.join(KEY_REVOCATIONS_FILE)
}

/// The key revocations at `path`. `Ok(empty)` when the file is absent; `Err`
/// when it exists but cannot be read or parsed, which callers treat as
/// "revoked" (a corrupt store must not silently un-revoke every key in it).
pub fn load_key_revocations_at(path: &Path) -> std::result::Result<Vec<Value>, ()> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(()),
        Ok(_) => {}
    }
    let raw = std::fs::read_to_string(path).map_err(|_| ())?;
    serde_json::from_str::<Vec<Value>>(&raw).map_err(|_| ())
}

/// Is `device_pub` named by a revocation that is still in force at `now`? An
/// entry ends when the certificate it revoked expires: past that point the
/// certificate cannot pass fleet-hello anyway. Pure.
pub fn key_revocation_in_force(entries: &[Value], device_pub: &[u8; 32], now: u64) -> bool {
    let key = hex::encode(device_pub);
    entries.iter().any(|entry| {
        entry["devicePub"].as_str() == Some(key.as_str())
            && entry["certExpires"]
                .as_u64()
                .map_or(true, |expires| expires > now)
    })
}

/// The key revocation in force for `device_pub` at `now`, as (the name it was
/// recorded under, when). Pure over `entries`.
pub fn key_revocation_for(
    entries: &[Value],
    device_pub: &[u8; 32],
    now: u64,
) -> Option<(String, u64)> {
    let key = hex::encode(device_pub);
    entries
        .iter()
        .find(|entry| {
            entry["devicePub"].as_str() == Some(key.as_str())
                && entry["certExpires"]
                    .as_u64()
                    .map_or(true, |expires| expires > now)
        })
        .map(|entry| {
            (
                entry["name"].as_str().unwrap_or("").to_string(),
                entry["revokedAt"].as_u64().unwrap_or(0),
            )
        })
}

fn push_key_block(
    entries: &mut Vec<Value>,
    device_key: [u8; 32],
    user_key: [u8; 32],
    cert_expires: u64,
    name: &str,
    now: u64,
) {
    let key = hex::encode(device_key);
    // Replace this key's entry and prune entries whose certificate has run out.
    entries.retain(|entry| {
        entry["devicePub"].as_str() != Some(key.as_str())
            && entry["certExpires"]
                .as_u64()
                .map_or(true, |expires| expires > now)
    });
    entries.push(json!({
        "devicePub": key,
        "userPub": hex::encode(user_key),
        "certExpires": cert_expires,
        "revokedAt": now,
        "name": name,
    }));
}

fn write_key_entries(path: &Path, entries: &[Value]) -> Result<()> {
    keep_backup(path);
    secret_write::SecretFile::write_str(path, &serde_json::to_string_pretty(entries)?)
        .with_context(|| format!("atomic write {}", path.display()))
}

/// Record `cert`'s key as revoked until the certificate expires, pruning
/// entries that have run out. `name` is kept for a reader only; nothing matches
/// on it.
///
/// THE ONLY MEANING OF AN ENTRY IS "FORGOTTEN" (see [`KEY_REVOCATIONS_FILE`]).
/// Do not call this for a revoke, a demote or an expiry: those keep their
/// record and carry their own reason, and reusing this list would make them
/// read "not recognized".
pub fn record_key_revocation_at(
    path: &Path,
    cert: &DeviceCert,
    name: &str,
    now: u64,
) -> Result<()> {
    let mut entries = load_key_revocations_at(path).map_err(|()| {
        anyhow::anyhow!(
            "{} exists but cannot be read; fix or remove it before forgetting a certified device",
            path.display()
        )
    })?;
    push_key_block(&mut entries, cert.device_pub, cert.user_pub, cert.expires, name, now);
    write_key_entries(path, &entries)
}

fn take_key_blocks(
    entries: &mut Vec<Value>,
    device_pub: Option<&[u8; 32]>,
    by_name: Option<&str>,
) -> Vec<LiftedKeyBlock> {
    let key = device_pub.map(hex::encode);
    let matches = |entry: &Value| {
        key.as_deref()
            .is_some_and(|key| entry["devicePub"].as_str() == Some(key))
            || by_name.is_some_and(|name| {
                entry["name"]
                    .as_str()
                    .is_some_and(|recorded| recorded.eq_ignore_ascii_case(name))
            })
    };
    let lifted: Vec<LiftedKeyBlock> = entries
        .iter()
        .filter(|entry| matches(entry))
        .map(|entry| LiftedKeyBlock {
            name: entry["name"].as_str().unwrap_or("").to_string(),
            revoked_at: entry["revokedAt"].as_u64().unwrap_or(0),
            device_key: entry["devicePub"].as_str().unwrap_or("").to_string(),
        })
        .collect();
    entries.retain(|entry| !matches(entry));
    lifted
}

/// Remove every entry for `device_pub` (or, with `by_name`, every entry
/// recorded under that name) from `path`. An explicit owner action is the only
/// caller: a fresh `add` of that device, or `promote <name>`.
pub fn lift_key_revocations_at(
    path: &Path,
    device_pub: Option<&[u8; 32]>,
    by_name: Option<&str>,
) -> Result<Vec<(String, u64, String)>> {
    let mut entries = load_key_revocations_at(path).map_err(|()| {
        anyhow::anyhow!("{} exists but cannot be read; fix or remove it first", path.display())
    })?;
    let lifted = take_key_blocks(&mut entries, device_pub, by_name);
    if !lifted.is_empty() {
        write_key_entries(path, &entries)?;
    }
    Ok(lifted
        .into_iter()
        .map(|entry| (entry.name, entry.revoked_at, entry.device_key))
        .collect())
}

/// Revoke every owner-signed grant that names `device_pub`, on every resource,
/// with a signed Revoke op per resource (`apply_cap_op` leaves a tombstone at
/// the new version, so the old grant op cannot be replayed back in). Returns
/// how many resources were revoked.
///
/// User-wide grants are deliberately not touched: they name the user key and
/// cover that user's other devices too. A grant is about a device KEY, not a
/// name, so a renamed record still loses the same grants.
fn revoke_device_grants_in(
    store: &mut Vec<Value>,
    user_key: &UserKey,
    device_pub: [u8; 32],
    now: u64,
) -> Result<usize> {
    let (target_kind, target) = (
        CapTarget::Device(device_pub).kind_byte(),
        CapTarget::Device(device_pub).target_bytes(),
    );
    let grantor = user_key.public_key_bytes();
    let (grantor_hex, target_hex) = (hex::encode(grantor), hex::encode(target));
    // resource -> every permission granted on it, so each tombstone names what
    // it took away.
    let mut resources: std::collections::BTreeMap<String, Vec<String>> = Default::default();
    for entry in store.iter().filter(|entry| {
        entry.get("type").and_then(|value| value.as_str()) == Some("cap_grant")
            && entry["grantor"].as_str() == Some(grantor_hex.as_str())
            && entry["targetKind"].as_u64().unwrap_or(0) == target_kind as u64
            && entry["target"].as_str() == Some(target_hex.as_str())
    }) {
        let Some(resource) = entry["resource"].as_str() else {
            continue;
        };
        let permissions = resources.entry(resource.to_string()).or_default();
        for permission in entry["permissions"].as_array().into_iter().flatten() {
            if let Some(permission) = permission.as_str() {
                if !permissions.iter().any(|seen| seen == permission) {
                    permissions.push(permission.to_string());
                }
            }
        }
    }
    let expires = now.saturating_add(90 * 24 * 3600);
    let mut revoked = 0;
    for (resource, permissions) in resources {
        let Some(header) = store
            .iter()
            .find(|entry| {
                entry.get("type").and_then(|value| value.as_str()) == Some("cap_header")
                    && entry["resource"].as_str() == Some(resource.as_str())
            })
            .and_then(CapHeader::from_json)
        else {
            continue;
        };
        let latest = latest_op_version(store, &grantor, &resource, target_kind, &target);
        let mut op = CapOp {
            op: CapOpKind::Revoke,
            grantor,
            target_kind,
            target,
            resource: resource.clone(),
            permissions,
            expires,
            issued_at: now,
            version: hlc_next(latest, now_ms()),
            sig: [0; 64],
        };
        op.sig = sign_cap_op(&op, user_key.keypair());
        apply_cap_op(store, &header, &op, now)?;
        revoked += 1;
    }
    Ok(revoked)
}

fn preflight(plan: &RemovalPlan, current: Option<&Value>) -> Result<()> {
    match plan.mode {
        RemovalMode::Forget => {
            // An absent record is an already-completed removal, not an error:
            // the block/grants below are idempotent and the record step will
            // simply report `record_removed = false`.
            if let Some(record) = current {
                check_planned_key(plan, record)?;
            }
        }
        RemovalMode::CutOff => {
            let Some(record) = current else {
                if plan.name.is_empty() {
                    bail!("no device record to remove");
                }
                bail!("device '{}' is not in the device store", plan.name);
            };
            check_planned_key(plan, record)?;
        }
        RemovalMode::Restore => {}
    }
    Ok(())
}

/// The record under the planned name must still hold the planned identity.
/// Key is identity, name is presentation: a record that now holds a different
/// key is a different device.
fn check_planned_key(plan: &RemovalPlan, record: &Value) -> Result<()> {
    if let Some(device_key) = plan.device_key {
        let current_key = DeviceCert::from_json(&record["deviceCert"]).map(|cert| cert.device_pub);
        if current_key != Some(device_key) {
            bail!(
                "device '{}' no longer holds the planned key; refusing to change it",
                plan.name
            );
        }
    } else if record.get("deviceCert").is_some_and(|cert| !cert.is_null()) {
        // A certified record with no planned key would skip the key
        // block/grants. Refuse rather than fail open on a half-built plan.
        bail!(
            "device '{}' has a certificate but the plan has no device key",
            plan.name
        );
    }
    Ok(())
}

fn remove_record_last(store: &DeviceStore, plan: &RemovalPlan) -> Result<bool> {
    store.with_devices_mut(|records| {
        let Some(index) = records
            .iter()
            .position(|record| record["name"].as_str() == Some(plan.name.as_str()))
        else {
            return Ok(false);
        };
        check_planned_key(plan, &records[index])?;
        records.remove(index);
        Ok(true)
    })
}

fn set_record_revocation(store: &DeviceStore, plan: &RemovalPlan, revoked: bool) -> Result<()> {
    store.with_devices_mut(|records| {
        let Some(record) = records
            .iter_mut()
            .find(|record| record["name"].as_str() == Some(plan.name.as_str()))
        else {
            // Restore is idempotent when the record is already gone. Cut off
            // preflights the record, so this arm is only a race.
            return Ok(());
        };
        check_planned_key(plan, record)?;
        record["certRevoked"] = json!(revoked);
        if revoked {
            record["revokedAt"] = json!(plan.now);
            record["principalState"] = json!(PRINCIPAL_STATE_REVOKED);
        } else {
            if let Some(record) = record.as_object_mut() {
                record.remove("revokedAt");
            }
            // Restore returns the device to its pre-revoke state: a lapsed
            // marker from the sweeper stays, the terminal revoke marker goes.
            if record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED) {
                record["principalState"] = Value::Null;
            }
        }
        Ok(())
    })
}

impl DeviceStore {
    /// Carry out a removal plan against this device store.
    ///
    /// The order is the invariant, not an implementation detail:
    ///
    /// 1. preflight every store the plan touches (damage is refused before any
    ///    write);
    /// 2. Forget: write the key block;
    /// 3. Forget: revoke the owner-signed grants naming the device key;
    /// 4. Forget: call the injected SSH-key hook;
    /// 5. the record step LAST (remove for Forget, mark/clear `certRevoked`
    ///    for CutOff/Restore).
    ///
    /// `owner_key` is the only signer that can revoke a grant; `None` means
    /// this device holds no owner key, so it holds no grant it could have
    /// signed and the count is zero. `remove_ssh_key` is host policy: the
    /// caller supplies the hook, and a client with no managed `authorized_keys`
    /// passes a no-op.
    pub fn apply_removal<F>(
        &self,
        plan: &RemovalPlan,
        owner_key: Option<&UserKey>,
        remove_ssh_key: F,
    ) -> Result<RemovalReceipt>
    where
        F: FnOnce(&str) -> Result<()>,
    {
        self.apply_removal_with(plan, owner_key, remove_ssh_key, remove_record_last)
    }

    /// [`apply_removal`] with the record-writing step injectable, so the
    /// crash-order test can fail the LAST write and prove the refusal is
    /// already durable. Production always passes [`remove_record_last`].
    fn apply_removal_with<F, W>(
        &self,
        plan: &RemovalPlan,
        owner_key: Option<&UserKey>,
        remove_ssh_key: F,
        mut record_writer: W,
    ) -> Result<RemovalReceipt>
    where
        F: FnOnce(&str) -> Result<()>,
        W: FnMut(&DeviceStore, &RemovalPlan) -> Result<bool>,
    {
        if plan.mode != RemovalMode::Restore && plan.name.is_empty() {
            bail!("no device record to remove");
        }

        // Preflight EVERY store this plan will touch before the first write.
        // A corrupt store is therefore refused with nothing half-applied; the
        // key-block-first ordering still governs a failure that happens after
        // preflight (a crash, an unwritable file, a racing writer).
        let records = self.devices_snapshot()?;
        let current = records
            .iter()
            .find(|record| record["name"].as_str() == Some(plan.name.as_str()));
        preflight(plan, current)?;
        if plan.write_key_block || plan.lift_key_block {
            self.key_revocation_entries()?;
        }
        if plan.revoke_grants {
            self.cap_store_checked()?;
        }

        let mut key_block_written = false;
        if plan.mode == RemovalMode::Forget && plan.write_key_block {
            let (Some(device_key), Some(user_key), Some(refused_until)) =
                (plan.device_key, plan.user_key, plan.refused_until)
            else {
                bail!("a forget plan with a key block needs a device key and an expiry");
            };
            self.with_key_revocations_mut(|entries| {
                push_key_block(
                    entries,
                    device_key,
                    user_key,
                    refused_until,
                    &plan.name,
                    plan.now,
                );
                Ok(((), true))
            })?;
            key_block_written = true;
        }

        let key_blocks_lifted = if plan.mode == RemovalMode::Restore && plan.lift_key_block {
            self.with_key_revocations_mut(|entries| {
                let lifted = take_key_blocks(
                    entries,
                    plan.device_key.as_ref(),
                    plan.lift_by_name.then_some(plan.name.as_str()),
                );
                let changed = !lifted.is_empty();
                Ok((lifted, changed))
            })?
        } else {
            Vec::new()
        };

        let mut grants_revoked = 0;
        if plan.mode == RemovalMode::Forget && plan.revoke_grants {
            if let (Some(device_key), Some(owner_key)) = (plan.device_key, owner_key) {
                grants_revoked = self.with_cap_store_mut(|store| {
                    let revoked = revoke_device_grants_in(store, owner_key, device_key, plan.now)?;
                    Ok((revoked, revoked > 0))
                })?;
            }
        }

        if plan.mode == RemovalMode::Forget {
            // The hook is host policy, but its POSITION is the service's: the
            // key that a managed shell key represents is already refused by
            // the block above, and the record is still present if this fails.
            remove_ssh_key(&plan.name)?;
        }

        let record_removed = match plan.mode {
            RemovalMode::Forget => record_writer(self, plan)?,
            RemovalMode::CutOff | RemovalMode::Restore => {
                if let Some(revoked) = plan.set_cert_revoked {
                    // Restore of an already-removed record is a successful
                    // no-op: there is no record to clear, only the key block
                    // the lift above may have removed.
                    if revoked || current.is_some() {
                        set_record_revocation(self, plan, revoked)?;
                    }
                }
                false
            }
        };

        Ok(RemovalReceipt {
            mode: plan.mode,
            name: plan.name.clone(),
            device_key: plan.device_key,
            refused_until: plan.refused_until,
            grants_revoked,
            record_removed,
            sessions: match plan.mode {
                RemovalMode::Restore => SessionsSummary::NotTouched,
                RemovalMode::Forget | RemovalMode::CutOff => SessionsSummary::EndsOnRecheck,
            },
            local_only: true,
            key_block_written,
            key_blocks_lifted,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::path::Path;

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new(tag: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("tunlion-removal-{tag}-{}-{nonce}", std::process::id()));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
        fn path(&self) -> &Path {
            &self.0
        }
        fn store(&self) -> DeviceStore {
            DeviceStore::open(self.path())
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn cert(device: u8, owner: [u8; 32], expires: u64) -> DeviceCert {
        DeviceCert {
            device_pub: [device; 32],
            user_pub: owner,
            expires,
            issued: 0,
            sig: [0; 64],
        }
    }

    fn record(name: &str, cert: &DeviceCert, revoked: bool) -> Value {
        let mut record = json!({
            "name": name,
            "secret": "s".repeat(64),
            "deviceCert": cert.to_json(),
            "caps": ["transfer"],
        });
        if revoked {
            record["certRevoked"] = json!(true);
        }
        record
    }

    fn write_devices(root: &Path, records: &[Value]) {
        std::fs::write(
            root.join("devices.json"),
            serde_json::to_string_pretty(&json!(records)).unwrap(),
        )
        .unwrap();
    }

    fn read_devices(root: &Path) -> Vec<Value> {
        serde_json::from_str(&std::fs::read_to_string(root.join("devices.json")).unwrap()).unwrap()
    }

    fn key_entries(root: &Path) -> Vec<Value> {
        serde_json::from_str(
            &std::fs::read_to_string(root.join(KEY_REVOCATIONS_FILE)).unwrap_or_default(),
        )
        .unwrap_or_default()
    }

    #[test]
    fn forget_writes_the_key_block_before_removing_the_record() {
        let root = TestRoot::new("order");
        let store = root.store();
        let owner = [0x22u8; 32];
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        write_devices(root.path(), &[record("beta", &cert, false)]);
        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );
        assert!(plan.write_key_block);

        let mut saw_block = false;
        let receipt = store
            .apply_removal_with(
                &plan,
                None,
                |_| Ok(()),
                |store, plan| {
                    // The LAST step must see the refusal already on disk.
                    let entries = key_entries(root.path());
                    saw_block = key_revocation_in_force(&entries, &cert.device_pub, 100);
                    remove_record_last(store, plan)
                },
            )
            .unwrap();

        assert!(saw_block, "the record was removed before the key block existed");
        assert!(receipt.record_removed);
        assert!(receipt.key_block_written);
        assert_eq!(receipt.refused_until, Some(1_000));
        assert!(read_devices(root.path()).is_empty());
        assert!(key_revocation_in_force(
            &key_entries(root.path()),
            &cert.device_pub,
            100
        ));
    }

    #[test]
    fn a_failing_record_writer_leaves_the_refusal_in_place() {
        let root = TestRoot::new("crash");
        let store = root.store();
        let owner = [0x22u8; 32];
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        write_devices(root.path(), &[record("beta", &cert, false)]);
        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );

        let error = store
            .apply_removal_with(&plan, None, |_| Ok(()), |_, _| {
                anyhow::bail!("simulated record-write crash")
            })
            .unwrap_err();
        assert!(error.to_string().contains("simulated record-write crash"));
        assert!(
            key_revocation_in_force(&key_entries(root.path()), &cert.device_pub, 100),
            "the refusal must outlive a failed record removal"
        );
        assert_eq!(
            read_devices(root.path()).len(),
            1,
            "the record is still present for a retry"
        );

        // The same plan retried after the writer is healthy completes.
        let receipt = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(receipt.record_removed);
        assert!(read_devices(root.path()).is_empty());
    }

    #[test]
    fn forgetting_twice_keeps_the_refusal_and_reports_no_record_removed() {
        let root = TestRoot::new("forget-twice");
        let store = root.store();
        let owner = [0x22u8; 32];
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        write_devices(root.path(), &[record("beta", &cert, false)]);
        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );
        let first = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(first.record_removed);
        let second = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(!second.record_removed, "the record step is a no-op");
        assert!(second.key_block_written, "the refusal is still written");
        assert!(key_revocation_in_force(
            &key_entries(root.path()),
            &cert.device_pub,
            100
        ));
        assert!(read_devices(root.path()).is_empty());
    }

    #[test]
    fn cut_off_keeps_the_record_and_its_grants() {
        let root = TestRoot::new("cut");
        let store = root.store();
        let owner_key = UserKey::from_seed(&[0x33u8; 32]).unwrap();
        let owner = owner_key.public_key_bytes();
        let cert = cert(0x11, owner, 1_000);
        write_devices(root.path(), &[record("beta", &cert, false)]);
        std::fs::write(
            root.path().join("caps.json"),
            serde_json::to_string_pretty(&json!([
                {
                    "type": "cap_header",
                    "resource": "self",
                    "owner_pub": hex::encode(owner),
                    "nonce": hex::encode([0x44u8; 32]),
                    "floors": [],
                    "issued_at": 0,
                    "epoch": 0,
                    "sig": hex::encode([0u8; 64]),
                },
                {
                    "type": "cap_grant",
                    "grantor": hex::encode(owner),
                    "targetKind": 1,
                    "target": hex::encode(cert.device_pub),
                    "resource": "self",
                    "permissions": ["transfer"],
                    "expires": 10_000,
                    "issued_at": 10,
                    "version": 10,
                    "sig": hex::encode([0u8; 64]),
                },
            ]))
            .unwrap(),
        )
        .unwrap();
        let caps_before = std::fs::read_to_string(root.path().join("caps.json")).unwrap();

        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::CutOff,
            100,
        );
        let receipt = store
            .apply_removal(&plan, Some(&owner_key), |_| Ok(()))
            .unwrap();

        assert_eq!(receipt.grants_revoked, 0);
        assert!(!receipt.record_removed);
        assert_eq!(receipt.sessions, SessionsSummary::EndsOnRecheck);
        assert!(!root.path().join(KEY_REVOCATIONS_FILE).exists());
        assert_eq!(
            std::fs::read_to_string(root.path().join("caps.json")).unwrap(),
            caps_before,
            "cut off keeps the grants"
        );
        let records = read_devices(root.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["certRevoked"], json!(true));
        assert_eq!(records[0]["principalState"], json!(PRINCIPAL_STATE_REVOKED));
    }

    #[test]
    fn restore_lifts_the_block_and_revocation_and_is_idempotent() {
        let root = TestRoot::new("restore");
        let store = root.store();
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        write_devices(root.path(), &[record("beta", &cert, true)]);
        std::fs::write(
            root.path().join(KEY_REVOCATIONS_FILE),
            serde_json::to_string_pretty(&json!([{
                "devicePub": hex::encode(cert.device_pub),
                "userPub": hex::encode(cert.user_pub),
                "certExpires": 1_000,
                "revokedAt": 50,
                "name": "beta",
            }]))
            .unwrap(),
        )
        .unwrap();

        let plan = plan_removal(
            &record("beta", &cert, true),
            Some(&cert),
            Some(cert.user_pub),
            RemovalMode::Restore,
            100,
        );
        let first = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert_eq!(first.mode, RemovalMode::Restore);
        assert_eq!(first.key_blocks_lifted.len(), 1);
        assert_eq!(first.key_blocks_lifted[0].name, "beta");
        assert!(first.local_only);
        assert!(key_entries(root.path()).is_empty());
        let records = read_devices(root.path());
        assert_eq!(records[0]["certRevoked"], json!(false));
        assert!(records[0].get("revokedAt").is_none());
        assert!(records[0]["principalState"].is_null());

        // Second apply: no block, already unrevoked, still a success.
        let second = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(second.key_blocks_lifted.is_empty());
        assert_eq!(second.sessions, SessionsSummary::NotTouched);
        assert!(!second.record_removed);
        assert_eq!(read_devices(root.path())[0]["certRevoked"], json!(false));
    }

    #[test]
    fn a_reused_petname_cannot_remove_a_different_key() {
        let root = TestRoot::new("reuse");
        let store = root.store();
        let owner = [0x22u8; 32];
        let old_cert = cert(0x11, [0x22u8; 32], 1_000);
        let new_cert = cert(0x12, [0x22u8; 32], 1_000);
        write_devices(root.path(), &[record("beta", &old_cert, false)]);
        let plan = plan_removal(
            &record("beta", &old_cert, false),
            Some(&old_cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );

        // The petname is freed and taken by a different device key.
        write_devices(root.path(), &[record("beta", &new_cert, false)]);
        let error = store.apply_removal(&plan, None, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("no longer holds the planned key"), "{error}");
        let records = read_devices(root.path());
        assert_eq!(records.len(), 1);
        assert_eq!(
            DeviceCert::from_json(&records[0]["deviceCert"])
                .unwrap()
                .device_pub,
            new_cert.device_pub,
            "the different key's record is untouched"
        );
        assert!(!key_revocation_in_force(
            &key_entries(root.path()),
            &old_cert.device_pub,
            100
        ));
    }

    #[test]
    fn a_corrupt_store_fails_closed_without_a_partial_write() {
        let root = TestRoot::new("corrupt");
        let store = root.store();
        let owner = [0x22u8; 32];
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        std::fs::write(root.path().join("devices.json"), "{not json").unwrap();
        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );
        let error = store.apply_removal(&plan, None, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("devices.json"), "{error}");
        assert_eq!(
            std::fs::read_to_string(root.path().join("devices.json")).unwrap(),
            "{not json",
            "a corrupt store is never written over"
        );
        assert!(
            !root.path().join(KEY_REVOCATIONS_FILE).exists(),
            "preflight refused before the key block was written"
        );

        // A corrupt key list also fails closed, and leaves the record in place.
        std::fs::write(
            root.path().join("devices.json"),
            serde_json::to_string(&json!([record("beta", &cert, false)])).unwrap(),
        )
        .unwrap();
        std::fs::write(root.path().join(KEY_REVOCATIONS_FILE), "{not json").unwrap();
        let error = store.apply_removal(&plan, None, |_| Ok(())).unwrap_err();
        assert!(error.to_string().contains("revoked-keys.json"), "{error}");
        assert_eq!(read_devices(root.path()).len(), 1);
    }

    #[test]
    fn a_live_owner_grant_is_revoked_by_key_on_forget() {
        let root = TestRoot::new("grants");
        let store = root.store();
        let owner_key = UserKey::from_seed(&[0x33u8; 32]).unwrap();
        let owner = owner_key.public_key_bytes();
        let cert = cert(0x11, owner, 1_000);
        write_devices(root.path(), &[record("beta", &cert, false)]);
        std::fs::write(
            root.path().join("caps.json"),
            serde_json::to_string_pretty(&json!([
                {
                    "type": "cap_header",
                    "resource": "self",
                    "owner_pub": hex::encode(owner),
                    "nonce": hex::encode([0x44u8; 32]),
                    "floors": [],
                    "issued_at": 0,
                    "epoch": 0,
                    "sig": hex::encode([0u8; 64]),
                },
                {
                    "type": "cap_grant",
                    "grantor": hex::encode(owner),
                    "targetKind": 1,
                    "target": hex::encode(cert.device_pub),
                    "resource": "self",
                    "permissions": ["transfer"],
                    "expires": 10_000,
                    "issued_at": 10,
                    "version": 10,
                    "sig": hex::encode([0u8; 64]),
                },
            ]))
            .unwrap(),
        )
        .unwrap();

        let plan = plan_removal(
            &record("beta", &cert, false),
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );
        let receipt = store
            .apply_removal(&plan, Some(&owner_key), |_| Ok(()))
            .unwrap();
        assert_eq!(receipt.grants_revoked, 1);
        assert!(receipt.record_removed);
        let caps: Vec<Value> =
            serde_json::from_str(&std::fs::read_to_string(root.path().join("caps.json")).unwrap())
                .unwrap();
        assert!(
            caps.iter().all(|entry| entry["type"] != json!("cap_grant")),
            "the device-keyed grant is gone"
        );
        assert!(caps.iter().any(|entry| entry["type"] == json!("cap_revoked")));
    }

    #[test]
    fn a_plain_pair_forget_keeps_no_block_and_still_removes_the_record() {
        let root = TestRoot::new("plain");
        let store = root.store();
        write_devices(
            root.path(),
            &[json!({"name": "beta", "secret": "s".repeat(64)})],
        );
        let plan = plan_removal(
            &json!({"name": "beta", "secret": "s".repeat(64)}),
            None,
            Some([0x22u8; 32]),
            RemovalMode::Forget,
            100,
        );
        assert!(!plan.write_key_block);
        let receipt = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(receipt.record_removed);
        assert!(!receipt.key_block_written);
        assert_eq!(receipt.refused_until, None);
        assert!(!root.path().join(KEY_REVOCATIONS_FILE).exists());
        assert!(read_devices(root.path()).is_empty());
    }

    #[test]
    fn restore_by_name_lifts_a_block_with_no_record_left() {
        let root = TestRoot::new("restore-name");
        let store = root.store();
        std::fs::write(
            root.path().join(KEY_REVOCATIONS_FILE),
            serde_json::to_string_pretty(&json!([{
                "devicePub": hex::encode([0x11u8; 32]),
                "userPub": hex::encode([0x22u8; 32]),
                "certExpires": 1_000,
                "revokedAt": 50,
                "name": "beta",
            }]))
            .unwrap(),
        )
        .unwrap();
        let plan = plan_restore_by_name("beta", 100);
        let receipt = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert_eq!(receipt.key_blocks_lifted.len(), 1);
        assert!(key_entries(root.path()).is_empty());
        // Idempotent: a second lift is a successful no-op.
        let again = store.apply_removal(&plan, None, |_| Ok(())).unwrap();
        assert!(again.key_blocks_lifted.is_empty());
    }

    #[test]
    fn the_plan_keeps_names_out_of_the_identity_decisions() {
        let owner = [0x22u8; 32];
        let cert = cert(0x11, [0x22u8; 32], 1_000);
        // A record whose name says one thing and whose cert says another still
        // plans by the key.
        let stale_name = json!({"name": "renamed", "deviceCert": cert.to_json()});
        let plan = plan_removal(
            &stale_name,
            Some(&cert),
            Some(owner),
            RemovalMode::Forget,
            100,
        );
        assert_eq!(plan.name, "renamed");
        assert_eq!(plan.device_key, Some([0x11u8; 32]));
        assert_eq!(plan.refused_until, Some(1_000));
        assert_eq!(plan.refused_days(), Some(1));
    }
}
