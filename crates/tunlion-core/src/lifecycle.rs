//! Typed device lifecycle calls shared by the Core/UniFFI surface.
//!
//! Removal delegates to `filament_peerloop::removal`; this module only builds
//! the plan from one fail-closed snapshot and maps the receipt across the
//! boundary. Capability edits write the same two stores the CLI writes: the
//! per-device policy record (`caps`/`deniedCaps`) and the owner-signed
//! capability store. A delegated device's authority comes from its enrollment
//! ceiling, so a grant cannot widen it and a revoke cannot narrow it; both are
//! typed outcomes instead of a silent no-op.
use crate::devices::delegated_ceiling;
use crate::{ActionKind, Core, CoreError};
use filament_cap::capability::{
    apply_cap_op, hlc_next, latest_op_version, now_ms, now_secs, self_resource_id,
    self_resource_nonce, sign_cap_header, sign_cap_op, CapHeader, CapOp, CapOpKind, CAP_TRANSFER,
};
use filament_id::{DeviceCert, UserKey};
use filament_peerloop::recv::store::DeviceStore;
use filament_peerloop::removal::{
    plan_removal, plan_restore_by_name, RemovalMode as SharedRemovalMode,
    SessionsSummary as SharedSessionsSummary,
};
use serde_json::{json, Value};

/// The owner-signed grant lifetime the CLI uses. The per-device record keeps
/// no expiry of its own, matching `tunlion grant`.
const CAP_OP_TTL_SECS: u64 = 90 * 24 * 3600;

/// What a removal request does to this phone's stores.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum RemovalMode { Forget, CutOff, Restore }

/// Whether this call touched a live session. It never claims to have ended one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum SessionsSummary { NotTouched, EndsOnRecheck }

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct LiftedKeyBlock {
    pub name: String,
    pub revoked_at: u64,
    /// Hex, because the block is a file format and this value is carried
    /// through to a reader, not matched against.
    pub device_key: String,
}

/// The facts a caller may show after the stores are written. `local_only` is
/// always true and is a field, not an inference: nothing here claims the peer
/// removed its record, dropped a grant, or ended a session.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct RemovalReceipt {
    pub mode: RemovalMode,
    pub name: String,
    pub device_key: Option<String>,
    pub refused_until: Option<u64>,
    pub grants_revoked: u64,
    pub record_removed: bool,
    pub sessions: SessionsSummary,
    pub local_only: bool,
    pub key_block_written: bool,
    pub key_blocks_lifted: Vec<LiftedKeyBlock>,
}

/// What one capability edit did. A delegated device's capability can be held
/// by its enrollment ceiling; then a grant cannot widen it and a revoke cannot
/// narrow it. Those are first-class outcomes, not success lines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum CapabilityOutcome {
    Applied,
    /// The requested capability is already held by the enrollment ceiling.
    AlreadyHeldByCeiling,
    /// The ceiling does not include the capability, and a grant cannot widen it.
    NotGrantableBecauseCeiling,
    /// The capability comes from the ceiling; revoking a grant cannot remove it.
    NotRevocableBecauseCeiling,
    /// The ceiling does not include the capability, so there is nothing to revoke.
    NotHeld,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct CapabilityReceipt {
    pub action: ActionKind,
    pub capability: String,
    pub outcome: CapabilityOutcome,
    /// True only when an owner-signed op was written to the capability store.
    pub signed: bool,
    /// The signed grant's horizon. `None` for a revoke, a plain pair and a
    /// ceiling outcome.
    pub expires_at: Option<u64>,
    /// The delegated ceiling when the outcome is about one; empty otherwise.
    pub ceiling: Vec<String>,
}

/// Whether this build can create, preview or join an invitation. `Unsupported`
/// means no enrollment surface is linked; the reason is a fact, not an empty
/// success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EnrollmentSupport { Supported, Unsupported }

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrollmentStatus {
    pub state: EnrollmentSupport,
    /// Present only when `state` is `Unsupported`.
    pub reason: Option<String>,
}

impl From<SharedRemovalMode> for RemovalMode {
    fn from(mode: SharedRemovalMode) -> Self {
        match mode {
            SharedRemovalMode::Forget => RemovalMode::Forget,
            SharedRemovalMode::CutOff => RemovalMode::CutOff,
            SharedRemovalMode::Restore => RemovalMode::Restore,
        }
    }
}

impl From<SharedSessionsSummary> for SessionsSummary {
    fn from(summary: SharedSessionsSummary) -> Self {
        match summary {
            SharedSessionsSummary::NotTouched => SessionsSummary::NotTouched,
            SharedSessionsSummary::EndsOnRecheck => SessionsSummary::EndsOnRecheck,
        }
    }
}

fn shared_mode(mode: RemovalMode) -> SharedRemovalMode {
    match mode {
        RemovalMode::Forget => SharedRemovalMode::Forget,
        RemovalMode::CutOff => SharedRemovalMode::CutOff,
        RemovalMode::Restore => SharedRemovalMode::Restore,
    }
}

impl From<filament_peerloop::removal::RemovalReceipt> for RemovalReceipt {
    fn from(receipt: filament_peerloop::removal::RemovalReceipt) -> Self {
        Self {
            mode: receipt.mode.into(),
            name: receipt.name,
            device_key: receipt.device_key.map(hex::encode),
            refused_until: receipt.refused_until,
            grants_revoked: receipt.grants_revoked as u64,
            record_removed: receipt.record_removed,
            sessions: receipt.sessions.into(),
            local_only: receipt.local_only,
            key_block_written: receipt.key_block_written,
            key_blocks_lifted: receipt
                .key_blocks_lifted
                .into_iter()
                .map(|block| LiftedKeyBlock {
                    name: block.name,
                    revoked_at: block.revoked_at,
                    device_key: block.device_key,
                })
                .collect(),
        }
    }
}

impl Core {
    /// Forget one device on this phone. The shared removal service writes the
    /// key block first, revokes the grants keyed by the device key, and removes
    /// the record last. Local only; the peer is never contacted.
    pub fn forget_device(&self, name: &str) -> Result<RemovalReceipt, CoreError> {
        self.apply_device_removal(name, RemovalMode::Forget)
    }

    /// Cut one device off in place: keep its record and grants, write the
    /// revocation marker so its next open is told why. Local only.
    pub fn cut_off_device(&self, name: &str) -> Result<RemovalReceipt, CoreError> {
        self.apply_device_removal(name, RemovalMode::CutOff)
    }

    /// Lift this phone's refusal for one device: clear the marker and any key
    /// block. A record removed by a forget is not recreated.
    pub fn restore_device(&self, name: &str) -> Result<RemovalReceipt, CoreError> {
        self.apply_device_removal(name, RemovalMode::Restore)
    }

    fn apply_device_removal(
        &self,
        name: &str,
        mode: RemovalMode,
    ) -> Result<RemovalReceipt, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let records = store.devices_snapshot().map_err(crate::store_err)?;
        let record = records
            .iter()
            .find(|record| record["name"].as_str() == Some(name));
        if record.is_none() && mode != RemovalMode::Restore {
            return Err(CoreError::Usage(format!("no known device named '{name}'")));
        }
        if record.is_none() && mode == RemovalMode::Restore && !key_block_named(&store, name)? {
            return Err(CoreError::Usage(format!("no known device named '{name}'")));
        }
        let now = now_secs();
        let owner = store.owner_pub_for_resources(None);
        let plan = match record {
            Some(record) => {
                let cert = DeviceCert::from_json(&record["deviceCert"]);
                plan_removal(record, cert.as_ref(), owner, shared_mode(mode), now)
            }
            // A restore after a forget has only the name left. This is the
            // documented presentation fallback; no record is recreated.
            None => plan_restore_by_name(name, now),
        };
        let owner_key = UserKey::load(&store.keystore()).map_err(crate::id_err)?;
        let receipt = store
            .apply_removal(&plan, owner_key.as_ref(), |_| Ok(()))
            .map_err(crate::store_err)?;
        Ok(receipt.into())
    }

    /// Grant one action's enforcing capability to a known device. The four
    /// action kinds map to the existing capability names (`transfer` covers
    /// both directions, `shell`, `mount`); the receipt says whether an
    /// owner-signed op was written and when it expires.
    pub fn grant_capability(
        &self,
        device: &str,
        action: ActionKind,
    ) -> Result<CapabilityReceipt, CoreError> {
        self.edit_capability(device, action, true)
    }

    /// Revoke one action's enforcing capability from a known device. This
    /// records an explicit deny even when the capability was not listed, so a
    /// blanket policy cannot keep allowing what the person just revoked.
    /// A capability that comes from a delegated enrollment ceiling cannot be
    /// narrowed by a grant edit and returns `NotRevocableBecauseCeiling`.
    pub fn revoke_capability(
        &self,
        device: &str,
        action: ActionKind,
    ) -> Result<CapabilityReceipt, CoreError> {
        self.edit_capability(device, action, false)
    }

    fn edit_capability(
        &self,
        device: &str,
        action: ActionKind,
        grant: bool,
    ) -> Result<CapabilityReceipt, CoreError> {
        let capability = action.capability();
        let store = DeviceStore::open(&self.dir);
        let records = store.devices_snapshot().map_err(crate::store_err)?;
        let record = records
            .iter()
            .find(|record| record["name"].as_str() == Some(device))
            .ok_or_else(|| CoreError::Usage(format!("no known device named '{device}'")))?;
        let now = now_secs();
        let delegated = record["principalKind"].as_str() == Some("delegated");
        let ceiling = delegated_ceiling(record);
        if delegated {
            let covered = ceiling
                .iter()
                .any(|entry| entry.eq_ignore_ascii_case(capability));
            let outcome = if grant {
                if covered {
                    CapabilityOutcome::AlreadyHeldByCeiling
                } else {
                    CapabilityOutcome::NotGrantableBecauseCeiling
                }
            } else if covered {
                CapabilityOutcome::NotRevocableBecauseCeiling
            } else {
                CapabilityOutcome::NotHeld
            };
            return Ok(CapabilityReceipt {
                action,
                capability: capability.to_string(),
                outcome,
                signed: false,
                expires_at: None,
                ceiling,
            });
        }

        let cert = DeviceCert::from_json(&record["deviceCert"]);
        let owner_key = UserKey::load(&store.keystore()).map_err(crate::id_err)?;
        if let (Some(cert), Some(_)) = (cert.as_ref(), owner_key.as_ref()) {
            cert.verify(now).map_err(|_| {
                CoreError::Usage(format!(
                    "peer identity cert for '{device}' is expired; re-pair to refresh it"
                ))
            })?;
            // Preflight the store the signed write will touch before changing
            // the per-device record, so damage is refused with nothing written.
            store.cap_store_checked().map_err(crate::store_err)?;
        }

        set_legacy_capability(&store, device, capability, grant)?;
        let signed = write_signed_capability(
            &store,
            cert.as_ref(),
            capability,
            grant,
            owner_key.as_ref(),
            now,
        )?;
        let expires_at = if grant && signed {
            Some(now.saturating_add(CAP_OP_TTL_SECS))
        } else {
            None
        };
        Ok(CapabilityReceipt {
            action,
            capability: capability.to_string(),
            outcome: CapabilityOutcome::Applied,
            signed,
            expires_at,
            ceiling,
        })
    }

    /// Whether this build links an invitation create/join surface.
    ///
    /// This branch carries `enrollment.rs` (preview, create, join, list and
    /// withdraw), so the typed answer is `Supported`. The status is still read
    /// from the core: a binding that ships without that module must report
    /// `Unsupported` here rather than infer support from compiled-in calls.
    pub fn enrollment_status(&self) -> EnrollmentStatus {
        EnrollmentStatus {
            state: EnrollmentSupport::Supported,
            reason: None,
        }
    }
}

fn key_block_named(store: &DeviceStore, name: &str) -> Result<bool, CoreError> {
    Ok(store
        .key_revocation_entries()
        .map_err(crate::store_err)?
        .iter()
        .any(|entry| {
            entry["name"]
                .as_str()
                .is_some_and(|recorded| recorded.eq_ignore_ascii_case(name))
        }))
}

/// Write the per-device policy record the same way the CLI does: a v1 record
/// is promoted to v2 with the transfer baseline, a revoke records an explicit
/// deny, and cap expiry/source entries for this capability are cleared.
fn set_legacy_capability(
    store: &DeviceStore,
    device: &str,
    capability: &str,
    grant: bool,
) -> Result<(), CoreError> {
    store
        .with_devices_mut(|records| {
            let Some(record) = records
                .iter_mut()
                .find(|record| record["name"].as_str() == Some(device))
            else {
                anyhow::bail!("no known device named '{device}'");
            };
            let mut denied: Vec<String> = record
                .get("deniedCaps")
                .and_then(|value| value.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            denied.retain(|entry| entry.as_str() != capability);
            if !grant {
                denied.push(capability.to_string());
            }
            denied.sort();
            denied.dedup();
            record["deniedCaps"] = json!(denied);

            let mut caps: Vec<String> = match record.get("caps").and_then(|value| value.as_array()) {
                Some(entries) => entries
                    .iter()
                    .filter_map(|entry| entry.as_str().map(String::from))
                    .collect(),
                // v1 records (no caps field) read as the transfer baseline.
                None => vec![CAP_TRANSFER.to_string()],
            };
            caps.retain(|entry| entry.as_str() != capability);
            if grant {
                caps.push(capability.to_string());
            }
            record["v"] = json!(2);
            record["caps"] = json!(caps);

            if let Some(object) = record.as_object_mut() {
                let mut expiries = object
                    .get("capExpires")
                    .and_then(|value| value.as_object())
                    .cloned()
                    .unwrap_or_default();
                expiries.remove(capability);
                object.insert("capExpires".to_string(), json!(expiries));
                let mut sources = object
                    .get("capSources")
                    .and_then(|value| value.as_object())
                    .cloned()
                    .unwrap_or_default();
                sources.remove(capability);
                object.insert("capSources".to_string(), json!(sources));
            }
            Ok(())
        })
        .map_err(crate::store_err)
}

/// Write an owner-signed grant or revoke. A revoke also takes a user-wide grant
/// that still covers this peer, otherwise the device would keep the capability
/// through its user key after the per-device grant was removed.
fn write_signed_capability(
    store: &DeviceStore,
    cert: Option<&DeviceCert>,
    capability: &str,
    grant: bool,
    owner_key: Option<&UserKey>,
    now: u64,
) -> Result<bool, CoreError> {
    let (Some(cert), Some(owner_key)) = (cert, owner_key) else {
        return Ok(false);
    };
    let owner_pub = owner_key.public_key_bytes();
    let expires = now.saturating_add(CAP_OP_TTL_SECS);
    store
        .with_cap_store_mut(|cap_store| {
            let header = ensure_self_header(cap_store, owner_key, now)?;
            if header.owner_pub != owner_pub {
                anyhow::bail!(
                    "this device's capability store is owned by another key; an owner-signed edit cannot be written here"
                );
            }
            let kind = if grant { CapOpKind::Grant } else { CapOpKind::Revoke };
            let op = sign_next_cap_op(
                cap_store,
                owner_key,
                kind,
                (1, cert.device_pub),
                "self",
                vec![capability.to_string()],
                expires,
                now,
            )?;
            apply_cap_op(cap_store, &header, &op, now)?;
            if !grant && user_wide_grant_covers(cap_store, &owner_pub, cert, capability, now) {
                let user_op = sign_next_cap_op(
                    cap_store,
                    owner_key,
                    CapOpKind::Revoke,
                    (0, cert.user_pub),
                    "self",
                    vec![capability.to_string()],
                    expires,
                    now,
                )?;
                apply_cap_op(cap_store, &header, &user_op, now)?;
            }
            Ok(((), true))
        })
        .map_err(crate::store_err)?;
    Ok(true)
}

/// Ensure the owner's "self" capability header exists. The stored header keeps
/// `resource: "self"`; its signature is over the self-certifying id, matching
/// the CLI writer.
fn ensure_self_header(
    store: &mut Vec<Value>,
    owner_key: &UserKey,
    now: u64,
) -> anyhow::Result<CapHeader> {
    let owner_pub = owner_key.public_key_bytes();
    let existing = store
        .iter()
        .find(|entry| {
            entry.get("type").and_then(|value| value.as_str()) == Some("cap_header")
                && entry["resource"].as_str() == Some("self")
        })
        .and_then(CapHeader::from_json);
    if let Some(header) = existing {
        return Ok(header);
    }
    let mut header = CapHeader {
        resource: self_resource_id(&owner_pub),
        epoch: 0,
        owner_pub,
        nonce: self_resource_nonce(),
        floors: Vec::new(),
        issued_at: now,
        prev_owner_pub: None,
        prev_header_hash: None,
        sig: [0; 64],
    };
    header.sig = sign_cap_header(&header, owner_key.keypair());
    let mut value = header.to_json();
    value["resource"] = json!("self");
    store.push(value);
    CapHeader::from_json(store.last().expect("just pushed"))
        .ok_or_else(|| anyhow::anyhow!("capability store header did not round-trip"))
}

/// Mint one owner-signed op at a version strictly above everything recorded
/// for the same (grantor, resource, target), revoke tombstones included.
fn sign_next_cap_op(
    store: &[Value],
    owner_key: &UserKey,
    kind: CapOpKind,
    (target_kind, target): (u8, [u8; 32]),
    resource: &str,
    permissions: Vec<String>,
    expires: u64,
    now: u64,
) -> anyhow::Result<CapOp> {
    let grantor = owner_key.public_key_bytes();
    let latest = latest_op_version(store, &grantor, resource, target_kind, &target);
    let mut op = CapOp {
        op: kind,
        grantor,
        target_kind,
        target,
        resource: resource.to_string(),
        permissions,
        expires,
        issued_at: now,
        version: hlc_next(latest, now_ms()),
        sig: [0; 64],
    };
    op.sig = sign_cap_op(&op, owner_key.keypair());
    Ok(op)
}

fn user_wide_grant_covers(
    store: &[Value],
    grantor: &[u8; 32],
    cert: &DeviceCert,
    capability: &str,
    now: u64,
) -> bool {
    let grantor_hex = hex::encode(grantor);
    let target_hex = hex::encode(cert.user_pub);
    store.iter().any(|entry| {
        entry.get("type").and_then(|value| value.as_str()) == Some("cap_grant")
            && entry["grantor"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&grantor_hex))
            && entry["resource"].as_str() == Some("self")
            && entry["targetKind"].as_u64() == Some(0)
            && entry["target"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&target_hex))
            && entry["expires"]
                .as_u64()
                .map_or(true, |expires| now < expires)
            && entry["permissions"].as_array().is_some_and(|permissions| {
                permissions
                    .iter()
                    .any(|permission| permission.as_str() == Some(capability))
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccessState, EnrollmentKind};
    use serde_json::json;
    use std::path::Path;

    fn enrolled(root: &Path) -> (Core, UserKey) {
        let core = Core::open(root).unwrap();
        let store = DeviceStore::open(root);
        store.ensure_identity_on_mutation().unwrap();
        let owner = UserKey::load(&store.keystore()).unwrap().unwrap();
        (core, owner)
    }

    fn write_record(root: &Path, record: Value) {
        let store = DeviceStore::open(root);
        std::fs::write(
            store.devices_path(),
            serde_json::to_string(&json!([record])).unwrap(),
        )
        .unwrap();
    }

    fn read_records(root: &Path) -> Vec<Value> {
        serde_json::from_str(
            &std::fs::read_to_string(DeviceStore::open(root).devices_path()).unwrap(),
        )
        .unwrap()
    }

    fn read_caps(root: &Path) -> Vec<Value> {
        serde_json::from_str(
            &std::fs::read_to_string(DeviceStore::open(root).cap_store_path()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn forget_writes_the_key_block_before_removing_the_record() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x11; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json()}),
        );

        let receipt = core.forget_device("beta").unwrap();
        assert_eq!(receipt.mode, RemovalMode::Forget);
        assert!(receipt.local_only);
        assert!(receipt.record_removed);
        assert!(receipt.key_block_written);
        assert_eq!(receipt.device_key, Some(hex::encode([0x11u8; 32])));
        assert_eq!(receipt.sessions, SessionsSummary::EndsOnRecheck);
        assert!(read_records(root.path()).is_empty());
        let keys: Value = serde_json::from_str(
            &std::fs::read_to_string(root.path().join("revoked-keys.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(keys.as_array().unwrap().len(), 1);
    }

    #[test]
    fn cut_off_keeps_the_record_and_marks_it_revoked() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x12; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json()}),
        );

        let receipt = core.cut_off_device("beta").unwrap();
        assert_eq!(receipt.mode, RemovalMode::CutOff);
        assert!(!receipt.record_removed);
        assert!(!receipt.key_block_written);
        let records = read_records(root.path());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["certRevoked"], json!(true));
        assert!(!root.path().join("revoked-keys.json").exists());
    }

    #[test]
    fn restore_lifts_the_block_after_a_forget() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x13; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json()}),
        );
        core.forget_device("beta").unwrap();

        let receipt = core.restore_device("beta").unwrap();
        assert_eq!(receipt.mode, RemovalMode::Restore);
        assert_eq!(receipt.key_blocks_lifted.len(), 1);
        assert_eq!(receipt.key_blocks_lifted[0].name, "beta");
        assert_eq!(
            receipt.key_blocks_lifted[0].device_key,
            hex::encode([0x13u8; 32])
        );
        assert!(receipt.local_only);
        assert!(read_records(root.path()).is_empty());
        let keys: Value = serde_json::from_str(
            &std::fs::read_to_string(root.path().join("revoked-keys.json")).unwrap(),
        )
        .unwrap();
        assert!(keys.as_array().unwrap().is_empty());
    }

    #[test]
    fn unknown_removals_are_typed_usage_errors() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        assert!(matches!(core.forget_device("ghost"), Err(CoreError::Usage(_))));
        assert!(matches!(core.cut_off_device("ghost"), Err(CoreError::Usage(_))));
        assert!(matches!(core.restore_device("ghost"), Err(CoreError::Usage(_))));
    }

    #[test]
    fn granting_a_capability_writes_the_record_and_the_owner_signed_store() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x21; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json(), "caps":["transfer"]}),
        );

        let receipt = core.grant_capability("beta", ActionKind::Terminal).unwrap();
        assert_eq!(receipt.outcome, CapabilityOutcome::Applied);
        assert!(receipt.signed);
        assert_eq!(receipt.capability, "shell");
        assert!(receipt.expires_at.is_some());
        assert!(read_records(root.path())[0]["caps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some("shell")));
        let caps = read_caps(root.path());
        assert!(caps.iter().any(|entry| {
            entry["type"] == json!("cap_grant")
                && entry["target"] == json!(hex::encode([0x21u8; 32]))
                && entry["permissions"]
                    .as_array()
                    .is_some_and(|permissions| permissions.iter().any(|p| p.as_str() == Some("shell")))
        }));

        let policy = core.device_policy("beta").unwrap();
        assert_eq!(policy.enrollment.kind, EnrollmentKind::OwnerDevice);
        // This reduced profile does not serve terminals, so a written grant is
        // not displayed as working access.
        assert_eq!(policy.actions[2].state, AccessState::Unsupported);
    }

    #[test]
    fn revoking_a_capability_writes_a_deny_and_a_tombstone() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x22; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json(), "caps":["transfer"]}),
        );
        core.grant_capability("beta", ActionKind::Terminal).unwrap();

        let receipt = core.revoke_capability("beta", ActionKind::Terminal).unwrap();
        assert_eq!(receipt.outcome, CapabilityOutcome::Applied);
        assert!(receipt.signed);
        assert!(read_records(root.path())[0]["deniedCaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some("shell")));
        let caps = read_caps(root.path());
        assert!(caps.iter().any(|entry| entry["type"] == json!("cap_revoked")));
        assert!(!caps.iter().any(|entry| {
            entry["type"] == json!("cap_grant")
                && entry["permissions"]
                    .as_array()
                    .is_some_and(|permissions| permissions.iter().any(|p| p.as_str() == Some("shell")))
        }));
    }

    #[test]
    fn a_ceiling_capability_is_not_revocable_by_a_grant_edit() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x23; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({
                "name":"guest",
                "secret":"s".repeat(64),
                "deviceCert": cert.to_json(),
                "principalKind":"delegated",
                "principalCeiling":["shell"],
                "principalExpires": now + 1_000,
                "principalMaxOffline": 1_000,
            }),
        );

        let already = core.grant_capability("guest", ActionKind::Terminal).unwrap();
        assert_eq!(already.outcome, CapabilityOutcome::AlreadyHeldByCeiling);
        assert_eq!(already.ceiling, vec!["shell".to_string()]);
        let outside = core.grant_capability("guest", ActionKind::Folder).unwrap();
        assert_eq!(outside.outcome, CapabilityOutcome::NotGrantableBecauseCeiling);
        let revoke = core.revoke_capability("guest", ActionKind::Terminal).unwrap();
        assert_eq!(revoke.outcome, CapabilityOutcome::NotRevocableBecauseCeiling);
        let not_held = core.revoke_capability("guest", ActionKind::Folder).unwrap();
        assert_eq!(not_held.outcome, CapabilityOutcome::NotHeld);
        // The rejected edits wrote nothing.
        assert!(read_records(root.path())[0].get("caps").is_none());
        assert!(!root.path().join("caps.json").exists());

        let policy = core.device_policy("guest").unwrap();
        assert_eq!(policy.enrollment.kind, EnrollmentKind::Delegated);
        assert_eq!(policy.enrollment.ceiling, vec!["shell".to_string()]);
        assert_eq!(policy.enrollment.reason, None);
    }

    #[test]
    fn a_plain_pair_grant_is_stored_but_not_signed() {
        let root = tempfile::tempdir().unwrap();
        let (core, _) = enrolled(root.path());
        write_record(
            root.path(),
            json!({"name":"browser", "secret":"s".repeat(64)}),
        );
        let receipt = core.grant_capability("browser", ActionKind::Folder).unwrap();
        assert_eq!(receipt.outcome, CapabilityOutcome::Applied);
        assert!(!receipt.signed);
        assert_eq!(receipt.expires_at, None);
        assert!(read_records(root.path())[0]["caps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry.as_str() == Some("mount")));
    }

    #[test]
    fn revoking_a_device_grant_also_takes_a_user_wide_grant() {
        let root = tempfile::tempdir().unwrap();
        let (core, owner) = enrolled(root.path());
        let now = now_secs();
        let cert = DeviceCert::certify(&owner, [0x24; 32], now, 10_000).unwrap();
        write_record(
            root.path(),
            json!({"name":"beta", "secret":"s".repeat(64), "deviceCert": cert.to_json(), "caps":["transfer"]}),
        );
        // A user-wide grant made with the same owner key. The old grant's
        // signature is irrelevant to this test: the writer verifies the NEW op
        // it mints, and the point is that the revoke also names this target.
        std::fs::write(
            DeviceStore::open(root.path()).cap_store_path(),
            serde_json::to_string_pretty(&json!([
                {
                    "type": "cap_header",
                    "resource": "self",
                    "owner_pub": hex::encode(owner.public_key_bytes()),
                    "nonce": hex::encode(self_resource_nonce()),
                    "floors": [],
                    "issued_at": now,
                    "epoch": 0,
                    "prev_owner_pub": null,
                    "prev_header_hash": null,
                    "sig": hex::encode([0u8; 64]),
                },
                {
                    "type": "cap_grant",
                    "grantor": hex::encode(owner.public_key_bytes()),
                    "targetKind": 0,
                    "target": hex::encode(cert.user_pub),
                    "resource": "self",
                    "permissions": ["shell"],
                    "expires": now + 1_000,
                    "issued_at": now,
                    "version": 1,
                    "sig": hex::encode([0u8; 64]),
                },
            ]))
            .unwrap(),
        )
        .unwrap();

        let receipt = core.revoke_capability("beta", ActionKind::Terminal).unwrap();
        assert_eq!(receipt.outcome, CapabilityOutcome::Applied);
        assert!(receipt.signed);
        let caps = read_caps(root.path());
        assert!(caps.iter().any(|entry| {
            entry["type"] == json!("cap_revoked")
                && entry["targetKind"] == json!(0)
                && entry["target"] == json!(hex::encode(cert.user_pub))
        }));
    }

    #[test]
    fn enrollment_status_reports_the_linked_invitation_surface() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        let status = core.enrollment_status();
        assert_eq!(status.state, EnrollmentSupport::Supported);
        assert_eq!(status.reason, None);
    }
}
