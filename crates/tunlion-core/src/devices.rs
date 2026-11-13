//! Read-only receiver facts. Presence and remote application are not inferred
//! from a stored relationship or a successful owner-side write.
use crate::{Core, CoreError};
use filament_cap::capability::{CAP_MOUNT, CAP_SHELL, CAP_TRANSFER};
use filament_id::DeviceCert;
use filament_peerloop::recv::store::{effective_principal_deadline, record_is_revoked, DeviceStore};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceRelationship { Paired, Fleet, Temporary, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DevicePresence { Unknown, Live }

/// What a stored fact says about one action right now.
///
/// `Available` is an authenticated observation, not a stored permission. This
/// build does not produce it from a record, a grant or an invitation: those
/// facts are `Pending` or `Unknown` until a live link proves the action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccessState {
    Available,
    /// A local policy fact exists (a grant, an admitted ceiling) but delivery
    /// to the peer or a live check has not been observed. Never read this as
    /// working access.
    Pending,
    Blocked,
    Unsupported,
    Unknown,
}

/// The stable direction/kind of one effective action. Clients switch on this
/// enum, never on the display string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ActionKind { Send, ReceiveInbox, Terminal, Folder }

impl ActionKind {
    /// Stable wire/display token. CLI text may use this; policy and client
    /// logic must match the enum variant instead.
    pub fn as_str(self) -> &'static str {
        match self {
            ActionKind::Send => "send",
            ActionKind::ReceiveInbox => "receive-inbox",
            ActionKind::Terminal => "terminal",
            ActionKind::Folder => "folder",
        }
    }

    /// The enforcement capability this action names. `transfer` covers both
    /// directions; the CLI refuses the bare `send`/`inbox` names for the same
    /// reason. Terminal and folder use the same `shell` and `mount` names the
    /// gate enforces.
    pub fn capability(self) -> &'static str {
        match self {
            ActionKind::Send | ActionKind::ReceiveInbox => CAP_TRANSFER,
            ActionKind::Terminal => CAP_SHELL,
            ActionKind::Folder => CAP_MOUNT,
        }
    }
}

impl std::fmt::Display for ActionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where the state in an [`ActionPolicy`] came from. This is a fact about the
/// local store, not a claim that the peer applied anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PolicySource {
    /// The stored device record: relationship, expiry, local revocation.
    Record,
    /// The local capability policy (the per-device caps/deniedCaps record) or
    /// an owner-signed grant in the capability store.
    GrantStore,
    /// The enrollment ceiling carried by a delegated record.
    EnrollmentCeiling,
    /// An explicit deny recorded on this phone.
    Denied,
    /// This core profile does not serve the action.
    Profile,
    /// The answer needs authenticated link facts this snapshot does not have.
    LinkFacts,
    /// A local key-revocation block refuses the device.
    KeyBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EffectiveAction {
    /// Direction is explicit: `send` is outbound; `receive-inbox` is local.
    pub action: ActionKind,
    pub state: AccessState,
    pub reason: String,
}

/// One action with the source of its state and the same stable order clients
/// already use.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ActionPolicy {
    pub action: ActionKind,
    pub state: AccessState,
    pub source: PolicySource,
    pub reason: String,
}

/// How this device was admitted, as far as the stored record says. This is a
/// typed fact, not an assertion that the invitation path is linked in this
/// build; `CoreSession::enrollment_status` reports that separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EnrollmentKind {
    /// A plain pair or owner device with no admission facts recorded.
    NotRecorded,
    /// This owner's own certified device.
    OwnerDevice,
    /// Admitted by an invitation. The ceiling is the admission bound, never a
    /// claim that the peer is reachable now.
    Delegated,
    /// An ephemeral/runner record admitted for a bounded time.
    Temporary,
    /// A plain pair with no certificate or admission facts.
    Paired,
    /// The record names an admission shape this core version does not know.
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EnrollmentState {
    pub kind: EnrollmentKind,
    /// Empty unless `kind` is `Delegated`.
    pub ceiling: Vec<String>,
    /// Present only for `Unsupported`, naming the shape this version cannot
    /// read. Never a substitute for an empty ceiling.
    pub reason: Option<String>,
}

/// Whether a local policy change has reached the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeliveryKind {
    /// This build keeps no outbox or acknowledgment record.
    NotTracked,
    /// A local policy change is waiting for the peer to connect.
    Pending,
    /// The peer acknowledged the change.
    Delivered,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeliveryState {
    pub kind: DeliveryKind,
    /// Present only when `kind` is `Delivered`.
    pub at: Option<u64>,
}

/// One device's full local policy: relationship, admission facts, delivery
/// state, and one row per action.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DevicePolicy {
    pub name: String,
    pub device_key: Option<String>,
    pub relationship: DeviceRelationship,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub presence: DevicePresence,
    pub enrollment: EnrollmentState,
    pub delivery: DeliveryState,
    pub actions: Vec<ActionPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceAccess {
    pub name: String,
    pub device_key: Option<String>,
    pub relationship: DeviceRelationship,
    pub expires_at: Option<u64>,
    pub revoked: bool,
    pub presence: DevicePresence,
    pub actions: Vec<EffectiveAction>,
}

fn action(action: ActionKind, state: AccessState, source: PolicySource, reason: &str) -> ActionPolicy {
    ActionPolicy { action, state, source, reason: reason.into() }
}

/// Which receiver endpoints this profile actually serves. The reduced Core
/// profile serves neither, and a test can construct a serving profile to pin
/// the `Pending` projection without claiming the production build serves it.
struct ProfileFacts {
    serves_terminal: bool,
    serves_folder: bool,
    delivery: DeliveryState,
}

impl ProfileFacts {
    fn reduced() -> Self {
        Self {
            serves_terminal: false,
            serves_folder: false,
            delivery: DeliveryState { kind: DeliveryKind::NotTracked, at: None },
        }
    }
}

impl Core {
    /// Inspect stored relationships without creating keys, probing a peer or
    /// taking an engine lease. An unreadable/corrupt store is an error, not an
    /// empty fleet. These facts never acknowledge a remote grant or removal.
    ///
    /// This list view tolerates a corrupt capability store (it reads as no
    /// owner-signed grants) so a damaged `caps.json` cannot hide the devices a
    /// person needs in order to repair or forget one. The detailed
    /// [`Core::device_policy`] is strict and reports the damage.
    pub fn devices(&self) -> Result<Vec<DeviceAccess>, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let records = store.devices_snapshot().map_err(crate::store_err)?;
        let cap_store = store.cap_store();
        let owner = store.owner_pub_for_resources(None);
        let now = filament_id::now_secs();
        let profile = ProfileFacts::reduced();
        records
            .iter()
            .map(|record| {
                project_with(record, &store, owner, &cap_store, now, &profile)
                    .map(access_from_policy)
            })
            .collect()
    }

    /// One device's typed policy. Strict: a corrupt devices or capability store
    /// is an error, not a silent "no policy". Read-only and local; no network
    /// work and no identity bootstrap.
    pub fn device_policy(&self, name: &str) -> Result<DevicePolicy, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let records = store.devices_snapshot().map_err(crate::store_err)?;
        let record = records
            .iter()
            .find(|record| record["name"].as_str() == Some(name))
            .ok_or_else(|| CoreError::Usage(format!("no known device named '{name}'")))?;
        let cap_store = store.cap_store_checked().map_err(crate::store_err)?;
        let owner = store.owner_pub_for_resources(None);
        project_with(
            record,
            &store,
            owner,
            &cap_store,
            filament_id::now_secs(),
            &ProfileFacts::reduced(),
        )
    }
}

#[cfg(test)]
fn project(record: &Value, store: &DeviceStore, now: u64) -> Result<DeviceAccess, CoreError> {
    let cap_store = store.cap_store();
    let owner = store.owner_pub_for_resources(None);
    project_with(record, store, owner, &cap_store, now, &ProfileFacts::reduced())
        .map(access_from_policy)
}

fn project_with(
    record: &Value,
    store: &DeviceStore,
    owner: Option<[u8; 32]>,
    cap_store: &[Value],
    now: u64,
    profile: &ProfileFacts,
) -> Result<DevicePolicy, CoreError> {
    let name = record["name"]
        .as_str()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| CoreError::Config("device record has no name".into()))?;
    let cert = DeviceCert::from_json(&record["deviceCert"]);
    let key = cert.as_ref().map(|cert| cert.device_pub);
    let record_revoked = record_is_revoked(record);
    let key_blocked = key
        .as_ref()
        .is_some_and(|key| store.device_cert_revoked(key));
    let revoked = record_revoked || key_blocked;
    let revoked_source = if key_blocked { PolicySource::KeyBlock } else { PolicySource::Record };
    let temporary = record["ephemeral"].as_bool() == Some(true)
        || record["invitedAs"].as_str() == Some("runner");
    let relationship = if temporary {
        DeviceRelationship::Temporary
    // Verify historical issuer provenance separately from current permission:
    // an expired personal device remains personal, but access below is blocked.
    } else if cert
        .as_ref()
        .is_some_and(|cert| cert.verify(0).is_ok() && Some(cert.user_pub) == owner)
        && record["invitedAs"].as_str() != Some("person")
    {
        DeviceRelationship::Fleet
    } else if record["secret"].as_str().is_some_and(|secret| !secret.is_empty()) {
        // A pair secret alone never proves fleet membership.
        DeviceRelationship::Paired
    } else {
        DeviceRelationship::Unknown
    };
    let expires_at = cert
        .as_ref()
        .map(|cert| {
            effective_principal_deadline(
                cert.expires,
                record["principalExpires"].as_u64(),
                record["lastSeen"].as_u64(),
                record["principalMaxOffline"].as_u64(),
            )
            .0
        })
        .or_else(|| record["principalExpires"].as_u64());
    let expired = expires_at.is_some_and(|at| at <= now);
    let delegated = record["principalKind"].as_str() == Some("delegated");
    let ceiling = delegated_ceiling(record);
    let ceiling_covers =
        |capability: &str| ceiling.iter().any(|entry| entry.eq_ignore_ascii_case(capability));
    let denied = |capability: &str| {
        record["deniedCaps"].as_array().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.as_str() == Some(capability))
        })
    };
    let caps = record_caps(record, now);
    let held = |capability: &str| {
        if delegated {
            ceiling_covers(capability)
        } else {
            caps.iter().any(|entry| entry.as_str() == capability)
                || signed_grant_holds(cap_store, owner, cert.as_ref(), capability, now)
        }
    };

    let send = if revoked {
        action(
            ActionKind::Send,
            AccessState::Blocked,
            revoked_source,
            "This device is revoked on this phone",
        )
    } else {
        action(
            ActionKind::Send,
            AccessState::Unknown,
            PolicySource::LinkFacts,
            "Remote receiver authorization and reachability are not observed",
        )
    };
    let receive = if revoked {
        action(
            ActionKind::ReceiveInbox,
            AccessState::Blocked,
            revoked_source,
            "Device access is revoked on this receiver",
        )
    } else if expired {
        action(
            ActionKind::ReceiveInbox,
            AccessState::Blocked,
            PolicySource::Record,
            "Device access has expired",
        )
    } else if denied(CAP_TRANSFER) {
        action(
            ActionKind::ReceiveInbox,
            AccessState::Blocked,
            PolicySource::Denied,
            "Transfer is explicitly denied on this receiver",
        )
    } else if delegated && !ceiling_covers(CAP_TRANSFER) {
        action(
            ActionKind::ReceiveInbox,
            AccessState::Blocked,
            PolicySource::EnrollmentCeiling,
            "The enrollment ceiling for this device does not include transfer",
        )
    } else {
        action(
            ActionKind::ReceiveInbox,
            AccessState::Unknown,
            PolicySource::LinkFacts,
            "Stored relationship only; the receive gate requires authenticated link facts",
        )
    };
    let terminal = if !profile.serves_terminal {
        action(
            ActionKind::Terminal,
            AccessState::Unsupported,
            PolicySource::Profile,
            "This core profile does not serve terminals",
        )
    } else if revoked {
        action(
            ActionKind::Terminal,
            AccessState::Blocked,
            revoked_source,
            "Device access is revoked on this receiver",
        )
    } else if expired {
        action(
            ActionKind::Terminal,
            AccessState::Blocked,
            PolicySource::Record,
            "Device access has expired",
        )
    } else if denied(CAP_SHELL) {
        action(
            ActionKind::Terminal,
            AccessState::Blocked,
            PolicySource::Denied,
            "Terminal is explicitly denied on this receiver",
        )
    } else if delegated {
        if ceiling_covers(CAP_SHELL) {
            action(
                ActionKind::Terminal,
                AccessState::Pending,
                PolicySource::EnrollmentCeiling,
                "Admitted by the invitation ceiling; delivery to the device is not confirmed",
            )
        } else {
            action(
                ActionKind::Terminal,
                AccessState::Blocked,
                PolicySource::EnrollmentCeiling,
                "The enrollment ceiling for this device does not include shell",
            )
        }
    } else if held(CAP_SHELL) {
        action(
            ActionKind::Terminal,
            AccessState::Pending,
            PolicySource::GrantStore,
            "Granted on this phone; the peer has not acknowledged delivery",
        )
    } else {
        action(
            ActionKind::Terminal,
            AccessState::Blocked,
            PolicySource::GrantStore,
            "Terminal is not granted to this device on this phone",
        )
    };
    let folder = if !profile.serves_folder {
        action(
            ActionKind::Folder,
            AccessState::Unsupported,
            PolicySource::Profile,
            "This core profile does not serve folder mounts",
        )
    } else if revoked {
        action(
            ActionKind::Folder,
            AccessState::Blocked,
            revoked_source,
            "Device access is revoked on this receiver",
        )
    } else if expired {
        action(
            ActionKind::Folder,
            AccessState::Blocked,
            PolicySource::Record,
            "Device access has expired",
        )
    } else if denied(CAP_MOUNT) {
        action(
            ActionKind::Folder,
            AccessState::Blocked,
            PolicySource::Denied,
            "Folder access is explicitly denied on this receiver",
        )
    } else if delegated {
        if ceiling_covers(CAP_MOUNT) {
            action(
                ActionKind::Folder,
                AccessState::Pending,
                PolicySource::EnrollmentCeiling,
                "Admitted by the invitation ceiling; delivery to the device is not confirmed",
            )
        } else {
            action(
                ActionKind::Folder,
                AccessState::Blocked,
                PolicySource::EnrollmentCeiling,
                "The enrollment ceiling for this device does not include mount",
            )
        }
    } else if held(CAP_MOUNT) {
        action(
            ActionKind::Folder,
            AccessState::Pending,
            PolicySource::GrantStore,
            "Granted on this phone; the peer has not acknowledged delivery",
        )
    } else {
        action(
            ActionKind::Folder,
            AccessState::Blocked,
            PolicySource::GrantStore,
            "Folder access is not granted to this device on this phone",
        )
    };

    Ok(DevicePolicy {
        name: name.into(),
        device_key: key.map(hex::encode),
        relationship,
        expires_at,
        revoked,
        presence: DevicePresence::Unknown,
        enrollment: enrollment_state(record, relationship),
        delivery: profile.delivery.clone(),
        actions: vec![send, receive, terminal, folder],
    })
}

fn access_from_policy(policy: DevicePolicy) -> DeviceAccess {
    DeviceAccess {
        name: policy.name,
        device_key: policy.device_key,
        relationship: policy.relationship,
        expires_at: policy.expires_at,
        revoked: policy.revoked,
        presence: policy.presence,
        actions: policy
            .actions
            .into_iter()
            .map(|action| EffectiveAction {
                action: action.action,
                state: action.state,
                reason: action.reason,
            })
            .collect(),
    }
}

fn enrollment_state(record: &Value, relationship: DeviceRelationship) -> EnrollmentState {
    if record["ephemeral"].as_bool() == Some(true)
        || record["invitedAs"].as_str() == Some("runner")
    {
        return EnrollmentState {
            kind: EnrollmentKind::Temporary,
            ceiling: Vec::new(),
            reason: None,
        };
    }
    if let Some(kind) = record["principalKind"].as_str() {
        if kind == "delegated" {
            return EnrollmentState {
                kind: EnrollmentKind::Delegated,
                ceiling: delegated_ceiling(record),
                reason: None,
            };
        }
        return EnrollmentState {
            kind: EnrollmentKind::Unsupported,
            ceiling: Vec::new(),
            reason: Some(format!(
                "principalKind '{kind}' is not understood by this core version"
            )),
        };
    }
    let kind = match relationship {
        DeviceRelationship::Fleet => EnrollmentKind::OwnerDevice,
        DeviceRelationship::Paired => EnrollmentKind::Paired,
        DeviceRelationship::Temporary => EnrollmentKind::Temporary,
        DeviceRelationship::Unknown => EnrollmentKind::NotRecorded,
    };
    EnrollmentState { kind, ceiling: Vec::new(), reason: None }
}

/// The persisted capability ceiling of a delegated record. Empty for every
/// other record shape. A delegated record with no readable ceiling is empty,
/// which fails closed for every capability.
pub(crate) fn delegated_ceiling(record: &Value) -> Vec<String> {
    if record["principalKind"].as_str() != Some("delegated") {
        return Vec::new();
    }
    record["principalCeiling"]
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn record_caps(record: &Value, now: u64) -> Vec<String> {
    let mut caps: Vec<String> = match record.get("caps").and_then(|caps| caps.as_array()) {
        Some(entries) => entries
            .iter()
            .filter_map(|entry| entry.as_str().map(str::to_string))
            .collect(),
        // v1 records (no caps field) read as the transfer baseline.
        None => vec![CAP_TRANSFER.to_string()],
    };
    if let Some(expiries) = record.get("capExpires").and_then(|value| value.as_object()) {
        caps.retain(|capability| {
            expiries
                .get(capability)
                .and_then(|value| value.as_u64())
                .map(|expiry| now < expiry)
                .unwrap_or(true)
        });
    }
    caps
}

/// Does an owner-signed grant in the capability store authorize `capability`
/// for this device? Device-targeted grants are the default; a user-targeted
/// grant is the documented per-person wildcard and is checked too.
fn signed_grant_holds(
    store: &[Value],
    owner: Option<[u8; 32]>,
    cert: Option<&DeviceCert>,
    capability: &str,
    now: u64,
) -> bool {
    let (Some(owner), Some(cert)) = (owner, cert) else {
        return false;
    };
    let grantor = hex::encode(owner);
    let device = hex::encode(cert.device_pub);
    let user = hex::encode(cert.user_pub);
    store.iter().any(|entry| {
        if entry.get("type").and_then(|value| value.as_str()) != Some("cap_grant") {
            return false;
        }
        if !entry["grantor"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(&grantor))
        {
            return false;
        }
        if entry["resource"].as_str() != Some("self") {
            return false;
        }
        let target_matches = match entry["targetKind"].as_u64().unwrap_or(0) {
            0 => entry["target"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&user)),
            1 => entry["target"]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&device)),
            _ => false,
        };
        target_matches
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
    use serde_json::json;

    #[test]
    fn inspection_never_bootstraps_identity_or_claims_remote_access() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        assert!(core.devices().unwrap().is_empty());
        std::fs::write(root.path().join("devices.json"), json!([
            {"name":"external", "secret":"must-not-cross-ffi", "caps":["shell"]},
            {"name":"worker", "ephemeral":true, "principalExpires":1},
        ]).to_string()).unwrap();
        let devices = core.devices().unwrap();
        assert_eq!(devices[0].relationship, DeviceRelationship::Paired);
        assert_eq!(devices[0].actions.iter().map(|a| a.action).collect::<Vec<_>>(),
            vec![ActionKind::Send, ActionKind::ReceiveInbox, ActionKind::Terminal, ActionKind::Folder]);
        assert_eq!(ActionKind::ReceiveInbox.to_string(), "receive-inbox");
        assert_eq!(devices[0].actions[0].state, AccessState::Unknown);
        assert_eq!(devices[0].actions[2].state, AccessState::Unsupported);
        assert_eq!(devices[1].relationship, DeviceRelationship::Temporary);
        assert_eq!(devices[1].actions[1].state, AccessState::Blocked);
        assert!(!format!("{devices:?}").contains("must-not-cross-ffi"));
        assert!(!root.path().join("identity.ed25519").exists());
        assert!(!root.path().join("overlay.ed25519").exists());
    }

    #[test]
    fn malformed_store_is_not_reported_as_an_empty_fleet() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        std::fs::write(root.path().join("devices.json"), "[").unwrap();
        assert!(core.devices().is_err());
    }

    #[test]
    fn expired_personal_device_keeps_relationship_but_not_access() {
        let root = tempfile::tempdir().unwrap();
        let store = DeviceStore::open(root.path());
        store.ensure_identity_on_mutation().unwrap();
        let owner = filament_id::UserKey::load(&store.keystore()).unwrap().unwrap();
        let cert = DeviceCert::certify(&owner, [7; 32], 1, 1).unwrap();
        let record = json!({"name":"old-laptop", "deviceCert":cert.to_json()});
        let device = project(&record, &store, 3).unwrap();
        assert_eq!(device.relationship, DeviceRelationship::Fleet);
        assert_eq!(device.actions[1].state, AccessState::Blocked);
        // Personal and external invitations both have delegated bounds; those
        // bounds are not a relationship classification.
        let personal = json!({"name":"personal", "deviceCert":cert.to_json(), "principalKind":"delegated", "secret":"pair"});
        assert_eq!(project(&personal, &store, 3).unwrap().relationship, DeviceRelationship::Fleet);
        let external = json!({"name":"external", "deviceCert":cert.to_json(), "principalKind":"delegated", "invitedAs":"person", "secret":"pair"});
        assert_eq!(project(&external, &store, 3).unwrap().relationship, DeviceRelationship::Paired);
    }

    #[test]
    fn a_served_grant_is_pending_not_working_access() {
        let root = tempfile::tempdir().unwrap();
        let store = DeviceStore::open(root.path());
        let record = json!({"name":"alpha", "secret":"s".repeat(64), "caps":["shell"]});
        let profile = ProfileFacts {
            serves_terminal: true,
            serves_folder: false,
            delivery: DeliveryState { kind: DeliveryKind::NotTracked, at: None },
        };
        let policy = project_with(&record, &store, None, &[], 10, &profile).unwrap();
        let terminal = &policy.actions[2];
        assert_eq!(terminal.action, ActionKind::Terminal);
        assert_eq!(terminal.state, AccessState::Pending);
        assert_eq!(terminal.source, PolicySource::GrantStore);
        assert_ne!(terminal.state, AccessState::Available);
        assert!(terminal.reason.contains("not acknowledged"));
        // Folder is not served, so its grant state stays out of the way.
        assert_eq!(policy.actions[3].state, AccessState::Unsupported);
    }

    #[test]
    fn a_delegated_ceiling_is_reported_and_blocks_uncovered_receive() {
        let root = tempfile::tempdir().unwrap();
        let store = DeviceStore::open(root.path());
        let record = json!({
            "name":"guest",
            "secret":"s".repeat(64),
            "principalKind":"delegated",
            "principalCeiling":["shell"],
            "principalExpires":50,
        });
        let policy = project_with(
            &record,
            &store,
            None,
            &[],
            10,
            &ProfileFacts::reduced(),
        )
        .unwrap();
        assert_eq!(
            policy.enrollment,
            EnrollmentState {
                kind: EnrollmentKind::Delegated,
                ceiling: vec!["shell".to_string()],
                reason: None,
            }
        );
        assert_eq!(policy.actions[1].state, AccessState::Blocked);
        assert_eq!(policy.actions[1].source, PolicySource::EnrollmentCeiling);
        assert_eq!(policy.delivery.kind, DeliveryKind::NotTracked);
    }

    #[test]
    fn a_key_blocked_record_reports_the_key_block_source() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        let now = filament_id::now_secs();
        let cert = DeviceCert {
            device_pub: [9; 32],
            user_pub: [8; 32],
            expires: now + 10_000,
            issued: 0,
            sig: [0; 64],
        };
        std::fs::write(
            root.path().join("devices.json"),
            json!([{"name":"beta", "secret":"s".repeat(64), "deviceCert":cert.to_json()}]).to_string(),
        )
        .unwrap();
        std::fs::write(
            root.path().join("revoked-keys.json"),
            json!([{
                "devicePub": hex::encode(cert.device_pub),
                "certExpires": now + 1_000,
                "name": "beta",
                "revokedAt": now,
            }])
            .to_string(),
        )
        .unwrap();
        let policy = core.device_policy("beta").unwrap();
        assert!(policy.revoked);
        assert_eq!(policy.actions[1].source, PolicySource::KeyBlock);
        assert_eq!(policy.actions[1].state, AccessState::Blocked);
    }

    #[test]
    fn an_unknown_name_is_not_a_device_policy() {
        let root = tempfile::tempdir().unwrap();
        let core = Core::open(root.path()).unwrap();
        assert!(matches!(core.device_policy("ghost"), Err(CoreError::Usage(_))));
    }
}
