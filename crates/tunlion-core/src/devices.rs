//! Read-only receiver facts. Presence and remote application are not inferred
//! from a stored relationship or a successful owner-side write.
use crate::{Core, CoreError};
use filament_id::DeviceCert;
use filament_peerloop::recv::store::{effective_principal_deadline, record_is_revoked, DeviceStore};
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DeviceRelationship { Paired, Fleet, Temporary, Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum DevicePresence { Unknown }

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum AccessState { Available, Blocked, Unsupported, Unknown }

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EffectiveAction {
    /// Direction is explicit: `send` is outbound; `receive-inbox` is local.
    pub action: String,
    pub state: AccessState,
    pub reason: String,
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

fn action(action: &str, state: AccessState, reason: &str) -> EffectiveAction {
    EffectiveAction { action: action.into(), state, reason: reason.into() }
}

impl Core {
    /// Inspect stored relationships without creating keys, probing a peer or
    /// taking an engine lease. An unreadable/corrupt store is an error, not an
    /// empty fleet. These facts never acknowledge a remote grant or removal.
    pub fn devices(&self) -> Result<Vec<DeviceAccess>, CoreError> {
        let store = DeviceStore::open(&self.dir);
        let raw = match std::fs::read(store.devices_path()) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(super::io_err(error)),
        };
        let records: Vec<Value> = serde_json::from_slice(&raw)
            .map_err(|error| CoreError::Config(format!("devices.json: {error}")))?;
        let now = filament_id::now_secs();
        records.iter().map(|record| project(record, &store, now)).collect()
    }
}

fn project(record: &Value, store: &DeviceStore, now: u64) -> Result<DeviceAccess, CoreError> {
    let name = record["name"].as_str().filter(|name| !name.is_empty())
        .ok_or_else(|| CoreError::Config("device record has no name".into()))?;
    let cert = DeviceCert::from_json(&record["deviceCert"]);
    let key = cert.as_ref().map(|cert| cert.device_pub);
    let revoked = record_is_revoked(record) || key.as_ref().is_some_and(|key| store.device_cert_revoked(key));
    let temporary = record["ephemeral"].as_bool() == Some(true)
        || record["invitedAs"].as_str() == Some("runner");
    let relationship = if temporary {
        DeviceRelationship::Temporary
    // Verify historical issuer provenance separately from current permission:
    // an expired personal device remains personal, but access below is blocked.
    } else if cert.as_ref().is_some_and(|cert| cert.verify(0).is_ok()
        && Some(cert.user_pub) == store.owner_pub_for_resources(None))
        && record["invitedAs"].as_str() != Some("person") {
        DeviceRelationship::Fleet
    } else if record["secret"].as_str().is_some_and(|secret| !secret.is_empty()) {
        // A pair secret alone never proves fleet membership.
        DeviceRelationship::Paired
    } else {
        DeviceRelationship::Unknown
    };
    let expires_at = cert.as_ref().map(|cert| effective_principal_deadline(
        cert.expires, record["principalExpires"].as_u64(), record["lastSeen"].as_u64(),
        record["principalMaxOffline"].as_u64(),
    ).0).or_else(|| record["principalExpires"].as_u64());
    let denied = record["deniedCaps"].as_array().is_some_and(|caps| caps.iter().any(|cap| cap.as_str() == Some("transfer")));
    let receive = if revoked {
        action("receive-inbox", AccessState::Blocked, "Device access is revoked on this receiver")
    } else if expires_at.is_some_and(|at| at <= now) {
        action("receive-inbox", AccessState::Blocked, "Device access has expired")
    } else if denied {
        action("receive-inbox", AccessState::Blocked, "Transfer is explicitly denied on this receiver")
    } else {
        action("receive-inbox", AccessState::Unknown, "Stored relationship only; the receive gate requires authenticated link facts")
    };
    Ok(DeviceAccess {
        name: name.into(), device_key: key.map(hex::encode), relationship, expires_at, revoked,
        presence: DevicePresence::Unknown,
        actions: vec![
            action("send", AccessState::Unknown, "Remote receiver authorization and reachability are not observed"),
            receive,
            action("terminal", AccessState::Unsupported, "This core profile does not serve terminals"),
            action("folder", AccessState::Unsupported, "This core profile does not serve folder mounts"),
        ],
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
}
