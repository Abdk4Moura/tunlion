//! Owner-signed mesh roster: mint, verify and store, with an explicit root.
//!
//! This is the trust-bearing half of `cli/src/roster.rs`. The roster is never
//! an authorization input; it is a visibility snapshot pushed over existing
//! links. What is preserved exactly:
//!
//! * the owner key in the blob must equal the owner key this device already
//!   holds in its own certificate;
//! * the signature is verified over the signed roster body;
//! * an expired roster is never stored and never replaces a valid one;
//! * acceptance is strictly monotonic in `(epoch, valid_until)` so a replayed
//!   blob is a silent no-op;
//! * only a persistent store root is touched; no process config or env.
//!
//! `roster.ttl_secs` is a caller input, not an env read: the CLI keeps its
//! `TUNLION_ROSTER_TTL_SECS` adapter, and Core supplies its own value.

use anyhow::{anyhow, bail, Result};
use filament_id::{DeviceCert, MeshRoster, RosterDevice, UserKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::recv::store::{record_is_revoked, DeviceStore};

pub const ROSTER_STATE_FILE: &str = "roster-state.json";
pub const ROSTER_FILE: &str = "roster.json";

#[derive(Default)]
struct OwnerState {
    epoch: u64,
    hash: String,
    valid_until: u64,
}

fn roster_state_path(store: &DeviceStore) -> std::path::PathBuf {
    store.root().join(ROSTER_STATE_FILE)
}

fn roster_path(store: &DeviceStore) -> std::path::PathBuf {
    store.root().join(ROSTER_FILE)
}

fn load_owner_state(store: &DeviceStore) -> OwnerState {
    std::fs::read_to_string(roster_state_path(store))
        .ok()
        .and_then(|r| serde_json::from_str::<Value>(&r).ok())
        .map(|v| OwnerState {
            epoch: v["epoch"].as_u64().unwrap_or(0),
            hash: v["hash"].as_str().unwrap_or("").to_string(),
            valid_until: v["valid_until"].as_u64().unwrap_or(0),
        })
        .unwrap_or_default()
}

fn save_owner_state(store: &DeviceStore, st: &OwnerState) -> Result<()> {
    secret_write::SecretFile::write_str(
        &roster_state_path(store),
        &serde_json::to_string_pretty(&json!({
            "epoch": st.epoch,
            "hash": st.hash,
            "valid_until": st.valid_until,
        }))?,
    )?;
    Ok(())
}

fn snapshot_hash(devices: &[RosterDevice]) -> String {
    let mut h = Sha256::new();
    for d in devices {
        h.update(d.device_pub);
        h.update((d.petname.len().min(u16::MAX as usize) as u16).to_le_bytes());
        h.update(d.petname.as_bytes());
    }
    hex::encode(h.finalize())
}

/// The owner's other devices: every record with a device cert chaining to the
/// owner key, excluding the owner's own device and any revoked record. Sorted by
/// device key so the snapshot is a set, not an ordering.
pub fn owner_snapshot(
    store: &DeviceStore,
    owner_pub: &[u8; 32],
    self_pub: Option<&[u8; 32]>,
) -> Vec<RosterDevice> {
    let mut out = Vec::new();
    for d in store.devices_records() {
        if record_is_revoked(&d) {
            continue;
        }
        let Some(cert) = DeviceCert::from_json(&d["deviceCert"]) else {
            continue;
        };
        if cert.user_pub != *owner_pub {
            continue;
        }
        if self_pub == Some(&cert.device_pub) {
            continue;
        }
        out.push(RosterDevice {
            device_pub: cert.device_pub,
            petname: d["name"].as_str().unwrap_or("?").to_string(),
        });
    }
    out.sort_by(|a, b| a.device_pub.cmp(&b.device_pub));
    out
}

/// Mint + sign the current roster. Returns the signed blob and whether its
/// content changed vs the last mint (epoch bumped, or `valid_until` refreshed).
pub fn mint_roster(
    store: &DeviceStore,
    owner: &UserKey,
    now: u64,
    self_pub: Option<&[u8; 32]>,
    ttl_secs: u64,
) -> Result<(Value, bool)> {
    let owner_pub = owner.public_key_bytes();
    let devices = owner_snapshot(store, &owner_pub, self_pub);
    let hash = snapshot_hash(&devices);
    let state = load_owner_state(store);

    let epoch = if state.epoch == 0 || state.hash != hash {
        state.epoch.saturating_add(1)
    } else {
        state.epoch
    };
    let refresh_horizon = ttl_secs / 2;
    let valid_until =
        if state.valid_until > now.saturating_add(refresh_horizon) && state.hash == hash {
            state.valid_until
        } else {
            now.saturating_add(ttl_secs)
        };

    let roster = MeshRoster {
        owner_pub,
        epoch,
        valid_until,
        devices,
    };
    let sig = roster.sign(owner.keypair())?;
    let mut blob = roster.to_json();
    blob["sig"] = json!(hex::encode(sig));

    let changed = epoch != state.epoch || valid_until != state.valid_until;
    if changed {
        save_owner_state(
            store,
            &OwnerState {
                epoch,
                hash,
                valid_until,
            },
        )?;
    }
    Ok((blob, changed))
}

/// Pure accept rule: strictly newer `(epoch, valid_until)`; a fresh
/// `valid_until` at the same epoch is deliverable, a replay is not.
pub fn roster_is_newer(
    epoch: u64,
    valid_until: u64,
    seen_epoch: Option<u64>,
    seen_valid_until: Option<u64>,
) -> bool {
    match (seen_epoch, seen_valid_until) {
        (Some(se), Some(su)) => epoch > se || (epoch == se && valid_until > su),
        _ => true,
    }
}

/// Parse, verify and store a pushed roster. `Ok(true)` means accepted/stored;
/// `Ok(false)` is a stale/replayed/expired no-op. A malformed or wrongly signed
/// roster is an error and is never stored.
pub fn verify_and_store_roster(
    store: &DeviceStore,
    blob: &Value,
    owner_pub: &[u8; 32],
    now: u64,
) -> Result<bool> {
    let Some(roster) = MeshRoster::from_json(blob) else {
        bail!("malformed roster");
    };
    if roster.owner_pub != *owner_pub {
        bail!("roster owner does not match the owner key in this device's certificate");
    }
    let sig_hex = blob["sig"]
        .as_str()
        .ok_or_else(|| anyhow!("roster missing signature"))?;
    let sig: [u8; 64] = hex::decode(sig_hex)?
        .try_into()
        .map_err(|_| anyhow!("roster signature has the wrong length"))?;
    roster.verify(&sig)?;
    if roster.valid_until <= now {
        return Ok(false);
    }
    if let Some(cur) = stored_roster(store) {
        let seen_epoch = cur["epoch"].as_u64();
        let seen_until = cur["valid_until"].as_u64();
        if !roster_is_newer(roster.epoch, roster.valid_until, seen_epoch, seen_until) {
            return Ok(false);
        }
    }
    let out = json!({
        "owner_pub": hex::encode(roster.owner_pub),
        "epoch": roster.epoch,
        "valid_until": roster.valid_until,
        "received_at": now,
        "devices": roster.devices.iter().map(|d| json!({
            "device_pub": hex::encode(d.device_pub),
            "petname": d.petname,
        })).collect::<Vec<_>>(),
    });
    secret_write::SecretFile::write_str(&roster_path(store), &serde_json::to_string_pretty(&out)?)?;
    Ok(true)
}

/// The last stored accepted roster on this spoke, if any.
pub fn stored_roster(store: &DeviceStore) -> Option<Value> {
    std::fs::read_to_string(roster_path(store))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
}

/// Petnames of the roster's devices, excluding this device's own key. A roster
/// on a spoke includes the spoke itself; "known devices" must never name the
/// asker.
pub fn roster_device_names(store: &DeviceStore, self_pub: Option<&[u8; 32]>) -> Vec<String> {
    stored_roster(store)
        .and_then(|r| r["devices"].as_array().cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    let name = d["petname"].as_str()?.to_string();
                    if let (Some(self_pub), Some(hex_pub)) = (self_pub, d["device_pub"].as_str()) {
                        if let Ok(decoded) = hex::decode(hex_pub) {
                            if decoded.as_slice() == self_pub {
                                return None;
                            }
                        }
                    }
                    Some(name)
                })
                .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterStaleness {
    None,
    Expired,
    Fresh { epoch: u64, received_at: u64 },
}

/// Display staleness for the stored roster, with the same three states the CLI
/// showed: never received, received but expired, currently valid.
pub fn roster_staleness(store: &DeviceStore, now: u64) -> RosterStaleness {
    match stored_roster(store) {
        None => RosterStaleness::None,
        Some(r) => {
            let until = r["valid_until"].as_u64().unwrap_or(0);
            if until <= now {
                RosterStaleness::Expired
            } else {
                RosterStaleness::Fresh {
                    epoch: r["epoch"].as_u64().unwrap_or(0),
                    received_at: r["received_at"].as_u64().unwrap_or(0),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-roster-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn owner() -> UserKey {
        UserKey::from_seed(&[9u8; 32]).unwrap()
    }

    #[test]
    fn a_replayed_roster_is_not_stored_and_an_older_one_cannot_win() {
        let dir = temp("replay");
        let store = DeviceStore::open(&dir);
        let owner = owner();
        let (first, changed) = mint_roster(&store, &owner, 100, None, 900).unwrap();
        assert!(changed);
        assert!(verify_and_store_roster(&store, &first, &owner.public_key_bytes(), 100).unwrap());
        // Same blob again: strictly-newer rule rejects it.
        assert!(!verify_and_store_roster(&store, &first, &owner.public_key_bytes(), 101).unwrap());
        // A valid_until refresh at the same epoch is accepted once the old
        // roster is inside its refresh horizon.
        let (refreshed, _) = mint_roster(&store, &owner, 600, None, 900).unwrap();
        assert!(
            verify_and_store_roster(&store, &refreshed, &owner.public_key_bytes(), 200).unwrap()
        );
        assert!(stored_roster(&store).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_expired_or_wrong_owner_roster_is_refused() {
        let dir = temp("wrong");
        let store = DeviceStore::open(&dir);
        let owner = owner();
        let (blob, _) = mint_roster(&store, &owner, 100, None, 10).unwrap();
        assert!(!verify_and_store_roster(&store, &blob, &owner.public_key_bytes(), 200).unwrap());
        assert!(stored_roster(&store).is_none());
        assert!(verify_and_store_roster(&store, &blob, &[3u8; 32], 100).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn independent_roots_do_not_share_roster_state() {
        let a_dir = temp("a");
        let b_dir = temp("b");
        let a = DeviceStore::open(&a_dir);
        let b = DeviceStore::open(&b_dir);
        let owner = owner();
        let (blob, _) = mint_roster(&a, &owner, 100, None, 900).unwrap();
        assert!(verify_and_store_roster(&a, &blob, &owner.public_key_bytes(), 100).unwrap());
        assert!(stored_roster(&b).is_none());
        assert_eq!(
            roster_staleness(&a, 101),
            RosterStaleness::Fresh {
                epoch: 1,
                received_at: 100
            }
        );
        assert_eq!(roster_staleness(&b, 101), RosterStaleness::None);
        let _ = std::fs::remove_dir_all(&a_dir);
        let _ = std::fs::remove_dir_all(&b_dir);
    }
}
