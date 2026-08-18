//! Owner-signed mesh roster (v1): a spoke can SEE the mesh.
//!
//! An owner mints a signed roster of its OTHER devices (names + keys only, no
//! ceiling, no cert expiry) and pushes it over links that already exist. A spoke
//! verifies the signature against the owner key it holds in its OWN device
//! certificate, accepts only a strictly newer `(epoch, valid_until)`, and stores
//! it. `devices` then renders the siblings from the roster.
//!
//! THE ROSTER IS NEVER AN AUTHORIZATION INPUT. It is not fetched, not merged,
//! and the acceptor's decision does not have it in scope. Roster presence is
//! evidence of nothing. The strongest property of push-over-existing-links is
//! not "no third party": it is that you cannot withhold the roster without also
//! blocking the link the user actually uses, so withholding is immediately
//! visible instead of a stale banner on an otherwise healthy system. A dedicated
//! roster endpoint would hand that back, which is why v1 has none.
//!
//! v1 has exactly ONE authoring primary. A second primary exists for root
//! redundancy, not concurrent authoring; the upgrade path when it arrives is a
//! version vector keyed by `(author_pub, counter)`, not the scalar epoch here.

use anyhow::{anyhow, bail, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::identity::{MeshRoster, RosterDevice, UserKey};

/// Short on purpose (amendment 3): the roster authorizes nothing, so a spoke
/// whose roster expires loses nothing functional. Keep the window small now;
/// lengthening it later has to be argued for.
pub fn roster_ttl_secs() -> u64 {
    std::env::var("FILAMENT_ROSTER_TTL_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(15 * 60)
}

fn devices_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("devices.json")
}

fn roster_state_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("roster-state.json")
}

fn roster_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("roster.json")
}

/// The owner's other devices: every record with a device cert chaining to the
/// owner key, excluding the owner's own device and any REVOKED record (a revoked
/// device is no longer a mesh member, so the roster must not keep re-issuing it
/// to every spoke; the acceptor refuses it independently, and `devices` must
/// not tell a spoke a lie about a security-relevant change). Sorted by
/// device_pub so the snapshot is a set, not an ordering.
pub fn owner_snapshot(owner_pub: &[u8; 32]) -> Vec<RosterDevice> {
    let self_pub = crate::overlay::overlay_pubkey_bytes().ok();
    let raw = std::fs::read_to_string(devices_path()).ok();
    let arr: Vec<Value> = raw
        .and_then(|r| serde_json::from_str::<Vec<Value>>(&r).ok())
        .unwrap_or_default();
    let mut out = Vec::new();
    for d in arr {
        if d["certRevoked"].as_bool() == Some(true) {
            continue;
        }
        let Some(cert) = crate::identity::DeviceCert::from_json(&d["deviceCert"]) else { continue };
        if cert.user_pub != *owner_pub {
            continue;
        }
        if self_pub.as_ref() == Some(&cert.device_pub) {
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

fn snapshot_hash(devices: &[RosterDevice]) -> String {
    let mut h = Sha256::new();
    for d in devices {
        h.update(d.device_pub);
        h.update((d.petname.len().min(u16::MAX as usize) as u16).to_le_bytes());
        h.update(d.petname.as_bytes());
    }
    hex::encode(h.finalize())
}

#[derive(Default)]
struct OwnerState {
    epoch: u64,
    hash: String,
    valid_until: u64,
}

fn load_owner_state() -> OwnerState {
    std::fs::read_to_string(roster_state_path())
        .ok()
        .and_then(|r| serde_json::from_str::<Value>(&r).ok())
        .map(|v| OwnerState {
            epoch: v["epoch"].as_u64().unwrap_or(0),
            hash: v["hash"].as_str().unwrap_or("").to_string(),
            valid_until: v["valid_until"].as_u64().unwrap_or(0),
        })
        .unwrap_or_default()
}

fn save_owner_state(st: &OwnerState) -> Result<()> {
    let path = roster_state_path();
    crate::platform::SecretFile::write_str(
        &path,
        &serde_json::to_string_pretty(&json!({
            "epoch": st.epoch,
            "hash": st.hash,
            "valid_until": st.valid_until,
        }))?,
    )?;
    Ok(())
}

/// Mint + sign the current roster. Returns the signed blob (no `type` field)
/// and whether its content changed vs the last mint (epoch bumped, or
/// `valid_until` refreshed). `valid_until` is stable between refreshes so a
/// quiet system does not re-push every tick.
pub fn mint_roster(owner: &UserKey, now: u64) -> Result<(Value, bool)> {
    let owner_pub = owner.public_key_bytes();
    let devices = owner_snapshot(&owner_pub);
    let hash = snapshot_hash(&devices);
    let state = load_owner_state();

    let epoch = if state.epoch == 0 || state.hash != hash {
        state.epoch.saturating_add(1)
    } else {
        state.epoch
    };
    let refresh_horizon = roster_ttl_secs() / 2;
    let valid_until = if state.valid_until > now.saturating_add(refresh_horizon) && state.hash == hash {
        state.valid_until // still fresh and unchanged: keep it stable
    } else {
        now.saturating_add(roster_ttl_secs())
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
        save_owner_state(&OwnerState {
            epoch,
            hash,
            valid_until,
        })?;
    }
    Ok((blob, changed))
}

/// Pure accept rule (amendment 1): accept on `(epoch, valid_until)` lexicographic.
/// Monotone, rejects replays (a replayed roster carries the older `valid_until`),
/// and a pure validity refresh (same epoch, later `valid_until`) is deliverable.
/// A scalar epoch with one authoring primary is a version, not a counter shared
/// by uncoordinated writers; two writers are the #238 lost-update again.
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

/// Spoke side: parse, verify, and store a pushed roster. Returns `Ok(true)` when
/// it was accepted (and stored), `Ok(false)` when it was rejected as a replay /
/// stale / expired (a normal, silent no-op). `owner_pub` is the owner key the
/// spoke already holds in its own device certificate.
pub fn verify_and_store_roster(blob: &Value, owner_pub: &[u8; 32], now: u64) -> Result<bool> {
    let Some(roster) = MeshRoster::from_json(blob) else {
        bail!("malformed roster");
    };
    if roster.owner_pub != *owner_pub {
        bail!("roster owner does not match the owner key in this device's certificate");
    }
    let sig_hex = blob["sig"].as_str().ok_or_else(|| anyhow!("roster missing signature"))?;
    let sig: [u8; 64] = hex::decode(sig_hex)?
        .try_into()
        .map_err(|_| anyhow!("roster signature has the wrong length"))?;
    roster.verify(&sig)?;
    if roster.valid_until <= now {
        // Expired: never store an expired roster, and never let it clobber a
        // still-valid one. This is the "empty because expired" display case.
        return Ok(false);
    }
    if let Some(cur) = stored_roster() {
        let seen_epoch = cur["epoch"].as_u64();
        let seen_until = cur["valid_until"].as_u64();
        if !roster_is_newer(roster.epoch, roster.valid_until, seen_epoch, seen_until) {
            return Ok(false); // replay or older: silently ignore
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
    crate::platform::SecretFile::write_str(&roster_path(), &serde_json::to_string_pretty(&out)?)?;
    Ok(true)
}

/// The last stored (accepted) roster on this spoke, if any.
pub fn stored_roster() -> Option<Value> {
    let raw = std::fs::read_to_string(roster_path()).ok()?;
    serde_json::from_str::<Value>(&raw).ok()
}

/// Petnames of the roster's devices, for name resolution (`require_known_device`).
/// Excludes this device's own key: the roster lists the owner's devices, which on
/// a spoke includes itself, and "known devices" must never name the asker.
pub fn roster_device_names() -> Vec<String> {
    let self_pub = crate::overlay::overlay_pubkey_bytes().ok();
    stored_roster()
        .and_then(|r| r["devices"].as_array().cloned())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| {
                    let name = d["petname"].as_str()?.to_string();
                    if let (Some(self_pub), Some(hex_pub)) = (self_pub.as_ref(), d["device_pub"].as_str()) {
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

/// Display staleness, distinguishing three states that look identical as an
/// empty list. `now` is unix seconds.
pub fn roster_staleness(now: u64) -> RosterStaleness {
    match stored_roster() {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterStaleness {
    /// No roster has ever been received.
    None,
    /// A roster was received but has lapsed past `valid_until`.
    Expired,
    /// A roster is currently valid.
    Fresh { epoch: u64, received_at: u64 },
}
