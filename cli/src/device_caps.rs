//! Device-capability store and evaluation, lifted out of `main.rs`.
//!
//! What a known device is allowed to do, and how a grant is written: read the
//! granted capabilities (`device_caps`, `device_caps_at`, `device_caps_at_time`,
//! `device_allows`, `device_allows_at`), the single decision surface the
//! enforcement points share (`device_capability_denied`), the effective set
//! after the enrollment ceiling is applied (`effective_device_caps`, which
//! consults `principal_ceiling_for` where it still lives in the crate root),
//! and the two writers (`device_set_cap`, `mark_bounded_cap_source`,
//! `issue_signed_bounded_grant`) plus device removal (`devices_remove`).
//!
//! Every function takes its inputs explicitly (a device name, a capability,
//! `&mut Vec<Value>` through `with_devices_mut`), so the move is a relocation:
//! no context struct, no closure capture, no ownership change. No cfg or
//! feature branches, no test hooks and no spawned tasks in this block.
use crate::{
    device_cert_for, devices_path, load_owner_key, principal_ceiling_for, with_devices_mut,
};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::path::Path;

/// L1-a (spec §8): read a device's granted capabilities. v1 records (no `caps`)
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
/// read as `["transfer"]` for backward compatibility; deny-by-default otherwise.
/// Returns None if the device isn't known.
fn device_caps(name: &str) -> Option<Vec<String>> {
    device_caps_at(&devices_path(), name)
}

/// The capabilities enforcement actually honours for this device: the enrollment
/// ceiling for a delegated device (grant writes never widen it), or the grant
/// store for a non-delegated device. The devices display renders from this, and
/// `grant`/`revoke` consult the same `principal_ceiling_for` source, so none of
/// the three surfaces hand-writes the delegated/ceiling verdict and drifts.
pub(crate) fn effective_device_caps(name: &str) -> Vec<String> {
    match principal_ceiling_for(name) {
        Some(ceiling) => ceiling,
        None => device_caps(name).unwrap_or_else(|| vec!["transfer".to_string()]),
    }
}

/// Path-explicit core of `device_caps` (testable without touching the global
/// config-dir env var).
#[allow(dead_code)]
pub(crate) fn device_caps_at(path: &Path, name: &str) -> Option<Vec<String>> {
    device_caps_at_time(path, name, crate::capability::now_secs())
}

pub(crate) fn device_caps_at_time(path: &Path, name: &str, now: u64) -> Option<Vec<String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    let arr = serde_json::from_str::<Value>(&raw).ok()?;
    for d in arr.as_array()? {
        if d["name"].as_str() == Some(name) {
            let mut caps = match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list
                    .iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect(),
                None => vec!["transfer".to_string()], // v1 record
            };
            if let Some(expiries) = d.get("capExpires").and_then(|v| v.as_object()) {
                caps.retain(|cap| {
                    expiries
                        .get(cap)
                        .and_then(|v| v.as_u64())
                        .map(|expiry| crate::capability::grant_active(expiry, now))
                        .unwrap_or(true)
                });
            }
            return Some(caps);
        }
    }
    None
}

/// Path-explicit deny-by-default check (testable).
#[allow(dead_code)]
pub(crate) fn device_allows_at(path: &Path, name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps_at_time(path, name, crate::capability::now_secs())
        .map(|c| c.iter().any(|g| g == capability))
        .unwrap_or(false)
}

/// L1-a (spec §8 / gate 5): deny-by-default capability enforcement hook. A
/// gated action is allowed only if the device's record grants the capability.
/// "transfer" is the L0 baseline (always allowed, even for empty caps) so this
/// never regresses existing send/recv. Wired now; future L-layers add caps.
#[allow(dead_code)] // enforcement hook (gate 5); exercised by the capability gate
pub(crate) fn device_allows(name: &str, capability: &str) -> bool {
    if capability == "transfer" {
        return true; // L0 baseline, never gated (spec §8)
    }
    device_caps(name)
        .map(|c| c.iter().any(|g| g == capability))
        .unwrap_or(false)
}

/// Grant or revoke a capability on an EXISTING known device, preserving its
/// secret and any other caps. Promotes a v1 record (no `caps`) to v2 with the
/// back-compat baseline `["transfer"]` first, so granting `shell` never silently
/// drops `transfer`. Deny-by-default consent for `tunlion grant`/`revoke`.
/// Returns Err if the device is unknown (you can't grant a stranger a shell).
/// Has the owner explicitly revoked this capability from this device?
///
/// #244: `revoke <device> shell` wrote caps, and the blanket `up --shell`
/// policy never read caps: `ShellPolicy::All => true`, name and caps ignored.
/// So the command printed "revoked 'shell' from 'X'" and the shell kept
/// working. Worse for a vouched record, which has no certificate, so
/// `revoke --certificate` bailed too and NEITHER verb could reach it. The
/// operator ran the security verb, got a success line, and lost nothing.
///
/// A grant is a capability. A revoke is a DECISION, and a decision has to
/// outrank a policy default or it is not a decision. This is the durable record
/// of that decision, and the blanket policy is now subordinate to it.
pub(crate) fn device_capability_denied(name: &str, capability: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter()
        .find(|d| d["name"].as_str() == Some(name))
        .and_then(|d| d["deniedCaps"].as_array())
        .is_some_and(|list| list.iter().any(|c| c.as_str() == Some(capability)))
}

pub(crate) fn device_set_cap(
    name: &str,
    capability: &str,
    grant: bool,
    expires: Option<u64>,
) -> Result<()> {
    let capability = crate::capability::canonical_capability(capability)?;
    let mut found = false;
    with_devices_mut(|arr| {
        for d in arr.iter_mut() {
            if d["name"].as_str() != Some(name) {
                continue;
            }
            found = true;
            // #244: a revoke is a decision, not just the absence of a grant, so
            // record it durably where the blanket shell policy can see it.
            // Without this, `revoke <dev> shell` under `up --shell` printed
            // success and changed nothing, because auto_allows reads no caps.
            {
                let mut denied: Vec<String> = d
                    .get("deniedCaps")
                    .and_then(|c| c.as_array())
                    .map(|l| {
                        l.iter()
                            .filter_map(|c| c.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                denied.retain(|c| c != &capability);
                if !grant {
                    denied.push(capability.clone());
                }
                denied.sort();
                denied.dedup();
                d["deniedCaps"] = json!(denied);
            }
            // Current caps: v1 (absent) reads as the transfer baseline.
            let mut caps: Vec<String> = match d.get("caps").and_then(|c| c.as_array()) {
                Some(list) => list
                    .iter()
                    .filter_map(|c| c.as_str().map(String::from))
                    .collect(),
                None => vec!["transfer".to_string()],
            };
            caps.retain(|c| c != &capability);
            if grant {
                caps.push(capability.to_string());
            }
            if let Some(obj) = d.as_object_mut() {
                obj.insert("v".into(), json!(2));
                obj.insert("caps".into(), json!(caps));
                let mut cap_expires = obj
                    .get("capExpires")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if grant {
                    if let Some(expiry) = expires {
                        cap_expires.insert(capability.to_string(), json!(expiry));
                    } else {
                        cap_expires.remove(&capability);
                    }
                } else {
                    cap_expires.remove(&capability);
                }
                obj.insert("capExpires".into(), json!(cap_expires));
                let mut sources = obj
                    .get("capSources")
                    .and_then(|v| v.as_object())
                    .cloned()
                    .unwrap_or_default();
                if grant && expires.is_some() {
                    sources.insert(capability.to_string(), json!("legacy"));
                } else {
                    sources.remove(&capability);
                }
                obj.insert("capSources".into(), json!(sources));
            }
        }
        if !found {
            return Err(anyhow::anyhow!(
                "no known device named '{name}', run `tunlion devices` to see who you've paired"
            ));
        }
        Ok(())
    })
}

pub(crate) fn mark_bounded_cap_source(name: &str, capability: &str, source: &str) -> Result<()> {
    with_devices_mut(|arr| {
        let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
            bail!("unknown device '{name}'")
        };
        let obj = device
            .as_object_mut()
            .ok_or_else(|| anyhow::anyhow!("invalid device record"))?;
        let mut sources = obj
            .get("capSources")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        sources.insert(capability.to_string(), json!(source));
        obj.insert("capSources".into(), json!(sources));
        Ok(())
    })
}

/// Which key an owner-signed grant names.
///
/// `Device` is the default and the only scope `tunlion grant <device>` used to
/// MEAN: the grant names the device's own key (target kind 0x01), so it reaches
/// exactly the device the operator typed. The writers used to sign every grant
/// to the peer's USER key (0x00), and a user-targeted grant matches every device
/// that user has certified. For a device of my own fleet that user key is MINE,
/// so `grant laptop shell` granted shell to the whole fleet under authoritative
/// evaluation and `revoke laptop shell` took it from all of them.
///
/// `User` is the documented per-person wildcard (docs/design-groups-tags-caps.md
/// 4.1: grant `User(Alice)` and every device Alice owns inherits it). It stays
/// available, but only when asked for by name (`--user`), never as the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantScope {
    Device,
    User,
}

impl GrantScope {
    /// The (target kind, target key) an op for this certified peer names.
    pub(crate) fn target(self, cert: &crate::identity::DeviceCert) -> (u8, [u8; 32]) {
        let t = match self {
            GrantScope::Device => crate::capability::CapTarget::Device(cert.device_pub),
            GrantScope::User => crate::capability::CapTarget::User(cert.user_pub),
        };
        (t.kind_byte(), t.target_bytes())
    }
}

/// Make sure the owner's "self" header exists, creating the genesis header when
/// it does not, and return it.
pub(crate) fn ensure_self_header(
    store: &mut Vec<Value>,
    user_key: &crate::identity::UserKey,
) -> Result<crate::capability::CapHeader> {
    let pk = user_key.public_key_bytes();
    let existing = store
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        })
        .and_then(crate::capability::CapHeader::from_json);
    if let Some(h) = existing {
        return Ok(h);
    }
    let mut hdr = crate::capability::CapHeader {
        resource: crate::capability::self_resource_id(&pk),
        epoch: 0,
        owner_pub: pk,
        nonce: crate::capability::self_resource_nonce(),
        floors: vec![],
        issued_at: crate::capability::now_secs(),
        prev_owner_pub: None,
        prev_header_hash: None,
        sig: [0; 64],
    };
    hdr.sig = crate::capability::sign_cap_header(&hdr, user_key.keypair());
    let mut value = hdr.to_json();
    value["resource"] = json!("self");
    store.push(value);
    crate::capability::CapHeader::from_json(store.last().expect("just pushed"))
        .ok_or_else(|| anyhow::anyhow!("capability store header did not round-trip"))
}

/// Mint one owner-signed op for (target, resource) at a version strictly above
/// everything the store has recorded for that key, revoke tombstones included,
/// so a regrant after a revoke lands above the tombstone instead of being
/// refused by it.
pub(crate) fn sign_next_cap_op(
    store: &[Value],
    user_key: &crate::identity::UserKey,
    kind: crate::capability::CapOpKind,
    (target_kind, target): (u8, [u8; 32]),
    resource: &str,
    permissions: Vec<String>,
    expires: u64,
) -> crate::capability::CapOp {
    let pk = user_key.public_key_bytes();
    let latest = crate::capability::latest_op_version(store, &pk, resource, target_kind, &target);
    let mut op = crate::capability::CapOp {
        op: kind,
        grantor: pk,
        target_kind,
        target,
        resource: resource.to_string(),
        permissions,
        expires,
        issued_at: crate::capability::now_secs(),
        version: crate::capability::hlc_next(latest, crate::capability::now_ms()),
        sig: [0; 64],
    };
    op.sig = crate::capability::sign_cap_op(&op, user_key.keypair());
    op
}

/// Does a live user-wide grant (target kind 0x00, the peer's user key) from
/// `grantor` carry `capability` for this peer? Such a grant authorizes the
/// device whatever happens to its own device-targeted grant, so a per-device
/// revoke has to know about it.
pub(crate) fn user_wide_grant_covers(
    store: &[Value],
    grantor: &[u8; 32],
    cert: &crate::identity::DeviceCert,
    capability: &str,
) -> bool {
    let (kind, target) = GrantScope::User.target(cert);
    let (grantor_hex, target_hex) = (hex::encode(grantor), hex::encode(target));
    let now = crate::capability::now_secs();
    store.iter().any(|e| {
        e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")
            && e["grantor"].as_str() == Some(grantor_hex.as_str())
            && e["resource"].as_str() == Some("self")
            && e["targetKind"].as_u64().unwrap_or(0) == kind as u64
            && e["target"].as_str() == Some(target_hex.as_str())
            && crate::capability::grant_active(e["expires"].as_u64().unwrap_or(0), now)
            && e["permissions"]
                .as_array()
                .is_some_and(|p| p.iter().any(|c| c.as_str() == Some(capability)))
    })
}

/// The owner-signed Revoke ops `tunlion revoke <device> <cap>` applies, and
/// whether a user-wide grant had to be taken with it.
///
/// The first op names the same key the grant named (`scope`). When revoking a
/// DEVICE grant and a live user-wide grant still carries the capability for
/// this peer, a second op revokes that too: otherwise the device keeps the
/// capability through its user key and the revoke reports success while
/// changing nothing. A revoke errs toward removing access.
pub(crate) fn signed_revoke_ops(
    store: &[Value],
    user_key: &crate::identity::UserKey,
    cert: &crate::identity::DeviceCert,
    capability: &str,
    scope: GrantScope,
) -> (Vec<crate::capability::CapOp>, bool) {
    let expires = crate::capability::now_secs().saturating_add(90 * 24 * 3600);
    let revoke = |target| {
        sign_next_cap_op(
            store,
            user_key,
            crate::capability::CapOpKind::Revoke,
            target,
            "self",
            vec![capability.to_string()],
            expires,
        )
    };
    let mut ops = vec![revoke(scope.target(cert))];
    let also_user_wide = scope == GrantScope::Device
        && user_wide_grant_covers(store, &user_key.public_key_bytes(), cert, capability);
    if also_user_wide {
        ops.push(revoke(GrantScope::User.target(cert)));
    }
    (ops, also_user_wide)
}

/// Add the authoritative owner-signed bounded grant when the peer is certified.
/// Uncertified peers intentionally retain the legacy `capExpires` fallback.
///
/// The grant names the DEVICE key (see `GrantScope`): approving one device's
/// request must not hand the capability to every device its user certified.
pub(crate) fn issue_signed_bounded_grant(
    device: &str,
    capability: &str,
    expires: u64,
) -> Result<bool> {
    let Some(user_key) = load_owner_key() else {
        return Ok(false);
    };
    let Some(peer_cert) = device_cert_for(device) else {
        return Ok(false);
    };
    peer_cert.verify(crate::identity::now_secs()).map_err(|_| {
        anyhow::anyhow!("peer identity cert for '{device}' is expired; re-pair to refresh it")
    })?;
    let config_dir = crate::settings::config_dir();
    let mut store = crate::capability::load_cap_store(&config_dir);
    let pk = user_key.public_key_bytes();
    ensure_self_header(&mut store, &user_key)?;
    let op = sign_next_cap_op(
        &store,
        &user_key,
        crate::capability::CapOpKind::Grant,
        GrantScope::Device.target(&peer_cert),
        "self",
        vec![capability.into()],
        expires,
    );
    let mut value = op.to_json();
    value["type"] = json!("cap_grant");
    store.push(value);
    crate::capability::update_ratchet(&mut store, &pk, op.issued_at)?;
    crate::capability::save_and_list_revoked(&store, &config_dir)?;
    Ok(true)
}

pub(crate) fn devices_remove(name: &str) -> Result<()> {
    let p = devices_path();
    if let Some(dir) = p.parent() {
        crate::platform::create_private_dir_all(dir)?;
    }
    // Raw-array filter so the REMAINING devices keep their v2 fields (caps,
    // addedAt). The old tuple round-trip rewrote every survivor as bare
    // {name, secret}, silently wiping their `shell` grants on any forget.
    with_devices_mut(|arr| {
        arr.retain(|d| d["name"].as_str() != Some(name));
        Ok(())
    })
}
