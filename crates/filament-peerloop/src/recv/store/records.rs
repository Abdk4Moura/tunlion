//! Pure device-record merge, sweep, principal-resolution, and naming rules.

use super::{
    DeadlineClock, PRINCIPAL_STATE_LAPSED, PRINCIPAL_STATE_REVOKED, PROVISIONAL_TTL_SECS,
};
use anyhow::Result;
use filament_cap::capability::PrincipalKind;
use filament_id::{now_secs, DeviceCert};
use serde_json::{json, Value};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Strip terminal escape sequences and control characters from a device
/// petname before it is stored. Pure.
pub fn sanitize_device_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// The single moment a delegated device stops being recognized:
/// `min(cert_expiry, not_after, last_seen + max_offline)`.
pub fn effective_principal_deadline(
    cert_expires: u64,
    not_after: Option<u64>,
    last_seen: Option<u64>,
    max_offline: Option<u64>,
) -> (u64, DeadlineClock) {
    let mut deadline = cert_expires;
    let mut clock = DeadlineClock::CertExpiry;
    if let Some(na) = not_after {
        if na < deadline {
            deadline = na;
            clock = DeadlineClock::AbsoluteStop;
        }
    }
    if let (Some(ls), Some(mo)) = (last_seen, max_offline) {
        if ls > 0 {
            let budget_deadline = ls.saturating_add(mo);
            if budget_deadline < deadline {
                deadline = budget_deadline;
                clock = DeadlineClock::LivenessBudget;
            }
        }
    }
    (deadline, clock)
}

/// Resolve the persisted principal record for a device cert. A missing or
/// malformed record FAILS CLOSED as a ceiling-less delegated principal.
pub fn principal_from_records(
    records: &[Value],
    cert: &DeviceCert,
    own_user_pub: Option<&[u8; 32]>,
) -> (PrincipalKind, Option<u64>, Option<u64>, Option<u64>) {
    let record = records.iter().find(|record| {
        DeviceCert::from_json(&record["deviceCert"])
            .map(|stored| stored.device_pub == cert.device_pub)
            .unwrap_or(false)
    });
    if let Some(record) = record {
        if record["principalKind"].is_null() {
            return (PrincipalKind::OwnerDevice, None, None, None);
        }
        if record["principalKind"].as_str() == Some("delegated") {
            let caps = record["principalCeiling"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let expires = record["principalExpires"].as_u64().unwrap_or(0);
            let max_offline = record["principalMaxOffline"].as_u64();
            let last_seen = record["lastSeen"].as_u64();
            return (
                PrincipalKind::Delegated { caps },
                Some(expires),
                max_offline,
                last_seen,
            );
        }
        return (
            PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    let is_same_owner = own_user_pub
        .map(|owner| *owner == cert.user_pub)
        .unwrap_or(false);
    if is_same_owner {
        return (
            PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    (PrincipalKind::OwnerDevice, None, None, None)
}

/// What to re-invite an expired delegated device with: the ceiling it was
/// admitted with and the lifetime its invitation granted (`principalIssued`,
/// stamped at enrolment, to `principalExpires`). Pure.
pub fn reinvite_from_record(record: &Value) -> Option<crate::refusal::Reinvite> {
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    let ceiling: Vec<String> = record["principalCeiling"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .filter(|c| !c.starts_with("route:"))
                .collect()
        })
        .unwrap_or_default();
    let end = record["principalExpires"].as_u64()?;
    let start = record["principalIssued"]
        .as_u64()
        .or_else(|| record["addedAt"].as_u64())
        .unwrap_or(end);
    (!ceiling.is_empty()).then(|| crate::refusal::Reinvite {
        ceiling,
        lifetime: end.saturating_sub(start).max(1),
    })
}

/// Sweep the device records for lapsed delegated records. Pure.
pub fn sweep_lapsed(records: &mut Vec<Value>, now: u64) -> usize {
    let mut changed = 0;
    for record in records.iter_mut() {
        if record["principalKind"].as_str() != Some("delegated") {
            continue;
        }
        if record["certRevoked"].as_bool() == Some(true)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED)
        {
            continue;
        }
        let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) else {
            continue;
        };
        let not_after = record["principalExpires"].as_u64();
        let last_seen = record["lastSeen"].as_u64();
        let max_offline = record["principalMaxOffline"].as_u64();
        let (deadline, _clock) =
            effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
        if deadline <= now {
            record["principalState"] = json!(PRINCIPAL_STATE_LAPSED);
            record["lapsedAt"] = json!(now);
            changed += 1;
        }
    }
    changed
}

/// Is this record an ephemeral device (enrolled with a runner invitation)?
/// Pure.
pub fn record_is_ephemeral(record: &Value) -> bool {
    record["ephemeral"].as_bool() == Some(true)
}

/// Has this ephemeral record ended: lapsed (offline past its budget, or
/// departed), or past its lease or certificate end? A revoked ephemeral record
/// is kept, because revoking is the owner's own explicit decision. Pure.
pub fn ephemeral_record_ended(record: &Value, now: u64) -> bool {
    if record_is_revoked(record) {
        return false;
    }
    if record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED) {
        return true;
    }
    let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) else {
        return true;
    };
    let (deadline, _) = effective_principal_deadline(
        cert.expires,
        record["principalExpires"].as_u64(),
        record["lastSeen"].as_u64(),
        record["principalMaxOffline"].as_u64(),
    );
    deadline <= now
}

/// On a joined device: has this fleet-sibling index record ended? A sibling
/// record is one we hold no pair secret for, certified by `owner`. It ends when
/// its certificate expired or `delisted` says the owner's roster dropped it. A
/// record carrying a local revoke is kept (that is this device's own decision),
/// and so is anything we paired with ourselves. Pure but for `delisted`.
pub fn sibling_record_ended(
    record: &Value,
    owner: &[u8; 32],
    now: u64,
    delisted: impl Fn(&[u8; 32]) -> bool,
) -> bool {
    if record["secret"].as_str().is_some_and(|s| !s.is_empty()) || record_is_revoked(record) {
        return false;
    }
    let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) else {
        return false;
    };
    if cert.user_pub != *owner {
        return false;
    }
    cert.expires <= now || delisted(&cert.device_pub)
}

/// Is this device record revoked (the certificate marker, or a durable device
/// revoke)? Pure.
pub fn record_is_revoked(record: &Value) -> bool {
    record["certRevoked"].as_bool() == Some(true)
        || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
}

/// The names of records whose capability list includes `shell`.
pub fn shell_grant_names_at(path: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    let mut names: Vec<String> = arr
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| {
            d.get("caps")
                .and_then(|c| c.as_array())
                .map(|list| list.iter().any(|c| c.as_str() == Some("shell")))
                .unwrap_or(false)
        })
        .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    names.sort();
    names
}

/// Upsert the (secret, cert, caps, scope) fields for `name` into `arr` as ONE
/// record, returning the final stored name (auto-suffixed on a new-name
/// collision). Pure.
pub fn upsert_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: Option<&str>,
    cert: Option<&DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
) -> String {
    // For existing name, update in place preserving other fields.
    if let Some(existing) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        if let Some(s) = secret {
            existing["secret"] = json!(s);
        }
        if let Some(c) = cert {
            existing["userKey"] = json!(hex::encode(c.user_pub));
            existing["deviceCert"] = c.to_json();
        } else if let Some(uk) = user_key_hex {
            existing["userKey"] = json!(uk);
        }
        if let Some(caps) = caps {
            existing["caps"] = json!(caps);
            existing["v"] = json!(2);
        }
        if let Some(sc) = scope {
            existing["identityScope"] = json!(sc);
        }
        if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
            existing["principalKind"] = json!("delegated");
            existing["principalCeiling"] = json!(ceiling);
            existing["principalExpires"] = json!(expires);
            existing["principalMaxOffline"] = json!(max_offline);
            existing["principalMaxOfflineCeiling"] = json!(max_offline_ceiling);
            existing["principalIssued"] = json!(now_secs());
            existing["principalState"] = Value::Null;
            if let Some(map) = existing.as_object_mut() {
                map.remove("lapsedAt");
            }
        }
        return existing["name"].as_str().unwrap_or(name).to_string();
    }

    // New device: auto-suffix if collision. Case-insensitive, as the store's
    // naming rule always was.
    let mut final_name = name.to_string();
    let taken = |a: &Vec<Value>, n: &str| {
        a.iter().any(|d| {
            d["name"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(n))
        })
    };
    if taken(arr, name) {
        let mut suffix = 2;
        let mut new_name = format!("{name}-{suffix}");
        while taken(arr, &new_name) {
            suffix += 1;
            new_name = format!("{name}-{suffix}");
        }
        eprintln!("  note: '{name}' already exists, pairing as '{new_name}'");
        final_name = new_name;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), json!(&final_name));
    if let Some(s) = secret {
        obj.insert("secret".to_string(), json!(s));
    }
    if let Some(c) = cert {
        obj.insert("userKey".to_string(), json!(hex::encode(c.user_pub)));
        obj.insert("deviceCert".to_string(), c.to_json());
    } else if let Some(uk) = user_key_hex {
        obj.insert("userKey".to_string(), json!(uk));
    }
    obj.insert("v".to_string(), json!(2));
    if let Some(caps) = caps {
        obj.insert("caps".to_string(), json!(caps));
    }
    if let Some(sc) = scope {
        obj.insert("identityScope".to_string(), json!(sc));
    }
    if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
        obj.insert("principalKind".to_string(), json!("delegated"));
        obj.insert("principalCeiling".to_string(), json!(ceiling));
        obj.insert("principalExpires".to_string(), json!(expires));
        obj.insert("principalMaxOffline".to_string(), json!(max_offline));
        obj.insert(
            "principalMaxOfflineCeiling".to_string(),
            json!(max_offline_ceiling),
        );
        obj.insert("principalIssued".to_string(), json!(now_secs()));
    }
    obj.insert(
        "addedAt".to_string(),
        json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)),
    );
    arr.push(Value::Object(obj));
    final_name
}

/// The writer's ownership guard: a cert under an existing name must match the
/// pinned key, and a secret under an existing name must be the same secret,
/// unless the caller holds the owner-decision opt-out. Pure.
pub fn refuse_unowned_rewrite(
    arr: &[Value],
    name: &str,
    secret: Option<&str>,
    cert: Option<&DeviceCert>,
    allow_reanchor: bool,
) -> Result<()> {
    if allow_reanchor {
        return Ok(());
    }
    let Some(existing) = arr.iter().find(|d| d["name"].as_str() == Some(name)) else {
        return Ok(());
    };
    if let Some(c) = cert {
        let incoming = hex::encode(c.device_pub);
        let pinned_matches = existing["deviceCert"]["devicePub"]
            .as_str()
            .is_some_and(|pinned| pinned == incoming.as_str());
        if !pinned_matches {
            anyhow::bail!(
                "refusing to re-anchor record '{name}': presented key {incoming} is not the pinned identity"
            );
        }
    }
    if let Some(s) = secret {
        if existing["secret"].as_str() != Some(s) {
            anyhow::bail!(
                "refusing to re-key record '{name}': a new pair secret for an existing device needs an owner re-pair (`tunlion add {name}` on the owner device)"
            );
        }
    }
    Ok(())
}

/// A name no record holds, compared case-insensitively. Pure.
pub fn free_device_name(arr: &[Value], name: &str) -> String {
    let taken = |n: &str| {
        arr.iter().any(|d| {
            d["name"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(n))
        })
    };
    if !taken(name) {
        return name.to_string();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{name}-{suffix}");
        if !taken(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Insert a NEW secret-only record and never touch an existing one. Pure.
pub fn insert_new_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: &str,
    introduced_by: Option<&str>,
) -> Result<String> {
    if arr.iter().any(|d| d["secret"].as_str() == Some(secret)) {
        anyhow::bail!("refusing to store a pair secret another device record already holds");
    }
    let free = free_device_name(arr, name);
    let stored = upsert_peer_record(arr, &free, Some(secret), None, None, None, None, None);
    if let Some(hub) = introduced_by {
        if let Some(rec) = arr
            .iter_mut()
            .find(|d| d["name"].as_str() == Some(stored.as_str()))
        {
            rec["introducedBy"] = json!(hub);
        }
    }
    Ok(stored)
}

/// Record the fleet owner a join acknowledgement certified, without re-keying
/// anything that is not provably that owner. Pure.
pub fn place_joined_owner(
    arr: &mut Vec<Value>,
    owner_name: &str,
    secret: &str,
    owner_cert: &DeviceCert,
    caps: &[String],
    scope: u8,
) -> Result<String> {
    let incoming = hex::encode(owner_cert.device_pub);
    let pinned_to = |d: &Value| d["deviceCert"]["devicePub"].as_str().map(str::to_string);
    if let Some(same) = arr
        .iter()
        .find(|d| pinned_to(d).as_deref() == Some(incoming.as_str()))
        .and_then(|d| d["name"].as_str().map(str::to_string))
    {
        return Ok(upsert_peer_record(
            arr,
            &same,
            Some(secret),
            Some(owner_cert),
            Some(caps),
            Some(scope),
            None,
            None,
        ));
    }
    if arr
        .iter()
        .any(|d| d["name"].as_str() == Some(owner_name) && pinned_to(d).is_some())
    {
        anyhow::bail!(
            "already have a different fleet owner recorded as '{owner_name}': forget it first, then join"
        );
    }
    if arr.iter().any(|d| d["secret"].as_str() == Some(secret)) {
        anyhow::bail!("refusing to store a pair secret another device record already holds");
    }
    let free = free_device_name(arr, owner_name);
    Ok(upsert_peer_record(
        arr,
        &free,
        Some(secret),
        Some(owner_cert),
        Some(caps),
        Some(scope),
        None,
        None,
    ))
}

/// Remove provisional identity records under `dir` older than
/// [`PROVISIONAL_TTL_SECS`] (by their `storedAt`, or the file's mtime when that
/// is unreadable). Returns how many were removed.
pub fn sweep_stale_provisional(dir: &Path, now: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in rd.flatten() {
        let path = entry.path();
        let is_provisional = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("provisional_") && n.ends_with(".json"));
        if !is_provisional {
            continue;
        }
        let stored_at = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v["storedAt"].as_u64())
            .or_else(|| {
                entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
            })
            .unwrap_or(0);
        if now.saturating_sub(stored_at) >= PROVISIONAL_TTL_SECS
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

