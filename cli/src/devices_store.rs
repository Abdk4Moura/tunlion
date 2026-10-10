//! The devices store: load, upsert and mutate `devices.json`, lifted out of
//! `main.rs`.
//!
//! The substrate every other capability and identity surface sits on:
//! `devices_path` (where the store lives), `devices_load` (read it, tolerating a
//! missing or malformed file), `with_devices_mut` (the write lock plus atomic
//! rewrite -- the one place mutating the store is safe), `devices_upsert_atomic`
//! (one-record upsert preserving v2 fields) and `upsert_peer_record` (the
//! peer-identity / capability write path).
//!
//! Re-exported from the crate root by `main.rs`, because `device_caps.rs`,
//! `identity_lifecycle.rs` and `renewal_lifecycle.rs` import these names from
//! there. No cfg or feature branches, no test hooks, no spawned tasks; every
//! function takes its inputs explicitly, so no ownership or loop-context change.
use crate::identity;
use crate::sanitize_device_name;
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn devices_path() -> PathBuf {
    crate::platform::Paths::config_path("devices.json")
}

/// Lock, read, mutate, and atomically write devices.json. The read-modify-write
/// is atomic across processes via the `devices.json.lock` sidecar (#238), so the
/// daemon's liveness sweep and a concurrent `grant`/`revoke`/`add`/`join` cannot
/// lose each other's update (a lost update is a revoke that reports success and
/// does not persist). The closure runs on the freshly-read array; if it returns
/// Err the file is NOT written (a bail must not clobber a valid store), and if
/// the store cannot be read or parsed the write is skipped too.
pub(crate) fn with_devices_mut<T>(f: impl FnOnce(&mut Vec<Value>) -> Result<T>) -> Result<T> {
    let _lock = crate::platform::DevicesFileLock::acquire()?;
    let p = devices_path();
    let mut arr: Vec<Value> = match std::fs::read_to_string(&p) {
        Ok(raw) => {
            serde_json::from_str(&raw).map_err(|e| anyhow::anyhow!("parse devices.json: {e}"))?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(anyhow::anyhow!("read devices.json: {e}")),
    };
    let out = f(&mut arr)?;
    crate::platform::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)
        .context("atomic write devices.json")?;
    Ok(out)
}

/// Pure merge step (no I/O): upsert the (secret, cert, caps, scope) fields for `name`
/// into `arr` as ONE record, returning the final stored name (auto-suffixed on a
/// new-name collision). This is the atomicity-relevant step: secret and cert land in
/// the SAME record object, so the single write that follows persists them together and
/// a reader can never observe new-secret + old-cert. Kept pure so the invariant is
/// unit-testable without the process-global config path.
pub(crate) fn upsert_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
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
            // A fresh enrollment is a NEW signed claim: its bounds WIN over any
            // prior record's, never merged (a device re-joining with a narrower
            // key must not inherit its wider old ceiling). Clearing the terminal
            // state is the revival of a LAPSED record by name continuity; a
            // REVOKED record is refused upstream before this write runs.
            existing["principalState"] = Value::Null;
            if let Some(map) = existing.as_object_mut() {
                map.remove("lapsedAt");
            }
        }
        return existing["name"].as_str().unwrap_or(name).to_string();
    }

    // New device: auto-suffix if collision.
    //
    // CASE-INSENSITIVE. An exact compare here meant `Laptop` and `laptop` became
    // two devices, and a petname is what `send --to <name>` targets, so a
    // near-duplicate is a targeting footgun rather than a cosmetic one. The
    // intent was already written down: `devices_name_taken` implements exactly
    // this and its doc comment says "(case-insensitive)". It was never wired,
    // and an unwired stricter check reads identically to dead code, which is how
    // it survived (WORK-STATE 1ad/1af).
    //
    // Fixed HERE rather than by calling that fn: it re-reads from disk via
    // `devices_load()`, while this call site works on an in-memory `arr` that is
    // mid-modification, so the two could disagree.
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
    }
    obj.insert(
        "addedAt".to_string(),
        json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        ),
    );
    arr.push(Value::Object(obj));
    final_name
}

/// Atomic per-peer (secret, cert) update: read-modify-write whole store via
/// `upsert_peer_record` (both fields in ONE record), persist via write-tmp-then-rename
/// (SecretFile::write already atomic on POSIX). A concurrent reader sees either the full
/// old peer or the full new peer, never a torn state.
/// `allow_reanchor` is the owner-agency escape hatch, and it is deliberately
/// a caller-visible boolean rather than inferred: re-anchoring a record to
/// a new device key is legitimate ONLY as a direct consequence of an
/// owner/user decision made outside this function (accepting an enrollment
/// or pairing ceremony, joining as the owner). The network-driven fleet
/// indexing path must always pass false -- a peer-asserted name may never
/// take over a pinned identity, which is the transplant the pin exists to
/// stop. Default to false unless the call site names the owner decision.
/// Whether `name` is pinned to a DIFFERENT device identity than `device_pub_hex`:
/// an exact-name record exists whose deviceCert.devicePub differs. Used by
/// enrollment to suffix to a fresh name instead of taking over (or refusing
/// outright) -- the check and the write are separate calls, so a concurrent
/// writer racing between them can only cause a refused enrollment, never a
/// takeover: the pin inside the write still refuses.
pub(crate) fn name_pinned_by_other(name: &str, device_pub_hex: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter().any(|d| {
        d["name"].as_str() == Some(name)
            && d["deviceCert"]["devicePub"]
                .as_str()
                .is_some_and(|p| p != device_pub_hex)
    })
}

/// The writer's ownership guard, pure so it is unit-testable without the
/// process-global config path. Runs inside `with_devices_mut`, in the SAME lock
/// cycle as the write it guards.
///
/// Records are keyed by identity; names are presentation. Two writes would
/// silently hand an existing record's grants to whoever presents them:
///
/// - a CERT under an existing name whose pinned key differs (a fleet sibling
///   naming itself after a ceilinged device; a record with NO pinned cert is
///   not a free slot either), and
/// - a SECRET under an existing name that differs from the stored one. The pair
///   secret IS the identity of a certless record (pair-proof resolves a link to
///   whichever record's secret matches), so replacing it in place keeps the
///   record's `caps`, `deviceCert`, `userKey` and every name-keyed grant
///   (`device_allows`, `ShellPolicy::Only`) and hands them to the new holder.
///   That is what a `pair-intro` or `pair-keep` naming an existing device did.
///
/// Both are refused unless the caller holds `allow_reanchor`, the explicit
/// owner decision (an owner-run `tunlion add`, joining under an owner-signed
/// invitation, re-enrolling the same key). Writing the SAME secret back is not
/// a re-key and passes. A network-driven write that wants a record must create
/// a NEW one: see `devices_store_new`.
pub(crate) fn refuse_unowned_rewrite(
    arr: &[Value],
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
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

/// A name no record holds, compared case-insensitively (the same rule as the
/// new-device branch of `upsert_peer_record`): `name` itself when free,
/// otherwise `name-2`, `name-3`, ...
pub(crate) fn free_device_name(arr: &[Value], name: &str) -> String {
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

/// Pure core of `devices_store_new`: insert a NEW secret-only record and never
/// touch an existing one. The name is suffixed past any record that already
/// holds it, and a secret some record already holds is refused outright (two
/// records answering the same pair-proof would make the link's identity depend
/// on store order). `introduced_by` marks a vouched record with the device that
/// vouched for it, so a vouched record cannot vouch in turn.
pub(crate) fn insert_new_peer_record(
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

/// Pure core of `devices_store_joined_owner`: record the fleet owner a join
/// acknowledgement certified, without re-keying anything that is not provably
/// that owner.
///
/// Join used to write under the invitation's owner name with `allow_reanchor`,
/// guarded only by `name_pinned_by_other`, which sees records that carry a
/// certificate. A secret-only or vouched record that happened to share the
/// owner's name had no certificate to compare, so the join rewrote its secret
/// and attached the owner's certificate in place: the record kept its `caps`,
/// `deniedCaps` and every name-keyed grant, and the owner's identity inherited
/// them. `allow_reanchor` also skipped `refuse_unowned_rewrite`, so nothing else
/// stopped it.
///
/// Only a record already pinned to the owner's DEVICE key is the same device,
/// and only that one is updated in place (a re-join). A record pinned to a
/// different key under the owner's name is refused, as before. Everything else,
/// certless records included, is someone else's: the owner lands in a NEW
/// record under a free (suffixed) name and the existing one is untouched.
/// `joined_owner_record` finds the owner by certificate, never by name, so the
/// suffix changes nothing downstream.
pub(crate) fn place_joined_owner(
    arr: &mut Vec<Value>,
    owner_name: &str,
    secret: &str,
    owner_cert: &identity::DeviceCert,
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

/// Record the fleet owner after a join. See `place_joined_owner`. Same lock
/// cycle as every other store write, so the decision and the write cannot be
/// separated by a concurrent writer.
pub(crate) fn devices_store_joined_owner(
    owner_name: &str,
    secret: &str,
    owner_cert: &identity::DeviceCert,
    caps: &[String],
    scope: u8,
) -> Result<String> {
    let clean = sanitize_device_name(owner_name);
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).context("create config dir")?;
    }
    with_devices_mut(|arr| place_joined_owner(arr, &clean, secret, owner_cert, caps, scope))
}

/// Store a pair secret handed to us over the NETWORK (`pair-keep`,
/// `pair-intro`) as a NEW record and return the name it landed under. Never
/// re-keys an existing record, whatever name the peer asked for: a peer that
/// could name its secret after an existing device would inherit that device's
/// grants. Same lock cycle as every other store write.
pub(crate) fn devices_store_new(
    name: &str,
    secret: &str,
    introduced_by: Option<&str>,
) -> Result<String> {
    let clean = sanitize_device_name(name);
    let p = devices_path();
    if let Some(dir) = p.parent() {
        std::fs::create_dir_all(dir).context("create config dir")?;
    }
    with_devices_mut(|arr| insert_new_peer_record(arr, &clean, secret, introduced_by))
}

/// Whether the record `name` was created by a `pair-intro` (it carries
/// `introducedBy`). A vouched device may not vouch for others: introductions
/// come from a device the owner paired directly, never transitively.
pub(crate) fn device_was_introduced(name: &str) -> bool {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return false;
    };
    let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
        return false;
    };
    arr.iter()
        .find(|d| d["name"].as_str() == Some(name))
        .is_some_and(|d| d.get("introducedBy").is_some_and(|v| !v.is_null()))
}

pub(crate) fn devices_upsert_atomic(
    name: &str,
    secret: Option<&str>,
    cert: Option<&identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
    allow_reanchor: bool,
) -> Result<String> {
    let clean = sanitize_device_name(name);
    let name = clean.as_str();
    let p = devices_path();
    if let Some(dir) = p.parent() {
        crate::platform::create_private_dir_all(dir).context("create config dir")?;
    }
    with_devices_mut(|arr| {
        // Identity pinning: records are keyed by identity, names are
        // presentation. A cert write under an existing name is refused
        // unless the incoming key matches the record's pinned one, and a
        // secret write under an existing name is refused unless it is the
        // secret already stored, in both cases unless the caller holds the
        // owner-decision opt-out (see `refuse_unowned_rewrite`). Refused
        // HERE, in the writer, in the SAME lock cycle as the write -- never
        // delegated to callers and with no TOCTOU window between check and
        // write.
        refuse_unowned_rewrite(arr, name, secret, cert, allow_reanchor)?;
        let final_name = upsert_peer_record(
            arr,
            name,
            secret,
            cert,
            caps,
            scope,
            user_key_hex,
            delegated,
        );
        Ok(final_name)
    })
}

pub(crate) fn devices_load() -> Vec<(String, String)> {
    let Ok(raw) = std::fs::read_to_string(devices_path()) else {
        return Vec::new();
    };
    serde_json::from_str::<Value>(&raw)
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|d| {
                        Some((
                            d["name"].as_str()?.to_string(),
                            d["secret"].as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}
