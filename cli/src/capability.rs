//! Capability/grant layer — CLI-side ORCHESTRATION over `filament-cap`.
//!
//! The reusable primitives, the two owner-signed objects, the pure `evaluate`,
//! the monotonic store logic, the restrictive composers, preview/self-lockout
//! and the crypto now live in the `filament-cap` crate and are re-exported below
//! so every existing `crate::capability::X` call site resolves unchanged.
//!
//! What STAYS here is bound to the host and cannot move without creating a
//! cli→filament-cap→cli cycle:
//!   - store file I/O (`load_cap_store` / `save_cap_store` over
//!     `platform::SecretFile`) + its read cache (`CAP_CACHE`),
//!   - the env mode flag (`cap_authoritative`),
//!   - the process-static observability counters that `cap-status` reads
//!     (`cap_shadow_counts` / `cap_action_counts`) + `log_once`,
//!   - the two glue gates `cap_authorize` (loads the store) and
//!     `cap_gate_effective` (mutates the counters, reads the mode),
//!   - `devices_with_shell_revoked` (reads a `crate::identity::DeviceCert`) and
//!     `reconcile_shell_keys` (edits `crate::sshkeys`).
//! These call INTO `filament-cap`; the crate never calls back.

pub use filament_cap::capability::*;

use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

// ---------------------------------------------------------------------------
// File-based store I/O  (thin wrappers, mirror update_peer_identity)
// ---------------------------------------------------------------------------

/// Cache cap store reads per config_dir, invalidated on every write.
/// Hot path: load_cap_store is called on every gated open; without this cache
/// each open re-reads + re-parses caps.json.
type CachedStore = (std::path::PathBuf, u128, Vec<Value>); // (path, mtime_nanos, parsed)
static CAP_CACHE: OnceLock<Mutex<Option<CachedStore>>> = OnceLock::new();

fn cache_init() -> &'static Mutex<Option<CachedStore>> {
    CAP_CACHE.get_or_init(|| Mutex::new(None))
}

/// Load the capability store from `caps.json` in the filament config dir.
/// Cached: subsequent calls with unchanged mtime return the cached store.
pub fn load_cap_store(config_dir: &std::path::Path) -> Vec<Value> {
    let p = config_dir.join("caps.json");

    // Check mtime of the file for cache invalidation. NANOSECOND precision:
    // seconds-only mtime would serve stale data for two writes in the same second
    // (a direct file rewrite that bypasses save_cap_store's explicit invalidation).
    let mtime = std::fs::metadata(&p)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos());

    if let Some(mtime_val) = mtime {
        let cache = cache_init().lock().unwrap();
        if let Some((cached_path, cached_mtime, cached_store)) = cache.as_ref() {
            if cached_path == &p && *cached_mtime == mtime_val {
                return cached_store.clone();
            }
        }
    }

    // Cache miss: read + parse
    let store = std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    // Cache store with mtime
    if let Some(mtime_val) = mtime {
        let mut cache = cache_init().lock().unwrap();
        *cache = Some((p, mtime_val, store.clone()));
    }

    store
}

/// Persist the capability store to `caps.json` (module-internal).
/// Callers MUST use `save_and_list_revoked` so reconciliation is a property
/// of the write. INVALIDATES the read cache so next cap_authorize sees the
/// fresh store immediately, never stale after a grant/revoke.
pub(crate) fn save_cap_store(config_dir: &std::path::Path, store: &[Value]) -> std::io::Result<()> {
    let p = config_dir.join("caps.json");
    let data = serde_json::to_string_pretty(&serde_json::json!(store))
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    crate::platform::SecretFile::write_str(&p, &data)?;
    // Invalidate cache: next load_cap_store will see the new mtime and re-read.
    let cache = cache_init();
    if let Ok(mut c) = cache.lock() {
        *c = None;
    }
    Ok(())
}

/// Persist the cap store, then return the devices whose shell keys must be
/// reconciled. Reconciliation is a property of the WRITE: any code path that
/// saves the cap store MUST process the returned list (gated on authoritative,
/// filtered by `sshkeys::has_block`), so a future sync path cannot forget it.
pub fn save_and_list_revoked(
    store: &[Value],
    config_dir: &std::path::Path,
) -> std::io::Result<Vec<String>> {
    save_cap_store(config_dir, store)?;
    Ok(devices_with_shell_revoked(config_dir))
}

/// Returns true when capability enforcement is AUTHORITATIVE (live-gating).
/// Read this in ONE place only, `cap_gate_effective`, the single policy site.
///
/// FLIP THROWN (0.7): authoritative enforcement is now the DEFAULT. Devices
/// without a matching grant are denied shell/transfer/mount. Opt out (return to
/// legacy shadow gating) by setting `FILAMENT_CAP_AUTHORITATIVE=0` (or `false`);
/// unsetting the var leaves enforcement ON. The env var is the rollback.
///
/// Historical FLIP CRITERION (satisfied before the throw) lived on
/// `ShadowCounts::flip_ready`: flip only when `la_authorized > 0` AND
/// `la_denied == 0` AND `la_no_header == 0`, and the throw commit cited the full
/// shadow counts including `ld_authorized` (the WIDENING count). See
/// docs/cap-flip-checklist.md for the evidence trail.
pub fn cap_authoritative() -> bool {
    std::env::var("FILAMENT_CAP_AUTHORITATIVE")
        .map(|x| x != "0" && !x.eq_ignore_ascii_case("false"))
        .unwrap_or(true)
}

// Shadow counters bucketed by the LEGACY decision AND by three cap outcomes:
// authorized, denied (a header EXISTS and refused, a real disagreement), and
// no-header (the resource is UNPROVISIONED, not a disagreement). The only opens a
// flip can change are legacy-ALLOWED ones; a cap-deny on a legacy-denied open
// alters nothing. Keeping ABSENT separate from DENIED is what stops a fresh,
// unprovisioned node from flooding CRITICAL on every normal open and from making
// the flip criterion unsatisfiable.
//
// Per-action shadow counters allow the flip decision to cite a COVERAGE MATRIX
// (which actions were exercised?) rather than a single numeric threshold that
// 1000 shell opens could satisfy while mount/transfer were never tested.
static LA_AUTHORIZED: AtomicU64 = AtomicU64::new(0);
static LA_DENIED: AtomicU64 = AtomicU64::new(0);
static LA_NO_HEADER: AtomicU64 = AtomicU64::new(0);
static LD_AUTHORIZED: AtomicU64 = AtomicU64::new(0);
static LD_DENIED: AtomicU64 = AtomicU64::new(0);
static LD_NO_HEADER: AtomicU64 = AtomicU64::new(0);

/// Dedicated counter for auth-key ceiling denials. Mode-independent (counted in
/// BOTH authoritative and shadow), OUTSIDE the flip criterion — a ceiling denial
/// is NOT something the flip changes. Exposed in cap-status for delegated-
/// enforcement review.
static CEILING_DENIED: AtomicU64 = AtomicU64::new(0);
static PA_CEILING_DENIED: OnceLock<ActionCounters> = OnceLock::new();

type ActionCounters = Mutex<HashMap<String, AtomicU64>>;

static PA_LA_AUTHORIZED: OnceLock<ActionCounters> = OnceLock::new();
static PA_LA_DENIED: OnceLock<ActionCounters> = OnceLock::new();
static PA_LA_NO_HEADER: OnceLock<ActionCounters> = OnceLock::new();
static PA_LD_AUTHORIZED: OnceLock<ActionCounters> = OnceLock::new();
static PA_LD_DENIED: OnceLock<ActionCounters> = OnceLock::new();
static PA_LD_NO_HEADER: OnceLock<ActionCounters> = OnceLock::new();

#[allow(dead_code)]
fn pa_get(map: &ActionCounters, action: &str) -> u64 {
    map.lock().unwrap().get(action).map(|a| a.load(Ordering::Relaxed)).unwrap_or(0)
}

fn pa_inc(map: &ActionCounters, action: &str) {
    map.lock().unwrap()
        .entry(action.to_string())
        .or_insert_with(|| AtomicU64::new(0))
        .fetch_add(1, Ordering::Relaxed);
}

/// Return per-action shadow counts for every action seen so far.
pub fn cap_action_counts() -> Vec<ActionCounts> {
    let mut actions: HashMap<String, ActionCounts> = HashMap::new();
    let maps: [(&ActionCounters, fn(&mut ActionCounts, &str, u64)); 6] = [
        (PA_LA_AUTHORIZED.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.la_authorized += val),
        (PA_LA_DENIED.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.la_denied += val),
        (PA_LA_NO_HEADER.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.la_no_header += val),
        (PA_LD_AUTHORIZED.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.ld_authorized += val),
        (PA_LD_DENIED.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.ld_denied += val),
        (PA_LD_NO_HEADER.get_or_init(|| Mutex::new(HashMap::new())), |a, _action, val| a.ld_no_header += val),
    ];
    for (map, setter) in maps {
        for (action, val) in map.lock().unwrap().iter() {
            let entry = actions.entry(action.clone()).or_insert_with(|| ActionCounts {
                action: action.clone(),
                la_authorized: 0, la_denied: 0, la_no_header: 0,
                ld_authorized: 0, ld_denied: 0, ld_no_header: 0,
            });
            setter(entry, action, val.load(Ordering::Relaxed));
        }
    }
    let mut v: Vec<_> = actions.into_values().collect();
    v.sort_by(|a, b| a.action.cmp(&b.action));
    v
}

/// Shadow counts since start. The FLIP CRITERION reads only the legacy-ALLOWED
/// buckets: flip when `la_authorized > 0` (a real, meaningful sample) AND
/// `la_denied == 0` (no header disagrees) AND `la_no_header == 0` (every reachable
/// resource is provisioned). A missing header is `la_no_header`, never `la_denied`,
/// so an unprovisioned node cannot be mistaken for a disagreement and cannot make
/// the criterion unreachable.
pub fn cap_shadow_counts() -> ShadowCounts {
    ShadowCounts {
        la_authorized: LA_AUTHORIZED.load(Ordering::Relaxed),
        la_denied: LA_DENIED.load(Ordering::Relaxed),
        la_no_header: LA_NO_HEADER.load(Ordering::Relaxed),
        ld_authorized: LD_AUTHORIZED.load(Ordering::Relaxed),
        ld_denied: LD_DENIED.load(Ordering::Relaxed),
        ld_no_header: LD_NO_HEADER.load(Ordering::Relaxed),
        ceiling_denied: CEILING_DENIED.load(Ordering::Relaxed),
    }
}

/// Log `msg` at most once per distinct `key` for the process lifetime, so shadow
/// diagnostics that recur per open (unprovisioned resources, widening opens) do not
/// flood. The reviewer needs the SET of distinct cases to enumerate; the lossless
/// volume already lives in the counters. The dedup set is CAPPED, because a key
/// space like distinct device_pubs is unbounded; past the cap, new keys stop logging
/// (their count is still counted), bounding memory.
fn log_once(key: String, msg: &str) {
    const LOG_ONCE_CAP: usize = 4096;
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
    if let Ok(mut g) = seen.lock() {
        if g.contains(&key) || g.len() >= LOG_ONCE_CAP {
            return;
        }
        g.insert(key);
        eprintln!("{msg}");
    }
}

/// Bridging authorization: loads the cap store, finds the header for `resource`,
/// and returns the REAL cap outcome. It never abstains and never reads the mode, so
/// its return value is always the truth about the capability decision. The mode
/// (shadow vs authoritative), the counters, and the logging all live in
/// `cap_gate_effective`, the single policy site.
///
/// Returns `Unprovisioned` when no header exists for `resource` (distinct from
/// `Denied`, where a header exists and refused), so callers can tell "provision
/// this node" from "the grants disagree".
pub fn cap_authorize(
    config_dir: &std::path::Path,
    resource: &str,
    action: &str,
    principal_device_pub: Option<&[u8; 32]>,
    principal_user_pub: Option<&[u8; 32]>,
    auth_key_caps: Option<&[String]>,
) -> CapOutcome {
    let store = load_cap_store(config_dir);
    let header = store
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some(resource)
        })
        .and_then(CapHeader::from_json);

    let device_pub = principal_device_pub.copied().unwrap_or([0u8; 32]);
    let user_pub = principal_user_pub.copied().unwrap_or([0u8; 32]);

    match header {
        None => CapOutcome::Unprovisioned,
        Some(hdr) => match evaluate(
            &store, &hdr, &device_pub, &user_pub, resource, action, now_secs(), auth_key_caps,
        ) {
            Decision::Authorized => CapOutcome::Authorized,
            Decision::Denied(reason) => CapOutcome::Denied(reason),
        },
    }
}

/// The single policy site. Reads the mode ONCE, records the shadow counters in BOTH
/// modes (so observability survives the flip), logs, and returns the effective gate
/// decision. `binding` and `cert_expires` are transport/policy facts composed under
/// authoritative (purely restrictive).
pub fn cap_gate_effective(
    legacy_allowed: bool,
    outcome: &CapOutcome,
    action: &str,
    resource: &str,
    device_pub: Option<&[u8; 32]>,
    user_pub: Option<&[u8; 32]>,
    binding: BindingStrength,
    cert_expires: Option<u64>,
    auth_key_caps: Option<&[String]>,
) -> GateDecision {
    let authoritative = cap_authoritative();

    // === Delegated-principal ceiling (check 2 of 2) ===================
    // Auth key ceiling applies UNCONDITIONALLY in both modes. Purely restrictive
    // (Authorized→Denied), no-op for non-delegated (None). A delegated principal
    // MUST never receive legacy_allowed if its ceiling denies the action.
    //
    // DEFENSE-IN-DEPTH — the SAME ceiling is also enforced inside
    // `filament_cap::capability::evaluate` (ahead of the owner shortcut). Each
    // check is sufficient on its own; both are retained DELIBERATELY. After the
    // crate split each is invisible from the other side of the boundary, so this
    // note pins them together: see the mirror comment in evaluate.
    //
    // NON-NEGOTIABLE: this check must NEVER be removed on the grounds that
    // evaluate already does it. In SHADOW mode the effective decision is
    // `legacy_allowed`, and evaluate's result is DISCARDED — so THIS check is the
    // ONLY thing enforcing the delegated ceiling in shadow. Deleting it would let
    // a delegated principal exceed its ceiling on every legacy-allowed open until
    // the flip. That is what makes it load-bearing, not stylistic.
    if let Some(caps) = auth_key_caps {
        let action_lc = action.to_lowercase();
        if !caps.iter().any(|c| c.to_lowercase() == action_lc) {
            // Dedicated ceiling counter — mode-independent (both shadow AND
            // authoritative increment it), OUTSIDE flip_ready. A ceiling denial
            // does NOT change at the flip, so it doesn't belong in LA_/LD_.
            CEILING_DENIED.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_CEILING_DENIED.get_or_init(|| Mutex::new(HashMap::new())), action);
            return GateDecision::Deny { cap_reason: Some("not in auth key caps".into()) };
        }
    }

    // Compose restrictive gates under authoritative (order-independent:
    // both are purely restrictive — Authorized→Denied or pass-through).
    let outcome = &cap_authorize_proven(
        outcome, binding, authoritative,
    );
    let outcome = &cap_authorize_expired(
        outcome, cert_expires, authoritative,
    );

    // Counters: recorded in BOTH modes so a flip does not blind us.
    // Per-action bucketing runs in parallel so the flip decision can cite
    // a coverage matrix, not just a total that 1000 shell opens could satisfy
    // while mount/transfer were never tested.
    match (legacy_allowed, outcome) {
        (true, CapOutcome::Authorized) => {
            LA_AUTHORIZED.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LA_AUTHORIZED.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
        (true, CapOutcome::Denied(_)) => {
            LA_DENIED.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LA_DENIED.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
        (true, CapOutcome::Unprovisioned) => {
            LA_NO_HEADER.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LA_NO_HEADER.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
        (false, CapOutcome::Authorized) => {
            LD_AUTHORIZED.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LD_AUTHORIZED.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
        (false, CapOutcome::Denied(_)) => {
            LD_DENIED.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LD_DENIED.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
        (false, CapOutcome::Unprovisioned) => {
            LD_NO_HEADER.fetch_add(1, Ordering::Relaxed);
            pa_inc(PA_LD_NO_HEADER.get_or_init(|| Mutex::new(HashMap::new())), action);
        }
    }

    let effective = if authoritative {
        matches!(outcome, CapOutcome::Authorized)
    } else {
        legacy_allowed
    };

    let dev = device_pub.copied().unwrap_or([0u8; 32]);
    let usr = user_pub.copied().unwrap_or([0u8; 32]);

    if !authoritative {
        // Shadow: surface the two directions that matter for a flip. BREAKAGE, a
        // header that DENIES an open legacy allowed (CRITICAL). WIDENING, an open
        // legacy refused that cap authorizes, which the flip will newly permit.
        // Unprovisioned is logged once per resource so a fresh node never floods.
        match (legacy_allowed, outcome) {
            (true, CapOutcome::Denied(reason)) => {
                eprintln!(
                    "CAP-SHADOW CRITICAL: a header EXISTS and DENIES '{action}' on '{resource}' for dev={} user={} that legacy ALLOWED (reason: {reason}); a flip would BREAK this open [{}]",
                    hex::encode(dev),
                    hex::encode(usr),
                    cap_shadow_counts().summary(),
                );
            }
            (true, CapOutcome::Unprovisioned) => log_once(
                format!("nh|{resource}"),
                &format!(
                    "CAP-SHADOW [unprovisioned]: resource '{resource}' has no capability header; opens rely on legacy authz. Expected until you provision (filament grant/init); not a disagreement."
                ),
            ),
            // Dedupe WIDENING by the (action, resource, device) triple: the reviewer
            // needs the distinct SET to enumerate, not one line per retry, and the
            // count is preserved losslessly in ld_authorized. Print the user too: a
            // widening can come from a user_pub-targeted grant, so the user is part
            // of the "why" a reviewer enumerates.
            (false, CapOutcome::Authorized) => log_once(
                format!("wd|{action}|{resource}|{}", hex::encode(dev)),
                &format!(
                    "CAP-SHADOW WIDENING: '{action}' on '{resource}' for dev={} user={} was REFUSED by legacy but cap AUTHORIZES; a flip will NEWLY PERMIT this open. Enumerate it in the flip decision.",
                    hex::encode(dev),
                    hex::encode(usr),
                ),
            ),
            _ => {}
        }
    } else {
        // Authoritative: the gate surfaces the reason now, so the dedicated
        // CAP-DENY [authoritative] eprintln block is removed. The operator sees
        // the real reason through GateDecision::deny_reason().
    }

    if effective {
        GateDecision::Allow
    } else if authoritative {
        let reason = match outcome {
            CapOutcome::Denied(r) => r.clone(),
            CapOutcome::Unprovisioned => "resource unprovisioned (no capability header); run filament grant/init".to_string(),
            CapOutcome::Authorized => String::new(),
        };
        GateDecision::Deny { cap_reason: Some(reason) }
    } else {
        GateDecision::Deny { cap_reason: None }
    }
}

/// Compute the set of devices whose managed authorized_keys blocks must be
/// removed because the capability layer no longer authorizes `shell`.
/// Returns petnames. Called by the shell-key reconciler on daemon start
/// and on cap-store change. Idempotent — running it with no drift is a no-op.
pub fn devices_with_shell_revoked(config_dir: &std::path::Path) -> Vec<String> {
    let cap_store = load_cap_store(config_dir);
    let devices_path = config_dir.join("devices.json");
    let devices: Vec<Value> = std::fs::read_to_string(&devices_path)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default();

    let header = cap_store
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        })
        .and_then(CapHeader::from_json);

    let Some(hdr) = header else {
        return Vec::new(); // No header = no cap store to enforce, nothing to revoke
    };

    let now = now_secs();
    let mut revoked = Vec::new();

    for entry in &devices {
        let name = entry["name"].as_str().unwrap_or("");
        if name.is_empty() {
            continue;
        }
        // Extract device_pub and user_pub from stored cert
        let cert_json = match entry.get("deviceCert") {
            Some(cj) => cj,
            None => continue,
        };
        let Some(cert) = crate::identity::DeviceCert::from_json(cert_json) else {
            continue;
        };

        let d = evaluate(
            &cap_store,
            &hdr,
            &cert.device_pub,
            &cert.user_pub,
            &hdr.resource,
            "shell",
            now,
            None,
        );
        if matches!(d, Decision::Denied(_)) {
            revoked.push(name.to_string());
        }
    }

    revoked
}

/// Gated shell-key reconciliation: strips managed authorized_keys blocks for
/// `revoked` devices from `ak_content`. Under authoritative, blocks are stripped;
/// in shadow, content is returned UNCHANGED (report-only). Caller emits per-device
/// WOULD-remove log lines in shadow from the `revoked` list, then writes the returned
/// content only when it differs from the input.
pub fn reconcile_shell_keys(revoked: &[String], ak_content: &str, authoritative: bool) -> String {
    if !authoritative {
        return ak_content.to_string();
    }
    let mut content = ak_content.to_string();
    for device in revoked {
        content = crate::sshkeys::strip_block(&content, device);
    }
    content
}

// ---------------------------------------------------------------------------
// Tests (the glue subset: store-I/O, observability counters, DeviceCert-backed
// reconciliation. The pure signed-object / evaluate / composer tests live in
// the filament-cap crate.)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_owner() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }

    fn owner_pub(keypair: &Ed25519KeyPair) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(keypair.public_key().as_ref());
        buf
    }

    fn make_grant(
        owner: &Ed25519KeyPair,
        target: CapTarget,
        resource: &str,
        permissions: &[&str],
        version: u64,
        ttl_secs: u64,
    ) -> CapOp {
        let grantor = owner_pub(owner);
        let issued_at = now_secs();
        let mut op = CapOp {
            op: CapOpKind::Grant,
            grantor,
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: resource.to_string(),
            permissions: permissions.iter().map(|s| s.to_string()).collect(),
            expires: issued_at.saturating_add(ttl_secs),
            issued_at,
            version,
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, owner);
        op
    }

    fn make_revoke(
        owner: &Ed25519KeyPair,
        target: CapTarget,
        resource: &str,
        version: u64,
        ttl_secs: u64,
    ) -> CapOp {
        let grantor = owner_pub(owner);
        let issued_at = now_secs();
        let mut op = CapOp {
            op: CapOpKind::Revoke,
            grantor,
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: resource.to_string(),
            permissions: vec![],
            expires: issued_at.saturating_add(ttl_secs),
            issued_at,
            version,
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, owner);
        op
    }

    fn make_self_header(pk: &[u8; 32], resource: &str, nonce: &[u8; 32], owner: &Ed25519KeyPair) -> CapHeader {
        let mut h = CapHeader {
            resource: resource.to_string(), epoch: 0, owner_pub: *pk,
            nonce: *nonce, floors: vec![],
            issued_at: now_secs(), prev_owner_pub: None, prev_header_hash: None, sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, owner);
        CapHeader { resource: "self".to_string(), ..h }
    }

    // Unique per-test dir (name suffix) so parallel cache tests never share a
    // caps.json — they'd otherwise race on the same file and the global cache.
    fn temp_dir(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("filament-cap-test-{}-{}", std::process::id(), name))
    }

    /// Zero-config: a resource with no header is UNPROVISIONED, distinct from a
    /// header that denies. cap_gate_effective keeps legacy authoritative in shadow,
    /// so a fresh owner is never locked out, and buckets this as no-header (not a
    /// disagreement) so it neither floods CRITICAL nor blocks the flip criterion.
    #[test]
    fn cap_authorize_no_header_is_unprovisioned() {
        let tmp = std::env::temp_dir().join(format!("fil-cap-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let d = cap_authorize(&tmp, "self", "shell", Some(&[0xcc; 32]), Some(&[0xaa; 32]), None);
        match d {
            CapOutcome::Unprovisioned => {}
            other => panic!("no-header must be Unprovisioned, got {other:?}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Delegated ceiling: a principal with auth_key_caps=[transfer] is
    /// Authorized for transfer but Denied for shell, even when the owner
    /// has both — the ceiling gates BEFORE the owner shortcut.
    /// Enters at cap_authorize (the PRODUCTION boundary), not evaluate.
    #[test]
    fn delegated_ceiling_gates_before_owner_shortcut() {
        let owner = make_owner();
        let owner_pub = owner_pub(&owner);
        let mut nonce = [0u8; 32];
        let rng = ring::rand::SystemRandom::new();
        ring::rand::SecureRandom::fill(&rng, &mut nonce).unwrap();
        let header = make_self_header(&owner_pub, "self", &nonce, &owner);
        let tmp = std::env::temp_dir().join(format!("fil-authcap-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        save_cap_store(&tmp, &[header.to_json()]).unwrap();
        let ak_caps = vec!["transfer".to_string()];
        // Same user_pub as header owner — normally shortcut to Authorized.
        // auth_key_caps ceiling gates first: transfer in caps → Authorized
        let r1 = cap_authorize(&tmp, "self", "transfer", Some(&[0xCC; 32]), Some(&owner_pub), Some(&ak_caps));
        assert_eq!(r1, CapOutcome::Authorized,
            "transfer in auth_key_caps must authorize (ceiling passed)");
        // Shell NOT in auth_key_caps → Denied
        let r2 = cap_authorize(&tmp, "self", "shell", Some(&[0xCC; 32]), Some(&owner_pub), Some(&ak_caps));
        assert!(matches!(r2, CapOutcome::Denied(_)),
            "shell not in auth_key_caps must be denied (ceiling enforced)");
        // Mount NOT in auth_key_caps → Denied
        let r3 = cap_authorize(&tmp, "self", "mount", Some(&[0xCC; 32]), Some(&owner_pub), Some(&ak_caps));
        assert!(matches!(r3, CapOutcome::Denied(_)),
            "mount not in auth_key_caps must be denied (ceiling enforced)");
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Per-action shadow counters must bucket each action independently so
    /// the flip decision can cite a coverage matrix, not just a total.
    /// One mis-bucketed counter could satisfy flip_ready silently.
    #[test]
    fn per_action_counters_bucket_correctly() {
        // Fresh owner + unknown principal; no actual store so outcome is
        // Unprovisioned (no cap header on disk). We test the counter
        // increment path directly via cap_gate_effective.
        //
        // This proves BUCKETING (which (legacy, cap-outcome) pair increments
        // which counter), not gate behavior. Since the authoritative-default
        // flip (0.7), cap_gate_effective reads FILAMENT_CAP_AUTHORITATIVE which
        // now defaults ON, so the restrictive gates run. We pass Proven binding
        // + Some(u64::MAX) cert expiry so cap_authorize_proven/expired are BOTH
        // no-ops (a valid, proven, live cert), leaving the raw cap outcome to be
        // counted verbatim in BOTH modes. The gates' downgrade behavior is
        // covered by their own both-branches tests in filament-cap.
        let uk = [0xaa; 32];
        // Legacy-allowed, cap denies (Unprovisioned) → la_no_header
        for action in ["shell", "mount"] {
            cap_gate_effective(true, &CapOutcome::Unprovisioned, action, "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        }
        // Legacy-allowed, cap denies (Denied) → la_denied
        cap_gate_effective(true, &CapOutcome::Denied("test".into()), "transfer", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        // Legacy-denied, cap authorizes → ld_authorized (widening)
        cap_gate_effective(false, &CapOutcome::Authorized, "mount", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);

        let ac = cap_action_counts();

        // The counters are process-global and cumulative across ALL tests.
        // Verify specific invariants:
        // 1. Per-action counts are a subset of global counts
        let global = cap_shadow_counts();
        let total_pa_la: u64 = ac.iter().map(|a| a.la_authorized).sum();
        let total_pa_ld: u64 = ac.iter().map(|a| a.la_denied).sum();
        let total_pa_ln: u64 = ac.iter().map(|a| a.la_no_header).sum();
        let total_pa_wa: u64 = ac.iter().map(|a| a.ld_authorized).sum();
        let total_pa_wd: u64 = ac.iter().map(|a| a.ld_denied).sum();
        let total_pa_wn: u64 = ac.iter().map(|a| a.ld_no_header).sum();

        assert!(total_pa_la <= global.la_authorized,
            "per-action la_authorized sum ({total_pa_la}) <= global ({})", global.la_authorized);
        assert!(total_pa_ld <= global.la_denied);
        assert!(total_pa_ln <= global.la_no_header);
        assert!(total_pa_wa <= global.ld_authorized);
        assert!(total_pa_wd <= global.ld_denied);
        assert!(total_pa_wn <= global.ld_no_header);

        // The per-action counters we just incremented MUST appear for the
        // actions we touched.
        let find = |action: &str, expected: bool| {
            for a in &ac {
                if a.action == action { return true; }
            }
            if expected { panic!("action '{action}' must appear in per-action counters"); }
            false
        };
        assert!(find("shell", true));
        assert!(find("mount", true));
        assert!(find("transfer", true));
    }

    /// Detector proof: one input per outcome bucket, asserting each increments
    /// exactly the right global counter and no sibling. A mis-bucketed increment
    /// would satisfy flip_ready() silently, so this proves the instrument before any
    /// rig reading is trusted. Delta-based, since the counters are process-global.
    #[test]
    fn shadow_detector_proof_six_buckets() {
        // Mode-independent since the 0.7 authoritative-default flip: pass
        // Proven binding + Some(u64::MAX) expiry so the restrictive gates are
        // no-ops and each (legacy, cap-outcome) pair is counted verbatim,
        // whether FILAMENT_CAP_AUTHORITATIVE is on (default) or off (shadow).
        let uk = [0xaa; 32];

        fn snap() -> [u64; 6] {
            [
                LA_AUTHORIZED.load(Ordering::Relaxed),
                LA_DENIED.load(Ordering::Relaxed),
                LA_NO_HEADER.load(Ordering::Relaxed),
                LD_AUTHORIZED.load(Ordering::Relaxed),
                LD_DENIED.load(Ordering::Relaxed),
                LD_NO_HEADER.load(Ordering::Relaxed),
            ]
        }

        // (legacy_allowed=true, Authorized) -> LA_AUTHORIZED++
        let before = snap();
        cap_gate_effective(true, &CapOutcome::Authorized, "shell", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 1, "LA_AUTHORIZED must increment");
        assert_eq!(after[1] - before[1], 0);
        assert_eq!(after[2] - before[2], 0);
        assert_eq!(after[3] - before[3], 0);
        assert_eq!(after[4] - before[4], 0);
        assert_eq!(after[5] - before[5], 0);

        // (legacy_allowed=true, Denied) -> LA_DENIED++
        let before = snap();
        cap_gate_effective(true, &CapOutcome::Denied("test".into()), "mount", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 0);
        assert_eq!(after[1] - before[1], 1, "LA_DENIED must increment");
        assert_eq!(after[2] - before[2], 0);
        assert_eq!(after[3] - before[3], 0);
        assert_eq!(after[4] - before[4], 0);
        assert_eq!(after[5] - before[5], 0);

        // (legacy_allowed=true, Unprovisioned) -> LA_NO_HEADER++
        let before = snap();
        cap_gate_effective(true, &CapOutcome::Unprovisioned, "transfer", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 0);
        assert_eq!(after[1] - before[1], 0);
        assert_eq!(after[2] - before[2], 1, "LA_NO_HEADER must increment");
        assert_eq!(after[3] - before[3], 0);
        assert_eq!(after[4] - before[4], 0);
        assert_eq!(after[5] - before[5], 0);

        // (legacy_allowed=false, Authorized) -> LD_AUTHORIZED++
        let before = snap();
        cap_gate_effective(false, &CapOutcome::Authorized, "shell", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 0);
        assert_eq!(after[1] - before[1], 0);
        assert_eq!(after[2] - before[2], 0);
        assert_eq!(after[3] - before[3], 1, "LD_AUTHORIZED must increment");
        assert_eq!(after[4] - before[4], 0);
        assert_eq!(after[5] - before[5], 0);

        // (legacy_allowed=false, Denied) -> LD_DENIED++
        let before = snap();
        cap_gate_effective(false, &CapOutcome::Denied("test".into()), "mount", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 0);
        assert_eq!(after[1] - before[1], 0);
        assert_eq!(after[2] - before[2], 0);
        assert_eq!(after[3] - before[3], 0);
        assert_eq!(after[4] - before[4], 1, "LD_DENIED must increment");
        assert_eq!(after[5] - before[5], 0);

        // (legacy_allowed=false, Unprovisioned) -> LD_NO_HEADER++
        let before = snap();
        cap_gate_effective(false, &CapOutcome::Unprovisioned, "transfer", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 0);
        assert_eq!(after[1] - before[1], 0);
        assert_eq!(after[2] - before[2], 0);
        assert_eq!(after[3] - before[3], 0);
        assert_eq!(after[4] - before[4], 0);
        assert_eq!(after[5] - before[5], 1, "LD_NO_HEADER must increment");

        // Same-bucket repeat proves no cross-contamination on a second call.
        let before = snap();
        cap_gate_effective(true, &CapOutcome::Authorized, "shell", "self", None, Some(&uk), BindingStrength::Proven, Some(u64::MAX), None);
        let after = snap();
        assert_eq!(after[0] - before[0], 1, "second call same bucket must increment");
        assert_eq!(after[1] - before[1], 0);
    }

    /// Shell-key reconciler test: after revoking shell, the device must appear
    /// in the revoked list (the cap store no longer authorizes it). The actual
    /// authorized_keys cleanup is done by the caller in main.rs.
    #[test]
    fn shell_revoke_returns_device_in_revoked_list() {
        let owner = make_owner();
        let nonce = self_resource_nonce();
        let pk = owner_pub(&owner);
        let resource = self_resource_id(&pk);
        let target = CapTarget::Device([0xcc; 32]);

        // Build self header (same pattern as filament grant)
        let mut hdr = CapHeader {
            resource: resource.clone(),
            epoch: 0,
            owner_pub: pk,
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        hdr.sig = sign_cap_header(&hdr, &owner);

        // Store header has resource="self" (override after signing, same as Cmd::Grant)
        let store_hdr = CapHeader {
            resource: "self".to_string(),
            ..hdr.clone()
        };

        // Grant shell (resource="self" matches the stored header)
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, "self", &["shell"], v1, 86400);

        let mut store = vec![];
        let mut hdr_json = hdr.to_json();
        hdr_json["resource"] = serde_json::json!("self");
        store.push(hdr_json);
        apply_cap_op(&mut store, &store_hdr, &grant, now_secs()).unwrap();

        // Write mock devices.json with cert for device "bob"
        // Use a distinct (non-owner) user_pub so the owner-always rule doesn't trigger
        let bob_user_pub = [0xaa; 32];
        let cert_json = serde_json::json!({
            "devicePub": hex::encode([0xcc; 32]),
            "userPub": hex::encode(bob_user_pub),
            "expires": now_secs() + 90 * 24 * 3600,
            "issued": now_secs(),
            "sig": hex::encode([0u8; 64]),
        });
        let devices = vec![serde_json::json!({
            "name": "bob",
            "secret": "aa".repeat(32),
            "v": 2,
            "caps": ["transfer"],
            "deviceCert": cert_json,
            "userKey": hex::encode(bob_user_pub),
        })];

        let tmp = std::env::temp_dir().join(format!("fil-recon-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(&tmp.join("caps.json"), serde_json::to_string(&serde_json::json!(store)).unwrap()).unwrap();
        std::fs::write(&tmp.join("devices.json"), serde_json::to_string(&serde_json::json!(devices)).unwrap()).unwrap();

        // Before revoke: device should NOT be in revoked list (has shell)
        let before = devices_with_shell_revoked(&tmp);
        assert!(before.is_empty(), "before revoke, device must not be in revoked list");

        // Apply revoke to cap store
        let v2 = hlc_next(v1, now_ms());
        let revoke = make_revoke(&owner, target, "self", v2, 86400);
        apply_cap_op(&mut store, &store_hdr, &revoke, now_secs()).unwrap();
        std::fs::write(&tmp.join("caps.json"), serde_json::to_string(&serde_json::json!(store)).unwrap()).unwrap();

        // After revoke: device MUST be in revoked list
        let after = devices_with_shell_revoked(&tmp);
        assert_eq!(after, vec!["bob".to_string()],
            "device must appear in revoked list after shell revoke (authorized_keys block still exists — reconciler needed)");

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// E2E: after revoke + reconciler, NO filament-managed authorized_keys
    /// block remains. Exercises the full pipeline: devices_with_shell_revoked
    /// → strip_block → block gone.
    #[test]
    fn shell_revoke_e2e_block_removed_after_reconcile() {
        let owner = make_owner();
        let nonce = self_resource_nonce();
        let pk = owner_pub(&owner);
        let resource = self_resource_id(&pk);
        let target = CapTarget::Device([0xcc; 32]);
        let bob_user_pub = [0xaa; 32];

        let mut hdr = CapHeader {
            resource: resource.clone(),
            epoch: 0,
            owner_pub: pk,
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        hdr.sig = sign_cap_header(&hdr, &owner);
        let store_hdr = CapHeader { resource: "self".to_string(), ..hdr.clone() };

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, "self", &["shell"], v1, 86400);
        let v2 = hlc_next(v1, now_ms());
        let revoke = make_revoke(&owner, target, "self", v2, 86400);

        let cert_json = serde_json::json!({
            "devicePub": hex::encode([0xcc; 32]),
            "userPub": hex::encode(bob_user_pub),
            "expires": now_secs() + 90 * 24 * 3600,
            "issued": now_secs(),
            "sig": hex::encode([0u8; 64]),
        });

        let tmp = std::env::temp_dir().join(format!("fil-recon2-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        // 1. Setup: grant shell, write caps.json + devices.json
        let mut store = vec![];
        let mut hdr_json = hdr.to_json();
        hdr_json["resource"] = serde_json::json!("self");
        store.push(hdr_json);
        apply_cap_op(&mut store, &store_hdr, &grant, now_secs()).unwrap();
        std::fs::write(&tmp.join("caps.json"), serde_json::to_string(&serde_json::json!(store)).unwrap()).unwrap();

        let devices = vec![serde_json::json!({
            "name": "bob",
            "secret": "aa".repeat(32),
            "v": 2,
            "caps": ["transfer"],
            "deviceCert": cert_json,
            "userKey": hex::encode(bob_user_pub),
        })];
        std::fs::write(&tmp.join("devices.json"), serde_json::to_string(&serde_json::json!(devices)).unwrap()).unwrap();

        // 2. Mock authorized_keys with managed block for "bob"
        let mock_ak = format!(
            "# BEGIN filament-managed bob\nssh-ed25519 AAAAfake filament-managed\n# END filament-managed bob\n"
        );
        assert!(crate::sshkeys::has_block(&mock_ak, "bob"));

        // 3. Apply revoke, save caps.json
        apply_cap_op(&mut store, &store_hdr, &revoke, now_secs()).unwrap();
        std::fs::write(&tmp.join("caps.json"), serde_json::to_string(&serde_json::json!(store)).unwrap()).unwrap();

        // 4. Reconciler pipeline: devices_with_shell_revoked → strip_block → block gone
        let revoked = devices_with_shell_revoked(&tmp);
        assert!(revoked.contains(&"bob".to_string()),
            "bob must appear in revoked list after shell revoke");

        // Simulate what the caller (Cmd::Grant / daemon-start) does:
        // for each revoked device, strip its block from the mock authorized_keys
        let mut cleaned = mock_ak.clone();
        for device in &revoked {
            cleaned = crate::sshkeys::strip_block(&cleaned, device);
        }

        // Verify the block is actually removed
        assert!(!crate::sshkeys::has_block(&cleaned, "bob"),
            "e2e: after reconcile, NO filament-managed authorized_keys block must remain for bob");

        std::fs::remove_dir_all(&tmp).ok();
    }

    /// Proves the EXACT safety property whose absence was the shadow #24 bug:
    /// authoritative=true → block IS stripped; authoritative=false → block
    /// is NOT stripped (shadow report-only). Both assertions on the SAME
    /// input so a regression in the gate is caught by CI, not by inspection.
    #[test]
    fn reconcile_shell_keys_gated_on_authoritative() {
        let mock_ak = "# BEGIN filament-managed bob\nssh-ed25519 AAAAfake filament-managed\n# END filament-managed bob\n";
        let revoked = vec!["bob".to_string()];

        // Under authoritative, the block IS removed.
        let out_auth = reconcile_shell_keys(&revoked, mock_ak, true);
        assert!(!crate::sshkeys::has_block(&out_auth, "bob"),
            "authoritative: block must be removed");

        // Under shadow, the block is NOT removed (report-only).
        let out_shadow = reconcile_shell_keys(&revoked, mock_ak, false);
        assert!(crate::sshkeys::has_block(&out_shadow, "bob"),
            "shadow: block must NOT be removed — report-only");
    }

    /// Cache returns same result as uncached load for identical store.
    #[test]
    fn cache_matches_uncached_load() {
        let dir = temp_dir("cache-match");
        let store = vec![serde_json::json!({"op":"grant","perms":["shell"]})];
        save_cap_store(&dir, &store).unwrap();
        let loaded = load_cap_store(&dir);
        // Second load should be cached (same mtime)
        let cached = load_cap_store(&dir);
        assert_eq!(loaded, cached, "cached load must match uncached");
    }

    /// Write invalidates cache: a grant then save must be visible to next load.
    #[test]
    fn cache_invalidated_on_save() {
        let dir = temp_dir("cache-inval");
        let store = vec![serde_json::json!({"perm":"shell"})];
        save_cap_store(&dir, &store).unwrap();
        assert_eq!(load_cap_store(&dir).len(), 1);

        // Mutate and save: invalidate cache
        let updated = vec![serde_json::json!({"perm":"shell"}), serde_json::json!({"perm":"deploy"})];
        save_cap_store(&dir, &updated).unwrap();

        let loaded = load_cap_store(&dir);
        assert_eq!(loaded.len(), 2, "cache must be invalidated after save, reflecting new grant");
    }
}
