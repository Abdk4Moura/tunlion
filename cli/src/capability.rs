//! Capability/grant layer: two owner-signed objects + monotonic store.
//!
//! CapOp: an owner-signed grant/revoke/modify.  CapHeader: the owner-signed
//! resource header (self-certifying resource id, hash-chained succession,
//! fork detection).  Ownership is derived from the header, never a grant.
//!
//! ## LIMIT — WireGuard / serve-tun mesh (accepted posture)
//!
//! The WG mesh is a COARSER trust tier. Mesh-join (filament serve-tun) grants
//! L3 IP reach to raw TCP services bound on the overlay address (SSH, exposed
//! ports). These services are NOT constrained by L2 capability gates (l2-open,
//! mount-open, pty-open) because the WG data path is L3 IP, not L2 control-plane
//! streams over QUIC/WebRTC.
//!
//! Everything reachable by WG peers with ONLY L3 IP: SSH daemon on overlay
//! address, any port exposed via `filament expose`. Everything else (forward,
//! netcat, proxy, file transfer, mount, PTY) requires an L2 control channel
//! that a WG-only peer lacks.
//!
//! Mesh-join is therefore a weighty grant at the transport layer. A peer
//! with WG access can reach SSH and exposed ports regardless of capability
//! grants. This is the stated boundary — the WG PSK IS the authorization
//! for SSH and exposed-port reach on the overlay.
use anyhow::{anyhow, bail, Result};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde_json::Value;

/// Hybrid logical clock: version = max(wall_clock_ms, last_seen + 1).
pub fn hlc_next(last_seen: u64, now_ms: u64) -> u64 {
    std::cmp::max(now_ms, last_seen.saturating_add(1))
}

pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Maximum clock skew for ratchet far-future clamp (seconds).
pub const MAX_SKEW_SECS: u64 = 300;

/// Domain constant for the deterministic "self" resource nonce.
/// Survives cold-key restore: the key survives, so the resource id does too.
pub const SELF_RESOURCE_DOMAIN: &[u8] = b"filament-self-resource-v1";

pub fn self_resource_nonce() -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(SELF_RESOURCE_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

pub fn self_resource_id(owner_pub: &[u8; 32]) -> String {
    make_resource_id(owner_pub, &self_resource_nonce())
}

/// Self-certifying resource id: hex(SHA-256(owner_pub || nonce)).
/// Only a genesis whose owner_pub+nonce hash to this id is accepted.
pub fn make_resource_id(owner_pub: &[u8; 32], nonce: &[u8; 32]) -> String {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(owner_pub);
    h.update(nonce);
    hex::encode(h.finalize())
}

/// Hash a header for chain linking: SHA-256(canonical_for_signing).
pub fn hash_header(header: &CapHeader) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(&header.canonical_for_signing());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

// ---------------------------------------------------------------------------
// CapOp  (domain b"filament/capability-op/v1")
// ---------------------------------------------------------------------------

const CAPOP_SIGN_DOMAIN: &[u8] = b"filament/capability-op/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapOpKind {
    Grant = 0x00,
    Revoke = 0x01,
    Modify = 0x02,
}

impl CapOpKind {
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(CapOpKind::Grant),
            0x01 => Some(CapOpKind::Revoke),
            0x02 => Some(CapOpKind::Modify),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTarget {
    User([u8; 32]),
    Device([u8; 32]),
}

impl CapTarget {
    pub fn kind_byte(&self) -> u8 {
        match self {
            CapTarget::User(_) => 0x00,
            CapTarget::Device(_) => 0x01,
        }
    }

    pub fn target_bytes(&self) -> [u8; 32] {
        match self {
            CapTarget::User(b) | CapTarget::Device(b) => *b,
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(self.kind_byte());
        v.extend_from_slice(&self.target_bytes());
        v
    }
}

#[derive(Debug, Clone)]
pub struct CapOp {
    pub op: CapOpKind,
    pub grantor: [u8; 32],
    pub target_kind: u8,
    pub target: [u8; 32],
    pub resource: String,
    pub permissions: Vec<String>,
    pub expires: u64,
    pub issued_at: u64,
    pub version: u64,
    pub sig: [u8; 64],
}

impl CapOp {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }

    pub fn canonical_for_signing(&self) -> Vec<u8> {
        let mut perms_blob = Vec::new();
        perms_blob.extend_from_slice(&(self.permissions.len() as u32).to_le_bytes());
        for p in &self.permissions {
            Self::lp(&mut perms_blob, p.as_bytes());
        }

        let mut target_blob = Vec::with_capacity(33);
        target_blob.push(self.target_kind);
        target_blob.extend_from_slice(&self.target);

        let mut v = Vec::new();
        v.extend_from_slice(CAPOP_SIGN_DOMAIN);
        Self::lp(&mut v, &[self.op.to_byte()]);
        Self::lp(&mut v, &self.grantor);
        Self::lp(&mut v, &target_blob);
        Self::lp(&mut v, self.resource.as_bytes());
        Self::lp(&mut v, &perms_blob);
        Self::lp(&mut v, &self.expires.to_le_bytes());
        Self::lp(&mut v, &self.issued_at.to_le_bytes());
        Self::lp(&mut v, &self.version.to_le_bytes());
        v
    }

    pub fn verify(&self, owner_pub: &[u8; 32], now: u64) -> Result<()> {
        if self.grantor != *owner_pub {
            bail!("capability op grantor != resource owner");
        }
        if now >= self.expires {
            bail!("capability op expired");
        }
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, &self.grantor);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("capability op signature invalid"))
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "op": self.op.to_byte(),
            "grantor": hex::encode(self.grantor),
            "targetKind": self.target_kind,
            "target": hex::encode(self.target),
            "resource": self.resource,
            "permissions": self.permissions,
            "expires": self.expires,
            "issued_at": self.issued_at,
            "version": self.version,
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let op_byte = v["op"].as_u64()? as u8;
        let op = CapOpKind::from_byte(op_byte)?;
        let grantor = {
            let b = hex::decode(v["grantor"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let target = {
            let b = hex::decode(v["target"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let target_kind = v["targetKind"].as_u64()? as u8;
        let sig = {
            let b = hex::decode(v["sig"].as_str()?).ok()?;
            if b.len() != 64 { return None; }
            let mut a = [0u8; 64]; a.copy_from_slice(&b); a
        };
        let perms: Vec<String> = v["permissions"]
            .as_array()?
            .iter()
            .map(|x| x.as_str().map(|s| s.to_string()))
            .collect::<Option<Vec<_>>>()?;
        Some(CapOp {
            op,
            grantor,
            target_kind,
            target,
            resource: v["resource"].as_str()?.to_string(),
            permissions: perms,
            expires: v["expires"].as_u64()?,
            issued_at: v["issued_at"].as_u64()?,
            version: v["version"].as_u64()?,
            sig,
        })
    }
}

pub fn sign_cap_op(op: &CapOp, keypair: &Ed25519KeyPair) -> [u8; 64] {
    let sig = keypair.sign(&op.canonical_for_signing());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ---------------------------------------------------------------------------
// evaluate() -- the single pure authorization fn
// ---------------------------------------------------------------------------

/// The outcome of an authorization check.
pub enum Decision {
    Authorized,
    Denied(String),
}

/// The outcome of a capability query at a gate. Unlike `Decision`, it separates an
/// ABSENT header (the resource is UNPROVISIONED) from a header that EXISTS and
/// refused (`Denied`, a real disagreement). Absent means "provision this node";
/// denied means "the grants disagree". Conflating them floods the shadow log and
/// makes the flip criterion unsatisfiable.
#[derive(Debug)]
pub enum CapOutcome {
    Authorized,
    Denied(String),
    Unprovisioned,
}

/// Single pure authorization fn. Both enforcement and preview call this, so
/// preview cannot diverge from enforcement.
///
/// Returns `Authorized` if:
/// - `principal_user_pub == header.owner_pub` (derived owner, always allowed)
/// - OR a non-expired grant exists where `grantor == header.owner_pub` and
///   target matches (Device→principal_device_pub, User→principal_user_pub)
///   and `action` is listed in permissions.
///
/// Expiry uses `eval_time = max(now, ratchet_for(header.owner_pub))`. If the
/// per-owner ratchet is uninitialized, grants are DENIED (fail-closed).
pub fn evaluate(
    store: &[Value],
    header: &CapHeader,
    principal_device_pub: &[u8; 32],
    principal_user_pub: &[u8; 32],
    resource: &str,
    action: &str,
    now: u64,
) -> Decision {
    // Owner is always authorized (derived, outside cap list)
    if principal_user_pub == &header.owner_pub {
        return Decision::Authorized;
    }

    // Lazy-loaded ratchet: None means uninitialized (fail-closed for grants)
    let ratchet = ratchet_for(store, &header.owner_pub);
    if ratchet.is_none() {
        return Decision::Denied("ratchet uninitialized".into());
    }
    let eval_time = std::cmp::max(now, ratchet.unwrap());

    for entry in store {
        if entry.get("type").and_then(|v| v.as_str()) != Some("cap_grant") {
            continue;
        }
        if entry["grantor"].as_str() != Some(hex::encode(header.owner_pub).as_str()) {
            continue;
        }
        if entry["resource"].as_str() != Some(resource) {
            continue;
        }

        let target_kind = entry["targetKind"].as_u64().unwrap_or(0) as u8;
        let target_matches = match target_kind {
            0x00 => {
                let t = hex::decode(entry["target"].as_str().unwrap_or("")).unwrap_or_default();
                t.len() == 32 && t.as_slice() == principal_user_pub
            }
            0x01 => {
                let t = hex::decode(entry["target"].as_str().unwrap_or("")).unwrap_or_default();
                t.len() == 32 && t.as_slice() == principal_device_pub
            }
            _ => continue, // unknown target kind: skip (owner-signed, but reject)
        };
        if !target_matches {
            continue;
        }

        // Check expiry: on expired grant, continue scanning (it must not
        // shadow a second matching grant that is still valid)
        let expires = entry["expires"].as_u64().unwrap_or(0);
        if eval_time >= expires {
            continue;
        }

        // Check action is in permissions
        if let Some(perms) = entry["permissions"].as_array() {
            if perms.iter().any(|p| p.as_str() == Some(action)) {
                return Decision::Authorized;
            }
        }
    }

    Decision::Denied("not authorized".into())
}

// ---------------------------------------------------------------------------
// CapHeader  (domain b"filament/capability-header/v1")
// ---------------------------------------------------------------------------

const CAPHEADER_SIGN_DOMAIN: &[u8] = b"filament/capability-header/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapFloor {
    pub target_kind: u8,
    pub target: [u8; 32],
    pub min_version: u64,
}

impl CapFloor {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(self.target_kind);
        v.extend_from_slice(&self.target);
        v
    }
}

#[derive(Debug, Clone)]
pub struct CapHeader {
    pub resource: String,
    pub epoch: u64,
    pub owner_pub: [u8; 32],
    pub nonce: [u8; 32],
    pub floors: Vec<CapFloor>,
    pub issued_at: u64,
    pub prev_owner_pub: Option<[u8; 32]>,
    /// None for genesis; for succession, SHA-256(canonical(predecessor)).
    pub prev_header_hash: Option<[u8; 32]>,
    pub sig: [u8; 64],
}

impl CapHeader {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }

    pub fn canonical_for_signing(&self) -> Vec<u8> {
        // Floors blob
        let mut floors_blob = Vec::new();
        floors_blob.extend_from_slice(&(self.floors.len() as u32).to_le_bytes());
        for f in &self.floors {
            Self::lp(&mut floors_blob, &f.encode());
            Self::lp(&mut floors_blob, &f.min_version.to_le_bytes());
        }

        // prev_owner_pub
        let mut prev_blob = Vec::with_capacity(33);
        match &self.prev_owner_pub {
            None => {
                prev_blob.push(0x00);
                prev_blob.extend_from_slice(&[0u8; 32]);
            }
            Some(pk) => {
                prev_blob.push(0x01);
                prev_blob.extend_from_slice(pk);
            }
        }

        // prev_header_hash
        let mut phh_blob = Vec::with_capacity(33);
        match &self.prev_header_hash {
            None => {
                phh_blob.push(0x00);
                phh_blob.extend_from_slice(&[0u8; 32]);
            }
            Some(h) => {
                phh_blob.push(0x01);
                phh_blob.extend_from_slice(h);
            }
        }

        let mut v = Vec::new();
        v.extend_from_slice(CAPHEADER_SIGN_DOMAIN);
        Self::lp(&mut v, self.resource.as_bytes());
        Self::lp(&mut v, &self.epoch.to_le_bytes());
        Self::lp(&mut v, &self.owner_pub);
        Self::lp(&mut v, &self.nonce);
        Self::lp(&mut v, &floors_blob);
        Self::lp(&mut v, &self.issued_at.to_le_bytes());
        Self::lp(&mut v, &prev_blob);
        Self::lp(&mut v, &phh_blob);
        v
    }

    /// Verify a header's signature under the expected signer pubkey.
    fn verify_sig(&self, signer: &[u8; 32]) -> Result<()> {
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, signer);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("capability header signature invalid"))
    }

    /// Verify a genesis header: self-signed, resource id is self-certifying,
    /// prev_owner_pub=None, prev_header_hash=None, epoch=0.
    pub fn verify_genesis(&self) -> Result<()> {
        if self.epoch != 0 {
            bail!("genesis header must have epoch=0");
        }
        if self.prev_owner_pub.is_some() {
            bail!("genesis header must have prev_owner_pub=None");
        }
        if self.prev_header_hash.is_some() {
            bail!("genesis header must have prev_header_hash=None");
        }
        // Self-certifying resource id
        let expected_id = make_resource_id(&self.owner_pub, &self.nonce);
        if self.resource != expected_id {
            bail!(
                "genesis resource id mismatch: stored '{}' != computed '{}' from owner_pub+nonce",
                self.resource,
                expected_id
            );
        }
        self.verify_sig(&self.owner_pub)
    }

    /// Verify a succession header against its predecessor.
    /// - Signed by predecessor's owner_pub
    /// - prev_header_hash == SHA-256(canonical(predecessor))
    /// - epoch > predecessor's epoch
    /// - prev_owner_pub == predecessor's owner_pub
    pub fn verify_succession(&self, predecessor: &CapHeader) -> Result<()> {
        if self.prev_owner_pub.is_none() {
            bail!("succession header must have prev_owner_pub set");
        }
        if self.prev_header_hash.is_none() {
            bail!("succession header must have prev_header_hash set");
        }
        if self.prev_owner_pub != Some(predecessor.owner_pub) {
            bail!("succession prev_owner_pub must equal predecessor's owner_pub");
        }
        let pred_hash = hash_header(predecessor);
        if self.prev_header_hash != Some(pred_hash) {
            bail!("succession prev_header_hash does not match predecessor hash");
        }
        if self.epoch <= predecessor.epoch {
            bail!(
                "epoch not strictly forward: new {} <= predecessor {}",
                self.epoch,
                predecessor.epoch
            );
        }
        self.verify_sig(&predecessor.owner_pub)
    }

    pub fn to_json(&self) -> Value {
        let floors: Vec<Value> = self
            .floors
            .iter()
            .map(|f| {
                serde_json::json!({
                    "targetKind": f.target_kind,
                    "target": hex::encode(f.target),
                    "min_version": f.min_version,
                })
            })
            .collect();
        serde_json::json!({
            "type": "cap_header",
            "resource": self.resource,
            "epoch": self.epoch,
            "owner_pub": hex::encode(self.owner_pub),
            "nonce": hex::encode(self.nonce),
            "floors": floors,
            "issued_at": self.issued_at,
            "prev_owner_pub": self.prev_owner_pub.map(hex::encode),
            "prev_header_hash": self.prev_header_hash.map(hex::encode),
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let owner_pub = {
            let b = hex::decode(v["owner_pub"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let nonce = {
            let b = hex::decode(v["nonce"].as_str()?).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32]; a.copy_from_slice(&b); a
        };
        let prev_owner_pub = v["prev_owner_pub"].as_str().and_then(|s| {
            let b = hex::decode(s).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Some(a)
        });
        let prev_header_hash = v["prev_header_hash"].as_str().and_then(|s| {
            let b = hex::decode(s).ok()?;
            if b.len() != 32 { return None; }
            let mut a = [0u8; 32];
            a.copy_from_slice(&b);
            Some(a)
        });
        let sig = {
            let b = hex::decode(v["sig"].as_str()?).ok()?;
            if b.len() != 64 { return None; }
            let mut a = [0u8; 64]; a.copy_from_slice(&b); a
        };
        let floors: Vec<CapFloor> = v["floors"]
            .as_array()?
            .iter()
            .map(|f| {
                let tk = f["targetKind"].as_u64()? as u8;
                let t = {
                    let b = hex::decode(f["target"].as_str()?).ok()?;
                    if b.len() != 32 { return None; }
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&b);
                    a
                };
                let mv = f["min_version"].as_u64()?;
                Some(CapFloor {
                    target_kind: tk,
                    target: t,
                    min_version: mv,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(CapHeader {
            resource: v["resource"].as_str()?.to_string(),
            epoch: v["epoch"].as_u64()?,
            owner_pub,
            nonce,
            floors,
            issued_at: v["issued_at"].as_u64()?,
            prev_owner_pub,
            prev_header_hash,
            sig,
        })
    }

    /// Find the floor min_version for a given target in this header.
    pub fn floor_for(&self, target_kind: u8, target: &[u8; 32]) -> u64 {
        self.floors
            .iter()
            .find(|f| f.target_kind == target_kind && &f.target == target)
            .map(|f| f.min_version)
            .unwrap_or(0)
    }
}

pub fn sign_cap_header(header: &CapHeader, keypair: &Ed25519KeyPair) -> [u8; 64] {
    let sig = keypair.sign(&header.canonical_for_signing());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

// ---------------------------------------------------------------------------
// Per-owner freshness ratchet
// ---------------------------------------------------------------------------

/// Read the ratchet for `owner_pub`. Returns `None` if uninitialized.
fn ratchet_for(store: &[Value], owner_pub: &[u8; 32]) -> Option<u64> {
    let owner_hex = hex::encode(owner_pub);
    store
        .iter()
        .find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
                && e["owner_pub"].as_str() == Some(owner_hex.as_str())
        })
        .and_then(|e| e["max_issued_at"].as_u64())
}

/// Update the per-owner ratchet. Clamps `issued_at` to `local_clock + MAX_SKEW_SECS`;
/// far-future values are rejected. On success, stores `max(existing, issued_at)`.
pub fn update_ratchet(store: &mut Vec<Value>, owner_pub: &[u8; 32], issued_at: u64) -> Result<()> {
    let local_now = now_secs();
    let max_allowed = local_now.saturating_add(MAX_SKEW_SECS);
    if issued_at > max_allowed {
        bail!(
            "far-future issued_at {} rejected (local clock {} + skew {})",
            issued_at,
            local_now,
            MAX_SKEW_SECS
        );
    }

    let owner_hex = hex::encode(owner_pub);
    for e in store.iter_mut() {
        if e.get("type").and_then(|v| v.as_str()) == Some("cap_ratchet")
            && e["owner_pub"].as_str() == Some(owner_hex.as_str())
        {
            let existing = e["max_issued_at"].as_u64().unwrap_or(0);
            e["max_issued_at"] = Value::from(std::cmp::max(existing, issued_at));
            return Ok(());
        }
    }
    store.push(serde_json::json!({
        "type": "cap_ratchet",
        "owner_pub": owner_hex,
        "max_issued_at": issued_at,
    }));
    Ok(())
}

// ---------------------------------------------------------------------------
// File-based store I/O  (thin wrappers, mirror update_peer_identity)
// ---------------------------------------------------------------------------

/// Load the capability store from `caps.json` in the filament config dir.
pub fn load_cap_store(config_dir: &std::path::Path) -> Vec<Value> {
    let p = config_dir.join("caps.json");
    std::fs::read_to_string(&p)
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
}

/// Persist the capability store to `caps.json`.
pub fn save_cap_store(config_dir: &std::path::Path, store: &[Value]) -> std::io::Result<()> {
    let p = config_dir.join("caps.json");
    if let Some(parent) = p.parent() { std::fs::create_dir_all(parent).ok(); }
    std::fs::write(&p, serde_json::to_string_pretty(&serde_json::json!(store))?)
}

/// Returns true when capability enforcement is AUTHORITATIVE (live-gating).
/// Read this in ONE place only, `cap_gate_effective`, the single policy site. The
/// FLIP CRITERION lives on `ShadowCounts::flip_ready`: flip only when
/// `la_authorized > 0` AND `la_denied == 0` AND `la_no_header == 0`. A bare total is
/// NOT sufficient. The commit that sets this to true MUST cite the full shadow
/// counts, INCLUDING `ld_authorized` (the WIDENING count of opens the flip newly
/// allows); if it is nonzero, enumerate which and why. Until then, legacy decides.
pub fn cap_authoritative() -> bool {
    std::env::var("FILAMENT_CAP_AUTHORITATIVE").map(|x| x == "1").unwrap_or(false)
}

use std::sync::atomic::{AtomicU64, Ordering};
// Shadow counters bucketed by the LEGACY decision AND by three cap outcomes:
// authorized, denied (a header EXISTS and refused, a real disagreement), and
// no-header (the resource is UNPROVISIONED, not a disagreement). The only opens a
// flip can change are legacy-ALLOWED ones; a cap-deny on a legacy-denied open
// alters nothing. Keeping ABSENT separate from DENIED is what stops a fresh,
// unprovisioned node from flooding CRITICAL on every normal open and from making
// the flip criterion unsatisfiable.
static LA_AUTHORIZED: AtomicU64 = AtomicU64::new(0); // legacy ALLOWED, cap authorizes (agree)
static LA_DENIED: AtomicU64 = AtomicU64::new(0); // legacy ALLOWED, header EXISTS and denies  <- real breakage-on-flip
static LA_NO_HEADER: AtomicU64 = AtomicU64::new(0); // legacy ALLOWED, resource UNPROVISIONED (absent)
static LD_AUTHORIZED: AtomicU64 = AtomicU64::new(0); // legacy DENIED, cap AUTHORIZES = an open the flip NEWLY ALLOWS (WIDENING; a mandatory review item, never merely informational)
static LD_DENIED: AtomicU64 = AtomicU64::new(0); // legacy DENIED, header exists and denies (agree)
static LD_NO_HEADER: AtomicU64 = AtomicU64::new(0); // legacy DENIED, resource unprovisioned

/// Shadow counts, bucketed by legacy outcome and cap outcome.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct ShadowCounts {
    pub la_authorized: u64,
    pub la_denied: u64,
    pub la_no_header: u64,
    pub ld_authorized: u64,
    pub ld_denied: u64,
    pub ld_no_header: u64,
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
    }
}

impl ShadowCounts {
    /// The FLIP CRITERION, in code (not just prose): flip to authoritative only when
    /// a real sample of legacy-ALLOWED opens has been seen (`la_authorized > 0`), NO
    /// header disagreed (`la_denied == 0`), and every reachable resource EXERCISED in
    /// the window was provisioned (`la_no_header == 0`).
    ///
    /// This boolean guards BREAKAGE (access the flip would remove). It deliberately
    /// does NOT read `ld_authorized`, the WIDENING count (opens legacy refused that
    /// cap authorizes, which the flip will newly ALLOW), because some widening is the
    /// intended point of the migration and a hard zero would forbid it. Widening is
    /// instead a MANDATORY REVIEW gate: the commit that sets the flag MUST cite
    /// `ld_authorized` alongside the `la_*` numbers, and if it is nonzero, enumerate
    /// which opens will be newly permitted and why. A number written down gets looked
    /// at; a number labeled "informational" does not.
    ///
    /// Caveat: `la_no_header == 0` proves every resource EXERCISED during the window
    /// was provisioned, not that every resource is. Today all gates pass "self" (one
    /// resource) so the claim is tight; when resources multiply this silently becomes
    /// a sampled claim, the biased-sample problem one level up. Revisit then.
    pub fn flip_ready(&self) -> bool {
        self.la_authorized > 0 && self.la_denied == 0 && self.la_no_header == 0
    }

    /// One-line operator summary of both populations plus flip-readiness.
    pub fn summary(&self) -> String {
        format!(
            "legacy-allowed ok={} deny={} no-header={} | WIDENING(newly-allowed-on-flip)={} legacy-denied[deny={} no-header={}] | flip_ready={}",
            self.la_authorized,
            self.la_denied,
            self.la_no_header,
            self.ld_authorized,
            self.ld_denied,
            self.ld_no_header,
            self.flip_ready(),
        )
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
            &store, &hdr, &device_pub, &user_pub, resource, action, now_secs(),
        ) {
            Decision::Authorized => CapOutcome::Authorized,
            Decision::Denied(reason) => CapOutcome::Denied(reason),
        },
    }
}

/// The effective gate decision with an optional capability denial reason so
/// the operator-facing diagnostic can say what actually happened instead of
/// repeating the legacy assertion.
pub enum GateDecision {
    Allow,
    Deny { cap_reason: Option<String> },
}

impl GateDecision {
    pub fn allowed(&self) -> bool {
        matches!(self, GateDecision::Allow)
    }

    /// Operator-facing denial reason: the real cap reason when present
    /// (authoritative), else `legacy`.
    pub fn deny_reason<'a>(&'a self, legacy: &'a str) -> &'a str {
        match self {
            GateDecision::Deny { cap_reason: Some(r) } => r,
            _ => legacy,
        }
    }
}

/// The single policy site. Reads the mode ONCE, records the shadow counters in BOTH
/// modes (so observability survives the flip), logs, and returns the effective gate
/// decision: the legacy decision stands in shadow; the cap outcome gates under
/// FILAMENT_CAP_AUTHORITATIVE. `legacy_allowed` is the pre-capability gate's
/// decision for this same open; it buckets the counters and is the effective answer
/// in shadow.
pub fn cap_gate_effective(
    legacy_allowed: bool,
    outcome: &CapOutcome,
    action: &str,
    resource: &str,
    device_pub: Option<&[u8; 32]>,
    user_pub: Option<&[u8; 32]>,
) -> GateDecision {
    let authoritative = cap_authoritative();

    // Counters: recorded in BOTH modes so a flip does not blind us.
    match (legacy_allowed, outcome) {
        (true, CapOutcome::Authorized) => {
            LA_AUTHORIZED.fetch_add(1, Ordering::Relaxed);
        }
        (true, CapOutcome::Denied(_)) => {
            LA_DENIED.fetch_add(1, Ordering::Relaxed);
        }
        (true, CapOutcome::Unprovisioned) => {
            LA_NO_HEADER.fetch_add(1, Ordering::Relaxed);
        }
        (false, CapOutcome::Authorized) => {
            LD_AUTHORIZED.fetch_add(1, Ordering::Relaxed);
        }
        (false, CapOutcome::Denied(_)) => {
            LD_DENIED.fetch_add(1, Ordering::Relaxed);
        }
        (false, CapOutcome::Unprovisioned) => {
            LD_NO_HEADER.fetch_add(1, Ordering::Relaxed);
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

/// A single authorization query for preview enumeration.
pub struct AuthQuery {
    pub principal_device_pub: [u8; 32],
    pub principal_user_pub: [u8; 32],
    pub action: String,
}

pub struct PreviewEntry {
    pub query: AuthQuery,
    pub authorized: bool,
}

/// Preview the effect of applying `ops` to a cloned store: compute
/// evaluate() for each query against the post-apply state. Same
/// evaluate() fn, so preview cannot diverge from enforcement.
pub fn preview(
    store: &[Value],
    header: &CapHeader,
    ops: &[CapOp],
    queries: &[AuthQuery],
    now: u64,
) -> Vec<PreviewEntry> {
    let mut cloned_store = store.to_vec();
    for op in ops {
        let _ = apply_cap_op(&mut cloned_store, header, op, now);
    }
    queries
        .iter()
        .map(|q| {
            let d = evaluate(
                &cloned_store,
                header,
                &q.principal_device_pub,
                &q.principal_user_pub,
                &header.resource,
                &q.action,
                now,
            );
            PreviewEntry {
                query: AuthQuery {
                    principal_device_pub: q.principal_device_pub,
                    principal_user_pub: q.principal_user_pub,
                    action: q.action.clone(),
                },
                authorized: matches!(d, Decision::Authorized),
            }
        })
        .collect()
}

/// Check whether applying an op self-locks out the admin: if a principal
/// held Authorized on an action before but is Denied after, return a
/// warning. The caller surfaces this toward the owner; it does NOT refuse
/// the op.
pub fn check_self_lockout(
    store: &[Value],
    header: &CapHeader,
    op: &CapOp,
    principals: &[(String, [u8; 32], [u8; 32])],
    admin_actions: &[&str],
    now: u64,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut after_store = store.to_vec();
    if apply_cap_op(&mut after_store, header, op, now).is_err() {
        return warnings;
    }
    for (label, dev_pub, user_pub) in principals {
        for action in admin_actions {
            let before = evaluate(store, header, dev_pub, user_pub, &header.resource, action, now);
            let after = evaluate(&after_store, header, dev_pub, user_pub, &header.resource, action, now);
            if matches!(before, Decision::Authorized) && matches!(after, Decision::Denied(_)) {
                warnings.push(format!(
                    "self-lockout WARNING: {} would lose '{}' on resource '{}'",
                    label, action, header.resource
                ));
            }
        }
    }
    warnings
}

// ---------------------------------------------------------------------------
// Store fns
// ---------------------------------------------------------------------------

fn find_header_idx(store: &[Value], resource: &str) -> Option<usize> {
    store
        .iter()
        .position(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                      && e["resource"].as_str() == Some(resource))
}

/// Apply a resource header.  Genesis must be self-certifying (resource id =
/// hex(SHA-256(owner_pub||nonce))).  Succession must hash-chain to the
/// predecessor and be signed by it.  Equal-epoch forks freeze the chain.
pub fn apply_header(store: &mut Vec<Value>, new_header: &CapHeader) -> Result<()> {
    let existing_idx = find_header_idx(store, &new_header.resource);

    if existing_idx.is_none() {
        // Genesis: first header for this resource
        new_header.verify_genesis()?;
        store.push(new_header.to_json());
        update_ratchet(store, &new_header.owner_pub, new_header.issued_at)?;
        return Ok(());
    }

    let current = CapHeader::from_json(&store[existing_idx.unwrap()])
        .ok_or_else(|| anyhow!("stored header is corrupt"))?;

    // Fork detection: same epoch, same predecessor -> must be identical, else fork
    if new_header.epoch == current.epoch {
        if new_header.prev_header_hash == current.prev_header_hash {
            let new_hash = hash_header(new_header);
            let cur_hash = hash_header(&current);
            if new_hash != cur_hash {
                // Equal-epoch fork: freeze, do not accept either
                store[existing_idx.unwrap()]["frozen"] = Value::from(true);
                bail!(
                    "equal-epoch fork detected at epoch {} for resource '{}': successor frozen",
                    new_header.epoch,
                    new_header.resource
                );
            }
            // Identical header: replay is non-forward
            bail!(
                "non-forward epoch: new epoch {} == current epoch {}",
                new_header.epoch,
                current.epoch
            );
        }
        bail!(
            "non-forward epoch: new epoch {} == current epoch {}",
            new_header.epoch,
            current.epoch
        );
    }

    // Check chain is not frozen
    if store[existing_idx.unwrap()].get("frozen").and_then(|v| v.as_bool()).unwrap_or(false) {
        bail!(
            "succession frozen for resource '{}' (fork detected)",
            new_header.resource
        );
    }

    // Verify hash-chained succession
    new_header.verify_succession(&current)?;

    store[existing_idx.unwrap()] = new_header.to_json();
    update_ratchet(store, &new_header.owner_pub, new_header.issued_at)?;
    Ok(())
}

/// Apply a verified capability op to the store.
pub fn apply_cap_op(
    store: &mut Vec<Value>,
    header: &CapHeader,
    op: &CapOp,
    now: u64,
) -> Result<()> {
    op.verify(&header.owner_pub, now)?;

    if find_header_idx(store, &header.resource).is_none() {
        bail!("cannot apply cap op: no header for resource '{}' in store", &header.resource);
    }

    let floor = header.floor_for(op.target_kind, &op.target);
    if op.version < floor {
        bail!(
            "cap op version {} below floor {} for target {}/{}",
            op.version,
            floor,
            op.target_kind,
            hex::encode(op.target)
        );
    }

    let grantor_hex = hex::encode(op.grantor);
    let target_hex = hex::encode(op.target);

    let mut found_idx = None;
    for (i, entry) in store.iter().enumerate() {
        if entry.get("type").and_then(|v| v.as_str()) != Some("cap_grant") {
            continue;
        }
        if entry["grantor"].as_str() == Some(&grantor_hex)
            && entry["resource"].as_str() == Some(op.resource.as_str())
            && entry["targetKind"].as_u64() == Some(op.target_kind as u64)
            && entry["target"].as_str() == Some(target_hex.as_str())
        {
            let existing_version = entry["version"].as_u64().unwrap_or(0);
            if existing_version >= op.version {
                bail!(
                    "monotonic version refusal: existing {} >= new {}",
                    existing_version,
                    op.version
                );
            }
            found_idx = Some(i);
            break;
        }
    }

    if op.op == CapOpKind::Revoke || op.permissions.is_empty() {
        if let Some(idx) = found_idx {
            store.remove(idx);
        }
        return Ok(());
    }

    let mut json_entry = op.to_json();
    json_entry["type"] = Value::from("cap_grant");

    if let Some(idx) = found_idx {
        if let Some(ma) = store[idx].get("max_issued_at").and_then(|v| v.as_u64()) {
            let new_ma = std::cmp::max(ma, op.issued_at);
            json_entry["max_issued_at"] = Value::from(new_ma);
        } else {
            json_entry["max_issued_at"] = Value::from(op.issued_at);
        }
        store[idx] = json_entry;
    } else {
        json_entry["max_issued_at"] = Value::from(op.issued_at);
        store.push(json_entry);
    }
    update_ratchet(store, &op.grantor, op.issued_at)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair;

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

    fn make_genesis_header(
        owner: &Ed25519KeyPair,
        nonce: &[u8; 32],
        floors: &[CapFloor],
    ) -> CapHeader {
        let pk = owner_pub(owner);
        let resource = make_resource_id(&pk, nonce);
        let mut h = CapHeader {
            resource,
            epoch: 0,
            owner_pub: pk,
            nonce: *nonce,
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, owner);
        h
    }

    fn make_succession_header(
        prev_owner: &Ed25519KeyPair,
        predecessor: &CapHeader,
        new_owner: &Ed25519KeyPair,
        epoch: u64,
        nonce: &[u8; 32],
        floors: &[CapFloor],
    ) -> CapHeader {
        let pred_hash = hash_header(predecessor);
        let mut h = CapHeader {
            resource: predecessor.resource.clone(),
            epoch,
            owner_pub: owner_pub(new_owner),
            nonce: *nonce,
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: Some(predecessor.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, prev_owner);
        h
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
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Grant,
            grantor,
            target_kind,
            target: target_bytes,
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
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Revoke,
            grantor,
            target_kind,
            target: target_bytes,
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

    fn init_store(header: &CapHeader) -> Vec<Value> {
        let mut s = vec![];
        apply_header(&mut s, header).unwrap();
        s
    }

    // -- CapOp tests -------------------------------------------------------

    #[test]
    fn honest_grant_verifies_and_applies() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v1, 86400);

        grant.verify(&pk, now_secs()).unwrap();

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["resource"].as_str().unwrap(), header.resource);
        assert_eq!(grants[0]["version"].as_u64().unwrap(), v1);
    }

    #[test]
    fn tampered_permission_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.permissions = vec!["admin".to_string()];
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_target_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xaa; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.target = [0xbb; 32];
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_resource_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.resource = "admin".to_string();
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_expires_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.expires = now_secs() + 999999;
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn tampered_version_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let mut grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&pk, now_secs()).is_ok());
        grant.version = v1.saturating_add(1000);
        assert!(grant.verify(&pk, now_secs()).is_err());
    }

    #[test]
    fn wrong_owner_sig_refused() {
        let alice = make_owner();
        let bob = make_owner();
        let alice_pub = owner_pub(&alice);
        let bob_pub = owner_pub(&bob);
        assert_ne!(alice_pub, bob_pub);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&alice, &nonce, &[]);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&alice, target, &header.resource, &["ssh"], v1, 86400);
        assert!(grant.verify(&alice_pub, now_secs()).is_ok());
        assert!(grant.verify(&bob_pub, now_secs()).is_err());
    }

    #[test]
    fn expired_grant_refused() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let issued_at = now_secs().saturating_sub(86401);
        let target_kind = target.kind_byte();
        let target_bytes = target.target_bytes();
        let mut op = CapOp {
            op: CapOpKind::Grant,
            grantor: pk,
            target_kind,
            target: target_bytes,
            resource: "shell".to_string(),
            permissions: vec!["ssh".to_string()],
            expires: issued_at.saturating_add(86400),
            issued_at,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        op.sig = sign_cap_op(&op, &owner);
        assert!(op.verify(&pk, now_secs()).is_err());
    }

    // -- Monotonic / rollback -----------------------------------------------

    #[test]
    fn rollback_lower_version_rejected() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v5 = hlc_next(hlc_next(hlc_next(hlc_next(hlc_next(0, seed), seed), seed), seed), seed);
        let v3 = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);

        let grant_v5 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, &header.resource, &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();
        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5 -> v3 must be rejected");
    }

    #[test]
    fn revoke_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let revoke = make_revoke(&owner, target, &header.resource, v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &revoke, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 0, "revoke must remove grant");
    }

    #[test]
    fn empty_permissions_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let empty_grant = make_grant(&owner, target, &header.resource, &[], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &empty_grant, now_secs()).unwrap();
        let grants: Vec<_> = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .collect();
        assert_eq!(grants.len(), 0);
    }

    #[test]
    fn rollback_guard_red_without_fix() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let v3 = hlc_next(v2, seed);
        let v4 = hlc_next(v3, seed);
        let v5 = hlc_next(v4, seed);

        let grant_v5 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, &header.resource, &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();

        let pk = owner_pub(&owner);
        assert!(grant_v3.verify(&pk, now_secs()).is_ok());

        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5->v3 must be REFUSED; if green, guard is broken");
    }

    // -- Floor --------------------------------------------------------------

    #[test]
    fn floor_rejects_first_seen_op_below_min_version() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let seed = now_ms();
        let floor_ver = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);
        let low_ver = hlc_next(0, seed);

        let header = make_genesis_header(
            &owner,
            &nonce,
            &[CapFloor {
                target_kind: target.kind_byte(),
                target: target.target_bytes(),
                min_version: floor_ver,
            }],
        );

        let grant_low = make_grant(&owner, target, &header.resource, &["ssh"], low_ver, 86400);
        let mut store = init_store(&header);
        let res = apply_cap_op(&mut store, &header, &grant_low, now_secs());
        assert!(res.is_err(), "op below floor must be rejected");

        let v = hlc_next(floor_ver, seed);
        let grant_ok = make_grant(&owner, target, &header.resource, &["ssh"], v, 86400);
        apply_cap_op(&mut store, &header, &grant_ok, now_secs()).unwrap();
    }

    // -- Genesis self-certifying resource id ---------------------------------

    #[test]
    fn genesis_id_forgery_rejected() {
        let alice = make_owner();
        let mallory = make_owner();
        let nonce = [0xaa; 32];

        // Alice creates a valid genesis
        let alice_genesis = make_genesis_header(&alice, &nonce, &[]);
        alice_genesis.verify_genesis().unwrap();

        // Mallory tries to create a genesis with the SAME resource id (alice's)
        // by computing her own nonce... but make_resource_id binds owner_pub too.
        // Any genesis with owner_pub=mallory will produce a different resource id.
        let mallory_pk = owner_pub(&mallory);
        let mallory_id = make_resource_id(&mallory_pk, &nonce);
        assert_ne!(mallory_id, alice_genesis.resource,
            "different owner must produce different resource id");

        // Mallory cannot produce a genesis for Alice's resource id because
        // sha256(mallory_pub||nonce) != sha256(alice_pub||nonce)
        // And she cannot change owner_pub without changing the resource id.
        // verify_genesis enforces resource_id == sha256(owner_pub||nonce).
        let mut bogus = CapHeader {
            resource: alice_genesis.resource.clone(),
            epoch: 0,
            owner_pub: mallory_pk,
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: None,
            prev_header_hash: None,
            sig: [0u8; 64],
        };
        bogus.sig = sign_cap_header(&bogus, &mallory);
        assert!(bogus.verify_genesis().is_err(),
            "genesis with mismatched owner_pub+nonce must be rejected");
    }

    // -- Succession hash-chained ---------------------------------------------

    #[test]
    fn succession_alice_to_bob_applies_bobs_ops() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let v1 = hlc_next(0, now_ms());
        let grant_alice = make_grant(&alice, target, &genesis.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &genesis, &grant_alice, now_secs()).unwrap();

        let succ = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        succ.verify_succession(&genesis).unwrap();
        apply_header(&mut store, &succ).unwrap();

        let v2 = hlc_next(v1, now_ms());
        let grant_bob = make_grant(&bob, target, &genesis.resource, &["shell"], v2, 86400);
        apply_cap_op(&mut store, &succ, &grant_bob, now_secs()).unwrap();

        let v3 = hlc_next(v2, now_ms());
        let grant_alice2 = make_grant(&alice, target, &genesis.resource, &["admin"], v3, 86400);
        assert!(apply_cap_op(&mut store, &succ, &grant_alice2, now_secs()).is_err());
    }

    #[test]
    fn succession_not_signed_by_prev_owner_rejected() {
        let alice = make_owner();
        let bob = make_owner();
        let mallory = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let pred_hash = hash_header(&genesis);
        let mut bogus = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        bogus.sig = sign_cap_header(&bogus, &mallory);
        let res = apply_header(&mut store, &bogus);
        assert!(res.is_err(), "succession not signed by prev owner must be rejected");
    }

    #[test]
    fn non_forward_epoch_rejected() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let succ1 = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        apply_header(&mut store, &succ1).unwrap();

        // Replay epoch 1
        let res = apply_header(&mut store, &succ1);
        assert!(res.is_err(), "non-forward epoch must be rejected");
    }

    #[test]
    fn succession_prev_header_hash_consistency() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);
        let mut store = init_store(&genesis);

        let succ1 = make_succession_header(&alice, &genesis, &bob, 1, &nonce, &[]);
        apply_header(&mut store, &succ1).unwrap();

        // Try to submit a header whose prev_header_hash is hash(genesis) not hash(succ1)
        let gen_hash = hash_header(&genesis);
        let mut gap = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 2,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(succ1.owner_pub),
            prev_header_hash: Some(gen_hash), // points to genesis, not succ1
            sig: [0u8; 64],
        };
        gap.sig = sign_cap_header(&gap, &bob);
        let res = apply_header(&mut store, &gap);
        assert!(res.is_err(), "chain gap: prev_header_hash must match stored predecessor");
    }

    // -- Equal-epoch fork ---------------------------------------------------

    #[test]
    fn equal_epoch_fork_frozen() {
        let alice = make_owner();
        let bob = make_owner();
        let carol = make_owner();
        let nonce = [0x01; 32];
        let genesis = make_genesis_header(&alice, &nonce, &[]);

        // Two valid but different successors at epoch 1 from genesis
        let pred_hash = hash_header(&genesis);

        let mut fork_a = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&bob),
            nonce,
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        fork_a.sig = sign_cap_header(&fork_a, &alice);

        let mut fork_b = CapHeader {
            resource: genesis.resource.clone(),
            epoch: 1,
            owner_pub: owner_pub(&carol),
            nonce,
            floors: vec![],
            issued_at: now_secs() + 1,
            prev_owner_pub: Some(genesis.owner_pub),
            prev_header_hash: Some(pred_hash),
            sig: [0u8; 64],
        };
        fork_b.sig = sign_cap_header(&fork_b, &alice);

        // Both are valid against genesis
        fork_a.verify_succession(&genesis).unwrap();
        fork_b.verify_succession(&genesis).unwrap();

        // Apply the first one -- ok
        let mut store = init_store(&genesis);
        apply_header(&mut store, &fork_a).unwrap();

        // Apply the second one at same epoch -- FORK, freeze
        let res = apply_header(&mut store, &fork_b);
        assert!(res.is_err(), "equal-epoch fork must be rejected");

        // Chain must be frozen now
        let stored = store.iter()
            .find(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                     && e["resource"].as_str() == Some(genesis.resource.as_str()))
            .unwrap();
        assert!(stored.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false),
            "chain must be frozen after fork detection");

        // Any succession after freeze is rejected
        let succ2 = make_succession_header(&alice, &fork_a, &bob, 2, &nonce, &[]);
        let res2 = apply_header(&mut store, &succ2);
        assert!(res2.is_err(), "succession after freeze must be rejected");
    }

    // -- Domain separation ---------------------------------------------------

    #[test]
    fn domain_separation_three_way() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0x11; 32]);
        let v1 = hlc_next(0, now_ms());
        let header = make_genesis_header(&owner, &nonce, &[]);
        let op = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let op_canon = op.canonical_for_signing();
        let header_canon = header.canonical_for_signing();

        let op_domain: &[u8] = b"filament/capability-op/v1";
        let header_domain: &[u8] = b"filament/capability-header/v1";
        let cert_domain: &[u8] = b"filament/identity-device-cert/v1";

        assert_ne!(op_domain, header_domain);
        assert_ne!(op_domain, cert_domain);
        assert_ne!(header_domain, cert_domain);

        assert!(op_canon.starts_with(op_domain));
        assert!(!op_canon.starts_with(header_domain));
        assert!(!op_canon.starts_with(cert_domain));

        assert!(header_canon.starts_with(header_domain));
        assert!(!header_canon.starts_with(op_domain));
        assert!(!header_canon.starts_with(cert_domain));

        let op_len = (op_domain.len() as u32).to_le_bytes();
        let header_len = (header_domain.len() as u32).to_le_bytes();
        let cert_len = (cert_domain.len() as u32).to_le_bytes();
        assert_ne!(op_len, header_len);
        assert_ne!(header_len, cert_len);
    }

    // -- Canonical injectivity ----------------------------------------------

    #[test]
    fn canonical_injectivity() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let target = CapTarget::Device([0x11; 32]);
        let seed = now_ms();

        let op1 = make_grant(&owner, target, &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        let op2 = make_grant(&owner, target, &header.resource, &["ssh"], hlc_next(hlc_next(0, seed), seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op2.canonical_for_signing());

        let op3 = make_grant(&owner, target, &header.resource, &["ssh", "shell"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op3.canonical_for_signing());

        let target2 = CapTarget::Device([0x22; 32]);
        let op4 = make_grant(&owner, target2, &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op4.canonical_for_signing());

        let op5 = make_grant(&owner, target, "admin", &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op5.canonical_for_signing());

        let op_user = make_grant(&owner, CapTarget::User([0x11; 32]), &header.resource, &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op_user.canonical_for_signing());
    }

    // -- JSON roundtrip -----------------------------------------------------

    #[test]
    fn grant_json_roundtrip() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);
        let target = CapTarget::Device([0x42; 32]);
        let v = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["send", "receive"], v, 86400);

        let j = grant.to_json();
        let grant2 = CapOp::from_json(&j).unwrap();
        assert_eq!(grant.grantor, grant2.grantor);
        assert_eq!(grant.target, grant2.target);
        assert_eq!(grant.resource, grant2.resource);
        assert_eq!(grant.permissions, grant2.permissions);
        assert_eq!(grant.expires, grant2.expires);
        assert_eq!(grant.issued_at, grant2.issued_at);
        assert_eq!(grant.version, grant2.version);
        assert_eq!(grant.sig, grant2.sig);

        let pk = owner_pub(&owner);
        grant2.verify(&pk, now_secs()).unwrap();
    }

    #[test]
    fn header_json_roundtrip() {
        let owner = make_owner();
        let nonce = [0xab; 32];
        let header = make_genesis_header(
            &owner,
            &nonce,
            &[CapFloor {
                target_kind: CapTarget::Device([0xaa; 32]).kind_byte(),
                target: [0xaa; 32],
                min_version: 123,
            }],
        );
        let j = header.to_json();
        let header2 = CapHeader::from_json(&j).unwrap();
        assert_eq!(header.resource, header2.resource);
        assert_eq!(header.epoch, header2.epoch);
        assert_eq!(header.owner_pub, header2.owner_pub);
        assert_eq!(header.nonce, header2.nonce);
        assert_eq!(header.floors.len(), header2.floors.len());
        assert_eq!(header.issued_at, header2.issued_at);
        assert_eq!(header.prev_owner_pub, header2.prev_owner_pub);
        assert_eq!(header.sig, header2.sig);
        header2.verify_genesis().unwrap();
    }

    // -- Multi-resource -----------------------------------------------------

    #[test]
    fn cross_resource_independent_keys() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let grant_shell = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let grant_transfer = make_grant(&owner, target, "transfer", &["send"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_shell, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &grant_transfer, now_secs()).unwrap();
        let grant_count = store.iter()
            .filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant"))
            .count();
        assert_eq!(grant_count, 2); // shell + transfer
    }

    // -- HLC ----------------------------------------------------------------

    #[test]
    fn hlc_seeds_from_wall_clock_not_zero() {
        let v = hlc_next(0, now_ms());
        assert!(v > 0);
        let v2 = hlc_next(v, now_ms());
        assert!(v2 > v);
    }

    // -- B1 evaluate() authorization ----------------------------------------

    #[test]
    fn evaluate_owner_authorized() {
        let alice = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&alice, &nonce, &[]);
        let store = init_store(&header);

        let device_pub = [0xff; 32];
        let user_pub = owner_pub(&alice);

        let d = evaluate(&store, &header, &device_pub, &user_pub, &header.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("owner must be authorized, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_granted_action_ok() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh", "shell"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32]; // different user, not the owner
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("granted action must be authorized, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_ungranted_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "admin", now_secs());
        match d {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("ungranted action must be denied"),
        }
    }

    #[test]
    fn evaluate_expired_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let issued_at = now_secs().saturating_sub(86401);
        let mut grant = CapOp {
            op: CapOpKind::Grant,
            grantor: pk,
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: issued_at.saturating_add(86400),
            issued_at,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        grant.sig = sign_cap_op(&grant, &owner);

        let mut store = init_store(&header);
        // Grant expired, but apply_cap_op doesn't check expiry — that's evaluate's job
        // We need to apply a non-expired op first so ratchet is initialized
        let v = hlc_next(0, now_ms());
        let fresh = make_grant(&owner, target, &header.resource, &["ssh"], v, 86400);
        apply_cap_op(&mut store, &header, &fresh, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        // fresh grant covers "ssh", expired grant is not there — test evaluates against stored grants
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("non-expired grant must be authorized, got: {}", reason),
        }

        // Now test with an expired grant
        let mut expired_store = init_store(&header);
        // Store the expired grant directly (bypassing apply_cap_op's monotonicity)
        let mut expired_entry = grant.to_json();
        expired_entry["type"] = Value::from("cap_grant");
        expired_store.push(expired_entry);

        // evaluate should see the grant but consider it expired
        let d2 = evaluate(&expired_store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs());
        match d2 {
            Decision::Denied(reason) => assert!(reason.contains("not authorized"), "expired-only store must be denied: {}", reason),
            Decision::Authorized => panic!("expired grant must be denied"),
        }
    }

    #[test]
    fn evaluate_expired_grant_does_not_shadow_valid_grant() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let device_target = CapTarget::Device([0xcc; 32]);
        let user_pub = [0xaa; 32];
        let user_target = CapTarget::User(user_pub);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Expired Device grant (will be skipped)
        let expired_issued = now_secs().saturating_sub(86401);
        let mut expired_grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&owner),
            target_kind: device_target.kind_byte(),
            target: device_target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: expired_issued.saturating_add(86400),
            issued_at: expired_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        expired_grant.sig = sign_cap_op(&expired_grant, &owner);

        // Valid User grant
        let v = hlc_next(0, now_ms());
        let user_grant = make_grant(&owner, user_target, &header.resource, &["ssh"], v, 86400);

        let mut store = init_store(&header);
        // Push expired grant first
        let mut expired_entry = expired_grant.to_json();
        expired_entry["type"] = Value::from("cap_grant");
        store.push(expired_entry);
        // Then valid User grant via apply_cap_op
        apply_cap_op(&mut store, &header, &user_grant, now_secs()).unwrap();

        // A principal with device=0xcc and user=0xaa matches BOTH grants.
        // The expired Device grant must NOT shadow the valid User grant.
        let d = evaluate(&store, &header, &[0xcc; 32], &user_pub, &header.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("valid User grant must authorize despite expired Device grant: {}", reason),
        }
    }

    #[test]
    fn evaluate_wrong_target_denied() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principal_user = [0xaa; 32];
        // Wrong device pubkey
        let d = evaluate(&store, &header, &[0xdd; 32], &principal_user, &header.resource, "ssh", now_secs());
        match d {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("wrong target device must be denied"),
        }
    }

    #[test]
    fn evaluate_user_grant_matches_device() {
        // target_kind=User: a device chaining to that user_pub is authorized
        let owner = make_owner();
        let nonce = [0x01; 32];
        let principal_user_pub = [0xaa; 32];
        let target = CapTarget::User(principal_user_pub);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Any device pubkey works when target_kind=User and principal_user_pub matches
        let d = evaluate(&store, &header, &[0x11; 32], &principal_user_pub, &header.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("User grant must authorize device chaining to that user, got: {}", reason),
        }

        // Wrong user_pub must be denied even with correct device
        let d2 = evaluate(&store, &header, &[0x11; 32], &[0xbb; 32], &header.resource, "ssh", now_secs());
        match d2 {
            Decision::Denied(_) => {},
            Decision::Authorized => panic!("wrong user must be denied"),
        }
    }

    #[test]
    fn evaluate_ratchet_uninitialized_denies() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Store has the header (via init_store which calls apply_header → update_ratchet)
        // So ratchet IS initialized. To test uninitialized, construct a store without the ratchet.
        let mut store: Vec<Value> = vec![];
        // Manually add header without ratchet
        let mut hdr_json = header.to_json();
        hdr_json["type"] = Value::from("cap_header");
        store.push(hdr_json);

        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let mut grant_json = grant.to_json();
        grant_json["type"] = Value::from("cap_grant");
        store.push(grant_json);

        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs());
        match d {
            Decision::Denied(reason) => assert!(reason.contains("ratchet"), "must fail on uninitialized ratchet: {}", reason),
            Decision::Authorized => panic!("uninitialized ratchet must deny grants"),
        }

        // But owner is still authorized even with uninitialized ratchet
        let owner_pubkey = owner_pub(&owner);
        let d2 = evaluate(&store, &header, &[0x00; 32], &owner_pubkey, &header.resource, "ssh", now_secs());
        match d2 {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("owner must be authorized even without ratchet, got: {}", reason),
        }
    }

    #[test]
    fn evaluate_clock_set_back_uses_ratchet() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        // Create a grant with a future issued_at (within skew) to advance ratchet
        let future_issued = now_secs() + 100;
        let future_expires = future_issued + 86400;
        let mut grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&owner),
            target_kind: target.kind_byte(),
            target: target.target_bytes(),
            resource: header.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: future_expires,
            issued_at: future_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        grant.sig = sign_cap_op(&grant, &owner);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Now test with `now` set behind the ratchet (clock went backwards)
        let clock_back_now = future_issued.saturating_sub(50);
        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", clock_back_now);
        // eval_time = max(clock_back_now, ratchet) = ratchet (future_issued)
        // grant.expires = future_issued + 86400
        // eval_time (future_issued) < grant.expires (future_issued + 86400) -> authorized
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("clock set back must still authorize via ratchet, got: {}", reason),
        }
    }

    // -- B2 per-owner ratchet -----------------------------------------------

    #[test]
    fn ratchet_per_owner_isolation() {
        let alice = make_owner();
        let bob = make_owner();
        let nonce_a = [0x01; 32];
        let nonce_b = [0x02; 32];
        let target = CapTarget::Device([0xcc; 32]);

        let header_a = make_genesis_header(&alice, &nonce_a, &[]);
        let header_b = make_genesis_header(&bob, &nonce_b, &[]);

        let mut store = init_store(&header_a);
        // Use a combined store with both headers and ratchets
        // Bob's future issued_at must NOT expire Alice's grants

        // Bob issues a grant with a far-future issued_at (but within skew)
        let future_issued = now_secs() + 100;
        let mut bob_grant = CapOp {
            op: CapOpKind::Grant,
            grantor: owner_pub(&bob),
            target_kind: target.kind_byte(),
            target: [0xdd; 32],
            resource: header_b.resource.clone(),
            permissions: vec!["ssh".to_string()],
            expires: future_issued + 86400,
            issued_at: future_issued,
            version: hlc_next(0, now_ms()),
            sig: [0u8; 64],
        };
        bob_grant.sig = sign_cap_op(&bob_grant, &bob);

        // Initialize Bob's header and apply his grant
        apply_header(&mut store, &header_b).unwrap();
        apply_cap_op(&mut store, &header_b, &bob_grant, now_secs()).unwrap();

        // Alice's grant with now-ish issued_at
        let v1 = hlc_next(0, now_ms());
        let alice_grant = make_grant(&alice, target, &header_a.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &header_a, &alice_grant, now_secs()).unwrap();

        // Bob's ratchet is at future_issued. Alice's ratchet should be her own.
        // evaluate Alice's grant: ratchet_for(Alice's owner) != future_issued
        let principal_user = [0xaa; 32];
        let d = evaluate(&store, &header_a, &[0xcc; 32], &principal_user, &header_a.resource, "ssh", now_secs());
        match d {
            Decision::Authorized => {},
            Decision::Denied(reason) => panic!("Bob's ratchet must not expire Alice's grant: {}", reason),
        }
    }

    #[test]
    fn ratchet_far_future_clamp() {
        let owner = make_owner();
        let far_future = now_secs() + MAX_SKEW_SECS + 1;
        let nonce = [0x01; 32];
        let header = make_genesis_header(&owner, &nonce, &[]);

        let mut store = init_store(&header);
        let res = update_ratchet(&mut store, &owner_pub(&owner), far_future);
        assert!(res.is_err(), "far-future issued_at must be rejected");
    }

    /// Zero-config: a resource with no header is UNPROVISIONED, distinct from a
    /// header that denies. cap_gate_effective keeps legacy authoritative in shadow,
    /// so a fresh owner is never locked out, and buckets this as no-header (not a
    /// disagreement) so it neither floods CRITICAL nor blocks the flip criterion.
    #[test]
    fn cap_authorize_no_header_is_unprovisioned() {
        let tmp = std::env::temp_dir().join(format!("fil-cap-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let d = cap_authorize(&tmp, "self", "shell", Some(&[0xcc; 32]), Some(&[0xaa; 32]));
        match d {
            CapOutcome::Unprovisioned => {}
            other => panic!("no-header must be Unprovisioned, got {other:?}"),
        }
        std::fs::remove_dir_all(&tmp).ok();
    }

    /// The flip criterion is code, not prose: a clean legacy-ALLOWED sample with
    /// everything provisioned is ready; a bare zero total, a real disagreement, or
    /// any unprovisioned resource each block the flip. Pure (no global atomics), so
    /// it is not subject to the parallel-test interference the process-global
    /// counters would have.
    #[test]
    fn shadow_flip_criterion() {
        let ready = ShadowCounts { la_authorized: 5, la_denied: 0, la_no_header: 0, ld_authorized: 2, ld_denied: 3, ld_no_header: 0 };
        assert!(ready.flip_ready(), "clean legacy-allowed sample, all provisioned, must be flip-ready");
        let empty = ShadowCounts { la_authorized: 0, la_denied: 0, la_no_header: 0, ld_authorized: 0, ld_denied: 0, ld_no_header: 0 };
        assert!(!empty.flip_ready(), "no sample yet: a bare zero total must NOT pass");
        let disagree = ShadowCounts { la_authorized: 10, la_denied: 1, la_no_header: 0, ld_authorized: 0, ld_denied: 0, ld_no_header: 0 };
        assert!(!disagree.flip_ready(), "a real header disagreement must block the flip");
        let unprov = ShadowCounts { la_authorized: 10, la_denied: 0, la_no_header: 4, ld_authorized: 0, ld_denied: 0, ld_no_header: 0 };
        assert!(!unprov.flip_ready(), "an unprovisioned resource must block the flip (absent != clean)");
        assert!(disagree.summary().contains("flip_ready=false"));
    }

    // -- B4 preview + self-lockout ------------------------------------------

    #[test]
    fn preview_matches_enforcement() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);
        let v1 = hlc_next(0, now_ms());
        let principal_user = [0xaa; 32];

        // Store with one grant
        let mut store = init_store(&header);
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        // Preview applying a revoke of that grant
        let v2 = hlc_next(v1, now_ms());
        let revoke = make_revoke(&owner, target, &header.resource, v2, 86400);
        let revoke2 = revoke.clone();

        let queries = vec![
            AuthQuery {
                principal_device_pub: [0xcc; 32],
                principal_user_pub: principal_user,
                action: "ssh".to_string(),
            },
        ];

        let preview_results = preview(&store, &header, &[revoke2], &queries, now_secs());
        assert!(!preview_results[0].authorized, "preview of revoke must show Denied");

        // Apply revoke for real and evaluate — must match preview
        apply_cap_op(&mut store, &header, &revoke, now_secs()).unwrap();
        let real_d = evaluate(&store, &header, &[0xcc; 32], &principal_user, &header.resource, "ssh", now_secs());
        assert!(matches!(real_d, Decision::Denied(_)), "real enforcement must match preview");

        // No-op preview: should show Authorized (preview doesn't mutate store)
        let mut store2 = init_store(&header);
        apply_cap_op(&mut store2, &header, &grant, now_secs()).unwrap();
        let preview_current = preview(&store2, &header, &[], &queries, now_secs());
        assert!(preview_current[0].authorized, "preview of no-op must show Authorized for existing grant");
    }

    #[test]
    fn self_lockout_warns_on_admin_loss() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let v2 = hlc_next(v1, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["admin", "ssh"], v1, 86400);
        let narrow = make_grant(&owner, target, &header.resource, &["ssh"], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principals = vec![(
            "bob".to_string(),
            [0xcc; 32],
            [0xaa; 32],
        )];

        // Narrowing from ["admin","ssh"] to ["ssh"] loses "admin"
        let warnings = check_self_lockout(
            &store, &header, &narrow, &principals, &["admin", "ssh", "shell"], now_secs(),
        );
        assert!(!warnings.is_empty(), "must warn when admin action is lost");
        assert!(warnings[0].contains("admin"), "warning must mention the lost action");
    }

    #[test]
    fn self_lockout_no_warn_on_gain() {
        let owner = make_owner();
        let nonce = [0x01; 32];
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, &nonce, &[]);

        let v1 = hlc_next(0, now_ms());
        let v2 = hlc_next(v1, now_ms());
        let grant = make_grant(&owner, target, &header.resource, &["ssh"], v1, 86400);
        let expand = make_grant(&owner, target, &header.resource, &["ssh", "admin"], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();

        let principals = vec![("bob".to_string(), [0xcc; 32], [0xaa; 32])];

        // Expanding grants must NOT warn (no loss)
        let warnings = check_self_lockout(
            &store, &header, &expand, &principals, &["admin"], now_secs(),
        );
        assert!(warnings.is_empty(), "must not warn when gaining access");
    }
}
