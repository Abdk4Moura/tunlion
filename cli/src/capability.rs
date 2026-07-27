//! Capability/grant layer: two owner-signed objects + monotonic store.
//!
//! CapOp: an owner-signed grant/revoke/modify.  CapHeader: the owner-signed
//! resource header (epoch, owner_pub, per-target version FLOOR, succession).
//! Ownership is derived from the header, never a grant.  The store is a pure
//! `Vec<serde_json::Value>` that callers load/save in thin wrappers (mirroring
//! identity::apply_peer_identity / update_peer_identity).
use anyhow::{anyhow, bail, Result};
use ring::signature::{Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde_json::Value;

/// Hybrid logical clock: version = max(wall_clock_ms, last_seen + 1).
/// Survives cold-key restore where local edge counters are lost.
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

    fn match_key(&self, grantor_hex: &str, target_kind: u8, target_hex: &str) -> bool {
        hex::encode(self.grantor) == grantor_hex
            && self.target_kind == target_kind
            && hex::encode(self.target) == target_hex
    }
}

pub fn sign_cap_op(op: &CapOp, keypair: &Ed25519KeyPair) -> [u8; 64] {
    let sig = keypair.sign(&op.canonical_for_signing());
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
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
    pub floors: Vec<CapFloor>,
    pub issued_at: u64,
    pub prev_owner_pub: Option<[u8; 32]>,
    pub sig: [u8; 64],
}

impl CapHeader {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }

    pub fn canonical_for_signing(&self) -> Vec<u8> {
        // Floors blob: 4-byte LE count, then each floor: LP(target 33B) + LP(min_version 8B LE)
        let mut floors_blob = Vec::new();
        floors_blob.extend_from_slice(&(self.floors.len() as u32).to_le_bytes());
        for f in &self.floors {
            Self::lp(&mut floors_blob, &f.encode());
            Self::lp(&mut floors_blob, &f.min_version.to_le_bytes());
        }

        // prev_owner_pub: 1 byte flag (0x00 absent, 0x01 present) + 32 bytes
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

        let mut v = Vec::new();
        v.extend_from_slice(CAPHEADER_SIGN_DOMAIN);
        Self::lp(&mut v, self.resource.as_bytes());
        Self::lp(&mut v, &self.epoch.to_le_bytes());
        Self::lp(&mut v, &self.owner_pub);
        Self::lp(&mut v, &floors_blob);
        Self::lp(&mut v, &self.issued_at.to_le_bytes());
        Self::lp(&mut v, &prev_blob);
        v
    }

    /// Verify ownership chain. Genesis (epoch 0, prev_owner_pub=None) is
    /// self-signed. Succession (epoch N>0, prev_owner_pub=Some(old)) must
    /// be signed by the previous owner.
    pub fn verify(&self, prev_owner: Option<&[u8; 32]>) -> Result<()> {
        let canonical = self.canonical_for_signing();

        let signer = if self.epoch == 0 || self.prev_owner_pub.is_none() {
            // Genesis: self-signed
            &self.owner_pub
        } else {
            // Succession: must be signed by previous owner
            match prev_owner {
                Some(pk) => pk,
                None => bail!("succession header needs a previous owner to verify against"),
            }
        };

        let peer_pub = UnparsedPublicKey::new(&ED25519, signer);
        peer_pub
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("capability header signature invalid"))
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
            "resource": self.resource,
            "epoch": self.epoch,
            "owner_pub": hex::encode(self.owner_pub),
            "floors": floors,
            "issued_at": self.issued_at,
            "prev_owner_pub": self.prev_owner_pub.map(hex::encode),
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let owner_pub = {
            let b = hex::decode(v["owner_pub"].as_str()?).ok()?;
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
            floors,
            issued_at: v["issued_at"].as_u64()?,
            prev_owner_pub,
            sig,
        })
    }

    /// Find the floor min_version for a given target in this header.
    /// Returns 0 if no floor is set for that target.
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
// Store fns  (pure, no file I/O)
// ---------------------------------------------------------------------------

fn find_header_idx(store: &[Value], resource: &str) -> Option<usize> {
    store
        .iter()
        .position(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                      && e["resource"].as_str() == Some(resource))
}

/// Apply the resource header.  Genesis (epoch=0) is self-signed; succession
/// (epoch N>0) must be signed by the PREVIOUS epoch's owner_pub and epoch
/// must be strictly forward.
pub fn apply_header(store: &mut Vec<Value>, new_header: &CapHeader) -> Result<()> {
    let existing_idx = find_header_idx(store, &new_header.resource);

    // Verify the ownership chain
    let prev_owner = existing_idx.map(|i| {
        let pk_hex = store[i]["owner_pub"].as_str().unwrap_or("");
        let bytes = hex::decode(pk_hex).unwrap_or_default();
        let mut pk = [0u8; 32];
        if bytes.len() == 32 { pk.copy_from_slice(&bytes); }
        pk
    });

    // Genesis: prev_owner_pub must be None
    if existing_idx.is_none() {
        if new_header.prev_owner_pub.is_some() {
            bail!("genesis header must have prev_owner_pub=None");
        }
        if new_header.epoch != 0 {
            bail!("genesis header must have epoch=0");
        }
    } else {
        if new_header.prev_owner_pub.is_none() {
            bail!("succession header must have prev_owner_pub set");
        }
        if let Some(prev) = prev_owner {
            if new_header.prev_owner_pub != Some(prev) {
                bail!("succession header prev_owner_pub must equal current owner");
            }
        }
    }

    new_header.verify(prev_owner.as_ref())?;

    let mut hdr_json = new_header.to_json();
    hdr_json["type"] = Value::from("cap_header");

    // Strictly forward epoch
    if let Some(idx) = existing_idx {
        let existing_epoch = store[idx]["epoch"].as_u64().unwrap_or(0);
        if new_header.epoch <= existing_epoch {
            bail!(
                "epoch not strictly forward: new {} <= existing {}",
                new_header.epoch,
                existing_epoch
            );
        }
        store[idx] = hdr_json;
    } else {
        store.push(hdr_json);
    }
    Ok(())
}

/// Apply a verified capability op to the store.
///
/// (1) verify op under header.owner_pub
/// (2) FLOOR: reject if op.version < header floor for that target
///     (defeats revoked-grant resurrection on fresh/restored stores)
/// (3) MONOTONIC: reject if stored version >= op.version
/// (4) insert/replace; Revoke or empty permissions removes the grant
pub fn apply_cap_op(
    store: &mut Vec<Value>,
    header: &CapHeader,
    op: &CapOp,
    now: u64,
) -> Result<()> {
    op.verify(&header.owner_pub, now)?;

    // Ensure the store has this header
    if find_header_idx(store, &header.resource).is_none() {
        bail!("cannot apply cap op: no header for resource '{}' in store", &header.resource);
    }

    // Floor check
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

    // Monotonic guard
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
                    "monotonic version refusal: existing {} >= new {} for grantor {} target {}/{} resource {}",
                    existing_version,
                    op.version,
                    grantor_hex,
                    op.target_kind,
                    target_hex,
                    op.resource
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

    /// Build a signed genesis header (epoch 0, self-signed).
    fn make_genesis_header(
        owner: &Ed25519KeyPair,
        resource: &str,
        floors: &[CapFloor],
    ) -> CapHeader {
        let mut h = CapHeader {
            resource: resource.to_string(),
            epoch: 0,
            owner_pub: owner_pub(owner),
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: None,
            sig: [0u8; 64],
        };
        h.sig = sign_cap_header(&h, owner);
        h
    }

    /// Build a signed succession header.
    fn make_succession_header(
        prev_owner: &Ed25519KeyPair,
        new_owner: &Ed25519KeyPair,
        resource: &str,
        epoch: u64,
        floors: &[CapFloor],
    ) -> CapHeader {
        let mut h = CapHeader {
            resource: resource.to_string(),
            epoch,
            owner_pub: owner_pub(new_owner),
            floors: floors.to_vec(),
            issued_at: now_secs(),
            prev_owner_pub: Some(owner_pub(prev_owner)),
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
        let header = make_genesis_header(&owner, "shell", &[]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, "shell", &["ssh", "shell"], v1, 86400);

        grant.verify(&pk, now_secs()).unwrap();

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        let grants: Vec<_> = store.iter().filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")).collect();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["resource"].as_str().unwrap(), "shell");
        assert_eq!(grants[0]["version"].as_u64().unwrap(), v1);
    }

    #[test]
    fn tampered_permission_verify_fails() {
        let owner = make_owner();
        let pk = owner_pub(&owner);
        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let mut grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
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
        let mut grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
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
        let mut grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
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
        let mut grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
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
        let mut grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
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

        let target = CapTarget::Device([0xcc; 32]);
        let v1 = hlc_next(0, now_ms());
        let grant = make_grant(&alice, target, "shell", &["ssh"], v1, 86400);
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
        let header = make_genesis_header(&owner, "shell", &[]);

        let seed = now_ms();
        let v5 = hlc_next(hlc_next(hlc_next(hlc_next(hlc_next(0, seed), seed), seed), seed), seed);
        let v3 = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);

        let grant_v5 = make_grant(&owner, target, "shell", &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, "shell", &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();
        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5 -> v3 must be rejected");
    }

    #[test]
    fn revoke_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, "shell", &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);

        let grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
        let revoke = make_revoke(&owner, target, "shell", v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &revoke, now_secs()).unwrap();

        let grants: Vec<_> = store.iter().filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")).collect();
        assert_eq!(grants.len(), 0, "revoke must remove grant");
    }

    #[test]
    fn empty_permissions_removes_grant() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, "shell", &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);

        let grant = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
        let empty_grant = make_grant(&owner, target, "shell", &[], v2, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &empty_grant, now_secs()).unwrap();

        let grants: Vec<_> = store.iter().filter(|e| e.get("type").and_then(|v| v.as_str()) == Some("cap_grant")).collect();
        assert_eq!(grants.len(), 0);
    }

    #[test]
    fn rollback_guard_red_without_fix() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, "shell", &[]);

        let seed = now_ms();
        let v1 = hlc_next(0, seed);
        let v2 = hlc_next(v1, seed);
        let v3 = hlc_next(v2, seed);
        let v4 = hlc_next(v3, seed);
        let v5 = hlc_next(v4, seed);

        let grant_v5 = make_grant(&owner, target, "shell", &["ssh", "shell"], v5, 86400);
        let grant_v3 = make_grant(&owner, target, "shell", &["ssh"], v3, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_v5, now_secs()).unwrap();

        // v3 has a valid signature (no tampering) -- would pass without the guard
        let owner_pubkey = owner_pub(&owner);
        assert!(grant_v3.verify(&owner_pubkey, now_secs()).is_ok());

        let res = apply_cap_op(&mut store, &header, &grant_v3, now_secs());
        assert!(res.is_err(), "rollback v5->v3 must be REFUSED; if green, guard is broken");
    }

    // -- Floor --------------------------------------------------------------

    #[test]
    fn floor_rejects_first_seen_op_below_min_version() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let seed = now_ms();
        let floor_ver = hlc_next(hlc_next(hlc_next(0, seed), seed), seed);
        let low_ver = hlc_next(0, seed);

        let header = make_genesis_header(
            &owner,
            "shell",
            &[CapFloor {
                target_kind: target.kind_byte(),
                target: target.target_bytes(),
                min_version: floor_ver,
            }],
        );

        let grant_low = make_grant(&owner, target, "shell", &["ssh"], low_ver, 86400);
        let mut store = init_store(&header);
        let res = apply_cap_op(&mut store, &header, &grant_low, now_secs());
        assert!(res.is_err(), "op below floor must be rejected");

        // Version above floor must apply
        let v = hlc_next(floor_ver, seed);
        let grant_ok = make_grant(&owner, target, "shell", &["ssh"], v, 86400);
        apply_cap_op(&mut store, &header, &grant_ok, now_secs()).unwrap();
    }

    // -- Header succession --------------------------------------------------

    #[test]
    fn succession_alice_to_bob_applies_bobs_ops() {
        let alice = make_owner();
        let bob = make_owner();
        let target = CapTarget::Device([0xcc; 32]);

        // Genesis by Alice
        let genesis = make_genesis_header(&alice, "shell", &[]);
        let mut store = init_store(&genesis);

        let v1 = hlc_next(0, now_ms());
        let grant_alice = make_grant(&alice, target, "shell", &["ssh"], v1, 86400);
        apply_cap_op(&mut store, &genesis, &grant_alice, now_secs()).unwrap();

        // Succession: Alice -> Bob
        let succ = make_succession_header(&alice, &bob, "shell", 1, &[]);
        // Verify under Alice's key, prev_owner_pub == Alice
        succ.verify(Some(&owner_pub(&alice))).unwrap();
        apply_header(&mut store, &succ).unwrap();

        // Bob's op applies under Bob's header
        let v2 = hlc_next(v1, now_ms());
        let grant_bob = make_grant(&bob, target, "shell", &["shell"], v2, 86400);
        apply_cap_op(&mut store, &succ, &grant_bob, now_secs()).unwrap();

        // Alice's key no longer works
        let v3 = hlc_next(v2, now_ms());
        let grant_alice2 = make_grant(&alice, target, "shell", &["admin"], v3, 86400);
        assert!(apply_cap_op(&mut store, &succ, &grant_alice2, now_secs()).is_err());
    }

    #[test]
    fn succession_not_signed_by_prev_owner_rejected() {
        let alice = make_owner();
        let bob = make_owner();
        let mallory = make_owner();

        let genesis = make_genesis_header(&alice, "shell", &[]);
        let mut store = init_store(&genesis);

        // Mallory tries to sign succession (pretending to be Alice)
        let mut bogus = CapHeader {
            resource: "shell".to_string(),
            epoch: 1,
            owner_pub: owner_pub(&bob),
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(owner_pub(&alice)),
            sig: [0u8; 64],
        };
        bogus.sig = sign_cap_header(&bogus, &mallory); // Signed by Mallory, not Alice

        // Canonical's signer is prev_owner_pub (alice). Sig is from Mallory -> fail
        let res = apply_header(&mut store, &bogus);
        assert!(res.is_err(), "succession not signed by prev owner must be rejected");
    }

    #[test]
    fn non_forward_epoch_rejected() {
        let alice = make_owner();
        let bob = make_owner();

        let genesis = make_genesis_header(&alice, "shell", &[]);
        let mut store = init_store(&genesis);

        let succ1 = make_succession_header(&alice, &bob, "shell", 1, &[]);
        apply_header(&mut store, &succ1).unwrap();

        // Replay epoch 1 (same epoch)
        let res = apply_header(&mut store, &succ1);
        assert!(res.is_err(), "non-forward epoch must be rejected");

        // Epoch 0 backward
        let mut bad = CapHeader {
            resource: "shell".to_string(),
            epoch: 0,
            owner_pub: owner_pub(&alice),
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(owner_pub(&bob)),
            sig: [0u8; 64],
        };
        bad.sig = sign_cap_header(&bad, &bob);
        let res2 = apply_header(&mut store, &bad);
        assert!(res2.is_err(), "backward epoch must be rejected");
    }

    #[test]
    fn succession_prev_owner_pub_consistency() {
        let alice = make_owner();
        let bob = make_owner();
        let carol = make_owner();

        let genesis = make_genesis_header(&alice, "shell", &[]);
        let mut store = init_store(&genesis);

        // Succession MUST set prev_owner_pub = current owner (alice)
        let mut bad = CapHeader {
            resource: "shell".to_string(),
            epoch: 1,
            owner_pub: owner_pub(&carol),
            floors: vec![],
            issued_at: now_secs(),
            prev_owner_pub: Some(owner_pub(&bob)), // pretends bob was previous owner
            sig: [0u8; 64],
        };
        bad.sig = sign_cap_header(&bad, &bob); // Signed by bob
        let res = apply_header(&mut store, &bad);
        assert!(res.is_err(), "prev_owner_pub must equal current store owner");
    }

    // -- Domain separation ---------------------------------------------------

    #[test]
    fn domain_separation_three_way() {
        let owner = make_owner();
        let target = CapTarget::Device([0x11; 32]);
        let v1 = hlc_next(0, now_ms());

        let op = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
        let header = make_genesis_header(&owner, "shell", &[]);

        let op_canon = op.canonical_for_signing();
        let header_canon = header.canonical_for_signing();

        let op_domain: &[u8] = b"filament/capability-op/v1";
        let header_domain: &[u8] = b"filament/capability-header/v1";
        let cert_domain: &[u8] = b"filament/identity-device-cert/v1";

        assert_ne!(op_domain, header_domain, "op vs header domain tags must differ");
        assert_ne!(op_domain, cert_domain, "op vs cert domain tags must differ");
        assert_ne!(header_domain, cert_domain, "header vs cert domain tags must differ");

        assert!(op_canon.starts_with(op_domain));
        assert!(!op_canon.starts_with(header_domain));
        assert!(!op_canon.starts_with(cert_domain));

        assert!(header_canon.starts_with(header_domain));
        assert!(!header_canon.starts_with(op_domain));
        assert!(!header_canon.starts_with(cert_domain));

        // Length-prefixed framing: different domain lengths guarantee LP differences
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
        let target = CapTarget::Device([0x11; 32]);
        let seed = now_ms();

        let op1 = make_grant(&owner, target, "shell", &["ssh"], hlc_next(0, seed), 86400);
        let op2 = make_grant(&owner, target, "shell", &["ssh"], hlc_next(hlc_next(0, seed), seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op2.canonical_for_signing());

        let op3 = make_grant(&owner, target, "shell", &["ssh", "shell"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op3.canonical_for_signing());

        let target2 = CapTarget::Device([0x22; 32]);
        let op4 = make_grant(&owner, target2, "shell", &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op4.canonical_for_signing());

        let op5 = make_grant(&owner, target, "admin", &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op5.canonical_for_signing());

        // User vs Device target kind
        let op_user = make_grant(&owner, CapTarget::User([0x11; 32]), "shell", &["ssh"], hlc_next(0, seed), 86400);
        assert_ne!(op1.canonical_for_signing(), op_user.canonical_for_signing());
    }

    // -- JSON roundtrip -----------------------------------------------------

    #[test]
    fn grant_json_roundtrip() {
        let owner = make_owner();
        let target = CapTarget::Device([0x42; 32]);
        let v = hlc_next(0, now_ms());
        let grant = make_grant(&owner, target, "transfer", &["send", "receive"], v, 86400);

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
        let header = make_genesis_header(
            &owner,
            "shell",
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
        assert_eq!(header.floors.len(), header2.floors.len());
        assert_eq!(header.issued_at, header2.issued_at);
        assert_eq!(header.prev_owner_pub, header2.prev_owner_pub);
        assert_eq!(header.sig, header2.sig);

        header2.verify(None).unwrap();
    }

    // -- Multi-resource, independent versioning -----------------------------

    #[test]
    fn cross_resource_independent_keys() {
        let owner = make_owner();
        let target = CapTarget::Device([0xcc; 32]);
        let header = make_genesis_header(&owner, "shell", &[]);

        let v1 = hlc_next(0, now_ms());
        let grant_shell = make_grant(&owner, target, "shell", &["ssh"], v1, 86400);
        let grant_transfer = make_grant(&owner, target, "transfer", &["send"], v1, 86400);

        let mut store = init_store(&header);
        apply_cap_op(&mut store, &header, &grant_shell, now_secs()).unwrap();
        apply_cap_op(&mut store, &header, &grant_transfer, now_secs()).unwrap();
        assert_eq!(store.len(), 3); // header + 2 grants

        let v2 = hlc_next(v1, now_ms());
        let grant_shell_v2 = make_grant(&owner, target, "shell", &["ssh", "shell"], v2, 86400);
        apply_cap_op(&mut store, &header, &grant_shell_v2, now_secs()).unwrap();
        assert_eq!(store.len(), 3);
    }

    // -- HLC ----------------------------------------------------------------

    #[test]
    fn hlc_seeds_from_wall_clock_not_zero() {
        let v = hlc_next(0, now_ms());
        assert!(v > 0);
        let v2 = hlc_next(v, now_ms());
        assert!(v2 > v);
    }
}
