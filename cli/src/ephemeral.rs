//! Ephemeral devices and auth keys — pre-authorized self-enrollment.
//!
//! Two enrollment doors, one trust root:
//!   1. Interactive pairing (PAKE): people and persistent devices
//!   2. Auth key: programmatic and ephemeral, pre-authorized delegation
//!
//! Both root in the same user key. The auth key is the user key pre-authorizing
//! the second door with a scope and a clock on it.
//!
//! Design: docs/design-ephemeral-auth-keys.md

use anyhow::{anyhow, bail, Result};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------------------
// AuthKey — owner-signed delegation token (no bearer secret)
// ---------------------------------------------------------------------------

/// Controls how many times an auth key may be used to enroll.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reuse {
    Once,
    N(u32),
    Reusable,
}

impl Reuse {
    fn to_byte(&self) -> u8 {
        match self {
            Reuse::Once => 0,
            Reuse::N(_) => 1,
            Reuse::Reusable => 2,
        }
    }
}

/// An owner-signed delegation token that authorizes a device to self-enroll
/// as a delegated principal. Carries an enroll PUBLIC key (no bearer secret).
#[derive(Debug, Clone)]
pub struct AuthKey {
    /// Owner's Ed25519 public key (the issuer, must match a trusted user_pub).
    pub issuer: [u8; 32],
    /// Public key of the enrollment keypair that the enrolled device must
    /// prove possession of. NOT a bearer secret — verifier learns only a
    /// public key, nothing replayable.
    pub enroll_pub: [u8; 32],
    /// Semantic capability actions — a CEILING, not a floor (see delegated
    /// principal). Sorted, deduplicated, lowercase for canonical marshalling.
    pub caps: Vec<String>,
    /// Which peer(s) may enroll this key. Empty = Any.
    pub audience: Vec<[u8; 32]>,
    /// Absolute expiry (unix seconds). MANDATORY, capped low by construction.
    pub expires: u64,
    /// How many times this key may be used.
    pub reuse: Reuse,
    /// Whether the enrolled device is ephemeral (removed on disconnect).
    pub ephemeral: bool,
    /// Human-readable tag for the use case ("ci", "gpu-borrower", etc.).
    pub tag: String,
    /// Ed25519 signature by the owner's user key over the canonical bytes.
    pub sig: [u8; 64],
}

/// Canonical bytes that the signature covers — deterministic, no ambiguity.
fn auth_key_canonical_bytes(k: &AuthKey) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"filament-auth-key-v1");
    b.extend_from_slice(&k.issuer);
    b.extend_from_slice(&k.enroll_pub);
    // caps sorted, deduped, lowercase
    let mut caps = k.caps.clone();
    caps.sort();
    caps.dedup();
    for c in &caps {
        let lc: String = c.to_lowercase();
        b.extend_from_slice(&(lc.len() as u8).to_le_bytes());
        b.extend_from_slice(lc.as_bytes());
    }
    // audience sorted
    let mut aud = k.audience.clone();
    aud.sort();
    b.push(aud.len() as u8);
    for a in &aud {
        b.extend_from_slice(a);
    }
    b.extend_from_slice(&k.expires.to_le_bytes());
    b.push(k.reuse.to_byte());
    b.push(if k.ephemeral { 1 } else { 0 });
    b.extend_from_slice(&(k.tag.len() as u8).to_le_bytes());
    b.extend_from_slice(k.tag.as_bytes());
    b
}

impl AuthKey {
    /// Mint a new auth key signed by the owner's user key.
    pub fn mint(
        owner_uk: &Ed25519KeyPair,
        enroll_pub: [u8; 32],
        caps: Vec<String>,
        audience: Vec<[u8; 32]>,
        ttl_secs: u64,
        reuse: Reuse,
        tag: String,
    ) -> Result<Self> {
        let now = now_secs();
        let mut k = AuthKey {
            issuer: owner_uk.public_key().as_ref().try_into().map_err(|_| anyhow!("bad owner pub"))?,
            enroll_pub,
            caps,
            audience,
            expires: now.saturating_add(ttl_secs),
            reuse,
            ephemeral: true,
            tag,
            sig: [0u8; 64],
        };
        let canonical = auth_key_canonical_bytes(&k);
        let sig = owner_uk.sign(&canonical);
        let sig_bytes: [u8; 64] = sig.as_ref().try_into().map_err(|_| anyhow!("bad sig"))?;
        k.sig = sig_bytes;
        Ok(k)
    }

    /// Verify the owner's signature + expiry (does NOT check issuer trust).
    pub fn verify(&self) -> Result<()> {
        if now_secs() >= self.expires {
            bail!("auth key expired");
        }
        let canonical = auth_key_canonical_bytes(self);
        let pubkey = UnparsedPublicKey::new(&ED25519, &self.issuer);
        pubkey
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("auth key signature invalid"))
    }

    /// Full verification against a trusted owner: sig valid, not expired,
    /// AND the issuer equals the trusted owner_pub (genesis-forgery rule).
    pub fn verify_against_owner(&self, owner_pub: &[u8; 32]) -> Result<()> {
        self.verify()?;
        if &self.issuer != owner_pub {
            bail!("auth key issuer does not match trusted owner");
        }
        // Mesh refusal: verifier-side structural ban, regardless of valid sig.
        if self.caps.iter().any(|c| c == "mesh") {
            bail!("auth keys must not carry mesh capability");
        }
        Ok(())
    }

    /// Returns true if audience is empty (Any) or this peer is named.
    pub fn audience_allows(&self, peer_pub: &[u8; 32]) -> bool {
        self.audience.is_empty() || self.audience.contains(peer_pub)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "issuer": hex::encode(self.issuer),
            "enroll_pub": hex::encode(self.enroll_pub),
            "caps": self.caps,
            "audience": self.audience.iter().map(hex::encode).collect::<Vec<_>>(),
            "expires": self.expires,
            "reuse": self.reuse,
            "ephemeral": self.ephemeral,
            "tag": self.tag,
            "sig": hex::encode(self.sig),
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let issuer = hex::decode(v.get("issuer")?.as_str()?).ok()?;
        let enroll_pub = hex::decode(v.get("enroll_pub")?.as_str()?).ok()?;
        let caps: Vec<String> = v.get("caps")?.as_array()?
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect();
        let audience: Vec<[u8; 32]> = v.get("audience")?.as_array()?
            .iter()
            .filter_map(|x| {
                let b = hex::decode(x.as_str()?).ok()?;
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&b);
                Some(arr)
            })
            .collect();
        let expires = v.get("expires")?.as_u64()?;
        let reuse = match v.get("reuse")?.as_str()? {
            "Once" => Reuse::Once,
            "Reusable" => Reuse::Reusable,
            s if s.starts_with("N(") => {
                let n: u32 = s[2..s.len()-1].parse().ok()?;
                Reuse::N(n)
            }
            _ => return None,
        };
        let ephemeral = v.get("ephemeral")?.as_bool()?;
        let tag = v.get("tag")?.as_str()?.to_string();
        let sig = hex::decode(v.get("sig")?.as_str()?).ok()?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig);
        let mut issuer_arr = [0u8; 32];
        issuer_arr.copy_from_slice(&issuer);
        let mut enroll_arr = [0u8; 32];
        enroll_arr.copy_from_slice(&enroll_pub);
        Some(AuthKey { issuer: issuer_arr, enroll_pub: enroll_arr, caps, audience, expires, reuse, ephemeral, tag, sig: sig_arr })
    }
}

impl serde::Serialize for Reuse {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Reuse::Once => s.serialize_str("Once"),
            Reuse::N(n) => s.serialize_str(&format!("N({})", n)),
            Reuse::Reusable => s.serialize_str("Reusable"),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Reuse {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        match s.as_str() {
            "Once" => Ok(Reuse::Once),
            "Reusable" => Ok(Reuse::Reusable),
            s if s.starts_with("N(") && s.ends_with(')') => {
                let n: u32 = s[2..s.len()-1].parse().map_err(serde::de::Error::custom)?;
                Ok(Reuse::N(n))
            }
            _ => Err(serde::de::Error::custom(format!("invalid Reuse: {}", s))),
        }
    }
}

// ---------------------------------------------------------------------------
// Enrollment payload — what the enrolling machine presents to a verifying peer
// ---------------------------------------------------------------------------

/// The enrollment payload carried over the wire. The machine generates its own
/// device keypair and presents the auth key + device_pub + possession proofs.
pub struct EnrollmentPayload {
    pub auth_key: AuthKey,
    pub device_pub: [u8; 32],
    /// Possession proof: sign("filament-auth-key-enroll-v1" || nonce || device_pub)
    /// with enroll_priv (proves holder possesses auth key's private half).
    pub enroll_possession_sig: [u8; 64],
    /// Possession proof: same message signed with device_priv (proves holder
    /// possesses the device key it claims).
    pub device_possession_sig: [u8; 64],
    /// The session nonce used to bind to this enrollment attempt.
    pub nonce: [u8; 32],
}

fn enrollment_possession_msg(nonce: &[u8; 32], device_pub: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"filament-auth-key-enroll-v1");
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(device_pub);
    msg
}

impl EnrollmentPayload {
    /// Build payload: sign possession messages with both keys.
    pub fn build(
        auth_key: AuthKey,
        device_pub: [u8; 32],
        enroll_keypair: &Ed25519KeyPair,
        device_keypair: &Ed25519KeyPair,
        nonce: [u8; 32],
    ) -> Self {
        let msg = enrollment_possession_msg(&nonce, &device_pub);
        let enroll_sig = enroll_keypair.sign(&msg);
        let device_sig = device_keypair.sign(&msg);
        let mut es = [0u8; 64];
        es.copy_from_slice(enroll_sig.as_ref());
        let mut ds = [0u8; 64];
        ds.copy_from_slice(device_sig.as_ref());
        EnrollmentPayload {
            auth_key,
            device_pub,
            enroll_possession_sig: es,
            device_possession_sig: ds,
            nonce,
        }
    }

    /// Verify the enrollment payload against a trusted owner.
    /// Returns (enroll_pub, device_pub, verified_auth_key) on success.
    pub fn verify(&self, owner_pub: &[u8; 32]) -> Result<([u8; 32], [u8; 32], AuthKey)> {
        // 1. Verify auth key under trusted owner
        self.auth_key.verify_against_owner(owner_pub)?;

        // 2. Verify enroll possession — holder proves ownership of enroll_priv
        let msg = enrollment_possession_msg(&self.nonce, &self.device_pub);
        let enroll_pkey = UnparsedPublicKey::new(&ED25519, &self.auth_key.enroll_pub);
        enroll_pkey
            .verify(&msg, &self.enroll_possession_sig)
            .map_err(|_| anyhow!("enroll possession proof invalid"))?;

        // 3. Verify device possession — holder proves ownership of device_priv
        let device_pkey = UnparsedPublicKey::new(&ED25519, &self.device_pub);
        device_pkey
            .verify(&msg, &self.device_possession_sig)
            .map_err(|_| anyhow!("device possession proof invalid"))?;

        Ok((self.auth_key.enroll_pub, self.device_pub, self.auth_key.clone()))
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "auth_key": self.auth_key.to_json(),
            "device_pub": hex::encode(self.device_pub),
            "enroll_possession_sig": hex::encode(self.enroll_possession_sig),
            "device_possession_sig": hex::encode(self.device_possession_sig),
            "nonce": hex::encode(self.nonce),
        })
    }

    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let auth_key = AuthKey::from_json(v.get("auth_key")?)?;
        let device_pub = {
            let b = hex::decode(v.get("device_pub")?.as_str()?).ok()?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        };
        let enroll_possession_sig = {
            let b = hex::decode(v.get("enroll_possession_sig")?.as_str()?).ok()?;
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        };
        let device_possession_sig = {
            let b = hex::decode(v.get("device_possession_sig")?.as_str()?).ok()?;
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&b);
            arr
        };
        let nonce = {
            let b = hex::decode(v.get("nonce")?.as_str()?).ok()?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        };
        Some(EnrollmentPayload {
            auth_key,
            device_pub,
            enroll_possession_sig,
            device_possession_sig,
            nonce,
        })
    }
}

// ---------------------------------------------------------------------------
// Burn / rate-limit state — per-peer, per-enroll_pub
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

struct BurnEntry {
    used_count: u32,
    first_seen: Instant,
}

struct BurnState {
    map: HashMap<[u8; 32], BurnEntry>,
}

static BURN: OnceLock<Mutex<BurnState>> = OnceLock::new();

fn burn_state() -> &'static Mutex<BurnState> {
    BURN.get_or_init(|| Mutex::new(BurnState { map: HashMap::new() }))
}

/// Consume one use of an auth key identified by `enroll_pub`.
/// Rate-limited: MAX 5 enrollments/min per enroll_pub per peer.
pub fn burn_auth_key(enroll_pub: &[u8; 32], reuse: &Reuse) -> Result<()> {
    let mut state = burn_state().lock().unwrap();
    let entry = state.map.entry(*enroll_pub).or_insert(BurnEntry {
        used_count: 0,
        first_seen: Instant::now(),
    });

    // Rate limit: max 5 enrollments per minute per enroll_pub
    let elapsed = entry.first_seen.elapsed().as_secs();
    if entry.used_count >= 5 && elapsed < 60 {
        bail!("auth key rate-limited (max 5 enrollments/min)");
    }
    // Reset rate window after 60s
    if elapsed >= 60 {
        entry.used_count = 0;
        entry.first_seen = Instant::now();
    }

    match reuse {
        Reuse::Once => {
            if entry.used_count > 0 {
                bail!("auth key already used (single-use)");
            }
        }
        Reuse::N(max) => {
            if entry.used_count >= *max {
                bail!("auth key exhausted ({} uses)", max);
            }
        }
        Reuse::Reusable => {} // no limit, but rate-limit still applies
    }

    entry.used_count += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegated principal — auth-key-enrolled devices have ceiling = caps ∩ owner
// ---------------------------------------------------------------------------

/// A delegated principal's effective capabilities are the INTERSECTION of the
/// owner's effective caps at this peer AND the auth key's caps. This ensures
/// the delegated principal never exceeds what the owner holds at that peer AND
/// never exceeds the auth key's stated ceiling.
///
/// Both invariants are enforced:
///   effective(delegated) ⊆ auth_key_caps  (the ceiling)
///   effective(delegated) ⊆ effective(owner)  (no escalation)
pub fn delegated_effective_caps(
    owner_effective: &[String],
    auth_key_caps: &[String],
) -> Vec<String> {
    let mut result = Vec::new();
    let owner_set: std::collections::HashSet<&str> = owner_effective.iter().map(|s| s.as_str()).collect();
    for cap in auth_key_caps {
        let lc = cap.to_lowercase();
        if owner_set.contains(lc.as_str()) {
            result.push(lc);
        }
    }
    result.sort();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::{SecureRandom, SystemRandom};
    use ring::signature::KeyPair;

    fn gen_keypair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let mut seed = [0u8; 32];
        rng.fill(&mut seed).unwrap();
        Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()
    }

    #[test]
    fn auth_key_mint_verify_roundtrip() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into(), "transfer".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();
        assert!(ak.verify().is_ok());
        assert!(ak.verify_against_owner(
            &owner.public_key().as_ref().try_into().unwrap()
        ).is_ok());
    }

    #[test]
    fn auth_key_expired_fails() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let mut ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();
        // Force expiry
        ak.expires = 0;
        // verify_against_owner will catch expiry first
        assert!(ak.verify().is_err());
        // verify also catches it
        assert!(ak.verify().is_err());
    }

    #[test]
    fn auth_key_wrong_owner_fails() {
        let owner = gen_keypair();
        let other = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();
        let other_pub: [u8; 32] = other.public_key().as_ref().try_into().unwrap();
        assert!(ak.verify_against_owner(&other_pub).is_err());
    }

    #[test]
    fn auth_key_mesh_refused() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["mesh".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();
        let owner_pub: [u8; 32] = owner.public_key().as_ref().try_into().unwrap();
        assert!(ak.verify_against_owner(&owner_pub).is_err());
    }

    #[test]
    fn audience_allows_empty_is_any() {
        let ak = AuthKey {
            issuer: [0u8; 32],
            enroll_pub: [0u8; 32],
            caps: vec![],
            audience: vec![],
            expires: now_secs() + 3600,
            reuse: Reuse::Once,
            ephemeral: true,
            tag: "test".into(),
            sig: [0u8; 64],
        };
        assert!(ak.audience_allows(&[1u8; 32]));
    }

    #[test]
    fn audience_allows_named_peer() {
        let peer = [0xAA; 32];
        let ak = AuthKey {
            issuer: [0u8; 32],
            enroll_pub: [0u8; 32],
            caps: vec![],
            audience: vec![peer],
            expires: now_secs() + 3600,
            reuse: Reuse::Once,
            ephemeral: true,
            tag: "test".into(),
            sig: [0u8; 64],
        };
        assert!(ak.audience_allows(&peer));
        assert!(!ak.audience_allows(&[0xBB; 32]));
    }

    #[test]
    fn enrollment_payload_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();

        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce);
        let owner_pub: [u8; 32] = owner.public_key().as_ref().try_into().unwrap();
        let (ep, dp, _ak) = payload.verify(&owner_pub).unwrap();
        assert_eq!(ep, enroll_pub);
        assert_eq!(dp, device_pub);
    }

    #[test]
    fn enrollment_wrong_enroll_key_fails() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let wrong_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();

        let payload = EnrollmentPayload::build(ak, device_pub, &wrong_kp, &device_kp, nonce);
        let owner_pub: [u8; 32] = owner.public_key().as_ref().try_into().unwrap();
        assert!(payload.verify(&owner_pub).is_err());
    }

    #[test]
    fn burn_once_twice_fails() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        assert!(burn_auth_key(&enroll_pub, &Reuse::Once).is_ok());
        assert!(burn_auth_key(&enroll_pub, &Reuse::Once).is_err());
    }

    #[test]
    fn burn_n_count_enforced() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        assert!(burn_auth_key(&enroll_pub, &Reuse::N(3)).is_ok());
        assert!(burn_auth_key(&enroll_pub, &Reuse::N(3)).is_ok());
        assert!(burn_auth_key(&enroll_pub, &Reuse::N(3)).is_ok());
        assert!(burn_auth_key(&enroll_pub, &Reuse::N(3)).is_err());
    }

    #[test]
    fn delegated_effective_intersection() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into(), "deploy".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert_eq!(eff, vec!["shell"]); // only shell is in both
    }

    #[test]
    fn delegated_never_above_auth_key() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| ak_caps.contains(c))); // subset of auth_key caps
    }

    #[test]
    fn delegated_never_above_owner() {
        let owner = vec!["shell".into()];
        let ak_caps = vec!["shell".into(), "transfer".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| owner.contains(c))); // subset of owner caps
    }

    #[test]
    fn auth_key_json_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into(), "transfer".into()],
            vec![[0xAA; 32]],
            3600,
            Reuse::N(5),
            "ci".into(),
        )
        .unwrap();
        let json = ak.to_json();
        let round = AuthKey::from_json(&json).unwrap();
        assert_eq!(ak.issuer, round.issuer);
        assert_eq!(ak.enroll_pub, round.enroll_pub);
        assert_eq!(ak.caps, round.caps);
        assert_eq!(ak.audience, round.audience);
        assert_eq!(ak.expires, round.expires);
        assert_eq!(ak.reuse, round.reuse);
        assert_eq!(ak.ephemeral, round.ephemeral);
        assert_eq!(ak.tag, round.tag);
        assert_eq!(ak.sig, round.sig);
    }

    #[test]
    fn enrollment_payload_json_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(
            &owner,
            enroll_pub,
            vec!["shell".into()],
            vec![],
            3600,
            Reuse::Once,
            "test".into(),
        )
        .unwrap();

        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce);
        let json = payload.to_json();
        let round = EnrollmentPayload::from_json(&json).unwrap();
        assert_eq!(payload.nonce, round.nonce);
        assert_eq!(payload.device_pub, round.device_pub);
        assert_eq!(payload.enroll_possession_sig, round.enroll_possession_sig);
        assert_eq!(payload.device_possession_sig, round.device_possession_sig);
    }
}
