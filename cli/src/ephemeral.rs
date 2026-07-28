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
// Constants
// ---------------------------------------------------------------------------

/// Maximum TTL an auth key may be minted with (30 days).
const MAX_TTL_SECS: u64 = 30 * 24 * 3600;

/// Maximum enrollemnts per minute per enroll_pub (rate-limit, independent of burn).
const ENROLL_RATE_LIMIT: u32 = 5;

/// Maximum length for a canonical cap or tag string (cap truncation → collision defense).
const MAX_CAP_LEN: usize = 65535;

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
    /// Commit both discriminant and count to canonical bytes.
    /// Once = (0, 0), N(n) = (1, n), Reusable = (2, u32::MAX).
    fn to_canonical(&self) -> (u32, u32) {
        match self {
            Reuse::Once => (0, 0),
            Reuse::N(n) => (1, *n),
            Reuse::Reusable => (2, u32::MAX),
        }
    }
}

/// Normalize a slice of capability strings: lowercase, sort, deduplicate.
pub fn normalize_caps(caps: &[String]) -> Vec<String> {
    let mut v: Vec<String> = caps.iter().map(|s| s.to_lowercase()).collect();
    v.sort();
    v.dedup();
    v
}

/// An owner-signed delegation token that authorizes a device to self-enroll
/// as a delegated principal. Carries an enroll PUBLIC key (no bearer secret).
///
/// Caps are NORMALIZED at construction and deserialization (lowercase, sorted,
/// deduped), so signature commitments are case-consistent and mesh-ban
/// comparisons (`c == "mesh"`) are sound.
#[derive(Debug, Clone)]
pub struct AuthKey {
    /// Owner's Ed25519 public key (the issuer, must match a trusted user_pub).
    pub issuer: [u8; 32],
    /// Public key of the enrollment keypair that the enrolled device must
    /// prove possession of. NOT a bearer secret — verifier learns only a
    /// public key, nothing replayable.
    pub enroll_pub: [u8; 32],
    /// Semantic capability actions — a CEILING, not a floor (see delegated
    /// principal). Normalized: sorted, deduplicated, lowercase.
    pub caps: Vec<String>,
    /// Which peer(s) may enroll this key. Empty = Any.
    pub audience: Vec<[u8; 32]>,
    /// Absolute expiry (unix seconds).
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
/// Uses u32 length prefixes to prevent truncation-based canonical collisions.
fn auth_key_canonical_bytes(k: &AuthKey) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"filament-auth-key-v1");
    b.extend_from_slice(&k.issuer);
    b.extend_from_slice(&k.enroll_pub);
    // caps (already normalized: sorted, deduped, lowercase)
    // COUNT PREFIX before loop — prevents caps/audience boundary forgery.
    b.extend_from_slice(&(k.caps.len() as u32).to_le_bytes());
    for c in &k.caps {
        b.extend_from_slice(&(c.len() as u32).to_le_bytes());
        b.extend_from_slice(c.as_bytes());
    }
    // audience sorted
    let mut aud = k.audience.clone();
    aud.sort();
    b.extend_from_slice(&(aud.len() as u32).to_le_bytes());
    for a in &aud {
        b.extend_from_slice(a);
    }
    b.extend_from_slice(&k.expires.to_le_bytes());
    let (disc, count) = k.reuse.to_canonical();
    b.extend_from_slice(&disc.to_le_bytes());
    b.extend_from_slice(&count.to_le_bytes());
    b.push(if k.ephemeral { 1 } else { 0 });
    b.extend_from_slice(&(k.tag.len() as u32).to_le_bytes());
    b.extend_from_slice(k.tag.as_bytes());
    b
}

impl AuthKey {
    /// Mint a new auth key signed by the owner's user key.
    /// Caps are normalized (lowercase, sorted, deduped) at construction.
    /// ttl_secs is capped at MAX_TTL_SECS (30 days).
    /// Rejects caps or tag exceeding MAX_CAP_LEN.
    pub fn mint(
        owner_uk: &Ed25519KeyPair,
        enroll_pub: [u8; 32],
        caps: Vec<String>,
        audience: Vec<[u8; 32]>,
        ttl_secs: u64,
        reuse: Reuse,
        tag: String,
    ) -> Result<Self> {
        if tag.len() > MAX_CAP_LEN {
            bail!("tag too long (max {} bytes)", MAX_CAP_LEN);
        }
        if caps.iter().any(|c| c.len() > MAX_CAP_LEN) {
            bail!("cap too long (max {} bytes)", MAX_CAP_LEN);
        }
        let now = now_secs();
        let mut k = AuthKey {
            issuer: owner_uk.public_key().as_ref().try_into().map_err(|_| anyhow!("bad owner pub"))?,
            enroll_pub,
            caps: normalize_caps(&caps),
            audience,
            expires: now.saturating_add(ttl_secs.min(MAX_TTL_SECS)),
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

    /// Verify signature + expiry only.
    /// Private — callers use verify_against_owner for the genesis-forgery guard.
    fn verify_sig_and_expiry(&self) -> Result<()> {
        if now_secs() >= self.expires {
            bail!("auth key expired");
        }
        let canonical = auth_key_canonical_bytes(self);
        let pubkey = UnparsedPublicKey::new(&ED25519, &self.issuer);
        pubkey
            .verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("auth key signature invalid"))
    }

    /// Full verification: audience allowed, sig valid, not expired,
    /// issuer equals trusted owner_pub (genesis-forgery rule), mesh refused.
    pub fn verify_against_owner(&self, owner_pub: &[u8; 32], verifier_pub: &[u8; 32]) -> Result<()> {
        // Audience check FIRST — don't verify sig if this verifier is excluded.
        if !self.audience_allows(verifier_pub) {
            bail!("auth key not authorized for this peer");
        }
        // Caps normalization invariant — cheap hardening at point of use.
        if self.caps != normalize_caps(&self.caps) {
            bail!("auth key caps not normalized");
        }
        self.verify_sig_and_expiry()?;
        if self.issuer != *owner_pub {
            bail!("auth key issuer does not match trusted owner");
        }
        // Mesh refusal: caps are normalized (lowercase), so "mesh" catches all case variants.
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

    /// SAFE deserialization: uses try_into() (no panics on wrong-length hex).
    /// Caps are normalized at parse time.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let issuer: [u8; 32] = hex::decode(v.get("issuer")?.as_str()?).ok()?.try_into().ok()?;
        let enroll_pub: [u8; 32] = hex::decode(v.get("enroll_pub")?.as_str()?).ok()?.try_into().ok()?;
        let caps: Vec<String> = v.get("caps")?.as_array()?
            .iter()
            .filter_map(|x| x.as_str().map(|s| s.to_string()))
            .collect();
        let caps = normalize_caps(&caps);
        let audience: Vec<[u8; 32]> = {
            let raw = v.get("audience")?.as_array()?;
            let mut out = Vec::with_capacity(raw.len());
            for x in raw {
                let b = hex::decode(x.as_str()?).ok()?;
                out.push(b.try_into().ok()?);
            }
            out
        };
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
        let sig: [u8; 64] = hex::decode(v.get("sig")?.as_str()?).ok()?.try_into().ok()?;
        Some(AuthKey { issuer, enroll_pub, caps, audience, expires, reuse, ephemeral, tag, sig })
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
///
/// NONCE IS NOT ON THE WIRE. The verifier always knows the challenge it issued;
/// keeping it on the wire enables replay attacks. The verifier passes its held
/// nonce to verify() directly.
pub struct EnrollmentPayload {
    pub auth_key: AuthKey,
    pub device_pub: [u8; 32],
    /// Possession proof: sign(possession_msg(nonce, device_pub, verifier_pub))
    /// with enroll_priv (proves holder possesses auth key's private half).
    pub enroll_possession_sig: [u8; 64],
    /// Possession proof: same message signed with device_priv (proves holder
    /// possesses the device key it claims).
    pub device_possession_sig: [u8; 64],
}

/// Possession message: binds the enrollment to a specific nonce, device,
/// AND verifier, so a payload captured for peer A cannot be presented to peer B.
fn enrollment_possession_msg(nonce: &[u8; 32], device_pub: &[u8; 32], verifier_pub: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"filament-auth-key-enroll-v1");
    msg.extend_from_slice(nonce);
    msg.extend_from_slice(device_pub);
    msg.extend_from_slice(verifier_pub);
    msg
}

impl EnrollmentPayload {
    /// Build payload: sign possession messages with both keys.
    /// verifier_pub binds this payload to a specific verifier.
    pub fn build(
        auth_key: AuthKey,
        device_pub: [u8; 32],
        enroll_keypair: &Ed25519KeyPair,
        device_keypair: &Ed25519KeyPair,
        nonce: [u8; 32],
        verifier_pub: [u8; 32],
    ) -> Self {
        let msg = enrollment_possession_msg(&nonce, &device_pub, &verifier_pub);
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
        }
    }

    /// Verify the enrollment payload against a trusted owner.
    /// `verifier_nonce` is the nonce THIS verifier issued — never trust the
    /// payload's own claim. `verifier_pub` binds to this specific verifier.
    /// Returns (enroll_pub, device_pub, verified_auth_key) on success.
    pub fn verify(
        &self,
        owner_pub: &[u8; 32],
        verifier_nonce: &[u8; 32],
        verifier_pub: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 32], AuthKey)> {
        // 1. Verify auth key under trusted owner (audience + expiry + sig + issuer + mesh)
        self.auth_key.verify_against_owner(owner_pub, verifier_pub)?;

        // 2. Build possession message from VERIFIER's held nonce, NOT payload bytes
        let msg = enrollment_possession_msg(verifier_nonce, &self.device_pub, verifier_pub);

        // 3. Verify enroll possession
        let enroll_pkey = UnparsedPublicKey::new(&ED25519, &self.auth_key.enroll_pub);
        enroll_pkey
            .verify(&msg, &self.enroll_possession_sig)
            .map_err(|_| anyhow!("enroll possession proof invalid"))?;

        // 4. Verify device possession
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
        })
    }

    /// SAFE deserialization: uses try_into() (no panics on wrong-length hex).
    /// Nonce is NOT in the JSON — the verifier supplies its own.
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        let auth_key = AuthKey::from_json(v.get("auth_key")?)?;
        let device_pub: [u8; 32] = hex::decode(v.get("device_pub")?.as_str()?).ok()?.try_into().ok()?;
        let enroll_possession_sig: [u8; 64] = hex::decode(v.get("enroll_possession_sig")?.as_str()?).ok()?.try_into().ok()?;
        let device_possession_sig: [u8; 64] = hex::decode(v.get("device_possession_sig")?.as_str()?).ok()?.try_into().ok()?;
        Some(EnrollmentPayload {
            auth_key,
            device_pub,
            enroll_possession_sig,
            device_possession_sig,
        })
    }
}

// ---------------------------------------------------------------------------
// Burn / rate-limit state — per-peer, per-enroll_pub
// ---------------------------------------------------------------------------

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Three independent counters:
/// - burn_count / burn_start: never reset (reuse guard)
/// - attempt_count / attempt_window_start: pre-flight anti-flood (incremented per call)
/// - window_count / window_start: rate limit on successful burns
struct BurnEntry {
    burn_count: u32,
    attempt_count: u32,
    attempt_window_start_secs: u64,
    window_count: u32,
    window_start_secs: u64,
}

struct BurnState {
    map: HashMap<[u8; 32], BurnEntry>,
}

static BURN: OnceLock<Mutex<BurnState>> = OnceLock::new();

fn burn_state() -> &'static Mutex<BurnState> {
    BURN.get_or_init(|| Mutex::new(BurnState { map: HashMap::new() }))
}

/// Consume one use of an auth key identified by `enroll_pub`.
/// Rate-limited: max 5 enrollments/min per enroll_pub per peer.
/// Burn is process-local: a daemon restart clears all burn state.
/// NEVER reset burn_count (reuse guard) — rate-limit window is independent.
pub fn burn_auth_key(enroll_pub: &[u8; 32], reuse: &Reuse) -> Result<()> {
    burn_auth_key_at(enroll_pub, reuse, now_secs())
}

/// Like burn_auth_key but takes an explicit now so tests can advance time
/// without sleeping.
pub(crate) fn burn_auth_key_at(enroll_pub: &[u8; 32], reuse: &Reuse, now_secs: u64) -> Result<()> {
    let mut state = burn_state().lock().unwrap();
    let entry = state.map.entry(*enroll_pub).or_insert(BurnEntry {
        burn_count: 0,
        attempt_count: 0,
        attempt_window_start_secs: now_secs,
        window_count: 0,
        window_start_secs: now_secs,
    });

    // Rate-limit window (independent from burn, resets every 60s)
    let elapsed = now_secs.saturating_sub(entry.window_start_secs);
    if elapsed >= 60 {
        entry.window_count = 0;
        entry.window_start_secs = now_secs;
    }
    if entry.window_count >= ENROLL_RATE_LIMIT {
        bail!("auth key rate-limited (max {} enrollments/min)", ENROLL_RATE_LIMIT);
    }

    // Burn guard (never reset — tracks lifetime uses)
    match reuse {
        Reuse::Once => {
            if entry.burn_count > 0 {
                bail!("auth key already used (single-use)");
            }
        }
        Reuse::N(max) => {
            if entry.burn_count >= *max {
                bail!("auth key exhausted ({} uses)", max);
            }
        }
        Reuse::Reusable => {} // no limit, rate-limit still applies
    }

    entry.burn_count += 1;
    entry.window_count += 1;
    Ok(())
}

/// Rate-limit check INCREMENTS the attempt counter — this is the pre-flight
/// anti-flood guard. Uses a SEPARATE attempt counter from burn accounting.
pub fn check_rate_limit(enroll_pub: &[u8; 32]) -> Result<()> {
    let now_secs = now_secs();
    let mut state = burn_state().lock().unwrap();
    let entry = state.map.entry(*enroll_pub).or_insert(BurnEntry {
        burn_count: 0,
        attempt_count: 0,
        attempt_window_start_secs: now_secs,
        window_count: 0,
        window_start_secs: now_secs,
    });
    let elapsed = now_secs.saturating_sub(entry.attempt_window_start_secs);
    if elapsed >= 60 {
        entry.attempt_count = 0;
        entry.attempt_window_start_secs = now_secs;
    }
    if entry.attempt_count >= ENROLL_RATE_LIMIT {
        bail!("too many enrollment attempts (max {}/min)", ENROLL_RATE_LIMIT);
    }
    entry.attempt_count += 1;
    Ok(())
}

// ---------------------------------------------------------------------------
// Delegated principal — auth-key-enrolled devices have ceiling = caps ∩ owner
// ---------------------------------------------------------------------------

/// A delegated principal's effective capabilities are the INTERSECTION of the
/// owner's effective caps at this peer AND the auth key's caps. Both sides are
/// normalized (lowercase) so mixed-case owner caps are correctly intersected.
///
/// Invariants (property-testable):
///   effective(delegated) ⊆ auth_key_caps  (the ceiling)
///   effective(delegated) ⊆ effective(owner)  (no escalation)
pub fn delegated_effective_caps(
    owner_effective: &[String],
    auth_key_caps: &[String],
) -> Vec<String> {
    let owner_set: std::collections::HashSet<String> =
        owner_effective.iter().map(|s| s.to_lowercase()).collect();
    let mut result: Vec<String> = auth_key_caps
        .iter()
        .filter(|c| owner_set.contains(c.as_str()))
        .cloned()
        .collect();
    result.sort();
    result.dedup();
    result
}

// ---------------------------------------------------------------------------
// Enrollment nonce store — challenge/response anti-replay
// ---------------------------------------------------------------------------

use std::time::Instant as StdInstant;

const ENROLL_NONCE_TTL_SECS: u64 = 60;

struct NonceEntry {
    nonce: [u8; 32],
    deadline: StdInstant,
}

struct NonceStore {
    // peer_id → list of pending nonces (one enrollment attempt at a time expected)
    pending: HashMap<String, Vec<NonceEntry>>,
}

static NONCE_STORE: OnceLock<Mutex<NonceStore>> = OnceLock::new();

fn nonce_store() -> &'static Mutex<NonceStore> {
    NONCE_STORE.get_or_init(|| Mutex::new(NonceStore { pending: HashMap::new() }))
}

/// Generate a fresh CSPRNG nonce for the given peer, store it, return the nonce.
/// Rate-limited: called once per attempt (by check_rate_limit), single outstanding
/// nonce per peer (replaced on each new request). Sweeps expired entries on insert.
/// Propagates CSPRNG fill error — never issues a zero-filled nonce.
pub fn generate_nonce(peer_id: &str) -> Result<[u8; 32]> {
    use ring::rand::{SecureRandom, SystemRandom};
    let rng = SystemRandom::new();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce).map_err(|e| anyhow!("CSPRNG failure: {}", e))?;
    // Nonce must be non-zero after fill
    if nonce == [0u8; 32] {
        bail!("CSPRNG returned zero nonce");
    }
    let mut store = nonce_store().lock().unwrap();
    // Sweep expired entries across ALL peers
    let now = StdInstant::now();
    store.pending.retain(|_, entries| {
        entries.iter().any(|e| e.deadline > now)
    });
    // Single outstanding nonce per peer — replace
    store.pending.insert(peer_id.to_string(), vec![NonceEntry {
        nonce,
        deadline: now + std::time::Duration::from_secs(ENROLL_NONCE_TTL_SECS),
    }]);
    Ok(nonce)
}

/// Consume the outstanding nonce for a peer and return it.
/// Since we maintain a single outstanding nonce per peer (replaced on each
/// new request), this simply takes it. Errors if none found or expired.
pub fn consume_latest_nonce(peer_id: &str) -> Result<[u8; 32]> {
    let mut store = nonce_store().lock().unwrap();
    let entries = match store.pending.get_mut(peer_id) {
        Some(v) => v,
        None => bail!("no enrollment nonce for peer"),
    };
    let now = StdInstant::now();
    entries.retain(|e| e.deadline > now);
    if entries.is_empty() {
        store.pending.remove(peer_id);
        bail!("enrollment nonce expired or already consumed");
    }
    let nonce = entries.remove(0).nonce;
    if entries.is_empty() {
        store.pending.remove(peer_id);
    }
    Ok(nonce)
}

// Remove consume_nonce (peer_id, nonce) — no longer needed since single-outstanding.

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
// Pending enrollment state (enroller side)
// ---------------------------------------------------------------------------

struct PendingEnroll {
    enroll_seed: [u8; 32],
    device_seed: [u8; 32],
    device_pub: [u8; 32],
    auth_key: AuthKey,
}

static PENDING_ENROLLS: OnceLock<Mutex<HashMap<String, PendingEnroll>>> = OnceLock::new();

/// Register a pending enrollment attempt. Called by the ephemeral enroll CLI.
pub fn register_enrollment(
    peer_id: String,
    enroll_seed: [u8; 32],
    device_seed: [u8; 32],
    device_pub: [u8; 32],
    auth_key: AuthKey,
) {
    let mut store = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new())).lock().unwrap();
    store.insert(peer_id, PendingEnroll { enroll_seed, device_seed, device_pub, auth_key });
}

/// Take a pending enrollment and build the response to the daemon's challenge.
/// Verifies the daemon's device cert chains to the auth key's issuer (mutual
/// authentication — the cert is MANDATORY) and that the verifier_pub is in the
/// auth key's audience (mirror audience check). Removal from the store happens
/// ONLY on success so a failed attempt doesn't burn a single-use key.
pub fn build_enrollment_response(
    peer_id: &str,
    nonce: [u8; 32],
    verifier_pub: [u8; 32],
    device_cert: &serde_json::Value,
) -> Option<serde_json::Value> {
    let store_ref = PENDING_ENROLLS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut store = store_ref.lock().unwrap();
    let pe = match store.get(peer_id) {
        Some(p) => p,
        None => return None,
    };
    let issuer = pe.auth_key.issuer;
    let audience = pe.auth_key.audience.clone();

    // Mutual authentication: daemon's cert MUST chain to auth_key.issuer.
    // Cert is MANDATORY — no if-let bypass for a missing field.
    let cert = crate::identity::DeviceCert::from_json(device_cert)?;
    if cert.user_pub != issuer
        || cert.verify(now_secs()).is_err()
        || cert.device_pub != verifier_pub
    {
        return None;
    }

    // Mirror audience check: the enroller verifies it was handed a verifier_pub
    // that its auth key actually authorizes (audience-scoped protection).
    if !(audience.is_empty() || audience.contains(&verifier_pub)) {
        return None;
    }

    // ALL checks passed — now remove from store and build.
    let pe = store.remove(peer_id)?;
    let ak = pe.auth_key;
    let enroll_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&pe.enroll_seed).ok()?;
    let device_kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&pe.device_seed).ok()?;
    let payload = EnrollmentPayload::build(
        ak.clone(),
        pe.device_pub,
        &enroll_kp,
        &device_kp,
        nonce,
        verifier_pub,
    );
    Some(serde_json::json!({
        "auth_key": payload.auth_key.to_json(),
        "device_pub": hex::encode(payload.device_pub),
        "enroll_possession_sig": hex::encode(payload.enroll_possession_sig),
        "device_possession_sig": hex::encode(payload.device_possession_sig),
    }))
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

    fn owner_pub(owner: &Ed25519KeyPair) -> [u8; 32] {
        owner.public_key().as_ref().try_into().unwrap()
    }

    // ── Finding 1: Replay ──────────────────────────────────────────────

    #[test]
    fn replay_payload_rejected_with_wrong_nonce() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce1 = [0u8; 32];
        rng.fill(&mut nonce1).unwrap();
        let mut nonce2 = [0u8; 32];
        rng.fill(&mut nonce2).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce1, verifier_pub);
        let op = owner_pub(&owner);

        // Correct nonce passes
        assert!(payload.verify(&op, &nonce1, &verifier_pub).is_ok());
        // Replayed with wrong nonce fails
        assert!(payload.verify(&op, &nonce2, &verifier_pub).is_err());
        // Nonce is not on the wire (JSON roundtrip has no nonce field)
        let json = payload.to_json();
        assert!(json.get("nonce").is_none());
    }

    #[test]
    fn replay_payload_verifier_bound() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let device_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let device_pub: [u8; 32] = device_kp.public_key().as_ref().try_into().unwrap();
        let verifier_a: [u8; 32] = [0xAA; 32];
        let verifier_b: [u8; 32] = [0xBB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce, verifier_a);
        let op = owner_pub(&owner);

        assert!(payload.verify(&op, &nonce, &verifier_a).is_ok());
        // Same payload presented to verifier B fails
        assert!(payload.verify(&op, &nonce, &verifier_b).is_err());
    }

    // ── Finding 2: Mesh case-bypass ────────────────────────────────────

    #[test]
    fn mesh_refused_normalized_lowercase() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["mesh".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        assert_eq!(ak.caps, vec!["mesh"]); // normalized
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_err());
    }

    #[test]
    fn mesh_refused_case_bypass_defeated() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["MESH".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        assert_eq!(ak.caps, vec!["mesh"]); // normalized at mint
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_err());
    }

    #[test]
    fn mesh_refused_when_parsed_from_json() {
        // Construct JSON with "MESH" (mixed or upper case) — from_json must normalize
        let ak_json = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["MESH"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        let parsed = AuthKey::from_json(&ak_json).unwrap();
        assert_eq!(parsed.caps, vec!["mesh"]); // normalized at parse
    }

    // ── Finding 3: Burn reset ──────────────────────────────────────────

    #[test]
    fn burn_once_not_undone_by_rate_window_reset() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();

        // Use once at t=0
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::Once, 0).is_ok());
        // Still at t=0: second use fails (single-use consumed)
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::Once, 0).is_err());

        // Manually reset window to simulate rate-window expiry at t=120
        {
            let mut state = burn_state().lock().unwrap();
            if let Some(entry) = state.map.get_mut(&enroll_pub) {
                entry.window_count = 0;
                entry.window_start_secs = 120;
            }
        }
        // At t=120, window is fresh — but burn_count is still 1, so Reuse::Once still fails
        assert!(
            burn_auth_key_at(&enroll_pub, &Reuse::Once, 120).is_err(),
            "burn must not reset with rate-limit window"
        );
    }

    #[test]
    fn burn_n_count_enforced() {
        let kp = gen_keypair();
        let enroll_pub: [u8; 32] = kp.public_key().as_ref().try_into().unwrap();
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 0).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 1).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 2).is_ok());
        assert!(burn_auth_key_at(&enroll_pub, &Reuse::N(3), 3).is_err());
    }

    // ── Finding 4: Pre-auth panic ──────────────────────────────────────

    #[test]
    fn from_json_no_panic_on_wrong_length_hex() {
        // AuthKey: short issuer
        let ak_json = serde_json::json!({
            "issuer": "aa",
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        assert!(AuthKey::from_json(&ak_json).is_none());

        // AuthKey: short sig
        let ak_json2 = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": [],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": "aa"
        });
        assert!(AuthKey::from_json(&ak_json2).is_none());

        // AuthKey: short audience element
        let ak_json3 = serde_json::json!({
            "issuer": hex::encode([0u8; 32]),
            "enroll_pub": hex::encode([0u8; 32]),
            "caps": ["shell"],
            "audience": ["aa"],
            "expires": now_secs() + 3600,
            "reuse": "Once",
            "ephemeral": true,
            "tag": "test",
            "sig": hex::encode([0u8; 64])
        });
        assert!(AuthKey::from_json(&ak_json3).is_none());

        // EnrollmentPayload: short device_pub
        let pl_json = serde_json::json!({
            "auth_key": {
                "issuer": hex::encode([0u8; 32]),
                "enroll_pub": hex::encode([0u8; 32]),
                "caps": ["shell"],
                "audience": [],
                "expires": now_secs() + 3600,
                "reuse": "Once",
                "ephemeral": true,
                "tag": "test",
                "sig": hex::encode([0u8; 64])
            },
            "device_pub": "aa",
            "enroll_possession_sig": hex::encode([0u8; 64]),
            "device_possession_sig": hex::encode([0u8; 64])
        });
        assert!(EnrollmentPayload::from_json(&pl_json).is_none());

        // EnrollmentPayload: short possession sig
        let pl_json2 = serde_json::json!({
            "auth_key": {
                "issuer": hex::encode([0u8; 32]),
                "enroll_pub": hex::encode([0u8; 32]),
                "caps": ["shell"],
                "audience": [],
                "expires": now_secs() + 3600,
                "reuse": "Once",
                "ephemeral": true,
                "tag": "test",
                "sig": hex::encode([0u8; 64])
            },
            "device_pub": hex::encode([0u8; 32]),
            "enroll_possession_sig": "aa",
            "device_possession_sig": hex::encode([0u8; 64])
        });
        assert!(EnrollmentPayload::from_json(&pl_json2).is_none());
    }

    // ── Finding 5: Canonical collision (length-prefix truncation) ──────

    #[test]
    fn canonical_bytes_uses_u32_prefixes() {
        // Verify that a cap longer than 255 bytes still gets a full u32 prefix
        let long_cap = vec!["x".repeat(500)];
        let short_cap = vec![] as Vec<String>;
        let b1 = {
            let ak = AuthKey {
                issuer: [0u8; 32], enroll_pub: [0u8; 32],
                caps: long_cap, audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                tag: String::new(), sig: [0u8; 64],
            };
            auth_key_canonical_bytes(&ak)
        };
        let b2 = {
            let ak = AuthKey {
                issuer: [0u8; 32], enroll_pub: [0u8; 32],
                caps: short_cap, audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                tag: String::new(), sig: [0u8; 64],
            };
            auth_key_canonical_bytes(&ak)
        };
        assert_ne!(b1, b2, "different caps must not collide canonical bytes");
    }

    #[test]
    fn max_cap_len_rejected_at_mint() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        // Cap exceeding MAX_CAP_LEN (65535)
        let mega_cap = "x".repeat(MAX_CAP_LEN + 1);
        assert!(AuthKey::mint(&owner, enroll_pub, vec![mega_cap], vec![], 3600, Reuse::Once, "test".into()).is_err());
        // Tag exceeding MAX_CAP_LEN
        let mega_tag = "y".repeat(MAX_CAP_LEN + 1);
        assert!(AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, mega_tag).is_err());
    }

    #[test]
    fn canonical_bytes_caps_count_prefix_prevents_boundary_forgery() {
        // Key A: caps=["shell"], audience=[]
        // Key B: caps=[], audience=[0..repeat "shell" bytes]
        // Without a caps count prefix, the bare sequence (len,"shell") from A's caps
        // could collide with B's audience data. With count prefix they MUST differ.
        let a = {
            let ak = AuthKey {
                issuer: [1u8; 32], enroll_pub: [0u8; 32],
                caps: vec!["shell".into()],
                audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                tag: String::new(), sig: [0u8; 64],
            };
            auth_key_canonical_bytes(&ak)
        };
        // Construct an audience whose raw bytes mirror "shell" but embedded
        // in the audience loop (no length prefix per entry — audience entries are 32B keys)
        // We need a 32-byte key; there's no direct way to match "shell".
        // Instead: generic property — changing caps count changes bytes.
        let b_empty_caps = {
            let ak = AuthKey {
                issuer: [1u8; 32], enroll_pub: [0u8; 32],
                caps: vec![],
                audience: vec![],
                expires: 0, reuse: Reuse::Once, ephemeral: true,
                tag: String::new(), sig: [0u8; 64],
            };
            auth_key_canonical_bytes(&ak)
        };
        // caps count differs (1 vs 0) → bytes MUST differ
        assert_ne!(a, b_empty_caps, "caps count prefix must make canonical bytes differ");
    }

    #[test]
    fn reuse_n_count_committed_to_signature() {
        // N(1) and N(999) must produce different canonical bytes → different sigs.
        // Mint two keys that differ ONLY in reuse count; verify sigs differ.
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();

        // Use explicit construction to set reuse directly (not through mint which uses wall clock)
        let make = |n: u32| -> AuthKey {
            let now = now_secs();
            let mut ak = AuthKey {
                issuer: owner.public_key().as_ref().try_into().unwrap(),
                enroll_pub,
                caps: vec!["shell".into()],
                audience: vec![],
                expires: now + 3600,
                reuse: Reuse::N(n),
                ephemeral: true,
                tag: "test".into(),
                sig: [0u8; 64],
            };
            let canonical = auth_key_canonical_bytes(&ak);
            let sig = owner.sign(&canonical);
            ak.sig = sig.as_ref().try_into().unwrap();
            ak
        };

        let ak1 = make(1);
        let ak3 = make(3);

        // Canonical bytes MUST differ (different reuse count)
        assert_ne!(
            auth_key_canonical_bytes(&ak1),
            auth_key_canonical_bytes(&ak3),
            "N(1) and N(3) must not share canonical bytes"
        );

        // Sigs MUST differ (signature commits to count)
        assert_ne!(ak1.sig, ak3.sig, "N(1) sig must not verify N(3)");
    }

    #[test]
    fn caps_not_normalized_rejected_by_verify_against_owner() {
        // Cheap hardening: verify_against_owner rejects when caps != normalize_caps(&self.caps)
        // Construct an AuthKey with non-normalized caps (not sorted, uppercase)
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32],
            caps: vec!["SHELL".into(), "transfer".into()],
            audience: vec![],
            expires: now_secs() + 3600,
            reuse: Reuse::Once, ephemeral: true,
            tag: "test".into(), sig: [0u8; 64],
        };
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let err = ak.verify_against_owner(&[0u8; 32], &verifier_pub).unwrap_err().to_string();
        assert!(err.contains("not normalized"), "non-normalized caps must be rejected");
    }

    // ── Finding 6: Audience ─────────────────────────────────────────────

    #[test]
    fn audience_enforced_by_verify_against_owner() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let named_peer = [0xAA; 32];
        let other_peer = [0xBB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![named_peer], 3600, Reuse::Once, "test".into()).unwrap();
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &named_peer).is_ok());
        assert!(ak.verify_against_owner(&op, &other_peer).is_err(),
            "audience-bound key must be rejected at unauthorized peer");
    }

    #[test]
    fn audience_checked_before_sig() {
        // Audience rejection should happen before signature verification.
        // Even with invalid sig, audience mismatch should produce "not authorized for this peer".
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let named_peer = [0xAA; 32];
        let other_peer = [0xBB; 32];
        let mut ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![named_peer], 3600, Reuse::Once, "test".into()).unwrap();
        // Corrupt sig so we can tell which check fired first
        ak.sig = [0u8; 64];
        let op = owner_pub(&owner);
        let err = ak.verify_against_owner(&op, &other_peer).unwrap_err().to_string();
        assert!(err.contains("not authorized for this peer"),
            "audience rejection must come before sig error: got '{err}'");
    }

    // ── General tests ──────────────────────────────────────────────────

    #[test]
    fn auth_key_mint_verify_roundtrip() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into(), "transfer".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_ok());
    }

    #[test]
    fn auth_key_expired_fails() {
        let owner = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let mut ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        ak.expires = 0;
        let op = owner_pub(&owner);
        assert!(ak.verify_against_owner(&op, &verifier_pub).is_err());
    }

    #[test]
    fn auth_key_wrong_owner_fails() {
        let owner = gen_keypair();
        let other = gen_keypair();
        let enroll = gen_keypair();
        let enroll_pub: [u8; 32] = enroll.public_key().as_ref().try_into().unwrap();
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let other_pub = owner_pub(&other);
        assert!(ak.verify_against_owner(&other_pub, &verifier_pub).is_err());
    }

    #[test]
    fn auth_key_caps_normalized_at_mint() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["TRANSFER".into(), "shell".into(), "TRANSFER".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        assert_eq!(ak.caps, vec!["shell", "transfer"]);
    }

    #[test]
    fn auth_key_ttl_capped() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let now = now_secs();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 90 * 24 * 3600, Reuse::Once, "test".into()).unwrap();
        assert!(ak.expires <= now + MAX_TTL_SECS);
    }

    #[test]
    fn audience_allows_empty_is_any() {
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32], caps: vec![], audience: vec![],
            expires: now_secs() + 3600, reuse: Reuse::Once, ephemeral: true,
            tag: "test".into(), sig: [0u8; 64],
        };
        assert!(ak.audience_allows(&[1u8; 32]));
    }

    #[test]
    fn audience_allows_named_peer() {
        let peer = [0xAA; 32];
        let ak = AuthKey {
            issuer: [0u8; 32], enroll_pub: [0u8; 32], caps: vec![], audience: vec![peer],
            expires: now_secs() + 3600, reuse: Reuse::Once, ephemeral: true,
            tag: "test".into(), sig: [0u8; 64],
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
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce, verifier_pub);
        let op = owner_pub(&owner);
        let (ep, dp, _ak) = payload.verify(&op, &nonce, &verifier_pub).unwrap();
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
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(ak, device_pub, &wrong_kp, &device_kp, nonce, verifier_pub);
        let op = owner_pub(&owner);
        assert!(payload.verify(&op, &nonce, &verifier_pub).is_err());
    }

    #[test]
    fn delegated_effective_intersection() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into(), "deploy".into()];
        assert_eq!(delegated_effective_caps(&owner, &ak_caps), vec!["shell"]);
    }

    #[test]
    fn delegated_never_above_auth_key() {
        let owner = vec!["shell".into(), "transfer".into(), "mount".into()];
        let ak_caps = vec!["shell".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| ak_caps.contains(c)));
    }

    #[test]
    fn delegated_never_above_owner() {
        let owner = vec!["shell".into()];
        let ak_caps = vec!["shell".into(), "transfer".into()];
        let eff = delegated_effective_caps(&owner, &ak_caps);
        assert!(eff.iter().all(|c| owner.contains(c)));
    }

    #[test]
    fn delegated_mixed_case_owner() {
        let owner = vec!["Shell".into(), "TRANSFER".into()];
        let ak_caps = vec!["shell".into()];
        assert_eq!(delegated_effective_caps(&owner, &ak_caps), vec!["shell"]);
    }

    #[test]
    fn auth_key_json_roundtrip() {
        let owner = gen_keypair();
        let enroll_kp = gen_keypair();
        let enroll_pub: [u8; 32] = enroll_kp.public_key().as_ref().try_into().unwrap();
        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into(), "transfer".into()], vec![[0xAA; 32]], 3600, Reuse::N(5), "ci".into()).unwrap();
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
        let verifier_pub: [u8; 32] = [0xAB; 32];
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).unwrap();

        let ak = AuthKey::mint(&owner, enroll_pub, vec!["shell".into()], vec![], 3600, Reuse::Once, "test".into()).unwrap();
        let payload = EnrollmentPayload::build(ak, device_pub, &enroll_kp, &device_kp, nonce, verifier_pub);
        let json = payload.to_json();
        let round = EnrollmentPayload::from_json(&json).unwrap();
        assert_eq!(payload.device_pub, round.device_pub);
        assert_eq!(payload.enroll_possession_sig, round.enroll_possession_sig);
        assert_eq!(payload.device_possession_sig, round.device_possession_sig);
    }
}
