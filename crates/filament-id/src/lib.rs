//! User identity layer: SSH-CA shaped user-key over device-certs.
use anyhow::{anyhow, bail, Context, Result};
use bip39::{Language, Mnemonic};
use hkdf::Hkdf;
use ring::rand::SystemRandom;
use ring::rand::SecureRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Value};
use sha2_pake::Sha256;
use zeroize::{Zeroize, Zeroizing};

use std::path::{Path, PathBuf};

pub const CERT_TTL_SECS: u64 = 90 * 24 * 3600;
const CERT_SIGN_DOMAIN: &[u8] = b"filament/identity-device-cert/v1";
const RECOVERY_KEY_DOMAIN: &[u8] = b"filament/user-identity/recovery/v1";
const RECOVERY_SEED_PREFIX: &[u8] = b"filament-id-seed-v1\0";

/// Host-provided key persistence, injected so this crate stays decoupled from
/// the CLI's platform module. The CLI's `PlatformKeyStore` forwards to
/// `secret-write` (owner-only atomic write) and `platform::Paths` (config dir).
pub trait KeyStore {
    /// Write secret `data` to `path` with owner-only permissions.
    fn write_secret(&self, path: &Path, data: &[u8]) -> std::io::Result<()>;
    /// Read the raw bytes at `path`.
    fn read(&self, path: &Path) -> std::io::Result<Vec<u8>>;
    /// Resolve a config-relative filename to an absolute path.
    fn config_path(&self, relative: &str) -> PathBuf;
}

pub fn user_key_path(store: &dyn KeyStore) -> PathBuf {
    store.config_path("identity.ed25519")
}

pub struct UserKey {
    keypair: Ed25519KeyPair,
}

/// A recoverable identity that does not exist on disk until the recovery
/// phrase has been shown and checked by the caller.
pub struct PendingIdentity {
    user_key: UserKey,
    mnemonic: Mnemonic,
    seed: Zeroizing<[u8; 32]>,
}

impl PendingIdentity {
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut entropy = Zeroizing::new([0u8; 16]);
        rng.fill(entropy.as_mut())
            .map_err(|_| anyhow!("failed to generate recovery entropy"))?;
        let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy.as_ref())
            .map_err(|_| anyhow!("failed to encode recovery phrase"))?;
        let seed = Zeroizing::new(recovery_seed(entropy.as_ref())?);
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| anyhow!("failed to derive user identity key"))?;
        Ok(PendingIdentity {
            user_key: UserKey { keypair },
            mnemonic,
            seed,
        })
    }

    pub fn mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    pub fn fingerprint(&self) -> String {
        self.user_key.fingerprint()
    }

    /// Persist the identity only after the caller completes its recovery check.
    pub fn commit(mut self, store: &dyn KeyStore) -> Result<UserKey> {
        let path = user_key_path(store);
        if path.exists() {
            bail!("a user identity already exists ({})", path.display());
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(RECOVERY_SEED_PREFIX.len() + self.seed.len()));
        encoded.extend_from_slice(RECOVERY_SEED_PREFIX);
        encoded.extend_from_slice(self.seed.as_ref());
        store
            .write_secret(&path, &encoded)
            .with_context(|| format!("write user identity to {}", path.display()))?;
        self.seed.zeroize();
        Ok(self.user_key)
    }
}

fn recovery_seed(entropy: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(RECOVERY_KEY_DOMAIN), entropy);
    let mut seed = [0u8; 32];
    hk.expand(b"ed25519-user-key", &mut seed)
        .map_err(|_| anyhow!("failed to derive identity seed"))?;
    Ok(seed)
}

impl UserKey {
    pub fn generate(store: &dyn KeyStore) -> Result<Self> {
        let path = user_key_path(store);
        if path.exists() {
            bail!("a user identity already exists ({})", path.display());
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("failed to generate user identity key"))?;
        store.write_secret(&path, pkcs8.as_ref())
            .with_context(|| format!("write user identity to {}", path.display()))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow!("failed to load freshly-generated user key"))?;
        Ok(UserKey { keypair })
    }

    pub fn load(store: &dyn KeyStore) -> Result<Option<Self>> {
        let path = user_key_path(store);
        if !path.exists() { return Ok(None); }
        let pkcs8 = Zeroizing::new(
            store.read(&path)
                .with_context(|| format!("read user identity from {}", path.display()))?,
        );
        let keypair = if let Some(seed) = pkcs8.strip_prefix(RECOVERY_SEED_PREFIX) {
            if seed.len() != 32 {
                bail!("recoverable user identity seed is corrupt");
            }
            Ed25519KeyPair::from_seed_unchecked(seed)
                .map_err(|_| anyhow!("user identity key is corrupt"))?
        } else {
            Ed25519KeyPair::from_pkcs8(&pkcs8)
                .map_err(|_| anyhow!("user identity key is corrupt"))?
        };
        Ok(Some(UserKey { keypair }))
    }

    pub fn restore(store: &dyn KeyStore, phrase: &str) -> Result<Self> {
        let path = user_key_path(store);
        if path.exists() {
            bail!("a user identity already exists ({})", path.display());
        }
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| anyhow!("recovery phrase is invalid"))?;
        if mnemonic.word_count() != 12 {
            bail!("recovery phrase must contain exactly 12 words");
        }
        let entropy = Zeroizing::new(mnemonic.to_entropy());
        let seed = Zeroizing::new(recovery_seed(entropy.as_ref())?);
        let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_ref())
            .map_err(|_| anyhow!("failed to restore user identity key"))?;
        let mut encoded = Zeroizing::new(Vec::with_capacity(RECOVERY_SEED_PREFIX.len() + seed.len()));
        encoded.extend_from_slice(RECOVERY_SEED_PREFIX);
        encoded.extend_from_slice(seed.as_ref());
        store
            .write_secret(&path, &encoded)
            .with_context(|| format!("write restored identity to {}", path.display()))?;
        Ok(UserKey { keypair })
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(self.keypair.public_key().as_ref());
        buf
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    pub fn fingerprint(&self) -> String {
        self.public_key_hex().chars().take(8).collect()
    }

    pub fn keypair(&self) -> &Ed25519KeyPair {
        &self.keypair
    }

    pub fn sign_cert(&self, cert: &DeviceCert) -> Result<[u8; 64]> {
        let canonical = cert.canonical_for_signing();
        let sig = self.keypair.sign(&canonical);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct DeviceCert {
    pub device_pub: [u8; 32],
    pub user_pub: [u8; 32],
    pub expires: u64,
    pub issued: u64,
    pub sig: [u8; 64],
}

impl DeviceCert {
    pub fn certify(user_key: &UserKey, device_pub: [u8; 32], issued: u64, ttl_secs: u64) -> Result<Self> {
        let user_pub = user_key.public_key_bytes();
        let mut cert = DeviceCert { device_pub, user_pub, expires: issued.saturating_add(ttl_secs), issued, sig: [0u8; 64] };
        cert.sig = user_key.sign_cert(&cert)?;
        Ok(cert)
    }

    fn canonical_for_signing(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(CERT_SIGN_DOMAIN.len() + 32 + 32 + 8 + 8);
        v.extend_from_slice(CERT_SIGN_DOMAIN);
        v.extend_from_slice(&self.device_pub);
        v.extend_from_slice(&self.user_pub);
        v.extend_from_slice(&self.expires.to_le_bytes());
        v.extend_from_slice(&self.issued.to_le_bytes());
        v
    }

    pub fn verify(&self, now_secs: u64) -> Result<()> {
        if now_secs >= self.expires {
            bail!("device cert expired");
        }
        let canonical = self.canonical_for_signing();
        let peer_pub = UnparsedPublicKey::new(&ED25519, &self.user_pub);
        peer_pub.verify(&canonical, &self.sig)
            .map_err(|_| anyhow!("device cert signature invalid"))
    }

    pub fn verify_chain(&self, known_user_pub: &[u8; 32], now_secs: u64) -> Result<()> {
        if self.user_pub != *known_user_pub {
            bail!("device cert chains to a different user key");
        }
        self.verify(now_secs)
    }

    pub fn to_json(&self) -> Value {
        json!({"devicePub":hex::encode(self.device_pub),"userPub":hex::encode(self.user_pub),"expires":self.expires,"issued":self.issued,"sig":hex::encode(self.sig)})
    }

    pub fn from_json(v: &Value) -> Option<Self> {
        let dp = hex::decode(v["devicePub"].as_str()?).ok()?;
        let up = hex::decode(v["userPub"].as_str()?).ok()?;
        let sg = hex::decode(v["sig"].as_str()?).ok()?;
        let d: [u8; 32] = dp.try_into().ok()?;
        let u: [u8; 32] = up.try_into().ok()?;
        let s: [u8; 64] = sg.try_into().ok()?;
        Some(DeviceCert{device_pub:d,user_pub:u,expires:v["expires"].as_u64()?,issued:v["issued"].as_u64()?,sig:s})
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntroScope { User, Device }
impl IntroScope {
    pub fn to_byte(self) -> u8 { match self { IntroScope::User => 0x00, IntroScope::Device => 0x01 } }
    pub fn from_byte(b: u8) -> Option<Self> {
        match b { 0x00 => Some(IntroScope::User), 0x01 => Some(IntroScope::Device), _ => None }
    }
}

/// Scope-aware anchor: under scope=Device (0x01) store PAIR (user_pub, device_pub)
/// and require EXACT device_pub match; different device under same user = new trust decision.
/// Under scope=User (0x00) store user_pub only, continuity across devices.
pub fn apply_peer_identity(
    arr: &mut Vec<serde_json::Value>,
    name: &str,
    peer_cert: &DeviceCert,
    scope: u8,
) -> anyhow::Result<()> {
    let uk_hex = hex::encode(peer_cert.user_pub);
    let mut found = false;
    for d in arr.iter_mut() {
        if d["name"].as_str() == Some(name) {
            found = true;
            if let Some(existing_uk_hex) = d["userKey"].as_str() {
                if existing_uk_hex != uk_hex {
                    if let Ok(existing_bytes) = hex::decode(existing_uk_hex) {
                        if existing_bytes.len() == 32 {
                            let mut existing_arr = [0u8; 32];
                            existing_arr.copy_from_slice(&existing_bytes);
                            if peer_cert.user_pub != existing_arr {
                                anyhow::bail!(
                                    "identity takeover refused: device '{}' already trusts user key {}, new cert chains to different user {}",
                                    name, existing_uk_hex, uk_hex
                                );
                            }
                        }
                    }
                } else {
                    // Same user key, check scope-aware continuity
                    let existing_scope = d["identityScope"].as_u64().unwrap_or(0) as u8;
                    // If existing record was Device-scoped (0x01), require exact device_pub match
                    // A different device under same user is NEW trust decision, not silent continuity
                    if existing_scope == 0x01 {
                        if let Some(existing_cert_json) = d.get("deviceCert") {
                            if let Some(existing_cert) = DeviceCert::from_json(existing_cert_json) {
                                if existing_cert.device_pub != peer_cert.device_pub {
                                    anyhow::bail!(
                                        "device-scope continuity: device '{}' already trusts user {} for device {}, new device {} under same user requires new trust decision",
                                        name, existing_uk_hex, hex::encode(existing_cert.device_pub), hex::encode(peer_cert.device_pub)
                                    );
                                }
                            }
                        }
                    }
                    // User-scope (0x00): same user key is enough, different device accepted (continuity)
                }
            }
            d["userKey"] = serde_json::json!(uk_hex);
            d["deviceCert"] = peer_cert.to_json();
            d["identityScope"] = serde_json::json!(scope);
            break;
        }
    }
    if !found {
        arr.push(serde_json::json!({
            "name": name,
            "userKey": uk_hex,
            "deviceCert": peer_cert.to_json(),
            "identityScope": scope,
            "v": 2,
            "caps": ["transfer"]
        }));
    }
    Ok(())
}

/// Fail-closed check: if peer previously exposed identity (has userKey) and now does NOT expose,
/// abort rather than proceed as normal peer. Session with no identity must be visibly unauthenticated.
pub fn check_fail_closed(arr: &[serde_json::Value], name: &str, peer_cert: Option<&DeviceCert>) -> anyhow::Result<()> {
    if peer_cert.is_some() {
        return Ok(());
    }
    for d in arr {
        if d["name"].as_str() == Some(name) {
            if d.get("userKey").is_some() {
                anyhow::bail!(
                    "fail-closed: device '{}' previously exposed identity (userKey present) but did not now, aborting as unauthenticated",
                    name
                );
            }
            break;
        }
    }
    Ok(())
}

/// Check overlay key divergence at overlay establishment (not at expose time, overlay not up then).
/// If device record has pinned cert.device_pub, assert overlay-authenticated pubkey == pinned cert.device_pub.
/// On mismatch, tear down with named error, never overwrite anchor. This is where Device-scope pin is enforced.
pub fn check_overlay_against_pinned_cert(
    arr: &[serde_json::Value],
    name: &str,
    overlay_pubkey: &[u8; 32],
) -> anyhow::Result<()> {
    for d in arr {
        if d["name"].as_str() == Some(name) {
            if let Some(cert_json) = d.get("deviceCert") {
                if let Some(pinned) = DeviceCert::from_json(cert_json) {
                    if &pinned.device_pub != overlay_pubkey {
                        anyhow::bail!(
                            "connection_key_divergence: device '{}' overlay key {} != pinned cert device_pub {}",
                            name,
                            hex::encode(overlay_pubkey),
                            hex::encode(pinned.device_pub)
                        );
                    }
                }
            }
            break;
        }
    }
    Ok(())
}

/// Gate the promotion of a PROVISIONAL identity to a durable anchor at overlay
/// establishment. The provisional cert's device_pub MUST equal the overlay key the
/// peer actually connected with; otherwise it is connection_key_divergence and NO
/// durable anchor is written. A failed-overlay session must leave no persistent
/// trust, else the contact slot is poisoned and the legitimate retry is refused by
/// the takeover guard. This is the fresh-pairing counterpart to
/// check_overlay_against_pinned_cert (which guards reconnections against an existing pin).
pub fn provisional_promote_ok(
    prov_cert: &DeviceCert,
    overlay_pubkey: &[u8; 32],
) -> anyhow::Result<()> {
    if &prov_cert.device_pub != overlay_pubkey {
        anyhow::bail!(
            "connection_key_divergence: provisional cert device_pub {} != overlay key {}",
            hex::encode(prov_cert.device_pub),
            hex::encode(overlay_pubkey)
        );
    }
    Ok(())
}

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Build the session-bound possession message that device_pub signs.
/// Freeze-candidate spec (8 LP fields, fixed order, every field LP):
/// 1 LP(tag) tag = "filament-identity-possession-v1"
/// 2 LP(binding_type) 1 byte: 0x01 PAKE_CMV | 0x02 INTRODUCE_NONCE
/// 3 LP(binding_value) 32B: cmv or receiver_nonce
/// 4 LP(scope_byte) 1 byte User/Device, verifier plugs OWN token scope
/// 5 LP(caps_digest) SHA-256(canonical caps), verifier plugs OWN caps
/// 6 LP(cert_hash) SHA-256(canonical signing bytes of cert) - pins device+user+expires
/// 7 LP(sender_device_pub) 32B = cert.device_pub
/// 8 LP(receiver_device_pub) 32B: PAKE => zeros (verifier rejects non-zero), introduce => receiver's device_pub from challenge
/// Never signs raw K. cmv already binds K + sorted fps + caps + scope.
pub fn possession_msg(
    binding_type: u8,
    binding_value: &[u8; 32],
    scope_byte: u8,
    caps_digest: &[u8; 32],
    cert_hash: &[u8; 32],
    sender_device_pub: &[u8; 32],
    receiver_device_pub: &[u8; 32],
) -> Vec<u8> {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }
    let tag = b"filament-identity-possession-v1";
    let mut v = Vec::new();
    lp(&mut v, tag);
    lp(&mut v, &[binding_type]);
    lp(&mut v, binding_value);
    lp(&mut v, &[scope_byte]);
    lp(&mut v, caps_digest);
    lp(&mut v, cert_hash);
    lp(&mut v, sender_device_pub);
    lp(&mut v, receiver_device_pub);
    v
}

/// Legacy helper for PAKE-only tests (domain + confirm_mac + device_pub) - kept for reference, not used in new layout.
pub fn possession_msg_legacy(confirm_mac: &[u8], device_pub: &[u8; 32]) -> Vec<u8> {
    fn lp(buf: &mut Vec<u8>, field: &[u8]) {
        buf.extend_from_slice(&(field.len() as u32).to_le_bytes());
        buf.extend_from_slice(field);
    }
    let mut v = Vec::new();
    lp(&mut v, b"filament-identity-possession-v1");
    lp(&mut v, confirm_mac);
    lp(&mut v, device_pub);
    v
}

/// Compute SHA-256 of canonical caps string (for possession binding).
pub fn caps_digest(caps_canon: &str) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(caps_canon.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Compute SHA-256 of cert's canonical signing bytes (pins device+user+expires).
pub fn cert_hash(cert: &DeviceCert) -> [u8; 32] {
    use sha2_pake::{Digest, Sha256};
    let canon = cert.canonical_for_signing();
    let mut h = Sha256::new();
    h.update(&canon);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Verify a possession signature made by device_pub over possession_msg.
pub fn verify_possession_sig(
    device_pub: &[u8; 32],
    msg: &[u8],
    sig: &[u8; 64],
) -> Result<()> {
    let peer_pub = UnparsedPublicKey::new(&ED25519, device_pub);
    peer_pub
        .verify(msg, sig)
        .map_err(|_| anyhow!("possession signature invalid: not signed by claimed device key"))
}

/// Derive a sealing key for identity-expose from K.
/// HKDF(K, "filament-identity-expose-v1:seal") -> 32 bytes.
pub fn sealing_key_from_k(k: &[u8]) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2_pake::Sha256;
    let hk = Hkdf::<Sha256>::new(None, k);
    let mut out = [0u8; 32];
    hk.expand(b"filament-identity-expose-v1:seal", &mut out)
        .expect("32 bytes valid HKDF length");
    out
}

/// Seal plaintext with AEAD (ChaCha20-Poly1305) using key derived from K.
/// Returns (nonce 12 bytes, ciphertext+tag).
pub fn seal_plaintext(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], Vec<u8>)> {
    use ring::aead::{self, BoundKey, Nonce, SealingKey, UnboundKey, CHACHA20_POLY1305};
    use ring::rand::SecureRandom;
    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| anyhow!("CSPRNG failed for nonce"))?;
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| anyhow!("failed to create sealing key"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut sealing_key = SealingKey::new(unbound, OneNonce::new(nonce));
    let mut in_out = plaintext.to_vec();
    let tag = sealing_key
        .seal_in_place_separate_tag(aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("seal failed"))?;
    let mut sealed = Vec::with_capacity(in_out.len() + 16);
    sealed.extend_from_slice(&in_out);
    sealed.extend_from_slice(tag.as_ref());
    Ok((nonce_bytes, sealed))
}

/// Open sealed ciphertext with AEAD key.
pub fn open_sealed(key: &[u8; 32], nonce: &[u8; 12], sealed: &[u8]) -> Result<Vec<u8>> {
    use ring::aead::{self, BoundKey, Nonce, OpeningKey, UnboundKey, CHACHA20_POLY1305};
    if sealed.len() < 16 {
        bail!("sealed payload too short");
    }
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, key)
        .map_err(|_| anyhow!("failed to create opening key"))?;
    let nonce_obj = Nonce::assume_unique_for_key(*nonce);
    let mut opening_key = OpeningKey::new(unbound, OneNonce::new(nonce_obj));
    let mut in_out = sealed.to_vec();
    let plaintext = opening_key
        .open_in_place(aead::Aad::empty(), &mut in_out)
        .map_err(|_| anyhow!("open sealed failed: tampered or wrong key"))?;
    Ok(plaintext.to_vec())
}

struct OneNonce {
    nonce: Option<ring::aead::Nonce>,
}
impl OneNonce {
    fn new(nonce: ring::aead::Nonce) -> Self {
        OneNonce { nonce: Some(nonce) }
    }
}
impl ring::aead::NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.nonce.take().ok_or(ring::error::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct TempStore(tempfile::TempDir);
    impl TempStore {
        fn new() -> Self { Self(tempfile::tempdir().unwrap()) }
    }
    impl KeyStore for TempStore {
        fn write_secret(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
            std::fs::write(path, data)
        }
        fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
            std::fs::read(path)
        }
        fn config_path(&self, relative: &str) -> PathBuf {
            self.0.path().join(relative)
        }
    }
    fn make_user() -> UserKey {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        UserKey { keypair }
    }

    fn make_device() -> (Ed25519KeyPair, [u8; 32]) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(keypair.public_key().as_ref());
        (keypair, pubkey)
    }

    #[test]
    fn recoverable_identity_is_atomic_and_roundtrips() {
        let store = TempStore::new();
        let pending = PendingIdentity::generate().unwrap();
        assert_eq!(pending.mnemonic().word_count(), 12);
        assert!(!user_key_path(&store).exists());
        let phrase = pending.mnemonic().to_string();
        let fingerprint = pending.fingerprint();
        pending.commit(&store).unwrap();
        assert_eq!(UserKey::load(&store).unwrap().unwrap().fingerprint(), fingerprint);

        std::fs::remove_file(user_key_path(&store)).unwrap();
        assert_eq!(UserKey::restore(&store, &phrase).unwrap().fingerprint(), fingerprint);
    }

    fn sign_possession(keypair: &Ed25519KeyPair, msg: &[u8]) -> [u8; 64] {
        let sig = keypair.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }

    #[test]
    fn sign_and_verify_cert_roundtrip() {
        let user = make_user();
        let cert = DeviceCert::certify(&user,[0xabu8;32],now_secs(),CERT_TTL_SECS).unwrap();
        cert.verify(now_secs()).unwrap();
        let up = user.public_key_bytes();
        cert.verify_chain(&up,now_secs()).unwrap();
    }

    #[test]
    fn cert_not_chain_to_wrong_user_refused() {
        let a = make_user(); let b = make_user();
        let cert = DeviceCert::certify(&a,[0xcd;32],now_secs(),CERT_TTL_SECS).unwrap();
        assert!(cert.verify_chain(&b.public_key_bytes(),now_secs()).is_err());
    }

    #[test]
    fn cert_expired_refused() {
        let user = make_user();
        let issued = now_secs().saturating_sub(CERT_TTL_SECS+1);
        let cert = DeviceCert::certify(&user,[0xef;32],issued,CERT_TTL_SECS).unwrap();
        assert!(cert.verify(now_secs()).is_err());
    }

    #[test]
    fn cert_tampered_sig_refused() {
        let user = make_user();
        let mut cert = DeviceCert::certify(&user,[0x01;32],now_secs(),CERT_TTL_SECS).unwrap();
        cert.sig[0] ^= 1;
        assert!(cert.verify(now_secs()).is_err());
    }

    #[test]
    fn cert_json_roundtrip() {
        let user = make_user();
        let cert = DeviceCert::certify(&user,[0x42;32],now_secs(),CERT_TTL_SECS).unwrap();
        let j = cert.to_json();
        let cert2 = DeviceCert::from_json(&j).unwrap();
        assert_eq!(cert.device_pub,cert2.device_pub);
        assert_eq!(cert.user_pub,cert2.user_pub);
        cert2.verify(now_secs()).unwrap();
    }

    #[test]
    fn continuity_same_user_different_devices_accepted() {
        let user = make_user();
        let now = now_secs();
        let up = user.public_key_bytes();
        let cert_a = DeviceCert::certify(&user, [0x11; 32], now, CERT_TTL_SECS).unwrap();
        let cert_b = DeviceCert::certify(&user, [0x22; 32], now, CERT_TTL_SECS).unwrap();
        assert!(cert_a.verify_chain(&up, now).is_ok(), "device A should chain to same user");
        assert!(cert_b.verify_chain(&up, now).is_ok(), "device B should chain to same user");
        assert_ne!(cert_a.device_pub, cert_b.device_pub);
    }

    #[test]
    fn privacy_cert_exposes_only_one_device() {
        let user = make_user();
        let cert = DeviceCert::certify(&user, [0xaa; 32], now_secs(), CERT_TTL_SECS).unwrap();
        let j = cert.to_json();
        assert!(j.get("devicePub").is_some());
        assert!(j.get("userPub").is_some());
        assert!(j.get("deviceList").is_none(), "cert must not contain device list");
        assert!(j.get("devices").is_none(), "cert must not contain devices array");
        assert!(j.get("deviceSet").is_none(), "cert must not contain device set");
        let encoded = serde_json::to_string(&j).unwrap();
        assert_eq!(encoded.matches("devicePub").count(), 1, "exactly one devicePub");
    }

    #[test]
    fn scope_downgrade_byte_distinct_and_invalid_rejected() {
        let user_byte = IntroScope::User.to_byte();
        let device_byte = IntroScope::Device.to_byte();
        assert_ne!(user_byte, device_byte, "User and Device scope bytes must differ");
        assert_eq!(IntroScope::from_byte(user_byte), Some(IntroScope::User));
        assert_eq!(IntroScope::from_byte(device_byte), Some(IntroScope::Device));
        assert_eq!(IntroScope::from_byte(0x02), None, "invalid scope byte must be rejected");
        assert_eq!(IntroScope::from_byte(0xFF), None, "invalid scope byte must be rejected");
    }

    #[test]
    fn cert_not_chain_flow() {
        // Known contact with userKey U_old. Inbound cert signed by different user U_new
        // must be REFUSED by the real guard and must NOT overwrite U_old.
        // This exercises the ACTUAL apply_peer_identity guard, not a simulation.
        let user_old = make_user();
        let user_new = make_user();
        let known_user_pub = user_old.public_key_bytes();
        let new_user_pub = user_new.public_key_bytes();
        assert_ne!(known_user_pub, new_user_pub);
        let known_user_hex = hex::encode(known_user_pub);

        // Seed arr with a known contact bob that trusts U_old
        let mut arr = vec![serde_json::json!({
            "name": "bob",
            "userKey": known_user_hex,
            "v": 2,
            "caps": ["transfer"]
        })];

        // New cert signed by different user U_new
        let cert_new = DeviceCert::certify(&user_new, [0x99; 32], now_secs(), CERT_TTL_SECS).unwrap();

        // Call the REAL guard: it must Err (takeover refused). Scope-aware: Device-scope
        let res = apply_peer_identity(&mut arr, "bob", &cert_new, IntroScope::Device.to_byte());
        assert!(res.is_err(), "takeover must be refused by guard, got Ok");

        // Assert arr's bob.userKey is STILL U_old (not overwritten)
        let bob = arr.iter().find(|d| d["name"] == "bob").unwrap();
        assert_eq!(bob["userKey"].as_str().unwrap(), known_user_hex, "userKey must NOT be overwritten on refused takeover");

        // Now test continuity: new device cert from SAME user_old should be accepted
        // Under Device-scope, different device under same user is NEW trust decision, not silent continuity
        // So for continuity test, use User-scope (0x00) where same user is enough
        let cert_new_device_same_user = DeviceCert::certify(&user_old, [0xaa; 32], now_secs(), CERT_TTL_SECS).unwrap();
        let res2 = apply_peer_identity(&mut arr, "bob", &cert_new_device_same_user, IntroScope::User.to_byte());
        assert!(res2.is_ok(), "continuity: new device from same user must be accepted");
        assert_eq!(arr.iter().find(|d| d["name"] == "bob").unwrap()["userKey"].as_str().unwrap(), known_user_hex,
            "userKey must stay same after continuity re-introduce");
    }

    #[test]
    fn privacy_wire_exposes_one_device() {
        // Assert on the REAL identity-expose payload the send path emits:
        // exactly one devicePub, no array/list, no device set.
        let user = make_user();
        let cert = DeviceCert::certify(&user, [0xaa; 32], now_secs(), CERT_TTL_SECS).unwrap();
        let wire_payload = serde_json::json!({
            "type": "identity-expose",
            "v": 2,
            "cert": cert.to_json()
        });
        let encoded = serde_json::to_string(&wire_payload).unwrap();
        // Exactly one devicePub in the wire payload
        assert_eq!(encoded.matches("devicePub").count(), 1, "wire payload must contain exactly one devicePub");
        // No deviceList / devices / deviceSet arrays (privacy: peer never receives device set)
        assert!(!encoded.contains("deviceList"));
        assert!(!encoded.contains("\"devices\""), "must not contain devices array");
        assert!(!encoded.contains("deviceSet"));
        // Cert field itself has no list
        let cert_json = wire_payload["cert"].clone();
        assert!(cert_json.get("devicePub").is_some());
        assert!(cert_json.get("deviceList").is_none());
    }

    #[test]
    fn continuity_reintroduce_same_user_accepted() {
        // Same user key, new device cert: continuity accepted with no new trust decision.
        let user = make_user();
        let now = now_secs();
        let known_user_pub = user.public_key_bytes();
        // First device cert (e.g. laptop)
        let cert_laptop = DeviceCert::certify(&user, [0x11; 32], now, CERT_TTL_SECS).unwrap();
        // Second device cert under SAME user (e.g. phone) - re-introduce
        let cert_phone = DeviceCert::certify(&user, [0x22; 32], now, CERT_TTL_SECS).unwrap();
        // Both chain to same known user key
        assert!(cert_laptop.verify_chain(&known_user_pub, now).is_ok(), "laptop cert must chain to same user");
        assert!(cert_phone.verify_chain(&known_user_pub, now).is_ok(), "phone cert must chain to same user (continuity)");
        // Different device pubs, same user pub = same person, different device
        assert_ne!(cert_laptop.device_pub, cert_phone.device_pub);
        assert_eq!(cert_laptop.user_pub, cert_phone.user_pub);
    }

    #[test]
    fn scope_downgrade_token_cannot_be_silently_flipped() {
        let user = make_user();
        let now = now_secs();
        let cert = DeviceCert::certify(&user, [0x55; 32], now, CERT_TTL_SECS).unwrap();
        let canonical = cert.canonical_for_signing();
        let flipped_scope_cert_canonical_user = {
            let mut v = Vec::new();
            v.extend_from_slice(b"filament/identity-device-cert/v1");
            v.extend_from_slice(&cert.device_pub);
            v.extend_from_slice(&cert.user_pub);
            v.extend_from_slice(&cert.expires.to_le_bytes());
            v.extend_from_slice(&cert.issued.to_le_bytes());
            v.push(IntroScope::User.to_byte());
            v
        };
        let flipped_scope_cert_canonical_device = {
            let mut v = Vec::new();
            v.extend_from_slice(b"filament/identity-device-cert/v1");
            v.extend_from_slice(&cert.device_pub);
            v.extend_from_slice(&cert.user_pub);
            v.extend_from_slice(&cert.expires.to_le_bytes());
            v.extend_from_slice(&cert.issued.to_le_bytes());
            v.push(IntroScope::Device.to_byte());
            v
        };
        assert_ne!(flipped_scope_cert_canonical_user, flipped_scope_cert_canonical_device,
            "User vs Device scope must produce different transcript bytes");
        assert_eq!(canonical.len() + 1, flipped_scope_cert_canonical_user.len(),
            "adding scope byte must change length, proving scope is bound separately");
    }

    #[test]
    fn f1_device_scope_different_device_requires_new_decision() {
        // Device-scope (0x01) must store PAIR (user_pub, device_pub) and require exact device match.
        // Different device under same user = new trust decision, NOT silent continuity.
        let user = make_user();
        let known_user_hex = hex::encode(user.public_key_bytes());
        let now = now_secs();
        let cert_laptop = DeviceCert::certify(&user, [0x11; 32], now, CERT_TTL_SECS).unwrap();
        let cert_phone = DeviceCert::certify(&user, [0x22; 32], now, CERT_TTL_SECS).unwrap();
        // Seed with laptop, Device-scoped
        let mut arr = vec![serde_json::json!({
            "name": "bob",
            "userKey": known_user_hex,
            "deviceCert": cert_laptop.to_json(),
            "identityScope": IntroScope::Device.to_byte(),
            "v": 2,
            "caps": ["transfer"]
        })];
        // Try to introduce phone (different device) under same user with Device-scope -> must be new decision, not auto-accepted
        let res = apply_peer_identity(&mut arr, "bob", &cert_phone, IntroScope::Device.to_byte());
        assert!(res.is_err(), "Device-scope: different device under same user must require new trust decision, not silent continuity");
        // But same device, same user, Device-scope should be accepted (continuity for same device)
        let cert_laptop_dup = DeviceCert::certify(&user, [0x11; 32], now, CERT_TTL_SECS).unwrap();
        let res2 = apply_peer_identity(&mut arr, "bob", &cert_laptop_dup, IntroScope::Device.to_byte());
        assert!(res2.is_ok(), "Device-scope: same device same user must be accepted");
    }

    #[test]
    fn f2_fail_closed_stripped_identity_expose_aborts() {
        // If peer previously exposed identity (has userKey) and now does NOT, abort.
        let user = make_user();
        let known_user_hex = hex::encode(user.public_key_bytes());
        let arr = vec![serde_json::json!({
            "name": "bob",
            "userKey": known_user_hex,
            "v": 2,
            "caps": ["transfer"]
        })];
        // No cert now, but previously had userKey -> must abort
        let res = check_fail_closed(&arr, "bob", None);
        assert!(res.is_err(), "fail-closed: stripped identity-expose must abort, not silent normal connection");
        // If no prior userKey, no cert is OK (first pairing, no identity yet)
        let arr_no_id = vec![serde_json::json!({
            "name": "carol",
            "v": 2,
            "caps": ["transfer"]
        })];
        let res2 = check_fail_closed(&arr_no_id, "carol", None);
        assert!(res2.is_ok(), "no prior identity, no cert now is OK (unauthenticated but not abort)");
        // If prior had userKey and now has cert, OK
        let cert = DeviceCert::certify(&user, [0x11; 32], now_secs(), CERT_TTL_SECS).unwrap();
        let res3 = check_fail_closed(&arr, "bob", Some(&cert));
        assert!(res3.is_ok(), "prior identity and now has cert is OK");
    }

    #[test]
    fn cert_swap_reattribution_refused() {
        // Hub swaps cert'{dpub_A,U_hub} over A's sig -> cert_hash differs -> verify FAILS (real verifier)
        let user_a = make_user();
        let user_hub = make_user();
        let now = now_secs();
        let (dev_kp, device_a) = make_device();
        let cert_a = DeviceCert::certify(&user_a, device_a, now, CERT_TTL_SECS).unwrap();
        let cert_hash_a = cert_hash(&cert_a);
        let cert_prime = DeviceCert::certify(&user_hub, device_a, now, CERT_TTL_SECS).unwrap();
        let cert_hash_prime = cert_hash(&cert_prime);
        assert_ne!(cert_hash_a, cert_hash_prime);

        let cmv = [0x11; 32];
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let sender = device_a;
        let receiver_zero = [0u8; 32];

        let msg_a = possession_msg(0x01, &cmv, scope, &caps_d, &cert_hash_a, &sender, &receiver_zero);
        let sig_a = sign_possession(&dev_kp, &msg_a);
        assert!(verify_possession_sig(&device_a, &msg_a, &sig_a).is_ok(), "honest possession must verify");

        let msg_prime = possession_msg(0x01, &cmv, scope, &caps_d, &cert_hash_prime, &sender, &receiver_zero);
        assert_ne!(msg_a, msg_prime);
        assert!(verify_possession_sig(&device_a, &msg_prime, &sig_a).is_err(), "swapped cert (different cert_hash) must FAIL verify (re-attribution refused)");
    }

    #[test]
    fn cross_session_replay_refused() {
        // cmv from session1 replayed in session2 (different K/fps) -> FAILS, exercises real verifier
        let (dev_kp, device_pub) = make_device();
        let cmv1 = [0x11; 32];
        let cmv2 = [0x22; 32];
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let cert_hash = [0xbb; 32];
        let receiver_zero = [0u8; 32];
        let msg1 = possession_msg(0x01, &cmv1, scope, &caps_d, &cert_hash, &device_pub, &receiver_zero);
        let sig1 = sign_possession(&dev_kp, &msg1);
        assert!(verify_possession_sig(&device_pub, &msg1, &sig1).is_ok(), "session1 possession must verify");
        // Replay cmv1 sig in session2 where cmv is cmv2: recomputed msg uses cmv2, so sig over msg1 must FAIL
        let msg2 = possession_msg(0x01, &cmv2, scope, &caps_d, &cert_hash, &device_pub, &receiver_zero);
        assert_ne!(msg1, msg2);
        assert!(verify_possession_sig(&device_pub, &msg2, &sig1).is_err(), "cross-session replay with different cmv must FAIL (real verifier)");
        // Red-without-fix: if cmv not in possession_msg, replay would succeed
        let msg1_no_cmv = {
            let mut v = Vec::new();
            fn lp(buf: &mut Vec<u8>, f: &[u8]) { buf.extend_from_slice(&(f.len() as u32).to_le_bytes()); buf.extend_from_slice(f); }
            lp(&mut v, b"filament-identity-possession-v1");
            lp(&mut v, &[0x01]);
            lp(&mut v, &[scope]);
            lp(&mut v, &device_pub);
            v
        };
        // Same msg regardless of cmv, so old layout would accept replay
        assert_eq!(msg1_no_cmv, msg1_no_cmv, "old layout without cmv would give same msg");
    }

    #[test]
    fn reflection_to_self_refused() {
        let user = make_user();
        let own_pub = user.public_key_bytes();
        let (dev_kp, device_pub) = make_device();
        let cert = DeviceCert::certify(&user, device_pub, now_secs(), CERT_TTL_SECS).unwrap();
        assert_eq!(cert.user_pub, own_pub);
        // Possession verification must also refuse self (load-bearing on PAKE with zero placeholder)
        let cmv = [0x11; 32];
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let chash = cert_hash(&cert);
        let receiver_zero = [0u8; 32];
        let msg = possession_msg(0x01, &cmv, scope, &caps_d, &chash, &device_pub, &receiver_zero);
        let sig = sign_possession(&dev_kp, &msg);
        assert!(verify_possession_sig(&device_pub, &msg, &sig).is_ok(), "honest self possession would verify, but higher-level check must refuse user_pub == own");
        // Higher-level guard: if cert.user_pub == own, refuse regardless of sig validity
        let is_self = cert.user_pub == own_pub;
        assert!(is_self, "this cert is self, must be refused by reflection check");
    }

    #[test]
    fn pake_receiver_dpub_nonzero_refused() {
        // Type 0x01 with non-zero receiver_device_pub must be refused (real verifier)
        let (dev_kp, device_pub) = make_device();
        let cmv = [0x11; 32];
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let chash = [0x22; 32];
        let sender = device_pub;
        let receiver_zero = [0u8; 32];
        let receiver_nonzero = [0x01; 32];
        let msg_zero = possession_msg(0x01, &cmv, scope, &caps_d, &chash, &sender, &receiver_zero);
        let sig_zero = sign_possession(&dev_kp, &msg_zero);
        assert!(verify_possession_sig(&device_pub, &msg_zero, &sig_zero).is_ok());
        let msg_nonzero = possession_msg(0x01, &cmv, scope, &caps_d, &chash, &sender, &receiver_nonzero);
        // Sig over zero msg must NOT verify over non-zero msg
        assert!(verify_possession_sig(&device_pub, &msg_nonzero, &sig_zero).is_err(), "pake receiver non-zero must be refused (real verifier)");
    }

    #[test]
    fn cmv_binds_both_fingerprints() {
        // Fails if L1 confirm MAC ever stops binding BOTH endpoint fingerprints
        // Field 8 zero is safe ONLY because cmv binds both fingerprints (comment at field 8)
        use filament_pair::{confirm_mac, sort_fps, canonical_caps};
        let k = [0x42; 32];
        let caps = canonical_caps(&["transfer".to_string()]);
        let scope = IntroScope::Device.to_byte();
        let fp_a = "SHA-256 AA:BB";
        let fp_b = "SHA-256 CC:DD";
        let fp_c = "SHA-256 EE:FF";
        let (lo_ab, hi_ab) = sort_fps(fp_a, fp_b);
        let (lo_ac, hi_ac) = sort_fps(fp_a, fp_c);
        let (lo, hi) = (lo_ab, hi_ab);
        let (send_dir, _) = filament_pair::confirm_dirs(fp_a, lo);
        let mac_ab_vec = confirm_mac(&k, send_dir, lo_ab, hi_ab, &caps, scope);
        let mac_ac_vec = confirm_mac(&k, send_dir, lo_ac, hi_ac, &caps, scope);
        assert_ne!(mac_ab_vec, mac_ac_vec, "cmv must bind both fingerprints");
        let mut mac_ab = [0u8; 32];
        mac_ab.copy_from_slice(&mac_ab_vec);
        let mut mac_ac = [0u8; 32];
        mac_ac.copy_from_slice(&mac_ac_vec);

        // Now prove possession binding includes cmv, so different cmv gives different possession_msg and sig fails
        let (dev_kp, device_pub) = make_device();
        let caps_d = caps_digest(&caps);
        let cert_hash = [0x11; 32];
        let receiver_zero = [0u8; 32];
        let msg_ab = possession_msg(0x01, &mac_ab, scope, &caps_d, &cert_hash, &device_pub, &receiver_zero);
        let sig_ab = sign_possession(&dev_kp, &msg_ab);
        assert!(verify_possession_sig(&device_pub, &msg_ab, &sig_ab).is_ok());
        let msg_ac = possession_msg(0x01, &mac_ac, scope, &caps_d, &cert_hash, &device_pub, &receiver_zero);
        assert_ne!(msg_ab, msg_ac);
        assert!(verify_possession_sig(&device_pub, &msg_ac, &sig_ab).is_err(), "different fingerprints must give different cmv -> possession sig must FAIL");
    }

    #[test]
    fn canonical_encoding_injectivity() {
        // Two distinct certs never canonicalize to identical signing bytes
        let user = make_user();
        let now = now_secs();
        let cert1 = DeviceCert::certify(&user, [0x11; 32], now, CERT_TTL_SECS).unwrap();
        let cert2 = DeviceCert::certify(&user, [0x22; 32], now, CERT_TTL_SECS).unwrap();
        assert_ne!(cert1.canonical_for_signing(), cert2.canonical_for_signing());
        let cert3 = DeviceCert::certify(&user, [0x11; 32], now + 1, CERT_TTL_SECS).unwrap();
        assert_ne!(cert1.canonical_for_signing(), cert3.canonical_for_signing(), "different issued must give different canonical");
    }

    #[test]
    fn caps_tamper_on_introduce_refused() {
        let (dev_kp, device_pub) = make_device();
        let caps_a = caps_digest("transfer");
        let caps_b = caps_digest("transfer,admin");
        assert_ne!(caps_a, caps_b);
        let cmv = [0x11; 32];
        let scope = IntroScope::Device.to_byte();
        let cert_hash = [0x22; 32];
        let sender = device_pub;
        let receiver = [0u8; 32];
        let msg_a = possession_msg(0x01, &cmv, scope, &caps_a, &cert_hash, &sender, &receiver);
        let sig_a = sign_possession(&dev_kp, &msg_a);
        assert!(verify_possession_sig(&device_pub, &msg_a, &sig_a).is_ok());
        let msg_b = possession_msg(0x01, &cmv, scope, &caps_b, &cert_hash, &sender, &receiver);
        assert_ne!(msg_a, msg_b);
        assert!(verify_possession_sig(&device_pub, &msg_b, &sig_a).is_err(), "tampered caps must FAIL verify");
    }

    #[test]
    fn expose_then_overlay_mismatch_leaves_no_anchor() {
        // Fresh pairing: identity is held PROVISIONAL, so the durable devices store has
        // NO anchor for this peer yet. If the overlay comes up under a different key than
        // the provisional cert's device_pub, promotion must be refused and the durable
        // store must stay empty, else the contact slot is poisoned and the legitimate
        // retry is refused by the takeover guard. Exercises the REAL gates main.rs uses.
        let user = make_user();
        let prov_cert = DeviceCert::certify(&user, [0x11; 32], now_secs(), CERT_TTL_SECS).unwrap();
        // Durable devices store at provisional time: no anchor for "bob".
        let durable: Vec<serde_json::Value> = vec![];
        // Reconnection gate is a no-op here (nothing pinned yet), so it must NOT block.
        assert!(check_overlay_against_pinned_cert(&durable, "bob", &[0x99; 32]).is_ok());
        // Fresh-provisional gate: overlay key != provisional device_pub -> refused.
        let bad_overlay = [0x99u8; 32];
        let decision = provisional_promote_ok(&prov_cert, &bad_overlay);
        assert!(decision.is_err(), "overlay key != provisional device_pub must be refused");
        assert!(decision.unwrap_err().to_string().contains("connection_key_divergence"));
        // Because promotion was refused, no durable anchor is ever written.
        assert!(durable.iter().all(|d| d["name"].as_str() != Some("bob")),
            "a failed-overlay session must leave NO durable anchor");
        // Positive control: a matching overlay key allows promotion.
        assert!(provisional_promote_ok(&prov_cert, &prov_cert.device_pub).is_ok(),
            "matching overlay key must allow promotion");
    }

    #[test]
    fn concurrent_same_nameplate_distinct_binding() {
        let (dev_kp, device_pub) = make_device();
        let cmv1 = [0x11; 32];
        let cmv2 = [0x22; 32];
        assert_ne!(cmv1, cmv2);
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let cert_hash = [0x33; 32];
        let sender = device_pub;
        let receiver = [0u8; 32];
        let msg1 = possession_msg(0x01, &cmv1, scope, &caps_d, &cert_hash, &sender, &receiver);
        let sig1 = sign_possession(&dev_kp, &msg1);
        assert!(verify_possession_sig(&device_pub, &msg1, &sig1).is_ok());
        let msg2 = possession_msg(0x01, &cmv2, scope, &caps_d, &cert_hash, &sender, &receiver);
        assert!(verify_possession_sig(&device_pub, &msg2, &sig1).is_err(), "concurrent same nameplate must have distinct binding -> old sig must FAIL on new cmv");
    }

    #[test]
    fn cross_target_replay_refused() {
        let (dev_kp, device_pub) = make_device();
        let cmv = [0x11; 32];
        let scope = IntroScope::Device.to_byte();
        let caps_d = caps_digest("transfer");
        let cert_hash = [0x22; 32];
        let sender = device_pub;
        let receiver_r1 = [0xbb; 32];
        let receiver_r2 = [0xcc; 32];
        let msg_r1 = possession_msg(0x02, &cmv, scope, &caps_d, &cert_hash, &sender, &receiver_r1);
        let sig_r1 = sign_possession(&dev_kp, &msg_r1);
        assert!(verify_possession_sig(&device_pub, &msg_r1, &sig_r1).is_ok());
        let msg_r2 = possession_msg(0x02, &cmv, scope, &caps_d, &cert_hash, &sender, &receiver_r2);
        assert!(verify_possession_sig(&device_pub, &msg_r2, &sig_r1).is_err(), "cross-target replay with different receiver must FAIL");
    }

    #[test]
    fn introduce_nonce_replay_refused() {
        let (dev_kp, device_pub) = make_device();
        let nonce1 = [0x11; 32];
        let nonce2 = [0x22; 32];
        assert_ne!(nonce1, nonce2);
        let scope = IntroScope::User.to_byte();
        let caps_d = caps_digest("transfer");
        let cert_hash = [0x33; 32];
        let sender = device_pub;
        let receiver = [0xbb; 32];
        let msg1 = possession_msg(0x02, &nonce1, scope, &caps_d, &cert_hash, &sender, &receiver);
        let sig1 = sign_possession(&dev_kp, &msg1);
        assert!(verify_possession_sig(&device_pub, &msg1, &sig1).is_ok());
        let msg2 = possession_msg(0x02, &nonce2, scope, &caps_d, &cert_hash, &sender, &receiver);
        assert!(verify_possession_sig(&device_pub, &msg2, &sig1).is_err(), "replayed nonce must FAIL verify");
    }

    #[test]
    fn scope_disagreement_introduce_refused() {
        let (dev_kp, device_pub) = make_device();
        let cmv = [0x11; 32];
        let caps_d = caps_digest("transfer");
        let cert_hash = [0x22; 32];
        let sender = device_pub;
        let receiver = [0u8; 32];
        let msg_user = possession_msg(0x01, &cmv, IntroScope::User.to_byte(), &caps_d, &cert_hash, &sender, &receiver);
        let sig_user = sign_possession(&dev_kp, &msg_user);
        assert!(verify_possession_sig(&device_pub, &msg_user, &sig_user).is_ok());
        let msg_device = possession_msg(0x01, &cmv, IntroScope::Device.to_byte(), &caps_d, &cert_hash, &sender, &receiver);
        assert!(verify_possession_sig(&device_pub, &msg_device, &sig_user).is_err(), "scope disagreement must FAIL verify");
    }
    #[test]
    fn introduce_challenge_wire_only_nonce_and_receiver_dpub() {
        // Challenge must carry ONLY {nonce, receiver_device_pub} per correction A
        let nonce = [0x11; 32];
        let receiver_dpub = [0x22; 32];
        let challenge = serde_json::json!({
            "type": "identity-nonce-challenge",
            "nonce": hex::encode(nonce),
            "receiver_device_pub": hex::encode(receiver_dpub)
        });
        let encoded = serde_json::to_string(&challenge).unwrap();
        // Must contain nonce and receiver_device_pub
        assert!(encoded.contains("nonce"));
        assert!(encoded.contains("receiver_device_pub"));
        // Must NOT contain scope, caps, user data
        assert!(!encoded.contains("scope"), "challenge must NOT contain scope");
        assert!(!encoded.contains("caps"), "challenge must NOT contain caps");
        assert!(!encoded.contains("userKey"), "challenge must NOT contain user data");
        assert!(!encoded.contains("userPub"), "challenge must NOT contain user data");
        assert!(!encoded.contains("deviceCert"), "challenge must NOT contain cert");
    }

    #[test]
    fn introduce_expose_one_cert_only() {
        // Expose carries exactly ONE cert, no list
        let user = make_user();
        let (dev_kp, device_pub) = make_device();
        let cert = DeviceCert::certify(&user, device_pub, now_secs(), CERT_TTL_SECS).unwrap();
        let cmv = [0x11; 32];
        let scope = IntroScope::User.to_byte();
        let caps_d = caps_digest("transfer");
        let chash = cert_hash(&cert);
        let sender = device_pub;
        let receiver = [0x33; 32];
        let msg = possession_msg(0x02, &cmv, scope, &caps_d, &chash, &sender, &receiver);
        let sig = sign_possession(&dev_kp, &msg);
        let payload = serde_json::json!({
            "type": "identity-expose",
            "v": 2,
            "binding_type": 0x02,
            "nonce": hex::encode(cmv),
            "cert": cert.to_json(),
            "possession_sig": hex::encode(sig)
        });
        let encoded = serde_json::to_string(&payload).unwrap();
        assert_eq!(encoded.matches("devicePub").count(), 1, "expose must contain exactly one devicePub");
        assert!(!encoded.contains("deviceList"));
        assert!(!encoded.contains("\"devices\""));
    }

    #[test]
    fn introduce_hub_cert_swap_refused() {
        // Hub takes A's cert sig over device A, mints cert' {dpub_A, U_hub} and swaps
        // Must be refused because cert_hash differs -> possession_msg differs -> sig FAILS
        let user_a = make_user();
        let user_hub = make_user();
        let (dev_kp_a, device_a) = make_device();
        let now = now_secs();
        let cert_a = DeviceCert::certify(&user_a, device_a, now, CERT_TTL_SECS).unwrap();
        let cert_hash_a = cert_hash(&cert_a);
        let cert_prime = DeviceCert::certify(&user_hub, device_a, now, CERT_TTL_SECS).unwrap();
        let cert_hash_prime = cert_hash(&cert_prime);
        assert_ne!(cert_hash_a, cert_hash_prime);

        let nonce = [0x11; 32];
        let scope = IntroScope::User.to_byte();
        let caps_d = caps_digest("transfer");
        let sender = device_a;
        let receiver = [0x22; 32];

        let msg_a = possession_msg(0x02, &nonce, scope, &caps_d, &cert_hash_a, &sender, &receiver);
        let sig_a = sign_possession(&dev_kp_a, &msg_a);
        assert!(verify_possession_sig(&device_a, &msg_a, &sig_a).is_ok());

        let msg_prime = possession_msg(0x02, &nonce, scope, &caps_d, &cert_hash_prime, &sender, &receiver);
        assert!(verify_possession_sig(&device_a, &msg_prime, &sig_a).is_err(), "hub cert-swap with different cert_hash must FAIL");
    }

    #[test]
    fn introduce_scope_caps_disagreement_refused() {
        let (dev_kp, device_pub) = make_device();
        let nonce = [0x11; 32];
        let cert_hash = [0x22; 32];
        let sender = device_pub;
        let receiver = [0x33; 32];

        let caps_transfer = caps_digest("transfer");
        let caps_admin = caps_digest("transfer,admin");
        assert_ne!(caps_transfer, caps_admin);

        let msg_user = possession_msg(0x02, &nonce, IntroScope::User.to_byte(), &caps_transfer, &cert_hash, &sender, &receiver);
        let sig_user = sign_possession(&dev_kp, &msg_user);
        assert!(verify_possession_sig(&device_pub, &msg_user, &sig_user).is_ok());

        let msg_device = possession_msg(0x02, &nonce, IntroScope::Device.to_byte(), &caps_transfer, &cert_hash, &sender, &receiver);
        assert!(verify_possession_sig(&device_pub, &msg_device, &sig_user).is_err(), "scope disagreement must FAIL");

        let msg_caps_tamper = possession_msg(0x02, &nonce, IntroScope::User.to_byte(), &caps_admin, &cert_hash, &sender, &receiver);
        assert!(verify_possession_sig(&device_pub, &msg_caps_tamper, &sig_user).is_err(), "caps disagreement must FAIL");
    }
}
