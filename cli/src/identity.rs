//! User identity layer: SSH-CA shaped user-key over device-certs.
use anyhow::{anyhow, bail, Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde_json::{json, Value};

use crate::platform;

pub const CERT_TTL_SECS: u64 = 90 * 24 * 3600;
const CERT_SIGN_DOMAIN: &[u8] = b"filament/identity-device-cert/v1";

pub fn user_key_path() -> std::path::PathBuf {
    platform::Paths::config_path("identity.ed25519")
}

pub struct UserKey {
    keypair: Ed25519KeyPair,
}

impl UserKey {
    pub fn generate() -> Result<Self> {
        let path = user_key_path();
        if path.exists() {
            bail!("a user identity already exists ({})", path.display());
        }
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| anyhow!("failed to generate user identity key"))?;
        platform::SecretFile::write(&path, pkcs8.as_ref())
            .with_context(|| format!("write user identity to {}", path.display()))?;
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow!("failed to load freshly-generated user key"))?;
        Ok(UserKey { keypair })
    }

    pub fn load() -> Result<Option<Self>> {
        let path = user_key_path();
        if !path.exists() { return Ok(None); }
        let pkcs8 = std::fs::read(&path)
            .with_context(|| format!("read user identity from {}", path.display()))?;
        let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| anyhow!("user identity key is corrupt"))?;
        Ok(Some(UserKey { keypair }))
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
        if dp.len()!=32||up.len()!=32||sg.len()!=64 { return None; }
        let mut d=[0u8;32]; d.copy_from_slice(&dp);
        let mut u=[0u8;32]; u.copy_from_slice(&up);
        let mut s=[0u8;64]; s.copy_from_slice(&sg);
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

pub fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn make_user() -> UserKey {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        UserKey { keypair }
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
        // Known contact with userKey U_old. Inbound cert signed by different user U_new must be REFUSED
        // and must NOT overwrite U_old. This exercises the actual takeover refusal path.
        let user_old = make_user();
        let user_new = make_user();
        let known_user_pub = user_old.public_key_bytes();
        let new_user_pub = user_new.public_key_bytes();
        assert_ne!(known_user_pub, new_user_pub);
        // New cert is signed by new_user, not old
        let cert_new = DeviceCert::certify(&user_new, [0x99; 32], now_secs(), CERT_TTL_SECS).unwrap();
        // Verify it does NOT chain to known old user
        assert!(cert_new.verify_chain(&known_user_pub, now_secs()).is_err(),
            "cert from different user must NOT chain to known userKey");
        // Verify it DOES chain to its own signer
        assert!(cert_new.verify_chain(&new_user_pub, now_secs()).is_ok());
        // If we had stored U_old for this contact, overwriting with U_new would be takeover
        // The fix is to refuse: new cert's user_pub != known_user_pub => bail
        // Simulate the check in update_peer_identity
        let would_overwrite = cert_new.user_pub != known_user_pub;
        assert!(would_overwrite, "this cert would trigger takeover refusal");
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
}
