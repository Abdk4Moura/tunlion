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
}
