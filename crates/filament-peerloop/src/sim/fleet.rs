//! A sim fleet: one owner key, one rendezvous secret, a certified device key
//! per member, the same objects a real fleet enrollment leaves on disk.
//!
//! Every key is derived from the run's seed, so a run replays bit-exact. The
//! certificates are real `DeviceCert`s signed by the owner key and the hello
//! is the real `filament_fleet::build_hello`, so the receiving daemon runs the
//! production `verify_hello` over the link's channel binding.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use filament_id::{DeviceCert, UserKey};
use serde_json::Value;

/// A fixed issue time in the past and a long validity, so a certificate is
/// valid against the wall clock the production checks read and its bytes do
/// not depend on when the run happened.
const CERT_ISSUED: u64 = 1_700_000_000;
const CERT_TTL: u64 = 100 * 365 * 24 * 3600;
/// How much later a renewed certificate expires than the one it replaces.
/// Fixed, like the issue time, so a renewal's bytes replay.
const RENEWAL_STEP: u64 = 24 * 3600;

fn seed_bytes(seed: u64, tag: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"tunlion-sim-fleet:");
    h.update(seed.to_le_bytes());
    h.update(tag.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// The PKCS8 v2 document ring writes for an Ed25519 key, built from a seed so
/// the overlay key is deterministic.
fn ed25519_pkcs8_v2(seed: &[u8; 32]) -> Result<Vec<u8>> {
    let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map_err(|_| anyhow!("sim fleet: bad seed"))?;
    use ring::signature::KeyPair;
    let mut doc = vec![
        0x30, 0x53, 0x02, 0x01, 0x01, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    doc.extend_from_slice(seed);
    doc.extend_from_slice(&[0xa1, 0x23, 0x03, 0x21, 0x00]);
    doc.extend_from_slice(kp.public_key().as_ref());
    Ok(doc)
}

/// One member device of the sim fleet.
pub struct SimFleetMember {
    overlay: filament_overlay::Identity,
    /// This device's own certificate record. A renewal replaces it.
    cert: Mutex<DeviceCert>,
    /// The certificate is in its last third: the daemon asks for a renewal
    /// (`renewal::renewal_due` in production, which reads the wall clock; the
    /// sim states it, so a run does not depend on when it happened).
    renewal_due: AtomicBool,
    announce_seq: AtomicU64,
}

impl SimFleetMember {
    pub fn device_pub(&self) -> [u8; 32] {
        self.overlay.pubkey()
    }

    pub fn cert(&self) -> DeviceCert {
        self.cert.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn renewal_due(&self) -> bool {
        self.renewal_due.load(Ordering::Relaxed)
    }

    /// Adopt a renewed certificate as this device's own: it is no longer due.
    pub fn adopt(&self, cert: DeviceCert) {
        *self.cert.lock().unwrap_or_else(|e| e.into_inner()) = cert;
        self.renewal_due.store(false, Ordering::Relaxed);
    }

    /// The production hello shape: an announce bound to `cb` plus our cert.
    #[cfg(feature = "fleet")]
    pub fn make_hello(&self, cb: &[u8], name: &str) -> Result<Value> {
        let seq = self.announce_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let announce = self.overlay.announce(seq, cb);
        Ok(filament_fleet::build_hello(&announce, &self.cert(), name))
    }

    #[cfg(not(feature = "fleet"))]
    pub fn make_hello(&self, _cb: &[u8], _name: &str) -> Result<Value> {
        anyhow::bail!("fleet is not compiled into this build")
    }
}

/// The fleet: its secret, its owner and its roster of members.
pub struct SimFleet {
    rv: String,
    owner: UserKey,
    owner_pub: [u8; 32],
    /// The member that holds the owner signing key (a primary), if any.
    primary: Option<String>,
    members: BTreeMap<String, Arc<SimFleetMember>>,
}

impl SimFleet {
    /// A fleet whose members are `names`, every key derived from `seed`.
    pub fn new(seed: u64, names: &[String]) -> Result<Arc<Self>> {
        Self::with_roles(seed, names, None, &[])
    }

    /// As [`SimFleet::new`], with `primary` holding the owner signing key and
    /// the members in `due` holding a certificate due for renewal.
    pub fn with_roles(
        seed: u64,
        names: &[String],
        primary: Option<&str>,
        due: &[String],
    ) -> Result<Arc<Self>> {
        let owner = UserKey::from_seed(&seed_bytes(seed, "owner"))?;
        let rv = hex::encode(seed_bytes(seed, "rv"));
        let mut members = BTreeMap::new();
        for name in names {
            let pkcs8 = ed25519_pkcs8_v2(&seed_bytes(seed, &format!("device:{name}")))?;
            let overlay = filament_overlay::Identity::from_pkcs8(&pkcs8)?;
            let cert = DeviceCert::certify(&owner, overlay.pubkey(), CERT_ISSUED, CERT_TTL)?;
            members.insert(
                name.clone(),
                Arc::new(SimFleetMember {
                    overlay,
                    cert: Mutex::new(cert),
                    renewal_due: AtomicBool::new(due.contains(name)),
                    announce_seq: AtomicU64::new(0),
                }),
            );
        }
        Ok(Arc::new(Self {
            rv,
            owner_pub: owner.public_key_bytes(),
            owner,
            primary: primary.map(str::to_string),
            members,
        }))
    }

    /// `node` holds the owner signing key.
    pub fn is_primary(&self, node: &str) -> bool {
        self.primary.as_deref() == Some(node)
    }

    /// The member names, in order.
    pub fn member_names(&self) -> impl Iterator<Item = &String> {
        self.members.keys()
    }

    /// The owner re-signs the member holding `device_pub`: same device key,
    /// same issue time, an expiry `RENEWAL_STEP` past the current one. None
    /// for a key that is not a member.
    pub fn renew(&self, device_pub: &[u8; 32]) -> Option<DeviceCert> {
        let m = self.members.values().find(|m| &m.device_pub() == device_pub)?;
        let current = m.cert();
        let ttl = current.expires.saturating_sub(CERT_ISSUED) + RENEWAL_STEP;
        DeviceCert::certify(&self.owner, *device_pub, CERT_ISSUED, ttl).ok()
    }

    pub fn rv(&self) -> &str {
        &self.rv
    }

    pub fn channel(&self) -> String {
        crate::recv::store::channel_of(&self.rv)
    }

    pub fn owner_pub(&self) -> [u8; 32] {
        self.owner_pub
    }

    pub fn member(&self, name: &str) -> Option<Arc<SimFleetMember>> {
        self.members.get(name).cloned()
    }

    /// The owner's roster lists this device key.
    pub fn lists(&self, device_pub: &[u8; 32]) -> bool {
        self.members.values().any(|m| &m.device_pub() == device_pub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fleet_keys_are_deterministic_and_certs_chain_to_the_owner() {
        let names = vec!["alpha".to_string(), "bravo".to_string()];
        let a = SimFleet::new(7, &names).unwrap();
        let b = SimFleet::new(7, &names).unwrap();
        assert_eq!(a.rv(), b.rv());
        assert_eq!(
            a.member("alpha").unwrap().device_pub(),
            b.member("alpha").unwrap().device_pub()
        );
        let m = a.member("bravo").unwrap();
        m.cert().verify_chain(&a.owner_pub(), filament_id::now_secs()).unwrap();
        assert!(a.lists(&m.device_pub()));
        assert_ne!(a.member("alpha").unwrap().device_pub(), m.device_pub());
    }

    #[cfg(feature = "fleet")]
    #[test]
    fn a_hello_verifies_with_the_production_check() {
        let names = vec!["alpha".to_string()];
        let f = SimFleet::new(9, &names).unwrap();
        let cb = [5u8; 32];
        let hello = f.member("alpha").unwrap().make_hello(&cb, "alpha").unwrap();
        let ok = filament_fleet::verify_hello(&hello, &cb, &f.owner_pub(), filament_id::now_secs())
            .unwrap();
        assert_eq!(ok.device_pub, f.member("alpha").unwrap().device_pub());
        assert!(filament_fleet::verify_hello(&hello, &[6u8; 32], &f.owner_pub(), filament_id::now_secs()).is_err());
    }
}
