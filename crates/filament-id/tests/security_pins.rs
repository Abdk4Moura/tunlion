//! Security properties of the identity layer that no test pinned.
//!
//! Found by the mutation probe (.github/workflows/mutants.yml): each test below
//! kills one or more mutants that the existing suite let survive, and each one
//! states the property it protects rather than the code shape it happens to
//! exercise. Kept in its own integration-test file, using only the public API,
//! so it merges independently of edits to src/lib.rs.

use filament_id::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::path::{Path, PathBuf};

struct TempStore(tempfile::TempDir);

impl TempStore {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
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

fn random_seed() -> [u8; 32] {
    use ring::rand::SecureRandom;
    let mut s = [0u8; 32];
    SystemRandom::new().fill(&mut s).unwrap();
    s
}

fn user() -> UserKey {
    UserKey::from_seed(&random_seed()).unwrap()
}

fn device_pub() -> [u8; 32] {
    let kp = Ed25519KeyPair::from_seed_unchecked(&random_seed()).unwrap();
    kp.public_key().as_ref().try_into().unwrap()
}

// ---------------------------------------------------------------------------
// Recovery: every new identity is a different key
// ---------------------------------------------------------------------------

/// Two freshly generated recoverable identities must be two different keys.
/// The existing round-trip test compares an identity with its own restore, so a
/// derivation that ignored the recovery entropy (every user gets the same key,
/// i.e. anyone can sign as anyone) passed it unchanged.
#[test]
fn independent_identities_are_different_keys() {
    let (sa, sb) = (TempStore::new(), TempStore::new());
    let a = PendingIdentity::generate().unwrap();
    let b = PendingIdentity::generate().unwrap();
    assert_ne!(a.mnemonic().to_string(), b.mnemonic().to_string());
    let ka = a.commit(&sa).unwrap();
    let kb = b.commit(&sb).unwrap();
    assert_ne!(
        ka.public_key_bytes(),
        kb.public_key_bytes(),
        "two recovery phrases derived the same identity key"
    );
    assert_ne!(ka.fingerprint(), kb.fingerprint());
}

/// The fingerprint a user compares out of band is the start of the real public
/// key, and `public_key_hex` is that key. A constant or empty fingerprint made
/// the recovery round-trip test compare "" with "" and pass.
#[test]
fn fingerprint_and_hex_name_the_actual_key() {
    let k = user();
    assert_eq!(k.public_key_hex(), hex::encode(k.public_key_bytes()));
    assert_eq!(k.fingerprint().len(), 8);
    assert!(k.public_key_hex().starts_with(&k.fingerprint()));
}

/// Restoring a phrase gives back exactly the identity it was issued for, and a
/// different phrase does not.
#[test]
fn restore_is_bound_to_its_phrase() {
    let a = PendingIdentity::generate().unwrap();
    let b = PendingIdentity::generate().unwrap();
    let (pa, pb) = (a.mnemonic().to_string(), b.mnemonic().to_string());
    let ka = a.commit(&TempStore::new()).unwrap().public_key_bytes();
    let kb = b.commit(&TempStore::new()).unwrap().public_key_bytes();
    assert_eq!(UserKey::restore(&TempStore::new(), &pa).unwrap().public_key_bytes(), ka);
    assert_eq!(UserKey::restore(&TempStore::new(), &pb).unwrap().public_key_bytes(), kb);
}

// ---------------------------------------------------------------------------
// Mesh roster: the signature covers the content
// ---------------------------------------------------------------------------

fn roster(owner: &UserKey) -> MeshRoster {
    MeshRoster {
        owner_pub: owner.public_key_bytes(),
        epoch: 7,
        valid_until: now_secs() + 1000,
        devices: vec![RosterDevice { device_pub: [3u8; 32], petname: "laptop".into() }],
    }
}

/// An owner's signature over a roster must not verify for a roster with
/// different content. If the signed bytes did not depend on the content, any
/// one valid signature would authenticate every roster that owner could have
/// published: a replayed old epoch, a stretched validity window, or a device
/// the owner never listed.
#[test]
fn roster_signature_covers_every_field() {
    let owner = user();
    let r = roster(&owner);
    let sig = r.sign(owner.keypair()).unwrap();
    r.verify(&sig).unwrap();

    let mut m = r.clone();
    m.epoch += 1;
    assert!(m.verify(&sig).is_err(), "epoch is not covered by the roster signature");

    let mut m = r.clone();
    m.valid_until += 1;
    assert!(m.verify(&sig).is_err(), "valid_until is not covered by the roster signature");

    let mut m = r.clone();
    m.devices.push(RosterDevice { device_pub: [4u8; 32], petname: "intruder".into() });
    assert!(m.verify(&sig).is_err(), "an added device is not covered by the roster signature");

    let mut m = r.clone();
    m.devices[0].petname = "renamed".into();
    assert!(m.verify(&sig).is_err(), "a petname is not covered by the roster signature");

    let mut m = r.clone();
    m.devices[0].device_pub = [5u8; 32];
    assert!(m.verify(&sig).is_err(), "a device key is not covered by the roster signature");
}

/// A roster read back from its wire form is the roster that was signed, so the
/// signature still verifies after transport.
#[test]
fn roster_wire_roundtrip_preserves_the_signed_content() {
    let owner = user();
    let r = roster(&owner);
    let sig = r.sign(owner.keypair()).unwrap();
    let back = MeshRoster::from_json(&r.to_json()).expect("roster JSON parses back");
    assert_eq!(back, r);
    back.verify(&sig).unwrap();
}

// ---------------------------------------------------------------------------
// Device pin at overlay establishment
// ---------------------------------------------------------------------------

fn record(name: &str, cert: &DeviceCert) -> serde_json::Value {
    serde_json::json!({ "name": name, "deviceCert": cert.to_json() })
}

/// A device whose record pins a certificate may only bring up an overlay with
/// that certificate's device key. Any other key is a different machine
/// claiming the name, and the check must refuse it. Nothing tested this
/// function directly, so replacing its body with `Ok(())` survived.
#[test]
fn overlay_with_a_key_other_than_the_pinned_one_is_refused() {
    let u = user();
    let pinned = device_pub();
    let cert = DeviceCert::certify(&u, pinned, now_secs(), CERT_TTL_SECS).unwrap();
    let arr = vec![record("laptop", &cert)];
    check_overlay_against_pinned_cert(&arr, "laptop", &pinned).unwrap();
    let err = check_overlay_against_pinned_cert(&arr, "laptop", &device_pub())
        .expect_err("an overlay key that is not the pinned device key was accepted");
    assert!(err.to_string().contains("connection_key_divergence"));
}

/// The pin that applies is the one recorded under THIS name. Checking against
/// another device's record would refuse the legitimate device and could admit
/// an impostor that happens to hold the other device's key.
#[test]
fn overlay_pin_is_looked_up_by_name() {
    let u = user();
    let (ka, kb) = (device_pub(), device_pub());
    let ca = DeviceCert::certify(&u, ka, now_secs(), CERT_TTL_SECS).unwrap();
    let cb = DeviceCert::certify(&u, kb, now_secs(), CERT_TTL_SECS).unwrap();
    let arr = vec![record("a", &ca), record("b", &cb)];
    check_overlay_against_pinned_cert(&arr, "b", &kb).unwrap();
    assert!(
        check_overlay_against_pinned_cert(&arr, "b", &ka).is_err(),
        "device b accepted device a's key"
    );
    assert!(
        check_overlay_against_pinned_cert(&arr, "a", &kb).is_err(),
        "device a accepted device b's key"
    );
}

// ---------------------------------------------------------------------------
// First identity anchor
// ---------------------------------------------------------------------------

/// The first identity a new peer presents must be written down as its anchor.
/// Without the anchor, a later session from that name could strip identity
/// (fail-closed would find no record to compare against) or present a
/// different user's certificate (the takeover guard would find nothing to
/// protect).
#[test]
fn first_identity_for_an_unknown_peer_becomes_its_anchor() {
    let u = user();
    let cert = DeviceCert::certify(&u, device_pub(), now_secs(), CERT_TTL_SECS).unwrap();
    let mut arr: Vec<serde_json::Value> = vec![];
    apply_peer_identity(&mut arr, "phone", &cert, 0x00).unwrap();
    assert_eq!(arr.len(), 1, "the anchor was not recorded exactly once");
    assert_eq!(arr[0]["name"], "phone");
    assert_eq!(arr[0]["userKey"], hex::encode(u.public_key_bytes()));

    assert!(
        check_fail_closed(&arr, "phone", None).is_err(),
        "a peer that exposed identity once may not silently drop it"
    );
    let other = user();
    let cert2 = DeviceCert::certify(&other, device_pub(), now_secs(), CERT_TTL_SECS).unwrap();
    assert!(
        apply_peer_identity(&mut arr, "phone", &cert2, 0x00).is_err(),
        "a different user key took over an anchored name"
    );
    assert_eq!(arr.len(), 1);
}

// ---------------------------------------------------------------------------
// Identity-expose sealing
// ---------------------------------------------------------------------------

/// What one side seals under the shared secret, the other side opens to the
/// same bytes, including an empty payload (exactly one tag, 16 bytes).
#[test]
fn sealed_identity_opens_to_the_same_bytes() {
    let key = sealing_key_from_k(b"pake shared secret");
    for pt in [&b""[..], b"x", b"{\"cert\":\"...\"}"] {
        let (nonce, sealed) = seal_plaintext(&key, pt).unwrap();
        assert_eq!(sealed.len(), pt.len() + 16);
        assert_eq!(open_sealed(&key, &nonce, &sealed).unwrap(), pt);
    }
}

/// A sealed identity that was altered in flight, or sealed under a different
/// key, must not open. Opening is the only integrity check on the exposed
/// certificate before it is parsed.
#[test]
fn tampered_or_foreign_sealed_identity_is_refused() {
    let key = sealing_key_from_k(b"k1");
    let (nonce, sealed) = seal_plaintext(&key, b"identity payload").unwrap();
    for i in [0, sealed.len() / 2, sealed.len() - 1] {
        let mut t = sealed.clone();
        t[i] ^= 0x01;
        assert!(open_sealed(&key, &nonce, &t).is_err(), "tampered byte {i} was accepted");
    }
    let mut n2 = nonce;
    n2[0] ^= 1;
    assert!(open_sealed(&key, &n2, &sealed).is_err(), "a different nonce opened it");
    assert!(open_sealed(&key, &nonce, &sealed[..15]).is_err());
    let other = sealing_key_from_k(b"k2");
    assert!(
        open_sealed(&other, &nonce, &sealed).is_err(),
        "a key derived from a different shared secret opened the identity"
    );
}

/// The sealing key is a function of the shared secret: both ends derive the
/// same key from the same K, and a session with a different K gets a different
/// key. A constant key would let anyone who saw one session open every other.
#[test]
fn sealing_key_depends_on_the_shared_secret() {
    assert_eq!(sealing_key_from_k(b"same"), sealing_key_from_k(b"same"));
    assert_ne!(sealing_key_from_k(b"one"), sealing_key_from_k(b"two"));
    assert_ne!(sealing_key_from_k(b"one"), [0u8; 32]);
}

/// Every seal uses a fresh nonce. ChaCha20-Poly1305 under a repeated
/// (key, nonce) leaks the XOR of plaintexts and the authentication key.
#[test]
fn every_seal_uses_a_fresh_nonce() {
    let key = sealing_key_from_k(b"k");
    let (n1, c1) = seal_plaintext(&key, b"same").unwrap();
    let (n2, c2) = seal_plaintext(&key, b"same").unwrap();
    assert_ne!(n1, n2);
    assert_ne!(c1, c2);
}
