//! Replays the shared enrolment vectors through the same functions the CLI and
//! a future browser build call.
//!
//! The fixture deliberately stores seeds and nonces, not captured ciphertext:
//! Ed25519 signatures and AEAD are deterministic from those inputs, so the
//! native test and a browser harness derive the same bytes.
//!
//! Run with: `cargo test -p filament-enrol`.

use filament_enrol::{
    build_enrol_offer, enrol_offer_decision, open_enrol_grant, open_enrol_offer, seal_enrol_grant,
    verify_mesh_grant, DeviceIdentity, EnrolError, EnrolGrant, EnrolOffer, EnrolOfferDecision,
    EnrolOfferInputs, RandomSource, SeedStore,
};
use filament_id::{
    verify_possession_sig, DeviceCert, UserKey,
};
use serde_json::{json, Value};
use std::cell::RefCell;

const VECTORS: &str = include_str!("../testdata/enrol_vectors.json");

fn bytes<const N: usize>(text: &str) -> [u8; N] {
    let raw = hex::decode(text).unwrap_or_else(|err| panic!("hex {text}: {err}"));
    raw.try_into()
        .unwrap_or_else(|raw: Vec<u8>| panic!("expected {N} bytes, got {}", raw.len()))
}

fn identity_seed(doc: &Value, name: &str) -> [u8; 32] {
    bytes(
        doc["identities"][name]
            .as_str()
            .unwrap_or_else(|| panic!("identity {name}")),
    )
}

fn user(seed: &[u8; 32]) -> UserKey {
    UserKey::from_seed(seed).expect("fixture seed is a valid Ed25519 seed")
}

fn nonce(doc: &Value, name: &str) -> [u8; 12] {
    bytes(
        doc["nonces"][name]
            .as_str()
            .unwrap_or_else(|| panic!("nonce {name}")),
    )
}

fn sign(key: &UserKey, msg: &[u8]) -> [u8; 64] {
    let sig = key.keypair().sign(msg);
    let mut out = [0u8; 64];
    out.copy_from_slice(sig.as_ref());
    out
}

struct Ceremony {
    k: [u8; 32],
    device_fp: String,
    owner_fp: String,
    caps: String,
    scope: u8,
}

impl Ceremony {
    fn get(doc: &Value, name: &str) -> Self {
        let c = &doc["ceremonies"][name];
        Self {
            k: bytes(c["k"].as_str().expect("ceremony k")),
            device_fp: c["deviceFp"].as_str().expect("deviceFp").to_string(),
            owner_fp: c["ownerFp"].as_str().expect("ownerFp").to_string(),
            caps: c["capsCanon"].as_str().expect("capsCanon").to_string(),
            scope: c["scope"].as_u64().expect("scope") as u8,
        }
    }

    fn offer(&self, signer: &UserKey, claimed_key: [u8; 32], nonce: [u8; 12]) -> EnrolOffer {
        build_enrol_offer(
            &self.k,
            &self.device_fp,
            &self.owner_fp,
            &self.caps,
            self.scope,
            claimed_key,
            "pop-os",
            nonce,
            &|msg| Some(sign(signer, msg)),
        )
        .expect("fixture builds an offer")
    }

    fn open_offer(&self, frame: &EnrolOffer, own_key: Option<[u8; 32]>) -> Result<[u8; 32], EnrolError> {
        // The receiver sees its own fingerprint and the peer's the other way
        // round; both sides sort internally.
        open_enrol_offer(
            &self.k,
            &self.owner_fp,
            &self.device_fp,
            &self.caps,
            self.scope,
            frame,
            own_key,
        )
    }
}

fn grant(
    ceremony: &Ceremony,
    owner: &UserKey,
    device_pub: [u8; 32],
    issued: u64,
    ttl: u64,
    nonce: [u8; 12],
) -> EnrolGrant {
    let cert = DeviceCert::certify(owner, device_pub, issued, ttl).expect("fixture certifies");
    let payload = json!({
        "device_cert": cert.to_json(),
        "owner_cert": Value::Null,
        "fleet_rv": "vector-fleet-rv",
        "cap_header": Value::Null,
        "cap_ops": [],
        "ceiling": ["transfer"],
        "expires": issued.saturating_add(ttl),
        "persistent": true
    });
    seal_enrol_grant(&ceremony.k, payload, "vector-owner", nonce).expect("fixture seals a grant")
}

#[test]
fn every_enrol_vector_matches_the_shared_ceremony() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors are valid JSON");
    let cases = doc["cases"].as_array().expect("vectors have a cases array");
    assert!(!cases.is_empty(), "vector file must not be empty");

    let primary = Ceremony::get(&doc, "primary");
    let replayed = Ceremony::get(&doc, "replayed");
    let device = user(&identity_seed(&doc, "device"));
    let owner = user(&identity_seed(&doc, "owner"));
    let other_device = user(&identity_seed(&doc, "otherDevice"));
    let other_owner = user(&identity_seed(&doc, "otherOwner"));
    let device_pub = device.public_key_bytes();
    let owner_pub = owner.public_key_bytes();
    let other_device_pub = other_device.public_key_bytes();
    let other_owner_pub = other_owner.public_key_bytes();
    let offer_nonce = nonce(&doc, "offer");
    let grant_nonce = nonce(&doc, "grant");

    let now = doc["times"]["now"].as_u64().expect("now");
    let issued = doc["times"]["grantIssued"].as_u64().expect("grantIssued");
    let ttl = doc["times"]["grantTtl"].as_u64().expect("grantTtl");
    let expired_issued = doc["times"]["expiredIssued"]
        .as_u64()
        .expect("expiredIssued");
    let expired_ttl = doc["times"]["expiredTtl"].as_u64().expect("expiredTtl");
    let expired_now = doc["times"]["expiredNow"]
        .as_u64()
        .expect("expiredNow");

    for case in cases {
        let name = case["name"].as_str().expect("case has a name");
        let kind = case["kind"].as_str().expect("case has a kind");
        let expect = case["expect"].as_str().expect("case has an expect");

        match kind {
            "valid_round_trip" => {
                assert_eq!(expect, "accepted", "vector {name}");
                let offer = primary.offer(&device, device_pub, offer_nonce);
                assert_eq!(primary.open_offer(&offer, Some(owner_pub)), Ok(device_pub), "vector {name}: offer");

                let frame = grant(&primary, &owner, device_pub, issued, ttl, grant_nonce);
                let payload = open_enrol_grant(&primary.k, &frame).expect("grant opens");
                let verified = verify_mesh_grant(&payload, device_pub, Some(owner_pub), now)
                    .expect("grant verifies");
                assert_eq!(verified.cert.device_pub, device_pub, "vector {name}: cert device");
                assert_eq!(verified.cert.user_pub, owner_pub, "vector {name}: cert owner");
                assert_eq!(verified.owner_name, "vector-owner", "vector {name}: owner name");
                assert_eq!(verified.fleet_rv.as_deref(), Some("vector-fleet-rv"));
            }
            "forged_possession_proof" => {
                // The offer names the device key but is signed by another key.
                let offer = primary.offer(&other_device, device_pub, offer_nonce);
                let refused = primary
                    .open_offer(&offer, Some(owner_pub))
                    .expect_err("forged possession must be refused");
                assert_eq!(refused.code(), expect, "vector {name}");
            }
            "wrong_device_key" => {
                let frame = grant(
                    &primary,
                    &owner,
                    other_device_pub,
                    issued,
                    ttl,
                    grant_nonce,
                );
                let payload = open_enrol_grant(&primary.k, &frame).expect("grant opens");
                let refused = verify_mesh_grant(&payload, device_pub, Some(owner_pub), now)
                    .expect_err("grant for another device must be refused");
                assert_eq!(refused.code(), expect, "vector {name}");
            }
            "wrong_owner" => {
                let frame = grant(&primary, &other_owner, device_pub, issued, ttl, grant_nonce);
                let payload = open_enrol_grant(&primary.k, &frame).expect("grant opens");
                let refused = verify_mesh_grant(&payload, device_pub, Some(owner_pub), now)
                    .expect_err("grant from another owner must be refused");
                assert_eq!(refused.code(), expect, "vector {name}");
            }
            "expired_cert" => {
                let frame = grant(
                    &primary,
                    &owner,
                    device_pub,
                    expired_issued,
                    expired_ttl,
                    grant_nonce,
                );
                let payload = open_enrol_grant(&primary.k, &frame).expect("grant opens");
                let refused = verify_mesh_grant(&payload, device_pub, Some(owner_pub), expired_now)
                    .expect_err("expired cert must be refused");
                assert_eq!(refused.code(), expect, "vector {name}");
            }
            "replayed_offer" => {
                // The offer was proved for another ceremony; its AEAD does not
                // open under this ceremony's K.
                let offer = replayed.offer(&device, device_pub, offer_nonce);
                let refused = primary
                    .open_offer(&offer, Some(owner_pub))
                    .expect_err("replayed offer must be refused");
                assert_eq!(refused.code(), expect, "vector {name}");
            }
            "replayed_offer_within_ceremony" => {
                // A re-sent offer inside one ceremony is handled by the decision
                // rule, not by a second certification.
                let decision = enrol_offer_decision(EnrolOfferInputs {
                    owner_here: true,
                    operator_said_own: true,
                    operator_said_person: false,
                    offer_opened: true,
                    peer_can_hold: true,
                    can_ask: true,
                    already_asked: true,
                });
                assert_eq!(decision, EnrolOfferDecision::Decline, "vector {name}");
                assert_eq!(expect, "decline", "vector {name}");
            }
            other => panic!("vector {name}: unknown kind {other}"),
        }
    }
}

#[test]
fn frames_round_trip_through_json() {
    let offer = EnrolOffer::new([1u8; 12], b"offer-sealed");
    assert_eq!(EnrolOffer::from_value(&offer.to_value().unwrap()).unwrap(), offer);

    let grant = EnrolGrant::new([2u8; 12], b"grant-sealed");
    assert_eq!(EnrolGrant::from_value(&grant.to_value().unwrap()).unwrap(), grant);

    let expose = filament_enrol::IdentityExpose::new([3u8; 12], b"expose-sealed");
    assert_eq!(
        filament_enrol::IdentityExpose::from_value(&expose.to_value().unwrap()).unwrap(),
        expose
    );
}

struct MemoryStore(RefCell<Option<[u8; 32]>>);
impl SeedStore for MemoryStore {
    fn load_seed(&self) -> Result<Option<[u8; 32]>, EnrolError> {
        Ok(*self.0.borrow())
    }

    fn store_seed(&self, seed: &[u8; 32]) -> Result<(), EnrolError> {
        *self.0.borrow_mut() = Some(*seed);
        Ok(())
    }
}

struct CountingRng(u8);

impl RandomSource for CountingRng {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), EnrolError> {
        for byte in out {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

/// The browser-facing identity wrapper: inject the seed store and the RNG, then
/// use the same offer/certificate verification paths the vectors exercise.
#[test]
fn device_identity_generates_loads_and_verifies_pinned_material() {
    let doc: Value = serde_json::from_str(VECTORS).expect("vectors are valid JSON");
    let primary = Ceremony::get(&doc, "primary");
    let owner = user(&identity_seed(&doc, "owner"));
    let owner_pub = owner.public_key_bytes();
    let other_owner_pub = user(&identity_seed(&doc, "otherOwner")).public_key_bytes();
    let now = doc["times"]["now"].as_u64().expect("now");
    let ttl = doc["times"]["grantTtl"].as_u64().expect("grantTtl");
    let grant_nonce = nonce(&doc, "grant");
    let offer_nonce = nonce(&doc, "offer");
    let expose_nonce = nonce(&doc, "expose");

    let store = MemoryStore(RefCell::new(None));
    let mut rng = CountingRng(0x40);
    let generated = DeviceIdentity::generate(&store, &mut rng, None, Some(owner_pub))
        .expect("first use generates and persists a seed");
    assert!(store.0.borrow().is_some(), "the seed was persisted");
    assert_eq!(
        DeviceIdentity::load(&store, None, Some(owner_pub))
            .expect("load succeeds")
            .expect("a seed exists")
            .device_pub(),
        generated.device_pub(),
        "the stored seed reloads as the same device"
    );

    let device_pub = generated.device_pub();
    let cert = DeviceCert::certify(&owner, device_pub, now, ttl).expect("certify this device");
    let identity = DeviceIdentity::load(&store, Some(cert.clone()), Some(owner_pub))
        .expect("load succeeds")
        .expect("a seed exists");
    assert_eq!(identity.cert().map(|c| c.device_pub), Some(device_pub));

    let msg = b"vector possession message";
    let sig = identity.sign_possession(msg);
    verify_possession_sig(&device_pub, msg, &sig).expect("the identity signs possession");

    let offer = identity
        .enrol_offer(
            &primary.k,
            &primary.device_fp,
            &primary.owner_fp,
            &primary.caps,
            primary.scope,
            "pop-os",
            offer_nonce,
        )
        .expect("identity builds an offer");
    assert_eq!(primary.open_offer(&offer, Some(owner_pub)), Ok(device_pub));

    let frame = grant(&primary, &owner, device_pub, now, ttl, grant_nonce);
    let verified = identity
        .open_enrol_grant(&primary.k, &frame, now)
        .expect("pinned grant verifies");
    assert_eq!(verified.cert.device_pub, device_pub);

    // A peer identity verifies the certificate and refuses one from another
    // owner, using only the pinned owner and the peer's own key.
    let peer = DeviceIdentity::from_seed(&[0x77; 32], None, Some(owner_pub)).expect("peer identity");
    let expose = identity
        .identity_expose(
            &primary.k,
            &primary.device_fp,
            &primary.owner_fp,
            &primary.caps,
            primary.scope,
            expose_nonce,
        )
        .expect("identity builds an expose");
    let opened = peer
        .open_peer_expose(
            &expose,
            &primary.k,
            Some((primary.owner_fp.as_str(), primary.device_fp.as_str())),
            &primary.caps,
            primary.scope,
            now,
        )
        .expect("peer opens the expose");
    assert_eq!(opened.device_pub, device_pub);
    peer.verify_peer_cert(&cert, now).expect("peer verifies the cert");

    let foreign = DeviceIdentity::from_seed(&[0x78; 32], None, Some(other_owner_pub))
        .expect("foreign identity");
    assert_eq!(
        foreign.verify_peer_cert(&cert, now).unwrap_err().code(),
        "wrong-owner"
    );
}
