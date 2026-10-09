//! Security properties of invitations and enrollment that no test pinned.
//!
//! Found by the mutation probe (.github/workflows/mutants.yml). The existing
//! enrollment tests drive the hidden Legacy principal; the path production
//! actually accepts (`EnrollmentPayload::from_json` takes only the compact
//! invitation) had no end-to-end test, so its owner check and expiry check
//! could be inverted with every test green. Each test states the property it
//! protects. Integration test over the public API so it merges independently.

use filament_cap::ephemeral::*;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

fn keypair() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn pubkey(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key().as_ref().try_into().unwrap()
}

fn random32() -> [u8; 32] {
    let mut b = [0u8; 32];
    SystemRandom::new().fill(&mut b).unwrap();
    b
}

fn unique(label: &str) -> String {
    format!("{label}-{}", hex::encode(random32()))
}

fn invitation(owner: &Ed25519KeyPair, seed: [u8; 32], expires: u64, reuse: Reuse) -> Invitation {
    Invitation::mint(
        owner,
        seed,
        vec!["transfer".into(), "shell".into()],
        expires,
        7 * 24 * 3600,
        reuse,
        false,
        "alice".into(),
        Vec::new(),
    )
    .unwrap()
}

/// What a joiner sends: it holds the token (with the seed), and the verifier
/// issued `nonce` and is `verifier_pub`.
fn join(
    token: &[u8],
    nonce: [u8; 32],
    verifier_pub: [u8; 32],
) -> (EnrollmentPayload, [u8; 32]) {
    let inv = Invitation::from_token(token).expect("token parses");
    let enroll_kp = Ed25519KeyPair::from_seed_unchecked(&inv.enroll_private_key).unwrap();
    let device_kp = keypair();
    let device_pub = pubkey(&device_kp);
    let wire = Invitation::from_payload(&inv.to_payload()).expect("payload parses");
    let p = EnrollmentPayload::build(
        EnrollmentPrincipal::Compact(wire),
        device_pub,
        &enroll_kp,
        &device_kp,
        nonce,
        verifier_pub,
    );
    (p, device_pub)
}

fn far_future() -> u64 {
    now_secs() + 3600
}

// ---------------------------------------------------------------------------
// Compact enrollment, end to end
// ---------------------------------------------------------------------------

/// The production enrollment path accepts a genuine compact invitation from
/// the owner, over the wire format, and yields the device and the ceiling the
/// owner signed.
#[test]
fn compact_enrollment_from_the_owner_is_accepted() {
    let owner = keypair();
    let seed = random32();
    let inv = invitation(&owner, seed, far_future(), Reuse::Once);
    let nonce = random32();
    let verifier = [0xABu8; 32];
    let (p, device_pub) = join(&inv.to_token(), nonce, verifier);
    // Over the JSON wire form, as the daemon receives it.
    let p = EnrollmentPayload::from_json(&p.to_json()).expect("payload JSON parses");
    let (enroll_pub, dev, ak) = p.verify(&pubkey(&owner), &nonce, &verifier).unwrap();
    assert_eq!(enroll_pub, inv.enroll_pub);
    assert_eq!(enroll_pub, pubkey(&Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()));
    assert_eq!(dev, device_pub);
    let mut caps = ak.caps.clone();
    caps.sort();
    assert_eq!(caps, vec!["shell".to_string(), "transfer".to_string()]);
    assert_eq!(ak.issuer, pubkey(&owner));
}

/// An invitation minted by anyone other than the verifier's owner is refused,
/// even though its signature is internally valid.
#[test]
fn compact_enrollment_from_another_owner_is_refused() {
    let owner = keypair();
    let mallory = keypair();
    let inv = invitation(&mallory, random32(), far_future(), Reuse::Once);
    let nonce = random32();
    let verifier = [0xABu8; 32];
    let (p, _) = join(&inv.to_token(), nonce, verifier);
    assert!(
        p.verify(&pubkey(&owner), &nonce, &verifier).is_err(),
        "an invitation from a different owner enrolled a device"
    );
}

/// An expired invitation enrolls nothing.
#[test]
fn compact_enrollment_after_expiry_is_refused() {
    let owner = keypair();
    let inv = invitation(&owner, random32(), now_secs() - 1, Reuse::Once);
    let nonce = random32();
    let verifier = [0xABu8; 32];
    let (p, _) = join(&inv.to_token(), nonce, verifier);
    let err = p
        .verify(&pubkey(&owner), &nonce, &verifier)
        .expect_err("an expired invitation enrolled a device");
    assert!(err.to_string().contains("expired"), "{err}");
}

/// The compact payload is bound to the verifier's own nonce and identity, and
/// to the device key it names.
#[test]
fn compact_enrollment_is_bound_to_nonce_verifier_and_device() {
    let owner = keypair();
    let inv = invitation(&owner, random32(), far_future(), Reuse::Once);
    let nonce = random32();
    let verifier = [0xABu8; 32];
    let (mut p, _) = join(&inv.to_token(), nonce, verifier);
    let op = pubkey(&owner);
    assert!(p.verify(&op, &random32(), &verifier).is_err(), "replayed under another nonce");
    assert!(p.verify(&op, &nonce, &[0xACu8; 32]).is_err(), "presented to another verifier");
    p.device_pub = pubkey(&keypair());
    assert!(p.verify(&op, &nonce, &verifier).is_err(), "device key swapped after signing");
}

/// The invitation's fields round-trip through both wire artifacts exactly,
/// including the reuse limit and IPv6 route prefixes, so the verifier enforces
/// the limit and the scope the owner chose.
#[test]
fn invitation_fields_survive_token_and_payload() {
    let owner = keypair();
    for reuse in [Reuse::Once, Reuse::N(3), Reuse::Reusable] {
        let inv = Invitation::mint(
            &owner,
            random32(),
            vec!["route".into(), "transfer".into()],
            far_future(),
            3600,
            reuse.clone(),
            true,
            "bob".into(),
            vec!["fd00:1::/64".into(), "10.1.0.0/16".into()],
        )
        .unwrap();
        for back in [
            Invitation::from_token(&inv.to_token()).unwrap(),
            Invitation::from_payload(&inv.to_payload()).unwrap(),
        ] {
            assert_eq!(back.reuse, reuse, "reuse limit changed in transit");
            assert_eq!(back.routes, vec!["fd00:1::/64".to_string(), "10.1.0.0/16".to_string()]);
            let (mut got, mut want) = (back.caps.clone(), inv.caps.clone());
            got.sort();
            want.sort();
            assert_eq!(got, want);
            assert_eq!(back.expires, inv.expires);
            assert_eq!(back.max_offline, inv.max_offline);
            assert!(back.ephemeral);
            assert_eq!(back.owner_name, "bob");
            assert!(back.verify_against_owner(&pubkey(&owner)));
        }
    }
}

/// Parsing attacker-supplied bytes never panics: every truncation of a valid
/// token or payload is refused cleanly. The payload arrives from the network.
#[test]
fn truncated_invitations_are_refused_without_panicking() {
    let owner = keypair();
    let inv = invitation(&owner, random32(), far_future(), Reuse::Once);
    let (token, payload) = (inv.to_token(), inv.to_payload());
    for n in 0..token.len() {
        assert!(Invitation::from_token(&token[..n]).is_none(), "token prefix {n} parsed");
    }
    for n in 0..payload.len() {
        assert!(Invitation::from_payload(&payload[..n]).is_none(), "payload prefix {n} parsed");
    }
}

/// Two owners rendezvous on different enrollment channels, and an
/// invitation's fingerprint selects only its own owner.
#[test]
fn owners_do_not_share_an_enrollment_channel() {
    let (a, b) = (keypair(), keypair());
    assert_ne!(issuer_fingerprint(&pubkey(&a)), issuer_fingerprint(&pubkey(&b)));
    assert_ne!(enroll_channel(&pubkey(&a)), enroll_channel(&pubkey(&b)));
    let inv = invitation(&a, random32(), far_future(), Reuse::Once);
    assert_eq!(inv.issuer_fp, issuer_fingerprint(&pubkey(&a)));
    assert!(!inv.verify_against_owner(&pubkey(&b)));
}

// ---------------------------------------------------------------------------
// Use limits, rate limits, nonces
// ---------------------------------------------------------------------------

/// A single-use key enrolls once; an N-use key enrolls N times; a reusable
/// key is still bounded by the per-minute rate limit.
#[test]
fn burn_enforces_reuse_and_rate_limits() {
    let once = random32();
    burn_auth_key(&once, &Reuse::Once).unwrap();
    assert!(burn_auth_key(&once, &Reuse::Once).is_err(), "single-use key used twice");

    let n = random32();
    burn_auth_key(&n, &Reuse::N(2)).unwrap();
    burn_auth_key(&n, &Reuse::N(2)).unwrap();
    assert!(burn_auth_key(&n, &Reuse::N(2)).is_err(), "N(2) key used three times");

    let r = random32();
    for i in 0..5 {
        burn_auth_key(&r, &Reuse::Reusable).unwrap_or_else(|e| panic!("use {i}: {e}"));
    }
    assert!(burn_auth_key(&r, &Reuse::Reusable).is_err(), "rate limit did not bound a reusable key");
}

/// Enrollment attempts from one transport peer are capped per minute, and the
/// cap is per peer.
#[test]
fn enrollment_attempts_are_rate_limited_per_peer() {
    let pid = unique("pid");
    for i in 0..5 {
        check_rate_limit(&pid).unwrap_or_else(|e| panic!("attempt {i}: {e}"));
    }
    assert!(check_rate_limit(&pid).is_err(), "sixth attempt in a minute was allowed");
    check_rate_limit(&unique("other")).unwrap();
}

/// The enrollment challenge is a fresh, unpredictable, single-use nonce per
/// peer: consuming returns exactly what was issued, a second consume fails,
/// a new challenge replaces the old one, and one peer's challenge does not
/// evict another's.
#[test]
fn enrollment_nonces_are_fresh_single_use_and_per_peer() {
    let (a, b) = (unique("a"), unique("b"));
    let na = generate_nonce(&a).unwrap();
    let nb = generate_nonce(&b).unwrap();
    assert_ne!(na, nb);
    assert_ne!(na, [0u8; 32]);
    assert_eq!(consume_latest_nonce(&a).unwrap(), na, "consumed nonce is not the issued one");
    assert!(consume_latest_nonce(&a).is_err(), "a nonce was consumed twice");
    assert_eq!(consume_latest_nonce(&b).unwrap(), nb, "another peer's challenge was evicted");

    let first = generate_nonce(&a).unwrap();
    let second = generate_nonce(&a).unwrap();
    assert_ne!(first, second);
    assert_eq!(consume_latest_nonce(&a).unwrap(), second, "an older challenge outlived its replacement");
    assert!(consume_latest_nonce(&a).is_err());
}
