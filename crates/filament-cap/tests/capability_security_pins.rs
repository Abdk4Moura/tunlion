//! Security properties of the capability layer that no test pinned.
//!
//! Found by the mutation probe (.github/workflows/mutants.yml): every test here
//! kills mutants the existing suite let survive. Each states the property it
//! protects. Kept as an integration test over the public API so it merges
//! independently of edits to src/capability.rs.

use filament_cap::capability::*;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

fn owner() -> Ed25519KeyPair {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn pk(k: &Ed25519KeyPair) -> [u8; 32] {
    k.public_key().as_ref().try_into().unwrap()
}

fn genesis(o: &Ed25519KeyPair, floors: Vec<CapFloor>) -> CapHeader {
    let nonce = [0x11u8; 32];
    let mut h = CapHeader {
        resource: make_resource_id(&pk(o), &nonce),
        epoch: 0,
        owner_pub: pk(o),
        nonce,
        floors,
        issued_at: now_secs(),
        prev_owner_pub: None,
        prev_header_hash: None,
        sig: [0u8; 64],
    };
    h.sig = sign_cap_header(&h, o);
    h
}

fn store_for(h: &CapHeader) -> Vec<Value> {
    let mut s = vec![];
    apply_header(&mut s, h).unwrap();
    s
}

fn op(
    o: &Ed25519KeyPair,
    kind: CapOpKind,
    target_kind: u8,
    target: [u8; 32],
    resource: &str,
    perms: &[&str],
    version: u64,
    ttl: u64,
) -> CapOp {
    let now = now_secs();
    let mut c = CapOp {
        op: kind,
        grantor: pk(o),
        target_kind,
        target,
        resource: resource.into(),
        permissions: perms.iter().map(|s| s.to_string()).collect(),
        expires: now + ttl,
        issued_at: now,
        version,
        sig: [0u8; 64],
    };
    c.sig = sign_cap_op(&c, o);
    c
}

fn authorized(d: Decision) -> bool {
    matches!(d, Decision::Authorized)
}

fn eval(store: &[Value], h: &CapHeader, dev: [u8; 32], user: [u8; 32], action: &str, now: u64) -> bool {
    authorized(evaluate(store, h, &dev, &user, &h.resource, action, now, None))
}

// ---------------------------------------------------------------------------
// Signed objects bind what they claim to
// ---------------------------------------------------------------------------

/// A signature over a Grant must not verify as a Revoke (or Modify). If the op
/// kind were outside the signed bytes, a captured grant could be replayed as a
/// revocation and the other way round.
#[test]
fn cap_op_kind_is_covered_by_the_signature() {
    let o = owner();
    let g = op(&o, CapOpKind::Grant, 0x01, [1; 32], "r", &["shell"], 1, 600);
    g.verify(&pk(&o), now_secs()).unwrap();
    for k in [CapOpKind::Revoke, CapOpKind::Modify] {
        let mut m = g.clone();
        m.op = k;
        assert!(m.verify(&pk(&o), now_secs()).is_err(), "a grant signature verified as {k:?}");
    }
}

/// Every op kind survives the store's JSON form, so a stored revoke is read
/// back as a revoke.
#[test]
fn cap_op_kind_roundtrips_through_the_store_format() {
    let o = owner();
    for k in [CapOpKind::Grant, CapOpKind::Revoke, CapOpKind::Modify] {
        let c = op(&o, k, 0x01, [1; 32], "r", &["shell"], 1, 600);
        let back = CapOp::from_json(&c.to_json()).expect("op JSON parses back");
        assert_eq!(back.op, k);
        back.verify(&pk(&o), now_secs()).unwrap();
    }
}

/// The header signature covers each floor's target, so nobody can move a
/// version floor from the device it protects onto another one.
#[test]
fn header_signature_covers_floor_targets() {
    let o = owner();
    let h = genesis(&o, vec![CapFloor { target_kind: 0x01, target: [1; 32], min_version: 9 }]);
    h.verify_genesis().unwrap();
    let mut m = h.clone();
    m.floors[0].target = [2; 32];
    assert!(m.verify_genesis().is_err(), "floor target is not covered by the header signature");
    let mut m = h.clone();
    m.floors[0].target_kind = 0x00;
    assert!(m.verify_genesis().is_err(), "floor target kind is not covered by the header signature");
}

/// A succession header read back from the store keeps its chain link, so the
/// next succession is checked against the real predecessor.
#[test]
fn succession_header_roundtrips_with_its_chain_link() {
    let o = owner();
    let o2 = owner();
    let g = genesis(&o, vec![]);
    let mut s = CapHeader {
        resource: g.resource.clone(),
        epoch: 1,
        owner_pub: pk(&o2),
        nonce: g.nonce,
        floors: vec![],
        issued_at: now_secs(),
        prev_owner_pub: Some(g.owner_pub),
        prev_header_hash: Some(hash_header(&g)),
        sig: [0u8; 64],
    };
    s.sig = sign_cap_header(&s, &o);
    let back = CapHeader::from_json(&s.to_json()).expect("header JSON parses back");
    assert_eq!(back.prev_owner_pub, Some(g.owner_pub));
    assert_eq!(back.prev_header_hash, Some(hash_header(&g)));
    assert_eq!(hash_header(&back), hash_header(&s));
    back.verify_succession(&g).unwrap();
}

/// The "self" resource id is self-certifying for its owner and stable across
/// releases: stores written by an earlier build file their header under this
/// id, so a different derivation would orphan every existing grant. The
/// expected value is SHA-256(owner_pub || SHA-256("filament-self-resource-v1")),
/// computed independently of this code.
#[test]
fn self_resource_id_is_stable_and_self_certifying() {
    assert_eq!(
        self_resource_id(&[7u8; 32]),
        "a9261cdeeede4e73c05ccb093af9c253a44e7911504158c94dfd385831062c18"
    );
    assert_eq!(
        hex::encode(self_resource_nonce()),
        "ed9f1a70d0c32a43ba6f7ed81056a32e77ef8d64c89f043124a1057c03b7ee9e"
    );
    let o = owner();
    let mut h = genesis(&o, vec![]);
    h.nonce = self_resource_nonce();
    h.resource = self_resource_id(&pk(&o));
    h.sig = sign_cap_header(&h, &o);
    h.verify_genesis().unwrap();
    assert_ne!(self_resource_id(&pk(&o)), self_resource_id(&pk(&owner())));
}

// ---------------------------------------------------------------------------
// Expiry, ratchet, floors
// ---------------------------------------------------------------------------

/// A grant is dead AT its expiry second, the same convention as certificates
/// (`now >= expires` is expired).
#[test]
fn grant_is_inactive_at_its_expiry_instant() {
    assert!(grant_active(100, 99));
    assert!(!grant_active(100, 100));
    assert!(!grant_active(100, 101));
}

/// The version clock is the wall clock in milliseconds. Versions are what
/// order a revoke after the grant it revokes, so a constant clock would mint
/// every op at the same version.
#[test]
fn version_clock_is_wall_clock_milliseconds() {
    let ms = now_ms();
    let s = now_secs();
    assert!(ms / 1000 + 1 >= s && ms / 1000 <= s + 1, "now_ms {ms} disagrees with now_secs {s}");
}

/// The freshness ratchet is per owner and only moves forward: once this owner
/// has signed something at time T, a grant that expired before T stays dead
/// even when the local clock reads earlier (rolled back, or skewed).
#[test]
fn ratchet_keeps_an_expired_grant_dead_under_clock_rollback() {
    let o = owner();
    let h = genesis(&o, vec![]);
    let mut s = store_for(&h);
    let dev = [0x22u8; 32];
    let g = op(&o, CapOpKind::Grant, 0x01, dev, &h.resource, &["shell"], hlc_next(0, now_ms()), 100);
    apply_cap_op(&mut s, &h, &g, now_secs()).unwrap();
    let now = now_secs();
    assert!(eval(&s, &h, dev, [0; 32], "shell", now));

    // Another owner's ratchet must not interfere with this one.
    update_ratchet(&mut s, &pk(&owner()), now).unwrap();
    update_ratchet(&mut s, &pk(&o), now + 200).unwrap();
    assert!(
        !eval(&s, &h, dev, [0; 32], "shell", now),
        "a grant that expired before the owner's latest signed time was honoured"
    );
}

/// A version floor protects exactly the target it names. Looking it up by
/// kind alone (or target alone) can return a different target's lower floor
/// and readmit an op the owner floored out.
#[test]
fn version_floor_applies_to_its_own_target() {
    let o = owner();
    let (a, b, c) = ([0xAAu8; 32], [0xBBu8; 32], [0xCCu8; 32]);
    let v = hlc_next(0, now_ms());
    let h = genesis(
        &o,
        vec![
            CapFloor { target_kind: 0x01, target: b, min_version: 0 },
            CapFloor { target_kind: 0x00, target: a, min_version: 0 },
            CapFloor { target_kind: 0x01, target: a, min_version: u64::MAX },
            CapFloor { target_kind: 0x01, target: c, min_version: v },
        ],
    );
    assert_eq!(h.floor_for(0x01, &a), u64::MAX);
    assert_eq!(h.floor_for(0x00, &a), 0);
    let mut s = store_for(&h);
    let below = op(&o, CapOpKind::Grant, 0x01, a, &h.resource, &["shell"], v, 600);
    assert!(apply_cap_op(&mut s, &h, &below, now_secs()).is_err(), "an op below its target's floor was applied");
    // An op exactly AT the floor is allowed: the floor is a minimum, inclusive.
    let at = op(&o, CapOpKind::Grant, 0x01, c, &h.resource, &["shell"], v, 600);
    apply_cap_op(&mut s, &h, &at, now_secs()).unwrap();
}

// ---------------------------------------------------------------------------
// Delegated ceiling inside evaluate
// ---------------------------------------------------------------------------

/// A delegated principal never exceeds its auth-key ceiling, even when it is
/// the owner (the owner shortcut runs AFTER the ceiling), and the ceiling is
/// case-insensitive. The CLI has an independent copy of this check; this pins
/// the crate's own copy, which is the one enforcement relies on in
/// authoritative mode.
#[test]
fn evaluate_enforces_the_delegated_ceiling_before_the_owner_shortcut() {
    let o = owner();
    let h = genesis(&o, vec![]);
    let mut s = store_for(&h);
    let me = pk(&o);
    let caps = vec!["Transfer".to_string()];
    let ev = |s: &[Value], action: &str, caps: Option<&[String]>| {
        authorized(evaluate(s, &h, &[1; 32], &me, &h.resource, action, now_secs(), caps))
    };
    assert!(ev(&s, "shell", None), "owner without a ceiling is authorized");
    assert!(!ev(&s, "shell", Some(&caps)), "the ceiling did not restrict the owner");
    assert!(ev(&s, "transfer", Some(&caps)), "an action inside the ceiling was refused");

    // evaluate_grants_only applies the same ceiling to an explicit grant.
    let dev = [0x33u8; 32];
    let g = op(&o, CapOpKind::Grant, 0x01, dev, &h.resource, &["shell", "transfer"], hlc_next(0, now_ms()), 600);
    apply_cap_op(&mut s, &h, &g, now_secs()).unwrap();
    let go = |action: &str, caps: Option<&[String]>| {
        authorized(evaluate_grants_only(&s, &h, &dev, &[0; 32], &h.resource, action, now_secs(), caps))
    };
    assert!(go("shell", None));
    assert!(!go("shell", Some(&caps)), "a grant exceeded the delegated ceiling");
    assert!(go("transfer", Some(&caps)));
}

// ---------------------------------------------------------------------------
// Tag grants
// ---------------------------------------------------------------------------

fn binding(o: &Ed25519KeyPair, tag: [u8; 32], kind: u8, subject: [u8; 32], version: u64, ttl: u64) -> TagBindingObj {
    let mut b = TagBindingObj {
        tag_ref: tag,
        subject_kind: kind,
        subject,
        owner_pub: pk(o),
        version,
        issued_at: now_secs(),
        expires: now_secs() + ttl,
        sig: [0u8; 64],
    };
    let sig = o.sign(&b.canonical_for_signing());
    b.sig.copy_from_slice(sig.as_ref());
    b
}

struct TagWorld {
    o: Ed25519KeyPair,
    h: CapHeader,
    s: Vec<Value>,
    tag: [u8; 32],
}

fn tag_world() -> TagWorld {
    let o = owner();
    let h = genesis(&o, vec![]);
    let mut s = store_for(&h);
    let tag = make_tag_target(&pk(&o), "ops");
    let g = op(&o, CapOpKind::Grant, 0x03, tag, &h.resource, &["shell"], hlc_next(0, now_ms()), 3600);
    apply_cap_op(&mut s, &h, &g, now_secs()).unwrap();
    TagWorld { o, h, s, tag }
}

/// A tag grant reaches exactly the subjects the owner bound to the tag: a
/// device-kind binding admits that device only, a user-kind binding admits
/// that user's devices only, and nobody is admitted before a binding exists.
#[test]
fn tag_grant_reaches_only_bound_subjects() {
    let mut w = tag_world();
    let (d1, d2) = ([0xD1u8; 32], [0xD2u8; 32]);
    let (u1, u2) = ([0xE1u8; 32], [0xE2u8; 32]);
    let now = now_secs();
    assert!(!eval(&w.s, &w.h, d1, u1, "shell", now), "authorized before any tag binding");

    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d1, 1, 3600)).unwrap();
    assert!(eval(&w.s, &w.h, d1, u2, "shell", now), "the bound device was refused");
    assert!(!eval(&w.s, &w.h, d2, u1, "shell", now), "an unbound device was admitted");
    assert!(!eval(&w.s, &w.h, d1, u1, "transfer", now), "the tag grant widened to another action");
    // A device-kind binding names a DEVICE key; a user whose key happens to be
    // those bytes is not that device.
    assert!(!eval(&w.s, &w.h, d2, d1, "shell", now), "a device binding matched a user key");

    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x00, u2, 1, 3600)).unwrap();
    assert!(eval(&w.s, &w.h, d2, u2, "shell", now), "a device of the bound user was refused");
    assert!(!eval(&w.s, &w.h, [0xD3; 32], u1, "shell", now), "an unbound user was admitted");
    assert!(!eval(&w.s, &w.h, u2, [0xE3; 32], "shell", now), "a user binding matched a device key");
}

/// A tag is scoped to its owner and its name.
#[test]
fn tag_targets_are_owner_and_name_scoped() {
    let (a, b) = (pk(&owner()), pk(&owner()));
    assert_ne!(make_tag_target(&a, "ops"), make_tag_target(&b, "ops"));
    assert_ne!(make_tag_target(&a, "ops"), make_tag_target(&a, "dev"));
    assert_eq!(make_tag_target(&a, "ops"), make_tag_target(&a, "ops"));
}

/// Only the resource owner's valid signature binds a subject to a tag:
/// applying a binding signed by anyone else fails, and one written into the
/// store directly (bypassing apply) is ignored at evaluation time.
#[test]
fn tag_binding_needs_the_owners_signature() {
    let mut w = tag_world();
    let d = [0xD1u8; 32];
    let mallory = owner();
    let mut forged = binding(&mallory, w.tag, 0x01, d, 1, 3600);
    forged.owner_pub = pk(&w.o); // claims the owner, signed by mallory
    assert!(apply_tag_binding(&mut w.s, &forged).is_err(), "a forged binding was applied");
    w.s.push(forged.to_json());
    assert!(!eval(&w.s, &w.h, d, [0; 32], "shell", now_secs()), "a forged binding in the store was honoured");

    // A genuine signature over different content does not carry over.
    let good = binding(&w.o, w.tag, 0x01, [0xD9; 32], 1, 3600);
    let mut moved = good.clone();
    moved.subject = d;
    assert!(moved.verify().is_err(), "the binding signature does not cover its subject");
    w.s.push(moved.to_json());
    assert!(!eval(&w.s, &w.h, d, [0; 32], "shell", now_secs()));
}

/// A tag binding cannot be rolled back to an older version (for example to
/// resurrect a binding the owner replaced), and a newer version replaces it.
#[test]
fn tag_binding_versions_only_move_forward() {
    let mut w = tag_world();
    let d = [0xD1u8; 32];
    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d, 2, 3600)).unwrap();
    assert!(apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d, 1, 3600)).is_err(), "rollback v2 -> v1 accepted");
    assert!(apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d, 2, 3600)).is_err(), "replay of v2 accepted");
    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d, 3, 3600)).unwrap();
    // Other subjects of the same tag are independent version streams.
    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, [0xD2; 32], 1, 3600)).unwrap();
    let n = w.s.iter().filter(|e| e["type"] == "cap_tag_binding").count();
    assert_eq!(n, 2, "a forward update must replace, not accumulate");
}

/// A binding stops admitting at its expiry, judged at the ratcheted time.
#[test]
fn tag_binding_expires_under_the_ratchet() {
    let mut w = tag_world();
    let d = [0xD1u8; 32];
    apply_tag_binding(&mut w.s, &binding(&w.o, w.tag, 0x01, d, 1, 100)).unwrap();
    let now = now_secs();
    assert!(eval(&w.s, &w.h, d, [0; 32], "shell", now));
    update_ratchet(&mut w.s, &pk(&w.o), now + 200).unwrap();
    assert!(!eval(&w.s, &w.h, d, [0; 32], "shell", now), "an expired tag binding still admitted");
}

// ---------------------------------------------------------------------------
// Route scoping
// ---------------------------------------------------------------------------

/// A route ceiling admits only prefixes inside it, for both families. In
/// particular a v6 ceiling compares the NETWORK bits: comparing host bits
/// would admit any prefix with the same low bits.
#[test]
fn route_containment_compares_network_bits() {
    let v6 = vec!["fd00::/16".to_string()];
    assert!(cidr_within_any("fd00:1::/64", &v6));
    assert!(!cidr_within_any("fe80::/64", &v6), "a v6 prefix outside the ceiling was admitted");
    assert!(!cidr_within_any("::/0", &v6));
    let v4 = vec!["10.0.0.0/24".to_string()];
    // A host route is the narrowest prefix, inside its network.
    assert!(cidr_within_any("10.0.0.5/32", &v4));
    assert!(!cidr_within_any("10.0.1.5/32", &v4));
    assert!(!cidr_within_any("10.0.0.5/33", &v4), "an impossible prefix length was accepted");
    assert!(cidr_within_any("fd00::1/128", &v6));
}

/// Normalization keeps full-length prefixes and masks v6 host bits, so one
/// prefix has one resource id and a grant applies to the advertisement it was
/// written for.
#[test]
fn cidr_normalization_handles_full_length_and_v6_masks() {
    assert_eq!(normalize_cidr("10.0.0.5/32").unwrap(), "10.0.0.5/32");
    assert_eq!(normalize_cidr("fd00::1/128").unwrap(), "fd00::1/128");
    assert_eq!(normalize_cidr("fd00::abcd/64").unwrap(), "fd00::/64");
    assert_eq!(normalize_cidr("fd00:1234:5678::1/48").unwrap(), "fd00:1234:5678::/48");
    assert!(normalize_cidr("10.0.0.0/33").is_err());
    assert!(normalize_cidr("fd00::/129").is_err());
}

// ---------------------------------------------------------------------------
// Gate decision plumbing and classification
// ---------------------------------------------------------------------------

/// `allowed()` is what every CLI gate branches on.
#[test]
fn gate_decision_allowed_and_reason() {
    assert!(GateDecision::Allow.allowed());
    let d = GateDecision::Deny { cap_reason: Some("device revoked".into()) };
    assert!(!d.allowed());
    assert_eq!(d.deny_reason("legacy"), "device revoked");
    let d = GateDecision::Deny { cap_reason: None };
    assert!(!d.allowed());
    assert_eq!(d.deny_reason("legacy"), "legacy");
}

/// A delegated principal always presents its ceiling to evaluate; owner and
/// fleet principals present none.
#[test]
fn delegated_principal_carries_its_ceiling() {
    let caps = vec!["transfer".to_string()];
    let p = PrincipalKind::Delegated { caps: caps.clone() };
    assert_eq!(p.auth_key_caps(), Some(&caps[..]));
    assert_eq!(PrincipalKind::OwnerDevice.auth_key_caps(), None);
    assert_eq!(PrincipalKind::FleetDevice.auth_key_caps(), None);
}

/// Only shell and route are deliberate-tier; transfer and mount are scoped
/// defaults; unknown actions are not classified at all.
#[test]
fn capability_tiers_are_disjoint() {
    for a in ["shell", "route"] {
        assert!(is_deliberate_capability(a), "{a} must be deliberate");
        assert!(!is_scoped_default_action(a));
    }
    for a in ["transfer", "mount"] {
        assert!(!is_deliberate_capability(a), "{a} must not be deliberate");
        assert!(is_scoped_default_action(a));
    }
    assert!(!is_enforced_capability("bogus"));
    assert!(!is_deliberate_capability("bogus"));
}
