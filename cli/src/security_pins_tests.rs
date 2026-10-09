//! Security decisions in the CLI that no test pinned.
//!
//! Found by the mutation probe (.github/workflows/mutants.yml): each test kills
//! mutants the existing suite let survive, and each states the property it
//! protects. A separate module (one `mod` line in main.rs) so it merges
//! independently of the files it exercises.
//!
//! Tests that read the process-global config dir hold `lock_test_config` for
//! their whole body, like every other such test in this crate.

use crate::capability::{
    CapHeader, CapOp, CapOpKind, CapOutcome, apply_cap_op, cap_authorize, cap_fleet_inputs,
    load_cap_store, now_ms, hlc_next, save_and_list_revoked, sign_cap_op, update_ratchet,
};
use crate::identity::{self, DeviceCert, UserKey};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn unique_dir(label: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!(
        "fil-pins-{label}-{}-{nanos:x}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Run `f` with FILAMENT_CONFIG_DIR pointing at a fresh directory.
fn with_cfg<T>(f: impl FnOnce(&Path) -> T) -> T {
    let _guard = crate::tests::lock_test_config();
    let dir = unique_dir("cfg");
    // SAFETY: the lock above makes this the only test touching the variable.
    unsafe { std::env::set_var("FILAMENT_CONFIG_DIR", &dir) };
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&dir)));
    unsafe { std::env::remove_var("FILAMENT_CONFIG_DIR") };
    let _ = std::fs::remove_dir_all(&dir);
    match r {
        Ok(v) => v,
        Err(e) => std::panic::resume_unwind(e),
    }
}

fn write_devices(dir: &Path, v: Value) {
    std::fs::write(dir.join("devices.json"), serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

fn rand32() -> [u8; 32] {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 32];
    ring::rand::SystemRandom::new().fill(&mut b).unwrap();
    b
}

fn user() -> UserKey {
    UserKey::from_seed(&rand32()).unwrap()
}

fn cert(u: &UserKey, device: [u8; 32]) -> DeviceCert {
    DeviceCert::certify(u, device, identity::now_secs(), identity::CERT_TTL_SECS).unwrap()
}

fn header(resource: &str, owner_pub: [u8; 32]) -> CapHeader {
    CapHeader {
        resource: resource.into(),
        epoch: 0,
        owner_pub,
        nonce: [0u8; 32],
        floors: vec![],
        issued_at: identity::now_secs(),
        prev_owner_pub: None,
        prev_header_hash: None,
        sig: [0u8; 64],
    }
}

/// A cap store where a header for ANOTHER resource, owned by `decoy`, comes
/// first, then the "self" header owned by `owner`, which has granted `shell`
/// to `device`.
fn store_with_decoy(owner: &UserKey, decoy: [u8; 32], device: [u8; 32]) -> Vec<Value> {
    let pk = owner.public_key_bytes();
    let mut store = vec![header("route-elsewhere", decoy).to_json()];
    let me = header("self", pk);
    let mut v = me.to_json();
    v["resource"] = json!("self");
    store.push(v);
    let now = identity::now_secs();
    update_ratchet(&mut store, &pk, now).unwrap();
    let mut op = CapOp {
        op: CapOpKind::Grant,
        grantor: pk,
        target_kind: 0x01,
        target: device,
        resource: "self".into(),
        permissions: vec!["shell".into()],
        expires: now + 3600,
        issued_at: now,
        version: hlc_next(0, now_ms()),
        sig: [0u8; 64],
    };
    op.sig = sign_cap_op(&op, owner.keypair());
    apply_cap_op(&mut store, &me, &op, now).unwrap();
    store
}

// ---------------------------------------------------------------------------
// Legacy device store: grant, revoke, deny
// ---------------------------------------------------------------------------

/// A revoke is a durable decision on THAT device: it denies the capability,
/// leaves the transfer baseline and other devices alone, and only a later
/// grant lifts it. Grants and revokes of an unknown device are refused. This
/// is the #244 decision `device_capability_denied` exists for; nothing
/// exercised the writer or the readers directly.
#[test]
fn revoke_is_a_durable_per_device_decision() {
    use crate::device_caps::{device_allows, device_capability_denied, device_set_cap};
    with_cfg(|dir| {
        write_devices(
            dir,
            json!([
                {"name": "alpha", "secret": "s1"},
                {"name": "beta", "secret": "s2", "v": 2, "caps": ["transfer"]}
            ]),
        );
        assert!(device_allows("alpha", "transfer"), "transfer is the L0 baseline");
        assert!(!device_allows("alpha", "shell"), "shell allowed with no grant");
        assert!(!device_allows("ghost", "shell"), "an unknown device was allowed");
        assert!(!device_capability_denied("alpha", "shell"));

        device_set_cap("alpha", "shell", true, None).unwrap();
        assert!(device_allows("alpha", "shell"), "the grant did not take");
        assert!(!device_allows("beta", "shell"), "a grant to alpha reached beta");

        device_set_cap("alpha", "shell", false, None).unwrap();
        assert!(!device_allows("alpha", "shell"), "revoked shell still allowed");
        assert!(device_capability_denied("alpha", "shell"), "the revoke left no durable deny");
        assert!(!device_capability_denied("alpha", "transfer"), "the deny spread to another capability");
        assert!(!device_capability_denied("beta", "shell"), "the deny spread to another device");
        let caps = crate::device_caps::device_caps_at(&dir.join("devices.json"), "alpha").unwrap();
        assert!(caps.contains(&"transfer".to_string()), "revoking shell dropped transfer: {caps:?}");

        device_set_cap("alpha", "shell", true, None).unwrap();
        assert!(!device_capability_denied("alpha", "shell"), "a re-grant did not lift the deny");
        assert!(device_allows("alpha", "shell"));

        assert!(device_set_cap("ghost", "shell", true, None).is_err(), "granted to a stranger");
        assert!(device_set_cap("ghost", "shell", false, None).is_err());
    })
}

/// A time-bounded legacy grant stops allowing at its expiry.
#[test]
fn expired_legacy_grant_does_not_allow() {
    use crate::device_caps::{device_allows, device_set_cap};
    with_cfg(|dir| {
        write_devices(dir, json!([{"name": "alpha", "secret": "s1"}]));
        let now = identity::now_secs();
        device_set_cap("alpha", "shell", true, Some(now + 3600)).unwrap();
        assert!(device_allows("alpha", "shell"));
        device_set_cap("alpha", "shell", true, Some(now - 1)).unwrap();
        assert!(!device_allows("alpha", "shell"), "an expired grant still allowed");
    })
}

/// What the devices view reports for a delegated (joined) device is its
/// enrolment ceiling, never a wider grant-store entry, so the operator sees
/// what enforcement honours.
#[test]
fn devices_view_reports_the_ceiling_for_a_delegated_device() {
    use crate::device_caps::effective_device_caps;
    with_cfg(|dir| {
        write_devices(
            dir,
            json!([
                {"name": "joined", "secret": "s1", "v": 2, "caps": ["transfer", "shell"],
                 "principalKind": "delegated", "principalCeiling": ["transfer"]},
                {"name": "paired", "secret": "s2", "v": 2, "caps": ["transfer", "mount"]}
            ]),
        );
        assert_eq!(effective_device_caps("joined"), vec!["transfer".to_string()]);
        assert_eq!(effective_device_caps("paired"), vec!["transfer".to_string(), "mount".to_string()]);
        assert_eq!(effective_device_caps("ghost"), vec!["transfer".to_string()]);
    })
}

// ---------------------------------------------------------------------------
// Devices store guards
// ---------------------------------------------------------------------------

/// A name is pinned by another device exactly when a record under that name
/// carries a certificate for a different device key. Enrollment uses this to
/// suffix instead of re-anchoring someone else's record.
#[test]
fn name_pinned_by_other_names_only_a_different_key_under_that_name() {
    use crate::devices_store::name_pinned_by_other;
    with_cfg(|dir| {
        let u = user();
        let (a, b) = (rand32(), rand32());
        write_devices(
            dir,
            json!([
                {"name": "laptop", "secret": "s1", "deviceCert": cert(&u, a).to_json()},
                {"name": "phone", "secret": "s2"}
            ]),
        );
        assert!(name_pinned_by_other("laptop", &hex::encode(b)), "a different key took a pinned name");
        assert!(!name_pinned_by_other("laptop", &hex::encode(a)), "the pinned key itself was refused");
        assert!(!name_pinned_by_other("desk", &hex::encode(b)), "an unused name reads as pinned");
    })
}

/// A devices.json that cannot be read is never overwritten: rewriting it from
/// an empty list would erase every pairing and every recorded revoke.
#[test]
fn unreadable_devices_store_is_not_overwritten() {
    with_cfg(|dir| {
        let p = dir.join("devices.json");
        let garbage = vec![0xffu8, 0xfe, 0x00, 0x7b];
        std::fs::write(&p, &garbage).unwrap();
        let r = crate::devices_store::with_devices_mut(|arr| {
            arr.push(json!({"name": "intruder"}));
            Ok(())
        });
        assert!(r.is_err(), "a write proceeded over an unreadable store");
        assert_eq!(std::fs::read(&p).unwrap(), garbage, "the unreadable store was replaced");
    })
}

/// A new device whose name collides (case-insensitively) with existing ones
/// lands on a fresh suffixed name and never on an existing record.
#[test]
fn colliding_new_device_gets_a_fresh_name() {
    let mut arr = vec![
        json!({"name": "Laptop", "secret": "s1"}),
        json!({"name": "laptop-2", "secret": "s2"}),
    ];
    let got = crate::devices_store::upsert_peer_record(&mut arr, "laptop", Some("s3"), None, None, None, None, None);
    assert_eq!(got, "laptop-3");
    assert_eq!(arr.len(), 3);
    assert_eq!(arr[0]["secret"], "s1");
    assert_eq!(arr[1]["secret"], "s2");
}

// ---------------------------------------------------------------------------
// Cap store: the header consulted is the requested resource's
// ---------------------------------------------------------------------------

/// The fleet gate's inputs come from the "self" header even when another
/// resource's header sits first in the store: `own_user` is MY key, and an
/// explicit grant is counted only for the device it names. A same-owner peer
/// is not counted as granted merely for sharing the user key.
#[test]
fn fleet_inputs_read_the_requested_resource_header() {
    let dir = unique_dir("fleet");
    let owner = user();
    let u = owner.public_key_bytes();
    let decoy = user().public_key_bytes();
    let (granted, other) = (rand32(), rand32());
    crate::capability::save_cap_store(&dir, &store_with_decoy(&owner, decoy, granted)).unwrap();

    assert_eq!(
        cap_fleet_inputs(&dir, "self", "shell", Some(&granted), Some(&rand32()), None),
        (Some(u), true)
    );
    assert_eq!(
        cap_fleet_inputs(&dir, "self", "shell", Some(&other), Some(&u), None),
        (Some(u), false),
        "a same-owner device without a grant was counted as granted"
    );
    assert_eq!(cap_fleet_inputs(&unique_dir("empty"), "self", "shell", Some(&granted), None, None), (None, false));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Authorization evaluates against the requested resource's header. Using
/// another resource's header would hand that header's owner the owner
/// shortcut on "self".
#[test]
fn cap_authorize_uses_the_requested_resource_header() {
    let dir = unique_dir("authz");
    let owner = user();
    let decoy = user().public_key_bytes();
    let granted = rand32();
    crate::capability::save_cap_store(&dir, &store_with_decoy(&owner, decoy, granted)).unwrap();
    assert!(
        matches!(cap_authorize(&dir, "self", "shell", Some(&rand32()), Some(&decoy), None), CapOutcome::Denied(_)),
        "another resource's owner was authorized on self"
    );
    assert_eq!(cap_authorize(&dir, "self", "shell", Some(&granted), Some(&rand32()), None), CapOutcome::Authorized);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Saving the cap store reports every certified device that no longer holds
/// a shell grant, so the caller strips its authorized_keys block. An empty
/// report would leave a revoked device's SSH key installed.
#[test]
fn saving_the_cap_store_lists_devices_without_shell() {
    let dir = unique_dir("revoked");
    let owner = user();
    let decoy = user().public_key_bytes();
    let (granted, plain) = (rand32(), rand32());
    let other_user = user();
    write_devices(
        &dir,
        json!([
            {"name": "granted", "deviceCert": cert(&other_user, granted).to_json()},
            {"name": "plain", "deviceCert": cert(&other_user, plain).to_json()},
            {"name": "nocert", "secret": "s"}
        ]),
    );
    let store = store_with_decoy(&owner, decoy, granted);
    let revoked = save_and_list_revoked(&store, &dir).unwrap();
    assert_eq!(revoked, vec!["plain".to_string()]);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Cap store read cache
// ---------------------------------------------------------------------------

fn set_mtime(p: &Path, secs: u64) {
    let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs);
    std::fs::File::options().write(true).open(p).unwrap().set_modified(t).unwrap();
}

fn marker(store: &[Value]) -> String {
    store.first().and_then(|e| e["v"].as_str()).unwrap_or("").to_string()
}

/// The cap-store read cache never serves a store other than the one on disk
/// at that path: a revoke written by another process (same length, new mtime;
/// or new length, same mtime) is seen on the next read, and two config dirs
/// never alias even when their files share an mtime and a length.
#[test]
fn cap_store_cache_never_serves_a_stale_or_foreign_store() {
    let (a, b) = (unique_dir("cache-a"), unique_dir("cache-b"));
    let (pa, pb) = (a.join("caps.json"), b.join("caps.json"));
    let t = 1_700_000_000;
    std::fs::write(&pa, r#"[{"v":"shell"}]"#).unwrap();
    std::fs::write(&pb, r#"[{"v":"mount"}]"#).unwrap();
    set_mtime(&pa, t);
    set_mtime(&pb, t);

    assert_eq!(marker(&load_cap_store(&a)), "shell");
    assert_eq!(marker(&load_cap_store(&b)), "mount", "a different config dir was served from the cache");

    assert_eq!(marker(&load_cap_store(&a)), "shell");
    std::fs::write(&pa, r#"[{"v":"xxxxx"}]"#).unwrap();
    set_mtime(&pa, t + 5);
    assert_eq!(marker(&load_cap_store(&a)), "xxxxx", "a same-length rewrite was not seen");

    std::fs::write(&pa, r#"[{"v":"revoked"}]"#).unwrap();
    set_mtime(&pa, t + 5);
    assert_eq!(marker(&load_cap_store(&a)), "revoked", "a rewrite with the same mtime was not seen");

    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

// ---------------------------------------------------------------------------
// Signed bounded grants
// ---------------------------------------------------------------------------

/// A time-bounded grant to a certified peer lands in the cap store as an
/// owner-signed grant the gate can see, under exactly one "self" header no
/// matter how many grants are issued.
#[test]
fn signed_bounded_grant_reaches_the_gate_under_one_header() {
    use crate::device_caps::issue_signed_bounded_grant;
    with_cfg(|dir| {
        let owner = UserKey::generate(&crate::platform::PlatformKeyStore).unwrap();
        let peer = user();
        let device = rand32();
        write_devices(dir, json!([{"name": "alpha", "secret": "s", "deviceCert": cert(&peer, device).to_json()}]));
        // A header for a DIFFERENT resource is not a "self" header: the grant
        // must still get its own, or it lands where the gate never looks.
        let other = header("route-elsewhere", owner.public_key_bytes()).to_json();
        crate::capability::save_cap_store(dir, &[other]).unwrap();
        let exp = identity::now_secs() + 3600;
        assert!(issue_signed_bounded_grant("alpha", "shell", exp).unwrap());
        assert!(issue_signed_bounded_grant("alpha", "mount", exp).unwrap());
        let store = load_cap_store(dir);
        let headers = store.iter().filter(|e| e["type"] == "cap_header" && e["resource"] == "self").count();
        assert_eq!(headers, 1, "expected exactly one self header, store: {store:?}");
        let (own, granted) = cap_fleet_inputs(dir, "self", "shell", Some(&device), Some(&peer.public_key_bytes()), None);
        assert_eq!(own, Some(owner.public_key_bytes()));
        assert!(granted, "the signed bounded grant is not visible to the gate");
        // A device with no certificate keeps the legacy fallback: nothing signed.
        write_devices(dir, json!([{"name": "bare", "secret": "s"}]));
        assert!(!issue_signed_bounded_grant("bare", "shell", exp).unwrap());
    })
}
