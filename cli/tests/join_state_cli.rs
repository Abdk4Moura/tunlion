//! Join-state CLI gates that need no signaling server.
//!
//! These run on every platform (including the Windows CI runner) because they
//! exercise the local commit boundary the Windows join report broke: the
//! journal an accepted join leaves behind, the certificate/key binding, reset,
//! and the display-vs-mesh split. The cross-machine receipt path lives in
//! `join-state-gates.sh`, which needs a real owner daemon and a backend.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_tunlion")
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tunlion-join-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .env("TUNLION_CONFIG_DIR", dir)
        .args(args)
        .output()
        .expect("run tunlion")
}

fn init(dir: &Path, name: &str) {
    let recovery = dir.join("recovery.txt");
    let out = run(
        dir,
        &[
            "init",
            "--name",
            name,
            "--recovery-file",
            recovery.to_str().unwrap(),
            "--yes",
        ],
    );
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "not JSON ({e}): stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
    })
}

/// `--name-as` is a DISPLAY override. `addr --json` must never claim it
/// renamed the mesh, which is what made `up --name-as dgmfa-repro` look applied
/// while peers still saw `device.mesh`.
#[test]
fn addr_json_separates_display_from_mesh_identity() {
    let dir = scratch("name-as");
    init(&dir, "meshname");
    let out = run(&dir, &["addr", "--json", "--name-as", "dgmfa-repro"]);
    assert!(
        out.status.success(),
        "addr failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v = json(&out);
    assert_eq!(v["displayName"], "dgmfa-repro");
    assert_eq!(v["meshName"], "meshname");
    assert_eq!(
        v["name"], "meshname",
        "the old `name` field stays the mesh label"
    );
    assert_eq!(v["mesh"], "meshname.mesh");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The human readout must not leave the operator guessing which name applies.
#[test]
fn addr_says_name_as_is_display_only() {
    let dir = scratch("name-as-human");
    init(&dir, "meshname");
    let out = run(&dir, &["addr", "--name-as", "dgmfa-repro"]);
    assert!(out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("display only"), "{err}");
    assert!(err.contains("tunlion set name"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A half-join leaves a certificate and a backup/journal; reset must remove all
/// of it, including the `.bak` that used to survive and let a stale store be
/// restored by hand.
#[test]
fn reset_removes_the_half_join_journal_and_backup() {
    let dir = scratch("reset");
    init(&dir, "resetme");
    std::fs::write(dir.join("devices.json.bak"), "[]").unwrap();
    std::fs::write(dir.join("join.pending.json"), "{}").unwrap();
    let out = run(&dir, &["reset", "-y"]);
    assert!(
        out.status.success(),
        "reset failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    for name in ["devices.json.bak", "join.pending.json", "devices.json"] {
        assert!(!dir.join(name).exists(), "reset left {name} behind");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A journal that carries the accepted certificate is the commit point. The
/// next `join` finishes it locally instead of relying on the owner or consuming
/// the invitation again.
#[test]
fn join_finishes_an_accepted_journal_without_the_network() {
    let owner = scratch("journal-owner");
    init(&owner, "owner");
    let joined = scratch("journal-joined");
    // Same overlay key the certificate names; deliberately no owner identity
    // and no server, so a network attempt would fail rather than pass.
    std::fs::copy(
        owner.join("overlay.ed25519"),
        joined.join("overlay.ed25519"),
    )
    .unwrap();
    let cert_record: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(owner.join("identity/device-cert.json")).unwrap(),
    )
    .unwrap();
    let cert = &cert_record["cert"];
    let overlay_pub = {
        let pkcs8 = std::fs::read(joined.join("overlay.ed25519")).unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        use ring::signature::KeyPair;
        hex::encode(key.public_key().as_ref())
    };
    let pending = serde_json::json!({
        "version": 1,
        "devicePub": overlay_pub,
        "ownerName": "owner",
        "startedAt": 1,
        "accepted": {
            "name": "joined",
            "localCert": { "name": "joined", "cert": cert },
            "ownerName": "owner",
            "ownerCert": cert,
            "secret": "11".repeat(32),
            "caps": ["transfer"],
            "scope": 1,
        },
    });
    std::fs::write(
        joined.join("join.pending.json"),
        serde_json::to_string_pretty(&pending).unwrap(),
    )
    .unwrap();
    let out = run(
        &joined,
        &[
            "join",
            "--invite-file",
            joined.join("does-not-exist.txt").to_str().unwrap(),
            "--name",
            "joined",
            "--no-interactive",
        ],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "resume failed: stdout={stdout} stderr={err}"
    );
    assert!(
        !joined.join("join.pending.json").exists(),
        "the completed journal must be removed"
    );
    assert!(
        joined.join("devices.json").exists(),
        "the owner record was not written"
    );
    assert!(
        joined.join("identity/device-cert.json").exists(),
        "the certificate was not written last"
    );
    let _ = std::fs::remove_dir_all(&owner);
    let _ = std::fs::remove_dir_all(&joined);
}

/// A journal whose pinned key is no longer the overlay key cannot be completed:
/// the owner would have certified a key this device cannot present. Fail with
/// the reset/rejoin path, not a generic transport error.
#[test]
fn join_refuses_a_pending_key_that_no_longer_matches() {
    let dir = scratch("pending-mismatch");
    init(&dir, "keygen");
    // Keep the overlay key but make the journal name a different one.
    std::fs::write(
        dir.join("join.pending.json"),
        serde_json::json!({
            "version": 1,
            "devicePub": "22".repeat(32),
            "ownerName": "owner",
            "startedAt": 1,
        })
        .to_string(),
    )
    .unwrap();
    let out = run(
        &dir,
        &[
            "join",
            "--invite-file",
            dir.join("nope.txt").to_str().unwrap(),
            "--no-interactive",
        ],
    );
    assert!(!out.status.success(), "a changed key must not join");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("join started with overlay key"), "{text}");
    assert!(text.contains("tunlion reset"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// `addr` must not print an address for a certificate/key mismatch. It is the
/// readout the Windows report used to prove the entered address differed from
/// the one the owner certified.
#[test]
fn addr_refuses_a_certificate_key_mismatch() {
    let a = scratch("mismatch-a");
    let b = scratch("mismatch-b");
    init(&a, "alpha");
    init(&b, "beta");
    std::fs::copy(b.join("overlay.ed25519"), a.join("overlay.ed25519")).unwrap();
    let out = run(&a, &["addr", "--json"]);
    assert!(!out.status.success(), "addr must refuse the mismatch");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("overlay key"), "{text}");
    assert!(text.contains("reset"), "{text}");
    let _ = std::fs::remove_dir_all(&a);
    let _ = std::fs::remove_dir_all(&b);
}

/// A corrupt certificate must not read as "no identity" and let `addr` print an
/// address the certificate cannot back.
#[test]
fn addr_refuses_a_corrupt_certificate() {
    let dir = scratch("corrupt-cert");
    init(&dir, "alpha");
    std::fs::write(
        dir.join("identity/device-cert.json"),
        r#"{"name":"alpha","cert":{}}"#,
    )
    .unwrap();
    let out = run(&dir, &["addr", "--json"]);
    assert!(
        !out.status.success(),
        "addr must refuse a corrupt certificate"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("certificate record"), "{text}");
    assert!(text.contains("tunlion reset"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// An accepted journal whose certificate was not written is not an address yet.
#[test]
fn addr_refuses_an_accepted_journal_without_a_certificate() {
    let dir = scratch("accepted-journal-addr");
    let owner = scratch("accepted-journal-owner");
    init(&owner, "owner");
    std::fs::copy(owner.join("overlay.ed25519"), dir.join("overlay.ed25519")).unwrap();
    let overlay = {
        let pkcs8 = std::fs::read(dir.join("overlay.ed25519")).unwrap();
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        use ring::signature::KeyPair;
        hex::encode(key.public_key().as_ref())
    };
    std::fs::write(
        dir.join("join.pending.json"),
        serde_json::json!({
            "version": 1,
            "devicePub": overlay,
            "ownerName": "owner",
            "startedAt": 1,
            "accepted": { "name": "joined" },
        })
        .to_string(),
    )
    .unwrap();
    let out = run(&dir, &["addr", "--json"]);
    assert!(
        !out.status.success(),
        "addr must refuse an uncommitted join"
    );
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("still pending locally"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&owner);
}

/// A structurally parseable certificate with an invalid signature must not be
/// presented: the fleet rejects it later, which looks like a transport fault.
#[test]
fn addr_refuses_a_certificate_with_a_bad_signature() {
    let dir = scratch("bad-signature");
    init(&dir, "alpha");
    let path = dir.join("identity/device-cert.json");
    let mut record: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let sig = record["cert"]["sig"].as_str().unwrap().to_string();
    let flipped = if sig.starts_with("00") { "01" } else { "00" };
    record["cert"]["sig"] = serde_json::json!(format!("{flipped}{}", &sig[2..]));
    std::fs::write(&path, serde_json::to_string(&record).unwrap()).unwrap();
    let out = run(&dir, &["addr", "--json"]);
    assert!(!out.status.success(), "addr must refuse a bad signature");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(text.contains("not valid"), "{text}");
    assert!(text.contains("tunlion reset"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Store records need a usable credential: a 32-byte secret or a valid device
/// certificate. Present-but-non-string secrets and name-only records are not
/// "unknown fields" to skip; they are a malformed store.
#[test]
fn addr_refuses_store_records_without_a_usable_credential() {
    let dir = scratch("store-credentials");
    init(&dir, "alpha");
    let store = dir.join("devices.json");
    for (body, needle) in [
        (r#"[{"name":"x"}]"#, "no usable credential"),
        (r#"[{"name":"x","secret":123}]"#, "non-string pair secret"),
        (r#"[{"name":"x","secret":null}]"#, "non-string pair secret"),
        (
            r#"[{"name":"x","deviceCert":{}}]"#,
            "invalid device certificate",
        ),
    ] {
        std::fs::write(&store, body).unwrap();
        let out = run(&dir, &["addr", "--json"]);
        assert!(
            !out.status.success(),
            "addr accepted malformed store {body}"
        );
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains(needle), "{body}: {text}");
        assert!(text.contains("tunlion reset"), "{body}: {text}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}
