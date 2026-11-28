//! CLI-level honesty for the L3 state.
//!
//! `expose` used to write expose.json and print success with no endpoint at all,
//! while `addr` printed a key-derived address as if it were routable. These use
//! the real binary in a hermetic config dir: no daemon, no TUN, no network.

use std::process::Command;

fn temp_config(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tunlion-l3-cli-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn run(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_tunlion"))
        .args(args)
        .env("TUNLION_CONFIG_DIR", dir)
        // Never let a developer's real daemon/config answer.
        .env("TUNLION_NO_WARM_REUSE", "1")
        .output()
        .expect("run tunlion")
}

#[test]
fn expose_without_an_endpoint_fails_nonzero_and_says_it_is_not_bound() {
    let dir = temp_config("expose");
    let out = run(&dir, &["expose", "9110"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let both = format!("{stdout}\n{stderr}");
    assert!(
        !out.status.success(),
        "expose must not report success with no live endpoint; stdout={stdout} stderr={stderr}"
    );
    assert!(
        stderr.contains("NOT bound") || stderr.contains("not bound"),
        "the failure must say the port is not bound on STDERR: {stderr}"
    );
    // It may save the request for a later daemon, but it must not claim a bind.
    assert!(
        !stdout.contains("[bound on the overlay"),
        "must never print a bound success line: {stdout}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn addr_json_reports_l3_down_and_identity_only() {
    let dir = temp_config("addr");
    let out = run(&dir, &["addr", "--json"]);
    assert!(
        out.status.success(),
        "addr is a read and stays exit 0: {:?}",
        out
    );
    let text = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(text.trim()).expect("addr --json object");
    assert_eq!(v["verb"], "addr");
    assert!(
        v["overlayV6"]
            .as_str()
            .is_some_and(|a| a.starts_with("fdf1:1af7:c30d:"))
    );
    assert_eq!(
        v["l3"]["state"], "down",
        "no daemon is a live endpoint: {v}"
    );
    assert_eq!(v["l3"]["mode"], "none");
    assert!(
        v["l3"]["reason"].as_str().is_some_and(|r| !r.is_empty()),
        "a down state must carry a reason: {v}"
    );

    // The human form says the address is identity-only, so a person reading it
    // is not misled either.
    let human = run(&dir, &["addr"]);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&human.stdout),
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(human.status.success());
    assert!(
        text.contains("identity-only"),
        "text addr must mark the no-endpoint case: {text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
