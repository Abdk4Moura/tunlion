//! #205/#211 regression test: arming the daemon is a FILE WRITE, not IPC.
//!
//! The armed set used to live in the daemon's process memory, so the only way a
//! mint could tell the daemon "an invitation is outstanding" was a unix socket
//! (absent on Windows, a bind race everywhere). This test proves the mechanism
//! that replaced it: after a mint, `armed.json` holds the key, with no daemon,
//! no socket, and no race. It is platform-independent by construction, which is
//! the point — it runs (and must pass) on all three CI runners for the same
//! reason, where the old IPC path could not.

use std::process::Command;

fn filament_bin() -> &'static str {
    env!("CARGO_BIN_EXE_filament")
}

#[test]
fn mint_writes_the_armed_store_without_a_daemon() {
    let dir = std::env::temp_dir().join(format!("filament-arm-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // init (local, no network): creates the identity the mint signs with.
    let rec = dir.join("recovery.txt");
    let init = Command::new(filament_bin())
        .env("FILAMENT_CONFIG_DIR", &dir)
        .args(["init", "--json", "--name", "armtest", "--recovery-file", rec.to_str().unwrap(), "--yes"])
        .output()
        .expect("init");
    assert!(init.status.success(), "init failed: {}", String::from_utf8_lossy(&init.stderr));

    // Mint a bounded invitation to an owner-only file. This is local: it signs
    // the key, writes armed.json, and writes the token. No daemon, no network.
    let out = dir.join("invite.txt");
    let mint = Command::new(filament_bin())
        .env("FILAMENT_CONFIG_DIR", &dir)
        .args(["add", "--for", "device", "--out", out.to_str().unwrap()])
        .output()
        .expect("mint");
    assert!(mint.status.success(), "mint failed: {}", String::from_utf8_lossy(&mint.stderr));

    // The armed store must hold the key. This is the assertion that used to be
    // "the daemon was reachable over IPC"; now it is "the file was written".
    let armed = dir.join("armed.json");
    let raw = std::fs::read_to_string(&armed).expect("armed.json must exist after a mint");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("armed.json must be valid JSON");
    let arr = v.as_array().expect("armed.json must be an array");
    assert!(!arr.is_empty(), "the armed store must hold the minted key");
    assert!(arr[0]["key_id"].is_string(), "the entry must carry key_id");
    assert!(arr[0]["expires"].is_number(), "the entry must carry expires");

    let _ = std::fs::remove_dir_all(&dir);
}
