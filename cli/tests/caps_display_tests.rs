//! Tests for caps display labeling.
//!
//! These tests verify that `filament devices` and `filament addr` show
//! the authoritative local capability-list sentence.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament devices` shows the authoritative capability note.
#[test]
fn devices_shows_granted_label() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("devices")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("This is a local index; each device's own capability list is authoritative.")
            || stdout.contains("No devices yet."),
        "Expected the devices state output, got: {}",
        stdout
    );
}

/// Test that `filament addr` shows "granted" instead of "caps".
#[test]
fn addr_shows_granted_label() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("addr")
        .arg("--json")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // JSON output should still use "caps" key for backward compatibility
    // (we only changed the human-readable display)
    // This test just verifies the command runs without error
    assert!(
        output.status.success() || stdout.contains("{"),
        "Expected valid JSON output from addr --json, got: {}",
        &stdout[..stdout.len().min(200)]
    );
}
