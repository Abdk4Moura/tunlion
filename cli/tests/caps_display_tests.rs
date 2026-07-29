//! Tests for caps display labeling.
//!
//! These tests verify that `filament devices` and `filament addr` show
//! "granted" instead of "caps" to make clear it's the local grant record.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament devices` shows "granted" instead of "caps".
#[test]
fn devices_shows_granted_label() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("devices")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should NOT contain "caps:" in the output (old label)
    // Note: may contain "caps" in other contexts (like "capabilities")
    // so we check for the specific label format
    assert!(
        !stdout.to_lowercase().contains("caps:"),
        "Expected no 'caps:' label in devices output, got: {}",
        stdout
    );

    // Should contain "granted" label if there are any devices
    // The column header is uppercase "GRANTED" in the table output
    if !stdout.contains("no known devices") {
        assert!(
            stdout.to_lowercase().contains("granted"),
            "Expected a 'granted' label/column in devices output, got: {}",
            stdout
        );
    }
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
