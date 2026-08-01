//! Tests for `filament devices` status table display.
//!
//! These tests verify that `filament devices` shows aligned, colored output
//! with address and last-seen information.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament devices` shows the final empty-state copy.
#[test]
fn devices_empty_shows_message() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-devices-test-empty"))
        .arg("devices")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("No devices yet."),
        "Expected the empty devices message, got: {}",
        stdout
    );
}

/// Test that `filament devices` shows the tiered listing for legacy records.
#[test]
fn devices_shows_table_headers() {
    let bin = filament_bin();
    let config_dir = std::env::temp_dir().join("filament-devices-test-headers");

    // Create a minimal devices.json with a test device
    std::fs::create_dir_all(&config_dir).unwrap();
    let devices_json = config_dir.join("devices.json");
    std::fs::write(&devices_json, r#"[
        {
            "name": "test-device",
            "secret": "abc123def456",
            "lastSeen": 1700000000,
            "overlayV6": "fd00::1"
        }
    ]"#).unwrap();

    let output = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &config_dir)
        .arg("devices")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("NEEDS REVIEW") && stdout.contains("promote to continue"),
        "Expected the needs-review listing, got: {}",
        stdout
    );

    assert!(
        stdout.contains("filament devices promote test-device"),
        "Expected the promote command hint, got: {}",
        stdout
    );

    // Should contain the device name
    assert!(
        stdout.contains("test-device"),
        "Expected 'test-device' in output, got: {}",
        stdout
    );

    // Should contain the address
    assert!(
        stdout.contains("fd00::1"),
        "Expected address 'fd00::1' in output, got: {}",
        stdout
    );

    assert!(
        stdout.contains("This is a local index; each device's own capability list is authoritative."),
        "Expected the authoritative-list note, got: {}",
        stdout
    );

    // Cleanup
    std::fs::remove_dir_all(&config_dir).ok();
}

/// Test that `filament devices --json` includes new fields.
#[test]
fn devices_json_includes_new_fields() {
    let bin = filament_bin();
    let config_dir = std::env::temp_dir().join("filament-devices-test-json");

    // Create a minimal devices.json with a test device
    std::fs::create_dir_all(&config_dir).unwrap();
    let devices_json = config_dir.join("devices.json");
    std::fs::write(&devices_json, r#"[
        {
            "name": "test-device",
            "secret": "abc123def456",
            "lastSeen": 1700000000,
            "overlayV6": "fd00::1",
            "caps": ["transfer", "shell"]
        }
    ]"#).unwrap();

    let output = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &config_dir)
        .arg("devices")
        .arg("--json")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should be valid JSON
    assert!(
        stdout.trim().starts_with('['),
        "Expected JSON array, got: {}",
        &stdout[..stdout.len().min(200)]
    );

    // Should contain the new fields
    assert!(
        stdout.contains("\"lastSeen\""),
        "Expected 'lastSeen' field in JSON, got: {}",
        stdout
    );
    assert!(
        stdout.contains("\"address\""),
        "Expected 'address' field in JSON, got: {}",
        stdout
    );
    assert!(
        stdout.contains("\"mesh\""),
        "Expected 'mesh' field in JSON, got: {}",
        stdout
    );

    // Should contain the device data
    assert!(
        stdout.contains("test-device"),
        "Expected 'test-device' in JSON, got: {}",
        stdout
    );
    assert!(
        stdout.contains("fd00::1"),
        "Expected address in JSON, got: {}",
        stdout
    );

    // Cleanup
    std::fs::remove_dir_all(&config_dir).ok();
}
