//! Tests for man page generation.
//!
//! These tests verify that `filament man` piped output is valid roff
//! that can be used for man page installation.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament man` piped produces valid roff with ".TH" header.
#[test]
fn man_page_is_valid_roff() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("man")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should start with roff header
    assert!(
        stdout.contains(".TH filament"),
        "Expected '.TH filament' in man page output, got: {}",
        &stdout[..stdout.len().min(200)]
    );

    // Should contain standard man sections
    assert!(
        stdout.contains(".SH NAME"),
        "Expected '.SH NAME' section in man page",
    );

    // Should contain SYNOPSIS
    assert!(
        stdout.contains(".SH SYNOPSIS"),
        "Expected '.SH SYNOPSIS' section in man page",
    );
}

/// Test that `filament man` can write to a file (simulating install.sh behavior).
#[test]
fn man_page_can_be_written_to_file() {
    let bin = filament_bin();
    let tmp_dir = std::env::temp_dir().join("filament-man-install-test");
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let man_path = tmp_dir.join("filament.1");

    let output = Command::new(&bin)
        .arg("man")
        .output()
        .expect("failed to execute filament");

    std::fs::write(&man_path, &output.stdout).unwrap();

    // Verify file exists and contains roff
    let content = std::fs::read_to_string(&man_path).unwrap();
    assert!(
        content.contains(".TH filament"),
        "Written man page should contain '.TH filament'",
    );

    // Cleanup
    std::fs::remove_dir_all(&tmp_dir).ok();
}
