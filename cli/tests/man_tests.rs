//! Tests for `filament man` command behavior.
//!
//! These tests verify that `filament man` emits readable help on TTY and
//! roff when piped, and handles unknown pages correctly.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament man` piped emits roff (contains ".TH").
#[test]
fn man_piped_emits_roff() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("man")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain roff control sequences
    assert!(
        stdout.contains(".TH"),
        "Expected '.TH' in piped man output, got: {}",
        &stdout[..stdout.len().min(500)]
    );
}

/// Test that `filament man` with simulated TTY emits readable help.
/// Gated to Linux: `script -qec` is util-linux syntax; macOS/Windows lack it.
#[test]
#[cfg(target_os = "linux")]
fn man_tty_emits_readable_help() {
    let bin = filament_bin();

    // Use script to simulate a TTY
    let output = Command::new("script")
        .arg("-qec")
        .arg(format!("{} man", bin.display()))
        .arg("/dev/null")
        .output()
        .expect("failed to execute script");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain readable help text (not roff)
    assert!(
        stdout.contains("Commands:") || stdout.contains("Usage:"),
        "Expected readable help in TTY man output, got: {}",
        &stdout[..stdout.len().min(500)]
    );

    // Should NOT contain roff control sequences
    assert!(
        !stdout.contains(".TH"),
        "Expected no '.TH' in TTY man output, got roff instead",
    );
}

/// Test that `filament man settings` (unknown page) shows error message.
/// Gated to Linux: `script -qec` is util-linux syntax; macOS/Windows lack it.
#[test]
#[cfg(target_os = "linux")]
fn man_unknown_page_shows_error() {
    let bin = filament_bin();

    // Use script to simulate a TTY (script merges stdout+stderr)
    let output = Command::new("script")
        .arg("-qec")
        .arg(format!("{} man settings", bin.display()))
        .arg("/dev/null")
        .output()
        .expect("failed to execute script");

    let combined = String::from_utf8_lossy(&output.stdout);

    // Should contain error message about unknown page
    assert!(
        combined.contains("no manual page 'settings'"),
        "Expected 'no manual page' error, got: {}",
        combined
    );

    // Should mention available pages
    assert!(
        combined.contains("routing"),
        "Expected 'routing' in available pages, got: {}",
        combined
    );
}

/// Test that `filament man routing` shows routing documentation.
#[test]
fn man_routing_shows_doc() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("man")
        .arg("routing")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Should contain routing documentation
    assert!(
        stdout.contains("filament-routing") || stdout.contains("THE ROUTE"),
        "Expected routing documentation, got: {}",
        &stdout[..stdout.len().min(500)]
    );
}
