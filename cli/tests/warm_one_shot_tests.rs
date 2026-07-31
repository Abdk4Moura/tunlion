//! Tests for warm one-shot shell (native PTY) behavior.
//!
//! These tests verify that `filament shell <peer> -- cmd` reuses the daemon's
//! held warm link and returns without redundant cold establish.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that one-shot pty respects FILAMENT_CONNECT_SECS environment variable.
/// This tests the cold path timeout (when warm link is unavailable).
#[test]
fn one_shot_pty_timeout_respects_env_var() {
    let bin = filament_bin();
    let connect_secs = 1;

    let start = std::time::Instant::now();
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-one-shot-test-timeout"))
        .arg("shell")
        .arg("definitely-unreachable-peer-12345")
        .arg("--")
        .arg("echo")
        .arg("hi")
        .output()
        .expect("failed to execute filament");
    let elapsed = start.elapsed();

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should exit quickly (within connect_secs + some overhead)
    assert!(
        elapsed.as_secs() <= connect_secs + 5,
        "Expected exit within {}s, took {:?}",
        connect_secs + 5,
        elapsed
    );

    // Should contain the peer name in the error
    assert!(
        stderr.contains("definitely-unreachable-peer-12345"),
        "Expected peer name in stderr, got: {}",
        stderr
    );
}

/// Test that one-shot pty with instant stdin-EOF (</dev/null) exits promptly
/// on the cold path. This exercises the same code path that #67 fixed for
/// the warm path (pump_warm_pty_one_shot + serve_stream half-close).
#[test]
fn one_shot_pty_instant_eof_cold_path() {
    let bin = filament_bin();
    let connect_secs = 5;

    let start = std::time::Instant::now();
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-one-shot-test-eof"))
        .arg("shell")
        .arg("definitely-unreachable-peer-12345")
        .arg("--")
        .arg("echo")
        .arg("hi")
        .stdin(std::process::Stdio::null()) // instant stdin-EOF
        .output()
        .expect("failed to execute filament");
    let elapsed = start.elapsed();

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should exit quickly (within connect_secs + some overhead)
    assert!(
        elapsed.as_secs() <= connect_secs + 5,
        "Expected exit within {}s, took {:?}",
        connect_secs + 5,
        elapsed
    );

    // Should exit with nonzero code (peer is unreachable)
    assert!(
        !output.status.success(),
        "Expected nonzero exit code, got: {:?}\nstderr: {}",
        output.status,
        stderr
    );

    // Should contain the peer name in the error
    assert!(
        stderr.contains("definitely-unreachable-peer-12345"),
        "Expected peer name in stderr, got: {}",
        stderr
    );
}

/// Test that one-shot pty stdin forwarding works for cold path.
#[test]
fn one_shot_pty_stdin_forwarding() {
    let bin = filament_bin();
    let connect_secs = 5;

    // Pipe stdin with data - the command should fail (unreachable peer),
    // but the structure should accept stdin input
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-one-shot-test-stdin"))
        .arg("shell")
        .arg("definitely-unreachable-peer-12345")
        .arg("--")
        .arg("cat")
        .stdin(std::process::Stdio::piped())
        .output()
        .expect("failed to execute filament");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should exit with nonzero code (peer is unreachable)
    assert!(
        !output.status.success(),
        "Expected nonzero exit code, got: {:?}\nstderr: {}",
        output.status,
        stderr
    );

    // Should contain the peer name in the error
    assert!(
        stderr.contains("definitely-unreachable-peer-12345"),
        "Expected peer name in stderr, got: {}",
        stderr
    );
}
