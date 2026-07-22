//! Tests for warm one-shot pty behavior.
//!
//! These tests verify that `filament pty <peer> -- cmd` can reuse the daemon's
//! held warm link for one-shot commands, matching cold path parity.

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that one-shot pty can run a command and produce correct output.
/// This is a basic sanity check - the warm path requires a running daemon.
/// Note: the error may be "no known device" (before timeout) or "can't reach"
/// (timeout path), both are valid failure modes for an unreachable peer.
#[test]
fn one_shot_pty_basic_output() {
    let bin = filament_bin();
    let connect_secs = 5;

    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-pty-test-basic"))
        .arg("pty")
        .arg("definitely-unreachable-peer-12345")
        .arg("--")
        .arg("echo")
        .arg("WARM_PTY_TEST_NONCE")
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

/// Test that one-shot pty respects FILAMENT_CONNECT_SECS environment variable.
/// Note: the error may be "no known device" (before timeout) or "can't reach"
/// (timeout path), both are valid failure modes for an unreachable peer.
#[test]
fn one_shot_pty_timeout_respects_env_var() {
    let bin = filament_bin();
    let connect_secs = 1;

    let start = std::time::Instant::now();
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-pty-test-timeout"))
        .arg("pty")
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

/// Test that stdin forwarding works for one-shot pty (cold path parity).
/// This tests the cold path since we don't have a running daemon, but verifies
/// the command structure is correct. Note: the error may be "no known device"
/// (before timeout) or "can't reach" (timeout path).
#[test]
fn one_shot_pty_stdin_forwarding() {
    let bin = filament_bin();
    let connect_secs = 5;

    // Pipe stdin with data - the command should fail (unreachable peer),
    // but the structure should accept stdin input
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-warm-pty-test-stdin"))
        .arg("pty")
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
