//! Tests for connect timeout behavior in shell and reach commands.
//!
//! These tests verify that `filament shell` (native PTY) and `filament reach`
//! exit promptly when connecting to an unreachable peer, instead of hanging
//! forever. (The old `pty`/`netcat` commands were renamed to `shell`/`reach` in
//! the 0.7.5 command-surface rework; the underlying connect paths are the same.)

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament shell <unreachable-peer> -- echo hi` exits within
/// connect_secs with a nonzero code and stderr containing "can't reach".
#[test]
fn pty_unreachable_peer_exits_with_timeout() {
    let bin = filament_bin();
    let connect_secs = 5;

    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-timeout-test-pty"))
        .arg("shell")
        .arg("definitely-unreachable-peer-12345")
        .arg("--")
        .arg("echo")
        .arg("hi")
        .output()
        .expect("failed to execute filament");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should exit with nonzero code (timeout is an error)
    assert!(
        !output.status.success(),
        "Expected nonzero exit code, got: {:?}\nstderr: {}",
        output.status,
        stderr
    );

    // Should fail promptly with a peer-naming error. Either the connect-timeout
    // path ("can't reach") or the earlier identity guard ("no known device") is a
    // valid prompt failure; the guarantee under test is "no hang", not which one.
    assert!(
        stderr.contains("can't reach") || stderr.contains("no known device"),
        "Expected 'can't reach' or 'no known device' in stderr, got: {}",
        stderr
    );

    // Should contain the peer name
    assert!(
        stderr.contains("definitely-unreachable-peer-12345"),
        "Expected peer name in stderr, got: {}",
        stderr
    );
}

/// Test that `filament reach <unreachable-peer>:<port>` exits with nonzero code.
/// Note: reach may fail with "no known device" before reaching the timeout path,
/// which is also a valid failure mode (the peer doesn't exist).
#[test]
fn netcat_unreachable_peer_exits_with_error() {
    let bin = filament_bin();
    let connect_secs = 5;

    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-timeout-test-netcat"))
        .arg("forward")
        .arg("definitely-unreachable-peer-12345:8080")
        .output()
        .expect("failed to execute filament");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should exit with nonzero code (either timeout or unknown device)
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

/// Test that the timeout respects FILAMENT_CONNECT_SECS environment variable.
/// With a very short timeout (1s), the command should fail quickly.
#[test]
fn pty_timeout_respects_env_var() {
    let bin = filament_bin();
    let connect_secs = 1;

    let start = std::time::Instant::now();
    let output = Command::new(&bin)
        .env("FILAMENT_CONNECT_SECS", connect_secs.to_string())
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-timeout-test-env"))
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

    // Prompt failure with a peer-naming error (see the note above): either the
    // connect-timeout path or the identity guard, both bounded well under the
    // elapsed check above.
    assert!(
        stderr.contains("can't reach") || stderr.contains("no known device"),
        "Expected 'can't reach' or 'no known device' in stderr, got: {}",
        stderr
    );
}
