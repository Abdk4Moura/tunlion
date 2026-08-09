//! Tests for HTTP CONNECT proxy and PAC file serving.
//!
//! These tests verify that `filament reach --socks --http-port` serves HTTP
//! CONNECT tunneling and PAC file for browser config. (The old `proxy` command
//! was folded into `reach --socks` in the 0.7.5 command-surface rework.)

use std::process::Command;

/// Get the path to the filament binary built with test-hooks feature.
fn filament_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // remove test binary name
    path.pop(); // remove deps/
    path.push("filament");
    path
}

/// Test that `filament reach --help` shows the --http-port flag.
#[test]
fn proxy_help_shows_http_port_flag() {
    let bin = filament_bin();

    let output = Command::new(&bin)
        .arg("forward")
        .arg("--help")
        .output()
        .expect("failed to execute filament");

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("--http-port"),
        "Expected --http-port flag in help output, got: {}",
        &stdout[..stdout.len().min(500)]
    );
}

/// Test that `filament reach --socks --http-port 0` disables HTTP proxy.
#[test]
fn proxy_http_port_zero_disables() {
    let bin = filament_bin();

    // Start proxy with http-port=0 (disabled), then kill it after a moment
    let mut child = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", std::env::temp_dir().join("filament-proxy-test-disabled"))
        .arg("forward")
        .arg("--socks")
        .arg("localhost:9")
        .arg("--http-port")
        .arg("0")
        .arg("--port")
        .arg("19999")
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("failed to start filament proxy");

    // Wait a moment for startup
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check that it doesn't mention HTTP proxy in output
    let _ = child.kill();
    let output = child.wait_with_output().expect("failed to wait for child");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should NOT contain "HTTP CONNECT proxy" since http_port=0
    assert!(
        !stderr.contains("HTTP CONNECT proxy"),
        "Expected no HTTP proxy message when http_port=0, got: {}",
        stderr
    );
}

/// Test that PAC file from live proxy contains the correct SOCKS5 port.
/// This is a real end-to-end test that starts the proxy and queries it.
#[test]
fn pac_file_returns_correct_socks_port() {
    let bin = filament_bin();
    let socks_port = 1081; // Non-default to catch hardcoded 1080
    let http_port = 18081;
    let config_dir = std::env::temp_dir().join("filament-proxy-pac-test");

    // Start proxy with custom ports
    let mut child = Command::new(&bin)
        .env("FILAMENT_CONFIG_DIR", &config_dir)
        .arg("forward")
        .arg("--socks")
        .arg("localhost:9")
        .arg("--port")
        .arg(socks_port.to_string())
        .arg("--http-port")
        .arg(http_port.to_string())
        .stdin(std::process::Stdio::null())
        .spawn()
        .expect("failed to start filament proxy");

    // Wait for proxy to start
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Query the PAC file endpoint
    let pac_url = format!("http://127.0.0.1:{http_port}/proxy.pac");
    let output = std::process::Command::new("curl")
        .arg("-s")
        .arg(&pac_url)
        .output()
        .expect("failed to run curl");

    let _ = child.kill();
    let _ = child.wait();

    let pac_content = String::from_utf8_lossy(&output.stdout);

    // PAC must contain the ACTUAL configured SOCKS port, not hardcoded 1080
    assert!(
        pac_content.contains(&format!("SOCKS5 127.0.0.1:{socks_port}")),
        "PAC should contain 'SOCKS5 127.0.0.1:{socks_port}' (configured port), got: {}",
        pac_content
    );

    // Must NOT contain hardcoded 1080 (the old bug)
    assert!(
        !pac_content.contains("SOCKS5 127.0.0.1:1080"),
        "PAC should NOT contain hardcoded port 1080, got: {}",
        pac_content
    );

    // Must have valid PAC structure
    assert!(pac_content.contains("FindProxyForURL"), "PAC should contain FindProxyForURL");
    assert!(pac_content.contains(".mesh"), "PAC should handle .mesh domains");
}
