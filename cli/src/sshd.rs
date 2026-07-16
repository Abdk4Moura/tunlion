use anyhow::{bail, Result};
use std::path::Path;

const SSHD_CONFIG: &str = "/etc/ssh/sshd_config";
const FILAMENT_MARKER: &str = "# Added by filament for L3 overlay access";

/// Configure sshd to listen on the L3 overlay addresses AND localhost.
/// Appends ListenAddress entries for both IPv6 and IPv4 overlay addresses,
/// plus 127.0.0.1 and ::1 so `filament ssh` (which dials localhost via the
/// L2 tunnel) continues to work. Without the localhost entries, sshd's
/// default all-interfaces listen is REPLACED by the explicit overlay entries
/// and localhost becomes unreachable (a regression).
pub fn configure_sshd_overlay(v6: &str, v4: &str) -> Result<()> {
    let config_path = Path::new(SSHD_CONFIG);
    
    if !config_path.exists() {
        bail!("sshd_config not found at {SSHD_CONFIG}");
    }
    
    let content = std::fs::read_to_string(config_path)?;
    
    // Check if already configured (idempotent)
    if content.contains(FILAMENT_MARKER) {
        crate::ui::say("sshd overlay addresses already configured");
        return Ok(());
    }
    
    // Build the entries to append — overlay addresses AND localhost.
    let entries = format!(
        "\n{FILAMENT_MARKER}\nListenAddress {v6}\nListenAddress {v4}\nListenAddress 127.0.0.1\nListenAddress ::1\n"
    );
    
    // Append to config
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(config_path)?;
    std::io::Write::write_all(&mut file, entries.as_bytes())?;
    
    crate::ui::say(&format!("added overlay addresses to sshd_config:"));
    crate::ui::say(&format!("  ListenAddress {v6}"));
    crate::ui::say(&format!("  ListenAddress {v4}"));
    
    // Reload sshd
    reload_sshd()?;
    
    Ok(())
}

/// Reload sshd to pick up configuration changes.
fn reload_sshd() -> Result<()> {
    // daemon-reload first to pick up unit file changes
    let _ = std::process::Command::new("sudo")
        .args(["systemctl", "daemon-reload"])
        .status();
    
    // Then restart sshd
    let status = std::process::Command::new("sudo")
        .args(["systemctl", "restart", "ssh"])
        .status();
    
    match status {
        Ok(s) if s.success() => {
            crate::ui::say("restarted sshd");
            Ok(())
        }
        _ => {
            // Try SIGHUP fallback
            let status = std::process::Command::new("sudo")
                .args(["kill", "-HUP"])
                .arg(get_sshd_pid()?)
                .status();
            
            match status {
                Ok(s) if s.success() => {
                    crate::ui::say("reloaded sshd via SIGHUP");
                    Ok(())
                }
                _ => bail!("failed to restart sshd (try: sudo systemctl restart ssh)"),
            }
        }
    }
}

/// Get the sshd PID.
fn get_sshd_pid() -> Result<String> {
    let output = std::process::Command::new("pidof")
        .arg("sshd")
        .output()?;
    
    let pid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if pid.is_empty() {
        bail!("sshd is not running");
    }
    
    // Take the first PID if multiple
    Ok(pid.split_whitespace().next().unwrap_or(&pid).to_string())
}

/// Check if sshd overlay addresses are configured.
pub fn is_configured() -> bool {
    let Ok(content) = std::fs::read_to_string(SSHD_CONFIG) else {
        return false;
    };
    content.contains(FILAMENT_MARKER)
}
