//! The local network interfaces, as the `set` menu offers them for the
//! prefer/avoid/only lists. The editors themselves live in `set_menu.rs`.

use std::net::IpAddr;

// ------------------------------------------------------ interface enumeration

pub struct InterfaceInfo {
    pub name: String,
    pub ips: Vec<IpAddr>,
    pub group: String,
}

fn classify_interface(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("wl") || lower.starts_with("wlan") { "wifi" }
    else if lower.starts_with("eth") || lower.starts_with("en") || lower.starts_with("ens") { "ethernet" }
    else if lower.contains("tailscale") || lower == "ts0" { "tailscale" }
    else if lower.contains("docker") || lower.starts_with("br-") { "docker" }
    else if lower == "lo" { "loopback" }
    else { "other" }
}

pub fn enumerate_interfaces() -> Vec<InterfaceInfo> {
    let mut out: Vec<InterfaceInfo> = Vec::new();
    if let Ok(raw) = crate::platform::command("ip").args(["-o", "-4", "addr", "show"]).output() {
        let text = String::from_utf8_lossy(&raw.stdout);
        let mut seen: std::collections::HashMap<String, Vec<IpAddr>> = std::collections::HashMap::new();
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let name = parts.iter().skip(1).find(|s| !s.is_empty()).cloned().unwrap_or("");
            if name.is_empty() || name.contains(':') { continue; }
            if let Some(ip_pos) = parts.iter().position(|p| *p == "inet") {
                if let Some(ip_str) = parts.get(ip_pos + 1) {
                    if let Ok(ip) = ip_str.split('/').next().unwrap_or("").parse::<IpAddr>() {
                        seen.entry(name.to_string()).or_default().push(ip);
                    }
                }
            }
        }
        for (name, ips) in seen {
            let group = classify_interface(&name).to_string();
            out.push(InterfaceInfo { name, ips, group });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}
