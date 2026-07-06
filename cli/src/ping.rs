// `filament ping <peer>`: show the live link to a known device, including route, RTT, and
// whether ssh/pty will be instant. Mirrors `tailscale ping` and elevates it with
// two things Tailscale has no concept of: WARM vs COLD (is a link already held by
// the local `up` daemon, so ssh/pty is instant?) and VERIFIED identity (paired +
// proof-verified, not merely reachable). A warm direct link reports quinn's RTT
// and the real remote IP:port; with no live link it reports the cold establish
// cost (what ssh/pty would actually pay) instead of a fake latency.
//
// Color is restrained: one accent (Brand mint = warm), amber only for the relay
// caveat, green for a good pong, red for unreachable, dim for metadata.

use crate::ui::{self, Tone};
use anyhow::Result;
use serde_json::{json, Value};

pub async fn ping_cmd(server: &str, peer: &str, count: u32, json_out: bool, relay: bool) -> Result<()> {
    let count = count.max(1);

    // Warm path: ask a local `up` daemon about its held link. Synchronous and
    // exact (quinn already measured RTT/addr). A miss → None → cold probe below.
    #[cfg(unix)]
    let warm = if relay { None } else { crate::ctl::try_ping(peer).await };
    #[cfg(not(unix))]
    let warm: Option<Value> = None;

    if json_out {
        return ping_json(server, peer, relay, warm).await;
    }

    println!("{} {}", ui::paint(Tone::Dim, "filament ping →"), ui::paint(Tone::Brand, peer));

    match warm {
        Some(mut v) => {
            for i in 0..count {
                if i > 0 {
                    tokio::time::sleep(std::time::Duration::from_millis(800)).await;
                    // Re-sample so repeated pings show live RTT drift (quinn keeps
                    // it fresh via the keepalive); keep the prior facts on a miss.
                    #[cfg(unix)]
                    if let Some(nv) = crate::ctl::try_ping(peer).await {
                        v = nv;
                    }
                }
                print_warm_line(&v);
            }
            print_warm_verdict(peer, &v);
        }
        None => print_cold(server, peer, relay).await,
    }
    Ok(())
}

/// A relay/TURN path (no direct line of sight), the only case we tint amber.
fn is_relay(route: &str) -> bool {
    matches!(route, "relay" | "relayed")
}

/// Human route label: collapse the relay aliases to one phrase, pass direct
/// labels through (direct-quic / holepunched / direct / local).
fn fmt_route(route: &str) -> String {
    if is_relay(route) {
        "relay · TURN".to_string()
    } else {
        route.to_string()
    }
}

/// Compact the doctor's address class for the one-line ping ("private (RFC1918)"
/// → "private", "CGNAT (100.64/10)" → "CGNAT"). Doctor keeps the full form.
fn short_class(class: &str) -> &str {
    class.split(" (").next().unwrap_or(class)
}

fn fmt_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        format!("{:.1}s", ms as f64 / 1000.0)
    }
}

/// One result line for a held (warm) link. The path is shown in fine detail but
/// compactly: the local network INTERFACE, the remote-address class, and the
/// concrete addresses, so you can see exactly which route the link takes (e.g.
/// `tailscale0 · CGNAT  100.x ↔ 100.y` means the tailnet, stated as data, not
/// guessed). A relay/TURN path has no line of sight, so it reads "relay · TURN"
/// with the encrypted caveat instead of addresses; direct links also carry a
/// real RTT from quinn.
fn print_warm_line(v: &Value) {
    let route = v["route"].as_str().unwrap_or("?");
    let rtt = v["rtt_ms"].as_u64();
    let verified = v["verified"].as_str();
    let direct = v["direct"].as_bool().unwrap_or(false);
    let path = &v["path"];

    let lead = match rtt {
        Some(ms) => ui::paint(Tone::Ok, &format!("● pong  {:>4}ms", ms)),
        None => ui::paint(Tone::Ok, "● warm       "),
    };
    let mut line = format!("  {lead}");

    let relayed = is_relay(route) || path["relay"].as_bool().unwrap_or(false);
    if relayed {
        line.push_str(&format!("   {}", ui::paint(Tone::Warn, &fmt_route(route))));
        line.push_str(&format!("  {}", ui::paint(Tone::Dim, "(encrypted, not direct)")));
    } else {
        // Interface · class, the heart of "show the path". When the interface
        // is a VPN/tailscale tunnel, tint it mint so the tunnel is obvious.
        if let Some(iface) = path["iface"].as_str() {
            let vpn = path["vpn"].as_bool().unwrap_or(false);
            let iface_tone = if vpn { Tone::Brand } else { Tone::Dim };
            line.push_str(&format!("   {}", ui::paint(iface_tone, iface)));
            if let Some(class) = path["class"].as_str() {
                line.push_str(&format!(" {} {}", ui::paint(Tone::Dim, "·"), ui::paint(Tone::Dim, short_class(class))));
            }
        } else if let Some(class) = path["class"].as_str() {
            line.push_str(&format!("   {}", ui::paint(Tone::Dim, short_class(class))));
        }
        // Addresses: direct-QUIC pins a 5-tuple, so the remote end is the story
        // (→ remote); a webrtc pair is meaningful on both ends (local ↔ remote).
        let local = path["local"].as_str();
        let remote = path["remote"].as_str().or_else(|| v["remote_addr"].as_str());
        if let Some(r) = remote {
            let addrs = match local {
                Some(l) if !direct => format!("{l} \u{2194} {r}"),
                _ => format!("\u{2192}{r}"),
            };
            line.push_str(&format!("  {}", ui::paint(Tone::Dim, &addrs)));
        }
    }

    if let Some(name) = verified {
        line.push_str(&format!("   {}", ui::paint(Tone::Ok, &format!("✓ {name}"))));
    }
    line.push_str(&format!("   {}", ui::paint(Tone::Brand, "⚡ warm")));
    println!("{line}");
}

fn print_warm_verdict(peer: &str, v: &Value) {
    let route = v["route"].as_str().unwrap_or("?");
    if is_relay(route) {
        println!("  {}", ui::paint(Tone::Warn, "⚠ on relay, no direct path · still end-to-end encrypted"));
        println!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant, over the relay")));
    } else {
        println!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant (warm direct link)")));
    }
}

/// No live link held locally: measure what a fresh connect would cost (the honest
/// number (that IS what ssh/pty would pay), via the same establish-then-drop
/// probe `filament doctor` uses.
async fn print_cold(server: &str, peer: &str, relay: bool) {
    match crate::l2::establish_probe(server, peer, relay).await {
        Ok(o) if o.established => {
            println!(
                "  {}   {}",
                ui::paint(Tone::Warn, "○ cold"),
                ui::paint(Tone::Dim, &format!("no warm link · would connect in ~{}", fmt_ms(o.total_ms)))
            );
            println!(
                "  {}",
                ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} would establish a fresh link; run `filament up` to keep it warm"))
            );
        }
        Ok(o) => {
            let phase = o.failed_phase.map(|p| p.label()).unwrap_or("establishing");
            println!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &format!("gave up at the {phase} phase (~{})", fmt_ms(o.total_ms)))
            );
            println!(
                "  {}",
                ui::paint(Tone::Dim, &format!("─ {peer} may be offline, or not running `filament up` / `--shell`"))
            );
        }
        Err(e) => {
            println!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &e.to_string())
            );
        }
    }
}

/// Machine-readable output: the warm facts verbatim, or the cold probe result.
async fn ping_json(server: &str, peer: &str, relay: bool, warm: Option<Value>) -> Result<()> {
    let out = if let Some(v) = warm {
        v
    } else {
        match crate::l2::establish_probe(server, peer, relay).await {
            Ok(o) => json!({
                "ok": true,
                "warm": false,
                "established": o.established,
                "total_ms": o.total_ms,
                "failed_phase": o.failed_phase.map(|p| p.label()),
            }),
            Err(e) => json!({ "ok": false, "warm": false, "error": e.to_string() }),
        }
    };
    println!("{}", serde_json::to_string(&out)?);
    Ok(())
}
