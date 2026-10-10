// `tunlion reach <peer>`: show the live link to a known device, including route, RTT, and
// whether ssh/pty will be instant. Mirrors `tailscale ping` and elevates it with
// two things Tailscale has no concept of: WARM vs COLD (is a link already held by
// the local `up` daemon, so ssh/pty is instant?) and VERIFIED identity (paired +
// proof-verified, not merely reachable). A warm direct link reports quinn's RTT
// and the real remote IP:port; with no live link it reports the cold establish
// cost (what ssh/pty would actually pay) instead of a fake latency.
//
// Every probe renders through one shape, `probe_line`: `pong via <where> <n> ms`.
// `reach` prints it once; `reach --until-direct` prints it once a second until the
// daemon's link to the peer is no longer relayed.
//
// Color is restrained: one accent (Brand mint = warm), amber only for the relay
// caveat, green for a good pong, red for unreachable, dim for metadata.

use crate::exit_codes::{self, ExitKind};
use crate::ui::{self, Tone};
use anyhow::{bail, Result};
use serde_json::{json, Value};

/// What ONE probe observed. Every field is read off the link the daemon holds
/// (quinn's RTT and 5-tuple, the link's own route label, the selected ICE pair),
/// never inferred: `relayed` in particular is the link's state, so a direct line
/// can never be reported for a path that is actually turning through a relay.
#[derive(Debug, Clone, PartialEq)]
pub enum Probe {
    /// A link the local `up` daemon already holds.
    Warm {
        relayed: bool,
        route: String,
        addr: Option<String>,
        rtt_ms: Option<u64>,
    },
    /// No held link. `--until-direct` watches the daemon's state and never
    /// establishes a link of its own, so this is what a miss looks like.
    NoLink,
}

impl Probe {
    /// Did this probe see a live path with no relay in it?
    pub fn is_direct(&self) -> bool {
        matches!(self, Probe::Warm { relayed: false, .. })
    }
}

/// The one-line result shape, uncoloured. `reach` and `reach --until-direct`
/// both render through this, so the two read identically and one unit test
/// covers both.
pub fn probe_line(p: &Probe) -> String {
    match p {
        Probe::Warm {
            relayed,
            route,
            addr,
            rtt_ms,
        } => {
            let via = match (relayed, addr) {
                (true, Some(a)) => format!("relay({a})"),
                (true, None) => "relay".to_string(),
                (false, Some(a)) => format!("{a} ({route})"),
                (false, None) => route.clone(),
            };
            match rtt_ms {
                Some(ms) => format!("pong via {via} {ms} ms"),
                None => format!("pong via {via}"),
            }
        }
        Probe::NoLink => "no warm link to this peer".to_string(),
    }
}

/// Tone for a probe line: green for a direct pong, amber for a relayed one,
/// red when nothing answered.
fn probe_tone(p: &Probe) -> Tone {
    match p {
        Probe::Warm { relayed: false, .. } => Tone::Ok,
        Probe::Warm { relayed: true, .. } => Tone::Warn,
        Probe::NoLink => Tone::Err,
    }
}

/// Read a warm daemon reply into a `Probe`. `relayed` is the link's own state
/// (its route label, or the ICE pair's relayed flag), not a guess from the
/// address.
fn probe_from_warm(v: &Value) -> Probe {
    let route = v["route"].as_str().unwrap_or("?").to_string();
    let path = &v["path"];
    Probe::Warm {
        relayed: is_relay(&route) || path["relay"].as_bool().unwrap_or(false),
        route,
        addr: path["remote"]
            .as_str()
            .or_else(|| v["remote_addr"].as_str())
            .map(str::to_string),
        rtt_ms: v["rtt_ms"].as_u64(),
    }
}

/// The per-probe `--json` envelope for this verb: one object per probe, so a
/// script watching `--until-direct` reads a line per second and the exit code.
fn probe_envelope(p: &Probe) -> Value {
    let (ok, route, direct, rtt, addr) = match p {
        Probe::Warm { relayed, route, addr, rtt_ms } => {
            (true, json!(route), !*relayed, json!(rtt_ms), json!(addr))
        }
        Probe::NoLink => (false, Value::Null, false, Value::Null, Value::Null),
    };
    json!({
        "ok": ok,
        "verb": "reach",
        "data": { "route": route, "direct": direct, "rtt_ms": rtt, "addr": addr },
    })
}

/// `reach <device>`. Exit 0 when the peer answered (warm link, or a cold probe
/// that established), 6 (`ExitKind::Unreachable`) when it did not, 7 when the
/// tunlion server itself could not be reached. `timeout` bounds the cold probe.
pub async fn ping_cmd(
    server: &str,
    peer: &str,
    count: u32,
    json_out: bool,
    relay: bool,
    timeout: Option<u64>,
) -> Result<()> {
    let count = count.max(1);

    // Warm path: ask a local `up` daemon about its held link. Synchronous and
    // exact (quinn already measured RTT/addr). A miss → None → cold probe below.
    #[cfg(unix)]
    let warm = if relay { None } else { crate::ctl::try_ping(peer).await };
    #[cfg(not(unix))]
    let warm: Option<Value> = None;

    if json_out {
        return ping_json(server, peer, relay, warm, timeout).await;
    }

    ui::say(&format!(
        "{} {}",
        ui::paint(Tone::Dim, "tunlion reach →"),
        ui::paint(Tone::Brand, peer)
    ));

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
            Ok(())
        }
        None => match print_cold(server, peer, relay, timeout).await {
            None => Ok(()),
            // The lines above already said why; exit with the kind, quietly.
            Some(kind) => Err(exit_codes::reported(kind)),
        },
    }
}

/// `reach <device> --until-direct`: print one line per probe and stop as soon as
/// the daemon's link to the peer stops being relayed (exit 0), or at the timeout
/// (exit 5). It WATCHES the local `up` daemon's link rather than establishing one
/// of its own, so a second of waiting costs one unix-socket round trip and the
/// "direct" it reports is the link ssh/pty would actually ride.
pub async fn reach_until_direct(
    peer: &str,
    timeout_s: u64,
    json_out: bool,
    relay: bool,
) -> Result<()> {
    if relay {
        bail!("`--relay` forces the relay path, so it cannot be combined with `--until-direct`");
    }
    // Portable: `ctl::daemon_present` is the adapter (false where the platform
    // has no control socket), so the same error covers "not running" and
    // "cannot run here" without a platform branch in this file.
    if !crate::ctl::daemon_present().await {
        bail!("no local `tunlion up` daemon: `--until-direct` watches the daemon's link to {peer}. Start `tunlion up` first.");
    }
    if !json_out {
        ui::say(&format!(
            "{} {} {}",
            ui::paint(Tone::Dim, "tunlion reach →"),
            ui::paint(Tone::Brand, peer),
            ui::paint(Tone::Dim, &format!("(until direct, {timeout_s}s)"))
        ));
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_s);
    let last = loop {
        let p = match crate::ctl::try_ping(peer).await {
            Some(v) => probe_from_warm(&v),
            None => Probe::NoLink,
        };
        emit_probe(&p, json_out);
        if p.is_direct() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            break p;
        }
        // Ctrl-C ends the watch here, between lines, so no half-written
        // line and no orphaned probe.
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            _ = tokio::signal::ctrl_c() => std::process::exit(130),
        }
    };
    let kind = until_direct_verdict(&last);
    if !json_out {
        let verdict = match kind {
            ExitKind::StillRelayed => format!("still on relay after {timeout_s}s"),
            _ => format!("no link to {peer} after {timeout_s}s (offline, or not running `tunlion up`)"),
        };
        ui::critical(&format!("  {}", ui::paint(Tone::Warn, &verdict)));
    }
    Err(exit_codes::reported(kind))
}

/// How a `--until-direct` watch that timed out ends, from the LAST probe: a
/// link still up but relayed is exit 5 (the documented meaning); no link at
/// all means the peer is gone, which is exit 6 like every other unreachable
/// peer. Both used to be 5, so a script could not tell "keep waiting" from
/// "it is offline".
pub(crate) fn until_direct_verdict(last: &Probe) -> ExitKind {
    match last {
        Probe::Warm { .. } => ExitKind::StillRelayed,
        Probe::NoLink => ExitKind::Unreachable,
    }
}

/// The exit kind for a cold probe that did not establish: the tunlion server
/// when that is what failed, otherwise the peer.
pub(crate) fn cold_failure_kind(error: Option<&str>) -> ExitKind {
    match error.map(exit_codes::classify_text) {
        Some(ExitKind::Network) => ExitKind::Network,
        _ => ExitKind::Unreachable,
    }
}

/// One probe, for whichever audience asked: the envelope on stdout under
/// `--json`, the one-line shape otherwise. A route label is must-see output
/// (docs/ui/OUTPUT.md), so it goes through `ui::critical`.
fn emit_probe(p: &Probe, json_out: bool) {
    if json_out {
        println!("{}", probe_envelope(p));
    } else {
        ui::critical(&format!("  {}", ui::paint(probe_tone(p), &probe_line(p))));
    }
}

/// A relay/TURN path (no direct line of sight), the only case we tint amber.
fn is_relay(route: &str) -> bool {
    matches!(route, "relay" | "relayed")
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

/// One result line for a held (warm) link: the shared `probe_line` shape, then
/// the detail only `reach` shows - the local network INTERFACE, the remote
/// address class, the verified name, and the warm badge. So you can see exactly
/// which route the link takes (e.g. `tailscale0 · CGNAT` means the tailnet,
/// stated as data, not guessed). A relay/TURN path has no line of sight, so it
/// reads "relay" with the encrypted caveat instead of an interface.
fn print_warm_line(v: &Value) {
    let p = probe_from_warm(v);
    let verified = v["verified"].as_str();
    let path = &v["path"];

    let mut line = format!("  {}", ui::paint(probe_tone(&p), &probe_line(&p)));

    if p.is_direct() {
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
    } else {
        line.push_str(&format!("  {}", ui::paint(Tone::Dim, "(encrypted, not direct)")));
    }

    if let Some(name) = verified {
        line.push_str(&format!("   {}", ui::paint(Tone::Ok, &format!("✓ {name}"))));
    }
    line.push_str(&format!("   {}", ui::paint(Tone::Brand, "⚡ warm")));
    ui::critical(&line);
}

fn print_warm_verdict(peer: &str, v: &Value) {
    let route = v["route"].as_str().unwrap_or("?");
    if is_relay(route) {
        ui::say(&format!("  {}", ui::paint(Tone::Warn, "⚠ on relay, no direct path · still end-to-end encrypted")));
        ui::say(&format!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant, over the relay"))));
    } else {
        ui::say(&format!("  {}", ui::paint(Tone::Dim, &format!("─ ssh/pty to {peer} will be instant (warm direct link)"))));
    }
}

/// No live link held locally: measure what a fresh connect would cost (the honest
/// number (that IS what ssh/pty would pay), via the same establish-then-drop
/// probe `tunlion doctor` uses.
async fn print_cold(server: &str, peer: &str, relay: bool, timeout: Option<u64>) -> Option<ExitKind> {
    match crate::l2::establish_probe_within(server, peer, relay, timeout).await {
        Ok(o) if o.established => {
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Warn, "○ cold"),
                ui::paint(Tone::Dim, &format!("no warm link · would connect in ~{}", fmt_ms(o.total_ms)))
            ));
            // "run `tunlion up`" only when no daemon runs: with one up, the
            // advice was to start what was already running. A running daemon
            // just has no link to this peer yet.
            let advice = if crate::daemon_alive().is_some() {
                format!("─ ssh/pty to {peer} would establish a fresh link; the running daemon holds no link to it yet")
            } else {
                format!("─ ssh/pty to {peer} would establish a fresh link; run `tunlion up` to keep it warm")
            };
            ui::say(&format!("  {}", ui::paint(Tone::Dim, &advice)));
            None
        }
        Ok(o) => {
            let phase = o.failed_phase.map(|p| p.label()).unwrap_or("establishing");
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &format!("gave up at the {phase} phase (~{})", fmt_ms(o.total_ms)))
            ));
            let kind = cold_failure_kind(o.error.as_deref());
            if kind == ExitKind::Network {
                ui::say(&format!("  {}", ui::paint(Tone::Dim, exit_codes::NETWORK_LINE)));
            } else {
                ui::say(&format!(
                    "  {}",
                    ui::paint(Tone::Dim, &format!("─ {peer} may be offline, or not running `tunlion up` / `--shell`"))
                ));
            }
            Some(kind)
        }
        Err(e) => {
            ui::critical(&format!(
                "  {}   {}",
                ui::paint(Tone::Err, "✗ unreachable"),
                ui::paint(Tone::Dim, &exit_codes::human_message(&e))
            ));
            ui::debug(&format!("  cause: {e:#}"));
            Some(exit_codes::classify(&e))
        }
    }
}

/// Machine-readable output. ONE shape for both paths, and the same envelope
/// `--until-direct` emits per probe: `ok`, `verb`, and
/// `data: {route, direct, rtt_ms, addr}`. The flat fields scripts already read
/// (`warm`, `route`, `established`, `total_ms`, `failed_phase`, and the warm
/// daemon's own reply fields) are kept alongside.
///
/// `ok` is the ANSWER, not the invocation: true only when the peer was
/// reached. It used to be true for an offline peer (`established: false,
/// ok: true`, exit 0), which is the opposite of what a script asked.
async fn ping_json(
    server: &str,
    peer: &str,
    relay: bool,
    warm: Option<Value>,
    timeout: Option<u64>,
) -> Result<()> {
    let (out, kind) = match warm {
        Some(v) => (reach_json_warm(v), None),
        None => match crate::l2::establish_probe_within(server, peer, relay, timeout).await {
            Ok(o) => {
                let kind = (!o.established).then(|| cold_failure_kind(o.error.as_deref()));
                (
                    reach_json_cold(
                        o.established,
                        o.total_ms,
                        o.failed_phase.map(|p| p.label()),
                        o.error.as_deref(),
                        kind,
                    ),
                    kind,
                )
            }
            Err(e) => {
                let kind = exit_codes::classify(&e);
                let message = exit_codes::human_message(&e);
                (reach_json_cold(false, 0, None, Some(&message), Some(kind)), Some(kind))
            }
        },
    };
    ui::json_out(&out);
    match kind {
        None => Ok(()),
        Some(k) => Err(exit_codes::reported(k)),
    }
}

/// A warm daemon reply, wrapped in the reach envelope. Pure.
pub(crate) fn reach_json_warm(mut v: Value) -> Value {
    let env = probe_envelope(&probe_from_warm(&v));
    v["ok"] = json!(true);
    v["verb"] = json!("reach");
    v["warm"] = json!(true);
    v["data"] = env["data"].clone();
    v
}

/// A cold probe's result in the reach envelope. Pure.
pub(crate) fn reach_json_cold(
    established: bool,
    total_ms: u64,
    failed_phase: Option<&str>,
    error: Option<&str>,
    kind: Option<ExitKind>,
) -> Value {
    let mut v = json!({
        "ok": established,
        "verb": "reach",
        "warm": false,
        "established": established,
        "total_ms": total_ms,
        "failed_phase": failed_phase,
        "data": { "route": Value::Null, "direct": false, "rtt_ms": Value::Null, "addr": Value::Null },
    });
    if let Some(k) = kind.filter(|_| !established) {
        let message = if k == ExitKind::Network {
            exit_codes::NETWORK_LINE.to_string()
        } else {
            error.unwrap_or("the peer did not answer").to_string()
        };
        v["error"] = json!({ "code": k.token(), "exit": k.code(), "message": message });
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warm(relayed: bool, route: &str, addr: Option<&str>, rtt: Option<u64>) -> Probe {
        Probe::Warm { relayed, route: route.into(), addr: addr.map(str::to_string), rtt_ms: rtt }
    }

    #[test]
    fn probe_line_renders_direct_relay_and_the_no_answer_cases() {
        assert_eq!(
            probe_line(&warm(false, "direct-quic", Some("203.0.113.7:41641"), Some(9))),
            "pong via 203.0.113.7:41641 (direct-quic) 9 ms"
        );
        // No address on the link: the route label still carries the answer.
        assert_eq!(probe_line(&warm(false, "holepunched", None, Some(12))), "pong via holepunched 12 ms");
        assert_eq!(
            probe_line(&warm(true, "relay", Some("198.51.100.4:3478"), Some(41))),
            "pong via relay(198.51.100.4:3478) 41 ms"
        );
        // A webrtc link labels its route by interface; `relayed` is the link's
        // own ICE state, and it is what decides the word "relay".
        assert_eq!(probe_line(&warm(true, "direct over eth0", None, None)), "pong via relay");
        assert_eq!(probe_line(&Probe::NoLink), "no warm link to this peer");
    }

    #[test]
    fn until_direct_tells_offline_from_still_relayed() {
        assert_eq!(until_direct_verdict(&warm(true, "relay", None, Some(40))), ExitKind::StillRelayed);
        assert_eq!(until_direct_verdict(&Probe::NoLink), ExitKind::Unreachable);
        assert_eq!(ExitKind::StillRelayed.code(), 5, "the documented --until-direct code");
        assert_ne!(ExitKind::Unreachable.code(), 5, "offline must not look like 'still relayed'");
    }

    #[test]
    fn an_offline_peer_is_not_ok_in_reach_json() {
        let kind = cold_failure_kind(Some("presence: peer never appeared"));
        assert_eq!(kind, ExitKind::Unreachable);
        let v = reach_json_cold(false, 30_000, Some("presence"), Some("peer never appeared"), Some(kind));
        assert_eq!(v["ok"], json!(false), "offline is not ok");
        assert_eq!(v["established"], json!(false));
        assert_eq!(v["failed_phase"], json!("presence"));
        assert_eq!(v["verb"], json!("reach"));
        assert_eq!(v["data"]["direct"], json!(false));
        assert_eq!(v["error"]["exit"], json!(6));
        let up = reach_json_cold(true, 900, None, None, None);
        assert_eq!(up["ok"], json!(true));
        assert!(up.get("error").is_none());
    }

    #[test]
    fn a_dead_server_is_a_network_failure_not_an_offline_peer() {
        let raw = "signaling connect to https://x: failed to lookup address information: Try again";
        assert_eq!(cold_failure_kind(Some(raw)), ExitKind::Network);
        let v = reach_json_cold(false, 0, None, Some(raw), Some(ExitKind::Network));
        assert_eq!(v["error"]["message"], json!(exit_codes::NETWORK_LINE));
    }

    #[test]
    fn warm_and_cold_json_share_the_envelope() {
        let w = reach_json_warm(json!({
            "ok": true, "warm": true, "route": "direct-quic", "rtt_ms": 9,
            "path": { "remote": "203.0.113.7:41641", "relay": false },
        }));
        let c = reach_json_cold(true, 900, None, None, None);
        for v in [&w, &c] {
            assert_eq!(v["verb"], json!("reach"));
            assert!(v["ok"].is_boolean());
            assert!(v["data"].get("direct").is_some());
            assert!(v.get("warm").is_some(), "the flat field scripts read is kept");
        }
        assert_eq!(w["route"], json!("direct-quic"), "warm keeps the daemon's flat route");
        assert_eq!(w["data"]["direct"], json!(true));
    }

    #[test]
    fn only_a_warm_unrelayed_link_counts_as_direct() {
        assert!(warm(false, "direct-quic", None, Some(1)).is_direct());
        assert!(!warm(true, "direct over eth0", None, Some(1)).is_direct());
        assert!(!Probe::NoLink.is_direct());
    }

    #[test]
    fn a_warm_reply_becomes_a_probe_with_the_links_own_facts() {
        let v = json!({
            "ok": true, "warm": true, "direct": true, "route": "direct-quic",
            "remote_addr": "203.0.113.7:41641", "rtt_ms": 9,
            "path": { "remote": "203.0.113.7:41641", "relay": false },
        });
        let p = probe_from_warm(&v);
        assert_eq!(probe_line(&p), "pong via 203.0.113.7:41641 (direct-quic) 9 ms");
        assert_eq!(
            probe_envelope(&p),
            json!({"ok": true, "verb": "reach", "data": {
                "route": "direct-quic", "direct": true, "rtt_ms": 9, "addr": "203.0.113.7:41641"}})
        );
        // A relayed ICE pair is relayed even though its route label is not the
        // word "relay": the flag comes from the path, never from the label.
        let r = json!({ "ok": true, "warm": true, "direct": false, "route": "direct over eth0",
                        "rtt_ms": 41, "path": { "remote": "198.51.100.4:3478", "relay": true } });
        let p = probe_from_warm(&r);
        assert!(!p.is_direct());
        assert_eq!(probe_line(&p), "pong via relay(198.51.100.4:3478) 41 ms");
        assert_eq!(probe_envelope(&p)["data"]["direct"], json!(false));
    }
}
