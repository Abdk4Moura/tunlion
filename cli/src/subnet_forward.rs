//! Router-side plumbing for subnet routes: make this machine actually carry
//! traffic for the prefixes it advertises.
//!
//! MEASURED, NOT ASSUMED. The obvious implementation is `sysctl
//! net.ipv4.ip_forward=1` and stop. That is wrong, and quietly so: on this
//! project's own build box, with forwarding enabled AND a valid return route,
//! forwarding still dropped every packet, because the `FORWARD` chain policy is
//! DROP. Docker and Tailscale both set that, so it is the NORMAL state of any
//! host likely to be a subnet router, not an exotic one. Verified with a pair of
//! network namespaces: rules in, traffic flows; rules out, traffic stops.
//!
//! So the requirements are:
//!   1. `ip_forward` on (necessary, nowhere near sufficient)
//!   2. explicit FORWARD ACCEPT for the overlay->LAN direction
//!   3. conntrack ESTABLISHED,RELATED for the return direction
//!   4. NAT only when the LAN cannot route back to the overlay
//!
//! Linux only for now. macOS (`pf`) and Windows are separate implementations and
//! are refused explicitly rather than silently doing nothing, because a router
//! that says it is routing and is not is the failure this module exists to avoid.

use anyhow::{bail, Context, Result};
use std::process::Command;

/// What we changed, so it can be undone exactly.
#[derive(Debug, Default, Clone)]
pub struct Applied {
    pub rules: Vec<Vec<String>>,
    pub forward_was_enabled: bool,
}

fn run(args: &[&str]) -> Result<String> {
    let out = Command::new(args[0])
        .args(&args[1..])
        .output()
        .with_context(|| format!("running {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "{} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Which interface this host would use to reach `addr`.
///
/// Asked of the kernel rather than guessed from interface names: the operator
/// advertises a PREFIX, and which NIC reaches it is a routing question only the
/// routing table can answer.
pub fn egress_for(addr: &str) -> Result<String> {
    let out = run(&["ip", "route", "get", addr])?;
    parse_egress(&out)
        .ok_or_else(|| anyhow::anyhow!("no route to {addr}; this machine cannot carry that prefix"))
}

/// Pure so the parse is testable without touching the network.
pub fn parse_egress(ip_route_get_output: &str) -> Option<String> {
    let mut it = ip_route_get_output.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            return it.next().map(str::to_string);
        }
    }
    None
}

/// True when `ip_forward` is currently on.
pub fn forwarding_enabled() -> bool {
    std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false)
}

fn rule_exists(rule: &[String]) -> bool {
    let mut args: Vec<&str> = vec!["iptables", "-C"];
    args.extend(rule.iter().map(String::as_str));
    run(&args).is_ok()
}

fn add_rule(rule: &[String]) -> Result<()> {
    if rule_exists(rule) {
        return Ok(()); // idempotent: re-running must not stack duplicates
    }
    let mut args: Vec<&str> = vec!["iptables", "-I"];
    args.extend(rule.iter().map(String::as_str));
    run(&args)?;
    Ok(())
}

fn del_rule(rule: &[String]) {
    let mut args: Vec<&str> = vec!["iptables", "-D"];
    args.extend(rule.iter().map(String::as_str));
    let _ = run(&args);
}

/// Rules needed to forward between the overlay device and one LAN interface.
///
/// Pure, so the exact rule set is inspectable in a test rather than only
/// observable by running iptables.
pub fn rules_for(tun: &str, lan: &str, snat: bool) -> Vec<Vec<String>> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
    let mut rules = vec![
        // Overlay -> LAN, the direction the peer initiates.
        s(&["FORWARD", "-i", tun, "-o", lan, "-j", "ACCEPT"]),
        // LAN -> overlay, replies only. NOT a blanket ACCEPT: the LAN must not
        // be able to originate into the overlay just because we carry routes
        // for it.
        s(&[
            "FORWARD", "-i", lan, "-o", tun, "-m", "conntrack", "--ctstate",
            "RELATED,ESTABLISHED", "-j", "ACCEPT",
        ]),
    ];
    if snat {
        // Masquerade so LAN hosts reply to US rather than to an overlay address
        // they have no route for. Needed only when the LAN cannot route back,
        // which is the common case but not universal, hence a flag.
        rules.push(s(&["POSTROUTING", "-t", "nat", "-o", lan, "-j", "MASQUERADE"]));
    }
    rules
}

/// Make this machine carry `prefixes`. Returns what was changed so it can be undone.
pub fn enable(tun: &str, prefixes: &[String], snat: bool) -> Result<Applied> {
    if !cfg!(target_os = "linux") {
        bail!("subnet-route forwarding is implemented for Linux only so far");
    }
    let mut applied = Applied { forward_was_enabled: forwarding_enabled(), ..Default::default() };
    if !applied.forward_was_enabled {
        run(&["sysctl", "-qw", "net.ipv4.ip_forward=1"]).context("enable ip_forward")?;
    }
    let mut seen_lans: Vec<String> = Vec::new();
    for p in prefixes {
        let addr = p.split('/').next().unwrap_or(p);
        let lan = egress_for(addr)?;
        if lan == tun {
            bail!("{p} routes back over the overlay itself; refusing to forward it into a loop");
        }
        if seen_lans.contains(&lan) {
            continue; // one rule set per interface, not per prefix
        }
        seen_lans.push(lan.clone());
        for r in rules_for(tun, &lan, snat) {
            add_rule(&r)?;
            applied.rules.push(r);
        }
    }
    if let Ok(mut g) = applied_slot().lock() {
        *g = Some(applied.clone());
    }
    Ok(applied)
}

/// What this process applied, so exit can undo it.
///
/// Process-global because the state it mirrors (kernel forwarding, firewall
/// rules) is process-global too. Threading an `Applied` through the daemon's
/// shutdown path would be tidier in the abstract and worse here: the value must
/// survive every exit route, and a handle that only some of them carry is a
/// handle that leaks rules on the others.
static APPLIED: std::sync::OnceLock<std::sync::Mutex<Option<Applied>>> = std::sync::OnceLock::new();

fn applied_slot() -> &'static std::sync::Mutex<Option<Applied>> {
    APPLIED.get_or_init(|| std::sync::Mutex::new(None))
}

/// Undo whatever this process applied. Safe to call when it applied nothing.
///
/// MUST run on the way out. A FORWARD ACCEPT rule that outlives the daemon is a
/// hole nobody can see: the machine keeps forwarding for an overlay that is no
/// longer running, and nothing in `filament status` would ever mention it.
pub fn cleanup() {
    if let Some(a) = applied_slot().lock().ok().and_then(|mut g| g.take()) {
        disable(&a);
    }
}

/// Undo exactly what `enable` did, and nothing else.
pub fn disable(applied: &Applied) {
    for r in &applied.rules {
        del_rule(r);
    }
    if !applied.forward_was_enabled {
        // Only if WE turned it on. Turning off forwarding somebody else needs
        // would break unrelated things on a shared host.
        let _ = run(&["sysctl", "-qw", "net.ipv4.ip_forward=0"]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real-kernel check, opt-in via FILAMENT_NETNS_RIG=1 because it needs root
    /// and mutates the host firewall. Not a unit test pretending to be one: it
    /// builds two network namespaces, proves traffic is BLOCKED first, applies
    /// the real rules, proves it flows, then removes them and proves it is
    /// blocked again. The negative control on both sides is the point, because
    /// "it worked" on a host that was already forwarding proves nothing.
    #[test]
    fn forwarding_rules_actually_forward_on_a_real_kernel() {
        if std::env::var("FILAMENT_NETNS_RIG").as_deref() != Ok("1") {
            return;
        }
        let sh = |c: &str| {
            let _ = std::process::Command::new("sh").arg("-c").arg(c).output();
        };
        let ok = |c: &str| {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(c)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };
        sh("ip netns del rigl 2>/dev/null; ip netns del rigp 2>/dev/null");
        sh("ip link del rig-h 2>/dev/null; ip link del rig-p 2>/dev/null");
        sh("ip netns add rigl && ip link add rig-h type veth peer name rig-l && ip link set rig-l netns rigl");
        sh("ip addr add 10.66.0.1/24 dev rig-h && ip link set rig-h up");
        sh("ip netns exec rigl ip addr add 10.66.0.5/24 dev rig-l && ip netns exec rigl ip link set rig-l up && ip netns exec rigl ip link set lo up");
        sh("ip netns exec rigl ip route add default via 10.66.0.1");
        sh("ip netns add rigp && ip link add rig-p type veth peer name rig-q && ip link set rig-q netns rigp");
        sh("ip addr add 10.99.0.1/24 dev rig-p && ip link set rig-p up");
        sh("ip netns exec rigp ip addr add 10.99.0.9/24 dev rig-q && ip netns exec rigp ip link set rig-q up && ip netns exec rigp ip link set lo up");
        sh("ip netns exec rigp ip route add 10.66.0.0/24 via 10.99.0.1");

        let reach = || ok("ip netns exec rigp ping -c1 -W2 10.66.0.5 >/dev/null 2>&1");
        assert!(!reach(), "negative control: must NOT forward before rules are applied");

        // rig-p stands in for the overlay device; 10.66.0.0/24 is the LAN.
        let applied = enable("rig-p", &["10.66.0.0/24".to_string()], false)
            .expect("enable forwarding");
        assert!(reach(), "rules applied: traffic must flow");

        disable(&applied);
        assert!(!reach(), "rules removed: must be blocked again");

        sh("ip netns del rigl; ip netns del rigp; ip link del rig-h 2>/dev/null; ip link del rig-p 2>/dev/null");
    }

    #[test]
    fn egress_is_parsed_from_the_kernels_answer() {
        assert_eq!(
            parse_egress("10.77.0.5 dev veth-h src 10.77.0.1 uid 0 \n    cache").as_deref(),
            Some("veth-h")
        );
        assert_eq!(
            parse_egress("8.8.8.8 via 10.0.0.1 dev eth0 src 10.0.0.5").as_deref(),
            Some("eth0")
        );
        assert_eq!(parse_egress("nonsense with no device"), None);
    }

    #[test]
    fn rules_cover_both_directions_asymmetrically() {
        let r = rules_for("filament0", "eth0", false);
        assert_eq!(r.len(), 2, "no NAT rule when snat is off");

        // Overlay -> LAN is unconditional; the peer initiates.
        assert!(r[0].contains(&"-i".to_string()) && r[0].contains(&"filament0".to_string()));
        assert!(r[0].contains(&"ACCEPT".to_string()));

        // LAN -> overlay is REPLIES ONLY. If this were a blanket ACCEPT the LAN
        // could originate into the overlay merely because we carry its routes,
        // which is a direction nobody asked us to open.
        assert!(r[1].contains(&"RELATED,ESTABLISHED".to_string()), "return path is conntracked");

        // NAT is opt-in, because it is needed only when the LAN cannot route
        // back, and it hides the peer's real source address when applied.
        let n = rules_for("filament0", "eth0", true);
        assert_eq!(n.len(), 3);
        assert!(n[2].contains(&"MASQUERADE".to_string()));
        assert!(n[2].contains(&"nat".to_string()));
    }
}
