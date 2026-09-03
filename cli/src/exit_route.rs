//! Exit nodes: accepting a DEFAULT route without cutting your own underlay.
//!
//! A subnet route and a default route look identical in the protocol and are
//! completely different in the kernel. `10.66.0.0/24 dev filament0` is additive.
//! `0.0.0.0/0 dev filament0` captures every packet the machine sends, including
//! the ones carrying the overlay. Install it naively into the main table and the
//! tunnel's own traffic is routed into the tunnel: the link dies, the route is
//! withdrawn, the link returns, and the machine oscillates. The first packet
//! lost is usually the one to the signaling server, so the node cannot even be
//! told to stop.
//!
//! So a default route goes into a SEPARATE table with a rule pointing at it, and
//! the traffic that must not be captured is carved back out by longest prefix
//! INSIDE that table. Carve-outs live in the exit table rather than as
//! higher-priority rules so that tearing the table down removes them too: a
//! carve-out that outlives its default route is a silent hole in the routing.
//!
//! WHAT IS CARVED OUT, and why each is mandatory rather than tidy:
//!   - the exit peer's own underlay address. Routing the tunnel through the
//!     tunnel is the oscillation above.
//!   - the signaling server, or the node cannot renegotiate, cannot be told to
//!     stop, and cannot recover on its own.
//!   - loopback and link-local, which were never ours to capture.
//!   - RFC1918. An exit node is for reaching the internet; silently capturing
//!     the LAN breaks printers and NAS boxes with no symptom other than "the
//!     network broke when I turned this on". A subnet route deliberately
//!     advertised for a LAN prefix still wins inside the table by being longer.
//!
//! DIRECT LINKS ONLY. `Transport::remote_addr` is `None` for a relay
//! (DataChannel) link, whose path is an ICE candidate pair rather than one UDP
//! 5-tuple, and the TURN servers are handed out by the signaling server at
//! runtime rather than configured. With no knowable underlay address there is no
//! safe carve-out, so a default route offered over a relay is REFUSED rather
//! than guessed at. Routing every packet you send through a TURN relay is
//! pathological anyway; an exit node worth using is a direct link.
//!
//! The `ip` invocations themselves live in `platform::policy_route`, so this
//! module carries no per-platform branching at all and the plan below can be
//! tested anywhere without touching a routing table.

use std::net::IpAddr;

/// The dedicated routing table. High enough to stay clear of the distro tables
/// (local 255, main 254, default 253), and named here rather than inlined so
/// setup and teardown cannot disagree about which table they mean.
pub const EXIT_TABLE: &str = "51820";
/// Rule priority. Below the main-table rule's 32766, and in Linux policy routing
/// a lower number is consulted first.
pub const EXIT_RULE_PRIORITY: &str = "5182";

/// Is this prefix a default route, the thing that cannot go in the main table?
pub fn is_default_route(net: IpAddr, len: u8) -> bool {
    len == 0 && net.is_unspecified()
}

/// Prefixes that must keep using the ordinary path while a default route is
/// accepted. `underlay` is every address we must still reach directly: the exit
/// peer's real endpoint and the signaling server.
pub fn carve_outs(underlay: &[IpAddr]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for ip in underlay {
        // IPv4 ONLY, because the route being installed is the IPv4 default. A v6
        // address cannot be routed `via` a v4 gateway (iproute2 rejects it:
        // "inet6 address is expected"), and it does not need to be: an IPv4
        // default route never captures v6 traffic, so there is nothing to
        // exclude. Mixing them made every install fail on a host whose signaling
        // name has AAAA records, which is most of them. A v6 exit route would
        // need ::/0 and its own v6 gateway, and is not implemented.
        if let IpAddr::V4(v) = ip {
            // Host routes, so they beat anything else in the table no matter
            // what the peer advertises.
            out.push(format!("{v}/32"));
        }
    }
    for fixed in ["127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    {
        out.push(fixed.to_string());
    }
    out.sort();
    out.dedup();
    out
}

/// The `ip` argument vectors that install a default route through `dev`, with
/// `underlay` carved back out via the pre-existing gateway.
///
/// Returned as data rather than executed, because this is the only way to test
/// code whose failure mode is destroying the connectivity of the machine running
/// the test.
pub fn install_plan(dev: &str, gateway: Option<&str>, underlay: &[IpAddr]) -> Vec<Vec<String>> {
    let mut plan: Vec<Vec<String>> = Vec::new();
    // Carve-outs FIRST. If this dies halfway, a table holding only exceptions is
    // harmless; a table holding only a default route is a disconnected machine.
    for cidr in carve_outs(underlay) {
        let mut cmd = vec!["route".to_string(), "replace".to_string(), cidr];
        if let Some(gw) = gateway {
            cmd.push("via".to_string());
            cmd.push(gw.to_string());
        }
        cmd.extend(["table".to_string(), EXIT_TABLE.to_string()]);
        plan.push(cmd);
    }
    plan.push(vec![
        "route".into(),
        "replace".into(),
        "0.0.0.0/0".into(),
        "dev".into(),
        dev.to_string(),
        "table".into(),
        EXIT_TABLE.into(),
    ]);
    plan.push(vec![
        "rule".into(),
        "add".into(),
        "from".into(),
        "all".into(),
        "lookup".into(),
        EXIT_TABLE.into(),
        "priority".into(),
        EXIT_RULE_PRIORITY.into(),
    ]);
    plan
}

/// Undo `install_plan`. The RULE goes first: while it exists the table is live,
/// so emptying the table first leaves a rule pointing at nothing, which
/// black-holes rather than falling through to main.
pub fn teardown_plan() -> Vec<Vec<String>> {
    vec![
        vec!["rule".into(), "del".into(), "priority".into(), EXIT_RULE_PRIORITY.into()],
        vec!["route".into(), "flush".into(), "table".into(), EXIT_TABLE.into()],
    ]
}

/// Addresses of the signaling server, resolved now.
///
/// Carved out because a node that loses its path to signaling cannot
/// renegotiate, cannot be told to stop, and cannot recover by itself: exactly
/// the state where a bad exit route becomes unrecoverable rather than merely
/// wrong. Every resolved address is taken, since the host may be multi-homed and
/// which one the next connection uses is not knowable here.
pub fn signaling_addrs() -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    let server = crate::settings::get_str("server", None)
        .unwrap_or_else(|| crate::DEFAULT_SERVER.to_string());
    let host = server
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or_default()
        .to_string();
    if host.is_empty() {
        return Vec::new();
    }
    let with_port = if host.contains(':') { host } else { format!("{host}:443") };
    with_port
        .to_socket_addrs()
        .map(|it| it.map(|sa| sa.ip()).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_a_default_route_in_both_families() {
        assert!(is_default_route("0.0.0.0".parse().unwrap(), 0));
        assert!(is_default_route("::".parse().unwrap(), 0));
        assert!(!is_default_route("10.66.0.0".parse().unwrap(), 24));
        // A /0 that is not the unspecified address is malformed, not a default.
        assert!(!is_default_route("10.0.0.1".parse().unwrap(), 0));
    }

    /// Routing the tunnel through the tunnel is the oscillation this exists to
    /// prevent, so the peer's own address is never optional.
    #[test]
    fn the_peers_underlay_address_is_always_carved_out() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(carve_outs(&[peer]).contains(&"203.0.113.9/32".to_string()));
    }

    /// An IPv6 address cannot be routed via an IPv4 gateway, and an IPv4 default
    /// route never captures v6 traffic anyway. Including them made every install
    /// fail on any host whose signaling name has AAAA records.
    #[test]
    fn v6_addresses_are_not_carved_out_of_a_v4_default_route() {
        let v6: IpAddr = "2606:4700:3030::ac43:8e08".parse().unwrap();
        let v4: IpAddr = "203.0.113.9".parse().unwrap();
        let c = carve_outs(&[v6, v4]);
        assert!(c.contains(&"203.0.113.9/32".to_string()));
        assert!(
            !c.iter().any(|x| x.contains(':')),
            "a v6 carve-out cannot be installed via a v4 gateway"
        );
    }

    #[test]
    fn private_ranges_and_loopback_are_not_captured() {
        let c = carve_outs(&[]);
        for expected in ["127.0.0.0/8", "10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"] {
            assert!(c.contains(&expected.to_string()), "{expected} must stay local");
        }
    }

    /// The difference between an exit node and a disconnected machine.
    #[test]
    fn the_default_route_goes_only_to_the_dedicated_table() {
        let plan = install_plan("filament0", Some("192.0.2.1"), &[]);
        let defaults: Vec<_> = plan.iter().filter(|c| c.contains(&"0.0.0.0/0".to_string())).collect();
        assert_eq!(defaults.len(), 1);
        assert!(defaults[0].contains(&"table".to_string()));
        assert!(defaults[0].contains(&EXIT_TABLE.to_string()));
        assert!(
            !plan.iter().any(|c| c.contains(&"main".to_string())),
            "nothing in this plan may touch the main table"
        );
    }

    /// A half-applied plan must fail safe: the escape hatch before the trap.
    #[test]
    fn carve_outs_are_installed_before_the_default_route() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let plan = install_plan("filament0", Some("192.0.2.1"), &[peer]);
        let default_at = plan.iter().position(|c| c.contains(&"0.0.0.0/0".to_string())).unwrap();
        let peer_at = plan.iter().position(|c| c.contains(&"203.0.113.9/32".to_string())).unwrap();
        assert!(peer_at < default_at);
    }

    /// A rule pointing at an emptied table black-holes instead of falling
    /// through, so the rule has to go first on the way out.
    #[test]
    fn teardown_removes_the_rule_before_emptying_the_table() {
        let plan = teardown_plan();
        assert_eq!(plan[0][0], "rule");
        assert_eq!(plan[0][1], "del");
        assert_eq!(plan[1][0], "route");
        assert_eq!(plan[1][1], "flush");
    }
}
