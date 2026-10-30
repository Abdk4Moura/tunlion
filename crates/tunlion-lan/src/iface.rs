//! Interfaces by capability, never by name (spec section 6).
//!
//! The adapter reports every up interface with its flags and addresses. The
//! core decides what to do on each from the flags alone: Ethernet, Wi-Fi,
//! WireGuard, ZeroTier, Tailscale, tunlion's own overlay, USB tethering and a
//! Hyper-V switch are all just "an interface that can (or cannot) multicast".
//! `name` is carried for display in `doctor` and for the user's own opt-out;
//! no decision here reads it.

use std::net::{IpAddr, Ipv4Addr};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    pub up: bool,
    pub loopback: bool,
    pub multicast: bool,
    pub broadcast: bool,
    pub point_to_point: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Addr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Interface {
    /// OS interface index (used to pick the egress for multicast).
    pub index: u32,
    /// Display only (doctor, opt-out matching done by the adapter).
    pub name: String,
    pub flags: Flags,
    pub addrs: Vec<Addr>,
    /// The user turned discovery off on this interface.
    pub opted_out: bool,
    /// The OS classes this network as public (Windows "Public" profile):
    /// nothing is announced or probed on it.
    pub public_network: bool,
}

/// What the interface can carry, from its flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// Multicast and/or broadcast reach the link: beacons go to the group.
    Shared,
    /// Point-to-point or no multicast/broadcast (most VPN tunnels): bounded
    /// unicast probe, neighbor hints, remembered addresses.
    PointToPoint,
    Loopback,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::Shared => "shared",
            Class::PointToPoint => "p2p",
            Class::Loopback => "loopback",
        }
    }
    pub fn parse(s: &str) -> Option<Class> {
        match s {
            "shared" => Some(Class::Shared),
            "p2p" => Some(Class::PointToPoint),
            "loopback" => Some(Class::Loopback),
            _ => None,
        }
    }
}

pub fn classify(f: &Flags) -> Class {
    if f.loopback {
        Class::Loopback
    } else if !f.point_to_point && (f.multicast || f.broadcast) {
        Class::Shared
    } else {
        Class::PointToPoint
    }
}

/// The most hosts a sweep of one prefix may cover: a /22 worth.
pub const SWEEP_MAX_HOSTS: usize = 1024;
/// The shortest IPv4 prefix that is swept at all.
pub const SWEEP_MIN_PREFIX_V4: u8 = 22;

/// The mechanisms used on one interface.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub multicast_v4: bool,
    pub multicast_v6: bool,
    /// Subnet broadcast addresses (one per IPv4 address with a prefix < 31).
    pub broadcast: Vec<Ipv4Addr>,
    /// Unicast probe targets (point-to-point interfaces only).
    pub sweep: Vec<IpAddr>,
}

impl Plan {
    pub fn is_empty(&self) -> bool {
        !self.multicast_v4 && !self.multicast_v6 && self.broadcast.is_empty() && self.sweep.is_empty()
    }
}

fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) }
}

/// Hosts of an IPv4 prefix, without the network and broadcast addresses
/// (except for /31 and /32) and without `own`. Empty when the prefix is
/// shorter than [`SWEEP_MIN_PREFIX_V4`].
pub fn sweep_hosts(net: Ipv4Addr, prefix: u8, own: &[Ipv4Addr]) -> Vec<Ipv4Addr> {
    if prefix < SWEEP_MIN_PREFIX_V4 || prefix > 32 {
        return Vec::new();
    }
    let mask = v4_mask(prefix);
    let base = u32::from(net) & mask;
    let size: u64 = 1u64 << (32 - prefix as u32);
    let (first, last) = if prefix >= 31 { (0, size - 1) } else { (1, size - 2) };
    (first..=last)
        .map(|i| Ipv4Addr::from(base + i as u32))
        .filter(|ip| !own.contains(ip))
        .take(SWEEP_MAX_HOSTS)
        .collect()
}

/// Decide the mechanisms for one interface. `routes` are on-link IPv4 routes
/// the OS has through this interface (`10.8.0.2/32 dev wg0`), used as extra
/// sweep prefixes on point-to-point links where the address itself is a /32.
pub fn plan(i: &Interface, routes: &[(Ipv4Addr, u8)]) -> Plan {
    let mut p = Plan::default();
    if !i.flags.up || i.opted_out || i.public_network {
        return p;
    }
    let class = classify(&i.flags);
    let own: Vec<Ipv4Addr> = i
        .addrs
        .iter()
        .filter_map(|a| match a.ip {
            IpAddr::V4(v) => Some(v),
            _ => None,
        })
        .collect();
    match class {
        Class::Loopback => {}
        Class::Shared => {
            p.multicast_v4 = i.flags.multicast && !own.is_empty();
            p.multicast_v6 = i.flags.multicast && i.addrs.iter().any(|a| a.ip.is_ipv6());
            if i.flags.broadcast {
                for a in &i.addrs {
                    if let IpAddr::V4(v) = a.ip {
                        if a.prefix < 31 {
                            p.broadcast.push(Ipv4Addr::from(u32::from(v) | !v4_mask(a.prefix)));
                        }
                    }
                }
            }
        }
        Class::PointToPoint => {
            let mut prefixes: Vec<(Ipv4Addr, u8)> = i
                .addrs
                .iter()
                .filter_map(|a| match a.ip {
                    IpAddr::V4(v) => Some((v, a.prefix)),
                    _ => None,
                })
                .collect();
            prefixes.extend_from_slice(routes);
            let mut seen = std::collections::BTreeSet::new();
            for (net, len) in prefixes {
                for h in sweep_hosts(net, len, &own) {
                    if seen.len() >= SWEEP_MAX_HOSTS {
                        break;
                    }
                    if seen.insert(h) {
                        p.sweep.push(IpAddr::V4(h));
                    }
                }
            }
        }
    }
    p
}
