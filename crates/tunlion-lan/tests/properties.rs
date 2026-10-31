//! Properties the spec promises, checked on the core.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use tunlion_lan::engine::{Action, Channel, Engine, Known};
use tunlion_lan::iface::{self, Addr, Class, Flags, Interface};
use tunlion_lan::record::{self, Hello, HelloAddr, Record, RouteOwner};
use tunlion_lan::wire::{self, BEACON_LEN, DISCOVERY_PORT};

/// Deterministic xorshift so the tests are reproducible.
struct Rng(u64);
impl Rng {
    fn fill(&mut self, b: &mut [u8]) {
        for x in b {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *x = self.0 as u8;
        }
    }
}

fn ethernet(name: &str, ip: [u8; 4], prefix: u8) -> Interface {
    Interface {
        index: 2,
        name: name.into(),
        flags: Flags { up: true, multicast: true, broadcast: true, ..Flags::default() },
        addrs: vec![Addr { ip: IpAddr::V4(Ipv4Addr::from(ip)), prefix }],
        opted_out: false,
        public_network: false,
    }
}

fn tunnel(name: &str, ip: [u8; 4], prefix: u8, multicast: bool) -> Interface {
    Interface {
        index: 7,
        name: name.into(),
        flags: Flags { up: true, point_to_point: true, multicast, ..Flags::default() },
        addrs: vec![Addr { ip: IpAddr::V4(Ipv4Addr::from(ip)), prefix }],
        opted_out: false,
        public_network: false,
    }
}

fn sent(actions: &[Action]) -> Vec<(Channel, SocketAddr, Vec<u8>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            Action::Send(s) => Some((s.chan, s.to, s.bytes.clone())),
            _ => None,
        })
        .collect()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// A stranger learns nothing identifying: across many beacons and epochs no
/// beacon or mDNS packet carries the key, any 4-byte window of it or of the
/// device name, and apart from the fixed header and the port no two beacons
/// share any 4-byte window at the same offset (nothing stable to link on).
#[test]
fn beacons_carry_nothing_identifying_across_epochs() {
    let pk = [0x5au8; 32];
    let name = b"abdulkabirs-laptop";
    let mut e = Engine::new(pk, wire::DEFAULT_LISTEN_PORT);
    let mut rng = Rng(7);
    let ifs = vec![ethernet("eth0", [192, 168, 1, 20], 24)];
    let mut beacons: Vec<[u8; BEACON_LEN]> = Vec::new();
    let mut mdns_packets: Vec<Vec<u8>> = Vec::new();
    for round in 0..40u64 {
        let now = round * 31_000;
        let unix = 1_800_000_000 + round * 300; // crosses 20 epochs
        for (chan, _, bytes) in sent(&e.tick(now, unix, &ifs, &[], &[], &mut |b| rng.fill(b))) {
            match chan {
                Channel::Beacon => beacons.push(bytes.as_slice().try_into().unwrap()),
                Channel::Mdns => mdns_packets.push(bytes),
            }
        }
    }
    assert!(beacons.len() >= 40, "engine sent {} beacons", beacons.len());
    for b in &beacons {
        for w in pk.windows(4) {
            assert!(!contains(b, w), "beacon carries part of the key");
        }
        for w in name.windows(4) {
            assert!(!contains(b, w), "beacon carries part of the name");
        }
    }
    for p in &mdns_packets {
        for w in name.windows(4) {
            assert!(!contains(p, w), "mDNS carries part of the name");
        }
        for w in pk.windows(4) {
            assert!(!contains(p, w), "mDNS carries part of the key");
        }
    }
    // Variable part: bytes 4..32 (nonce and tag or zero field). Presence and
    // query beacons differ in kind; compare presence beacons among themselves.
    let presence: Vec<_> = beacons.iter().filter(|b| b[3] == 1).collect();
    for (i, a) in presence.iter().enumerate() {
        for b in presence.iter().skip(i + 1) {
            for off in (4..32).step_by(4) {
                assert_ne!(a[off..off + 4], b[off..off + 4], "two beacons share bytes {off}..{} ", off + 4);
            }
        }
    }
    // mDNS instance labels change every epoch.
    let labels: std::collections::BTreeSet<Vec<u8>> = mdns_packets
        .iter()
        .filter(|p| p[2] == 0x84)
        .map(|p| p[12 + 1 + "_tunlion".len() + 1 + "_udp".len() + 1 + "local".len() + 1 + 10..][..17].to_vec())
        .collect();
    assert!(labels.len() >= 10, "instance labels did not rotate: {} distinct", labels.len());
}

/// A listener holding no key of ours recognizes nothing, and one holding it
/// recognizes us.
#[test]
fn only_key_holders_recognize() {
    let pk = [9u8; 32];
    let mut rng = Rng(11);
    let mut nonce = [0u8; 12];
    for i in 0..500u64 {
        rng.fill(&mut nonce);
        let unix = 1_800_000_000 + i * 97;
        let b = wire::presence(&pk, unix, nonce, 47821);
        let mut other = [0u8; 32];
        rng.fill(&mut other);
        assert_eq!(wire::recognize(&b, &[other], unix), None);
        assert_eq!(wire::recognize(&b, &[other, pk], unix), Some(1));
    }
}

/// Interfaces are classed by flags only: the same flags under any name give
/// the same plan. tunlion's own TUN, WireGuard, ZeroTier and an unnamed
/// adapter are not special.
#[test]
fn plans_ignore_names() {
    for name in ["eth0", "wlan0", "zt7nnig26", "Ethernet 3", "vEthernet (WSL)", "en5", "x"] {
        let p = iface::plan(&ethernet(name, [192, 168, 7, 3], 24), &[]);
        assert!(p.multicast_v4);
        assert_eq!(p.broadcast, vec![Ipv4Addr::new(192, 168, 7, 255)]);
        assert!(p.sweep.is_empty());
    }
    let base = iface::plan(&tunnel("wg0", [10, 8, 0, 1], 24, false), &[]);
    for name in ["tunlion0", "utun4", "tailscale0", "nebula1", "tun0", "wg0"] {
        assert_eq!(iface::plan(&tunnel(name, [10, 8, 0, 1], 24, false), &[]), base);
        // A TUN that reports MULTICAST but is point-to-point is still swept.
        assert_eq!(iface::classify(&tunnel(name, [10, 8, 0, 1], 24, true).flags), Class::PointToPoint);
    }
    assert_eq!(base.sweep.len(), 253);
    assert!(!base.multicast_v4);
}

#[test]
fn p2p_slash32_uses_routes_and_caps_sweeps() {
    let wg = tunnel("wg0", [10, 8, 0, 1], 32, false);
    assert!(iface::plan(&wg, &[]).sweep.is_empty());
    let p = iface::plan(&wg, &[(Ipv4Addr::new(10, 8, 0, 2), 32)]);
    assert_eq!(p.sweep, vec![IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))]);
    let wide = iface::plan(&tunnel("t", [10, 0, 0, 1], 16, false), &[(Ipv4Addr::new(10, 1, 0, 0), 22), (Ipv4Addr::new(10, 2, 0, 0), 22)]);
    assert_eq!(wide.sweep.len(), iface::SWEEP_MAX_HOSTS, "a sweep never exceeds a /22 worth of hosts");
}

#[test]
fn opt_out_and_public_networks_send_nothing() {
    let mut e = ethernet("eth0", [192, 168, 1, 2], 24);
    e.opted_out = true;
    assert!(iface::plan(&e, &[]).is_empty());
    let mut e = ethernet("Wi-Fi", [10, 0, 0, 2], 24);
    e.public_network = true;
    assert!(iface::plan(&e, &[]).is_empty());
    let mut eng = Engine::new([1; 32], 47821);
    let mut rng = Rng(3);
    assert!(sent(&eng.tick(0, 1_800_000_000, &[e], &[], &[], &mut |b| rng.fill(b))).is_empty());
}

/// Queries are answered with a reply no larger than the query, rate limited
/// per source and never on an interface where discovery is off.
#[test]
fn replies_are_bounded() {
    let mut e = Engine::new([2; 32], 47821);
    let mut rng = Rng(5);
    let q = wire::query([3; 12]).encode();
    let src: SocketAddr = "10.8.0.2:47820".parse().unwrap();
    let r = sent(&e.on_datagram(1000, 1_800_000_000, Channel::Beacon, src, &q, true, &mut |b| rng.fill(b)));
    assert_eq!(r.len(), 1);
    assert!(r[0].2.len() <= q.len());
    assert_eq!(r[0].1, src);
    assert!(sent(&e.on_datagram(1500, 1_800_000_000, Channel::Beacon, src, &q, true, &mut |b| rng.fill(b))).is_empty());
    let other: SocketAddr = "10.8.0.3:47820".parse().unwrap();
    assert!(sent(&e.on_datagram(1500, 1_800_000_000, Channel::Beacon, other, &q, false, &mut |b| rng.fill(b))).is_empty());
    let mut replies = 0;
    for i in 0..500u32 {
        let s = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)), DISCOVERY_PORT);
        replies += sent(&e.on_datagram(5000, 1_800_000_000, Channel::Beacon, s, &q, true, &mut |b| rng.fill(b))).len();
    }
    assert!(replies <= 50, "{replies} replies in one second");
}

#[test]
fn recognizes_known_ignores_self_and_dedupes() {
    let me = [1u8; 32];
    let laptop = [2u8; 32];
    let mut e = Engine::new(me, 47821);
    e.set_known(vec![Known { name: "laptop".into(), presence_key: laptop }]);
    let mut rng = Rng(9);
    let unix = 1_800_000_000;
    let src: SocketAddr = "192.168.1.9:47820".parse().unwrap();
    let own = wire::presence(&me, unix, [4; 12], 47821).encode();
    assert!(e.on_datagram(0, unix, Channel::Beacon, src, &own, true, &mut |b| rng.fill(b)).is_empty());
    let theirs = wire::presence(&laptop, unix, [5; 12], 50000).encode();
    let a = e.on_datagram(0, unix, Channel::Beacon, src, &theirs, true, &mut |b| rng.fill(b));
    assert_eq!(a, vec![Action::Found { peer: "laptop".into(), addr: "192.168.1.9:50000".parse().unwrap(), how: tunlion_lan::engine::How::Beacon }]);
    let again = wire::presence(&laptop, unix, [6; 12], 50000).encode();
    assert!(e.on_datagram(100, unix, Channel::Beacon, src, &again, true, &mut |b| rng.fill(b)).is_empty());
}

#[test]
fn pairing_beacons_only_while_a_code_is_shown() {
    let mut e = Engine::new([1; 32], 47821);
    let mut rng = Rng(13);
    let ifs = vec![ethernet("eth0", [192, 168, 1, 20], 24)];
    let kinds = |a: &[Action]| -> Vec<u8> { sent(a).iter().filter(|s| s.0 == Channel::Beacon).map(|s| s.2[3]).collect() };
    assert!(!kinds(&e.tick(0, 1_800_000_000, &ifs, &[], &[], &mut |b| rng.fill(b))).contains(&2));
    e.set_pairing(Some([8; 16]));
    assert!(kinds(&e.tick(1, 1_800_000_000, &ifs, &[], &[], &mut |b| rng.fill(b))).contains(&2));
    e.set_pairing(None);
    assert!(!kinds(&e.tick(2, 1_800_000_000, &ifs, &[], &[], &mut |b| rng.fill(b))).contains(&2));
}

struct Overlay;
impl RouteOwner for Overlay {
    fn carried_by(&self, ip: IpAddr) -> Option<String> {
        match ip.to_string().as_str() {
            "fdf1:1af7:c30d::a" => Some("laptop".into()),
            "fdf1:1af7:c30d::b" => Some("desktop".into()),
            _ => None,
        }
    }
}

/// The one guard: an address carried by the link to X is never used to reach
/// X; an overlay address carried by a link to someone else is a real path.
#[test]
fn circular_routes_are_dropped_by_ownership_not_name() {
    let cands: Vec<SocketAddr> = vec![
        "[fdf1:1af7:c30d::a]:47821".parse().unwrap(),
        "[fdf1:1af7:c30d::b]:47821".parse().unwrap(),
        "192.168.1.9:47821".parse().unwrap(),
    ];
    let to_laptop = record::not_circular("laptop", cands.clone(), &Overlay);
    assert_eq!(to_laptop, vec![cands[1], cands[2]]);
    let to_desktop = record::not_circular("Desktop", cands.clone(), &Overlay);
    assert_eq!(to_desktop, vec![cands[0], cands[2]]);
    assert_eq!(record::not_circular("laptop", cands.clone(), &record::NoOverlay), cands);
}

#[test]
fn remembered_addresses_rank_and_expire() {
    let mut r = Record::default();
    let hello = Hello {
        presence_key: [3; 32],
        port: 47821,
        addrs: vec![
            HelloAddr { ip: "192.168.1.9".parse().unwrap(), class: Class::Shared },
            HelloAddr { ip: "10.8.0.2".parse().unwrap(), class: Class::PointToPoint },
        ],
    };
    r.learn(&hello, 1000);
    r.mark_ok("10.8.0.2:47821".parse().unwrap(), 2000);
    assert_eq!(r.dial_order()[0], "10.8.0.2:47821".parse::<SocketAddr>().unwrap());
    let back = Record::from_json(&r.to_json()).unwrap();
    assert_eq!(back, r);
    // Past the unused address's 30 days (learned at 1000) but within the
    // used one's (ok at 2000).
    r.prune(1000 + record::FORGET_SECS + 1);
    assert_eq!(r.addrs.len(), 1, "the unused address is forgotten, the used one kept");
    for i in 0..40u8 {
        r.learn(&Hello { presence_key: [3; 32], port: 47821, addrs: vec![HelloAddr { ip: IpAddr::V4(Ipv4Addr::new(10, 9, 0, i)), class: Class::Shared }] }, 5000 + i as u64);
    }
    assert_eq!(r.addrs.len(), record::MAX_ADDRS);
    assert!(r.dial_order().len() <= record::MAX_DIAL);
}
