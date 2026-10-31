//! The sans-IO discovery engine (spec section 10).
//!
//! The adapter owns sockets and the clock; it calls [`Engine::tick`] a few
//! times a second and [`Engine::on_datagram`] for every packet on the
//! discovery port or on mDNS, and executes the returned [`Action`]s. The
//! engine never blocks, never allocates a socket, and never reads interface
//! names.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::iface::{plan, Interface};
use crate::mdns;
use crate::wire::{self, Beacon, Kind, DISCOVERY_PORT, NONCE_LEN};

/// Presence beacon period on shared interfaces.
pub const BEACON_EVERY_MS: u64 = 30_000;
/// Unicast probe sweep period on point-to-point interfaces.
pub const SWEEP_EVERY_MS: u64 = 300_000;
/// Unicast probes per second, all interfaces together.
pub const PROBES_PER_SEC: u64 = 200;
/// At most one reply per source address in this window.
pub const REPLY_GAP_MS: u64 = 2_000;
/// At most this many replies per second in total.
pub const REPLIES_PER_SEC: u32 = 50;
/// The same (peer, address) is reported at most once in this window.
pub const FOUND_GAP_MS: u64 = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    /// The discovery port, [`DISCOVERY_PORT`].
    Beacon,
    /// mDNS, port 5353.
    Mdns,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum How {
    /// On the discovery port: multicast, broadcast, or a reply to our unicast
    /// query (a point-to-point sweep or a neighbor hint).
    Beacon,
    /// In an mDNS TXT record.
    Mdns,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Send {
    pub chan: Channel,
    pub to: SocketAddr,
    /// Egress interface index for multicast (`IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`).
    pub iface: Option<u32>,
    /// Egress source for IPv4 multicast on that interface.
    pub src_v4: Option<Ipv4Addr>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Send(Send),
    /// A recognized peer announced itself: dial `addr` (its QUIC listener)
    /// with the authenticated handshake. A hint, never trust.
    Found { peer: String, addr: SocketAddr, how: How },
    /// Someone nearby has a pairing code on screen (spec section 7).
    PairingNearby { addr: SocketAddr, id: [u8; 16], label: String },
}

#[derive(Clone, Debug)]
pub struct Known {
    pub name: String,
    pub presence_key: [u8; 32],
}

/// Counters for `doctor`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub beacons_sent: u64,
    pub queries_sent: u64,
    pub probes_sent: u64,
    pub received: u64,
    pub recognized: u64,
    pub replies_sent: u64,
    pub ignored: u64,
}

pub struct Engine {
    me: [u8; 32],
    known: Vec<Known>,
    port: u16,
    next_beacon: u64,
    next_sweep: u64,
    want_query: bool,
    sweep: VecDeque<IpAddr>,
    probe_credit: f64,
    last_tick: u64,
    replied: HashMap<IpAddr, u64>,
    reply_window: (u64, u32),
    found: HashMap<(String, SocketAddr), u64>,
    mdns_label: (u32, String),
    last_mdns_answer: u64,
    pairing: Option<[u8; 16]>,
    pairing_seen: HashMap<(SocketAddr, [u8; 16]), u64>,
    announce: bool,
    pub stats: Stats,
}

fn group_v4() -> Ipv4Addr {
    let g = wire::GROUP_V4;
    Ipv4Addr::new(g[0], g[1], g[2], g[3])
}

fn group_v6() -> Ipv6Addr {
    let g = wire::GROUP_V6;
    Ipv6Addr::new(g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7])
}

fn mdns_v4() -> SocketAddr {
    let g = mdns::MDNS_V4;
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(g[0], g[1], g[2], g[3])), mdns::MDNS_PORT)
}

fn mdns_v6() -> SocketAddr {
    let g = mdns::MDNS_V6;
    SocketAddr::new(IpAddr::V6(Ipv6Addr::new(g[0], g[1], g[2], g[3], g[4], g[5], g[6], g[7])), mdns::MDNS_PORT)
}

impl Engine {
    /// `me` is this device's presence key; `port` is its QUIC listener.
    pub fn new(me: [u8; 32], port: u16) -> Engine {
        Engine {
            me,
            known: Vec::new(),
            port,
            next_beacon: 0,
            next_sweep: 0,
            want_query: true,
            sweep: VecDeque::new(),
            probe_credit: 0.0,
            last_tick: 0,
            replied: HashMap::new(),
            reply_window: (0, 0),
            found: HashMap::new(),
            mdns_label: (u32::MAX, String::new()),
            last_mdns_answer: 0,
            pairing: None,
            pairing_seen: HashMap::new(),
            announce: true,
            stats: Stats::default(),
        }
    }

    /// `false` for a client with no listener (a one-shot command): it sends
    /// queries only, never a presence, pairing or mDNS announcement, and
    /// answers nothing.
    pub fn set_announce(&mut self, on: bool) {
        self.announce = on;
    }

    pub fn set_known(&mut self, known: Vec<Known>) {
        self.known = known;
    }

    pub fn set_port(&mut self, port: u16) {
        self.port = port;
    }

    /// Ask the network now (a command wants a peer that is not linked).
    pub fn query_soon(&mut self) {
        self.want_query = true;
        self.next_sweep = 0;
    }

    /// Announce "ready to pair" with this random id while a code is on screen;
    /// `None` stops it. Nothing else ever sends a pairing beacon.
    pub fn set_pairing(&mut self, id: Option<[u8; 16]>) {
        self.pairing = id;
        self.next_beacon = 0;
    }

    fn nonce(rng: &mut dyn FnMut(&mut [u8])) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        rng(&mut n);
        n
    }

    fn label(&mut self, unix: u64, rng: &mut dyn FnMut(&mut [u8])) -> String {
        let e = wire::epoch(unix);
        if self.mdns_label.0 != e {
            let mut b = [0u8; 8];
            rng(&mut b);
            self.mdns_label = (e, hex::encode(b));
        }
        self.mdns_label.1.clone()
    }

    /// `now_ms` is a monotonic clock, `unix` wall-clock seconds (for epochs).
    /// `routes` are extra on-link IPv4 prefixes per interface index; `hints`
    /// are neighbor-table addresses worth a unicast query.
    pub fn tick(
        &mut self,
        now_ms: u64,
        unix: u64,
        ifaces: &[Interface],
        routes: &[(u32, Ipv4Addr, u8)],
        hints: &[IpAddr],
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Vec<Action> {
        let mut out = Vec::new();
        let plans: Vec<_> = ifaces
            .iter()
            .map(|i| {
                let r: Vec<(Ipv4Addr, u8)> = routes.iter().filter(|(ix, _, _)| *ix == i.index).map(|(_, n, l)| (*n, *l)).collect();
                (i, plan(i, &r))
            })
            .collect();

        if now_ms >= self.next_beacon || self.want_query {
            let query = std::mem::take(&mut self.want_query);
            self.next_beacon = now_ms + BEACON_EVERY_MS;
            let label = self.label(unix, rng);
            for (i, p) in &plans {
                let src_v4 = i.addrs.iter().find_map(|a| match a.ip {
                    IpAddr::V4(v) => Some(v),
                    _ => None,
                });
                let mut dests: Vec<(SocketAddr, Option<u32>, Option<Ipv4Addr>)> = Vec::new();
                if p.multicast_v4 {
                    dests.push((SocketAddr::new(IpAddr::V4(group_v4()), DISCOVERY_PORT), Some(i.index), src_v4));
                }
                if p.multicast_v6 {
                    dests.push((SocketAddr::new(IpAddr::V6(group_v6()), DISCOVERY_PORT), Some(i.index), None));
                }
                for b in &p.broadcast {
                    dests.push((SocketAddr::new(IpAddr::V4(*b), DISCOVERY_PORT), None, None));
                }
                for (to, iface, src) in dests {
                    let mut msgs = Vec::new();
                    if self.announce {
                        msgs.push(wire::presence(&self.me, unix, Self::nonce(rng), self.port).encode());
                    }
                    if let (Some(id), true) = (self.pairing, self.announce) {
                        msgs.push(wire::pairing(id, Self::nonce(rng), self.port).encode());
                    }
                    if query {
                        msgs.push(wire::query(Self::nonce(rng)).encode());
                        self.stats.queries_sent += 1;
                    }
                    for m in msgs {
                        self.stats.beacons_sent += 1;
                        out.push(Action::Send(Send { chan: Channel::Beacon, to, iface, src_v4: src, bytes: m.to_vec() }));
                    }
                }
                if self.announce && (p.multicast_v4 || p.multicast_v6) {
                    let b = wire::presence(&self.me, unix, Self::nonce(rng), self.port).encode();
                    let addrs: Vec<IpAddr> = i.addrs.iter().map(|a| a.ip).filter(crate::record::advertisable).collect();
                    let ann = mdns::announce(&label, &b, self.port, &addrs);
                    if p.multicast_v4 {
                        out.push(Action::Send(Send { chan: Channel::Mdns, to: mdns_v4(), iface: Some(i.index), src_v4, bytes: ann.clone() }));
                        if query {
                            out.push(Action::Send(Send { chan: Channel::Mdns, to: mdns_v4(), iface: Some(i.index), src_v4, bytes: mdns::query() }));
                        }
                    }
                    if p.multicast_v6 {
                        out.push(Action::Send(Send { chan: Channel::Mdns, to: mdns_v6(), iface: Some(i.index), src_v4: None, bytes: ann }));
                    }
                }
            }
        }

        if now_ms >= self.next_sweep {
            self.next_sweep = now_ms + SWEEP_EVERY_MS;
            let mut queued: std::collections::BTreeSet<IpAddr> = self.sweep.iter().copied().collect();
            for (_, p) in &plans {
                for t in &p.sweep {
                    if queued.insert(*t) {
                        self.sweep.push_back(*t);
                    }
                }
            }
            for h in hints {
                if crate::record::advertisable(h) && queued.insert(*h) {
                    self.sweep.push_back(*h);
                }
            }
        }

        let elapsed = now_ms.saturating_sub(self.last_tick).min(1000);
        self.last_tick = now_ms;
        self.probe_credit = (self.probe_credit + elapsed as f64 * PROBES_PER_SEC as f64 / 1000.0).min(PROBES_PER_SEC as f64);
        while self.probe_credit >= 1.0 {
            let Some(t) = self.sweep.pop_front() else { break };
            self.probe_credit -= 1.0;
            self.stats.probes_sent += 1;
            out.push(Action::Send(Send {
                chan: Channel::Beacon,
                to: SocketAddr::new(t, DISCOVERY_PORT),
                iface: None,
                src_v4: None,
                bytes: wire::query(Self::nonce(rng)).encode().to_vec(),
            }));
        }
        out
    }

    fn may_reply(&mut self, now_ms: u64, src: IpAddr) -> bool {
        if self.replied.get(&src).is_some_and(|t| now_ms < t + REPLY_GAP_MS) {
            return false;
        }
        if now_ms >= self.reply_window.0 + 1000 {
            self.reply_window = (now_ms, 0);
        }
        if self.reply_window.1 >= REPLIES_PER_SEC {
            return false;
        }
        self.reply_window.1 += 1;
        if self.replied.len() > 4096 {
            self.replied.retain(|_, t| now_ms < *t + REPLY_GAP_MS);
        }
        self.replied.insert(src, now_ms);
        true
    }

    fn found(&mut self, now_ms: u64, peer: String, addr: SocketAddr, how: How) -> Option<Action> {
        let k = (peer.clone(), addr);
        if self.found.get(&k).is_some_and(|t| now_ms < t + FOUND_GAP_MS) {
            return None;
        }
        if self.found.len() > 1024 {
            self.found.retain(|_, t| now_ms < *t + FOUND_GAP_MS);
        }
        self.found.insert(k, now_ms);
        self.stats.recognized += 1;
        Some(Action::Found { peer, addr, how })
    }

    fn on_beacon(&mut self, now_ms: u64, unix: u64, src: SocketAddr, b: &Beacon, how: How, allowed: bool, rng: &mut dyn FnMut(&mut [u8])) -> Vec<Action> {
        let mut out = Vec::new();
        match b.kind {
            Kind::Query => {
                if self.announce && allowed && how != How::Mdns && self.may_reply(now_ms, src.ip()) {
                    self.stats.replies_sent += 1;
                    let reply = wire::presence(&self.me, unix, Self::nonce(rng), self.port).encode();
                    out.push(Action::Send(Send { chan: Channel::Beacon, to: src, iface: None, src_v4: None, bytes: reply.to_vec() }));
                }
            }
            Kind::Presence => {
                if wire::recognize(b, &[self.me], unix).is_some() {
                    return out; // our own, looped back
                }
                let keys: Vec<[u8; 32]> = self.known.iter().map(|k| k.presence_key).collect();
                match wire::recognize(b, &keys, unix) {
                    Some(ix) => {
                        let peer = self.known[ix].name.clone();
                        if let Some(a) = self.found(now_ms, peer, SocketAddr::new(src.ip(), b.port), how) {
                            out.push(a);
                        }
                    }
                    None => self.stats.ignored += 1,
                }
            }
            Kind::Pairing => {
                if !allowed {
                    self.stats.ignored += 1;
                } else if Some(b.field) != self.pairing {
                    let addr = SocketAddr::new(src.ip(), b.port);
                    let key = (addr, b.field);
                    if self.pairing_seen.get(&key).is_none_or(|t| now_ms >= *t + 2_000) {
                        if self.pairing_seen.len() > 256 {
                            self.pairing_seen.retain(|_, t| now_ms < *t + 10_000);
                        }
                        self.pairing_seen.insert(key, now_ms);
                        out.push(Action::PairingNearby { addr, id: b.field, label: wire::pairing_label(&b.field) });
                    }
                }
            }
        }
        out
    }

    /// `allowed` is false when the packet arrived on an interface where
    /// discovery is off (opted out, or a public network): it is still read,
    /// never answered.
    pub fn on_datagram(
        &mut self,
        now_ms: u64,
        unix: u64,
        chan: Channel,
        src: SocketAddr,
        data: &[u8],
        allowed: bool,
        rng: &mut dyn FnMut(&mut [u8]),
    ) -> Vec<Action> {
        self.stats.received += 1;
        match chan {
            Channel::Beacon => {
                let Some(b) = Beacon::decode(data) else {
                    self.stats.ignored += 1;
                    return Vec::new();
                };
                self.on_beacon(now_ms, unix, src, &b, How::Beacon, allowed, rng)
            }
            Channel::Mdns => match mdns::parse(data) {
                mdns::Parsed::Query => {
                    if !self.announce || !allowed || now_ms < self.last_mdns_answer + 1000 {
                        return Vec::new();
                    }
                    self.last_mdns_answer = now_ms;
                    let label = self.label(unix, rng);
                    let b = wire::presence(&self.me, unix, Self::nonce(rng), self.port).encode();
                    let to = if src.is_ipv4() { mdns_v4() } else { mdns_v6() };
                    vec![Action::Send(Send { chan: Channel::Mdns, to, iface: None, src_v4: None, bytes: mdns::announce(&label, &b, self.port, &[]) })]
                }
                mdns::Parsed::Beacons(bs) => {
                    let mut out = Vec::new();
                    for raw in bs {
                        if let Some(b) = Beacon::decode(&raw) {
                            if b.kind != Kind::Query {
                                out.extend(self.on_beacon(now_ms, unix, src, &b, How::Mdns, allowed, rng));
                            }
                        }
                    }
                    out
                }
                mdns::Parsed::Other => Vec::new(),
            },
        }
    }
}
