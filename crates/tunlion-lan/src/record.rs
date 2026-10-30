//! The hello exchanged over an authenticated link, and the remembered-address
//! record built from it (spec sections 8 and 9).
//!
//! This is the generic mechanism that makes any overlay or private network
//! work without knowing what it is: whenever two peers link, each tells the
//! other every address it has on every interface; each keeps those, and later
//! dials them directly when the server is unreachable.

use std::net::{IpAddr, SocketAddr};

use serde_json::{json, Value};

use crate::iface::Class;

/// Addresses kept per peer.
pub const MAX_ADDRS: usize = 16;
/// Addresses dialled per attempt.
pub const MAX_DIAL: usize = 8;
/// Forget an address not seen or used for this long.
pub const FORGET_SECS: u64 = 30 * 24 * 3600;

pub const HELLO_TYPE: &str = "lan-hello";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloAddr {
    pub ip: IpAddr,
    pub class: Class,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub presence_key: [u8; 32],
    pub port: u16,
    pub addrs: Vec<HelloAddr>,
}

/// An address worth telling a peer about: unicast, not loopback, and dialable
/// without a scope id (IPv6 link-local needs one, so it is left out).
pub fn advertisable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !v.is_loopback() && !v.is_unspecified() && !v.is_multicast() && !v.is_broadcast(),
        IpAddr::V6(v) => {
            !v.is_loopback() && !v.is_unspecified() && !v.is_multicast() && (v.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

impl Hello {
    pub fn to_json(&self) -> Value {
        json!({
            "type": HELLO_TYPE,
            "v": 1,
            "pk": hex::encode(self.presence_key),
            "port": self.port,
            "addrs": self.addrs.iter().map(|a| json!({"ip": a.ip.to_string(), "class": a.class.as_str()})).collect::<Vec<_>>(),
        })
    }

    /// Lenient on unknown fields and unknown classes (skipped), strict on the
    /// key and port: a hello without them is not a hello.
    pub fn from_json(v: &Value) -> Option<Hello> {
        if v["type"] != HELLO_TYPE || v["v"].as_u64() != Some(1) {
            return None;
        }
        let pk = hex::decode(v["pk"].as_str()?).ok()?;
        let presence_key: [u8; 32] = pk.as_slice().try_into().ok()?;
        let port = u16::try_from(v["port"].as_u64()?).ok().filter(|p| *p != 0)?;
        let addrs = v["addrs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        let ip: IpAddr = e["ip"].as_str()?.parse().ok()?;
                        let class = Class::parse(e["class"].as_str()?)?;
                        advertisable(&ip).then_some(HelloAddr { ip, class })
                    })
                    .take(MAX_ADDRS * 2)
                    .collect()
            })
            .unwrap_or_default();
        Some(Hello { presence_key, port, addrs })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Remembered {
    pub ip: IpAddr,
    pub port: u16,
    pub class: Class,
    /// Last time the peer told us about this address (unix seconds).
    pub seen: u64,
    /// Last time a dial to it succeeded, 0 if never.
    pub ok: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Record {
    pub presence_key: Option<[u8; 32]>,
    pub port: u16,
    pub addrs: Vec<Remembered>,
}

impl Record {
    /// Merge a hello received at `now`. The key and port are replaced (a peer
    /// rotates its key on unpair); addresses are upserted, never dropped here:
    /// the address from another network is still the one to try there.
    pub fn learn(&mut self, h: &Hello, now: u64) {
        self.presence_key = Some(h.presence_key);
        self.port = h.port;
        for a in &h.addrs {
            match self.addrs.iter_mut().find(|r| r.ip == a.ip && r.port == h.port) {
                Some(r) => {
                    r.seen = now;
                    r.class = a.class;
                }
                None => self.addrs.push(Remembered { ip: a.ip, port: h.port, class: a.class, seen: now, ok: 0 }),
            }
        }
        self.prune(now);
    }

    /// A dial to `addr` authenticated at `now`.
    pub fn mark_ok(&mut self, addr: SocketAddr, now: u64) {
        if !advertisable(&addr.ip()) {
            return;
        }
        match self.addrs.iter_mut().find(|r| r.ip == addr.ip() && r.port == addr.port()) {
            Some(r) => r.ok = now,
            None => self.addrs.push(Remembered { ip: addr.ip(), port: addr.port(), class: Class::Shared, seen: now, ok: now }),
        }
        self.prune(now);
    }

    fn rank(&mut self) {
        self.addrs.sort_by(|a, b| b.ok.cmp(&a.ok).then(b.seen.cmp(&a.seen)).then(a.ip.cmp(&b.ip)));
    }

    pub fn prune(&mut self, now: u64) {
        self.addrs.retain(|r| r.seen.max(r.ok) + FORGET_SECS >= now);
        self.rank();
        self.addrs.truncate(MAX_ADDRS);
    }

    /// What to dial, best first: proven addresses, then the most recently
    /// learned.
    pub fn dial_order(&self) -> Vec<SocketAddr> {
        let mut r = self.clone();
        r.rank();
        r.addrs.iter().take(MAX_DIAL).map(|a| SocketAddr::new(a.ip, a.port)).collect()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "v": 1,
            "pk": self.presence_key.map(hex::encode),
            "port": self.port,
            "addrs": self.addrs.iter().map(|a| json!({
                "ip": a.ip.to_string(), "port": a.port, "class": a.class.as_str(), "seen": a.seen, "ok": a.ok,
            })).collect::<Vec<_>>(),
        })
    }

    pub fn from_json(v: &Value) -> Option<Record> {
        if v["v"].as_u64() != Some(1) {
            return None;
        }
        let presence_key = v["pk"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
        let port = v["port"].as_u64().and_then(|p| u16::try_from(p).ok()).unwrap_or(0);
        let addrs = v["addrs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|e| {
                        Some(Remembered {
                            ip: e["ip"].as_str()?.parse().ok()?,
                            port: u16::try_from(e["port"].as_u64()?).ok()?,
                            class: Class::parse(e["class"].as_str()?)?,
                            seen: e["seen"].as_u64().unwrap_or(0),
                            ok: e["ok"].as_u64().unwrap_or(0),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Record { presence_key, port, addrs })
    }
}

/// Answers "is this address carried by the link to that peer?". An adapter
/// implements it from its own routing state (for tunlion, the L3 overlay's
/// prefix ownership). Nothing here looks at interface names.
pub trait RouteOwner {
    /// The peer whose link carries traffic to `ip`, if the route to `ip` rides
    /// one of our own links.
    fn carried_by(&self, ip: IpAddr) -> Option<String>;
}

/// No overlay at all: nothing is carried by a link.
pub struct NoOverlay;
impl RouteOwner for NoOverlay {
    fn carried_by(&self, _ip: IpAddr) -> Option<String> {
        None
    }
}

/// The one guard on candidates (spec section 9.3): never use, for peer X, an
/// address whose route is carried by our link to X. That dial could only
/// succeed when the link already exists. An overlay address carried by a link
/// to some OTHER peer is a real path (a third device relays) and is kept.
pub fn not_circular(peer: &str, cands: Vec<SocketAddr>, owner: &dyn RouteOwner) -> Vec<SocketAddr> {
    cands
        .into_iter()
        .filter(|c| owner.carried_by(c.ip()).map_or(true, |p| !p.eq_ignore_ascii_case(peer)))
        .collect()
}
