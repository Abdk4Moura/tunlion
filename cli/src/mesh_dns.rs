//! The mesh name responder: an authoritative-only DNS server for `<name>.mesh`
//! and the overlay's reverse zones, answered from the daemon's VERIFIED name
//! table (the same table `dial`, the SOCKS proxy and `tunlion ssh` resolve from).
//!
//! WHERE IT LIVES. At a reserved overlay address, `fdf1:1af7:c30d::53`, inside
//! the prefix the kernel already routes to the TUN. A query to it is read by the
//! TUN loop like any other outbound packet and answered by writing the reply back
//! into the TUN: no socket, no port-53 privilege, nothing listening on the host.
//! IPv6 only, deliberately: the v4 overlay range has no address to spare that a
//! peer could not also derive, and every resolver that will be pointed here
//! (systemd-resolved, NRPT, /etc/resolver) speaks v6 to a v6 server.
//!
//! WHAT IT ANSWERS, and nothing else:
//!   - A / AAAA for `<name>.mesh` (and the `<name>-<4hex>` alias of each device),
//!     case-insensitively, including this machine itself;
//!   - an existing name with no record of the asked type: NOERROR with no answer
//!     (NODATA), so a v6-only peer does not look absent to an A query;
//!   - an unknown name under a zone we own: NXDOMAIN with the zone's SOA, so a
//!     resolver caches the absence for a few seconds rather than retrying;
//!   - PTR in the overlay reverse zones (ip6.arpa for the /48, and
//!     18/19.198.in-addr.arpa for the v4 /15);
//!   - everything else: REFUSED. It never recurses and never forwards, so it can
//!     never be turned into a path to a resolver the user did not choose.
//!
//! COLLISIONS RESOLVE TO NOTHING. Two devices with the same name used to be
//! served round-robin from the hosts file, so a connection to `laptop.mesh`
//! landed on whichever device the resolver picked. A name that maps to more than
//! one device is now ambiguous and answers NXDOMAIN; each device stays reachable
//! by its alias, `<name>-<4hex>`, where the hex is the first 16 bits of the
//! key-derived part of its overlay address (so it is derived from the device
//! key, stable, and the same on every peer).
//!
//! The codec is written by hand and kept PURE (bytes in, bytes out, no I/O, no
//! clock), because it parses packets from any local process. Every read is
//! bounds-checked, name compression is bounded twice (pointers must go strictly
//! backwards AND at most `MAX_JUMPS` are followed), and a name is capped at 255
//! wire bytes. The unit tests feed it random bytes, every truncation of a valid
//! query and pointer loops. A crate (hickory-proto) was considered and not taken:
//! it is large, pulls a resolver's worth of dependencies into a binary that only
//! needs four record types, and its parser would still need these same tests.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::{json, Value};

/// The mesh name suffix.
// TODO(setting): make this a `mesh-suffix` setting once slices 3-5 register
// the zone with the OS resolvers; until then the constant is the one place
// that names it.
pub const SUFFIX: &str = "mesh";

/// The responder's reserved overlay address. Inside the overlay /48, and never a
/// device address: those are `PREFIX || SHA256(key)[..10]`, and a key whose hash
/// starts with 64 zero bits is a preimage search, not an accident. `add_peer`
/// still refuses it, so a route can never shadow the responder.
pub const RESPONDER_V6: Ipv6Addr = Ipv6Addr::new(0xfdf1, 0x1af7, 0xc30d, 0, 0, 0, 0, 0x53);
/// The port the responder answers on.
pub const DNS_PORT: u16 = 53;

pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;
const CLASS_ANY: u16 = 255;

pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;

/// Positive answers are short-lived: a name moves when a device is renamed or
/// re-keyed, and a resolver must not hold the old address for long.
const ANSWER_TTL: u32 = 60;
/// Negative answers (the SOA minimum) are shorter still, so a device that just
/// joined becomes resolvable within seconds even after someone asked for it.
const NEGATIVE_TTL: u32 = 5;
/// RFC 1035: a name is at most 255 octets on the wire.
const MAX_NAME: usize = 255;
/// Compression pointers followed per name, at most. Real messages need one.
const MAX_JUMPS: usize = 16;

// ------------------------------------------------------------------- names --

/// Canonical form of a mesh name: trimmed, without a trailing dot, lowercase.
/// DNS is case-insensitive, so two devices that differ only in case are the
/// same name and must collide rather than both be served.
pub fn canonical(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Can `name` be served under the suffix at all? Empty and loopback names are
/// refused (a `localhost.mesh` must never mean a peer), and so is anything that
/// does not fit DNS: labels of 1..=63 bytes from [a-z0-9-], and room for the
/// suffix within the 255-byte limit.
pub fn is_safe_mesh_name(name: &str) -> bool {
    let name = canonical(name);
    if name.is_empty() || matches!(name.as_str(), "localhost" | "localhost4" | "localhost6") {
        return false;
    }
    if name.len() + 1 + SUFFIX.len() > 253 {
        return false;
    }
    name.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// The 4-hex tag that tells same-named devices apart: the first 16 bits of the
/// key-derived part of the overlay address (octets 6 and 7; octets 0..6 are the
/// fixed prefix). Derived from the device key, so every peer computes the same.
pub fn alias_tag(v6: &Ipv6Addr) -> String {
    let o = v6.octets();
    format!("{:02x}{:02x}", o[6], o[7])
}

/// `<name>-<tag>`, the name that stays unambiguous when `name` is not.
pub fn alias(name: &str, v6: &Ipv6Addr) -> String {
    format!("{}-{}", canonical(name), alias_tag(v6))
}

/// One device in the name table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub name: String,
    pub v6: Ipv6Addr,
    pub v4: Option<Ipv4Addr>,
    pub is_self: bool,
}

/// The result of resolving a name against the table.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    Found(&'a Entry),
    /// More than one device answers to the name: it resolves to nothing.
    Ambiguous,
    Unknown,
}

/// A snapshot of the verified name table, canonicalised and de-duplicated. A
/// DEVICE is identified by its v6 overlay address (it is the hash of its key),
/// so the same device listed under several link ids is one entry, and two
/// entries with the same name and different addresses are a collision.
#[derive(Clone, Debug, Default)]
pub struct Zone {
    entries: Vec<Entry>,
}

impl Zone {
    pub fn new<I: IntoIterator<Item = Entry>>(entries: I) -> Zone {
        let mut out: Vec<Entry> = Vec::new();
        for mut e in entries {
            e.name = canonical(&e.name);
            if !is_safe_mesh_name(&e.name) {
                continue;
            }
            match out.iter_mut().find(|x| x.name == e.name && x.v6 == e.v6) {
                Some(x) => {
                    x.is_self |= e.is_self;
                    if x.v4.is_none() {
                        x.v4 = e.v4;
                    }
                }
                None => out.push(e),
            }
        }
        // Stable order, so answers and listings do not depend on HashMap order.
        out.sort_by(|a, b| (&a.name, a.v6).cmp(&(&b.name, b.v6)));
        Zone { entries: out }
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Distinct devices that answer to `name`, by exact name or by alias.
    fn hits(&self, name: &str) -> Vec<&Entry> {
        let q = canonical(name);
        let mut hits: Vec<&Entry> = Vec::new();
        for e in &self.entries {
            if (e.name == q || alias(&e.name, &e.v6) == q) && !hits.iter().any(|h| h.v6 == e.v6) {
                hits.push(e);
            }
        }
        hits
    }

    /// Resolve `name` (no suffix). Exactly one device, or nothing.
    pub fn lookup(&self, name: &str) -> Lookup<'_> {
        let mut hits = self.hits(name);
        match hits.len() {
            0 => Lookup::Unknown,
            1 => Lookup::Found(hits.remove(0)),
            _ => Lookup::Ambiguous,
        }
    }

    /// The unique device for `name`, if there is exactly one.
    pub fn resolve(&self, name: &str) -> Option<&Entry> {
        match self.lookup(name) {
            Lookup::Found(e) => Some(e),
            _ => None,
        }
    }

    /// Is `name` held by more than one device?
    pub fn is_ambiguous(&self, name: &str) -> bool {
        let q = canonical(name);
        let mut seen: Vec<Ipv6Addr> = Vec::new();
        for e in self.entries.iter().filter(|e| e.name == q) {
            if !seen.contains(&e.v6) {
                seen.push(e.v6);
            }
        }
        seen.len() > 1
    }

    /// Every name held by more than one device, with those devices.
    pub fn collisions(&self) -> Vec<(String, Vec<&Entry>)> {
        let mut out: Vec<(String, Vec<&Entry>)> = Vec::new();
        for e in &self.entries {
            if out.iter().any(|(n, _)| *n == e.name) || !self.is_ambiguous(&e.name) {
                continue;
            }
            let devs = self.entries.iter().filter(|x| x.name == e.name).collect();
            out.push((e.name.clone(), devs));
        }
        out
    }

    /// The name each device is SERVED under: its own when unambiguous, its alias
    /// when the name collides. An alias that itself collides (two same-named
    /// devices whose tags match, 1 in 65536) is not served at all.
    pub fn served(&self) -> Vec<(String, &Entry)> {
        let mut out = Vec::new();
        for e in &self.entries {
            let n = if self.is_ambiguous(&e.name) { alias(&e.name, &e.v6) } else { e.name.clone() };
            if self.resolve(&n).is_some() {
                out.push((n, e));
            }
        }
        out
    }

    /// The PTR target for an overlay address: `<served name>.<suffix>`.
    pub fn ptr_name(&self, ip: IpAddr) -> Option<String> {
        self.served()
            .into_iter()
            .find(|(_, e)| match ip {
                IpAddr::V6(a) => e.v6 == a,
                IpAddr::V4(a) => e.v4 == Some(a),
            })
            .map(|(n, _)| format!("{n}.{SUFFIX}"))
    }
}

/// The reverse-lookup name for an address (`...ip6.arpa` / `...in-addr.arpa`).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(a) => {
            let mut s = String::with_capacity(72);
            for b in a.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", b & 0xf, b >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// The reverse zones this responder is authoritative for: the overlay /48 in
/// ip6.arpa (derived from the responder's own prefix, so the two cannot drift)
/// and the two /16s of the v4 overlay /15 (198.18.0.0/15).
fn reverse_zones() -> Vec<String> {
    let o = RESPONDER_V6.octets();
    let mut nibbles = Vec::with_capacity(12);
    for b in &o[..6] {
        nibbles.push(b >> 4);
        nibbles.push(b & 0xf);
    }
    let mut v6: String = nibbles.iter().rev().map(|n| format!("{n:x}.")).collect();
    v6.push_str("ip6.arpa");
    vec![v6, "18.198.in-addr.arpa".into(), "19.198.in-addr.arpa".into()]
}

// ------------------------------------------------------------------- wire --

/// Why a message could not be read. Every variant is a refusal, never a panic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Short,
    BadLabel,
    NameTooLong,
    PointerLoop,
}

fn u16_at(msg: &[u8], at: usize) -> Result<u16, WireError> {
    let b = msg.get(at..at.checked_add(2).ok_or(WireError::Short)?).ok_or(WireError::Short)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(msg: &[u8], at: usize) -> Result<u32, WireError> {
    let b = msg.get(at..at.checked_add(4).ok_or(WireError::Short)?).ok_or(WireError::Short)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a (possibly compressed) name starting at `start`. Returns its labels and
/// the offset just past the name where it STARTED (after the first pointer, if
/// any). Bounded: pointers must point strictly backwards, at most `MAX_JUMPS`
/// are followed, and the expanded name is at most `MAX_NAME` bytes.
pub fn read_name(msg: &[u8], start: usize) -> Result<(Vec<Vec<u8>>, usize), WireError> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0usize;
    let mut total = 0usize;
    loop {
        let len = *msg.get(pos).ok_or(WireError::Short)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => {
                total += 1;
                if total > MAX_NAME {
                    return Err(WireError::NameTooLong);
                }
                return Ok((labels, end.unwrap_or(pos + 1)));
            }
            0x00 => {
                let label = msg.get(pos + 1..pos + 1 + len).ok_or(WireError::Short)?;
                total += 1 + len;
                if total > MAX_NAME {
                    return Err(WireError::NameTooLong);
                }
                labels.push(label.to_vec());
                pos += 1 + len;
            }
            0xC0 => {
                let lo = *msg.get(pos + 1).ok_or(WireError::Short)? as usize;
                let target = ((len & 0x3F) << 8) | lo;
                if end.is_none() {
                    end = Some(pos + 2);
                }
                jumps += 1;
                if jumps > MAX_JUMPS || target >= pos {
                    return Err(WireError::PointerLoop);
                }
                pos = target;
            }
            // 0x40 / 0x80: extended and reserved label types. Not ours to guess.
            _ => return Err(WireError::BadLabel),
        }
    }
}

fn push_name(out: &mut Vec<u8>, name: &str) {
    for l in name.split('.').filter(|l| !l.is_empty()) {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
}

/// One record in an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rdata {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    /// A PTR target, as a dotted name without the trailing dot.
    Ptr(String),
    /// The SOA of the zone named here (its apex).
    Soa(String),
}

/// What the responder decided for one question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: u8,
    pub authoritative: bool,
    pub answers: Vec<Rdata>,
    /// `Some(apex)` puts that zone's SOA in the authority section (negative
    /// answers), which is what lets a resolver cache the absence.
    pub soa: Option<String>,
}

impl Answer {
    fn refused() -> Answer {
        Answer { rcode: REFUSED, authoritative: false, answers: Vec::new(), soa: None }
    }
    fn found(answers: Vec<Rdata>) -> Answer {
        Answer { rcode: NOERROR, authoritative: true, answers, soa: None }
    }
    fn nodata(apex: &str) -> Answer {
        Answer { rcode: NOERROR, authoritative: true, answers: Vec::new(), soa: Some(apex.to_string()) }
    }
    fn nxdomain(apex: &str) -> Answer {
        Answer { rcode: NXDOMAIN, authoritative: true, answers: Vec::new(), soa: Some(apex.to_string()) }
    }
}

/// Decide the answer to `qtype`/`qclass` for the name `labels`. Pure.
pub fn answer(labels: &[Vec<u8>], qtype: u16, qclass: u16, zone: &Zone) -> Answer {
    if qclass != CLASS_IN && qclass != CLASS_ANY {
        return Answer::refused();
    }
    let lower: Vec<String> = labels
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect();
    // A label we could never have issued (a dot, a space, non-ASCII) cannot name
    // anything in our zones. Under one of them that is NXDOMAIN, not a guess.
    let valid = lower
        .iter()
        .all(|l| !l.is_empty() && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
    let qname = lower.join(".");

    // Forward zone.
    if lower.last().map(String::as_str) == Some(SUFFIX) {
        let host = &lower[..lower.len() - 1];
        if host.is_empty() {
            return if matches!(qtype, TYPE_SOA | TYPE_ANY) {
                Answer::found(vec![Rdata::Soa(SUFFIX.to_string())])
            } else {
                Answer::nodata(SUFFIX)
            };
        }
        if !valid {
            return Answer::nxdomain(SUFFIX);
        }
        return match zone.lookup(&host.join(".")) {
            Lookup::Found(e) => {
                let mut out = Vec::new();
                if matches!(qtype, TYPE_A | TYPE_ANY) {
                    if let Some(v4) = e.v4 {
                        out.push(Rdata::A(v4));
                    }
                }
                if matches!(qtype, TYPE_AAAA | TYPE_ANY) {
                    out.push(Rdata::Aaaa(e.v6));
                }
                if out.is_empty() {
                    Answer::nodata(SUFFIX)
                } else {
                    Answer::found(out)
                }
            }
            // Ambiguous resolves to nothing: answering with one of the devices
            // is exactly the wrong-machine connection this replaces.
            Lookup::Ambiguous | Lookup::Unknown => Answer::nxdomain(SUFFIX),
        };
    }

    // Reverse zones.
    for apex in reverse_zones() {
        if qname != apex && !qname.ends_with(&format!(".{apex}")) {
            continue;
        }
        if qname == apex && matches!(qtype, TYPE_SOA | TYPE_ANY) {
            return Answer::found(vec![Rdata::Soa(apex)]);
        }
        if !valid {
            return Answer::nxdomain(&apex);
        }
        let mut owners: Vec<(String, IpAddr)> = Vec::new();
        for e in zone.entries() {
            owners.push((reverse_name(IpAddr::V6(e.v6)), IpAddr::V6(e.v6)));
            if let Some(v4) = e.v4 {
                owners.push((reverse_name(IpAddr::V4(v4)), IpAddr::V4(v4)));
            }
        }
        if let Some((_, ip)) = owners.iter().find(|(n, _)| *n == qname) {
            if !matches!(qtype, TYPE_PTR | TYPE_ANY) {
                return Answer::nodata(&apex);
            }
            return match zone.ptr_name(*ip) {
                Some(target) => Answer::found(vec![Rdata::Ptr(target)]),
                // The only owners without a served name are an alias collision.
                None => Answer::nxdomain(&apex),
            };
        }
        // The apex and every empty non-terminal above a real owner exist.
        let suffix = format!(".{qname}");
        if qname == apex || owners.iter().any(|(n, _)| n.ends_with(&suffix)) {
            return Answer::nodata(&apex);
        }
        return Answer::nxdomain(&apex);
    }

    // Not a zone we own. Never recurse, never forward.
    Answer::refused()
}

fn header_only(id: u16, rd: u16, rcode: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(12);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(0x8000 | rd | rcode as u16).to_be_bytes());
    out.extend_from_slice(&[0u8; 8]);
    out
}

fn soa_rdata(apex: &str) -> Vec<u8> {
    let mut r = Vec::with_capacity(64);
    push_name(&mut r, apex);
    push_name(&mut r, &format!("hostmaster.{apex}"));
    for v in [1u32, 3600, 600, 86400, NEGATIVE_TTL] {
        r.extend_from_slice(&v.to_be_bytes());
    }
    r
}

fn record(out: &mut Vec<u8>, ty: u16, ttl: u32, rdata: &[u8]) {
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// Answer one DNS message. `None` only when there is nothing to answer to: a
/// message too short to carry an id, or one that is itself a response (never
/// answering a response is what keeps two responders from looping).
pub fn respond(msg: &[u8], zone: &Zone) -> Option<Vec<u8>> {
    if msg.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([msg[0], msg[1]]);
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    if flags & 0x8000 != 0 {
        return None;
    }
    let rd = flags & 0x0100;
    if (flags >> 11) & 0xF != 0 {
        return Some(header_only(id, rd, NOTIMP));
    }
    if u16_at(msg, 4).ok() != Some(1) {
        return Some(header_only(id, rd, FORMERR));
    }
    let Ok((labels, after)) = read_name(msg, 12) else {
        return Some(header_only(id, rd, FORMERR));
    };
    let (Ok(qtype), Ok(qclass)) = (u16_at(msg, after), u16_at(msg, after + 2)) else {
        return Some(header_only(id, rd, FORMERR));
    };
    let a = answer(&labels, qtype, qclass, zone);

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(&id.to_be_bytes());
    let mut f: u16 = 0x8000 | rd | a.rcode as u16;
    if a.authoritative {
        f |= 0x0400;
    }
    out.extend_from_slice(&f.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(a.answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&(a.soa.is_some() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    // The question, echoed as asked: case preserved, because a resolver using
    // 0x20 randomisation compares it byte for byte.
    for l in &labels {
        out.push(l.len() as u8);
        out.extend_from_slice(l);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&qclass.to_be_bytes());
    for r in &a.answers {
        // Every answer is owned by the question name: a pointer to offset 12.
        out.extend_from_slice(&[0xC0, 0x0C]);
        match r {
            Rdata::A(v4) => record(&mut out, TYPE_A, ANSWER_TTL, &v4.octets()),
            Rdata::Aaaa(v6) => record(&mut out, TYPE_AAAA, ANSWER_TTL, &v6.octets()),
            Rdata::Ptr(n) => {
                let mut rd = Vec::new();
                push_name(&mut rd, n);
                record(&mut out, TYPE_PTR, ANSWER_TTL, &rd);
            }
            Rdata::Soa(apex) => record(&mut out, TYPE_SOA, NEGATIVE_TTL, &soa_rdata(apex)),
        }
    }
    if let Some(apex) = &a.soa {
        push_name(&mut out, apex);
        record(&mut out, TYPE_SOA, NEGATIVE_TTL, &soa_rdata(apex));
    }
    Some(out)
}

/// Build a query for `name`/`qtype` (RD set, as a stub resolver sends it).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, WireError> {
    let name = name.trim().trim_end_matches('.');
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes());
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    let mut total = 1usize;
    if !name.is_empty() {
        for l in name.split('.') {
            if l.is_empty() || l.len() > 63 {
                return Err(WireError::BadLabel);
            }
            total += 1 + l.len();
            out.push(l.len() as u8);
            out.extend_from_slice(l.as_bytes());
        }
    }
    if total > MAX_NAME {
        return Err(WireError::NameTooLong);
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

/// A decoded response: what `tunlion dns query` prints and the tests assert on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub id: u16,
    pub rcode: u8,
    pub authoritative: bool,
    pub answers: Vec<Rdata>,
    /// The apex of the SOA in the authority section, when there is one.
    pub soa: Option<String>,
}

fn dotted(labels: &[Vec<u8>]) -> String {
    labels
        .iter()
        .map(|l| String::from_utf8_lossy(l).to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(".")
}

/// Decode a response. Records of types we do not produce are skipped.
pub fn parse_response(msg: &[u8]) -> Result<Response, WireError> {
    let id = u16_at(msg, 0)?;
    let flags = u16_at(msg, 2)?;
    let qd = u16_at(msg, 4)?;
    let an = u16_at(msg, 6)?;
    let ns = u16_at(msg, 8)?;
    let mut pos = 12usize;
    for _ in 0..qd {
        let (_, after) = read_name(msg, pos)?;
        u32_at(msg, after)?;
        pos = after + 4;
    }
    let mut answers = Vec::new();
    let mut soa = None;
    for i in 0..(an as usize + ns as usize) {
        let (owner, after) = read_name(msg, pos)?;
        let ty = u16_at(msg, after)?;
        let rdlen = u16_at(msg, after + 8)? as usize;
        let start = after + 10;
        let rdata = msg.get(start..start + rdlen).ok_or(WireError::Short)?;
        pos = start + rdlen;
        let rec = match (ty, rdlen) {
            (TYPE_A, 4) => Some(Rdata::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]))),
            (TYPE_AAAA, 16) => {
                let mut o = [0u8; 16];
                o.copy_from_slice(rdata);
                Some(Rdata::Aaaa(Ipv6Addr::from(o)))
            }
            (TYPE_PTR, _) => Some(Rdata::Ptr(dotted(&read_name(msg, start)?.0))),
            (TYPE_SOA, _) => Some(Rdata::Soa(dotted(&owner))),
            _ => None,
        };
        match (i < an as usize, rec) {
            (true, Some(r)) => answers.push(r),
            (false, Some(Rdata::Soa(apex))) => soa = Some(apex),
            _ => {}
        }
    }
    Ok(Response {
        id,
        rcode: (flags & 0xF) as u8,
        authoritative: flags & 0x0400 != 0,
        answers,
        soa,
    })
}

// ----------------------------------------------------------------- packets --

fn sum16(mut acc: u64, bytes: &[u8]) -> u64 {
    let mut chunks = bytes.chunks_exact(2);
    for c in &mut chunks {
        acc += u16::from_be_bytes([c[0], c[1]]) as u64;
    }
    if let [last] = chunks.remainder() {
        acc += (*last as u64) << 8;
    }
    acc
}

fn fold(mut acc: u64) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    acc as u16
}

/// The UDP checksum over the IPv6 pseudo-header (mandatory in IPv6).
fn udp6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, udp: &[u8]) -> u16 {
    let mut acc = sum16(0, &src.octets());
    acc = sum16(acc, &dst.octets());
    acc = sum16(acc, &(udp.len() as u32).to_be_bytes());
    acc = sum16(acc, &[0, 0, 0, 17]);
    acc = sum16(acc, udp);
    match !fold(acc) {
        0 => 0xFFFF,
        c => c,
    }
}

/// If `pkt` is an IPv6 UDP datagram to the responder's port 53, the complete
/// IPv6 packet that answers it (addresses and ports swapped, checksum set).
/// `None` for anything else, including extension headers and malformed UDP:
/// a stub resolver sends neither, and anything that does is not owed an answer.
pub fn udp6_reply(pkt: &[u8], zone: &Zone) -> Option<Vec<u8>> {
    if pkt.len() < 48 || pkt[0] >> 4 != 6 || pkt[6] != 17 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    if pkt.len() < 40 + payload_len || payload_len < 8 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&pkt[24..40]);
    if Ipv6Addr::from(a) != RESPONDER_V6 {
        return None;
    }
    a.copy_from_slice(&pkt[8..24]);
    let client = Ipv6Addr::from(a);
    let udp = &pkt[40..40 + payload_len];
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if dport != DNS_PORT || ulen < 8 || ulen > payload_len {
        return None;
    }
    let dns = respond(&udp[8..ulen], zone)?;
    let ulen_out = 8 + dns.len();
    let mut out_udp = Vec::with_capacity(ulen_out);
    out_udp.extend_from_slice(&DNS_PORT.to_be_bytes());
    out_udp.extend_from_slice(&sport.to_be_bytes());
    out_udp.extend_from_slice(&(ulen_out as u16).to_be_bytes());
    out_udp.extend_from_slice(&[0, 0]);
    out_udp.extend_from_slice(&dns);
    let ck = udp6_checksum(&RESPONDER_V6, &client, &out_udp);
    out_udp[6..8].copy_from_slice(&ck.to_be_bytes());

    let mut out = Vec::with_capacity(40 + ulen_out);
    out.extend_from_slice(&[0x60, 0, 0, 0]);
    out.extend_from_slice(&(ulen_out as u16).to_be_bytes());
    out.push(17);
    out.push(64);
    out.extend_from_slice(&RESPONDER_V6.octets());
    out.extend_from_slice(&client.octets());
    out.extend_from_slice(&out_udp);
    Some(out)
}

// -------------------------------------------------------------- reporting --

pub fn type_name(t: u16) -> String {
    match t {
        TYPE_A => "A".into(),
        TYPE_NS => "NS".into(),
        TYPE_SOA => "SOA".into(),
        TYPE_PTR => "PTR".into(),
        TYPE_AAAA => "AAAA".into(),
        TYPE_ANY => "ANY".into(),
        n => format!("TYPE{n}"),
    }
}

/// Parse a `--type` argument: a mnemonic or a number.
pub fn parse_type(s: &str) -> Option<u16> {
    match s.trim().to_ascii_uppercase().as_str() {
        "A" => Some(TYPE_A),
        "AAAA" => Some(TYPE_AAAA),
        "PTR" => Some(TYPE_PTR),
        "SOA" => Some(TYPE_SOA),
        "NS" => Some(TYPE_NS),
        "ANY" => Some(TYPE_ANY),
        n => n.strip_prefix("TYPE").unwrap_or(n).parse().ok(),
    }
}

pub fn rcode_name(r: u8) -> String {
    match r {
        NOERROR => "NOERROR".into(),
        FORMERR => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        NXDOMAIN => "NXDOMAIN".into(),
        NOTIMP => "NOTIMP".into(),
        REFUSED => "REFUSED".into(),
        n => format!("RCODE{n}"),
    }
}

fn rdata_json(r: &Rdata) -> Value {
    match r {
        Rdata::A(a) => json!({ "type": "A", "data": a.to_string() }),
        Rdata::Aaaa(a) => json!({ "type": "AAAA", "data": a.to_string() }),
        Rdata::Ptr(n) => json!({ "type": "PTR", "data": format!("{n}.") }),
        Rdata::Soa(apex) => json!({ "type": "SOA", "data": format!("{apex}.") }),
    }
}

/// Run one question through the SAME path a packet takes (encode, `respond`,
/// decode), so `tunlion dns query` cannot answer differently from the wire.
pub fn query_json(zone: &Zone, name: &str, qtype: u16) -> Value {
    let q = match build_query(0x6d65, name, qtype) {
        Ok(q) => q,
        Err(e) => return json!({ "ok": false, "err": format!("not a valid DNS name ({e:?})") }),
    };
    let Some(resp) = respond(&q, zone) else {
        return json!({ "ok": false, "err": "the responder produced no answer" });
    };
    match parse_response(&resp) {
        Ok(r) if r.id != 0x6d65 => json!({ "ok": false, "err": "the answer is for a different query" }),
        Ok(r) => json!({
            "ok": true,
            "name": name,
            "type": type_name(qtype),
            "rcode": rcode_name(r.rcode),
            "authoritative": r.authoritative,
            "answers": r.answers.iter().map(rdata_json).collect::<Vec<_>>(),
            "authority": r.soa.map(|apex| format!("{apex}.")),
        }),
        Err(e) => json!({ "ok": false, "err": format!("unreadable answer ({e:?})") }),
    }
}

/// The name table as `status` and `doctor` show it: every device, the name it
/// is served under, and the names that collide.
pub fn names_json(zone: &Zone) -> Value {
    let served = zone.served();
    let names: Vec<Value> = zone
        .entries()
        .iter()
        .map(|e| {
            let as_name = served.iter().find(|(_, x)| x.v6 == e.v6 && x.name == e.name).map(|(n, _)| n.clone());
            json!({
                "name": e.name,
                "served_as": as_name.map(|n| format!("{n}.{SUFFIX}")),
                "alias": format!("{}.{SUFFIX}", alias(&e.name, &e.v6)),
                "v6": e.v6.to_string(),
                "v4": e.v4.map(|a| a.to_string()),
                "self": e.is_self,
            })
        })
        .collect();
    let collisions: Vec<Value> = zone
        .collisions()
        .into_iter()
        .map(|(n, devs)| {
            json!({
                "name": format!("{n}.{SUFFIX}"),
                "aliases": devs.iter().map(|e| format!("{}.{SUFFIX}", alias(&e.name, &e.v6))).collect::<Vec<_>>(),
            })
        })
        .collect();
    json!({
        "ok": true,
        "suffix": SUFFIX,
        "responder": RESPONDER_V6.to_string(),
        "names": names,
        "collisions": collisions,
    })
}

/// One line per collision, for `status` and `doctor` to print.
pub fn collision_lines(v: &Value) -> Vec<String> {
    v["collisions"]
        .as_array()
        .map(|cs| {
            cs.iter()
                .map(|c| {
                    let aliases: Vec<&str> = c["aliases"]
                        .as_array()
                        .map(|a| a.iter().filter_map(Value::as_str).collect())
                        .unwrap_or_default();
                    format!(
                        "{} is claimed by {} devices and resolves to none of them; use {}",
                        c["name"].as_str().unwrap_or("?"),
                        aliases.len(),
                        aliases.join(" or ")
                    )
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }
    fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }
    fn e(name: &str, a6: &str, a4: Option<&str>) -> Entry {
        Entry { name: name.into(), v6: v6(a6), v4: a4.map(v4), is_self: false }
    }

    /// alice dual-stack, bob v6-only, two devices called laptop, and self.
    fn zone() -> Zone {
        Zone::new(vec![
            e("alice", "fdf1:1af7:c30d:a11c::1", Some("198.18.1.1")),
            e("bob", "fdf1:1af7:c30d:b0b0::2", None),
            e("laptop", "fdf1:1af7:c30d:1111::3", Some("198.19.0.3")),
            e("Laptop", "fdf1:1af7:c30d:2222::4", None),
            Entry { is_self: true, ..e("me", "fdf1:1af7:c30d:5e1f::5", Some("198.18.9.9")) },
        ])
    }

    fn ask(name: &str, qtype: u16) -> Response {
        let q = build_query(0x1234, name, qtype).unwrap();
        parse_response(&respond(&q, &zone()).unwrap()).unwrap()
    }

    // ------------------------------------------------------------ goldens --

    /// The exact bytes of a positive AAAA answer. A golden, not a round trip:
    /// a round trip through our own decoder would accept a symmetric mistake.
    #[test]
    fn golden_aaaa_answer_bytes() {
        let z = Zone::new(vec![e("alice", "fdf1:1af7:c30d:a11c::1", None)]);
        let q = build_query(0x1234, "alice.mesh", TYPE_AAAA).unwrap();
        #[rustfmt::skip]
        let want_q: Vec<u8> = vec![
            0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0,
            5, b'a', b'l', b'i', b'c', b'e', 4, b'm', b'e', b's', b'h', 0,
            0, 28, 0, 1,
        ];
        assert_eq!(q, want_q);
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            0x12, 0x34, 0x85, 0x00, 0, 1, 0, 1, 0, 0, 0, 0,
            5, b'a', b'l', b'i', b'c', b'e', 4, b'm', b'e', b's', b'h', 0,
            0, 28, 0, 1,
            0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16,
            0xfd, 0xf1, 0x1a, 0xf7, 0xc3, 0x0d, 0xa1, 0x1c, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        assert_eq!(respond(&q, &z).unwrap(), want);
    }

    /// The exact bytes of NXDOMAIN with the zone SOA in the authority section.
    #[test]
    fn golden_nxdomain_with_soa_bytes() {
        let q = build_query(0xbeef, "nobody.mesh", TYPE_A).unwrap();
        #[rustfmt::skip]
        let want: Vec<u8> = vec![
            0xbe, 0xef, 0x85, 0x03, 0, 1, 0, 0, 0, 1, 0, 0,
            6, b'n', b'o', b'b', b'o', b'd', b'y', 4, b'm', b'e', b's', b'h', 0,
            0, 1, 0, 1,
            4, b'm', b'e', b's', b'h', 0,
            0, 6, 0, 1, 0, 0, 0, 5, 0, 43,
            4, b'm', b'e', b's', b'h', 0,
            10, b'h', b'o', b's', b't', b'm', b'a', b's', b't', b'e', b'r', 4, b'm', b'e', b's', b'h', 0,
            0, 0, 0, 1, 0, 0, 0x0e, 0x10, 0, 0, 0x02, 0x58, 0, 1, 0x51, 0x80, 0, 0, 0, 5,
        ];
        assert_eq!(respond(&q, &Zone::default()).unwrap(), want);
    }

    #[test]
    fn a_and_aaaa_answer_from_the_table_case_insensitively() {
        let r = ask("ALICE.Mesh", TYPE_A);
        assert_eq!((r.rcode, r.authoritative), (NOERROR, true));
        assert_eq!(r.answers, vec![Rdata::A(v4("198.18.1.1"))]);
        assert_eq!(ask("alice.mesh.", TYPE_AAAA).answers, vec![Rdata::Aaaa(v6("fdf1:1af7:c30d:a11c::1"))]);
        // ANY gives both families.
        assert_eq!(ask("alice.mesh", TYPE_ANY).answers.len(), 2);
    }

    #[test]
    fn self_is_served_like_any_device() {
        assert_eq!(ask("me.mesh", TYPE_AAAA).answers, vec![Rdata::Aaaa(v6("fdf1:1af7:c30d:5e1f::5"))]);
        assert_eq!(ask("me.mesh", TYPE_A).answers, vec![Rdata::A(v4("198.18.9.9"))]);
    }

    /// bob has no v4: an A query is NODATA (NOERROR, no answer, SOA), never
    /// NXDOMAIN, which would tell a dual-stack resolver bob does not exist.
    #[test]
    fn existing_name_without_that_record_is_nodata() {
        let r = ask("bob.mesh", TYPE_A);
        assert_eq!(r.rcode, NOERROR);
        assert!(r.answers.is_empty());
        assert_eq!(r.soa.as_deref(), Some("mesh"));
        let r = ask("bob.mesh", 16 /* TXT */);
        assert_eq!((r.rcode, r.answers.len()), (NOERROR, 0));
    }

    #[test]
    fn unknown_names_under_the_suffix_are_nxdomain_with_soa() {
        for n in ["nobody.mesh", "a.alice.mesh", "bad_label!.mesh"] {
            let r = ask(n, TYPE_AAAA);
            assert_eq!(r.rcode, NXDOMAIN, "{n}");
            assert_eq!(r.soa.as_deref(), Some("mesh"), "{n}");
        }
        // The apex itself exists: SOA answers, other types are NODATA.
        assert_eq!(ask("mesh", TYPE_SOA).answers, vec![Rdata::Soa("mesh".into())]);
        assert_eq!(ask("mesh", TYPE_AAAA).rcode, NOERROR);
    }

    /// The decision this module changes: a collided name answers nothing, and
    /// each device is reachable by its key-derived alias instead.
    #[test]
    fn a_collided_name_resolves_to_nothing_and_aliases_resolve_to_each() {
        let r = ask("laptop.mesh", TYPE_AAAA);
        assert_eq!(r.rcode, NXDOMAIN);
        assert!(r.answers.is_empty());
        assert_eq!(ask("laptop-1111.mesh", TYPE_AAAA).answers, vec![Rdata::Aaaa(v6("fdf1:1af7:c30d:1111::3"))]);
        assert_eq!(ask("LAPTOP-2222.mesh", TYPE_AAAA).answers, vec![Rdata::Aaaa(v6("fdf1:1af7:c30d:2222::4"))]);
        let z = zone();
        assert_eq!(z.lookup("laptop"), Lookup::Ambiguous);
        assert_eq!(z.collisions()[0].1.len(), 2);
        assert_eq!(z.collisions().len(), 1);
        assert!(z.resolve("laptop").is_none());
    }

    #[test]
    fn the_same_device_under_two_link_ids_is_not_a_collision() {
        let z = Zone::new(vec![
            e("alice", "fdf1:1af7:c30d:a11c::1", None),
            e("alice", "fdf1:1af7:c30d:a11c::1", Some("198.18.1.1")),
        ]);
        assert_eq!(z.entries().len(), 1);
        assert!(z.collisions().is_empty());
        assert_eq!(z.resolve("alice").and_then(|e| e.v4), Some(v4("198.18.1.1")));
    }

    #[test]
    fn ptr_answers_for_both_reverse_zones() {
        let r = ask(&reverse_name(IpAddr::V6(v6("fdf1:1af7:c30d:a11c::1"))), TYPE_PTR);
        assert_eq!(r.answers, vec![Rdata::Ptr("alice.mesh".into())]);
        let r = ask(&reverse_name(IpAddr::V4(v4("198.19.0.3"))), TYPE_PTR);
        // laptop collides, so its PTR names the alias, which is unambiguous.
        assert_eq!(r.answers, vec![Rdata::Ptr("laptop-1111.mesh".into())]);
        // An address in the zone with no device: NXDOMAIN with the zone's SOA.
        let r = ask(&reverse_name(IpAddr::V6(v6("fdf1:1af7:c30d:dead::1"))), TYPE_PTR);
        assert_eq!(r.rcode, NXDOMAIN);
        assert!(r.soa.unwrap().ends_with("ip6.arpa"));
        // The zone apex is an existing name.
        assert_eq!(ask("d.0.3.c.7.f.a.1.1.f.d.f.ip6.arpa", TYPE_PTR).rcode, NOERROR);
        assert_eq!(ask("18.198.in-addr.arpa", TYPE_SOA).answers.len(), 1);
    }

    #[test]
    fn the_reverse_zone_is_derived_from_the_overlay_prefix() {
        assert_eq!(reverse_zones()[0], "d.0.3.c.7.f.a.1.1.f.d.f.ip6.arpa");
        let net: Ipv6Addr = crate::overlay::prefix_cidr().split('/').next().unwrap().parse().unwrap();
        assert_eq!(&net.octets()[..6], &RESPONDER_V6.octets()[..6], "responder inside the overlay /48");
        assert_eq!(crate::overlay::prefix_v4_cidr(), "198.18.0.0/15");
        assert_eq!(reverse_name(IpAddr::V4(v4("198.18.1.2"))), "2.1.18.198.in-addr.arpa");
    }

    #[test]
    fn everything_else_is_refused_and_never_forwarded() {
        for n in ["example.com", "localhost", "", "8.8.8.8.in-addr.arpa", "1.0.0.0.ip6.arpa", "mesh.example"] {
            let r = ask(n, TYPE_A);
            assert_eq!(r.rcode, REFUSED, "{n:?}");
            assert!(!r.authoritative && r.answers.is_empty() && r.soa.is_none(), "{n:?}");
        }
        // A non-IN class is refused even for our names.
        let mut q = build_query(1, "alice.mesh", TYPE_A).unwrap();
        let n = q.len();
        q[n - 1] = 3; // CHAOS
        assert_eq!(parse_response(&respond(&q, &zone()).unwrap()).unwrap().rcode, REFUSED);
    }

    #[test]
    fn localhost_can_never_be_a_mesh_name() {
        assert!(!is_safe_mesh_name(""));
        assert!(!is_safe_mesh_name("localhost"));
        assert!(!is_safe_mesh_name("LocalHost"));
        assert!(is_safe_mesh_name("other-do"));
        assert!(!is_safe_mesh_name(&"a".repeat(64)));
        let z = Zone::new(vec![e("localhost", "fdf1:1af7:c30d:1::1", None)]);
        assert!(z.entries().is_empty());
    }

    // --------------------------------------------------- hostile input --

    /// A tiny xorshift, so the property tests are deterministic and need no
    /// dev-dependency.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
    }

    #[test]
    fn random_bytes_never_panic() {
        let z = zone();
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for _ in 0..20_000 {
            let len = (rng.next() % 600) as usize;
            let buf: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
            let _ = respond(&buf, &z);
            let _ = parse_response(&buf);
            let _ = udp6_reply(&buf, &z);
            if len >= 12 {
                let _ = read_name(&buf, (rng.next() as usize) % len);
            }
        }
    }

    /// Mutating a VALID query reaches far deeper than uniform noise does.
    #[test]
    fn mutated_queries_never_panic_and_always_answer_a_query() {
        let z = zone();
        let mut rng = Rng(42);
        let base = build_query(7, "alice.mesh", TYPE_AAAA).unwrap();
        for _ in 0..20_000 {
            let mut q = base.clone();
            for _ in 0..1 + rng.next() % 4 {
                let i = (rng.next() as usize) % q.len();
                q[i] = rng.next() as u8;
            }
            if let Some(r) = respond(&q, &z) {
                assert!(r.len() >= 12 && r[2] & 0x80 != 0, "a reply is always a response");
                assert!(r.len() <= 512, "fits a plain UDP answer: {}", r.len());
                assert_eq!(&r[..2], &q[..2], "the id is echoed");
            }
        }
    }

    #[test]
    fn every_truncation_of_a_query_is_refused_not_answered() {
        let q = build_query(9, "alice.mesh", TYPE_AAAA).unwrap();
        for cut in 0..q.len() {
            match respond(&q[..cut], &zone()) {
                None => assert!(cut < 12, "only a headerless message goes unanswered ({cut})"),
                Some(r) => {
                    let p = parse_response(&r).unwrap();
                    assert_eq!(p.rcode, FORMERR, "cut at {cut}");
                    assert!(p.answers.is_empty());
                }
            }
        }
    }

    #[test]
    fn compression_loops_are_bounded() {
        let header = [0u8, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        // A pointer to itself.
        let mut m = header.to_vec();
        m.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1]);
        assert_eq!(read_name(&m, 12), Err(WireError::PointerLoop));
        // A pointer forwards.
        let mut m = header.to_vec();
        m.extend_from_slice(&[0xC0, 20, 0, 1, 0, 1, 0, 0, 0]);
        assert_eq!(read_name(&m, 12), Err(WireError::PointerLoop));
        // A label then a pointer back to it: label, jump, label, jump...
        let mut m = header.to_vec();
        m.extend_from_slice(&[1, b'a', 0xC0, 12, 0, 1, 0, 1]);
        assert!(read_name(&m, 12).is_err());
        assert_eq!(parse_response(&respond(&m, &zone()).unwrap()).unwrap().rcode, FORMERR);
        // A long chain of backward pointers stops at the jump cap.
        let mut m = header.to_vec();
        m.extend_from_slice(&[1, b'a', 0]);
        for i in 0..40u8 {
            let at = if i == 0 { 12 } else { (12 + 3 + 2 * (i as usize - 1)) as u8 };
            m.extend_from_slice(&[0xC0, at]);
        }
        let last = m.len() - 2;
        assert_eq!(read_name(&m, last), Err(WireError::PointerLoop));
        // A name over 255 bytes is refused.
        let mut m = header.to_vec();
        for _ in 0..5 {
            m.push(63);
            m.extend_from_slice(&[b'x'; 63]);
        }
        m.push(0);
        assert_eq!(read_name(&m, 12), Err(WireError::NameTooLong));
    }

    #[test]
    fn responses_and_other_opcodes_are_not_answered_as_queries() {
        let mut q = build_query(3, "alice.mesh", TYPE_A).unwrap();
        q[2] |= 0x80; // QR: it is a response
        assert!(respond(&q, &zone()).is_none());
        let mut q = build_query(3, "alice.mesh", TYPE_A).unwrap();
        q[2] |= 0x28; // opcode 5 (UPDATE)
        assert_eq!(parse_response(&respond(&q, &zone()).unwrap()).unwrap().rcode, NOTIMP);
        let mut q = build_query(3, "alice.mesh", TYPE_A).unwrap();
        q[5] = 2; // two questions
        assert_eq!(parse_response(&respond(&q, &zone()).unwrap()).unwrap().rcode, FORMERR);
    }

    // ------------------------------------------------------------ packet --

    fn udp6_query(dst: Ipv6Addr, dport: u16, dns: &[u8]) -> Vec<u8> {
        let src = v6("fdf1:1af7:c30d:5e1f::5");
        let ulen = 8 + dns.len();
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(ulen as u16).to_be_bytes());
        p.extend_from_slice(&[17, 64]);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&dport.to_be_bytes());
        p.extend_from_slice(&(ulen as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]);
        p.extend_from_slice(dns);
        p
    }

    #[test]
    fn a_packet_to_the_responder_gets_a_correct_udp_reply() {
        let q = build_query(0x4242, "alice.mesh", TYPE_AAAA).unwrap();
        let pkt = udp6_query(RESPONDER_V6, 53, &q);
        let r = udp6_reply(&pkt, &zone()).expect("answered");
        assert_eq!(r[0] >> 4, 6);
        assert_eq!(r[6], 17);
        assert_eq!(&r[8..24], &RESPONDER_V6.octets(), "from the responder");
        assert_eq!(&r[24..40], &pkt[8..24], "to the asker");
        assert_eq!(u16::from_be_bytes([r[40], r[41]]), 53);
        assert_eq!(u16::from_be_bytes([r[42], r[43]]), 40000);
        let plen = u16::from_be_bytes([r[4], r[5]]) as usize;
        assert_eq!(r.len(), 40 + plen);
        assert_eq!(u16::from_be_bytes([r[44], r[45]]) as usize, plen);
        // The checksum verifies: summing the pseudo-header and the datagram,
        // checksum included, folds to all ones.
        let mut acc = sum16(0, &r[8..24]);
        acc = sum16(acc, &r[24..40]);
        acc = sum16(acc, &(plen as u32).to_be_bytes());
        acc = sum16(acc, &[0, 0, 0, 17]);
        acc = sum16(acc, &r[40..]);
        assert_eq!(fold(acc), 0xFFFF);
        let p = parse_response(&r[48..]).unwrap();
        assert_eq!(p.id, 0x4242);
        assert_eq!(p.answers, vec![Rdata::Aaaa(v6("fdf1:1af7:c30d:a11c::1"))]);
    }

    #[test]
    fn only_port_53_on_the_responder_address_is_intercepted() {
        let q = build_query(1, "alice.mesh", TYPE_AAAA).unwrap();
        assert!(udp6_reply(&udp6_query(v6("fdf1:1af7:c30d::54"), 53, &q), &zone()).is_none());
        assert!(udp6_reply(&udp6_query(RESPONDER_V6, 5353, &q), &zone()).is_none());
        let mut tcp = udp6_query(RESPONDER_V6, 53, &q);
        tcp[6] = 6;
        assert!(udp6_reply(&tcp, &zone()).is_none());
    }

    #[test]
    fn query_json_is_the_wire_answer() {
        let v = query_json(&zone(), "alice.mesh", TYPE_AAAA);
        assert_eq!(v["rcode"], "NOERROR");
        assert_eq!(v["answers"][0]["data"], "fdf1:1af7:c30d:a11c::1");
        assert_eq!(query_json(&zone(), "laptop.mesh", TYPE_A)["rcode"], "NXDOMAIN");
        let names = names_json(&zone());
        let lines = collision_lines(&names);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("laptop.mesh") && lines[0].contains("laptop-1111.mesh"));
        assert_eq!(parse_type("aaaa"), Some(TYPE_AAAA));
        assert_eq!(parse_type("TYPE16"), Some(16));
        assert_eq!(parse_type("bogus"), None);
    }
}
