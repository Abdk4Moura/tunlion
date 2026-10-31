//! DNS-SD carrier of the beacon (spec section 5). A minimal mDNS encoder and
//! parser: just enough to announce `_tunlion._udp.local` with the beacon in a
//! TXT record, to ask for it, and to read other devices' announcements. Names
//! are random per epoch; nothing in the packet identifies the device.

use std::net::IpAddr;

pub const SERVICE: &str = "_tunlion._udp.local";
pub const MDNS_PORT: u16 = 5353;
pub const MDNS_V4: [u8; 4] = [224, 0, 0, 251];
pub const MDNS_V6: [u16; 8] = [0xff02, 0, 0, 0, 0, 0, 0, 0xfb];
const TTL: u32 = 120;
const T_A: u16 = 1;
const T_PTR: u16 = 12;
const T_TXT: u16 = 16;
const T_AAAA: u16 = 28;
const T_SRV: u16 = 33;
const CLASS_IN: u16 = 1;
const CACHE_FLUSH: u16 = 0x8000;

fn put_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn put_rr(out: &mut Vec<u8>, name: &str, ty: u16, class: u16, rdata: &[u8]) {
    put_name(out, name);
    out.extend_from_slice(&ty.to_be_bytes());
    out.extend_from_slice(&class.to_be_bytes());
    out.extend_from_slice(&TTL.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(rdata);
}

/// A PTR question for the service (QM, so answers go to the group).
pub fn query() -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    put_name(&mut out, SERVICE);
    out.extend_from_slice(&T_PTR.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out
}

/// An unsolicited response announcing one instance. `label` is the per-epoch
/// random instance and host label (lowercase hex, 16 chars by convention).
pub fn announce(label: &str, beacon: &[u8; crate::wire::BEACON_LEN], port: u16, addrs: &[IpAddr]) -> Vec<u8> {
    let instance = format!("{label}.{SERVICE}");
    let host = format!("{label}.local");
    let mut answers: Vec<u8> = Vec::new();
    let mut n = 0u16;
    let mut ptr = Vec::new();
    put_name(&mut ptr, &instance);
    put_rr(&mut answers, SERVICE, T_PTR, CLASS_IN, &ptr);
    n += 1;
    let mut srv = vec![0, 0, 0, 0];
    srv.extend_from_slice(&port.to_be_bytes());
    put_name(&mut srv, &host);
    put_rr(&mut answers, &instance, T_SRV, CLASS_IN | CACHE_FLUSH, &srv);
    n += 1;
    let mut txt = Vec::new();
    for entry in ["v=1".to_string(), format!("b={}", hex::encode(beacon))] {
        txt.push(entry.len() as u8);
        txt.extend_from_slice(entry.as_bytes());
    }
    put_rr(&mut answers, &instance, T_TXT, CLASS_IN | CACHE_FLUSH, &txt);
    n += 1;
    for a in addrs {
        match a {
            IpAddr::V4(v4) => put_rr(&mut answers, &host, T_A, CLASS_IN | CACHE_FLUSH, &v4.octets()),
            IpAddr::V6(v6) => put_rr(&mut answers, &host, T_AAAA, CLASS_IN | CACHE_FLUSH, &v6.octets()),
        }
        n += 1;
    }
    let mut out = vec![0, 0, 0x84, 0, 0, 0];
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&answers);
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// Someone asked for `_tunlion._udp.local`.
    Query,
    /// Beacons found in TXT records of tunlion instances.
    Beacons(Vec<[u8; crate::wire::BEACON_LEN]>),
    Other,
}

fn read_name(p: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end: Option<usize> = None;
    for _ in 0..64 {
        let len = *p.get(at)? as usize;
        if len == 0 {
            return Some((name, end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let off = ((len & 0x3f) << 8) | *p.get(at + 1)? as usize;
            if end.is_none() {
                end = Some(at + 2);
            }
            if off >= at {
                return None; // forward pointers can loop
            }
            at = off;
            continue;
        }
        let label = p.get(at + 1..at + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        at += 1 + len;
    }
    None
}

fn u16_at(p: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*p.get(at)?, *p.get(at + 1)?]))
}

pub fn parse(p: &[u8]) -> Parsed {
    parse_inner(p).unwrap_or(Parsed::Other)
}

fn parse_inner(p: &[u8]) -> Option<Parsed> {
    let flags = u16_at(p, 2)?;
    let qd = u16_at(p, 4)? as usize;
    let rr = u16_at(p, 6)? as usize + u16_at(p, 8)? as usize + u16_at(p, 10)? as usize;
    let mut at = 12;
    let mut asked = false;
    for _ in 0..qd.min(32) {
        let (name, next) = read_name(p, at)?;
        let ty = u16_at(p, next)?;
        if name == SERVICE && (ty == T_PTR || ty == 255) {
            asked = true;
        }
        at = next + 4;
    }
    if flags & 0x8000 == 0 {
        return Some(if asked { Parsed::Query } else { Parsed::Other });
    }
    let mut beacons = Vec::new();
    let suffix = format!(".{SERVICE}");
    for _ in 0..rr.min(64) {
        let (name, next) = read_name(p, at)?;
        let ty = u16_at(p, next)?;
        let rdlen = u16_at(p, next + 8)? as usize;
        let rdata = p.get(next + 10..next + 10 + rdlen)?;
        if ty == T_TXT && name.ends_with(&suffix) {
            let mut i = 0;
            while i < rdata.len() {
                let l = rdata[i] as usize;
                let Some(entry) = rdata.get(i + 1..i + 1 + l) else { break };
                if let Some(h) = entry.strip_prefix(b"b=") {
                    if let Ok(bytes) = hex::decode(h) {
                        if let Ok(arr) = <[u8; crate::wire::BEACON_LEN]>::try_from(bytes.as_slice()) {
                            beacons.push(arr);
                        }
                    }
                }
                i += 1 + l;
            }
        }
        at = next + 10 + rdlen;
    }
    Some(if beacons.is_empty() { Parsed::Other } else { Parsed::Beacons(beacons) })
}
