//! Beacon wire format and key derivation (spec sections 3 and 4).
//!
//! Every datagram is exactly [`BEACON_LEN`] bytes:
//!
//! ```text
//! 0      2    3     4            16             32     34
//! | "TL" | v  | kind | nonce (12) | field (16)  | port |
//! ```
//!
//! `field` is the presence tag (kind 1), the pairing id (kind 2) or zero
//! (kind 3, query). A query is padded to full length so a reply is never
//! larger than the request that caused it.

use sha2::{Digest, Sha256};

pub const MAGIC: [u8; 2] = *b"TL";
pub const VERSION: u8 = 1;
pub const BEACON_LEN: usize = 34;
pub const NONCE_LEN: usize = 12;
pub const FIELD_LEN: usize = 16;
/// Epoch length in seconds. Receivers accept the current epoch and one either
/// side, so clocks may disagree by up to one epoch.
pub const EPOCH_SECS: u64 = 600;
/// UDP port for beacons and queries (multicast, broadcast and unicast).
pub const DISCOVERY_PORT: u16 = 47820;
/// Preferred UDP port for the authenticated QUIC listener. A client that cannot
/// bind it binds any port and advertises that one.
pub const DEFAULT_LISTEN_PORT: u16 = 47821;
/// IPv4 group, administratively scoped, sent with TTL 1.
pub const GROUP_V4: [u8; 4] = [239, 255, 84, 76];
/// IPv6 link-scope group `ff02::7475:6e6c` ("tunl"), hop limit 1.
pub const GROUP_V6: [u16; 8] = [0xff02, 0, 0, 0, 0, 0, 0x7475, 0x6e6c];

const PRESENCE_LABEL: &[u8] = b"tunlion-lan-v1/presence";
const LABEL_LABEL: &[u8] = b"tunlion-lan-v1/label";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Presence = 1,
    Pairing = 2,
    Query = 3,
}

impl Kind {
    fn from_u8(b: u8) -> Option<Kind> {
        match b {
            1 => Some(Kind::Presence),
            2 => Some(Kind::Pairing),
            3 => Some(Kind::Query),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Beacon {
    pub kind: Kind,
    pub nonce: [u8; NONCE_LEN],
    pub field: [u8; FIELD_LEN],
    pub port: u16,
}

impl Beacon {
    pub fn encode(&self) -> [u8; BEACON_LEN] {
        let mut b = [0u8; BEACON_LEN];
        b[0..2].copy_from_slice(&MAGIC);
        b[2] = VERSION;
        b[3] = self.kind as u8;
        b[4..16].copy_from_slice(&self.nonce);
        b[16..32].copy_from_slice(&self.field);
        b[32..34].copy_from_slice(&self.port.to_be_bytes());
        b
    }

    /// Strict decode: wrong length, magic, version or kind is `None`. A query
    /// with a non-zero field or port is malformed (it would let a sender
    /// smuggle bytes into a reply-shaped packet) and is also `None`.
    pub fn decode(b: &[u8]) -> Option<Beacon> {
        if b.len() != BEACON_LEN || b[0..2] != MAGIC || b[2] != VERSION {
            return None;
        }
        let kind = Kind::from_u8(b[3])?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&b[4..16]);
        let mut field = [0u8; FIELD_LEN];
        field.copy_from_slice(&b[16..32]);
        let port = u16::from_be_bytes([b[32], b[33]]);
        if kind == Kind::Query && (field != [0u8; FIELD_LEN] || port != 0) {
            return None;
        }
        if kind != Kind::Query && port == 0 {
            return None;
        }
        Some(Beacon { kind, nonce, field, port })
    }
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(k.map(|b| b ^ 0x36));
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(k.map(|b| b ^ 0x5c));
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y)) == 0
}

pub fn epoch(unix_secs: u64) -> u32 {
    (unix_secs / EPOCH_SECS) as u32
}

/// `HMAC-SHA256(P, "tunlion-lan-v1/presence" || epoch_be32 || nonce || port_be16)[0..16]`.
pub fn presence_tag(pk: &[u8; 32], epoch: u32, nonce: &[u8; NONCE_LEN], port: u16) -> [u8; FIELD_LEN] {
    let mut m = Vec::with_capacity(PRESENCE_LABEL.len() + 4 + NONCE_LEN + 2);
    m.extend_from_slice(PRESENCE_LABEL);
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(nonce);
    m.extend_from_slice(&port.to_be_bytes());
    let full = hmac_sha256(pk, &m);
    let mut t = [0u8; FIELD_LEN];
    t.copy_from_slice(&full[..FIELD_LEN]);
    t
}

pub fn presence(pk: &[u8; 32], unix_secs: u64, nonce: [u8; NONCE_LEN], port: u16) -> Beacon {
    Beacon { kind: Kind::Presence, nonce, field: presence_tag(pk, epoch(unix_secs), &nonce, port), port }
}

pub fn query(nonce: [u8; NONCE_LEN]) -> Beacon {
    Beacon { kind: Kind::Query, nonce, field: [0; FIELD_LEN], port: 0 }
}

/// Which of `keys` produced this presence beacon, trying epochs e-1, e, e+1.
/// Returns the index into `keys`. One HMAC per key per epoch: microseconds for
/// any realistic number of devices.
pub fn recognize(b: &Beacon, keys: &[[u8; 32]], unix_secs: u64) -> Option<usize> {
    if b.kind != Kind::Presence {
        return None;
    }
    let e = epoch(unix_secs);
    for (i, pk) in keys.iter().enumerate() {
        for ep in [e.wrapping_sub(1), e, e.wrapping_add(1)] {
            if ct_eq(&presence_tag(pk, ep, &b.nonce, b.port), &b.field) {
                return Some(i);
            }
        }
    }
    None
}

/// Pairing announce (spec section 7): the field is a random pairing id; no
/// value derived from the code is ever sent. `label` is shown beside the code
/// on both screens: four decimal digits from `SHA256(label || id)`.
pub fn pairing(id: [u8; FIELD_LEN], nonce: [u8; NONCE_LEN], port: u16) -> Beacon {
    Beacon { kind: Kind::Pairing, nonce, field: id, port }
}

pub fn pairing_label(id: &[u8; FIELD_LEN]) -> String {
    let mut h = Sha256::new();
    h.update(LABEL_LABEL);
    h.update(id);
    let d = h.finalize();
    format!("{:04}", u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 10_000)
}
