//! DERP-style relay ticket primitives.
//!
//! The relay itself is a sibling WSS service. This module owns only the
//! signaling-scoped ticket format and its offline verification logic.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

const INFO_PAIR_ID: &[u8] = b"filament/relay/pair-id";
const INFO_TICKET_MAC: &[u8] = b"filament/relay/ticket-mac";
pub const TICKET_TTL_SECS: u64 = 30;
pub const TICKET_SKEW_SECS: u64 = 5;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut hash = Sha256::new();
        hash.update(key);
        k[..32].copy_from_slice(&hash.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    for byte in &mut k {
        *byte ^= 0x36;
    }
    inner.update(k);
    inner.update(msg);
    let inner = inner.finalize();
    for byte in &mut k {
        *byte ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(k);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

fn hkdf_expand(key: &[u8], info: &[u8]) -> [u8; 32] {
    // HKDF-Extract with an all-zero HashLen salt, followed by one Expand block.
    let prk = hmac_sha256(&[0u8; 32], key);
    let mut expand = Vec::with_capacity(info.len() + 1);
    expand.extend_from_slice(info);
    expand.push(1);
    hmac_sha256(&prk, &expand)
}

/// Derive the two domain-separated keys from the signaling shared key `k`.
pub fn relay_keys(k: &[u8]) -> ([u8; 32], [u8; 32]) {
    (hkdf_expand(k, INFO_PAIR_ID), hkdf_expand(k, INFO_TICKET_MAC))
}

/// Derive the pair id for one pairing attempt. The nonce is deliberately not
/// carried in the ticket: it is committed into this 32-byte pair id.
pub fn derive_pair_id(k: &[u8], session_a: &[u8], session_b: &[u8], round_nonce: &[u8]) -> [u8; 32] {
    let (first, second) = if session_a <= session_b {
        (session_a, session_b)
    } else {
        (session_b, session_a)
    };
    let mut input = Vec::with_capacity(2 + first.len() + 2 + second.len() + 2 + round_nonce.len());
    push_len_prefixed(&mut input, first);
    push_len_prefixed(&mut input, second);
    push_len_prefixed(&mut input, round_nonce);
    let (k_id, _) = relay_keys(k);
    hmac_sha256(&k_id, &input)
}

/// A signaling-scoped, side-scoped relay ticket.
///
/// Wire format: `[32B pair_id][1B side][8B BE exp][32B mac]`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayTicket {
    pub pair_id: [u8; 32],
    pub side: u8,
    pub exp: u64,
    pub mac: [u8; 32],
}

impl RelayTicket {
    pub fn mint(k: &[u8], pair_id: [u8; 32], side: u8, exp: u64) -> Result<Self> {
        if side > 1 {
            bail!("relay ticket side must be 0 or 1");
        }
        let (_, k_mac) = relay_keys(k);
        let prefix = wire_prefix(&pair_id, side, exp);
        let mac = hmac_sha256(&k_mac, &prefix);
        Ok(Self { pair_id, side, exp, mac })
    }

    pub fn mint_for_pair(
        k: &[u8],
        session_a: &[u8],
        session_b: &[u8],
        round_nonce: &[u8],
        side: u8,
        exp: u64,
    ) -> Result<Self> {
        Self::mint(k, derive_pair_id(k, session_a, session_b, round_nonce), side, exp)
    }

    /// Verify offline at the relay. No signaling callback or payload access is
    /// needed; `k` is the relay's shared ticket-verification key.
    pub fn verify(&self, k: &[u8], now: u64) -> bool {
        let latest = now.saturating_add(TICKET_TTL_SECS + TICKET_SKEW_SECS);
        if self.side > 1
            || now > self.exp.saturating_add(TICKET_SKEW_SECS)
            || self.exp > latest
        {
            return false;
        }
        let (_, k_mac) = relay_keys(k);
        ct_eq(&self.mac, &hmac_sha256(&k_mac, &wire_prefix(&self.pair_id, self.side, self.exp)))
    }

    pub fn to_bytes(self) -> [u8; 73] {
        let mut out = [0u8; 73];
        out[..41].copy_from_slice(&wire_prefix(&self.pair_id, self.side, self.exp));
        out[41..].copy_from_slice(&self.mac);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 73 {
            bail!("relay ticket must be exactly 73 bytes");
        }
        let mut pair_id = [0u8; 32];
        pair_id.copy_from_slice(&bytes[..32]);
        let side = bytes[32];
        let exp = u64::from_be_bytes(bytes[33..41].try_into().unwrap());
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&bytes[41..]);
        Ok(Self { pair_id, side, exp, mac })
    }
}

/// Canonical serialized ticket prefix. The MAC covers this whole prefix by
/// construction, so adding fields before `mac` requires serialization to add
/// them here and automatically brings them under authentication.
fn wire_prefix(pair_id: &[u8; 32], side: u8, exp: u64) -> [u8; 41] {
    let mut input = [0u8; 41];
    input[..32].copy_from_slice(pair_id);
    input[32] = side;
    input[33..].copy_from_slice(&exp.to_be_bytes());
    input
}

fn push_len_prefixed(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_id_is_order_independent_and_nonce_bound() {
        let a = derive_pair_id(b"k", b"a", b"b", b"n1");
        assert_eq!(a, derive_pair_id(b"k", b"b", b"a", b"n1"));
        assert_ne!(a, derive_pair_id(b"k", b"a", b"b", b"n2"));
    }

    #[test]
    fn ticket_roundtrip_and_verify() {
        let ticket = RelayTicket::mint(b"k", [7; 32], 1, 1_000).unwrap();
        assert_eq!(RelayTicket::from_bytes(&ticket.to_bytes()).unwrap(), ticket);
        assert!(ticket.verify(b"k", 1_004));
        assert!(!ticket.verify(b"k", 1_006));
        assert!(!ticket.verify(b"wrong", 1_000));
        assert!(!ticket.verify(b"k", 1_031));
        assert!(!RelayTicket::mint(
            b"k",
            [7; 32],
            1,
            1_000 + TICKET_TTL_SECS + TICKET_SKEW_SECS + 1,
        )
            .unwrap()
            .verify(b"k", 1_000));
    }

    #[test]
    fn side_is_explicit_and_mac_bound() {
        assert!(RelayTicket::mint(b"k", [0; 32], 2, 100).is_err());
        let mut ticket = RelayTicket::mint(b"k", [0; 32], 0, 100).unwrap();
        ticket.side = 1;
        assert!(!ticket.verify(b"k", 100));
    }

    #[test]
    fn every_wire_prefix_field_is_mac_bound() {
        let ticket = RelayTicket::mint(b"k", [0; 32], 0, 100).unwrap();
        let mut pair_id = ticket;
        pair_id.pair_id[0] ^= 1;
        assert!(!pair_id.verify(b"k", 100));
        let mut exp = ticket;
        exp.exp += 1;
        assert!(!exp.verify(b"k", 100));
    }

    #[test]
    fn keys_are_domain_separated() {
        let (a, b) = relay_keys(b"k");
        assert_ne!(a, b);
    }
}
