//! DERP-style WSS byte relay for UDP-hostile networks (rung d).
//!
//! A lightweight relay server accepts WSS connections on port 443, matches peers
//! by relay ticket, and forwards raw bytes bidirectionally. The inner TLS/TCP
//! transport (tls_tcp.rs) runs end-to-end inside this WSS tunnel, so the relay
//! sees only opaque ciphertext — it cannot read or tamper with the payload.
//!
//! Relay tickets are signaling-scoped: derived from the pair secret via
//! HKDF-SHA256 with domain-separated subkeys (k_id for identity, k_mac for
//! ticket MAC). The ticket is bound to the inner TLS session via RFC 5705 TLS
//! exporter, preventing the relay from replaying tickets to a different peer.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};

// ============================================================ relay tickets ==

/// HKDF domain-separated info strings for relay ticket subkeys.
/// These MUST match the design doc exactly — do not change without updating
/// the advisor-reviewed spec.
const INFO_K_ID: &[u8] = b"filament-relay-id-v1";
const INFO_K_MAC: &[u8] = b"filament-relay-mac-v1";

/// Relay ticket version byte (wire format header).
const TICKET_V1: u8 = 1;

/// Default relay ticket TTL in seconds (5 minutes).
pub const TICKET_TTL_SECS: u64 = 300;
/// Clock-skew allowance applied when checking ticket expiry. Both peers may
/// have slightly different wall clocks; tolerate this bounded drift without
/// turning expiration into an unbounded lifetime.
pub const TICKET_SKEW_SECS: u64 = 30;

/// Raw-bytes HMAC-SHA256 (matches direct.rs::hmac_sha256_raw).
fn hmac_sha256_raw(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut h = Sha256::new();
        h.update(key);
        k[..32].copy_from_slice(&h.finalize());
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(inner);
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer.finalize());
    out
}

/// HKDF-SHA256 extract step: PRK = HMAC(salt, ikm).
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256_raw(salt, ikm)
}

/// HKDF-SHA256 expand step: OKM = HMAC(PRK, info || 0x01).
/// Single-block expand (32 bytes ≤ hash length).
fn hkdf_expand(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut msg = info.to_vec();
    msg.push(0x01);
    hmac_sha256_raw(prk, &msg)
}

/// Derive domain-separated relay ticket subkeys from a pair secret.
///
/// Returns (k_id, k_mac):
/// - k_id: identity binding key (proves the ticket holder knows the pair secret)
/// - k_mac: ticket MAC key (authenticates ticket fields)
///
/// The pair secret is the same one that keys `direct::transport_key()` and the
/// PAKE ceremony; the domain-separated info strings ensure zero key overlap.
pub fn relay_ticket_keys(pair_secret: &str) -> ([u8; 32], [u8; 32]) {
    let prk = hkdf_extract(&[0u8; 32], pair_secret.as_bytes());
    let k_id = hkdf_expand(&prk, INFO_K_ID);
    let k_mac = hkdf_expand(&prk, INFO_K_MAC);
    (k_id, k_mac)
}

/// A parsed relay ticket.
///
/// Wire format (v1):
/// ```text
/// [1B version][8B BE expiration][32B k_id_tag][32B MAC]
/// ```
///
/// The k_id_tag proves the ticket holder knows the pair secret.
/// The MAC covers: version || expiration || k_id_tag || relay_url || my_id || peer_id
/// (all string fields are length-prefixed with 2B BE).
#[derive(Clone, Debug)]
pub struct RelayTicket {
    /// Expiration as Unix timestamp (seconds).
    pub expiration: u64,
    /// k_id-based identity tag (proves pair-secret knowledge).
    pub k_id_tag: [u8; 32],
    /// MAC over all fields (authenticates ticket integrity + scope).
    pub mac: [u8; 32],
}

impl RelayTicket {
    /// Mint a new relay ticket for a specific peer pair and relay URL.
    ///
    /// - `pair_secret`: the PAKE-derived shared secret
    /// - `relay_url`: the WSS URL of the relay server (e.g. "wss://relay.filament.autumated.com:443")
    /// - `my_id`: this peer's device ID
    /// - `peer_id`: the target peer's device ID
    pub fn mint(
        pair_secret: &str,
        relay_url: &str,
        my_id: &str,
        peer_id: &str,
    ) -> Self {
        let (k_id, k_mac) = relay_ticket_keys(pair_secret);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let expiration = now + TICKET_TTL_SECS;

        // k_id_tag: HMAC(k_id, expiration || my_id || peer_id)
        // Proves the holder knows the pair secret.
        let id_input = id_input(expiration, my_id, peer_id);
        let k_id_tag = hmac_sha256_raw(&k_id, &id_input);

        // MAC: HMAC(k_mac, version || expiration || k_id_tag || relay_url || my_id || peer_id)
        // Covers all fields to prevent tampering.
        let mac_input = mac_input(TICKET_V1, expiration, &k_id_tag, relay_url, my_id, peer_id);
        let mac = hmac_sha256_raw(&k_mac, &mac_input);

        RelayTicket {
            expiration,
            k_id_tag,
            mac,
        }
    }

    /// Verify a relay ticket against expected fields.
    ///
    /// Returns true if:
    /// 1. The ticket has not expired
    /// 2. The k_id_tag matches (holder knows pair secret)
    /// 3. The MAC is valid (ticket fields not tampered)
    pub fn verify(
        &self,
        pair_secret: &str,
        relay_url: &str,
        my_id: &str,
        peer_id: &str,
    ) -> bool {
        let (k_id, k_mac) = relay_ticket_keys(pair_secret);

        // Check expiration
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.expiration.saturating_add(TICKET_SKEW_SECS) {
            return false;
        }

        // Verify k_id_tag
        let id_input = id_input(self.expiration, my_id, peer_id);
        let expected_id_tag = hmac_sha256_raw(&k_id, &id_input);
        if !ct_eq(&self.k_id_tag, &expected_id_tag) {
            return false;
        }

        // Verify MAC
        let expected_mac_input = mac_input(TICKET_V1, self.expiration, &self.k_id_tag, relay_url, my_id, peer_id);
        let expected_mac = hmac_sha256_raw(&k_mac, &expected_mac_input);
        ct_eq(&self.mac, &expected_mac)
    }

    /// Serialize ticket to wire format (v1):
    /// [1B version][8B BE expiration][32B k_id_tag][32B MAC]
    pub fn to_bytes(&self) -> [u8; 73] {
        let mut buf = [0u8; 73];
        buf[0] = TICKET_V1;
        buf[1..9].copy_from_slice(&self.expiration.to_be_bytes());
        buf[9..41].copy_from_slice(&self.k_id_tag);
        buf[41..73].copy_from_slice(&self.mac);
        buf
    }

    /// Deserialize ticket from wire format.
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < 73 {
            bail!("relay ticket too short: {} bytes", buf.len());
        }
        if buf[0] != TICKET_V1 {
            bail!("unsupported relay ticket version: {}", buf[0]);
        }
        let expiration = u64::from_be_bytes(buf[1..9].try_into().unwrap());
        let mut k_id_tag = [0u8; 32];
        k_id_tag.copy_from_slice(&buf[9..41]);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&buf[41..73]);
        Ok(RelayTicket {
            expiration,
            k_id_tag,
            mac,
        })
    }
}

/// Build the MAC input buffer: version || expiration || k_id_tag || relay_url || my_id || peer_id
/// All string fields are length-prefixed with 2B BE.
fn mac_input(
    version: u8,
    expiration: u64,
    k_id_tag: &[u8; 32],
    relay_url: &str,
    my_id: &str,
    peer_id: &str,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(version);
    buf.extend_from_slice(&expiration.to_be_bytes());
    buf.extend_from_slice(k_id_tag);
    buf.extend_from_slice(&(relay_url.len() as u16).to_be_bytes());
    buf.extend_from_slice(relay_url.as_bytes());
    buf.extend_from_slice(&(my_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(my_id.as_bytes());
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id.as_bytes());
    buf
}

/// Build the identity-tag input with unambiguous framing for every variable
/// field. This must stay aligned with the MAC's encoding discipline.
fn id_input(expiration: u64, my_id: &str, peer_id: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 2 + my_id.len() + 2 + peer_id.len());
    buf.extend_from_slice(&expiration.to_be_bytes());
    buf.extend_from_slice(&(my_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(my_id.as_bytes());
    buf.extend_from_slice(&(peer_id.len() as u16).to_be_bytes());
    buf.extend_from_slice(peer_id.as_bytes());
    buf
}

/// Constant-time equality (same as direct.rs::ct_eq).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ================================================================ tests ==

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ticket_roundtrip() {
        let ticket = RelayTicket::mint(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        );

        let bytes = ticket.to_bytes();
        let restored = RelayTicket::from_bytes(&bytes).unwrap();

        assert_eq!(ticket.expiration, restored.expiration);
        assert_eq!(ticket.k_id_tag, restored.k_id_tag);
        assert_eq!(ticket.mac, restored.mac);
    }

    #[test]
    fn relay_ticket_verify_valid() {
        let ticket = RelayTicket::mint(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        );

        assert!(ticket.verify(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        ));
    }

    #[test]
    fn relay_ticket_verify_wrong_secret() {
        let ticket = RelayTicket::mint(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        );

        assert!(!ticket.verify(
            "wrong-secret",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        ));
    }

    #[test]
    fn relay_ticket_verify_wrong_peer() {
        let ticket = RelayTicket::mint(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        );

        assert!(!ticket.verify(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-eve",
        ));
    }

    #[test]
    fn relay_ticket_verify_wrong_relay_url() {
        let ticket = RelayTicket::mint(
            "test-pair-secret-123",
            "wss://relay.filament.autumated.com:443",
            "device-alice",
            "device-bob",
        );

        assert!(!ticket.verify(
            "test-pair-secret-123",
            "wss://evil-relay.example.com:443",
            "device-alice",
            "device-bob",
        ));
    }

    #[test]
    fn relay_ticket_domain_separation() {
        let (k_id, k_mac) = relay_ticket_keys("test-secret");
        assert_ne!(k_id, k_mac);
    }

    #[test]
    fn relay_ticket_keys_deterministic() {
        let (k_id1, k_mac1) = relay_ticket_keys("test-secret");
        let (k_id2, k_mac2) = relay_ticket_keys("test-secret");
        assert_eq!(k_id1, k_id2);
        assert_eq!(k_mac1, k_mac2);
    }

    #[test]
    fn relay_ticket_keys_independent() {
        let (k_id1, k_mac1) = relay_ticket_keys("secret-a");
        let (k_id2, k_mac2) = relay_ticket_keys("secret-b");
        assert_ne!(k_id1, k_id2);
        assert_ne!(k_mac1, k_mac2);
    }

    #[test]
    fn relay_ticket_from_bytes_too_short() {
        assert!(RelayTicket::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn relay_ticket_from_bytes_wrong_version() {
        let mut buf = [0u8; 73];
        buf[0] = 99; // invalid version
        assert!(RelayTicket::from_bytes(&buf).is_err());
    }
}
