//! L3 overlay identity + self-certifying addressing (steps 2/3).
//!
//! Each device holds a long-term Ed25519 "overlay key". Its overlay IPv6 address
//! is a hash of the public key, so the address itself proves which key owns it
//! (Yggdrasil-style crypto-addressing). Peers announce their address in a SIGNED
//! `Announce` bound to the live link's channel binding; a receiver installs a
//! route only after three checks pass:
//!
//!   1. address-is-key:  addr == addr_from_pubkey(pubkey)   (no arbitrary IP)
//!   2. channel binding: cb  == this_link.channel_binding() (no replay onto
//!                                                            another link)
//!   3. possession:      Ed25519_verify(pubkey, msg, sig)   (holds the key)
//!
//! Together these make route hijack, replay, and IP spoofing infeasible even for
//! a legitimately paired peer: to claim node C's address an attacker needs C's
//! private key (check 3) AND a signature bound to the attacker's own link (check
//! 2), and cannot pick an address that isn't the hash of the key it presents
//! (check 1). This closes the unauthenticated-route-injection hole in the first
//! l3-hello draft.
//!
//! The derivation + verification here are portable (pure hashing/crypto); only
//! the key file lives under the config dir. `ring` provides Ed25519 + CSPRNG.

use std::net::Ipv6Addr;
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use sha2::{Digest, Sha256};

/// Fixed filament overlay prefix: `fdf1:1af7:c30d::/48`. `fd..` is a ULA
/// (RFC 4193, never routed on the Internet); the next 40 bits tag the filament
/// overlay so the whole network shares one prefix and the kernel routes it to the
/// single TUN with one route. The low 80 bits are the key hash.
const PREFIX: [u8; 6] = [0xfd, 0xf1, 0x1a, 0xf7, 0xc3, 0x0d];
const PREFIX_LEN: u8 = 48;

/// Domain-separation tags so a hash/signature here can never be mistaken for one
/// from another filament protocol (or a future overlay version).
const ADDR_DOMAIN: &[u8] = b"filament/overlay-addr/v1\0";
const BIND_DOMAIN: &[u8] = b"filament/overlay-bind/v1\0";

/// The overlay prefix as a `<addr>/48` string for route installation.
pub fn prefix_cidr() -> String {
    let net = Ipv6Addr::from([
        PREFIX[0], PREFIX[1], PREFIX[2], PREFIX[3], PREFIX[4], PREFIX[5], 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,
    ]);
    format!("{net}/{PREFIX_LEN}")
}

/// Derive the overlay address from a 32-byte Ed25519 public key:
/// `PREFIX(48) || SHA256(ADDR_DOMAIN || pubkey)[..10]`. 80 host bits make a
/// targeted collision infeasible (needs a 2^80 preimage AND the matching key).
pub fn addr_from_pubkey(pubkey: &[u8; 32]) -> Ipv6Addr {
    let mut h = Sha256::new();
    h.update(ADDR_DOMAIN);
    h.update(pubkey);
    let digest = h.finalize();
    let mut octets = [0u8; 16];
    octets[..6].copy_from_slice(&PREFIX);
    octets[6..16].copy_from_slice(&digest[..10]);
    Ipv6Addr::from(octets)
}

// ------------------------------------------------------ v4 overlay (opt-in) --
//
// The OPT-IN dual-stack v4 plane lets v4-only services (a server on 0.0.0.0 or a
// specific v4 iface) be reached over the mesh. Reserved range `198.18.0.0/15` (RFC
// 2544 benchmark space): never internet-routed, and clear of tailscale's 100.64/10
// and typical LAN/docker ranges, so it never shadows a real host. UNLIKE the v6
// address this is NOT self-certifying - 17 host bits can't cryptographically bind a
// key - so the v4 address is carried in the SAME signed `Announce` as the v6 address
// and trusted via that signature + channel binding. The v6 self-cert stays the
// anchor; v4 rides its trust. Collisions are birthday-bounded (~1 at a few hundred
// peers) and handled separately.

const V4_PREFIX: [u8; 4] = [198, 18, 0, 0];
const V4_PREFIX_LEN: u8 = 15;
/// Low 17 bits = the host part of a `/15`.
const V4_HOST_MASK: u32 = 0x0001_FFFF;
/// Domain tag for the v4 host derivation, distinct from the v6 addr tag.
const ADDR_V4_DOMAIN: &[u8] = b"filament/overlay-v4-addr/v1\0";

/// The v4 overlay prefix as a CIDR string for route installation.
pub fn prefix_v4_cidr() -> String {
    format!("{}/{}", std::net::Ipv4Addr::from(V4_PREFIX), V4_PREFIX_LEN)
}

/// Derive this device's v4 overlay address: the `198.18.0.0/15` prefix with the low
/// 17 bits taken from `SHA256(ADDR_V4_DOMAIN || pubkey)`.
pub fn addr_v4_from_pubkey(pubkey: &[u8; 32]) -> std::net::Ipv4Addr {
    let mut h = Sha256::new();
    h.update(ADDR_V4_DOMAIN);
    h.update(pubkey);
    let digest = h.finalize();
    let host = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]) & V4_HOST_MASK;
    std::net::Ipv4Addr::from(u32::from_be_bytes(V4_PREFIX) | host)
}

// ------------------------------------------------------------- identity key --

fn key_path() -> PathBuf {
    crate::platform::Paths::config_path("overlay.ed25519")
}

fn seq_path() -> PathBuf {
    crate::platform::Paths::config_path("overlay.announce-seq")
}

/// The next announce sequence number, PERSISTED beside the identity key.
///
/// It has to be persisted, and the reason is the whole point of the field.
/// An in-process counter restarts at zero, so a peer that restarts announces
/// 0, 1, 2 while its peers still hold a last-seen of (say) 47. A receiver that
/// rejects `seq <= last_seen` would then lock that peer out PERMANENTLY, and
/// the failure is silent, per-peer, and looks exactly like a network problem.
/// That is a worse bug than the replay this counter exists to stop, and it is
/// the obvious implementation.
///
/// Persisting the counter beside the key keeps it monotonic across restarts,
/// which is the property the receiver check actually depends on. A timestamp
/// would also survive restarts and is deliberately NOT used: it imports clock
/// skew into a security check and hands an adversary a knob.
///
/// The new value is written BEFORE it is returned, so a crash can only ever
/// skip numbers, never reuse one. Gaps are fine; the receiver requires
/// strictly-increasing, not contiguous.
///
/// On a read error we start from the current time in seconds rather than 0.
/// A fresh identity has no peers holding a last-seen, so any start works; but
/// if the file is lost on an EXISTING identity, restarting at 0 would be the
/// permanent lock-out above. Seconds-since-epoch is far above any plausible
/// announce count and keeps us monotonic in practice without the value being
/// load-bearing as a clock.
pub fn next_announce_seq() -> u64 {
    next_announce_seq_at(&seq_path())
}

/// Path-taking form, so the persistence behaviour is testable without mutating
/// the process environment (which races under parallel test execution).
pub fn next_announce_seq_at(path: &std::path::Path) -> u64 {
    let current = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse::<u64>().ok())
        .unwrap_or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(1)
        });
    let next = current.saturating_add(1);
    // Best-effort persist. If this fails we still return a value the receiver
    // will accept for this session; the next restart falls back to the branch
    // above rather than to zero.
    let _ = std::fs::write(path, next.to_string());
    next
}

/// Is `seq` fresh, given the highest previously accepted value from that
/// identity? Strictly increasing, NOT contiguous: the persisted counter can
/// skip numbers after a crash and that must not lock a peer out.
///
/// A free function so the rule can be tested directly, rather than only
/// through an `L3` that needs a netstack to construct.
pub fn seq_is_fresh(last_seen: Option<u64>, seq: u64) -> bool {
    match last_seen {
        Some(last) => seq > last,
        None => true,
    }
}

/// This device's overlay identity: the Ed25519 keypair + its cached pubkey/addr.
pub struct Identity {
    keypair: Ed25519KeyPair,
    pubkey: [u8; 32],
    addr: Ipv6Addr,
}

impl Identity {
    /// Load the overlay key, generating + persisting it (PKCS8, 0600) on first
    /// use. Kept separate from the ssh managed key so neither format constrains
    /// the other.
    pub fn load_or_create() -> Result<Identity> {
        let path = key_path();
        let pkcs8 = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(_) => {
                let rng = ring::rand::SystemRandom::new();
                let doc = Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|_| anyhow!("overlay key generation failed"))?;
                crate::platform::SecretFile::write(&path, doc.as_ref())
                    .context("write overlay key")?;
                doc.as_ref().to_vec()
            }
        };
        Self::from_pkcs8(&pkcs8)
    }

    fn from_pkcs8(pkcs8: &[u8]) -> Result<Identity> {
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| anyhow!("overlay key is corrupt (bad PKCS8)"))?;
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(keypair.public_key().as_ref());
        let addr = addr_from_pubkey(&pubkey);
        Ok(Identity { keypair, pubkey, addr })
    }

    pub fn pubkey(&self) -> [u8; 32] {
        self.pubkey
    }
    pub fn addr(&self) -> Ipv6Addr {
        self.addr
    }
    /// This device's v4 overlay address (opt-in dual-stack). Always derivable; only
    /// installed as a route when the v4 overlay is enabled.
    pub fn addr_v4(&self) -> std::net::Ipv4Addr {
        addr_v4_from_pubkey(&self.pubkey)
    }

    /// Build a signed announcement of our address bound to `cb` (this link's
    /// channel binding). `seq` lets a receiver ignore stale re-announces.
    pub fn announce(&self, seq: u64, cb: &[u8]) -> Announce {
        let msg = bind_message(&self.addr, seq, cb);
        let sig = self.keypair.sign(&msg);
        let mut sig64 = [0u8; 64];
        sig64.copy_from_slice(sig.as_ref());
        Announce { pubkey: self.pubkey, addr: self.addr, seq, sig: sig64 }
    }

    /// Return the 32-byte Ed25519 public key (for cert signing / identity binding).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.pubkey
    }

    /// Sign arbitrary bytes with this device's Ed25519 private key (for possession binding).
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.keypair.sign(msg);
        let mut out = [0u8; 64];
        out.copy_from_slice(sig.as_ref());
        out
    }
}

/// Convenience: load the overlay key and return just the 32-byte public key.
pub fn overlay_pubkey_bytes() -> Result<[u8; 32]> {
    Ok(Identity::load_or_create()?.public_key_bytes())
}

/// Convenience: sign arbitrary bytes with this device's overlay private key.
pub fn overlay_sign_possession(msg: &[u8]) -> Result<[u8; 64]> {
    Ok(Identity::load_or_create()?.sign(msg))
}

/// The message an announce signs: DOMAIN || addr(16) || seq_be(8) || cb.
fn bind_message(addr: &Ipv6Addr, seq: u64, cb: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BIND_DOMAIN.len() + 16 + 8 + cb.len());
    msg.extend_from_slice(BIND_DOMAIN);
    msg.extend_from_slice(&addr.octets());
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(cb);
    msg
}

// ----------------------------------------------------------------- announce --

/// A peer's signed claim to an overlay address over a specific link.
#[derive(Clone)]
pub struct Announce {
    pub pubkey: [u8; 32],
    pub addr: Ipv6Addr,
    pub seq: u64,
    pub sig: [u8; 64],
}

impl Announce {
    /// The announcer's v4 overlay address, DERIVED from its pubkey. The v4 address
    /// is not carried in the signature or trusted from the wire: it is a pure
    /// function of the pubkey, which `verify` already authenticates (possession +
    /// self-cert + channel binding). So a verified announce yields a trustworthy v4
    /// address with no wire-format or signature change - old and new peers stay
    /// mutually verifiable. Only meaningful once `verify` has passed.
    pub fn addr_v4(&self) -> std::net::Ipv4Addr {
        addr_v4_from_pubkey(&self.pubkey)
    }

    /// Serialize for the `l3-announce` control message (base64 fields). `addr4` is
    /// INFORMATIONAL only (a reader/log sees the v4 addr without deriving it); the
    /// receiver always recomputes it from the verified pubkey, never trusts this.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "l3-announce",
            "pubkey": b64(&self.pubkey),
            "addr": self.addr.to_string(),
            "addr4": self.addr_v4().to_string(),
            "seq": self.seq,
            "sig": b64(&self.sig),
        })
    }

    /// Parse from a received `l3-announce` (no verification yet).
    pub fn from_json(v: &serde_json::Value) -> Result<Announce> {
        let pubkey: [u8; 32] = unb64(v["pubkey"].as_str().unwrap_or_default())?
            .try_into()
            .map_err(|_| anyhow!("announce pubkey not 32 bytes"))?;
        let sig: [u8; 64] = unb64(v["sig"].as_str().unwrap_or_default())?
            .try_into()
            .map_err(|_| anyhow!("announce sig not 64 bytes"))?;
        let addr: Ipv6Addr = v["addr"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| anyhow!("announce addr invalid"))?;
        let seq = v["seq"].as_u64().unwrap_or(0);
        Ok(Announce { pubkey, addr, seq, sig })
    }

    /// Verify against the live link's channel binding `cb`. On success returns the
    /// verified overlay address to route to `pubkey`'s owner. The three checks are
    /// the whole security argument (see module docs).
    pub fn verify(&self, cb: &[u8]) -> Result<Ipv6Addr> {
        // 1. address-is-key: the address MUST be the hash of the presented key,
        //    so a peer cannot announce an arbitrary (e.g. a third node's) IP.
        if self.addr != addr_from_pubkey(&self.pubkey) {
            bail!("l3-announce: address does not match public key");
        }
        // 2. channel binding: the signature is over THIS link's binding, so a
        //    genuine announce captured on another link cannot be replayed here.
        // 3. possession: verifying under the presented key proves the sender holds
        //    the private key for it.
        let msg = bind_message(&self.addr, self.seq, cb);
        UnparsedPublicKey::new(&ED25519, &self.pubkey)
            .verify(&msg, &self.sig)
            .map_err(|_| anyhow!("l3-announce: signature or channel-binding mismatch"))?;
        Ok(self.addr)
    }
}

// ------------------------------------------------------------------- base64 --
// Tiny std-only base64 (the wire uses it for the 32/64-byte fields); avoids a dep.

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = u32::from_be_bytes([0, b[0], b[1], b[2]]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn unb64(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => bail!("bad base64 char"),
        }
    }
    let s = s.trim_end_matches('=').as_bytes();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {

    // ---- announce sequence: replay rejection AND restart survival ----------
    //
    // The restart cases are the point. A replay-only test passes for a BROKEN
    // implementation (an in-process counter starting at zero), which is the
    // obvious implementation and locks every restarted peer out permanently,
    // silently and per-peer. So the counter's persistence is tested directly.

    #[test]
    fn seq_rejects_a_replayed_announce() {
        // P announced 3, then moved and announced 5; add_peer installed the new
        // address. A replayed seq-3 announce must not roll it back.
        assert!(super::seq_is_fresh(None, 3), "first announce is always fresh");
        assert!(super::seq_is_fresh(Some(3), 5), "a newer announce is accepted");
        assert!(!super::seq_is_fresh(Some(5), 3), "the replayed seq-3 is REJECTED");
        assert!(!super::seq_is_fresh(Some(5), 5), "an exact duplicate is rejected");
    }

    #[test]
    fn seq_allows_gaps_so_a_crash_does_not_lock_a_peer_out() {
        // The persisted counter can skip numbers after a crash. Requiring
        // contiguity would reject a peer that merely restarted.
        assert!(super::seq_is_fresh(Some(5), 900), "gaps are fine");
    }

    #[test]
    fn announce_seq_survives_a_restart() {
        // THE trap this guards: an in-process AtomicU64 restarts at zero, so a
        // restarted peer announces 0,1,2 while its peers hold last_seen=47 and
        // is rejected forever. Each call here reads from disk, which is exactly
        // what a fresh process does, so consecutive calls model restarts.
        let dir = std::env::temp_dir().join(format!("fil-seq-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("announce-seq");
        let _ = std::fs::remove_file(&path);

        // The DECISIVE assertion. Three in-process calls returning 1,2,3 would
        // satisfy a mere "is it increasing" check, so an in-process counter
        // would pass that and still be broken. What distinguishes the two is
        // whether a value ALREADY ON DISK is respected: that is the state a
        // fresh process inherits, and the one a reset counter ignores.
        std::fs::write(&path, "47").unwrap();
        let after_restart = super::next_announce_seq_at(&path);
        assert!(
            after_restart > 47,
            "a restarted peer must continue past the persisted value, not reset. \
             got {after_restart}, which a peer holding last_seen=47 would REJECT \
             forever. This is what an in-process counter does."
        );

        // And it keeps advancing from there.
        let next = super::next_announce_seq_at(&path);
        assert!(next > after_restart, "still monotonic: {next} !> {after_restart}");
        assert!(super::seq_is_fresh(Some(after_restart), next));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn announce_seq_does_not_restart_at_zero_when_the_file_is_lost() {
        // If the counter file is lost on an EXISTING identity, restarting at 0
        // would be the permanent lock-out. The fallback must be large.
        let dir = std::env::temp_dir().join(format!("fil-seq-lost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("announce-seq");
        let _ = std::fs::remove_file(&path);
        let v = super::next_announce_seq_at(&path);
        assert!(v > 1_000_000, "must not restart near zero, got {v}");
        let _ = std::fs::remove_dir_all(&dir);
    }
    use super::*;

    fn ident() -> Identity {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Identity::from_pkcs8(doc.as_ref()).unwrap()
    }

    #[test]
    fn addr_is_ula_and_deterministic() {
        let pk = [7u8; 32];
        let a = addr_from_pubkey(&pk);
        assert_eq!(a, addr_from_pubkey(&pk), "deterministic");
        assert_eq!(a.octets()[..6], PREFIX, "carries the filament ULA prefix");
    }

    #[test]
    fn distinct_keys_distinct_addrs() {
        assert_ne!(addr_from_pubkey(&[1u8; 32]), addr_from_pubkey(&[2u8; 32]));
    }

    #[test]
    fn v4_addr_in_benchmark_range_deterministic_and_distinct() {
        let pk = [7u8; 32];
        let a = addr_v4_from_pubkey(&pk);
        assert_eq!(a, addr_v4_from_pubkey(&pk), "deterministic");
        // Inside 198.18.0.0/15 (first octet 198; second 18 or 19).
        let o = a.octets();
        assert_eq!(o[0], 198, "must carry the benchmark prefix: {a}");
        assert!(o[1] == 18 || o[1] == 19, "must be within /15: {a}");
        assert_ne!(a, addr_v4_from_pubkey(&[8u8; 32]), "distinct keys -> distinct addrs");
        assert_eq!(prefix_v4_cidr(), "198.18.0.0/15");
    }

    #[test]
    fn announce_roundtrips_and_verifies() {
        let id = ident();
        let cb = b"link-channel-binding-xyz";
        let ann = id.announce(1, cb);
        let wire = ann.to_json();
        // the wire carries addr4 informationally, but it is derived, never trusted.
        assert_eq!(wire["addr4"].as_str().unwrap(), id.addr_v4().to_string());
        let parsed = Announce::from_json(&wire).unwrap();
        let addr = parsed.verify(cb).expect("verifies under the same cb");
        assert_eq!(addr, id.addr());
        // V2: a verified announce yields the announcer's v4 address, derived from
        // the pubkey `verify` just authenticated (no separate v4 signature).
        assert_eq!(parsed.addr_v4(), id.addr_v4());
    }

    #[test]
    fn rejects_wrong_channel_binding() {
        // replay defense: an announce signed for one link fails on another.
        let id = ident();
        let ann = id.announce(1, b"cb-of-link-A");
        assert!(ann.verify(b"cb-of-link-B").is_err());
    }

    #[test]
    fn rejects_hijacked_address() {
        // a peer that swaps in a different address (e.g. a victim's) is rejected
        // by check 1 before the signature is even examined.
        let id = ident();
        let cb = b"cb";
        let mut ann = id.announce(1, cb);
        ann.addr = addr_from_pubkey(&[99u8; 32]); // someone else's address
        assert!(ann.verify(cb).is_err());
    }

    #[test]
    fn rejects_forged_signature() {
        let id = ident();
        let cb = b"cb";
        let mut ann = id.announce(1, cb);
        ann.sig[0] ^= 0xff; // tamper
        assert!(ann.verify(cb).is_err());
    }

    #[test]
    fn rejects_key_substitution() {
        // present a valid announce but swap the pubkey to another real key: check 1
        // fails (addr no longer matches the substituted key).
        let a = ident();
        let b = ident();
        let cb = b"cb";
        let mut ann = a.announce(1, cb);
        ann.pubkey = b.pubkey();
        assert!(ann.verify(cb).is_err());
    }

    #[test]
    fn base64_roundtrip() {
        for len in [0usize, 1, 2, 3, 31, 32, 64, 100] {
            let data: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(unb64(&b64(&data)).unwrap(), data, "len {len}");
        }
    }
}
