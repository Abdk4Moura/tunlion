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
    /// Build an identity from a PKCS8 Ed25519 key.
    ///
    /// Where that key comes from, and who writes it on first use, is the host's
    /// business and stays with the caller. This crate only needs the bytes.
    pub fn from_pkcs8(pkcs8: &[u8]) -> Result<Identity> {
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
        Announce {
            pubkey: self.pubkey,
            addr: self.addr,
            seq,
            sig: sig64,
            relay_datagrams: true,
            routes: Vec::new(),
            routes_sig: None,
        }
    }

    /// An announce that also advertises `routes`, each signed under its own
    /// domain. Callers pass NORMALIZED CIDRs; the signature covers the exact
    /// strings sent, so normalizing after signing would invalidate it.
    pub fn announce_with_routes(&self, seq: u64, cb: &[u8], routes: Vec<String>) -> Announce {
        let mut a = self.announce(seq, cb);
        if routes.is_empty() {
            return a;
        }
        let msg = routes_message(&self.pubkey, seq, cb, &routes);
        a.routes_sig = Some(self.sign(&msg));
        a.routes = routes;
        a
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

/// The message an announce signs: DOMAIN || addr(16) || seq_be(8) || cb.
fn bind_message(addr: &Ipv6Addr, seq: u64, cb: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BIND_DOMAIN.len() + 16 + 8 + cb.len());
    msg.extend_from_slice(BIND_DOMAIN);
    msg.extend_from_slice(&addr.octets());
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(cb);
    msg
}

/// Domain for the SEPARATE signature over advertised routes.
///
/// Separate, and not folded into `bind_message`, for one reason: the base
/// announce signature must keep covering exactly the bytes it covers today, or
/// an older peer computing the digest without a routes field would fail to
/// verify a newer peer's announce and interop would break on upgrade. A second
/// signature over a second domain leaves the first untouched.
const ROUTES_DOMAIN: &[u8] = b"filament-l3-routes-v1";

/// Bytes signed to authenticate an advertised route set.
///
/// Binds `pubkey` (whose routes), `seq` (which announce generation) and `cb`
/// (which link). `seq` is what stops a captured route set being spliced onto a
/// later announce to resurrect a prefix the advertiser has since WITHDRAWN, and
/// `cb` stops it being replayed onto a different link.
///
/// Each CIDR is length-prefixed. Plain concatenation would let `["10.0.0.0/2",
/// "4"]` and `["10.0.0.0/24"]` produce identical bytes, so one signature would
/// authenticate two different route sets.
fn routes_message(pubkey: &[u8; 32], seq: u64, cb: &[u8], routes: &[String]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(ROUTES_DOMAIN.len() + 32 + 8 + cb.len() + 32 * routes.len());
    msg.extend_from_slice(ROUTES_DOMAIN);
    msg.extend_from_slice(pubkey);
    msg.extend_from_slice(&seq.to_be_bytes());
    msg.extend_from_slice(&(cb.len() as u32).to_be_bytes());
    msg.extend_from_slice(cb);
    msg.extend_from_slice(&(routes.len() as u32).to_be_bytes());
    for r in routes {
        msg.extend_from_slice(&(r.len() as u32).to_be_bytes());
        msg.extend_from_slice(r.as_bytes());
    }
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
    /// The sender can carry L3 packets over a RELAY link, not just direct-QUIC.
    ///
    /// ADVISORY and deliberately outside the signature. It selects a transport,
    /// it does not authorize anything, and the worst a tamperer achieves is
    /// suppressing L3-over-relay, which is a denial they could cause anyway by
    /// dropping the announce. What it must NOT do is default to true: an older
    /// peer does not send it and cannot receive relay datagrams, so assuming
    /// support would install a route that silently black-holes.
    pub relay_datagrams: bool,
    /// Prefixes this peer offers to carry, NORMALIZED by the sender.
    ///
    /// INSIDE a signature, unlike `relay_datagrams`, and the difference is not
    /// caution. `relay_datagrams` selects a transport and authorizes nothing, so
    /// tampering with it achieves only a denial the tamperer could cause anyway.
    /// A route set is a statement of CURRENT INTENT whose withdrawal matters:
    /// left unsigned, an attacker could re-add a prefix the peer was granted long
    /// ago and has since stopped advertising, and the capability check would
    /// still pass because the grant is real. Signing binds "I am advertising
    /// this, now, on this link".
    ///
    /// Being signed is NOT authorization. It proves who said it; whether to
    /// install it is a CAP_ROUTE decision plus the receiver's accept-routes.
    pub routes: Vec<String>,
    /// Signature over `routes_message`. `None` from a peer that advertises none.
    pub routes_sig: Option<[u8; 64]>,
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
            // Advisory capability flag; older peers ignore the unknown key.
            "dg_relay": self.relay_datagrams,
            // Advertised prefixes and their signature. Older peers ignore both
            // keys and verify the base announce unchanged, which is the whole
            // reason routes got their OWN signature rather than joining
            // bind_message.
            "routes": self.routes,
            "routes_sig": self.routes_sig.map(|s| b64(&s)),
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
        // Absent (older peer) means NO. See the field's note.
        let relay_datagrams = v["dg_relay"].as_bool().unwrap_or(false);
        // Absent means "advertises nothing", the safe reading for an older peer.
        let routes: Vec<String> = v["routes"]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let routes_sig = match v["routes_sig"].as_str() {
            Some(s) => {
                let raw = unb64(s)?;
                let arr: [u8; 64] =
                    raw.try_into().map_err(|_| anyhow!("announce routes_sig not 64 bytes"))?;
                Some(arr)
            }
            None => None,
        };
        Ok(Announce { pubkey, addr, seq, sig, relay_datagrams, routes, routes_sig })
    }

    /// Verify the advertised route set, SEPARATELY from the announce itself.
    ///
    /// Returns the routes only if their signature checks out. Deliberately not
    /// folded into `verify`: a bad route signature must not invalidate the
    /// ADDRESS, because the address is self-certifying and still perfectly good.
    /// Failing the whole announce would let a tamperer knock a peer off the
    /// overlay entirely by corrupting a field that only ever adds routes.
    ///
    /// An empty result is the answer for a peer advertising nothing, for an
    /// older peer that has no such field, and for a route set whose signature
    /// fails. All three mean "install no prefixes from this peer", which is the
    /// safe reading of each.
    ///
    /// PROVES AUTHORSHIP, NOT PERMISSION. The caller must still check CAP_ROUTE
    /// for every prefix and the receiver's own accept-routes.
    pub fn verify_routes(&self, cb: &[u8]) -> Vec<String> {
        if self.routes.is_empty() {
            return Vec::new();
        }
        let Some(sig) = self.routes_sig else {
            return Vec::new(); // routes without a signature are not a claim
        };
        let msg = routes_message(&self.pubkey, self.seq, cb, &self.routes);
        // Same primitive and same construction as `verify`, deliberately: one
        // signature check in this file that behaves differently from the other
        // is how the two drift.
        match UnparsedPublicKey::new(&ED25519, &self.pubkey).verify(&msg, &sig) {
            Ok(()) => self.routes.clone(),
            Err(_) => Vec::new(),
        }
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

pub fn b64(data: &[u8]) -> String {
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

pub fn unb64(s: &str) -> Result<Vec<u8>> {
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
    #[test]
    fn signed_routes_survive_roundtrip_and_resist_the_attacks_they_exist_for() {
        let id = ident();
        let cb = b"channel-binding-A";
        let routes = vec!["10.0.0.0/24".to_string(), "192.168.5.0/24".to_string()];

        let a = id.announce_with_routes(7, cb, routes.clone());
        // Survives the JSON hop the wire actually uses.
        let a = Announce::from_json(&a.to_json()).unwrap();
        assert_eq!(a.verify_routes(cb), routes, "honest advertisement verifies");
        assert!(a.verify(cb).is_ok(), "and the announce itself still verifies");

        // WRONG LINK. A route set captured on one channel must not apply to
        // another, or a relay could replay it onto a different link.
        assert!(a.verify_routes(b"channel-binding-B").is_empty(), "cb is bound");

        // TAMPERED SET. Adding a prefix invalidates the signature, so a peer
        // cannot be made to advertise something it did not.
        let mut t = a.clone();
        t.routes.push("172.16.0.0/12".into());
        assert!(t.verify_routes(cb).is_empty(), "added prefix is rejected");

        // REMOVED prefix is equally a different set, so a tamperer cannot
        // silently narrow someone's advertisement either.
        let mut t2 = a.clone();
        t2.routes.pop();
        assert!(t2.verify_routes(cb).is_empty(), "altered set is rejected");

        // RESURRECTION. The seq binding is the point: a route set signed for
        // announce 7 must not be splicable onto announce 8, which is how a
        // WITHDRAWN prefix would otherwise come back while its grant is still
        // valid.
        let mut later = id.announce(8, cb);
        later.routes = a.routes.clone();
        later.routes_sig = a.routes_sig;
        assert!(later.verify_routes(cb).is_empty(), "route set is bound to its seq");

        // Routes with no signature are not a claim.
        let mut unsigned = a.clone();
        unsigned.routes_sig = None;
        assert!(unsigned.verify_routes(cb).is_empty(), "unsigned routes are ignored");
    }

    #[test]
    fn routes_never_invalidate_the_address_and_older_peers_are_unaffected() {
        let id = ident();
        let cb = b"cb";

        // A CORRUPT route signature must not cost the peer its address. The
        // address is self-certifying and still good; failing the whole announce
        // would let a tamperer knock a peer off the overlay by corrupting a
        // field that only ever ADDS routes.
        let mut a = id.announce_with_routes(3, cb, vec!["10.0.0.0/24".into()]);
        a.routes_sig = Some([0u8; 64]);
        assert!(a.verify(cb).is_ok(), "address still verifies");
        assert!(a.verify_routes(cb).is_empty(), "but no routes are taken");

        // OLDER PEER: no routes keys at all. The base announce must verify
        // exactly as before, which is why routes got their own signature instead
        // of joining bind_message.
        let plain = id.announce(4, cb);
        let mut j = plain.to_json();
        j.as_object_mut().unwrap().remove("routes");
        j.as_object_mut().unwrap().remove("routes_sig");
        let parsed = Announce::from_json(&j).unwrap();
        assert!(parsed.verify(cb).is_ok(), "old-shape announce still verifies");
        assert!(parsed.verify_routes(cb).is_empty(), "and advertises nothing");
    }

    #[test]
    fn route_list_is_length_prefixed_so_two_sets_cannot_share_a_signature() {
        // Plain concatenation would make ["10.0.0.0/2","4"] and ["10.0.0.0/24"]
        // identical bytes, so one signature would authenticate both.
        let pk = [1u8; 32];
        let a = routes_message(&pk, 1, b"cb", &["10.0.0.0/2".into(), "4".into()]);
        let b = routes_message(&pk, 1, b"cb", &["10.0.0.0/24".into()]);
        assert_ne!(a, b, "split must not collide with joined");

        // The channel binding is length-prefixed for the same reason.
        let c = routes_message(&pk, 1, b"cbX", &["10.0.0.0/24".into()]);
        let d = routes_message(&pk, 1, b"cb", &["X10.0.0.0/24".into()]);
        assert_ne!(c, d, "cb boundary must not be ambiguous");
    }


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
