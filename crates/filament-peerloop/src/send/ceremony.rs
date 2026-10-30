//! Shared SPAKE2 key-agreement ceremony, used by BOTH `pair` and the transfer
//! path (`send --code` / `recv <code>`).
//!
//! The pairing command historically inlined the whole L1-a SPAKE2 ceremony in
//! `pair_cmd`. The transfer path had NO PAKE at all (it used the legacy
//! server-minted v1 code, and `send --remember` handed a plaintext secret over
//! the DataChannel). This module factors the ceremony out so the two flows run
//! the IDENTICAL handshake and differ ONLY in what they do with the result:
//!
//!   * `pair`    : run the ceremony, then PERSIST the agreed secret (a known
//!                 device) via `devices_store_v2`.
//!   * transfer  : run the ceremony, VERIFY it, then DISCARD the secret. The
//!                 ceremony authenticates the link (mutual auth, MITM-detectable
//!                 via the DTLS-fingerprint-bound confirmation MAC); the transfer
//!                 keeps no lasting trust. "Link with mutual auth, then forget."
//!
//! SECURITY INVARIANTS (shared by both callers, enforced here):
//!   - The PAKE words (password) NEVER cross the signaling server. Only the
//!     numeric nameplate is sent (by the caller, via pair-create / pair-claim).
//!     This module only ever relays the opaque 33-byte SPAKE2 element and the
//!     32-byte confirmation MAC over the `signal` channel.
//!   - The confirmation MAC binds BOTH sides' DTLS fingerprints (and the agreed
//!     caps), so a server/relay that substitutes a DTLS cert is DETECTED and the
//!     ceremony ABORTS, agreeing nothing.
//!   - The agreed secret is HKDF(K): agreed on both sides, never transmitted.
//!     The transfer caller throws it away; only `pair` (or `--remember`) stores.
//!
//! This is a pure protocol state machine: it never touches the network or the
//! `Conn`. The caller drives it from its event loop, feeding in the peer's
//! signal payloads and the link's DTLS fingerprints, and relaying the opaque
//! payloads this module produces. That keeps it unit-testable end to end (two
//! in-process ceremonies, no sockets), see the tests at the bottom.

use filament_pair::PakeState;
use serde_json::{json, Value};
use std::time::Instant;

use crate::retry::Resend;

/// Versioned purpose binding carried by the EXISTING PAKE relay frames. A
/// digest observed before confirmation is untrusted; only successful mutual
/// confirmation authenticates it. Ordinary pairing cannot accept this purpose.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TemporaryBinding {
    pub offer_id: String,
    pub revision: u64,
    pub offer_digest: [u8; 32],
    pub host_peer: [u8; 32],
}

impl TemporaryBinding {
    pub fn new(host_peer: [u8; 32], spec: &crate::access::AccessSpec,
        lifetime: crate::access::Lifetime, claim_expires_at: u64) -> Result<Self, crate::access::AccessError> {
        let mut random = [0;32];
        getrandom::getrandom(&mut random).map_err(|_| crate::access::AccessError::Unavailable)?;
        let mut binding = Self { offer_id: hex::encode(random), revision: 1, offer_digest: [0;32], host_peer };
        binding.offer_digest = binding.digest_for(spec, lifetime, claim_expires_at)?;
        Ok(binding)
    }

    pub(crate) fn digest_for(&self, spec: &crate::access::AccessSpec,
        lifetime: crate::access::Lifetime, claim_expires_at: u64) -> Result<[u8;32], crate::access::AccessError> {
        spec.validate()?;
        let bytes = serde_json::to_vec(&("tunlion/temporary-offer/v1", &self.offer_id,
            self.revision, self.host_peer, spec, lifetime, claim_expires_at))
            .map_err(|_| crate::access::AccessError::InvalidSpec)?;
        Ok(ring::digest::digest(&ring::digest::SHA256, &bytes).as_ref().try_into().expect("SHA256 length"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporaryRole { Host, Recipient }
impl TemporaryRole {
    fn wire(self) -> &'static str { match self { Self::Host => "host", Self::Recipient => "recipient" } }
    fn opposite(self) -> Self { match self { Self::Host => Self::Recipient, Self::Recipient => Self::Host } }
}

/// Inspect only to choose the PAKE state machine before sending the recipient's
/// first element. This is UNAUTHENTICATED negotiation, never actionable review.
/// A recognizable temporary marker with malformed binding fails closed.
pub fn inspect_temporary_binding(data: &Value) -> Result<Option<TemporaryBinding>, crate::access::AccessError> {
    match data.get("purpose") {
        None if data.get("access_binding").is_none() => Ok(None),
        Some(value) if value.as_str() == Some("temporary-access-v1") && data["access_role"].as_str() == Some("host") => {
            let binding: TemporaryBinding = serde_json::from_value(data["access_binding"].clone()).map_err(|_| crate::access::AccessError::InvalidSpec)?;
            if binding.offer_id.len() != 64 || !binding.offer_id.bytes().all(|b| b.is_ascii_hexdigit()) || binding.revision == 0 {
                return Err(crate::access::AccessError::InvalidSpec);
            }
            Ok(Some(binding))
        }
        _ => Err(crate::access::AccessError::Unsupported),
    }
}

/// The capability set v2 first-pairing / ephemeral transfer-auth agrees on.
/// "transfer" is the L0 baseline (always allowed); deny-by-default future caps
/// are NOT granted here. BOTH sides MAC the identical canonical string or
/// confirmation fails (spec §8 / gate 5), so this default is fixed.
pub fn pair_v2_caps() -> Vec<String> {
    vec!["transfer".to_string()]
}

/// Base64 (no external dep). Used only for the 33-byte SPAKE2 element / 32-byte
/// MAC opaque payloads on the signal relay. Mirrors the browser's b64.
pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { T[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[(n & 63) as usize] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let mut n = 0u32;
        let mut bits = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
            bits += 6;
        }
        n <<= 24 - bits;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Outcome of feeding an inbound `signal` payload into the ceremony.
#[derive(Debug)]
pub enum Inbound {
    /// The payload WAS a PAKE message (consumed). The caller must NOT route it
    /// into the WebRTC signal path. Drive the ceremony again afterwards.
    Consumed,
    /// The payload was malformed key-exchange material. The caller MUST abort
    /// the ceremony loudly (agree nothing) with this message.
    Abort(String),
    /// Not a PAKE payload (it is SDP/ICE); fall through to the WebRTC path.
    Ignored,
    /// A re-sent copy of the peer's confirmation, which this ceremony already
    /// verified: the peer is still waiting for OURS, so it was lost. Relay this
    /// payload (our same confirmation) back to that peer. Nothing else changed;
    /// it is not a new ceremony step and never a second attempt.
    Reply(Value),
}

/// One SPAKE2 ceremony with one peer. Holds all the protocol state the loops
/// previously inlined (the live session, our element, derived K, the sent-flags)
/// so both `pair` and the transfer path drive it identically.
pub struct Ceremony {
    confirmed_fingerprints: Option<(String, String)>,
    temporary: Option<(TemporaryBinding, TemporaryRole)>,
    /// The agreed capability set (relayed in the confirm payload) and its
    /// canonical form (fed to the MAC).
    caps: Vec<String>,
    caps_canon: String,
    /// Introduction scope byte (0x00 User, 0x01 Device), MANDATORY, bound into
    /// the confirmation transcript alongside caps + sorted DTLS fingerprints.
    /// Derived from the authenticated introduction token; no default.
    scope: u8,
    /// Live SPAKE2 session (consumed by `finish`). `None` after K is derived.
    state: Option<PakeState>,
    /// Our outbound 33-byte SPAKE2 element.
    msg: Vec<u8>,
    /// Derived shared key K (after finishing on the peer's element). Held until
    /// confirmation, then HKDF'd to the secret.
    k: Option<Vec<u8>>,
    /// The agreed pinned secret (HKDF(K)); set ONLY after confirmation passes.
    secret: Option<String>,
    /// Abort reason if the ceremony was refused (wrong code / tampering / etc.).
    aborted: Option<String>,
    sent_msg: bool,
    sent_confirm: bool,
    /// Re-sends whichever of our element / confirmation is current until the
    /// peer's confirmation is verified (see [`Resend`]).
    resend: Resend,
    /// The public routing nameplate this ceremony is for. Carried (as `np`) on
    /// every payload so a peer can tell whose ceremony a message belongs to:
    /// two concurrent `send --code` on one device share the sender's auto room,
    /// and a receiver claiming one code meets BOTH senders there. The nameplate
    /// already crosses the server (pair-create / pair-claim); it is routing, not
    /// a secret, and changing it cannot make a ceremony agree (SPAKE2 binds it).
    nameplate: String,
    /// The peer said it can take a direct QUIC connection (`"direct": true` on
    /// its PAKE payloads). A browser cannot, and never says so. Promoting a
    /// browser to direct QUIC tears down the WebRTC link it is using, and the
    /// re-established link never came back, so a code transfer to a browser
    /// stalled forever after "authenticated". Only routing, not a secret: a
    /// server that strips it just keeps the transfer on WebRTC.
    peer_direct: bool,
    /// The peer can move a live transfer to direct QUIC at a frame boundary
    /// (`handoff`, the make-before-break promotion). An older CLI advertises
    /// `direct` without this and still tears its WebRTC link down at confirm.
    peer_handoff: bool,
    /// This side will send a pairing `identity-expose` (it holds a device
    /// certificate) and re-send it until it is acknowledged. Advertised as
    /// `exposes: true` next to `expose_ack: 1` on our PAKE payloads.
    exposes: bool,
    /// The peer acknowledges a pairing `identity-expose` (`expose_ack: 1`).
    /// A 0.9.1 CLI and the browser do not: facing them the frame is sent the
    /// old way, once, and nothing waits for an answer they never send.
    peer_expose_ack: bool,
    /// The peer said it will send an `identity-expose` (`exposes: true`), so
    /// a pairing that ends without its certificate is a failure, not a
    /// pairing with an uncertified device.
    peer_exposes: bool,
}

/// Who a pairing ceremony should run with, given one inbound PAKE payload.
///
/// A claimer joins the code creator's ROOM, and everyone else on that network
/// is in the room too. Binding the ceremony to the first link that came up let
/// a bystander (another browser tab, another device on the same Wi-Fi) take
/// the creator's place: our element went to it, the creator never heard from
/// us, and pairing stalled about one time in four. The creator's own element
/// names our nameplate, so it identifies the real partner.
#[derive(Debug, PartialEq, Eq)]
pub enum Partner {
    /// From the peer we are bound to (or nobody yet): feed the ceremony.
    Ours,
    /// The real partner, and we bound a bystander: switch and resend.
    Switch,
    /// Another code's ceremony, or a stray after K: not ours, ignore it.
    Ignore,
}

/// Pure: see [`Partner`]. `addressed` is [`addressed_to`] for our nameplate
/// (None for an untagged payload from an old peer, treated as ours).
pub fn partner_for(
    bound: Option<&str>,
    from: &str,
    is_msg: bool,
    addressed: Option<bool>,
    has_k: bool,
) -> Partner {
    if addressed == Some(false) {
        return Partner::Ignore;
    }
    match bound {
        None => Partner::Ours,
        Some(b) if b == from => Partner::Ours,
        Some(_) if is_msg && addressed == Some(true) && !has_k => Partner::Switch,
        Some(_) => Partner::Ignore,
    }
}

/// Is this PAKE payload for the ceremony on `nameplate`? `Some(true)` when the
/// payload names our nameplate, `Some(false)` when it names a DIFFERENT one
/// (another code's ceremony sharing the room: never ours to answer or to fail
/// on), `None` when it names none (a build that predates the tag). Pure.
pub fn addressed_to(data: &Value, nameplate: &str) -> Option<bool> {
    data["np"].as_str().map(|np| np == nameplate)
}

impl Ceremony {
    /// Begin a symmetric SPAKE2 ceremony. `password` is the spoken words,
    /// `nameplate` the numeric routing suffix. Both sides MUST pass identical
    /// password AND nameplate (the SPAKE2 identity) or they derive different K.
    /// `scope` is the introduction scope byte (0x00 User-scoped "reach me",
    /// 0x01 Device-scoped), MANDATORY, derived from the authenticated
    /// introduction token (or the fixed convention for plain pair). Both sides
    /// must pass the SAME scope byte or confirmation fails (confused-deputy
    /// prevention). There is no default: every production call site must
    /// explicitly pass the scope it derived from the token.
    pub fn new(password: &str, nameplate: &str, caps: Vec<String>, scope: u8) -> Self {
        let caps_canon = filament_pair::canonical_caps(&caps);
        let (state, msg) = filament_pair::start(password.as_bytes(), nameplate.as_bytes());
        Ceremony {
            confirmed_fingerprints: None,
            temporary: None,
            caps,
            caps_canon,
            scope,
            state: Some(state),
            msg,
            k: None,
            secret: None,
            aborted: None,
            sent_msg: false,
            sent_confirm: false,
            resend: Resend::default(),
            nameplate: nameplate.to_string(),
            peer_direct: false,
            peer_handoff: false,
            exposes: false,
            peer_expose_ack: false,
            peer_exposes: false,
        }
    }

    /// Say, on our PAKE payloads, whether this side will send a pairing
    /// `identity-expose`. Set before the first payload goes out; every copy of
    /// a payload is then the same bytes. Not used by a temporary ceremony.
    pub fn set_exposes(&mut self, exposes: bool) {
        self.exposes = exposes;
    }

    /// Whether the peer acknowledges a pairing `identity-expose`.
    pub fn peer_acks_expose(&self) -> bool {
        self.peer_expose_ack
    }

    /// Whether the peer acknowledges `identity-expose` AND said it will send
    /// one: its certificate must arrive before this pairing can succeed.
    pub fn peer_will_expose(&self) -> bool {
        self.peer_expose_ack && self.peer_exposes
    }

    /// The identity-expose advertisement (`expose_ack`, `exposes`) on a
    /// standing pairing's PAKE payloads. A temporary ceremony refuses
    /// identity frames, so it advertises nothing.
    fn advertise_expose(&self, mut payload: Value) -> Value {
        if self.temporary.is_none() {
            payload["expose_ack"] = json!(1);
            if self.exposes {
                payload["exposes"] = json!(true);
            }
        }
        payload
    }

    /// Explicit opt-in. No temporary-to-standing fallback is possible: purpose
    /// metadata is checked and the purpose/digest are also inside the PAKE MAC.
    pub fn new_temporary(password: &str, nameplate: &str, binding: TemporaryBinding, role: TemporaryRole) -> Self {
        let bytes = serde_json::to_vec(&binding).expect("binding serialization");
        let digest = ring::digest::digest(&ring::digest::SHA256, &bytes);
        let caps = vec![format!("temporary-access-v1:{}", hex::encode(digest.as_ref()))];
        let mut ceremony = Self::new(password, nameplate, caps, 0x01);
        ceremony.temporary = Some((binding, role));
        ceremony
    }

    pub fn temporary_binding(&self) -> Option<&TemporaryBinding> {
        self.temporary.as_ref().map(|(binding, _)| binding)
    }

    /// Used by the embedding handoff to pin this completed ceremony to the
    /// exact existing transport link. No caller-supplied trusted flag suffices.
    pub fn confirmed_temporary_transport(&self, mine: &str, theirs: &str) -> bool {
        self.temporary.is_some() && self.secret.is_some() && self.aborted.is_none() && self.sent_confirm
            && self.confirmed_fingerprints.as_ref().is_some_and(|(a,b)|a==mine && b==theirs)
    }

    pub fn temporary_role(&self) -> Option<TemporaryRole> { self.temporary.as_ref().map(|(_,role)|*role) }

    fn decorate(&self, mut payload: Value) -> Value {
        if let Some((binding, role)) = &self.temporary {
            payload["purpose"] = json!("temporary-access-v1");
            payload["access_binding"] = json!(binding);
            payload["access_role"] = json!(role.wire());
        }
        payload
    }

    fn confirm_canon(&self, my_fp: &str, their_fp: &str) -> String {
        match &self.temporary {
            None => self.caps_canon.clone(),
            Some((_, role)) => {
                let (host, recipient) = match role { TemporaryRole::Host => (my_fp, their_fp), TemporaryRole::Recipient => (their_fp, my_fp) };
                // Role mapping is authenticated, not merely an unsigned relay field.
                format!("{}|roles:{}", self.caps_canon, serde_json::to_string(&(host,recipient)).expect("fingerprints"))
            }
        }
    }

    /// Sign only after mutual PAKE confirmation. This challenge binds possession
    /// to this PAKE session, purpose, role and both device keys; it reveals no K.
    pub fn temporary_possession_message(&self, sender: [u8;32], receiver: [u8;32]) -> Result<Vec<u8>, crate::access::AccessError> {
        let Some((binding, role)) = &self.temporary else { return Err(crate::access::AccessError::Unsupported); };
        if self.secret.is_none() || self.aborted.is_some() { return Err(crate::access::AccessError::NotAccepted); }
        if sender == receiver { return Err(crate::access::AccessError::InvalidProof); }
        let k = self.k.as_ref().ok_or(crate::access::AccessError::NotAccepted)?;
        let session = ring::digest::digest(&ring::digest::SHA256, k);
        let host = match role { TemporaryRole::Host => sender, TemporaryRole::Recipient => receiver };
        if binding.host_peer != host { return Err(crate::access::AccessError::WrongPeer); }
        serde_json::to_vec(&("tunlion/temporary-possession/v1", binding, session.as_ref(), role.wire(), sender, receiver))
            .map_err(|_| crate::access::AccessError::InvalidSpec)
    }

    pub fn authenticate_temporary_peer(&self, local: [u8;32], peer: [u8;32], signature: [u8;64])
        -> Result<crate::access::ProvenPeer, crate::access::AccessError> {
        let Some((binding, role)) = &self.temporary else { return Err(crate::access::AccessError::Unsupported); };
        if self.secret.is_none() || self.aborted.is_some() { return Err(crate::access::AccessError::NotAccepted); }
        if local == peer { return Err(crate::access::AccessError::InvalidProof); }
        let host = match role { TemporaryRole::Host => local, TemporaryRole::Recipient => peer };
        if binding.host_peer != host { return Err(crate::access::AccessError::WrongPeer); }
        let session = ring::digest::digest(&ring::digest::SHA256, self.k.as_ref().ok_or(crate::access::AccessError::NotAccepted)?);
        let bytes = serde_json::to_vec(&("tunlion/temporary-possession/v1", binding, session.as_ref(), role.opposite().wire(), peer, local))
            .map_err(|_| crate::access::AccessError::InvalidSpec)?;
        filament_id::verify_possession_sig(&peer, &bytes, &signature).map_err(|_| crate::access::AccessError::InvalidProof)?;
        Ok(crate::access::ProvenPeer::from_temporary_proof(peer, binding.offer_digest))
    }

    /// A control payload on the existing proven transport, not a new channel.
    /// Its signature must be over `temporary_possession_message(sender,receiver)`.
    pub fn temporary_proof_payload(&self, sender: [u8;32], receiver: [u8;32], signature: [u8;64])
        -> Result<Value, crate::access::AccessError> {
        let message = self.temporary_possession_message(sender, receiver)?;
        filament_id::verify_possession_sig(&sender, &message, &signature).map_err(|_| crate::access::AccessError::InvalidProof)?;
        Ok(json!({"type":"access-possession", "v":1, "peer":hex::encode(sender), "signature":hex::encode(signature)}))
    }

    pub fn authenticate_temporary_payload(&self, local: [u8;32], payload: &Value)
        -> Result<crate::access::ProvenPeer, crate::access::AccessError> {
        if payload["type"].as_str() != Some("access-possession") || payload["v"].as_u64() != Some(1) {
            return Err(crate::access::AccessError::Unsupported);
        }
        let decode = |field: &str, size: usize| -> Result<Vec<u8>, crate::access::AccessError> {
            let value = payload[field].as_str().ok_or(crate::access::AccessError::InvalidProof)?;
            if value.len() != size * 2 { return Err(crate::access::AccessError::InvalidProof); }
            hex::decode(value).map_err(|_| crate::access::AccessError::InvalidProof)
        };
        let key = decode("peer", 32)?.try_into().map_err(|_| crate::access::AccessError::InvalidProof)?;
        let signature = decode("signature", 64)?.try_into().map_err(|_| crate::access::AccessError::InvalidProof)?;
        self.authenticate_temporary_peer(local, key, signature)
    }

    /// Recipient-side gate before showing an actionable full scope review.
    pub fn review_temporary_offer(&self, snapshot: crate::access::AgreementSnapshot, host_signature: [u8;64],
        local_peer: [u8;32], now: u64) -> Result<crate::access::AuthenticatedReview, crate::access::AccessError> {
        let Some((binding, TemporaryRole::Recipient)) = &self.temporary else { return Err(crate::access::AccessError::Unsupported); };
        if self.secret.is_none() || self.aborted.is_some() { return Err(crate::access::AccessError::NotAccepted); }
        crate::access::AuthenticatedReview::verify(binding, snapshot, host_signature, local_peer, now)
    }

    /// Re-mint with a FRESH nameplate (and optionally fresh words) after a
    /// server `taken` collision. Resets the session and the sent-flag so the new
    /// element goes out. The caller re-emits `pair-create {nameplate}`.
    /// Scope is preserved (same introduction).
    pub fn restart(&mut self, password: &str, nameplate: &str) {
        let (state, msg) = filament_pair::start(password.as_bytes(), nameplate.as_bytes());
        self.nameplate = nameplate.to_string();
        self.state = Some(state);
        self.msg = msg;
        self.k = None;
        self.secret = None;
        self.confirmed_fingerprints = None;
        self.aborted = None;
        self.sent_msg = false;
        self.sent_confirm = false;
        self.resend = Resend::default();
    }

    /// Explicitly re-mint with a new scope (if the introduction token's scope
    /// changes, which should be rare). Used only in tests for scope-downgrade.
    #[cfg(test)]
    pub fn restart_with_scope(&mut self, password: &str, nameplate: &str, scope: u8) {
        let (state, msg) = filament_pair::start(password.as_bytes(), nameplate.as_bytes());
        self.nameplate = nameplate.to_string();
        self.state = Some(state);
        self.msg = msg;
        self.scope = scope;
        self.k = None;
        self.secret = None;
        self.confirmed_fingerprints = None;
        self.aborted = None;
        self.sent_msg = false;
        self.sent_confirm = false;
        self.resend = Resend::default();
    }

    pub fn secret(&self) -> Option<&String> {
        self.secret.as_ref()
    }

    /// Our element as a `signal` payload, without marking it sent: for a
    /// claimer offering it to every peer that comes up in the room before the
    /// creator has spoken (only the creator, who holds the code, can use it).
    pub fn msg_payload(&self) -> Value {
        self.advertise_expose(self.decorate(json!({
            "type": "pake-msg", "v": 2,
            "msg": b64_encode(&self.msg),
            "np": self.nameplate,
            "direct": true,
            "handoff": 1,
        })))
    }

    /// Send our element again, to a new partner: the peer it went to was a
    /// bystander in the room, not the other side of this code. Only possible
    /// before K is derived (after that the ceremony is committed to its peer).
    /// Returns whether the send was re-armed.
    pub fn rearm_msg(&mut self) -> bool {
        if self.k.is_some() {
            return false;
        }
        self.sent_msg = false;
        true
    }
    /// The abort reason, if the ceremony was refused. Callers normally act on the
    /// `Inbound::Abort` returned by `on_signal`; this accessor is used by the
    /// module's own tests to assert the terminal state.
    #[cfg(test)]
    pub fn aborted(&self) -> Option<&String> {
        self.aborted.as_ref()
    }

    /// The opaque `signal` payload carrying our SPAKE2 element: the first time
    /// it is asked for, then again on the [`Resend`] backoff until our
    /// confirmation supersedes it (that carries the element too). The caller
    /// relays the returned JSON to the peer (`{to, data: <this>}`) and simply
    /// calls this every tick. Every copy is the same element: one SPAKE2
    /// session per ceremony, so a re-send is never another guess.
    pub fn take_msg_payload(&mut self) -> Option<Value> {
        self.take_msg_payload_at(Instant::now())
    }

    pub(crate) fn take_msg_payload_at(&mut self, now: Instant) -> Option<Value> {
        if !self.sent_msg {
            self.sent_msg = true;
            self.resend.arm(now);
        } else if self.sent_confirm || !self.unsettled() || !self.resend.due(now) {
            return None;
        }
        Some(self.msg_payload())
    }

    /// The opaque `signal` payload carrying our key-confirmation MAC, once K is
    /// derived: the first time it is asked for, then again on the [`Resend`]
    /// backoff until the peer's confirmation verifies. Needs both DTLS
    /// fingerprints (so the MAC binds them) AND the introduction scope byte (so
    /// a scope downgrade is detected). `None` until ready / between re-sends.
    pub fn take_confirm_payload(&mut self, my_fp: &str, their_fp: &str) -> Option<Value> {
        self.take_confirm_payload_at(my_fp, their_fp, Instant::now())
    }

    pub(crate) fn take_confirm_payload_at(&mut self, my_fp: &str, their_fp: &str, now: Instant) -> Option<Value> {
        self.k.as_ref()?;
        if !self.sent_confirm {
            self.sent_confirm = true;
            self.resend.arm(now);
        } else if !self.unsettled() || !self.resend.due(now) {
            return None;
        }
        self.confirm_payload(my_fp, their_fp)
    }

    /// Neither confirmed nor refused: our current message still needs re-sending.
    fn unsettled(&self) -> bool {
        self.secret.is_none() && self.aborted.is_none()
    }

    /// Our confirmation for this link. Deterministic in K, the fingerprints, the
    /// caps and the scope, so every copy (and a reply to a duplicate) is the
    /// same. It also carries our element (`msg`): a peer whose copy of the
    /// element was lost derives K from it instead of refusing a confirmation
    /// that arrived before key exchange.
    fn confirm_payload(&self, my_fp: &str, their_fp: &str) -> Option<Value> {
        let k = self.k.as_ref()?;
        // Scope byte is MANDATORY and is derived from the authenticated
        // introduction token (or the fixed convention for plain pair).
        let canon = self.confirm_canon(my_fp, their_fp);
        let mac = filament_pair::our_confirm(k, my_fp, their_fp, &canon, self.scope);
        Some(self.advertise_expose(self.decorate(json!({
            "type": "pake-confirm", "v": 2,
            "mac": b64_encode(&mac),
            "msg": b64_encode(&self.msg),
            "caps": self.caps.clone(),
            "scope": self.scope,
            "np": self.nameplate,
        }))))
    }

    /// Whether K has been derived (the peer's element was consumed).
    pub fn has_k(&self) -> bool {
        self.k.is_some()
    }

    /// Borrow K if derived (for sealing identity-expose).
    pub fn k(&self) -> Option<&Vec<u8>> {
        self.k.as_ref()
    }

    /// Whether the peer can take a direct QUIC connection. False for a
    /// browser: callers must then keep the WebRTC link instead of promoting.
    pub fn peer_supports_direct(&self) -> bool {
        self.peer_direct
    }

    /// Whether the peer runs the make-before-break promotion. Without it the
    /// promotion must behave as the peer expects (tear down at confirm), or
    /// the peer's teardown and our handoff would race on a dying link.
    pub fn peer_supports_handoff(&self) -> bool {
        self.peer_direct && self.peer_handoff
    }

    /// Scope byte (mandatory, no default).
    pub fn scope(&self) -> u8 {
        self.scope
    }

    /// Canonical caps string (for possession binding).
    pub fn caps_canon(&self) -> &str {
        &self.caps_canon
    }

    /// Feed an inbound `signal` payload. PAKE messages are consumed; SDP/ICE is
    /// ignored (falls through to the WebRTC path). A `pake-confirm` carries the
    /// fingerprints to verify against (the caller supplies the link's current
    /// fingerprints). On a verified confirm the secret is derived.
    pub fn on_signal(&mut self, data: &Value, fps: Option<(&str, &str)>) -> Inbound {
        if matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm")) {
            let matches = match &self.temporary {
                None => data.get("purpose").is_none() && data.get("access_binding").is_none(),
                Some((binding, role)) => data["purpose"].as_str() == Some("temporary-access-v1")
                    && data["access_role"].as_str() == Some(role.opposite().wire())
                    && serde_json::from_value::<TemporaryBinding>(data["access_binding"].clone()).ok().as_ref() == Some(binding),
            };
            if !matches {
                self.aborted = Some("pairing purpose/binding mismatch".into());
                self.secret = None;
                return Inbound::Abort("pairing purpose/binding mismatch; temporary access cannot fall back to standing pairing".into());
            }
        }
        if self.aborted.is_some() { return Inbound::Abort("ceremony already aborted".into()); }
        if matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm"))
            && data["direct"].as_bool() == Some(true)
        {
            self.peer_direct = true;
            if data["handoff"].as_u64() == Some(1) {
                self.peer_handoff = true;
            }
        }
        // Read from either payload: the confirmation is re-sent until it
        // verifies, so by the time a secret is agreed a copy carrying the
        // advertisement has arrived even if every element copy was lost.
        if self.temporary.is_none() && matches!(data["type"].as_str(), Some("pake-msg") | Some("pake-confirm")) {
            if data["expose_ack"].as_u64() == Some(1) {
                self.peer_expose_ack = true;
                if data["exposes"].as_bool() == Some(true) {
                    self.peer_exposes = true;
                }
            }
        }
        match data["type"].as_str() {
            // A re-sent element after K is a no-op: K comes from the FIRST
            // element only (the SPAKE2 session is consumed), so neither a copy
            // nor a different element can buy another guess.
            Some("pake-msg") => match self.absorb_element(data) {
                Ok(()) => Inbound::Consumed,
                Err(abort) => abort,
            },
            Some("pake-confirm") => {
                // Our copy of the peer's element was lost: its confirmation
                // carries the same element, so derive K from that first.
                if self.k.is_none() && data.get("msg").is_some() {
                    if let Err(abort) = self.absorb_element(data) {
                        return abort;
                    }
                }
                let Some(k) = self.k.clone() else {
                    return Inbound::Abort(
                        "confirmation arrived before key exchange (abort)".to_string(),
                    );
                };
                let recv_mac = data["mac"].as_str().and_then(b64_decode).unwrap_or_default();
                // Without this link's fingerprints there is nothing to verify the
                // MAC against yet. Verify nothing, agree nothing: the peer re-sends
                // its confirmation until ours arrives, and a later copy is checked.
                let Some((my_fp, their_fp)) = fps else {
                    return Inbound::Consumed;
                };
                // We MAC against OUR fixed caps + scope, so a server that rewrites the
                // relayed `caps` or `scope` field cannot make the MAC verify. Scope
                // byte is read from the authenticated token, not a local guess.
                let verified = filament_pair::verify_peer_confirm(
                    &k,
                    my_fp,
                    their_fp,
                    &self.confirm_canon(my_fp, their_fp),
                    self.scope,
                    &recv_mac,
                );
                // Already confirmed: this is a re-send, so the peer has not heard
                // our confirmation. Answer with the same one, marked `answer` so
                // a peer that is itself confirmed never answers back (two
                // confirmed sides would otherwise ping-pong). It is never a second
                // attempt: the outcome was fixed by the first verification, and a
                // copy that does not verify (an old link's) changes nothing.
                if self.secret.is_some() {
                    if !verified || data["answer"].as_bool() == Some(true) {
                        return Inbound::Consumed;
                    }
                    self.sent_confirm = true;
                    return match self.confirm_payload(my_fp, their_fp) {
                        Some(mut reply) => {
                            reply["answer"] = json!(true);
                            Inbound::Reply(reply)
                        }
                        None => Inbound::Consumed,
                    };
                }
                if verified {
                    self.secret = Some(filament_pair::secret_from_k(&k));
                    self.confirmed_fingerprints = Some((my_fp.to_string(), their_fp.to_string()));
                    Inbound::Consumed
                } else {
                    self.aborted = Some("key confirmation failed".to_string());
                    Inbound::Abort(
                        "key confirmation failed: wrong code, or the connection is being tampered with (a server cannot forge this)".to_string(),
                    )
                }
            }
            _ => Inbound::Ignored,
        }
    }

    /// Derive K from the peer's element (`data["msg"]`), once. Later copies are
    /// no-ops: the SPAKE2 session is consumed by the first.
    fn absorb_element(&mut self, data: &Value) -> Result<(), Inbound> {
        if self.k.is_none() {
            if let Some(state) = self.state.take() {
                let peer_el = data["msg"].as_str().and_then(b64_decode).unwrap_or_default();
                match filament_pair::finish(state, &peer_el) {
                    Some(k) => self.k = Some(k),
                    None => {
                        return Err(Inbound::Abort(
                            "malformed key-exchange message (abort)".to_string(),
                        ))
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_pair(binding: TemporaryBinding) -> (Ceremony, Ceremony) {
        let mut a = Ceremony::new_temporary("correct horse", "1234", binding.clone(), TemporaryRole::Host);
        let mut b = Ceremony::new_temporary("correct horse", "1234", binding, TemporaryRole::Recipient);
        let am = a.take_msg_payload().unwrap(); let bm = b.take_msg_payload().unwrap();
        assert!(matches!(a.on_signal(&bm, None), Inbound::Consumed));
        assert!(matches!(b.on_signal(&am, None), Inbound::Consumed));
        let ac = a.take_confirm_payload("host-fp", "recipient-fp").unwrap();
        let bc = b.take_confirm_payload("recipient-fp", "host-fp").unwrap();
        assert!(matches!(a.on_signal(&bc, Some(("host-fp", "recipient-fp"))), Inbound::Consumed));
        assert!(matches!(b.on_signal(&ac, Some(("recipient-fp", "host-fp"))), Inbound::Consumed));
        assert!(a.secret().is_some()); assert_eq!(a.secret(), b.secret());
        (a,b)
    }

    #[test]
    fn temporary_purpose_cannot_downgrade_or_swap_binding_or_roles() {
        let binding = TemporaryBinding::new([1;32], &crate::access::AccessSpec::default(), crate::access::Lifetime::UntilEnded, 100).unwrap();
        let mut temp = Ceremony::new_temporary("pw", "1234", binding.clone(), TemporaryRole::Host);
        let mut legacy = Ceremony::new("pw", "1234", pair_v2_caps(), 1);
        assert!(matches!(legacy.on_signal(&temp.msg_payload(), None), Inbound::Abort(_)));
        assert!(matches!(temp.on_signal(&legacy.msg_payload(), None), Inbound::Abort(_)));
        let mut other = binding.clone(); other.revision += 1;
        let mut host = Ceremony::new_temporary("pw", "1234", binding.clone(), TemporaryRole::Host);
        let recipient = Ceremony::new_temporary("pw", "1234", other, TemporaryRole::Recipient);
        assert!(matches!(host.on_signal(&recipient.msg_payload(), None), Inbound::Abort(_)));
        let mut host = Ceremony::new_temporary("pw", "1234", binding.clone(), TemporaryRole::Host);
        let same_role = Ceremony::new_temporary("pw", "1234", binding.clone(), TemporaryRole::Host);
        assert!(matches!(host.on_signal(&same_role.msg_payload(), None), Inbound::Abort(_)));
        // Rewriting the unsigned role marker cannot bypass authenticated role mapping.
        let mut a = Ceremony::new_temporary("pw", "1234", binding.clone(), TemporaryRole::Host);
        let mut b = Ceremony::new_temporary("pw", "1234", binding, TemporaryRole::Host);
        let mut am = a.msg_payload(); let mut bm = b.msg_payload();
        am["access_role"] = json!("recipient"); bm["access_role"] = json!("recipient");
        a.on_signal(&bm, None); b.on_signal(&am, None);
        let mut confirm = b.take_confirm_payload("b", "a").unwrap(); confirm["access_role"] = json!("recipient");
        assert!(matches!(a.on_signal(&confirm, Some(("a", "b"))), Inbound::Abort(_)));
        assert!(a.secret().is_none());
    }

    #[test]
    fn real_two_party_temporary_pake_possession_full_review_acceptance_and_end() {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        use crate::access::{AccessSpec, AgreementEngine, AccessError, Lifetime, ServiceAccess, ServiceProtocol};
        let make_key = || {
            let bytes = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
            Ed25519KeyPair::from_pkcs8(bytes.as_ref()).unwrap()
        };
        let host = make_key(); let recipient = make_key();
        let hp: [u8;32] = host.public_key().as_ref().try_into().unwrap();
        let rp: [u8;32] = recipient.public_key().as_ref().try_into().unwrap();
        let spec = AccessSpec { services: vec![ServiceAccess { id: "web".into(), target: "127.0.0.1:8080".parse().unwrap(), protocol: ServiceProtocol::Tcp }], ..AccessSpec::default() };
        let binding = TemporaryBinding::new(hp, &spec, Lifetime::UntilEnded, 100).unwrap();
        let (a,b) = temporary_pair(binding.clone());
        let (different_session, _) = temporary_pair(binding.clone());
        let recipient_msg = b.temporary_possession_message(rp, hp).unwrap();
        let recipient_sig: [u8;64] = recipient.sign(&recipient_msg).as_ref().try_into().unwrap();
        let proven_recipient = a.authenticate_temporary_peer(hp, rp, recipient_sig).unwrap();
        assert_eq!(different_session.authenticate_temporary_peer(hp, rp, recipient_sig).err(), Some(AccessError::InvalidProof));
        assert_eq!(a.authenticate_temporary_peer(hp, hp, recipient_sig).err(), Some(AccessError::InvalidProof));
        let host_msg = a.temporary_possession_message(hp, rp).unwrap();
        let host_sig = host.sign(&host_msg).as_ref().try_into().unwrap();
        assert_eq!(b.authenticate_temporary_peer(rp, hp, host_sig).unwrap().public_key(), hp);
        let engine = AgreementEngine::new(hp, Vec::new());
        let s = engine.offer_bound(proven_recipient, &binding, "existing-hostname", spec.clone(), Lifetime::UntilEnded, 100, 10).unwrap();
        assert_eq!(engine.offer_bound(proven_recipient, &binding, "existing-hostname", spec, Lifetime::UntilEnded, 100, 10).err(), Some(AccessError::InvalidProof));
        let review_sig = host.sign(&engine.review_message(&s.id, 1, 10).unwrap()).as_ref().try_into().unwrap();
        let review = b.review_temporary_offer(s.clone(), review_sig, rp, 10).unwrap();
        assert_eq!(review.snapshot(), &s);
        let mut altered = s.clone(); altered.spec.shell = true;
        assert!(b.review_temporary_offer(altered, review_sig, rp, 10).is_err());
        let signature = recipient.sign(&review.acceptance_message().unwrap()).as_ref().try_into().unwrap();
        engine.accept(&s.id, 1, proven_recipient, signature, 10).unwrap();
        engine.end(&s.id, 11).unwrap();
        assert_eq!(engine.accept(&s.id, 1, proven_recipient, signature, 12).err(), Some(AccessError::Ended));
    }

    fn fps_for(a_is_lo: bool) -> ((&'static str, &'static str), (&'static str, &'static str)) {
        // Distinct fingerprints; each side passes (mine, theirs).
        let a = "SHA-256 AA:BB:CC";
        let b = "SHA-256 DD:EE:FF";
        if a_is_lo {
            ((a, b), (b, a))
        } else {
            ((a, b), (b, a))
        }
    }

    // Run a full two-party ceremony in process and return both outcomes.
    // Scope is MANDATORY: for plain pair (device-to-device) both sides use
    // Device-scoped (0x01), derived from the fixed convention for pair.
    // Scope byte is read from the authenticated token, not a local guess.
    fn run_pair(pw_a: &str, pw_b: &str, np: &str) -> (Ceremony, Ceremony) {
        // Fixed convention for plain pair: Device-scoped (device-to-device).
        // Both sides derive scope from the authenticated token, so honest ends match.
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new(pw_a, np, pair_v2_caps(), scope);
        let mut b = Ceremony::new(pw_b, np, pair_v2_caps(), scope);
        let ((a_mine, a_theirs), (b_mine, b_theirs)) = fps_for(true);

        // Exchange elements.
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        assert!(matches!(b.on_signal(&a_msg, None), Inbound::Consumed));
        assert!(matches!(a.on_signal(&b_msg, None), Inbound::Consumed));
        assert!(a.has_k() && b.has_k());

        // Exchange confirms (each binds its OWN fingerprint view).
        let a_conf = a.take_confirm_payload(a_mine, a_theirs).unwrap();
        let b_conf = b.take_confirm_payload(b_mine, b_theirs).unwrap();
        let _ = b.on_signal(&a_conf, Some((b_mine, b_theirs)));
        let _ = a.on_signal(&b_conf, Some((a_mine, a_theirs)));
        (a, b)
    }

    #[test]
    fn honest_ceremony_agrees_same_secret() {
        let (a, b) = run_pair("brave-otter", "brave-otter", "314");
        assert!(a.secret().is_some(), "A agreed a secret");
        assert!(b.secret().is_some(), "B agreed a secret");
        assert_eq!(a.secret(), b.secret(), "both sides agree the SAME secret");
        assert_eq!(a.secret().unwrap().len(), 64);
        assert!(a.aborted().is_none() && b.aborted().is_none());
    }

    #[test]
    fn wrong_password_aborts_no_secret() {
        let (a, b) = run_pair("brave-otter", "tidy-walrus", "314");
        // Different passwords -> different K -> confirmation fails on both sides.
        assert!(a.secret().is_none(), "A agrees nothing on a wrong code");
        assert!(b.secret().is_none(), "B agrees nothing on a wrong code");
        assert!(a.aborted().is_some() || b.aborted().is_some());
    }

    #[test]
    fn fingerprint_mismatch_aborts() {
        // A server-substituted DTLS cert => the two sides see different peer
        // fingerprints => confirmation MAC fails => abort, no secret.
        // Scope: fixed convention Device-scoped for plain pair, derived from token.
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut b = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        // A's view: own=AA, peer=MITM_A. B's view: own=BB, peer=MITM_B.
        let a_conf = a.take_confirm_payload("SHA-256 AA", "SHA-256 MITM-A").unwrap();
        let r = b.on_signal(&a_conf, Some(("SHA-256 BB", "SHA-256 MITM-B")));
        assert!(matches!(r, Inbound::Abort(_)));
        assert!(b.secret().is_none());
    }

    #[test]
    fn confirm_before_key_exchange_aborts() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let stray = json!({ "type": "pake-confirm", "v": 2, "mac": b64_encode(&[0u8; 32]), "caps": ["transfer"] });
        let r = a.on_signal(&stray, Some(("SHA-256 AA", "SHA-256 BB")));
        assert!(matches!(r, Inbound::Abort(_)));
    }

    #[test]
    fn non_pake_signal_is_ignored() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let sdp = json!({ "type": "description", "description": { "type": "offer" } });
        assert!(matches!(a.on_signal(&sdp, None), Inbound::Ignored));
    }


    #[test]
    fn b64_roundtrips() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(b64_decode(&b64_encode(&data)).unwrap(), data);
        }
    }

    // ---- Gate #2 (server-can't-derive): NEGATIVE security test ----
    // A relay/MITM that does NOT know the password cannot derive K and cannot
    // silently substitute its own key. It runs its own SPAKE2 under a WRONG
    // password, injects its element toward A, and the confirmation MAC MUST
    // fail on A's side, agreeing ZERO secret. Per the ledger rule, an auth
    // feature is VERIFIED only if this negative test exists.
    #[test]
    fn gate2_spake2_substitution_detected() {
        // Honest A and B with the same password. A fake relay (C) does NOT know
        // the password; it guesses wrong and substitutes ITS element for B's
        // when forwarding to A. A must detect the tampering and abort.
        let pw_a = "brave-otter";
        let np = "314";
        let caps = pair_v2_caps();
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new(pw_a, np, caps.clone(), scope);
        let mut b = Ceremony::new(pw_a, np, caps.clone(), scope);
        // The fake relay C runs its own SPAKE2 with a GUESSED password.
        let relay_pw = "tidy-walrus"; // wrong password
        let mut relay = Ceremony::new(relay_pw, np, caps, scope);

        // A sends its element; relay receives it for forwarding.
        let a_msg = a.take_msg_payload().unwrap();
        // B sends its element; relay intercepts it.
        let b_msg = b.take_msg_payload().unwrap();
        // Relay sends its OWN element (under wrong password) to A.
        let relay_msg = relay.take_msg_payload().unwrap();

        // A receives the relay's (forged) element instead of B's.
        assert!(matches!(a.on_signal(&relay_msg, None), Inbound::Consumed));
        assert!(a.has_k(), "A derived K from the forged element (different K)");

        // B receives A's element honestly.
        assert!(matches!(b.on_signal(&a_msg, None), Inbound::Consumed));
        assert!(b.has_k(), "B derived K from A's element");

        // Now the confirmation step. Both sides have different K.
        let a_conf = a.take_confirm_payload("SHA-256 A", "SHA-256 MITM").unwrap();
        // B verifies A's confirm under B's OWN K. Since K differs, it MUST fail.
        let r = b.on_signal(&a_conf, Some(("SHA-256 B", "SHA-256 A")));
        // The MITM substitution must be DETECTED: confirmation fails.
        assert!(matches!(r, Inbound::Abort(_)), "Gate #2 BROKEN: MITM substitution undetected, {r:?}");
        assert!(b.secret().is_none(), "Gate #2 BROKEN: B agreed a secret despite MITM");
        assert!(b.aborted().is_some(), "Gate #2: confirmed abort flag is set");
        // A also has no secret (the relay never completed the ceremony).
        assert!(a.secret().is_none(), "Gate #2: A agreed nothing (ceremony incomplete)");
    }

    // ---- Gate #2b: relay cannot derive the password from relayed bytes ----
    // The password NEVER appears in any relayed payload (spec gate:relay-blind).
    #[test]
    fn gate2b_password_never_in_relayed_payloads() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut b = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        // The password "brave-otter" must not appear in either payload.
        for payload in &[&a_msg, &b_msg] {
            let s = serde_json::to_string(payload).unwrap();
            assert!(!s.contains("brave-otter"), "Gate #2b BROKEN: password leaked in payload: {s}");
        }
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        let a_conf = a.take_confirm_payload("SHA-256 A", "SHA-256 B").unwrap();
        let b_conf = b.take_confirm_payload("SHA-256 B", "SHA-256 A").unwrap();
        for payload in &[&a_conf, &b_conf] {
            let s = serde_json::to_string(payload).unwrap();
            assert!(!s.contains("brave-otter"), "Gate #2b BROKEN: password leaked in confirm payload: {s}");
        }
    }

    #[test]
    fn scope_downgrade_detected() {
        let pw = "brave-otter";
        let np = "314";
        let caps = pair_v2_caps();
        let scope_user = filament_id::IntroScope::User.to_byte();
        let scope_device = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new(pw, np, caps.clone(), scope_user);
        let mut b = Ceremony::new(pw, np, caps.clone(), scope_device);
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        let a_conf = a.take_confirm_payload("SHA-256 AA", "SHA-256 BB").unwrap();
        let r = b.on_signal(&a_conf, Some(("SHA-256 BB", "SHA-256 AA")));
        assert!(matches!(r, Inbound::Abort(_)), "scope downgrade must be detected");
        assert!(b.secret().is_none());
    }

    // Two concurrent codes on one device share a room. Every payload names its
    // nameplate, so a peer can tell another code's ceremony from its own
    // without running it (the concurrent-send defect: a receiver of code 1
    // handshook with code 2's sender, which then refused its own transfer).
    #[test]
    fn a_bystander_bound_at_link_up_gives_way_to_the_real_partner() {
        // Bound to a bystander; the creator's element names our nameplate.
        assert_eq!(partner_for(Some("desk"), "phone", true, Some(true), false), Partner::Switch);
        // The same from the peer we are bound to.
        assert_eq!(partner_for(Some("phone"), "phone", true, Some(true), false), Partner::Ours);
        // Another code's ceremony never feeds ours.
        assert_eq!(partner_for(Some("phone"), "other", true, Some(false), false), Partner::Ignore);
        assert_eq!(partner_for(None, "other", true, Some(false), false), Partner::Ignore);
        // Once K is derived the ceremony is committed.
        assert_eq!(partner_for(Some("phone"), "desk", true, Some(true), true), Partner::Ignore);
        // A confirm from someone else is never a reason to switch.
        assert_eq!(partner_for(Some("phone"), "desk", false, Some(true), false), Partner::Ignore);
        // Nobody bound yet: the first speaker is ours (old untagged peers too).
        assert_eq!(partner_for(None, "phone", true, None, false), Partner::Ours);
        // Re-arming our element works only before K.
        let (mut a, mut b) = (
            Ceremony::new("pw", "314", pair_v2_caps(), 1),
            Ceremony::new("pw", "314", pair_v2_caps(), 1),
        );
        assert!(a.take_msg_payload().is_some());
        assert!(a.take_msg_payload().is_none());
        assert!(a.rearm_msg());
        assert!(a.take_msg_payload().is_some());
        let bm = b.take_msg_payload().unwrap();
        a.on_signal(&bm, None);
        assert!(!a.rearm_msg());
    }

    #[test]
    fn payloads_name_their_nameplate() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut b = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        assert_eq!(addressed_to(&a_msg, "314"), Some(true));
        assert_eq!(addressed_to(&a_msg, "2718"), Some(false));
        assert_eq!(addressed_to(&json!({"type": "pake-msg"}), "314"), None);
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        let conf = a.take_confirm_payload("SHA-256 A", "SHA-256 B").unwrap();
        assert_eq!(addressed_to(&conf, "314"), Some(true));
        assert_eq!(addressed_to(&conf, "999"), Some(false));
        // A restart on a fresh nameplate re-tags.
        let mut c = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        c.restart("brave-otter", "4242");
        let c_msg = c.take_msg_payload().unwrap();
        assert_eq!(addressed_to(&c_msg, "4242"), Some(true));
        assert_eq!(addressed_to(&c_msg, "314"), Some(false));
    }

    /// Two CLIs tell each other they can go direct; a browser's payloads carry
    /// no `direct` field, so a CLI facing one keeps the WebRTC link.
    #[test]
    fn only_a_peer_that_says_so_is_promoted_to_direct() {
        let (a, b) = run_pair("brave-otter", "brave-otter", "314");
        assert!(a.peer_supports_direct() && b.peer_supports_direct());

        let scope = filament_id::IntroScope::Device.to_byte();
        let mut cli = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut browser_side = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut from_browser = browser_side.take_msg_payload().unwrap();
        from_browser.as_object_mut().unwrap().remove("direct");
        assert!(matches!(cli.on_signal(&from_browser, None), Inbound::Consumed));
        assert!(!cli.peer_supports_direct());
    }

    // ---- C30: the ceremony over a relay that loses or repeats frames --------

    #[derive(Clone, Copy, PartialEq)]
    enum Fate {
        Deliver,
        Drop,
        Twice,
    }

    const A_FPS: (&str, &str) = ("SHA-256 AA", "SHA-256 BB");
    const B_FPS: (&str, &str) = ("SHA-256 BB", "SHA-256 AA");

    /// Drive two ceremonies the way the event loops do (each tick: take our
    /// element, then our confirmation; deliver what the relay lets through;
    /// relay any `Reply` back), in REAL time on a 10 ms tick, until both settle
    /// or `bound` passes. `fate(side, kind, n)` decides the n-th (1-based) copy
    /// of `kind` sent by `side`. Uses only the drivers' API, so it runs the
    /// same against a build without re-sends. Returns the elapsed time and
    /// every payload each side put on the wire.
    fn run_lossy(
        a: &mut Ceremony,
        b: &mut Ceremony,
        fate: impl Fn(char, &str, usize) -> Fate,
        bound: std::time::Duration,
    ) -> (std::time::Duration, Vec<Value>, Vec<Value>) {
        let started = std::time::Instant::now();
        let mut wire: (Vec<Value>, Vec<Value>) = (Vec::new(), Vec::new());
        let mut counts = std::collections::HashMap::<(char, String), usize>::new();
        let mut queue: std::collections::VecDeque<(char, Value)> = Default::default();
        let mut send = |side: char, v: Value, queue: &mut std::collections::VecDeque<(char, Value)>, wire: &mut (Vec<Value>, Vec<Value>)| {
            let kind = v["type"].as_str().unwrap_or("").to_string();
            let n = counts.entry((side, kind.clone())).or_default();
            *n += 1;
            if side == 'a' { wire.0.push(v.clone()) } else { wire.1.push(v.clone()) }
            match fate(side, &kind, *n) {
                Fate::Drop => {}
                Fate::Deliver => queue.push_back((side, v)),
                Fate::Twice => {
                    queue.push_back((side, v.clone()));
                    queue.push_back((side, v));
                }
            }
        };
        let settled = |c: &Ceremony| c.secret().is_some() || c.aborted().is_some();
        loop {
            for (side, c, fps) in [('a', &mut *a, A_FPS), ('b', &mut *b, B_FPS)] {
                if let Some(v) = c.take_msg_payload() {
                    send(side, v, &mut queue, &mut wire);
                }
                if c.has_k() {
                    if let Some(v) = c.take_confirm_payload(fps.0, fps.1) {
                        send(side, v, &mut queue, &mut wire);
                    }
                }
            }
            while let Some((from, v)) = queue.pop_front() {
                let (to, side, fps) = if from == 'a' { (&mut *b, 'b', B_FPS) } else { (&mut *a, 'a', A_FPS) };
                if let Inbound::Reply(r) = to.on_signal(&v, Some(fps)) {
                    send(side, r, &mut queue, &mut wire);
                }
            }
            if (settled(a) && settled(b)) || started.elapsed() > bound {
                return (started.elapsed(), wire.0, wire.1);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }

    fn honest() -> (Ceremony, Ceremony) {
        let scope = filament_id::IntroScope::Device.to_byte();
        (
            Ceremony::new("brave-otter", "314", pair_v2_caps(), scope),
            Ceremony::new("brave-otter", "314", pair_v2_caps(), scope),
        )
    }

    /// The observed hang: each ceremony message went out exactly once, so one
    /// lost relay frame left both sides waiting out the 60 s budget. Losing the
    /// FIRST copy of every message (both elements, both confirmations) must
    /// still confirm, in well under 3 s.
    #[test]
    fn losing_the_first_copy_of_every_ceremony_message_still_confirms_fast() {
        let (mut a, mut b) = honest();
        let (took, _, _) = run_lossy(
            &mut a,
            &mut b,
            |_, _, n| if n == 1 { Fate::Drop } else { Fate::Deliver },
            std::time::Duration::from_secs(3),
        );
        eprintln!("first copies lost: settled after {took:?}");
        assert!(a.aborted().is_none() && b.aborted().is_none(), "{:?} {:?}", a.aborted(), b.aborted());
        assert!(a.secret().is_some() && b.secret().is_some(), "no confirmation within {took:?}");
        assert_eq!(a.secret(), b.secret());
        assert!(took < std::time::Duration::from_secs(3), "took {took:?}");
    }

    /// One side's element lost, the other's delivered: the side that derived K
    /// confirms, and that confirmation reaches a peer that has no K yet. It
    /// carries the element, so the peer derives K from it instead of refusing.
    #[test]
    fn a_lost_element_is_carried_by_the_confirmation() {
        let (mut a, mut b) = honest();
        let (took, _, _) = run_lossy(
            &mut a,
            &mut b,
            |side, kind, n| if side == 'a' && kind == "pake-msg" && n == 1 { Fate::Drop } else { Fate::Deliver },
            std::time::Duration::from_secs(3),
        );
        assert!(b.aborted().is_none(), "b refused: {:?}", b.aborted());
        assert!(a.secret().is_some() && a.secret() == b.secret(), "no confirmation within {took:?}");
    }

    /// Our confirmation lost AFTER we verified the peer's: we have stopped
    /// re-sending, so the peer's re-sent confirmation must be answered.
    #[test]
    fn a_confirmed_side_answers_the_peers_resent_confirmation() {
        let (mut a, mut b) = honest();
        let (took, _, wire_b) = run_lossy(
            &mut a,
            &mut b,
            |side, kind, n| if side == 'b' && kind == "pake-confirm" && n == 1 { Fate::Drop } else { Fate::Deliver },
            std::time::Duration::from_secs(3),
        );
        assert!(a.secret().is_some() && a.secret() == b.secret(), "no confirmation within {took:?}");
        assert!(
            wire_b.iter().any(|v| v["answer"].as_bool() == Some(true)),
            "b answered a's re-sent confirmation"
        );
    }

    /// Every frame delivered twice: idempotent on both sides, one K, no abort,
    /// and a copy is never counted as a second attempt.
    #[test]
    fn duplicated_ceremony_messages_are_idempotent() {
        let (mut a, mut b) = honest();
        let (_, wire_a, wire_b) = run_lossy(&mut a, &mut b, |_, _, _| Fate::Twice, std::time::Duration::from_secs(3));
        assert!(a.aborted().is_none() && b.aborted().is_none());
        assert!(a.secret().is_some() && a.secret() == b.secret());

        let k = b.k().cloned();
        let secret = b.secret().cloned();
        let a_msg = wire_a.iter().find(|v| v["type"] == "pake-msg").unwrap().clone();
        let a_conf = wire_a.iter().find(|v| v["type"] == "pake-confirm" && v.get("answer").is_none()).unwrap().clone();
        let b_conf = wire_b.iter().find(|v| v["type"] == "pake-confirm" && v.get("answer").is_none()).unwrap().clone();
        // A re-sent element after K changes nothing.
        assert!(matches!(b.on_signal(&a_msg, Some(B_FPS)), Inbound::Consumed));
        assert_eq!(b.k().cloned(), k);
        // A re-sent confirmation is answered with our same confirmation, marked.
        let Inbound::Reply(answer) = b.on_signal(&a_conf, Some(B_FPS)) else { panic!("no answer") };
        assert_eq!(answer["mac"], b_conf["mac"]);
        assert_eq!(answer["answer"], json!(true));
        assert_eq!(b.secret().cloned(), secret);
        // An answer is never answered: two confirmed sides do not ping-pong.
        assert!(matches!(a.on_signal(&answer, Some(A_FPS)), Inbound::Consumed));
        // A copy that does not verify (an old link's fingerprints) is not a
        // second attempt: it neither refuses nor re-agrees the ceremony.
        assert!(matches!(b.on_signal(&a_conf, Some(("SHA-256 BB", "SHA-256 OLD"))), Inbound::Consumed));
        assert_eq!(b.secret().cloned(), secret);
        assert!(b.aborted().is_none());
    }

    /// A re-send is the SAME element on the documented backoff (never a fresh
    /// SPAKE2 session per retry, which would hand an attacker another guess),
    /// and re-sends stop once the ceremony is refused.
    #[test]
    fn resends_repeat_the_same_element_on_backoff_and_stop_when_refused() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let t0 = Instant::now();
        let first = a.take_msg_payload_at(t0).unwrap();
        let ms = |n: u64| t0 + std::time::Duration::from_millis(n);
        assert!(a.take_msg_payload_at(ms(249)).is_none());
        let mut at = Vec::new();
        for t in (250..=6000).step_by(10) {
            if let Some(v) = a.take_msg_payload_at(ms(t)) {
                assert_eq!(v, first, "every copy is the same element");
                at.push(t);
            }
        }
        assert_eq!(at, vec![250, 750, 1750, 3750, 5750]);

        // Wrong code: the confirmation fails once, the ceremony is refused, and
        // nothing more goes out however long the loop keeps ticking.
        let mut b = Ceremony::new("brave-ottar", "314", pair_v2_caps(), scope);
        let b_msg = b.take_msg_payload_at(t0).unwrap();
        assert!(matches!(a.on_signal(&b_msg, None), Inbound::Consumed));
        assert!(matches!(b.on_signal(&first, None), Inbound::Consumed));
        assert!(a.take_confirm_payload_at(A_FPS.0, A_FPS.1, ms(6000)).is_some());
        let b_conf = b.take_confirm_payload_at(B_FPS.0, B_FPS.1, ms(6000)).unwrap();
        assert!(matches!(a.on_signal(&b_conf, Some(A_FPS)), Inbound::Abort(_)));
        assert!(matches!(a.on_signal(&b_conf, Some(A_FPS)), Inbound::Abort(_)), "a copy cannot rescue it");
        assert!(a.secret().is_none());
        for t in (6000..=20000).step_by(10) {
            assert!(a.take_msg_payload_at(ms(t)).is_none());
            assert!(a.take_confirm_payload_at(A_FPS.0, A_FPS.1, ms(t)).is_none());
        }
    }

    /// A confirmation that arrives before this link's fingerprints are known
    /// verifies nothing and refuses nothing: a later copy is checked.
    #[test]
    fn a_confirmation_before_fingerprints_waits_for_a_copy() {
        let (mut a, mut b) = honest();
        let a_msg = a.take_msg_payload().unwrap();
        let b_msg = b.take_msg_payload().unwrap();
        b.on_signal(&a_msg, None);
        a.on_signal(&b_msg, None);
        let a_conf = a.take_confirm_payload(A_FPS.0, A_FPS.1).unwrap();
        assert!(matches!(b.on_signal(&a_conf, None), Inbound::Consumed));
        assert!(b.secret().is_none() && b.aborted().is_none());
        assert!(matches!(b.on_signal(&a_conf, Some(B_FPS)), Inbound::Consumed));
        assert!(b.secret().is_some());
    }

    /// Two current CLIs advertise the make-before-break handoff. A 0.9.1 CLI
    /// sends `direct` but no `handoff` (its payload, byte for byte, minus the
    /// new field): facing it, the promotion must behave the old way.
    #[test]
    fn only_a_peer_that_advertises_handoff_is_handed_off() {
        let (a, b) = run_pair("brave-otter", "brave-otter", "314");
        assert!(a.peer_supports_handoff() && b.peer_supports_handoff());

        let scope = filament_id::IntroScope::Device.to_byte();
        let mut new_cli = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut old_side = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut from_old = old_side.take_msg_payload().unwrap();
        assert_eq!(from_old["handoff"], json!(1), "a current CLI must advertise it");
        from_old.as_object_mut().unwrap().remove("handoff");
        assert!(matches!(new_cli.on_signal(&from_old, None), Inbound::Consumed));
        assert!(new_cli.peer_supports_direct(), "0.9.1 still goes direct");
        assert!(!new_cli.peer_supports_handoff(), "0.9.1 cannot answer path-promote");
    }

    /// A current CLI advertises that it acknowledges identity-expose, and
    /// whether it will send one; both payloads carry it, so a peer that lost
    /// every element copy still learns it from the confirmation. A 0.9.1 CLI
    /// sends neither field: facing it nothing waits for an acknowledgement.
    #[test]
    fn the_expose_advertisement_rides_both_payloads_and_0_9_1_sends_none() {
        let scope = filament_id::IntroScope::Device.to_byte();
        let mut a = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut b = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        a.set_exposes(true);
        let am = a.take_msg_payload().unwrap();
        let bm = b.take_msg_payload().unwrap();
        assert_eq!(am["expose_ack"], json!(1));
        assert_eq!(am["exposes"], json!(true));
        assert_eq!(bm["expose_ack"], json!(1));
        assert!(bm.get("exposes").is_none(), "a side with no certificate says nothing about one");
        // b loses a's element: the confirmation alone carries the advertisement.
        a.on_signal(&bm, None);
        let ac = a.take_confirm_payload(A_FPS.0, A_FPS.1).unwrap();
        assert_eq!(ac["expose_ack"], json!(1));
        assert_eq!(ac["exposes"], json!(true));
        assert!(matches!(b.on_signal(&ac, Some(B_FPS)), Inbound::Consumed));
        assert!(b.peer_acks_expose() && b.peer_will_expose());
        assert!(!a.peer_will_expose() && a.peer_acks_expose());

        // 0.9.1: the same payload without the two new fields.
        let mut new_cli = Ceremony::new("brave-otter", "314", pair_v2_caps(), scope);
        let mut old = am.clone();
        old.as_object_mut().unwrap().remove("expose_ack");
        new_cli.on_signal(&old, None);
        assert!(!new_cli.peer_acks_expose() && !new_cli.peer_will_expose(),
            "`exposes` without `expose_ack` is not the new protocol");
    }
}
