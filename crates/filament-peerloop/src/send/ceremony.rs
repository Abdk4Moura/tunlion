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
}

/// One SPAKE2 ceremony with one peer. Holds all the protocol state the loops
/// previously inlined (the live session, our element, derived K, the sent-flags)
/// so both `pair` and the transfer path drive it identically.
pub struct Ceremony {
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
            nameplate: nameplate.to_string(),
            peer_direct: false,
        }
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
        self.aborted = None;
        self.sent_msg = false;
        self.sent_confirm = false;
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
        self.aborted = None;
        self.sent_msg = false;
        self.sent_confirm = false;
    }

    pub fn secret(&self) -> Option<&String> {
        self.secret.as_ref()
    }

    /// Our element as a `signal` payload, without marking it sent: for a
    /// claimer offering it to every peer that comes up in the room before the
    /// creator has spoken (only the creator, who holds the code, can use it).
    pub fn msg_payload(&self) -> Value {
        self.decorate(json!({
            "type": "pake-msg", "v": 2,
            "msg": b64_encode(&self.msg),
            "np": self.nameplate,
            "direct": true,
        }))
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

    /// The opaque `signal` payload carrying our SPAKE2 element, IF it hasn't been
    /// sent yet. `None` once sent (idempotent). Marks it sent. The caller relays
    /// the returned JSON to the peer (`{to, data: <this>}`).
    pub fn take_msg_payload(&mut self) -> Option<Value> {
        if self.sent_msg {
            return None;
        }
        self.sent_msg = true;
        Some(self.decorate(json!({
            "type": "pake-msg", "v": 2,
            "msg": b64_encode(&self.msg),
            "np": self.nameplate,
            "direct": true,
        })))
    }

    /// The opaque `signal` payload carrying our key-confirmation MAC, IF K is
    /// derived AND it hasn't been sent yet. Needs both DTLS fingerprints (so the
    /// MAC binds them) AND the introduction scope byte (so a scope downgrade is
    /// detected). `None` until ready / once sent.
    pub fn take_confirm_payload(&mut self, my_fp: &str, their_fp: &str) -> Option<Value> {
        if self.sent_confirm {
            return None;
        }
        let k = self.k.as_ref()?;
        // Scope byte is MANDATORY and is derived from the authenticated
        // introduction token (or the fixed convention for plain pair).
        let canon = self.confirm_canon(my_fp, their_fp);
        let mac = filament_pair::our_confirm(k, my_fp, their_fp, &canon, self.scope);
        self.sent_confirm = true;
        Some(self.decorate(json!({
            "type": "pake-confirm", "v": 2,
            "mac": b64_encode(&mac),
            "caps": self.caps.clone(),
            "scope": self.scope,
            "np": self.nameplate,
        })))
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
        }
        match data["type"].as_str() {
            Some("pake-msg") => {
                if self.k.is_none() {
                    if let Some(state) = self.state.take() {
                        let peer_el = data["msg"].as_str().and_then(b64_decode).unwrap_or_default();
                        match filament_pair::finish(state, &peer_el) {
                            Some(k) => self.k = Some(k),
                            None => {
                                return Inbound::Abort(
                                    "malformed key-exchange message (abort)".to_string(),
                                )
                            }
                        }
                    }
                }
                Inbound::Consumed
            }
            Some("pake-confirm") => {
                let Some(k) = self.k.clone() else {
                    return Inbound::Abort(
                        "confirmation arrived before key exchange (abort)".to_string(),
                    );
                };
                let recv_mac = data["mac"].as_str().and_then(b64_decode).unwrap_or_default();
                let Some((my_fp, their_fp)) = fps else {
                    return Inbound::Abort(
                        "no DTLS fingerprints to bind confirmation (abort)".to_string(),
                    );
                };
                // We MAC against OUR fixed caps + scope, so a server that rewrites the
                // relayed `caps` or `scope` field cannot make the MAC verify. Scope
                // byte is read from the authenticated token, not a local guess.
                if filament_pair::verify_peer_confirm(
                    &k,
                    my_fp,
                    their_fp,
                    &self.confirm_canon(my_fp, their_fp),
                    self.scope,
                    &recv_mac,
                ) {
                    self.secret = Some(filament_pair::secret_from_k(&k));
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
}
