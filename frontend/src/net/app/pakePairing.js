// PROTOCOL: the browser half of the SPAKE2 code ceremony (the CLI's
// send::ceremony::Ceremony; keep the two in step). Pure state: the SPAKE2
// session is injected (lib/pairing.js passes the WASM one), and it owns no
// timer. The caller calls tick() on its own cadence and the ceremony decides
// whether a re-send is due.
//
// C30: no single emit may be load-bearing. Our element, then our confirmation,
// is re-sent on a bounded backoff (RESEND_FIRST_MS, doubling to RESEND_CAP_MS)
// until the peer's confirmation verifies. Every copy is the SAME element and
// the SAME MAC: one SPAKE2 session per ceremony, so a re-send is never another
// password guess. A copy of a peer message we already processed is idempotent:
// a re-sent element is ignored (K comes from the first), and a re-sent
// confirmation after we confirmed is answered once with our same confirmation
// (the peer is still waiting for it), never verified as a second attempt.

export const RESEND_FIRST_MS = 250
export const RESEND_CAP_MS = 2000

/// Delay before the re-send that follows re-send number `step` (0-based):
/// 250, 500, 1000, then 2000 ms from there on.
export function resendDelay(step) {
  return Math.min(RESEND_FIRST_MS * 2 ** Math.min(step, 8), RESEND_CAP_MS)
}

/// A single v2 pairing attempt with one peer. Drives:
///   start → (send our element over signal) → finish on peer's element →
///   once K AND both fingerprints known → send confirm MAC → verify peer's →
///   on success: derive the pinned secret (HKDF(K)).
///
/// `session` is the SPAKE2 session (message/finish/ourConfirm/
/// verifyPeerConfirm/secret). `sendSignal(data)` relays an opaque payload to
/// the peer via the server. `getFingerprints()` returns {mine, theirs} once SDP
/// is exchanged (or null).
export class PakeCeremony {
  constructor({ nameplate, caps, capsCanon, session, sendSignal, getFingerprints, now = () => Date.now() }) {
    this.nameplate = nameplate
    this.caps = caps
    this.capsCanon = capsCanon
    this.session = session
    this.sendSignal = sendSignal
    this.getFingerprints = getFingerprints
    this.now = now
    this.msg = session.message()
    this.sentMsg = false
    this.sentConfirm = false
    this.haveK = false
    this.secret = null // set ONLY after confirmation passes
    this.aborted = null // abort reason if the pairing was refused
    this._pendingConfirmMac = null // a confirm that arrived before fingerprints
    this._resendAt = null
    this._resendStep = 0
  }

  /// Send our SPAKE2 element (idempotent). Call once the peer sid is known.
  sendOurMessage() {
    if (this.sentMsg) return
    // `np` names whose ceremony this is: concurrent codes from one device
    // share a room, and a peer of another code must not answer or fail it.
    this.sendSignal(this._msgPayload())
    this.sentMsg = true
    this._arm()
  }

  /// Try to send our key-confirmation MAC once K + both fingerprints exist.
  tryConfirm() {
    if (this.sentConfirm || !this.haveK || this.aborted) return
    const payload = this._confirmPayload()
    if (!payload) return
    this.sendSignal(payload)
    this.sentConfirm = true
    this._arm()
    // A confirm from the peer may have arrived first; process it now.
    if (this._pendingConfirmMac && !this.secret) this._verify(this._pendingConfirmMac)
  }

  /// Re-send the current message if its backoff slot is due. Call on a short
  /// cadence while the ceremony is live; a no-op once confirmed or refused.
  tick() {
    if (this.secret || this.aborted || this._resendAt == null) return
    // Fingerprints may have become known since the last step.
    if (!this.sentConfirm) this.tryConfirm()
    const now = this.now()
    if (now < this._resendAt) return
    this._resendStep += 1
    this._resendAt = now + resendDelay(this._resendStep)
    const payload = this.sentConfirm ? this._confirmPayload() : this._msgPayload()
    if (payload) this.sendSignal(payload)
  }

  /// Handle an inbound opaque signal. Returns true if it was a PAKE message
  /// (and thus consumed); false if it should fall through to WebRTC.
  onSignal(data) {
    if (data?.type === 'pake-msg') {
      if (!this.haveK) this._absorb(data.msg)
      return true
    }
    if (data?.type === 'pake-confirm') {
      // Our copy of the peer's element was lost: its confirmation carries
      // the same element, so derive K from that first.
      if (!this.haveK && data.msg) {
        this._absorb(data.msg)
        if (this.aborted) return true
      }
      const mac = b64d(data.mac)
      if (!this.haveK) {
        // Out-of-order: stash until K is derived.
        this._pendingConfirmMac = mac
        return true
      }
      if (this.secret) {
        if (!data.answer) this._answerDuplicate(mac)
        return true
      }
      this._verify(mac)
      return true
    }
    return false
  }

  _absorb(msgB64) {
    if (!this.session.finish(b64d(msgB64))) {
      this.aborted = 'malformed key-exchange message'
      return
    }
    this.haveK = true
    this.tryConfirm()
  }

  _verify(mac) {
    const fps = this.getFingerprints()
    if (!fps) {
      // Can't verify without fingerprints; stash and retry on tryConfirm.
      this._pendingConfirmMac = mac
      return
    }
    if (this.session.verifyPeerConfirm(fps.mine, fps.theirs, this.capsCanon, mac)) {
      // CONFIRMED. Derive the pinned secret from K (agreed, never transmitted).
      this.secret = this.session.secret()
      // Ours may not have gone out yet (the fingerprints arrived with theirs).
      this.tryConfirm()
    } else {
      this.aborted = 'key confirmation failed: wrong code or tampering (a server cannot forge this)'
    }
  }

  // Already confirmed, and the peer re-sent its confirmation: it has not heard
  // ours. Answer with the same one, marked `answer` so a peer that is itself
  // confirmed never answers back (two confirmed sides would ping-pong). The
  // outcome is fixed; a copy that does not verify (an old link's) changes
  // nothing and is never a second attempt.
  _answerDuplicate(mac) {
    const fps = this.getFingerprints()
    if (!fps || !this.session.verifyPeerConfirm(fps.mine, fps.theirs, this.capsCanon, mac)) return
    const payload = this._confirmPayload()
    if (!payload) return
    this.sendSignal({ ...payload, answer: true })
    this.sentConfirm = true
  }

  _arm() {
    this._resendStep = 0
    this._resendAt = this.now() + RESEND_FIRST_MS
  }

  _msgPayload() {
    return { type: 'pake-msg', v: 2, msg: b64(this.msg), np: this.nameplate }
  }

  // Deterministic in K, the fingerprints and the caps, so every copy is the
  // same. It carries our element too (`msg`), for a peer whose copy of the
  // element was lost.
  _confirmPayload() {
    const fps = this.getFingerprints()
    if (!fps) return null
    const mac = this.session.ourConfirm(fps.mine, fps.theirs, this.capsCanon)
    if (!mac) return null
    return { type: 'pake-confirm', v: 2, mac: b64(mac), msg: b64(this.msg), caps: this.caps, np: this.nameplate }
  }
}

// Minimal base64 helpers for the opaque 33-byte element / 32-byte MAC payloads.
function b64(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s)
}
function b64d(str) {
  const s = atob(str)
  const out = new Uint8Array(s.length)
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
  return out
}
