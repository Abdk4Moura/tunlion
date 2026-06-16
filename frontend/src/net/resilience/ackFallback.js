// RESILIENCE layer — the delivery-ack fallback controller (P4, timer-owning).
//
// A send is "complete" ONLY on a genuine CTRL.DELIVERY_ACK; bytes draining out
// of the SCTP buffer prove nothing (a black-holed path drains while nothing
// arrives). So after END+drain we arm a no-ack WINDOW: if it elapses we re-probe
// once (re-send END to prompt a possibly-lost ack) and, failing that, end
// HONESTLY (paused/resumable) — never a false success, never a hang. This object
// owns the per-transfer timers + the "peer acks" memory; the pure verdict is
// decideAckFallback (protocol/transfer.js). `host` is the PeerLink.
import { log } from '../../lib/log.js'
import { decideAckFallback, endMsg } from '../protocol/transfer.js'

const rlog = log.scope('rtc')

export class AckFallbackController {
  constructor(host, { fallbackMs, reprobeMs }) {
    this.h = host
    this.fallbackMs = fallbackMs
    this.reprobeMs = reprobeMs
    this.timers = new Map() // transferId → setTimeout handle
    this._peerAckedThisLink = false
  }

  // Arm (or re-arm, after a re-probe) the no-ack window for an outgoing send.
  // `reprobed` is true on the second arming (after we re-sent END once).
  arm(id, sid, reprobed = false) {
    const h = this.h
    if (this.timers.has(id)) clearTimeout(this.timers.get(id))
    const wait = reprobed ? this.reprobeMs : this.fallbackMs
    this.timers.set(id, setTimeout(() => {
      this.timers.delete(id)
      const cur = h.transfers.get(id)
      if (!cur || cur.status === 'complete') return // the real ack landed meanwhile
      const entry = h._outgoingFiles.get(id)
      const decision = decideAckFallback({
        channelOpen: h.channel?.readyState === 'open',
        connected: h.pc?.connectionState === 'connected',
        peerHasAcked: this.peerAcks(),
        offeredDigest: !!entry?.offeredDigest,
        reprobed,
      })
      if (decision.action === 'reprobe') {
        // The ack may have been lost on a still-healthy link. Re-send END once to
        // prompt the receiver to re-ack, then wait one more (shorter) window.
        rlog.debug('no delivery-ack yet, re-probing (re-sending END)', id)
        h._control(endMsg(id, sid))
        this.arm(id, sid, true)
        return
      }
      // No ack after the re-probe (or the link is unhealthy). Do NOT complete.
      // Keep the file in the outgoing store so it can resume, end honestly.
      rlog.warn('no delivery-ack: send NOT confirmed, ending as unconfirmed (resumable)', id)
      const resumable = decision.resumable && h.stores.outgoing.has(id)
      h._outgoingFiles.delete(id)
      h._update(cur, { status: resumable ? 'paused' : 'failed', reason: 'delivery not confirmed' })
    }, wait))
  }

  // The genuine delivery-ack arrived → cancel the window for this transfer.
  onAck(id) {
    const tm = this.timers.get(id)
    if (tm) {
      clearTimeout(tm)
      this.timers.delete(id)
    }
  }

  // Remember "this peer delivery-acks" (this link + persisted per peerUid) so a
  // future ack-window NEVER falls back to a weak completion — the ack is
  // mandatory for an ack-capable peer.
  markPeerAcks() {
    this._peerAckedThisLink = true
    try {
      if (this.h.peerUid) localStorage.setItem('filamentPeerAcks:' + this.h.peerUid, '1')
    } catch {}
  }

  peerAcks() {
    if (this._peerAckedThisLink) return true
    try {
      if (this.h.peerUid) return localStorage.getItem('filamentPeerAcks:' + this.h.peerUid) === '1'
    } catch {}
    return false
  }

  // Clear all pending windows (link teardown / failActive).
  clear() {
    for (const tm of this.timers.values()) clearTimeout(tm)
    this.timers.clear()
  }
}
