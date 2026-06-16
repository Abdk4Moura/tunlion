// RESILIENCE layer — the idle-shell (PTY) liveness controller (M1, timer-owning).
//
// A file transfer hands liveness to the StallController; an idle shell has no
// file bytes, so this tracks the ICE-CONSENT signal (it advances only while the
// remote answers STUN consent) and, if it stalls for the window, recovers via a
// short ladder. Owns the consent read (getStats), the counters, and the test
// seam; the pure decisions are in ./liveness.js. PeerLink ticks it from the
// shared 2s interval (alongside StallController) and resets it on open/teardown.
import { log } from '../../lib/log.js'
import * as linkdiag from '../../lib/linkdiag.js'
import { ptyLivenessTick, nextPtyStage } from './liveness.js'

const rlog = log.scope('rtc')

export class LivenessController {
  constructor(host, { windowMs, tickMs, freezePtyTest }) {
    this.h = host
    this.windowMs = windowMs
    this.tickMs = tickMs
    this.freezePtyTest = !!freezePtyTest // ?test=freezepty static opt-in
    this.liveSignal = null
    this.deadMs = 0
    this.episode = null
    this._testFrozen = false // set by PeerLink.sendPtyInput under ?test=freezepty
  }

  // Reset the baseline (channel-open) / clear the latches (teardown).
  reset() {
    this.liveSignal = null
    this.deadMs = 0
    this.episode = null
  }

  // M1 test seam: PeerLink calls this when it black-holes PTY input under the
  // freezepty shim, so the detector fires against a genuinely-alive local peer.
  markFrozenForTest() {
    this._testFrozen = true
  }

  // Read an ICE-CONSENT liveness value off the selected candidate pair. Advances
  // only while the remote answers STUN consent (~5s on a connected pair), so it
  // keeps climbing on a healthy idle link and freezes the instant the path is
  // black-holed. Preference: responsesReceived > lastPacketReceivedTimestamp >
  // bytesReceived. Returns a strictly-increasing number, or null (no pair/unsupp).
  async _readConsent() {
    const h = this.h
    if (h._closed) return null
    try {
      const stats = await h.pc.getStats()
      let transportSelectedId = null
      stats.forEach((r) => {
        if (r.type === 'transport' && r.selectedCandidatePairId) transportSelectedId = r.selectedCandidatePairId
      })
      let pair = null
      stats.forEach((r) => {
        if (r.type !== 'candidate-pair') return
        if (r.id === transportSelectedId || (!transportSelectedId && r.state === 'succeeded' && (r.nominated || r.selected)))
          pair = r
      })
      if (!pair) return null
      if (typeof pair.responsesReceived === 'number') return pair.responsesReceived
      if (typeof pair.lastPacketReceivedTimestamp === 'number') return pair.lastPacketReceivedTimestamp
      if (typeof pair.bytesReceived === 'number') return pair.bytesReceived
      return null
    } catch {
      return null // getStats unsupported
    }
  }

  // One tick (driven by PeerLink's shared interval). Active only for a shell link
  // (_ptySid != null) over an open+connected channel with NO file transfer in
  // flight (a transfer is the StallController's job).
  async tick() {
    const h = this.h
    if (h._closed || h.channel?.readyState !== 'open') return
    if (h._ptySid == null) { this.liveSignal = null; this.deadMs = 0; return }
    if (h.pc.connectionState !== 'connected') { this.deadMs = 0; return }
    const transferring = [...h.transfers.values()].some(
      (t) => t.status === 'transferring' && (t.progress ?? 0) < 1,
    )
    if (transferring) { this.deadMs = 0; return } // defer to the StallController
    // C21 announced-absence grace: a peer that said `brb`/hidden is legitimately quiet.
    if ((h._awayUntil || 0) > Date.now()) { this.deadMs = 0; return }

    const signal = await this._readConsent()
    if (h._closed) return
    const frozenForTest = this.freezePtyTest && this._testFrozen
    if (signal == null && !frozenForTest) { this.deadMs = 0; return } // can't read: don't guess

    // The seed/advance/accumulate-dead/correct verdict is the pure reducer.
    const r = ptyLivenessTick(
      { liveSignal: this.liveSignal, deadMs: this.deadMs, episode: this.episode },
      { signal, frozenForTest, windowMs: this.windowMs, tickMs: this.tickMs, now: Date.now() },
    )
    this.liveSignal = r.state.liveSignal
    this.deadMs = r.state.deadMs
    this.episode = r.state.episode
    if (r.recovered) rlog.info('idle shell link recovered, consent advancing again', h.id.slice(-6))
    if (r.action === 'correct') {
      rlog.debug('idle shell link appears dead (consent not advancing)', h.id.slice(-6), 'deadMs', this.deadMs)
      linkdiag.record('m1-dead', { deadMs: this.deadMs, route: h.route || null }, h._diagMeta())
      this._correct()
    }
  }

  // M1+M6 short shell recovery ladder: rung 1 impolite-only restartIce, rung 2
  // straight to the relay rebuild (onStall) — an interactive link should reach
  // the relay fast (the PTY reattaches on the new link via its stable sessionId).
  // The stage SHAPE (ice → relay → exhausted) is nextPtyStage.
  _correct() {
    const h = this.h
    const now = Date.now()
    const stage = nextPtyStage(this.episode?.stage)
    if (stage === 'ice') {
      if (h.pc.connectionState === 'connected' && !h.polite) {
        try {
          linkdiag.record('action', { what: 'restartIce', reason: 'm1-shell-rung-1' }, h._diagMeta())
          h.pc.restartIce()
          rlog.info('idle shell dead (rung 1): restartIce', h.id.slice(-6))
        } catch {}
      } else {
        rlog.info('idle shell dead (rung 1): no restartIce (polite/not-connected), waiting one window', h.id.slice(-6))
      }
      this.episode = { stage: 'ice', at: now }
      return
    }
    if (stage === 'relay') {
      rlog.info('idle shell still dead (rung 2): escalating to relay rebuild (onStall)', h.id.slice(-6))
      linkdiag.record('action', { what: 'onStall', reason: 'm1-shell-rung-2', route: h.route || null }, h._diagMeta())
      try {
        h.onStall?.({ reason: 'persistent', route: h.route })
      } catch (err) {
        rlog.warn('onStall hook threw', h.id.slice(-6), err)
      }
      this.episode = { stage: 'relay', at: now }
      return
    }
    // Exhausted: relay rebuild already requested (hook bounds it at-most-once);
    // let the connection-state machine / M2 grace carry it to a clean 'failed'.
    // Re-latch so we keep deferring rather than thrashing.
    this.episode = { stage: 'relay', at: now }
  }
}
