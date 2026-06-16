// RESILIENCE layer — the in-flight STALL controller (timer-owning).
//
// Owns the stall watchdog's mutable state (idle clock, episode latch, the
// moved/buffered snapshots) and the correction-ladder mechanics. The pure
// decisions live in ./stall.js (stallTick / nextStallRung); this object is the
// stateful home that drives them. PeerLink keeps the single 2s interval (it also
// ticks the PTY liveness detector) and calls `tick()`; on channel-open it calls
// `reset()`, and on teardown `clearState()`. `host` is the PeerLink — the
// controller reads its transport/transfer state and drives its rung mechanics
// (a faithful relocation; the narrow Transport interface is a later tightening).
import { log } from '../../lib/log.js'
import * as linkdiag from '../../lib/linkdiag.js'
import { acceptMsg } from '../protocol/transfer.js'
import { stallTick, nextStallRung } from './stall.js'

const rlog = log.scope('rtc')

export class StallController {
  constructor(host, { stallMs, tickMs }) {
    this.h = host
    this.stallMs = stallMs
    this.tickMs = tickMs
    this.idleMs = 0
    this.episode = null // {rung, at} latch (read by the upgrade prober for glare avoidance)
    this.lastMoved = 0
    this.lastBuffered = 0
  }

  // Seed the baseline so the first tick starts clean (channel-open).
  reset() {
    this.idleMs = 0
    this.episode = null
    this.lastMoved = this.h._bytesMoved
    this.lastBuffered = this.h.channel?.bufferedAmount || 0
  }

  // Clear the watchdog state without re-seeding (link torn down / failed).
  clearState() {
    this.episode = null
    this.idleMs = 0
  }

  // One watchdog tick (driven by PeerLink's interval).
  tick() {
    const h = this.h
    // A genuine drop is C4's job; this detector is for an OPEN-but-dark channel.
    if (h._closed || h.channel?.readyState !== 'open') return
    // Stall-eligible only with bytes STILL TO MOVE (progress < 1); a transfer at
    // progress 1 is in its legitimate no-wire-bytes tail (drain + verify + ack).
    const transferring = [...h.transfers.values()].some(
      (t) => t.status === 'transferring' && (t.progress ?? 0) < 1,
    )
    const r = stallTick(
      { idleMs: this.idleMs, episode: this.episode, lastMoved: this.lastMoved, lastBuffered: this.lastBuffered },
      {
        transferring,
        awayActive: (h._awayUntil || 0) > Date.now(),
        bytesMoved: h._bytesMoved,
        buffered: h.channel.bufferedAmount,
        stallMs: this.stallMs,
        tickMs: this.tickMs,
        now: Date.now(),
      },
    )
    this.idleMs = r.state.idleMs
    this.episode = r.state.episode
    this.lastMoved = r.state.lastMoved
    this.lastBuffered = r.state.lastBuffered
    if (r.recovered) rlog.info('stall corrected, bytes moving again', h.id.slice(-6), 'rung', r.recovered)
    if (r.action === 'correct') {
      rlog.debug('stall detected', h.id.slice(-6), 'idleMs', this.idleMs)
      this._correct()
    }
  }

  // Least-disruptive-first correction ladder (mirrors Rust correct_stall):
  //   (a) liveness ping + (impolite, connected) restartIce — cheapest, in place
  //   (b) re-offer/resume unfinished transfers (receiver re-acks at its offset)
  //   (c) escalate to onStall (P1 relay-preferred rebuild)
  // Bounded; on exhaustion → onStatus('failed') + _failActive (transfers become
  // paused/resumable, never silently dead). The ladder SHAPE is nextStallRung.
  _correct() {
    const h = this.h
    const now = Date.now()
    const step = nextStallRung(this.episode?.rung)
    // RUNG (a): liveness probe + in-place ICE repair.
    if (step === 'a') {
      try {
        // A control send over the reliable channel: success ⇒ transport up (data
        // path dark, link alive). A throw ⇒ truly dead; let C4 / _failActive own it.
        h.channel.send(JSON.stringify({ type: 'ping', v: 1, reason: 'stall-probe' }))
      } catch {
        rlog.debug('stall: control send threw: link is dead, deferring to C4', h.id.slice(-6))
        return
      }
      // Only the IMPOLITE side nudges ICE while CONNECTED (C4 owns it while
      // 'disconnected'; both sides restarting glares).
      if (h.pc.connectionState === 'connected' && !h.polite) {
        try {
          linkdiag.record('action', { what: 'restartIce', reason: 'stall-rung-a' }, h._diagMeta())
          h.pc.restartIce()
          rlog.info('stall corrected attempt (rung a), liveness ping + restartIce', h.id.slice(-6))
        } catch {}
      } else {
        rlog.info('stall corrected attempt (rung a), liveness ping (no ICE restart: polite/not-connected)', h.id.slice(-6))
      }
      this.episode = { rung: 'a', at: now }
      return
    }
    // RUNG (b): re-issue every unfinished transfer so the data path re-flows.
    if (step === 'b') {
      let nudged = 0
      for (const t of h.transfers.values()) {
        if (t.status !== 'transferring') continue
        if (t.direction === 'send') {
          // Re-offer with resume:true; clear the per-link send state so resumeSend
          // re-arms a fresh stream (the receiver auto-resumes from its partial).
          h._outgoingFiles.delete(t.id)
          h.resumeSend(t.id)
          nudged++
        } else if (t.direction === 'receive') {
          // Receiver side: re-send a resume accept at the current offset to nudge
          // the sender to (re)stream from where we are, never restart from 0.
          const partial = h.stores.partials.get(t.id)
          h._control(acceptMsg(t.id, partial ? partial.received : 0))
          nudged++
        }
      }
      rlog.info('stall correction (rung b), re-offered/resumed unfinished transfers', h.id.slice(-6), 'count', nudged)
      this.episode = { rung: 'b', at: now }
      return
    }
    // RUNG (c): escalate to the hook (P1 relay-preferred rebuild; may be a no-op).
    if (step === 'c') {
      rlog.info('stall correction (rung c), escalating to onStall', h.id.slice(-6))
      linkdiag.record('action', { what: 'onStall', reason: 'stall-rung-c', route: h.route || null }, h._diagMeta())
      try {
        h.onStall?.({ reason: 'persistent', route: h.route })
      } catch (err) {
        rlog.warn('onStall hook threw', h.id.slice(-6), err)
      }
      this.episode = { rung: 'c', at: now }
      return
    }
    // EXHAUSTED (rungs a→c spent): no rung recovered. Fail CLEAN — transfers
    // become paused/resumable via _failActive, never silently dead.
    rlog.warn('stall correction exhausted, failing clean (partials preserved)', h.id.slice(-6))
    h.onStatus('failed')
    h._failActive()
  }
}
