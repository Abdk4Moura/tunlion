// RESILIENCE layer — the relay→direct UPGRADE prober (P5, timer-owning).
//
// While a link serves on a TURN relay, this periodically restartIce()s to look
// for a direct path and, if one appears, VERIFIES it holds (UPGRADE_VERIFY_MS)
// before cutting over — no flap. Owns the backoff timer + cadence + the
// verify-window latch; the timer-free POLICY is in ./upgrade.js. `host` is the
// PeerLink: the prober reads its route/pc/transfers/bytes and, on commit, sets
// host.route + fires host.onRoute. Mirrors the Rust judge_upgrade_standby.
import { log } from '../../lib/log.js'
import * as linkdiag from '../../lib/linkdiag.js'
import { decideProbeResult, decideUpgradeVerifyTick, nextUpgradeDelay } from './upgrade.js'

const rlog = log.scope('rtc')
const VERIFY_TICK = 500

export class UpgradeProber {
  constructor(host, { firstMs, steadyMs, verifyMs }) {
    this.h = host
    this.firstMs = firstMs
    this.steadyMs = steadyMs
    this.verifyMs = verifyMs
    this.timer = null
    this.delay = firstMs
    this.verify = null // in-progress verify latch {route, bytesAt, lastBytes, lastSeen}
    this.upgrading = false // re-entrancy guard while a probe/verify is mid-flight
  }

  // Begin probing while on relay. Idempotent. First probe is eager (firstMs),
  // then each failed probe doubles toward steadyMs.
  arm() {
    if (this.h._closed || this.timer) return
    rlog.debug('upgrade prober armed (on relay, probing for a direct path)', this.h.id.slice(-6))
    this.delay = this.firstMs
    this._schedule(this.delay)
  }

  disarm() {
    if (this.timer) {
      clearTimeout(this.timer)
      this.timer = null
    }
    this.verify = null
    this.upgrading = false
    this.delay = this.firstMs
  }

  _schedule(delay) {
    if (this.h._closed) return
    clearTimeout(this.timer)
    this.timer = setTimeout(() => this._probe(), delay)
  }

  // Re-probe NOW: collapse the backoff so the next probe fires immediately (the
  // hook calls this on a network change — the browser analog of an iface-change).
  probeNow() {
    if (this.h._closed || this.h.route !== 'relayed') return
    this.delay = this.firstMs // a fresh path may exist, reset the cadence
    if (this.upgrading) return // a probe is already in flight; let it run
    rlog.debug('upgrade re-probe now (network change)', this.h.id.slice(-6))
    this._schedule(0)
  }

  // One upgrade attempt: restartIce() on the live PC (the data channel survives),
  // let ICE re-nominate, MEASURE (not commit) the route. A non-relay measurement
  // enters the verify-before-commit window; anything else backs off.
  async _probe() {
    const h = this.h
    this.timer = null
    if (h._closed || h.route !== 'relayed') return this.disarm()
    // Kill-switch (browser analog of FILAMENT_UPGRADE_PROBE=0).
    try {
      if (localStorage.getItem('filamentUpgradeProbe') === '0') {
        rlog.debug('upgrade prober disabled (filamentUpgradeProbe=0), staying on relay', h.id.slice(-6))
        return
      }
    } catch {}
    // Shared-ICE-restart guard: the P0 stall ladder also drives restartIce; never
    // both at once. Skip + back off if a stall episode is open or not connected.
    if (h.pc.connectionState !== 'connected' || h._stall.episode) {
      rlog.debug('upgrade probe skipped (not connected or stall episode open)', h.id.slice(-6))
      return this._backoff()
    }
    // Only the IMPOLITE side drives restartIce (restarting from both glares).
    this.upgrading = true
    if (!h.polite) {
      try {
        rlog.debug('upgrade probe: restartIce to find a direct path', h.id.slice(-6))
        linkdiag.record('action', { what: 'restartIce', reason: 'p5-upgrade-probe' }, h._diagMeta())
        h.pc.restartIce()
      } catch {}
    } else {
      rlog.debug('upgrade probe: re-detecting route (polite: no restartIce)', h.id.slice(-6))
    }
    // Give ICE a moment to re-nominate, then MEASURE (not commit): a relay→direct
    // flip must pass verify-before-commit first (only _commit fires onRoute).
    await new Promise((r) => setTimeout(r, 1200))
    this.upgrading = false
    if (h._closed || h.route !== 'relayed') return
    const route = await h._measureRoute()
    if (h._closed || h.route !== 'relayed') return
    if (decideProbeResult(route).action === 'verify') {
      this._beginVerify(route)
    } else {
      this.verify = null
      this._backoff()
    }
  }

  // Verify-before-commit: a direct path that wins re-nomination must keep moving
  // data (or read non-relay) for verifyMs before we cut over. Discard on revert
  // or an inflight stall (no flap).
  _beginVerify(route) {
    const h = this.h
    rlog.debug('direct path detected, verifying it holds before committing', h.id.slice(-6))
    const start = Date.now()
    const verify = { route, bytesAt: h._bytesMoved, lastBytes: h._bytesMoved, lastSeen: start }
    this.verify = verify
    const tick = async () => {
      if (h._closed || this.verify !== verify) return
      if (h.route !== 'relayed') return // someone else committed; stop
      const re = await h._measureRoute() // MEASURE only
      if (h._closed || this.verify !== verify) return
      const hasInflight = [...h.transfers.values()].some(
        (t) => t.status === 'transferring' && (t.progress ?? 0) < 1,
      )
      const moved = h._bytesMoved !== verify.lastBytes
      if (moved) {
        verify.lastBytes = h._bytesMoved
        verify.lastSeen = Date.now()
      }
      const decision = decideUpgradeVerifyTick({
        measuredRoute: re,
        hasInflight,
        idleMs: Date.now() - verify.lastSeen,
        elapsedMs: Date.now() - start,
        verifyMs: this.verifyMs,
      })
      if (decision.action === 'discard') {
        rlog.debug('direct path connected but did not hold, staying on relay (no flap)', h.id.slice(-6))
        this.verify = null
        this._backoff()
        return
      }
      if (decision.action === 'commit') {
        this._commit(verify.route)
        return
      }
      this.timer = setTimeout(tick, VERIFY_TICK)
    }
    this.timer = setTimeout(tick, VERIFY_TICK)
  }

  // Commit: the direct path held. Set the route, fire onRoute (auto-clears the
  // amber relay UI), log the value-prop line, disarm (we're a destination now).
  _commit(route) {
    const h = this.h
    if (h._closed) return
    linkdiag.record('action', { what: 'upgrade-commit', route, from: h.route || null }, h._diagMeta())
    h.route = route
    h.onRoute(route)
    rlog.info('upgraded to direct, relay released', h.id.slice(-6), route)
    this.disarm()
  }

  // A probe / failed verify didn't yield a held direct path: double the cadence
  // toward the cap and re-schedule, so a peer that never gets direct isn't hammered.
  _backoff() {
    this.upgrading = false
    this.delay = nextUpgradeDelay(this.delay, this.steadyMs)
    if (this.h.route === 'relayed' && !this.h._closed) this._schedule(this.delay)
  }
}
