// RESILIENCE layer — relay→direct UPGRADE prober (P5).
//
// When a link settles on a TURN relay, the prober periodically restartIce()s to
// look for a direct path and, if one appears, VERIFIES it holds before cutting
// over (no flap). PeerLink owns the timers, the backoff cadence state, and the
// verify-window bookkeeping (lastBytes/lastSeen); the timer-free POLICY lives
// here so it is node-testable. Mirrors the Rust client's judge_upgrade_standby.
//
// NOTE on verification: the relay→direct scenario is not reproducible on a single
// host (links are always `local`), so these decisions are pinned by unit tests;
// a true live check needs a two-machine / NAT'd relay setup.

// The probe MEASURED a route (verify-before-commit, no UI fired yet). A non-relay
// measurement enters the verify window; relay/none backs off and re-schedules.
export function decideProbeResult(measuredRoute) {
  return measuredRoute && measuredRoute !== 'relayed'
    ? { action: 'verify', route: measuredRoute }
    : { action: 'backoff' }
}

// One tick of the verify-before-commit window. Pure decision; the caller tracks
// the moved-bytes bookkeeping and refreshes `idleMs` (ms since bytes last moved)
// and `elapsedMs` (ms since the window opened).
//   measuredRoute  this tick's route measurement
//   hasInflight    a transfer is still moving (progress < 1)
//   idleMs         ms since the last byte moved (only meaningful with inflight)
//   elapsedMs      ms since the verify window opened
//   verifyMs       the hold-time required before commit
// Returns:
//   { action: 'discard' }  reverted to relay, or an inflight transfer stalled →
//                          stay on relay, back off (no flap)
//   { action: 'commit' }   held long enough → cut over to direct
//   { action: 'wait' }     keep sampling
export function decideUpgradeVerifyTick({ measuredRoute, hasInflight, idleMs, elapsedMs, verifyMs }) {
  const idleTooLong = hasInflight && idleMs >= verifyMs
  if (measuredRoute === 'relayed' || idleTooLong) return { action: 'discard' }
  if (elapsedMs >= verifyMs) return { action: 'commit' }
  return { action: 'wait' }
}

// Backoff cadence: a probe (or failed verify) that didn't yield a held direct
// path doubles the delay toward the steady cap, so a peer that will never get
// direct isn't hammered.
export function nextUpgradeDelay(currentDelay, steadyMs) {
  return Math.min(currentDelay * 2, steadyMs)
}
