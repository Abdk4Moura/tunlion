// RESILIENCE layer — idle INTERACTIVE-link (PTY/shell) liveness (M1).
//
// A file transfer hands liveness to the stall watchdog (resilience/stall.js); an
// idle shell has no file bytes to watch, so this detector tracks the ICE-CONSENT
// signal instead (it advances only while the remote answers STUN consent). If it
// stops advancing for the window, the path is silently dead though the channel
// still claims open → recover via a short 2-stage ladder. PeerLink owns the timer
// (shares _checkStall's tick), the consent read (getStats), and the mutable
// counters; the timer-free POLICY lives here. Mirrors the stall detector/ladder.
//
// Verification note: the live path needs the ?test=freezepty shim over a granted
// browser PTY (trusted device + `shell` cap), so these decisions are pinned by
// unit tests; a true live drive needs that PTY harness.

// One tick of the consent-liveness detector, AFTER the consent signal is read.
// The caller keeps the early guards (no PTY / not connected / a transfer in
// flight / announced-absence / unreadable signal) — those are IO/async, not
// policy. Mirrors stallTick.
//   state: { liveSignal, deadMs, episode }
//   obs:   { signal, frozenForTest, windowMs, tickMs, now }
// Returns: { state: {...next}, action: 'none' | 'correct', recovered }
//   recovered is true when consent resumed and an open episode was cleared
//   (for the "idle shell recovered" log).
export function ptyLivenessTick(s, o) {
  // First reading seeds the baseline (the frozen-test seam never seeds, it forces
  // the no-progress branch so the detector fires against a genuinely-alive peer).
  if (s.liveSignal == null && !o.frozenForTest) {
    return { state: { liveSignal: o.signal, deadMs: 0, episode: s.episode }, action: 'none', recovered: false }
  }
  const advanced = !o.frozenForTest && s.liveSignal != null && o.signal > s.liveSignal
  if (advanced) {
    return { state: { liveSignal: o.signal, deadMs: 0, episode: null }, action: 'none', recovered: !!s.episode }
  }
  // No advance this tick: keep the latest signal (unless frozen), accumulate dead.
  const liveSignal = o.frozenForTest ? s.liveSignal : o.signal
  const deadMs = s.deadMs + o.tickMs
  const state = { liveSignal, deadMs, episode: s.episode }
  if (deadMs < o.windowMs) return { state, action: 'none', recovered: false }
  // Latch so we don't re-fire every tick while a correction converges.
  if (s.episode && (o.now - s.episode.at) < o.windowMs) return { state, action: 'none', recovered: false }
  return { state, action: 'correct', recovered: false }
}

// The shell recovery ladder (M6: shorter than the file ladder — an interactive
// link should reach the relay fast). Given the current episode stage, the stage
// to run NOW:
//   no episode → 'ice'        rung 1: impolite-only in-place restartIce
//   'ice'      → 'relay'       rung 2: escalate straight to onStall (relay rebuild)
//   'relay'    → 'exhausted'   already escalated → re-latch, take no new action
export function nextPtyStage(currentStage) {
  if (!currentStage) return 'ice'
  if (currentStage === 'ice') return 'relay'
  return 'exhausted'
}
