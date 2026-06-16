// Characterization tests for the idle-shell (PTY) consent-liveness detector +
// recovery ladder. Plain Node ESM:
// node frontend/src/net/resilience/__tests__/liveness.test.mjs
// Pins the seed/advance/accumulate/correct reducer and the ice→relay→exhausted
// ladder extracted 1:1 from webrtc.js _checkPtyLiveness/_correctPtyDead. (Live
// path needs ?test=freezepty over a granted browser PTY, so unit tests are the
// floor for this slice.)
import { ptyLivenessTick, nextPtyStage } from '../liveness.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const S = (liveSignal, deadMs, episode) => ({ liveSignal, deadMs, episode })
const base = { frozenForTest: false, windowMs: 8000, tickMs: 2000, now: 100000 }

// First reading seeds the baseline, no correction.
eq('seed baseline',
  ptyLivenessTick(S(null, 0, null), { ...base, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 0, episode: null }, action: 'none', recovered: false })
// Seed preserves any existing episode (it is only cleared on real advance).
eq('seed keeps episode',
  ptyLivenessTick(S(null, 0, { stage: 'ice', at: 1 }), { ...base, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 0, episode: { stage: 'ice', at: 1 } }, action: 'none', recovered: false })
// Consent advanced → reset dead clock, clear+report episode.
eq('advance clears episode + recovered',
  ptyLivenessTick(S(500, 6000, { stage: 'ice', at: 7 }), { ...base, signal: 501 }),
  { state: { liveSignal: 501, deadMs: 0, episode: null }, action: 'none', recovered: true })
eq('advance, no episode → recovered false',
  ptyLivenessTick(S(500, 4000, null), { ...base, signal: 600 }),
  { state: { liveSignal: 600, deadMs: 0, episode: null }, action: 'none', recovered: false })
// No advance (signal flat) under the window → accumulate dead time.
eq('flat signal under window → accumulate',
  ptyLivenessTick(S(500, 2000, null), { ...base, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 4000, episode: null }, action: 'none', recovered: false })
// Crosses the window, no episode → correct.
eq('crosses window → correct',
  ptyLivenessTick(S(500, 6000, null), { ...base, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 8000, episode: null }, action: 'correct', recovered: false })
// Over window but episode within grace → wait.
eq('episode within grace → wait',
  ptyLivenessTick(S(500, 8000, { stage: 'ice', at: 99000 }), { ...base, now: 100000, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 10000, episode: { stage: 'ice', at: 99000 } }, action: 'none', recovered: false })
// Over window and grace expired → correct.
eq('episode grace expired → correct',
  ptyLivenessTick(S(500, 8000, { stage: 'ice', at: 90000 }), { ...base, now: 100000, signal: 500 }),
  { state: { liveSignal: 500, deadMs: 10000, episode: { stage: 'ice', at: 90000 } }, action: 'correct', recovered: false })
// Frozen-for-test forces the no-progress branch even when the signal would advance,
// and keeps the prior liveSignal (the local peer's consent is genuinely alive).
eq('frozenForTest forces accumulate, keeps signal',
  ptyLivenessTick(S(500, 6000, null), { ...base, frozenForTest: true, signal: 999 }),
  { state: { liveSignal: 500, deadMs: 8000, episode: null }, action: 'correct', recovered: false })
eq('frozenForTest with null signal does not seed',
  ptyLivenessTick(S(null, 0, null), { ...base, frozenForTest: true, signal: null }),
  { state: { liveSignal: null, deadMs: 2000, episode: null }, action: 'none', recovered: false })

// --- the shell recovery ladder ---
eq('no episode → ice', nextPtyStage(undefined), 'ice')
eq('null → ice', nextPtyStage(null), 'ice')
eq('ice → relay', nextPtyStage('ice'), 'relay')
eq('relay → exhausted', nextPtyStage('relay'), 'exhausted')
eq('exhausted stays exhausted', nextPtyStage('exhausted'), 'exhausted')

console.log(ok ? 'LIVENESS TESTS PASS' : 'LIVENESS TESTS FAIL')
process.exit(ok ? 0 : 1)
