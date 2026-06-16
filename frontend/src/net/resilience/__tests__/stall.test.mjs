// Characterization tests for the resilience stall-ladder shape. Plain Node ESM:
// node frontend/src/net/resilience/__tests__/stall.test.mjs
// Pins the rung progression extracted 1:1 from webrtc.js _correctStall's nested
// ifs, so the rewire is provably behavior-preserving.
import { STALL_LADDER, nextStallRung, stallTick } from '../stall.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

eq('ladder is a,b,c', STALL_LADDER, ['a', 'b', 'c'])
// No episode yet → start the cheapest rung.
eq('no episode → a', nextStallRung(undefined), 'a')
eq('null episode → a', nextStallRung(null), 'a')
// Climb the ladder.
eq('a → b', nextStallRung('a'), 'b')
eq('b → c', nextStallRung('b'), 'c')
// Ladder spent → fail clean.
eq('c → fail', nextStallRung('c'), 'fail')
// Defensive: an unknown rung is treated as exhausted (fail), never loops.
eq('unknown → fail', nextStallRung('zzz'), 'fail')

// --- stallTick: the detection reducer (extracted 1:1 from _checkStall) ---
const S = (idleMs, episode, lastMoved, lastBuffered) => ({ idleMs, episode, lastMoved, lastBuffered })
const base = { stallMs: 6000, tickMs: 2000, now: 100000 }
// Idle (nothing to move): reset baseline + idle, clear episode.
eq('idle → reset + clear episode',
  stallTick(S(4000, { rung: 'a', at: 1 }, 50, 99), { ...base, transferring: false, awayActive: false, bytesMoved: 50, buffered: 0 }),
  { state: { idleMs: 0, episode: null, lastMoved: 50, lastBuffered: 0 }, action: 'none', recovered: null })
// Away grace: reset baseline + idle but KEEP the episode latch.
eq('away → reset, keep episode',
  stallTick(S(4000, { rung: 'b', at: 7 }, 50, 99), { ...base, transferring: true, awayActive: true, bytesMoved: 999, buffered: 0 }),
  { state: { idleMs: 0, episode: { rung: 'b', at: 7 }, lastMoved: 999, lastBuffered: 0 }, action: 'none', recovered: null })
// Progress via moved bytes: reset, clear + REPORT the recovered rung.
eq('progress (bytes) → reset + recovered rung',
  stallTick(S(4000, { rung: 'a', at: 7 }, 50, 99), { ...base, transferring: true, awayActive: false, bytesMoved: 60, buffered: 99 }),
  { state: { idleMs: 0, episode: null, lastMoved: 60, lastBuffered: 99 }, action: 'none', recovered: 'a' })
// Progress via SCTP buffer drain (bytesMoved unchanged, buffered < lastBuffered).
eq('progress (drain) → reset, no episode → recovered null',
  stallTick(S(2000, null, 50, 99), { ...base, transferring: true, awayActive: false, bytesMoved: 50, buffered: 40 }),
  { state: { idleMs: 0, episode: null, lastMoved: 50, lastBuffered: 40 }, action: 'none', recovered: null })
// No progress, under threshold: accumulate idle, keep lastMoved, refresh buffered.
eq('no progress under threshold → accumulate',
  stallTick(S(2000, null, 50, 99), { ...base, transferring: true, awayActive: false, bytesMoved: 50, buffered: 99 }),
  { state: { idleMs: 4000, episode: null, lastMoved: 50, lastBuffered: 99 }, action: 'none', recovered: null })
// No progress, crosses threshold, no episode → correct.
eq('no progress crosses threshold → correct',
  stallTick(S(4000, null, 50, 99), { ...base, transferring: true, awayActive: false, bytesMoved: 50, buffered: 99 }),
  { state: { idleMs: 6000, episode: null, lastMoved: 50, lastBuffered: 99 }, action: 'correct', recovered: null })
// Over threshold but episode within grace → wait (no re-fire).
eq('episode within grace → wait',
  stallTick(S(6000, { rung: 'a', at: 99000 }, 50, 99), { ...base, now: 100000, transferring: true, awayActive: false, bytesMoved: 50, buffered: 99 }),
  { state: { idleMs: 8000, episode: { rung: 'a', at: 99000 }, lastMoved: 50, lastBuffered: 99 }, action: 'none', recovered: null })
// Over threshold and episode grace expired → correct (climb the ladder).
eq('episode grace expired → correct',
  stallTick(S(6000, { rung: 'a', at: 90000 }, 50, 99), { ...base, now: 100000, transferring: true, awayActive: false, bytesMoved: 50, buffered: 99 }),
  { state: { idleMs: 8000, episode: { rung: 'a', at: 90000 }, lastMoved: 50, lastBuffered: 99 }, action: 'correct', recovered: null })

console.log(ok ? 'STALL TESTS PASS' : 'STALL TESTS FAIL')
process.exit(ok ? 0 : 1)
