// Characterization tests for the resilience stall-ladder shape. Plain Node ESM:
// node frontend/src/net/resilience/__tests__/stall.test.mjs
// Pins the rung progression extracted 1:1 from webrtc.js _correctStall's nested
// ifs, so the rewire is provably behavior-preserving.
import { STALL_LADDER, nextStallRung } from '../stall.js'

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

console.log(ok ? 'STALL TESTS PASS' : 'STALL TESTS FAIL')
process.exit(ok ? 0 : 1)
