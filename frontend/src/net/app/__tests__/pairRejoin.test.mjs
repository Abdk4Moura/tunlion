// node frontend/src/net/app/__tests__/pairRejoin.test.mjs
// Same-network pairing: the creator must read a prompt rejoin of the same
// peer as a rejoin, not as "the other device ended the pairing".
import { isSamePeerBack, PEER_LEFT_GRACE_MS } from '../pairRejoin.js'

let ok = true
const eq = (label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`)
    ok = false
  } else console.log(`  ${label}: OK`)
}


eq('same sid is back', isSamePeerBack({ id: 's1', uid: 'u1' }, { id: 's1', uid: 'u1' }), true)
eq('same uid under a fresh sid is back', isSamePeerBack({ id: 's1', uid: 'u1' }, { id: 's2', uid: 'u1' }), true)
eq('a different peer is not', isSamePeerBack({ id: 's1', uid: 'u1' }, { id: 's2', uid: 'u2' }), false)
eq('no uid on either: only the sid counts', isSamePeerBack({ id: 's1', uid: null }, { id: 's2', uid: null }), false)
eq('nothing left: not back', isSamePeerBack(null, { id: 's1' }), false)
eq('grace is short but covers a rejoin', PEER_LEFT_GRACE_MS >= 1000 && PEER_LEFT_GRACE_MS <= 10000, true)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('pairRejoin.test: ok')
