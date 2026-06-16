// Characterization tests for the state-reducer's pure list transforms (Phase 2).
// node frontend/src/net/app/__tests__/state.test.mjs
// Pins addPeer/updatePeer/removePeer/upsertTransfer list logic extracted 1:1 from
// useFilament.js (incl. the same-reference-on-no-change contract React relies on).
import { addPeerToList, patchPeerInList, removePeerFromList, upsertTransferInList } from '../state.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const is = (label, cond) => { if (!cond) { console.log(`  !! ${label}`); ok = false } else console.log(`  ${label}: OK`) }

// --- addPeerToList ---
eq('add to empty', addPeerToList([], { id: 'a' }), [{ id: 'a' }])
eq('append new', addPeerToList([{ id: 'a' }], { id: 'b' }), [{ id: 'a' }, { id: 'b' }])
{
  const l = [{ id: 'a' }]
  is('dup id → SAME reference (no render)', addPeerToList(l, { id: 'a' }) === l)
}

// --- patchPeerInList ---
eq('patch merges', patchPeerInList([{ id: 'a', status: 'connecting' }], 'a', { status: 'ready' }),
  [{ id: 'a', status: 'ready' }])
{
  const l = [{ id: 'a' }]
  is('unknown id → SAME reference (no resurrect #3)', patchPeerInList(l, 'zzz', { status: 'ready' }) === l)
}
eq('patch only the matched peer',
  patchPeerInList([{ id: 'a', n: 1 }, { id: 'b', n: 2 }], 'b', { n: 9 }),
  [{ id: 'a', n: 1 }, { id: 'b', n: 9 }])

// --- removePeerFromList ---
eq('remove by id', removePeerFromList([{ id: 'a' }, { id: 'b' }], 'a'), [{ id: 'b' }])
eq('remove missing → unchanged contents', removePeerFromList([{ id: 'a' }], 'b'), [{ id: 'a' }])

// --- upsertTransferInList (new prepends, existing merges) ---
eq('new transfer prepends (newest first)',
  upsertTransferInList([{ id: 't1' }], { id: 't2', status: 'offered' }),
  [{ id: 't2', status: 'offered' }, { id: 't1' }])
eq('existing transfer merges in place',
  upsertTransferInList([{ id: 't1', progress: 0 }, { id: 't2' }], { id: 't1', progress: 0.5 }),
  [{ id: 't1', progress: 0.5 }, { id: 't2' }])

console.log(ok ? 'STATE TESTS PASS' : 'STATE TESTS FAIL')
process.exit(ok ? 0 : 1)
