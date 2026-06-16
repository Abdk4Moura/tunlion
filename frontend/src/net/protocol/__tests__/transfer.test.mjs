// Characterization tests for the filament file-transfer protocol layer. Plain
// Node ESM (no deps): node frontend/src/net/protocol/__tests__/transfer.test.mjs
// These pin the control-message shapes (incl. key ORDER, which encodeControl/
// JSON.stringify emit verbatim — CONTRACT.md is byte-frozen) and the pure
// offer/verify/ack decisions extracted from webrtc.js, so the rewire is provably
// behavior-preserving.
import {
  offerMsg, acceptMsg, declineMsg, endMsg, deliveryAckMsg,
  decideOnOffer, decideAfterVerify, decideAckFallback, sendsToResume,
} from '../transfer.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}
// Pin the exact serialized bytes (key order included).
const eqStr = (label, got, wantStr) => {
  const g = JSON.stringify(got)
  if (g !== wantStr) { console.log(`  !! ${label}: got ${g} want ${wantStr}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// --- message builders: exact shape + key order (the wire is frozen) ---
eqStr('offerMsg fresh (no resume/head/full)',
  offerMsg({ id: 'x', sid: 1, name: 'n', size: 10, mime: 'm' }),
  '{"type":"file-offer","id":"x","sid":1,"name":"n","size":10,"mime":"m"}')
eqStr('offerMsg with head+full',
  offerMsg({ id: 'x', sid: 1, name: 'n', size: 10, mime: 'm', head: 'h', full: 'f' }),
  '{"type":"file-offer","id":"x","sid":1,"name":"n","size":10,"mime":"m","head":"h","full":"f"}')
eqStr('offerMsg resume (resume after mime, then head, full)',
  offerMsg({ id: 'x', sid: 1, name: 'n', size: 10, mime: 'm', resume: true, head: 'h', full: 'f' }),
  '{"type":"file-offer","id":"x","sid":1,"name":"n","size":10,"mime":"m","resume":true,"head":"h","full":"f"}')
eqStr('acceptMsg default offset 0', acceptMsg('x'), '{"type":"file-accept","id":"x","offset":0}')
eqStr('acceptMsg with offset', acceptMsg('x', 4096), '{"type":"file-accept","id":"x","offset":4096}')
eqStr('declineMsg', declineMsg('x'), '{"type":"file-decline","id":"x"}')
eqStr('endMsg', endMsg('x', 7), '{"type":"file-end","id":"x","sid":7}')
eqStr('deliveryAckMsg carries v:1', deliveryAckMsg('x', 7), '{"type":"delivery-ack","id":"x","sid":7,"v":1}')

// --- decideOnOffer: auto-accept only when resuming AND we hold a partial ---
eq('onOffer resume+partial → auto-accept', decideOnOffer({ resume: true, hasPartial: true }), { action: 'auto-accept' })
eq('onOffer resume+no-partial → surface', decideOnOffer({ resume: true, hasPartial: false }), { action: 'surface' })
eq('onOffer fresh → surface', decideOnOffer({ resume: false, hasPartial: false }), { action: 'surface' })
eq('onOffer fresh+stray-partial → surface', decideOnOffer({ resume: false, hasPartial: true }), { action: 'surface' })

// --- decideAfterVerify: the whole-file verify decision tree ---
const MAXF = 2
eq('verify match → finalize-ack',
  decideAfterVerify({ hashMatches: true, received: 10, size: 10, verifyFails: 0, maxFails: MAXF }),
  { action: 'finalize-ack' })
eq('verify mismatch truncated → rerequest from offset, no reset',
  decideAfterVerify({ hashMatches: false, received: 6, size: 10, verifyFails: 1, maxFails: MAXF }),
  { action: 'rerequest', offset: 6, reset: false })
eq('verify mismatch full-size (corrupt) → rerequest 0, reset',
  decideAfterVerify({ hashMatches: false, received: 10, size: 10, verifyFails: 1, maxFails: MAXF }),
  { action: 'rerequest', offset: 0, reset: true })
eq('verify mismatch over bound → fail',
  decideAfterVerify({ hashMatches: false, received: 10, size: 10, verifyFails: 3, maxFails: MAXF }),
  { action: 'fail' })
eq('verify match wins even over bound',
  decideAfterVerify({ hashMatches: true, received: 10, size: 10, verifyFails: 9, maxFails: MAXF }),
  { action: 'finalize-ack' })

// --- decideAckFallback: never returns complete; honest fail or one reprobe ---
eq('ack unhealthy → fail/resumable',
  decideAckFallback({ channelOpen: false, connected: true, peerHasAcked: true, offeredDigest: true, reprobed: false }),
  { action: 'fail', resumable: true })
eq('ack healthy not-yet-reprobed → reprobe',
  decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: false, offeredDigest: false, reprobed: false }),
  { action: 'reprobe' })
eq('ack healthy already-reprobed → fail/resumable',
  decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: false, offeredDigest: false, reprobed: true }),
  { action: 'fail', resumable: true })

// --- sendsToResume: complete sends the peer holds short ---
{
  const local = new Map([
    ['a', { direction: 'send', status: 'complete', size: 100 }],   // peer short → resume
    ['b', { direction: 'send', status: 'complete', size: 100 }],   // peer has all → skip
    ['c', { direction: 'send', status: 'transferring', size: 100 }], // not complete → skip
    ['d', { direction: 'receive', status: 'complete', size: 100 }], // not a send → skip
  ])
  const peer = { a: 40, b: 100, c: 10, d: 40, e: 5 /* unknown id → skip */ }
  eq('sendsToResume picks only short complete sends', sendsToResume(peer, local), ['a'])
  eq('sendsToResume empty peer digest → []', sendsToResume(undefined, local), [])
}

console.log(ok ? 'TRANSFER TESTS PASS' : 'TRANSFER TESTS FAIL')
process.exit(ok ? 0 : 1)
