// node frontend/src/lib/__tests__/session.test.mjs
// A room join on the server drops the socket's channel subscriptions. After a
// `welcome` the session must re-assert its channels at once, not wait for the
// 30 s staleness re-sync (two browsers that remember each other stayed OFFLINE
// for about 35 s after a reload).
import { createSession } from '../session.js'

let ok = true
const check = (label, cond) => { console.log(`  ${label}: ${cond ? 'OK' : '!! FAIL'}`); if (!cond) ok = false }

const sent = []
const sig = { connected: true, sync(wire, ack) { sent.push(wire); ack({ ok: true, peers: [] }) } }
const s = createSession(sig)
s.setRoom('r1', 'me', 'u1')
s.setChannels(['a'.repeat(64)])
s.kick()
check('first kick syncs the channels', sent.length === 1 && sent[0].channels.length === 1)
s.kick()
check('an unchanged, confirmed state is not re-sent', sent.length === 1)
check('the session can be told the server rejoined it', typeof s.rejoined === 'function')
if (typeof s.rejoined === 'function') s.rejoined()
check('after a welcome the channels are re-asserted at once', sent.length === 2 && sent[1].channels.length === 1)
s.stop()
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
