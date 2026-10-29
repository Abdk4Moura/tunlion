// node frontend/src/net/app/__tests__/pakePairing.test.mjs
//
// The browser code ceremony over a lossy, duplicating relay. The SPAKE2 session
// is a stand-in with the same shape as the WASM one (K depends on the password
// and both elements; each side's MAC binds its own fingerprint), so these pin
// the ceremony's state machine, not the cryptography (the Rust tests do that).
import { PakeCeremony, resendDelay } from '../pakePairing.js'

let ok = true
const check = (label, cond, detail = '') => {
  if (!cond) { console.log(`  !! ${label} ${detail}`); ok = false }
  else console.log(`  ${label}: OK`)
}

const enc = (s) => new TextEncoder().encode(s)
const dec = (u8) => new TextDecoder().decode(u8)

let nextId = 0
function fakeSession(password) {
  const mine = `el-${++nextId}`
  const s = { finishes: 0, k: null }
  s.message = () => enc(mine)
  s.finish = (peer) => {
    s.finishes += 1
    if (s.k) return false // a real session is consumed by its first finish
    s.k = `${password}|${[mine, dec(peer)].sort().join('|')}`
    return true
  }
  s.ourConfirm = (myFp) => (s.k ? enc(`${s.k}|${myFp}`) : undefined)
  s.verifyPeerConfirm = (_myFp, theirFp, _caps, mac) => !!s.k && dec(mac) === `${s.k}|${theirFp}`
  s.secret = () => (s.k ? `secret:${s.k}` : undefined)
  return s
}

// Two ceremonies joined by a relay that can drop or duplicate each message.
// `fate(from, payload, n)` is 'drop' | 'dup' | 'ok' for the n-th copy of that
// message kind from that side.
function rig({ pwA = 'brave-otter', pwB = 'brave-otter', fate = () => 'ok' } = {}) {
  let t = 0
  const now = () => t
  const queue = []
  const sent = { a: [], b: [] }
  const counts = {}
  const mk = (name, pw, myFp, theirFp) => {
    const session = fakeSession(pw)
    const c = new PakeCeremony({
      nameplate: '314', caps: ['transfer'], capsCanon: 'transfer', session, now,
      getFingerprints: () => ({ mine: myFp, theirs: theirFp }),
      sendSignal: (payload) => {
        sent[name].push(payload)
        const key = `${name}:${payload.type}`
        counts[key] = (counts[key] || 0) + 1
        const f = fate(name, payload, counts[key])
        if (f === 'drop') return
        queue.push([name, payload])
        if (f === 'dup') queue.push([name, payload])
      },
    })
    c.fake = session
    return c
  }
  const a = mk('a', pwA, 'fp-a', 'fp-b')
  const b = mk('b', pwB, 'fp-b', 'fp-a')
  const pump = () => {
    while (queue.length) {
      const [from, payload] = queue.shift()
      ;(from === 'a' ? b : a).onSignal(structuredClone(payload))
    }
  }
  const step = (ms) => {
    t += ms
    for (const c of [a, b]) { c.tick(); c.sendOurMessage(); c.tryConfirm() }
    pump()
  }
  // Run until both settle (or the bound), ticking at the hook's 100 ms.
  const run = (boundMs) => {
    a.sendOurMessage(); b.sendOurMessage(); pump()
    while (t < boundMs && !((a.secret || a.aborted) && (b.secret || b.aborted))) step(100)
    return t
  }
  return { a, b, run, sent, pump, queue }
}

// --- backoff schedule ---------------------------------------------------------
check('backoff: 250 then 500, 1000, capped at 2000',
  [0, 1, 2, 3, 4, 9].map(resendDelay).join(',') === '250,500,1000,2000,2000,2000')

// --- the first copy of every ceremony message is lost --------------------------
{
  const r = rig({ fate: (_from, _p, n) => (n === 1 ? 'drop' : 'ok') })
  const ms = r.run(3000)
  check('first copies lost: both sides confirm', !!r.a.secret && !!r.b.secret, `after ${ms}ms`)
  check('first copies lost: same secret', r.a.secret === r.b.secret)
  check('first copies lost: well under 3s', ms < 3000, `${ms}ms`)
  console.log(`    (completed in ${ms}ms of relay time)`)
}

// --- only one element lost: the confirmation carries it -------------------------
{
  const r = rig({ fate: (from, p, n) => (from === 'a' && p.type === 'pake-msg' && n === 1 ? 'drop' : 'ok') })
  const ms = r.run(3000)
  check('element lost, confirm arrives first: no abort', !r.a.aborted && !r.b.aborted, `${r.a.aborted || r.b.aborted}`)
  check('element lost: completes', !!r.a.secret && r.a.secret === r.b.secret, `after ${ms}ms`)
}

// --- every message delivered twice --------------------------------------------
{
  const r = rig({ fate: () => 'dup' })
  r.run(3000)
  check('duplicates: both confirm, no abort', !!r.a.secret && !!r.b.secret && !r.a.aborted && !r.b.aborted)
  check('duplicates: one SPAKE2 finish per side', r.a.fake.finishes === 1 && r.b.fake.finishes === 1,
    `a=${r.a.fake.finishes} b=${r.b.fake.finishes}`)
  // A confirmed side that gets the peer's confirmation again answers it with
  // its same confirmation, and stays confirmed.
  const ours = r.sent.b.filter((p) => p.type === 'pake-confirm')[0]
  const theirs = r.sent.a.filter((p) => p.type === 'pake-confirm')[0]
  const before = r.sent.b.length
  const secret = r.b.secret
  r.b.onSignal(structuredClone(theirs))
  const reply = r.sent.b.slice(before)
  check('duplicate confirm is answered once, with the same confirmation',
    reply.length === 1 && JSON.stringify({ ...reply[0], answer: undefined }) === JSON.stringify(ours))
  check('the answer is marked, so a confirmed peer does not answer back', reply[0]?.answer === true)
  const sentByA = r.sent.a.length
  r.a.onSignal(structuredClone(reply[0]))
  check('an answer is never answered', r.sent.a.length === sentByA)
  check('duplicate confirm changes nothing', r.b.secret === secret && !r.b.aborted)
  // A copy that does not verify (an old link's) is not a second attempt.
  r.b.onSignal({ ...theirs, mac: btoa('garbage') })
  check('a non-verifying copy after confirming is ignored', r.b.secret === secret && !r.b.aborted)
}

// --- wrong code, with loss: re-sends are never another guess -------------------
{
  const r = rig({ pwB: 'brave-ottar', fate: (_from, _p, n) => (n === 1 ? 'drop' : 'ok') })
  r.run(3000)
  check('wrong code: nobody confirms', !r.a.secret && !r.b.secret)
  check('wrong code: refused', !!r.a.aborted || !!r.b.aborted)
  check('wrong code: one SPAKE2 finish per side', r.a.fake.finishes <= 1 && r.b.fake.finishes <= 1)
  const els = new Set([...r.sent.a.map((p) => p.msg)])
  check('every copy carries the same element', els.size === 1)
  const after = r.sent.a.length + r.sent.b.length
  for (const c of [r.a, r.b]) for (let i = 0; i < 50; i++) c.tick()
  check('a refused or confirmed ceremony stops re-sending', r.sent.a.length + r.sent.b.length === after)
}

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
