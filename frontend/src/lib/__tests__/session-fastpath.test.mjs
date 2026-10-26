// node frontend/src/lib/__tests__/session-fastpath.test.mjs
// The convergent session's fast path must not wait for the 5 s tick.
//   - a change made while a sync is in flight goes out when its ack lands;
//   - setRoom / setChannels changes raise themselves;
//   - a lost emit is re-sent when the ack window lapses (ACK_MS), not at the
//     first tick after it;
//   - a sync the transport declined (no token yet) does not hold the guard.
// A manual clock drives every timer, so nothing here sleeps.
let now = 1_000_000
const timers = []
let nextId = 1
globalThis.Date.now = () => now
globalThis.setTimeout = (fn, ms) => { const id = nextId++; timers.push({ id, at: now + ms, fn }); return id }
globalThis.clearTimeout = (id) => { const i = timers.findIndex((t) => t.id === id); if (i >= 0) timers.splice(i, 1) }
globalThis.setInterval = (fn, ms) => { const id = nextId++; const t = { id, at: now + ms, fn, every: ms }; timers.push(t); return id }
globalThis.clearInterval = globalThis.clearTimeout
const advance = async (ms) => {
  const end = now + ms
  for (;;) {
    timers.sort((a, b) => a.at - b.at)
    const t = timers[0]
    if (!t || t.at > end) break
    now = t.at
    if (t.every) t.at += t.every
    else timers.shift()
    t.fn()
    await Promise.resolve()
  }
  now = end
}
const flush = () => new Promise((r) => queueMicrotask(r))

const { createSession } = await import('../session.js')

let ok = true
const check = (label, cond) => { console.log(`  ${label}: ${cond ? 'OK' : '!! FAIL'}`); if (!cond) ok = false }

// A transport whose acks we release by hand.
function fakeSig() {
  const sig = { connected: true, sent: [], acks: [], drop: false, declined: false }
  sig.sync = (wire, ack) => {
    if (sig.declined) return false
    sig.sent.push(wire)
    if (!sig.drop) sig.acks.push(() => ack({ ok: true, peers: [] }))
    return true
  }
  sig.ackAll = () => { const a = sig.acks.splice(0); a.forEach((f) => f()) }
  return sig
}
const CH = 'a'.repeat(64)

{
  const sig = fakeSig()
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  s.kick()
  check('the first kick sends the room', sig.sent.length === 1 && sig.sent[0].room === 'r1')
  s.setChannels([CH]) // a device stored while the first sync is in flight
  s.kick()
  await flush()
  check('a change inside the ack window is not sent twice at once', sig.sent.length === 1)
  await advance(50)
  sig.ackAll()
  check('the change goes out the moment the ack lands', sig.sent.length === 2 && sig.sent[1].channels.length === 1)
  sig.ackAll()
  await advance(20000)
  check('a converged session stays quiet until the staleness re-sync', sig.sent.length === 2)
  s.stop()
}

{
  const sig = fakeSig()
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  s.kick(); sig.ackAll()
  const before = sig.sent.length
  s.setChannels([CH])
  await flush()
  check('setChannels raises itself, with no kick and no tick', sig.sent.length === before + 1)
  sig.ackAll()
  s.setRoom('r2', 'me', 'u1')
  check('setRoom does not sync before the caller finishes its turn', sig.sent.length === before + 1)
  await flush()
  check('setRoom raises itself on the next microtask', sig.sent.length === before + 2 && sig.sent.at(-1).room === 'r2')
  sig.ackAll()
  s.setChannels([CH])
  await flush()
  check('an unchanged edit does not emit', sig.sent.length === before + 2)
  s.stop()
}

{
  const sig = fakeSig()
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  sig.drop = true
  s.kick()
  check('a sync went out', sig.sent.length === 1)
  sig.drop = false
  await advance(4000)
  check('a lost emit is re-sent when the ack window lapses (4 s), not at the next tick', sig.sent.length === 2)
  sig.ackAll()
  s.stop()
}

{
  const sig = fakeSig()
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  sig.declined = true
  s.kick()
  check('a declined sync sent nothing', sig.sent.length === 0)
  sig.declined = false
  s.kick()
  check('a declined sync does not hold the in-flight guard', sig.sent.length === 1)
  sig.ackAll()
  s.stop()
}

{
  const sig = fakeSig()
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  s.kick()
  s.stop()
  const pending = timers.length
  check('stop() leaves no timer behind', pending === 0)
  sig.ackAll()
}

{
  // Firebase acks inside sync(); the session must accept that ack.
  const sent = []
  const sig = { connected: true, sync(w, ack) { sent.push(w); ack({ v: 1, ok: true, firebase: true }) } }
  const s = createSession(sig)
  s.setRoom('r1', 'me', 'u1')
  s.kick(); s.kick()
  await advance(10000)
  check('a synchronous ack confirms (no re-send loop)', sent.length === 1)
  s.stop()
}

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
