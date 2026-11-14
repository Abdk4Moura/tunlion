// node frontend/src/net/app/__tests__/pakeFingerprintRace.test.mjs
//
// The browser reads its DTLS fingerprints from the CURRENT link at the moment
// it sends or checks a key-confirmation MAC:
//
//   getFingerprints: () => linksRef.current.get(peerId)?.fingerprints() || null
//
// and PakeCeremony calls it from _confirmPayload() and from _verify(). If the
// link is REPLACED between those two moments - peer-left closes the old link
// and peer-joined rebinds the ceremony onto a fresh one - the MAC we sent was
// computed over the OLD fingerprints and the peer's MAC is checked against
// the NEW ones. The check then fails and the ceremony aborts with
// "key confirmation failed: wrong code or tampering", which the UI shows as
// "That code didn't match", even though the code was right.
//
// This pins the requirement: a confirmation must be checked against the
// fingerprints of the link it was made on. A link that changed underneath must
// not be reported as a wrong code.
import { PakeCeremony } from '../pakePairing.js'
import { readFileSync } from 'node:fs'

let ok = true
const check = (label, cond, detail = '') => {
  if (!cond) { console.log(`  !! ${label} ${detail}`); ok = false }
  else console.log(`  ${label}: OK`)
}

const enc = (s) => new TextEncoder().encode(s)
const dec = (u8) => new TextDecoder().decode(u8)

// The same stand-in session shape as the pakePairing test: the MAC binds the
// fingerprint PAIR, sorted, the way filament-pair's our_confirm does, so both
// sides agree on the bytes whichever role they took.
let nextId = 0
function fakeSession(password) {
  const mine = `el-${++nextId}`
  const s = { k: null }
  s.message = () => enc(mine)
  s.finish = (peer) => {
    if (s.k) return false
    s.k = `${password}|${[mine, dec(peer)].sort().join('|')}`
    return true
  }
  const token = (myFp, theirFp, caps, sender) => {
    const pair = [myFp, theirFp].sort().join('|')
    return `${s.k}|${pair}|sender:${sender}|caps:${caps}|scope:browser`
  }
  s.ourConfirm = (myFp, theirFp, caps) => (s.k ? enc(token(myFp, theirFp, caps, myFp)) : undefined)
  s.verifyPeerConfirm = (myFp, theirFp, caps, mac) => !!s.k && dec(mac) === token(myFp, theirFp, caps, theirFp)
  s.secret = () => (s.k ? `secret:${s.k}` : undefined)
  return s
}

// One side whose link can be replaced under it. `linkFp` is what the current
// link's fingerprints() reports right now.
function side(name, pw, link) {
  const session = fakeSession(pw)
  const sent = []
  const c = new PakeCeremony({
    nameplate: '314', caps: ['transfer'], capsCanon: 'transfer', session,
    getFingerprints: () => link.fp(),
    sendSignal: (payload) => { sent.push(payload); link.deliver(name, payload) },
    now: () => link.now(),
  })
  return { c, sent, session }
}

// A relay that can hold a message back until we say so.
// One relay, two ends. The local description's fingerprint is this side's own
// DTLS fingerprint, and it is the peer's REMOTE fingerprint, so A's "mine" is
// B's "theirs" and the two sides agree on one pair.
// A relay that can hold a CONFIRMATION back, so a confirmation can be made on
// one link and delivered on another.
function rig({ pwA = 'brave-otter', pwB = 'brave-otter' } = {}) {
  const queue = []
  const deferred = []
  let clock = 1000
  let holdConfirms = false
  const linkA = { fp: () => ({ mine: 'fp-a', theirs: 'fp-b' }), now: () => clock, deliver: (from, p) => queue.push([from, p]) }
  const linkB = { fp: () => ({ mine: 'fp-b', theirs: 'fp-a' }), now: () => clock, deliver: (from, p) => queue.push([from, p]) }
  const a = side('a', pwA, linkA)
  const b = side('b', pwB, linkB)
  const pump = () => {
    let guard = 0
    while (queue.length && guard++ < 100) {
      const [from, payload] = queue.shift()
      if (holdConfirms && payload.type === 'pake-confirm') { deferred.push([from, payload]); continue }
      ;(from === 'a' ? b.c : a.c).onSignal(structuredClone(payload))
    }
    if (queue.length) throw new Error('pairing relay exceeded 100 deliveries; possible ping-pong')
  }
  const step = () => { clock += 250; a.c.tick(); b.c.tick(); pump() }
  const hold = () => { holdConfirms = true }
  const release = () => { holdConfirms = false; while (deferred.length) queue.push(deferred.shift()); pump() }
  return { a, b, linkA, linkB, queue, deferred, pump, step, hold, release }
}

// --- the race: the link is replaced between sending and checking ---------------
{
  const r = rig()
  // Hold the confirmations so they are made on one link and checked on another.
  r.hold()
  // Both sides send their element; both derive K.
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  // A and B each make a confirmation over link generation 1.
  r.a.c.tryConfirm(); r.b.c.tryConfirm(); r.pump()
  check('A sent a confirmation', r.a.sent.some((p) => p.type === 'pake-confirm'))
  check('the confirmations are held by the relay', r.deferred.length > 0, `held=${r.deferred.length}`)

  // The link is REPLACED before the confirmations are checked. Both sides now
  // have different DTLS fingerprints.
  r.linkA.fp = () => ({ mine: 'fp-a2', theirs: 'fp-b2' })
  r.linkB.fp = () => ({ mine: 'fp-b2', theirs: 'fp-a2' })

  // The confirmations, made over generation 1, now arrive.
  r.release()

  check('a confirmation from the previous link is not reported as a wrong code',
    !String(r.b.c.aborted || '').includes('key confirmation failed'),
    `aborted=${r.b.c.aborted}`)
  check('the ceremony is not aborted over a link change',
    !r.b.c.aborted, `aborted=${r.b.c.aborted}`)
}

// --- the same link still confirms ----------------------------------------------
{
  const r = rig()
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  for (let i = 0; i < 40 && !(r.a.c.secret && r.b.c.secret); i++) r.step()
  check('an undisturbed ceremony confirms on both sides', !!r.a.c.secret && !!r.b.c.secret)
  check('an undisturbed ceremony does not abort', !r.a.c.aborted && !r.b.c.aborted)
}

// Observed in #689 WebKit fragment #1/#2/#8: B's old data channel was
// already open, but its element arrived only after pair-matched removed that
// link. A sent an old-link confirmation while B had no fingerprints; B stashed
// it and had never itself sent a confirmation on that old link. On the new
// link the old MAC must be classified as stale, not as a wrong code. A secret
// is released only after the NEW link's confirmation verifies.
{
  const r = rig()
  r.b.c.observeFingerprints?.(r.linkB.fp())
  r.linkB.fp = () => null
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  check('observed race stashes the old confirmation without current fingerprints',
    !!r.b.c._pendingConfirmMac && !r.b.c.sentConfirm && !r.b.c.secret)
  r.linkA.fp = () => ({ mine: 'fp-a2', theirs: 'fp-b2' })
  r.linkB.fp = () => ({ mine: 'fp-b2', theirs: 'fp-a2' })
  r.b.c.tryConfirm()
  check('observed race does not abort the correct code', !r.b.c.aborted, `aborted=${r.b.c.aborted}`)
  check('an old-link confirmation never authorizes either side on the replacement link', !r.a.c.secret && !r.b.c.secret)
  r.pump()
  // The receiver's next confirmation prompts the already-confirmed peer to
  // answer with its confirmation over the current fingerprint pair.
  for (let i = 0; i < 10 && !(r.a.c.secret && r.b.c.secret); i++) r.step()
  check('observed race eventually confirms both sides on the new link', !!r.a.c.secret && !!r.b.c.secret && r.a.c.secret === r.b.c.secret && !r.a.c.aborted && !r.b.c.aborted)
}

// First classify a valid but stale MAC, then deliver a deliberately invalid
// CURRENT-link MAC. This cannot pass by rejecting the stale pair first.
{
  const r = rig()
  r.b.c.observeFingerprints?.(r.linkB.fp())
  r.linkB.fp = () => null
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  r.linkA.fp = () => ({ mine: 'fp-a2', theirs: 'fp-b2' })
  r.linkB.fp = () => ({ mine: 'fp-b2', theirs: 'fp-a2' })
  r.b.c.tryConfirm()
  const staleClassified = !r.b.c.aborted && !r.b.c.secret
  check('valid stale confirmation is classified before the wrong-code control', staleClassified)
  if (staleClassified) {
    r.a.session.k += '|wrong-password'
    r.b.c.onSignal(r.a.c._confirmPayload())
  }
  check('wrong current-link confirmation is specifically refused', staleClassified && /key confirmation failed/.test(r.b.c.aborted || ''))
  check('wrong current-link confirmation releases no secret on either side', !r.a.c.secret && !r.b.c.secret)
}

// Same-pair controls isolate an actual wrong password, reflected confirmation,
// and changed capabilities from the link-replacement path.
{
  const r = rig({ pwA: 'brave-otter', pwB: 'wrong-otter' })
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  check('wrong password on the current link has the specific rejection', /key confirmation failed/.test(r.a.c.aborted || '') || /key confirmation failed/.test(r.b.c.aborted || ''))
  check('wrong current-link password yields no secret on either side', !r.a.c.secret && !r.b.c.secret)
}
{
  const r = rig()
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  const fps = r.linkA.fp()
  const reflected = r.a.session.ourConfirm(fps.mine, fps.theirs, 'transfer')
  check('fake rejects a reflected confirmation', !r.a.session.verifyPeerConfirm(fps.mine, fps.theirs, 'transfer', reflected))
  check('fake rejects changed capabilities', !r.b.session.verifyPeerConfirm(fps.theirs, fps.mine, 'shell', reflected))
}

// Production seam: the actual pair-matched handler must observe the bound
// link before it asks the session to rejoin (which removes the link). This is
// deliberately a source seam assertion, not a real-browser proof by itself.
{
  const hook = readFileSync(new URL('../../../lib/useTunlion.js', import.meta.url), 'utf8')
  const start = hook.indexOf("sig.on('pair-matched'")
  const end = hook.indexOf("sig.on('pair-used'", start)
  const handler = hook.slice(start, end)
  const observed = handler.indexOf('observeFingerprints(')
  const rejoin = handler.indexOf("rejoinRef.current?.(room, 'pair')")
  check('pair-matched captures the bound fingerprints before rejoin', start >= 0 && end > start && observed >= 0 && rejoin > observed)
}

// --- a genuinely wrong code is still refused ----------------------------------
{
  const r = rig({ pwA: 'brave-otter', pwB: 'wrong-otter' })
  r.a.c.sendOurMessage(); r.b.c.sendOurMessage(); r.pump()
  for (let i = 0; i < 40 && !(r.a.c.aborted || r.b.c.aborted); i++) r.step()
  check('a wrong code is still refused', !!(r.a.c.aborted || r.b.c.aborted), `a=${r.a.c.aborted} b=${r.b.c.aborted}`)
  check('a wrong code never yields a secret', !r.a.c.secret && !r.b.c.secret)
}

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
