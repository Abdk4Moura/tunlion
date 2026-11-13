// node frontend/src/net/app/__tests__/accept.test.mjs
// Pins which incoming offers the browser asks the shared policy about, and that
// the policy's answer is the only thing that accepts one. The policy itself is
// Rust; the real wasm is driven by frontend/tests/policy-wire.spec.cjs.
import { shouldAutoAccept, offersCoveredNow, acceptIfCurrent } from '../accept.js'
import { readFileSync } from 'node:fs'

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${got} want ${want}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// A stand-in for the core's legacy path only. It does not implement the real
// cap/revocation/expiry policy; the browser gate does that against the wasm.
const admit = async (json) => {
  const i = JSON.parse(json)
  return JSON.stringify({
    allowed: i.legacyAllowed === true,
    deny: i.legacyAllowed ? null : { kind: 'shadowLegacy' },
    denyReason: null,
    observableOutcome: i.outcome,
    fleetOk: false,
    ceilingOk: false,
  })
}
const denyAll = async () => JSON.stringify({
  allowed: false, deny: { kind: 'revoked' }, denyReason: 'device revoked',
  observableOutcome: { kind: 'unprovisioned' }, fleetOk: false, ceilingOk: false,
})

const NOW = 1000
const offer = { direction: 'receive', status: 'offered' }
const opts = { admit }
const code = { ...offer, byCode: true, consent: true, now: NOW }
const proven = { ...offer, proven: true, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW }

eq('receive by code', await shouldAutoAccept(code, opts), true)
eq('a remembered device that proved itself', await shouldAutoAccept(proven, opts), true)
eq('a stranger in the room asks', await shouldAutoAccept({ ...offer, now: NOW }, opts), false)
eq('claimed but unproven asks', await shouldAutoAccept({ ...offer, proven: false, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW }, opts), false)
eq('a code claim without the consent fact asks', await shouldAutoAccept({ ...offer, byCode: true, now: NOW }, opts), false)
eq('our own send is never accepted here', await shouldAutoAccept({ direction: 'send', status: 'offered', proven: true, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW }, opts), false)
eq('only an offer, not a running transfer', await shouldAutoAccept({ ...proven, status: 'transferring' }, opts), false)
eq('the policy denial wins over a code consent', await shouldAutoAccept(code, { admit: denyAll }), false)
eq('the policy denial wins over a proof', await shouldAutoAccept(proven, { admit: denyAll }), false)

// An offer that landed before the consent: re-checked when the consent lands.
const early = [{ id: 'a', ...offer }, { id: 'b', direction: 'receive', status: 'transferring' }, { id: 'c', direction: 'send', status: 'offered' }]
eq('code consent covers the early offer only', (await offersCoveredNow(early, { byCode: true, consent: true, now: NOW }, opts)).join(','), 'a')
eq('proof covers the early offer only', (await offersCoveredNow(early, { proven: true, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW }, opts)).join(','), 'a')
eq('no consent, nothing accepted', (await offersCoveredNow(early, { now: NOW }, opts)).length, 0)

// Both consent paths must re-check offers that arrived first (B01/B02: the
// receive-by-code path did not, so a CLI sender that offered before the
// browser finished the ceremony waited forever).
const hook = readFileSync(new URL('../../../lib/useTunlion.js', import.meta.url), 'utf8')
const webrtc = readFileSync(new URL('../../../lib/webrtc.js', import.meta.url), 'utf8')
const acceptSrc = readFileSync(new URL('../accept.js', import.meta.url), 'utf8')
const eph = hook.slice(hook.indexOf('if (pendingPakeRef.current?.ephemeral)'), hook.indexOf("tel('pake-transfer-authed'"))
eq('receive by code re-checks early offers', /acceptCoveredByPolicy\(/.test(eph), true)
eq('pair-proof re-checks early offers', /proof-ok[\s\S]{0,400}acceptCoveredByPolicy\(/.test(hook), true)
eq('the code ceremony marks the link code-authed, not verified', /_codeAuthed = true/.test(eph) && !/_verified/.test(hook), true)
eq('the state ping reports only the pair proof', /trusted: !!this\._proven/.test(webrtc), true)
eq('accept.js keeps no local trust boolean', /provenKnown|byCode \|\|/.test(acceptSrc), false)

// Suspend the policy result at the actual async boundary, then forget or
// revoke before it returns. A stale allow must never reach acceptTransfer.
for (const mutation of ['forget', 'deny', 'replace', 'close', 'decline']) {
  let finish
  const paused = () => new Promise((resolve) => { finish = resolve })
  const entry = { id: 'race', ...offer }
  let accepted = 0
  const link = { transfers: new Map([['race', entry]]), _closed: false,
    acceptTransfer() { accepted++ } }
  let current = { facts: { ...proven }, recordId: 'peer', secret: 'old' }
  const pending = acceptIfCurrent(link, 'race', () => current, { admit: paused })
  // admitTransfer invokes its injected core synchronously before yielding.
  if (mutation === 'forget') current = null
  if (mutation === 'deny') current = { ...current, facts: { ...current.facts, denied: true } }
  if (mutation === 'replace') current = { ...current, secret: 'new' }
  if (mutation === 'close') link._closed = true
  if (mutation === 'decline') link.transfers.delete('race')
  finish(JSON.stringify({ allowed: true, deny: null }))
  eq(`${mutation} during pending policy cannot auto-accept`, await pending, false)
  eq(`${mutation} never calls acceptTransfer`, accepted, 0)
}

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
