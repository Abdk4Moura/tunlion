// node frontend/src/lib/__tests__/policy.test.mjs
// Pins the browser adapter's mapping and its fail-closed defaults. The decision
// itself is Rust; the real wasm is replayed by frontend/tests/policy-wire.spec.cjs.
// These tests never re-implement the policy.
import { decideTransfer, mapAdmitOutput, toAdmitInput, admitTransfer } from '../policy.js'
import { linkPolicyFacts } from '../../net/app/policyFacts.js'

let ok = true
const eq = (label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) { console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); ok = false }
  else console.log(`  ${label}: OK`)
}

const NOW = 1000

// ---- no facts: every field the core reads is absent or false ----------------
const empty = toAdmitInput({})
eq('no facts: no authority claimed', empty.authoritative, false)
eq('no facts: no legacy consent', empty.legacyAllowed, false)
eq('no facts: unprovisioned outcome', empty.outcome, { kind: 'unprovisioned' })
eq('no facts: no revoked claim', empty.certRevoked, false)
eq('no facts: no local deny', empty.denied, false)
eq('no facts: no caps', empty.authKeyCaps, null)
eq('no facts: no expiry', empty.certExpires, null)
eq('no facts: no now', empty.now, null)
eq('no facts: no owner claim', empty.sameOwner, false)
eq('no facts: no proof binding', empty.binding, 'none')
eq('no facts: not in bounds', empty.scopedInBounds, false)
eq('no facts: no grant', empty.hasExplicitGrant, false)
eq('no facts: no ceiling', empty.ceilingAuthorizes, false)
eq('no facts: identity pending', empty.identityState, 'pending')

const withDenies = toAdmitInput({ revoked: true, denied: true, expiresAt: 2000, ceiling: true, explicitGrant: true, now: NOW })
eq('a revocation fact reaches the core', withDenies.certRevoked, true)
eq('a local deny fact reaches the core', withDenies.denied, true)
eq('an expiry fact reaches the core', withDenies.certExpires, 2000)
eq('a ceiling fact reaches the core', withDenies.ceilingAuthorizes, true)
eq('an explicit grant fact reaches the core', withDenies.hasExplicitGrant, true)
eq('an owner claim is still not made by the browser', withDenies.sameOwner, false)

// ---- never call the core without an explicit now, and never allow ----------
let consulted = false
const allowIfCalled = async () => { consulted = true; return '{"allowed":true}' }
const noNow = await decideTransfer({ direction: 'receive', status: 'offered', byCode: true, consent: true }, { admit: allowIfCalled })
eq('missing now: core not consulted', consulted, false)
eq('missing now: denied', noNow.allowed, false)
eq('missing now: unsupported', noNow.deny.kind, 'unsupported')
eq('missing now: has a reason', typeof noNow.denyReason, 'string')

const badNow = await decideTransfer({ direction: 'receive', status: 'offered', byCode: true, consent: true, now: NaN }, { admit: allowIfCalled })
eq('non-finite now: core not consulted', consulted, false)
eq('non-finite now: denied', badNow.allowed, false)

const negativeNow = await decideTransfer({ direction: 'receive', status: 'offered', byCode: true, consent: true, now: -1 }, { admit: allowIfCalled })
eq('negative now: core not consulted', consulted, false)
eq('negative now: denied', negativeNow.allowed, false)

// ---- the adapter maps the core's answer, it does not make one --------------
const seen = []
const allowCore = async (json) => {
  seen.push(JSON.parse(json))
  return JSON.stringify({ allowed: true, deny: null, denyReason: null, observableOutcome: { kind: 'authorized' }, fleetOk: false, ceilingOk: false })
}
const mapped = await decideTransfer({ direction: 'receive', status: 'offered', now: NOW }, { admit: allowCore })
eq('core allow maps to allow', mapped.allowed, true)
eq('the explicit now reaches the core', seen[0].now, NOW)
eq('a fractional now is floored', (await decideTransfer({ direction: 'receive', status: 'offered', now: 1000.9 }, { admit: allowCore })), { allowed: true, deny: null, denyReason: null, observableOutcome: { kind: 'authorized' }, fleetOk: false, ceilingOk: false })
eq('the floored now reaches the core', seen[1].now, 1000)

const denyCore = async () => JSON.stringify({ allowed: false, deny: { kind: 'revoked' }, denyReason: 'device revoked', observableOutcome: { kind: 'authorized' }, fleetOk: false, ceilingOk: false })
const denied = await decideTransfer({ direction: 'receive', status: 'offered', byCode: true, consent: true, now: NOW }, { admit: denyCore })
eq('a core denial wins over the facts', denied.allowed, false)
eq('the structured deny is preserved', denied.deny, { kind: 'revoked' })
eq('the core reason is preserved', denied.denyReason, 'device revoked')

eq('a malformed allow is a denial', (await decideTransfer({ now: NOW }, { admit: async () => '{"allowed":"yes"}' })).allowed, false)
eq('an error output is a denial', (await decideTransfer({ now: NOW }, { admit: async () => '{"error":"bad input"}' })).allowed, false)
eq('a throwing core is a denial', (await decideTransfer({ now: NOW }, { admit: async () => { throw new Error('missing wasm') } })).allowed, false)
eq('a missing core is a denial', (await decideTransfer({ now: NOW })).allowed, false)
eq('a missing core is unsupported', (await decideTransfer({ now: NOW })).deny.kind, 'unsupported')

// ---- the DTO mapping for each real link fact -------------------------------
const code = toAdmitInput({ direction: 'receive', status: 'offered', byCode: true, consent: true, now: NOW })
eq('code ceremony: anonymous identity', code.identityState, 'explicitlyUnavailableAnonymous')
eq('code ceremony: no proof binding', code.binding, 'none')
eq('code ceremony: consent is the legacy allow', code.legacyAllowed, true)
eq('code ceremony: in the tab inbox', code.scopedInBounds, true)
eq('code ceremony: no caps', code.authKeyCaps, null)
eq('code ceremony: not provisioned', code.outcome, { kind: 'unprovisioned' })
eq('code ceremony: no cert authority', code.authoritative, false)

const codeNoConsent = toAdmitInput({ direction: 'receive', status: 'offered', byCode: true, now: NOW })
eq('code ceremony without the consent fact does not allow', codeNoConsent.legacyAllowed, false)

const proven = toAdmitInput({ direction: 'receive', status: 'offered', proven: true, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW })
eq('proven record: resolved identity', proven.identityState, 'resolved')
eq('proven record: proven binding', proven.binding, 'proven')
eq('proven record: consent is the legacy allow', proven.legacyAllowed, true)
eq('proven record: caps reach the ceiling check', proven.authKeyCaps, ['transfer'])
eq('proven record: provisioned', proven.outcome, { kind: 'authorized' })

const held = toAdmitInput({ direction: 'receive', status: 'offered', proven: false, relationship: 'remembered', caps: ['transfer'], consent: true, now: NOW })
eq('stored cap, unresolved identity: pending', held.identityState, 'pending')
eq('stored cap, unresolved identity: no proof', held.binding, 'none')
eq('stored cap, unresolved identity: no legacy allow', held.legacyAllowed, false)
eq('stored cap, unresolved identity: the cap is still a fact', held.authKeyCaps, ['transfer'])

const gone = toAdmitInput({ direction: 'receive', status: 'offered', proven: true, relationship: 'unknown', caps: null, consent: true, now: NOW })
eq('a proof of a forgotten record is not proof', gone.binding, 'none')
eq('a proof of a forgotten record is pending', gone.identityState, 'pending')
eq('a proof of a forgotten record does not allow', gone.legacyAllowed, false)

const send = toAdmitInput({ direction: 'send', status: 'offered', byCode: true, consent: true, now: NOW })
eq('our own send is not in the receive inbox', send.scopedInBounds, false)

// ---- the link facts that feed the DTO --------------------------------------
const offer = { direction: 'receive', status: 'offered' }
const codeFacts = linkPolicyFacts({ transfer: offer, byCode: true, now: NOW })
eq('facts: the code is the consent', codeFacts.consent, true)
eq('facts: the code is not a pair proof', codeFacts.proven, false)
eq('facts: the code has no remembered record', codeFacts.relationship, 'unknown')
eq('facts: the code carries the explicit now', codeFacts.now, NOW)

const provenFacts = linkPolicyFacts({ transfer: offer, proven: true, caps: ['transfer'], now: NOW })
eq('facts: a proved record is remembered', provenFacts.relationship, 'remembered')
eq('facts: a proved record is proven', provenFacts.proven, true)
eq('facts: a remembered device is consented', provenFacts.consent, true)

const unprovenFacts = linkPolicyFacts({ transfer: offer, proven: false, caps: ['transfer'], now: NOW })
eq('facts: a stored record alone is consented', unprovenFacts.consent, true)
eq('facts: a stored record alone is not proven', unprovenFacts.proven, false)

const goneFacts = linkPolicyFacts({ transfer: offer, proven: true, caps: null, now: NOW })
eq('facts: a proof of no record collapses to unknown', goneFacts.proven, false)
eq('facts: a proof of no record is not consented', goneFacts.consent, false)

const strangerFacts = linkPolicyFacts({ transfer: offer, now: NOW })
eq('facts: a stranger is not consented', strangerFacts.consent, false)
eq('facts: a stranger has no record', strangerFacts.relationship, 'unknown')

// ---- the raw surface and the output mapper ---------------------------------
let rawInput = null
const raw = await admitTransfer('{"now":1000}', { admit: async (s) => { rawInput = s; return '{"allowed":true}' } })
eq('the raw surface passes JSON through', rawInput, '{"now":1000}')
eq('the raw surface parses the core output', raw, { allowed: true })

eq('an output without a decision never allows', mapAdmitOutput({}).allowed, false)
eq('a null output never allows', mapAdmitOutput(null).allowed, false)
eq('a non-object output never allows', mapAdmitOutput('allow').allowed, false)
eq('an allow carrying a deny never allows', mapAdmitOutput({ allowed: true, deny: { kind: 'revoked' } }).allowed, false)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
