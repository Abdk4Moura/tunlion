// The browser's single adapter onto the shared transfer-admission policy.
//
// The decision itself is Rust (crates/filament-policy), compiled to wasm
// (crates/tunlion-policy-wasm) and called as admitTransfer(JSON). This module
// does three things and nothing else:
//   1. translate browser facts into the policy's required input DTO,
//   2. call the core with an explicit `now`,
//   3. map the core's decision back to allow/deny.
//
// It contains no allow rule. If the core cannot be consulted,
// `decideTransfer` returns an "unsupported" denial, never an allow. The wasm
// loading lives in policyCore.js so this module stays importable by plain Node
// for the adapter tests.

/// A denial that did not come from the core: the core is missing, the input
/// could not be built, or the core returned something malformed. `unsupported`
/// is adapter-only; it is never emitted by the Rust policy.
export function unsupported(reason) {
  return {
    allowed: false,
    deny: { kind: 'unsupported' },
    denyReason: reason ? String(reason) : 'policy core unavailable',
    observableOutcome: null,
    fleetOk: false,
    ceilingOk: false,
  }
}

/// Translate the browser's facts into the complete, required policy input.
/// Every field is explicit: there are no wire defaults.
export function toAdmitInput(facts) {
  const f = facts && typeof facts === 'object' ? facts : {}
  const direction = f.direction === 'receive' || f.direction === 'send' ? f.direction : null
  const byCode = f.byCode === true
  const remembered = f.relationship === 'remembered'
  const caps = remembered && Array.isArray(f.caps) ? f.caps.map((c) => String(c)) : null
  const hasRecord = caps !== null
  // A proof of a record that no longer exists is not a proof of anything.
  const proven = f.proven === true && hasRecord
  const consent = f.consent === true
  // Seconds since the epoch, the only clock the policy reads. A negative or
  // non-finite value is not a time; the caller gets an unsupported denial.
  const now = Number.isFinite(f.now) && f.now >= 0 ? Math.floor(f.now) : null
  const expiresAt = Number.isFinite(f.expiresAt) && f.expiresAt >= 0 ? Math.floor(f.expiresAt) : null

  // A code ceremony is the one case where the peer explicitly has no
  // certificate: the typed code selected it and the ceremony authenticated it.
  // A pair-proof resolves a remembered record; anything else is still pending.
  const identityState = byCode && !proven
    ? 'explicitlyUnavailableAnonymous'
    : (proven ? 'resolved' : 'pending')

  return {
    // The browser holds no capability header or certificate chain, so it cannot
    // claim authority. The core still applies explicit denial and cap-ceiling
    // facts below, plus expiry when a remembered record carries one; the legacy
    // allow is the human consent the browser does hold.
    authoritative: false,
    // Consent only counts for the identity it was given to: a code ceremony on
    // this link, or a pair-proof of a remembered record. A stored record that
    // has not proved itself does not get here.
    legacyAllowed: consent && (byCode || proven),
    // A remembered record means the resource is provisioned. The core decides
    // whether "transfer" is inside that record's caps.
    outcome: hasRecord ? { kind: 'authorized' } : { kind: 'unprovisioned' },
    certRevoked: f.revoked === true,
    denied: f.denied === true,
    authKeyCaps: caps,
    certExpires: expiresAt,
    now,
    // No browser fact establishes the owner relationship.
    sameOwner: false,
    // The core's name for link-identity strength. The browser's strongest
    // proof is a pair-proof of a stored secret, not a device certificate; with
    // no authority claimed it only annotates the decision, never grants one.
    binding: proven ? 'proven' : 'none',
    // A received file lands in this tab's transfer inbox, not an arbitrary path.
    scopedInBounds: direction === 'receive',
    hasExplicitGrant: f.explicitGrant === true,
    ceilingAuthorizes: f.ceiling === true,
    identityState,
  }
}

/// Map the core's decision to the browser's allow/deny view. A malformed or
/// errored response can only become a denial.
export function mapAdmitOutput(output) {
  if (!output || typeof output !== 'object') return unsupported('policy core returned no decision')
  if (output.error) return unsupported(output.error)
  if (output.allowed !== true && output.allowed !== false) {
    return unsupported('policy core returned no allow/deny')
  }
  if (output.allowed === true && output.deny) {
    return unsupported('policy core returned an allow with a deny')
  }
  return {
    allowed: output.allowed === true,
    deny: output.deny || null,
    denyReason: output.denyReason || null,
    observableOutcome: output.observableOutcome || null,
    fleetOk: output.fleetOk === true,
    ceilingOk: output.ceilingOk === true,
  }
}

let defaultCore = null

function core() {
  if (!defaultCore) defaultCore = import('./policyCore.js').then((m) => m.initPolicyWasm())
  return defaultCore
}

/// The raw JSON-in/JSON-out surface, for the shared browser vectors. Invalid
/// input is the core's business: it returns `{"error":"..."}`, which the caller
/// can inspect. Loading the module itself throws, so a missing artifact cannot
/// look like a policy result.
export async function admitTransfer(input, { admit } = {}) {
  const call = admit || (await core())
  const raw = await call(typeof input === 'string' ? input : JSON.stringify(input))
  return typeof raw === 'string' ? JSON.parse(raw) : raw
}

/// The one browser decision entrypoint. `now` is required and explicit: the
/// policy reads no clock of its own.
export async function decideTransfer(facts, { admit } = {}) {
  const input = toAdmitInput(facts)
  if (input.now === null) return unsupported('an explicit now is required')
  try {
    return mapAdmitOutput(await admitTransfer(JSON.stringify(input), { admit }))
  } catch (e) {
    return unsupported('policy core unavailable: ' + (e && e.message ? e.message : String(e)))
  }
}
