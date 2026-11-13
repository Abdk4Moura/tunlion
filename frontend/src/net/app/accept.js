// APPLICATION layer: whether an incoming file offer is accepted without a click.
//
// The trust decision is NOT here. It is the shared core
// (crates/filament-policy, compiled to tunlion-policy-wasm) called through
// lib/policy.js. This module only decides whether auto-accept APPLIES (a
// receive offer) and forwards the caller's real link facts to the core.
//
// The old local boolean (a code, or a claimed proof with no link proof) is
// gone. If the core cannot be consulted, the offer waits for a click.
import { decideTransfer } from '../../lib/policy.js'

export async function shouldAutoAccept(facts, opts) {
  if (!facts || facts.direction !== 'receive' || facts.status !== 'offered') return false
  const decision = await decideTransfer(facts, opts)
  return decision.allowed === true
}

// The decision may wait for WASM initialization. Never act on an allow after
// the trust facts, link or offer changed during that wait. `snapshot` is read
// again synchronously immediately before accept; the caller includes the
// identity of the actual proved record, not just its displayed capabilities.
export async function acceptIfCurrent(link, id, snapshot, opts) {
  const offer = link.transfers.get(id)
  if (!offer || link._closed) return false
  // A rollover requires a fresh decision with the new clock: an allowance
  // before expiry is not an allowance after expiry. Bound retries so a slow
  // core fails closed instead of spinning indefinitely.
  for (let attempt = 0; attempt < 3; attempt++) {
    const before = snapshot(offer)
    if (!before) return false
    const { now, ...beforeFacts } = before.facts
    const token = JSON.stringify({ ...before, facts: beforeFacts })
    if (!await shouldAutoAccept(before.facts, opts)) return false
    const current = link.transfers.get(id)
    if (!current || current !== offer || link._closed) return false
    const after = snapshot(current)
    if (!after) return false
    const { now: currentNow, ...afterFacts } = after.facts
    if (JSON.stringify({ ...after, facts: afterFacts }) !== token) return false
    if (currentNow !== now) continue
    // Only a live, proved remembered record can bind a partial to a peer.
    // A one-time code authenticates this session, not a durable identity.
    const owner = after.facts.proven && after.recordId && after.secret
      ? { id: after.recordId, secret: after.secret } : null
    link.acceptTransfer(id, owner)
    return true
  }
  return false
}

// Offers that arrived BEFORE the consent was established (the pair-proof or the
// code ceremony finishes asynchronously, and a sender may offer first) are
// re-checked the moment it lands, so the order of the two never decides the
// outcome. The transfer owns direction/status; `facts` supplies the trust
// facts (byCode, proven, relationship, caps, consent, now). Returns the ids the
// core allows.
export async function offersCoveredNow(transfers, facts = {}, opts) {
  const ids = []
  for (const t of transfers || []) {
    // Trust facts come from the caller; the transfer owns what it is and where
    // it is in its lifecycle.
    const merged = { ...t, ...facts }
    if (t.direction !== undefined) merged.direction = t.direction
    if (t.status !== undefined) merged.status = t.status
    if (await shouldAutoAccept(merged, opts)) ids.push(t.id)
  }
  return ids
}
