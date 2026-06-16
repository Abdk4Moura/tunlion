// APPLICATION layer — the resilience-MANAGER's pure decisions (Phase 2).
//
// useFilament owns the retry budgets, the relay-escalation counter, and the
// network-change recovery EFFECTS (rebuilding PeerLinks, reconnecting signaling).
// The timer-free POLICY of those — "escalate to relay? retry? give a second
// wind? rebuild this link?" — is split out here so it is node-testable, the same
// discipline the net/protocol and net/resilience layers follow. The hook keeps
// the side effects (makeLink, link.close, setTimeout, setState) and delegates the
// decisions.

// P1 (GAP-4): what to do when a link's in-flight stall ladder is exhausted
// (onStall, reason 'persistent'). Bounded: a peer is escalated to relay at most
// once; a relay link that itself stalls falls through to P0's terminal failure.
//   reason        the onStall reason ('persistent' is the only actionable one)
//   relayOnly     this link was ALREADY rebuilt relay-preferred
//   relayedCount  how many times this peer has been relay-escalated
// Returns { action }:
//   'ignore'        not a persistent stall — do nothing
//   'leave-to-p0'   already on relay and it stalled too — let P0 fail it clean
//   'already-spent' the at-most-once relay escalation is used up
//   'escalate-relay' rebuild the link relay-preferred (caller bumps relayedCount)
export function decideStallEscalation({ reason, relayOnly, relayedCount }) {
  if (reason !== 'persistent') return { action: 'ignore' }
  if (relayOnly) return { action: 'leave-to-p0' }
  if ((relayedCount || 0) >= 1) return { action: 'already-spent' }
  return { action: 'escalate-relay' }
}

// Watchdog (#8): a link never connected within its window (onStuck). Retry with a
// fresh link up to maxRetries; then fail honestly, granting ONE delayed "second
// wind" if we're VISIBLE and haven't spent it (the #13 both-tabs-finally-awake
// rendezvous). `attempts` is the ALREADY-INCREMENTED count for this peer.
// Returns { action }:
//   'retry'        tear down + rebuild now
//   'second-wind'  mark failed, then schedule ONE delayed fresh start
//   'fail'         mark failed, stop
export function decideStuckRecovery({ attempts, visible, secondWindUsed, maxRetries = 2 }) {
  if (attempts <= maxRetries) return { action: 'retry' }
  if (visible && !secondWindUsed) return { action: 'second-wind' }
  return { action: 'fail' }
}

// M3/#13: on a "we may be on a new network now" recovery pass, which links to
// rebuild. A link whose RTCPeerConnection is failed/closed/disconnected has a
// dead ICE path (e.g. a wifi↔cellular handoff black-holed it); rebuild it.
export const REBUILD_STATES = ['failed', 'closed', 'disconnected']
export function shouldRebuildLink(connectionState) {
  return REBUILD_STATES.includes(connectionState)
}
