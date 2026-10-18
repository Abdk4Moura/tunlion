// APPLICATION layer — the resilience-MANAGER's pure decisions (Phase 2).
//
// useTunlion owns the retry budgets, the relay-escalation counter, and the
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

// Is this PeerLink still a live data path? Signaling presence and the data
// channel are independent: a roster digest can briefly omit a peer (our own
// signaling reconnect, the peer re-subscribing on a fresh sid) while its
// WebRTC channel is still open and carrying a shell. This is the browser half
// of the server's #513 rule; it lets digest reconcile tell "absent from the
// roster" from "the link is gone". Same shape as WebTerminal's down check.
export function linkIsLive(link) {
  const ch = link && link.channel
  if (!ch || ch.readyState !== 'open') return false
  const pc = link && link.pc
  return !pc || pc.connectionState === 'connected'
}

// C30 phase 2 digest reconcile, as a pure decision.
//
// `peers` is the roster in the sync ack; `links` is [{id, live}] for every
// PeerLink we hold; `channelPids` are channel-introduced known-device links
// (room-independent by design). A room link absent from TWO consecutive
// digests is a missed peer-left and may be retired — but only when its own
// transport is not alive. An alive link is deferred indefinitely: presence
// gaps are not a data-plane failure (#513), and a peer that really went away
// closes its channel, which makes the next miss actionable.
//
// Returns { adopt, drops, misses }: new peers to link, link ids to retire, and
// the next consecutive-miss map (fresh for present/channel/live links, so a
// transient absence never leaves a half-armed drop).
export function reconcileDigest({ peers, present, links, channelPids, misses, threshold = 2 }) {
  const linked = new Set((links || []).map((l) => l && l.id).filter(Boolean))
  const adopt = (peers || []).filter((p) => p && p.id && !linked.has(p.id))
  const absent = misses instanceof Map ? misses : new Map()
  const next = new Map()
  const drops = []
  for (const l of links || []) {
    if (!l || !l.id) continue
    if (present.has(l.id) || channelPids.has(l.id) || l.live) continue
    const n = (absent.get(l.id) || 0) + 1
    if (n >= threshold) drops.push(l.id)
    else next.set(l.id, n)
  }
  return { adopt, drops, misses: next }
}
