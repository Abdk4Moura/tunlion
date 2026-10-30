// APPLICATION layer: room moves and peer churn around a code ceremony.
//
// Pairing is additive: the claimer joins the creator's CURRENT room. On the
// same network both are already in that room, so a leave + join is a no-op
// move that only tears down the link the ceremony runs on. And the creator
// must not read a peer-left that is promptly followed by the same peer
// coming back (same sid, or same uid under a new sid) as "the other device
// ended the pairing": that is a rejoin, not a refusal.

/// How long a ceremony survives its partner's peer-left, waiting for the same
/// peer to rejoin. A CLI that refuses a bad confirmation leaves and stays
/// gone, so a real refusal still fails, just this much later.
export const PEER_LEFT_GRACE_MS = 4000

/// pair-matched names the room to join. Rejoin only when it is a different
/// room from the one we are in (or we are in none).
export function shouldRejoinOnPairMatched(currentRoom, matchedRoom) {
  if (!matchedRoom) return false
  return currentRoom !== matchedRoom
}

/// A peer that left mid-ceremony (`left`: {id, uid}) is back when the joining
/// peer has the same sid, or the same non-empty uid under a fresh sid.
export function isSamePeerBack(left, joined) {
  if (!left || !joined) return false
  if (left.id && joined.id === left.id) return true
  return !!(left.uid && joined.uid && joined.uid === left.uid)
}
