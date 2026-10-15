// APPLICATION layer: whether an incoming file offer is accepted without a click.
//
// A person consented once, and that consent covers the offer:
//   - a receive by code: typing the code was the consent (`tunlion receive
//     <code>` never asks either);
//   - a device this browser remembered, and the device proved it on this link
//     (its pair-proof matched a stored secret). Remembering a device is what
//     lets it send here, as a paired device may send into a CLI's inbox.
// Anything else (a stranger in the same-network room, a device that claims to
// be remembered but has not proved it) still asks.
// Accepting only moves the bytes into this tab; saving the file stays a click.
export function shouldAutoAccept({ direction, status, byCode, provenKnown }) {
  if (direction !== 'receive' || status !== 'offered') return false
  return !!(byCode || provenKnown)
}

// Offers that arrived BEFORE the consent was established (the pair-proof or the
// code ceremony finishes asynchronously, and a sender may offer first) are
// re-checked the moment it lands, so the order of the two never decides the
// outcome. Returns the ids to accept.
export function offersCoveredNow(transfers, { byCode = false, provenKnown = false } = {}) {
  const ids = []
  for (const t of transfers || []) {
    if (shouldAutoAccept({ ...t, byCode, provenKnown })) ids.push(t.id)
  }
  return ids
}
