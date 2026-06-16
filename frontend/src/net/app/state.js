// APPLICATION layer — the state-REDUCER's pure list operations (Phase 2).
//
// useFilament keeps the React state (setPeers/setTransfers) and the side effects
// (telemetry, logging, owner/status refs); the pure "merge a snapshot into the
// list" transforms live here so they are node-testable. Each returns a NEW list
// (or the same reference when nothing changed, so React can skip a render).

// Add a peer iff its id is not already present (never duplicates a tile).
export function addPeerToList(list, peer) {
  return list.some((x) => x.id === peer.id) ? list : [...list, peer]
}

// Patch an EXISTING peer only — never re-adds (#3: a late callback from a closed
// PeerLink must not resurrect a removed tile). Unknown id → list unchanged.
export function patchPeerInList(list, id, patch) {
  const i = list.findIndex((x) => x.id === id)
  if (i === -1) return list
  const next = [...list]
  next[i] = { ...next[i], ...patch }
  return next
}

export function removePeerFromList(list, id) {
  return list.filter((p) => p.id !== id)
}

// Insert a new transfer at the FRONT (newest first), or merge a patch into the
// existing one by id.
export function upsertTransferInList(list, t) {
  const i = list.findIndex((x) => x.id === t.id)
  if (i === -1) return [t, ...list]
  const next = [...list]
  next[i] = { ...next[i], ...t }
  return next
}
