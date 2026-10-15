// APPLICATION layer: one row per device in the "here now" list.
//
// A device can be in the room more than once under one install uid: its
// background service (`tunlion up`) and a CLI command it is running
// (`tunlion receive <code>`, `tunlion send`) each hold their own signaling
// session. Showing both as two identical rows is wrong (it is one device) and
// harmful (the copy that is not part of this browser's session cannot take a
// file from it). Keep the copy this browser has a proven relationship with,
// then the one whose link is ready, then the newest.
const rank = (p) => (p.verified ? 4 : 0) + (p.status === 'ready' ? 2 : p.status === 'connecting' ? 1 : 0)

export function oneRowPerDevice(peers) {
  const best = new Map()
  const order = []
  for (const p of peers || []) {
    const key = p.uid ? 'u:' + p.uid : 'i:' + p.id
    const cur = best.get(key)
    if (!cur) { best.set(key, p); order.push(key); continue }
    if (rank(p) >= rank(cur)) best.set(key, p)
  }
  return order.map((k) => best.get(k))
}
