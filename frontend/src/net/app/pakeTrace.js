// Opt-in, bounded pairing diagnostics for CI. Never log a code, peer id, PAKE
// element, MAC, secret, or raw DTLS fingerprint. Sequence numbers are assigned
// before asynchronous hashing so log ordering can be reconstructed.
let sequence = 0
let nextObjectId = 0
const ids = new WeakMap()
function objectId(value) {
  if (!value || (typeof value !== 'object' && typeof value !== 'function')) return null
  if (!ids.has(value)) ids.set(value, ++nextObjectId)
  return ids.get(value)
}

export function tracePake(event, { ceremony, link, fingerprints, state } = {}) {
  try {
    if (sessionStorage.getItem('tunlion.pakeTrace') !== '1' || sequence >= 160) return
    const seq = ++sequence
    const row = { seq, event, ceremony: objectId(ceremony), link: objectId(link), state: state || null }
    if (!fingerprints || !crypto?.subtle) {
      console.info('[pake-trace]', JSON.stringify({ ...row, pairHash: null }))
      return
    }
    const pair = [fingerprints.mine, fingerprints.theirs].sort().join('\0')
    crypto.subtle.digest('SHA-256', new TextEncoder().encode(pair)).then((hash) => {
      const pairHash = Array.from(new Uint8Array(hash), (b) => b.toString(16).padStart(2, '0')).join('')
      console.info('[pake-trace]', JSON.stringify({ ...row, pairHash }))
    }).catch(() => console.info('[pake-trace]', JSON.stringify({ ...row, pairHash: null })))
  } catch {
    // Diagnostics must not affect a pairing.
  }
}
