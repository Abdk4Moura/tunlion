// The dashboard talks only to the device that served it (same origin). The
// one-time secret arrives in the URL fragment, is traded once for an HttpOnly
// session cookie, and is wiped from the address bar straight away.

export async function signIn() {
  const m = /(?:^|[#&])k=([0-9a-f]{64})(?:&|$)/.exec(location.hash || '')
  // Clear the fragment whatever happens: the secret must not linger in history.
  if (location.hash) history.replaceState(null, '', location.pathname)
  if (!m) {
    // Maybe already signed in (a reload keeps the cookie).
    const r = await fetch('/api/state', { credentials: 'same-origin' })
    if (r.ok) return { ok: true }
    return { ok: false, error: 'Open the dashboard from the link `tunlion dashboard` prints. Each link works once.' }
  }
  const r = await fetch('/api/session', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret: m[1] }),
  })
  const j = await r.json().catch(() => ({}))
  return r.ok ? { ok: true } : { ok: false, error: j.error || 'That link did not work. Run tunlion dashboard again.' }
}

export async function getState() {
  const r = await fetch('/api/state', { credentials: 'same-origin' })
  const j = await r.json().catch(() => null)
  if (!r.ok || !j) throw new Error((j && j.error) || 'The dashboard stopped answering.')
  return j
}

async function post(path, body) {
  const r = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const j = await r.json().catch(() => ({ ok: false, error: 'No answer.' }))
  return j
}

export const act = (verb, args) => post('/api/act', { verb, ...args })
export const invite = (args) => post('/api/invite', args)
export const startCode = (args) => post('/api/code', args)
export const cancelCode = () => post('/api/code/cancel', {})
export async function codeStatus() {
  const r = await fetch('/api/code', { credentials: 'same-origin' })
  return r.json().catch(() => ({ ok: false }))
}
