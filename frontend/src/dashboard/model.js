// Turn the device's own state (GET /api/state) into what the screens show.
// Everything here is this device's side of each relationship: what each other
// device may do HERE. What this device may do on another one is written on
// that device, so the dashboard says so instead of guessing.

const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
const MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

export function utc(secs) {
  if (!secs) return ''
  const d = new Date(secs * 1000)
  const p = (n) => String(n).padStart(2, '0')
  return `${DAYS[d.getUTCDay()]} ${d.getUTCDate()} ${MON[d.getUTCMonth()]} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())} UTC`
}

export function ago(now, secs) {
  if (!secs) return 'never seen'
  const s = Math.max(0, now - secs)
  if (s < 90) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  const d = Math.round(s / 86400)
  return d === 1 ? 'yesterday' : `${d} days ago`
}

// The CLI's capability names, in the words people use.
export const CAP_WORD = { transfer: 'files', shell: 'shell', mount: 'folders' }
export const capWord = (c) => (CAP_WORD[c] || (c.startsWith('route') ? c.replace(':', ' ') : c))
export const GRANTABLE = ['transfer', 'shell', 'mount']

const list = (a) => (a.length ? a.join(', ') : 'nothing')

export function rows(state) {
  const me = state.me.name
  const perms = new Map((state.perms || []).map((p) => [p.name, p]))
  return (state.devices || []).map((d) => {
    const p = perms.get(d.name) || { caps: [], tier: '', caveats: [] }
    // effective is null when the gate cannot be asked from the store alone
    // (an uncertified, code-paired device); then the cap store's own list,
    // which `devices --json` reports, is what this device enforces.
    const stored = new Set(d.caps || [])
    const live = (p.caps || []).filter((c) => c.resource === 'self' && (c.effective === true || (c.effective == null && stored.has(c.action))))
    for (const a of stored) if (!live.some((c) => c.action === a)) live.push({ action: a, resource: 'self', source: 'grant', valid_until: null, effective: null })
    const caps = live.map((c) => c.action)
    const ends = live.map((c) => c.valid_until).filter(Boolean)
    const until = d.accessUntil || (ends.length ? Math.min(...ends) : null)
    const gone = d.state && d.state !== 'active'
    const group = gone ? 'gone' : p.tier === 'FLEET' ? 'mine' : 'remembered'
    const word = group === 'mine' ? 'my device' : 'remembered'
    let line
    if (d.state === 'revoked') line = `cut off by ${me} · nothing allowed here`
    else if (gone) line = `ended${until ? ' ' + utc(until) : ''} · nothing allowed here`
    else line = `${word} · ${d.name} can use ${me} for: ${list(caps.map(capWord))} · ${until ? 'ends ' + utc(until) : 'no end time'}`
    return {
      name: d.name, group, line, caps, live, until, tier: p.tier, caveats: p.caveats || [],
      state: d.state || 'active', online: d.online, status: d.status, lastSeen: d.lastSeen,
    }
  })
}

// What can reach this device, riskiest first. Each item has one fix.
export function exposure(state, rs, done) {
  const out = []
  const now = state.now
  for (const r of rs) {
    if (r.group === 'gone') continue
    const shell = r.live.find((c) => c.action === 'shell')
    const fromCeiling = shell && /ceiling/.test(shell.source || '')
    if (shell && !shell.valid_until && !r.until) out.push({ id: 'sh-' + r.name, risk: 'high', name: r.name, title: `${r.name} can open a shell on ${state.me.name}, with no end time`, sub: r.line, ...(fromCeiling ? { fix: 'Review', open: r.name } : { fix: 'Remove shell', act: { verb: 'revoke-cap', device: r.name, cap: 'shell' } }) })
  }
  for (const r of rs) {
    if (r.group === 'gone' || !r.caps.length) continue
    if (r.lastSeen && now - r.lastSeen > 30 * 86400 && !r.online) out.push({ id: 'st-' + r.name, risk: 'high', name: r.name, title: `${r.name} hasn't been seen for ${Math.round((now - r.lastSeen) / 86400)} days and still has access`, sub: r.line, fix: 'Cut off', act: { verb: 'cut', device: r.name } })
  }
  for (const r of rs) {
    if (r.group === 'gone') continue
    if (r.tier && r.tier !== 'FLEET' && r.tier !== 'EXTERNAL') out.push({ id: 'tr-' + r.name, risk: 'mid', name: r.name, title: `${r.name} is trusted without a certified identity`, sub: r.caveats.join(' ') || r.line, fix: 'Review', open: r.name })
  }
  for (const r of rs) {
    const shell = r.live.find((c) => c.action === 'shell')
    if (r.group !== 'gone' && shell && (shell.valid_until || r.until)) out.push({ id: 'she-' + r.name, risk: 'low', name: r.name, title: `${r.name} can open a shell on ${state.me.name} until ${utc(shell.valid_until || r.until)}`, sub: r.line, ...(/ceiling/.test(shell.source || '') ? { fix: 'Review', open: r.name } : { fix: 'Remove shell', act: { verb: 'revoke-cap', device: r.name, cap: 'shell' } }) })
  }
  for (const r of rs) {
    if (r.group === 'remembered' && r.caps.length) out.push({ id: 'p-' + r.name, risk: 'low', name: r.name, title: `${r.name} has access here`, sub: r.line, fix: 'Review', open: r.name })
  }
  return out.filter((x) => !done.includes(x.id))
}

// Log lines, newest first, with the kind a filter can pick.
export function history(state) {
  return (state.history || []).slice().reverse().map((l) => {
    const t = l.toLowerCase()
    const kind = /shell|pty|exec/.test(t) ? 'shell' : /receiv|sent|transfer|file/.test(t) ? 'files' : /pair|join|enrol|grant|revok|forget|restor/.test(t) ? 'access' : 'other'
    return { text: l, kind }
  })
}
