// Known devices: the browser half of persistent pairing (C12/C20).
//
// A "known device" is a {name, secret} pair persisted in localStorage. The
// secret is E2E: the server only ever sees sha256("filament-pair:"+secret),
// the meeting-point channel two holders subscribe to. Mutual acknowledgement
// is structural: presence lights up ONLY when both sides hold the secret and
// raise the same channel; trust is asserted per-link with an HMAC proof bound
// to the link's DTLS fingerprints, so neither the server nor a MITM can
// impersonate a known device.
//
// This mirrors the CLI exactly (cli/src/main.rs channel_of / proof_for); the
// strings MUST stay byte-identical or browsers and CLIs stop recognizing
// each other.
import { log } from './log.js'

const dlog = log.scope('dev')
const KEY = 'filament-known-devices'

const validRecord = (d) => !!(d && d.name && /^[0-9a-f]{64}$/.test(d.secret || ''))
const recordAge = (d) => {
  const n = Number(d && d.addedAt)
  return Number.isFinite(n) ? n : 0 // missing/invalid addedAt = oldest
}
/// Names collide when they read the same to a person: trimmed, any case.
const nameKey = (n) => String(n || '').trim().toLowerCase()
const MAX_NAME = 48

/// A fresh, non-secret, stable handle for a record (rows, rename, forget).
function newId() {
  try {
    const b = new Uint8Array(8)
    crypto.getRandomValues(b)
    return 'd' + [...b].map((x) => x.toString(16).padStart(2, '0')).join('')
  } catch {
    return 'd' + Date.now().toString(16) + Math.random().toString(16).slice(2, 10)
  }
}

/// `name`, or "name 2", "name 3", ... : the first that no record in `list`
/// (other than the ids in `except`) already uses.
export function uniqueName(list, name, except = []) {
  const base = String(name || '').trim().slice(0, MAX_NAME) || 'device'
  const skip = new Set(except)
  const taken = new Set((list || []).filter((d) => !skip.has(d.id)).map((d) => nameKey(d.name)))
  if (!taken.has(nameKey(base))) return base
  for (let i = 2; ; i++) {
    const cand = `${base} ${i}`
    if (!taken.has(nameKey(cand))) return cand
  }
}

/// Identity is the SECRET, never the name. Two records with different
/// secrets are two devices, however they are labeled, and neither is ever
/// dropped. Only same-secret records collapse (the newest wins: a re-store of
/// one pairing). Then names are made unique so every row, rename and forget
/// is unambiguous: on a clash the newest record keeps the name and older ones
/// read "name 2", "name 3". Records also get a stable non-secret `id`; a
/// missing one is derived from the record's position in the stored list, so
/// two tabs migrating the same storage agree on it. Order is preserved.
export function devicesDedupe(list) {
  const raw = Array.isArray(list) ? list : []
  const bySecret = new Map()
  const order = []
  raw.forEach((d, i) => {
    if (!validRecord(d)) return
    const rec = d.id ? d : { ...d, id: `d${recordAge(d).toString(16)}-${i}` }
    const cur = bySecret.get(d.secret)
    if (!cur) {
      order.push(d.secret)
      bySecret.set(d.secret, rec)
    } else if (recordAge(rec) >= recordAge(cur)) {
      bySecret.set(d.secret, { ...rec, id: cur.id })
    }
  })
  const out = order.map((sec) => bySecret.get(sec))
  // ids must be unique too (hand-edited or merged storage).
  const ids = new Set()
  out.forEach((d, i) => {
    if (ids.has(d.id)) out[i] = { ...d, id: `${d.id}-${i}` }
    ids.add(out[i].id)
  })
  // Unique names, newest first so the live pairing keeps its label.
  const byAge = out.map((d, i) => [d, i]).sort((a, b) => recordAge(b[0]) - recordAge(a[0]) || a[1] - b[1])
  const kept = []
  for (const [d, i] of byAge) {
    const name = uniqueName(kept, d.name)
    const rec = name === d.name ? d : { ...d, name }
    kept.push(rec)
    out[i] = rec
  }
  return out
}

/// Stable, non-secret key for React rows.
export function deviceRowKey(d) {
  return d.id || `${d.name}:${recordAge(d)}`
}

/// The record a UI handle names: its id, or (older callers) its name. Names
/// are unique after devicesDedupe, so the name fallback is unambiguous.
export function findDevice(list, key) {
  if (!key) return null
  return (list || []).find((d) => d.id === key) || (list || []).find((d) => d.name === key) || null
}

function persist(list) {
  try {
    localStorage.setItem(KEY, JSON.stringify(list))
  } catch (e) {
    // Private Browsing / storage blocked: the device won't be remembered and
    // auto-reconnect won't work, say so where a debugger will look.
    dlog.warn('could not persist known device (private browsing?)', e)
  }
  return list
}

export function devicesLoad() {
  let raw = []
  try {
    const v = JSON.parse(localStorage.getItem(KEY) || '[]')
    raw = Array.isArray(v) ? v : []
  } catch {
    raw = []
  }
  const list = devicesDedupe(raw)
  // Migrate on load (ids, same-secret duplicates, clashing names); no
  // reset/clear-data path needed.
  try {
    const serialized = JSON.stringify(list)
    if (localStorage.getItem(KEY) !== serialized) localStorage.setItem(KEY, serialized)
  } catch {}
  return list
}

/// Store a pairing. The record with the SAME secret is superseded (a re-store
/// of one pairing); so are the records in `opts.replaces`, which the caller
/// passes only when the new pairing is PROVABLY the same peer (it proved it
/// holds that record's secret on the very link the new pairing ran on, or the
/// record carries the same peer uid). Nothing else is ever dropped: a name
/// already used by a different device makes the new one unique ("Kabir
/// Laptop 2"). `opts.peerUid` is kept on the record as the peer's identity.
function storeRecord(rec, opts = {}) {
  const replaces = new Set(opts.replaces || [])
  const prev = devicesLoad()
  const same = prev.filter((d) => d.secret === rec.secret || replaces.has(d.id) || (opts.peerUid && d.peerUid && d.peerUid === opts.peerUid))
  const list = prev.filter((d) => !same.includes(d))
  const name = uniqueName(list, rec.name)
  const out = { ...rec, name, id: (same.find((d) => d.secret === rec.secret) || {}).id || newId(), addedAt: Date.now() }
  if (opts.peerUid) out.peerUid = opts.peerUid
  list.push(out)
  return persist(list)
}

export function devicesStore(name, secret, opts) {
  return storeRecord({ name, secret }, opts)
}

/// L1-a (spec §8): store a v2 device record with its agreed capability set.
/// Grows the record with `v` and `caps` (deny-by-default; "transfer" is the L0
/// baseline). The {name, secret} fields are unchanged so the reconnect path
/// (devicesLoad / channelOf / proofFor) keeps working byte-for-byte.
export function devicesStoreV2(name, secret, caps, opts) {
  return storeRecord({ name, secret, v: 2, caps: caps || ['transfer'] }, opts)
}

/// L1-a (spec §8): a device's granted capabilities. v1 records (no caps) read
/// as ["transfer"] for back-compat. Returns null if the device isn't known.
export function deviceCaps(key) {
  const d = findDevice(devicesLoad(), key)
  if (!d) return null
  return Array.isArray(d.caps) ? d.caps : ['transfer']
}

/// L1-a (spec §8 / gate 5): deny-by-default capability check. "transfer" is the
/// always-allowed L0 baseline; future caps must be explicitly granted.
export function deviceAllows(key, capability) {
  if (capability === 'transfer') return true
  const caps = deviceCaps(key)
  return !!caps && caps.includes(capability)
}

/// Why `newName` cannot be the label of record `key`, or null if it can. A
/// rename never moves a label onto a different device.
export function devicesRenameError(list, key, newName) {
  const next = String(newName || '').trim()
  if (!next) return 'Enter a name.'
  const self = findDevice(list, key)
  if (!self) return 'That device is no longer remembered.'
  const other = (list || []).find((d) => d.id !== self.id && nameKey(d.name) === nameKey(next))
  if (other) return `Another remembered device is already called "${other.name}". Pick a different name, or forget that one first.`
  return null
}

/// Rename a device's LOCAL petname: pure client-side relabel. The `secret`
/// (and thus the meeting-point channel + every proof) is untouched, so the
/// reconnect identity is byte-stable; only the human-facing label changes.
/// `key` is the record id (or its unique name). Refused, list unchanged, when
/// the name is blank or another device already uses it. Returns
/// {list, error, device}.
export function devicesRenameResult(key, newName) {
  const list = devicesLoad()
  const next = String(newName || '').trim().slice(0, MAX_NAME)
  const self = findDevice(list, key)
  if (self && next === self.name) return { list, error: null, device: self }
  const error = devicesRenameError(list, key, next)
  if (error) return { list, error, device: self }
  const renamed = list.map((d) => (d.id === self.id ? { ...d, name: next } : d))
  persist(renamed)
  return { list: renamed, error: null, device: { ...self, name: next } }
}

/// The list after a rename (refused renames return it unchanged).
export function devicesRename(key, newName) {
  return devicesRenameResult(key, newName).list
}

export function devicesForget(key) {
  const list = devicesLoad()
  const d = findDevice(list, key)
  return persist(d ? list.filter((x) => x.id !== d.id) : list)
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('')
const utf8 = (s) => new TextEncoder().encode(s)

/// The server-visible meeting point: sha256("filament-pair:" + secret), hex.
export async function channelOf(secret) {
  return hex(await crypto.subtle.digest('SHA-256', utf8('filament-pair:' + secret)))
}

/// C20 proof: HMAC-SHA256(secret, "filament-proof2:{prover}|{loUid}|{hiUid}|{loFp}|{hiFp}").
/// uids and fingerprints are order-normalized so both sides derive the same
/// message; the prover's uid tags direction so a proof can't be replayed back.
export async function proofFor(secret, proverUid, aUid, bUid, fp1, fp2) {
  const [lo, hi] = aUid < bUid ? [aUid, bUid] : [bUid, aUid]
  const [fLo, fHi] = fp1 < fp2 ? [fp1, fp2] : [fp2, fp1]
  const key = await crypto.subtle.importKey('raw', utf8(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return hex(await crypto.subtle.sign('HMAC', key, utf8(`filament-proof2:${proverUid}|${lo}|${hi}|${fLo}|${fHi}`)))
}

/// Same parse as the CLI's sdp_fingerprint: the full `a=fingerprint:` value,
/// trimmed and uppercased (e.g. "SHA-256 AB:CD:…").
export function sdpFingerprint(sdp) {
  const line = (sdp || '').split(/\r?\n/).find((l) => l.startsWith('a=fingerprint:'))
  return line ? line.slice('a=fingerprint:'.length).trim().toUpperCase() : null
}
