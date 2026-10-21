// Device identity for the browser client.
//
// There are two separate things here, deliberately:
//
//   * the DEVICE NAME is the human label this browser shows to peers and to
//     its own user. It is stored in localStorage so every tab on the same
//     browser is recognisably the same device, and a rename is a relabel of
//     that one identity (the signaling uid does not change).
//
//   * the SESSION GENERATION is minted fresh on every page load. It is NOT
//     persisted anywhere, so a reload/bfcache restore is a new generation of
//     the same device. The relay uses (uid, generation) to let the new session
//     take over immediately while ignoring a late close from the old one.
//
// The uid itself stays per-tab (sessionStorage): a tab is the unit that can
// resume a transfer, while the name is what the person calls the device.

import { ADJ, ANIMAL } from './words.js'

const NAME_KEY = 'tunlion.deviceName'
const LEGACY_NAME_KEY = 'tunlion.name' // per-tab name used before this module
const UID_KEY = 'tunlion.uid'
const MAX_NAME = 48

function cryptoPick(list) {
  const buf = new Uint32Array(1)
  // rejection sampling: no modulo bias even for non-power-of-two lists
  const limit = Math.floor(0xffffffff / list.length) * list.length
  do {
    crypto.getRandomValues(buf)
  } while (buf[0] >= limit)
  return list[buf[0] % list.length]
}

/// A fresh, speakable device name (`silken-chickadee`). The name is a label,
/// not a secret; the 64x64 wordlist is the same one the pairing codes use.
export function randomDeviceName() {
  return `${cryptoPick(ADJ)}-${cryptoPick(ANIMAL)}`
}

/// Trim/normalize a name a person typed. Returns '' for a name that would be
/// unusable on the wire. We keep spaces inside (a person may call their iPad
/// "Sam's iPad") but strip control characters and collapse runs of whitespace.
export function normalizeDeviceName(raw) {
  const s = String(raw == null ? '' : raw)
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return s.slice(0, MAX_NAME)
}

/// Load this browser's device name, generating + persisting one on first use.
/// Migrates the old per-tab `tunlion.name` so existing users keep the name
/// they already had.
export function loadDeviceName() {
  try {
    const stored = normalizeDeviceName(localStorage.getItem(NAME_KEY) || '')
    if (stored) {
      try { sessionStorage.setItem(LEGACY_NAME_KEY, stored) } catch {}
      return stored
    }
    const legacy = normalizeDeviceName(sessionStorage.getItem(LEGACY_NAME_KEY) || '')
    if (legacy) {
      try { localStorage.setItem(NAME_KEY, legacy) } catch {}
      return legacy
    }
  } catch {}
  const name = randomDeviceName()
  try { localStorage.setItem(NAME_KEY, name) } catch {}
  try { sessionStorage.setItem(LEGACY_NAME_KEY, name) } catch {}
  return name
}

/// Persist a chosen name for THIS device. Returns the normalized value, or the
/// current name when the input is blank (a device always keeps a usable name).
export function saveDeviceName(raw) {
  const next = normalizeDeviceName(raw)
  if (!next) return loadDeviceName()
  try { localStorage.setItem(NAME_KEY, next) } catch {}
  // Keep the old per-tab key in sync: the CLI browser drivers read it.
  try { sessionStorage.setItem(LEGACY_NAME_KEY, next) } catch {}
  return next
}

/// Stable per-tab identity (survives reconnects and reloads; sids don't).
/// Basis for transfer resume. NOT the device name: the name can be renamed
/// without changing this identity or any pairing secret.
export function tabUid() {
  try {
    let u = sessionStorage.getItem(UID_KEY)
    if (!u) {
      u = (crypto.randomUUID && crypto.randomUUID()) || Math.random().toString(36).slice(2) + Date.now().toString(36)
      sessionStorage.setItem(UID_KEY, u)
    }
    if (!/^[\x00-\x7F]*$/.test(u)) throw new Error('Tunlion UID must be ASCII')
    return u
  } catch {
    return Math.random().toString(36).slice(2) + Date.now().toString(36)
  }
}

function newGeneration() {
  return (crypto.randomUUID && crypto.randomUUID()) || Math.random().toString(36).slice(2) + '-' + Date.now().toString(36)
}

// Page-load generation. Module scope means exactly one value per loaded page.
let generation = newGeneration()

export function currentGeneration() {
  return generation
}

/// Rotate to a fresh generation. Used when a bfcache-restored page comes back
/// after another page load superseded it: it rejoins as a NEW session rather
/// than replaying a retired generation (which the relay correctly refuses).
export function rotateGeneration() {
  generation = newGeneration()
  return generation
}
