// L1-a (PAKE v2): the browser half of secure first-pairing.
//
// Mirrors the CLI `pair_cmd` exactly, using the SHARED Rust→WASM SPAKE2 core
// (src/pake). The server only ever sees the numeric nameplate; the password
// (words) is minted/typed CLIENT-SIDE and never transmitted. A strong key K is
// agreed over the opaque `signal` relay BEFORE the pinned secret exists; the
// 32-byte device secret is HKDF(K), agreed, never sent. A key-confirmation MAC
// folds the SORTED DTLS fingerprints + caps so a server that substitutes a DTLS
// cert (or rewrites caps) is detected and the pairing aborts.
//
// Downgrade-refusal (spec §6.1): a v2 pairing NEVER sends or stores a pair-keep
// secret over the DataChannel; a received pair-keep means the peer is v1 → the
// caller refuses with "update to pair securely".

import initPake, { PakeSession, canonicalCaps, normCode, splitCode, splitChosenCode as wasmSplitChosenCode } from '../pake/filament_pake.js'
import pakeWasmUrl from '../pake/filament_pake_bg.wasm?url'
import { validateChosenPassword } from './words.js'
import { PakeCeremony } from '../net/app/pakePairing.js'

let _ready = null
/// Initialize the WASM module once (idempotent). Vite serves the .wasm via ?url.
export async function pakeReady() {
  if (!_ready) _ready = initPake({ module_or_path: pakeWasmUrl })
  return _ready
}

const utf8 = (s) => new TextEncoder().encode(s)

// The caps v2 first-pairing agrees on. "transfer" is the L0 baseline (always
// allowed); deny-by-default future caps are NOT granted at enrollment. BOTH
// sides MAC the identical canonical string (spec §8 / gate 5).
export const PAIR_V2_CAPS = ['transfer']

/// A single v2 pairing attempt with one peer, on the WASM SPAKE2 session. The
/// ceremony itself (including its re-sends) is the pure PakeCeremony in
/// net/app/pakePairing.js; this only binds it to the shared Rust core.
///
/// `sendSignal(data)` relays an opaque payload to the peer via the server.
/// `getFingerprints()` returns {mine, theirs} once SDP is exchanged (or null).
export class PakePairing extends PakeCeremony {
  constructor({ nameplate, password, caps = PAIR_V2_CAPS, sendSignal, getFingerprints }) {
    super({
      nameplate,
      caps,
      capsCanon: canonicalCaps(caps),
      session: new PakeSession(utf8(password), utf8(nameplate)),
      sendSignal,
      getFingerprints,
    })
    this.password = password
  }
}

/// Parse a typed spoken code into {nameplate, password} the SAME way the CLI
/// does (shared WASM normCode/splitCode), so K agrees.
export function parseSpokenCode(typed) {
  const normalized = normCode(typed)
  const [nameplate, password] = splitCode(normalized)
  return { nameplate, password, normalized }
}

/// STEERING: count word tokens (letter-runs of >= 2 chars) in a password,
/// mirrors the CLI `password_word_tokens`. A user-chosen pairing password must
/// contain >= 2 of these (a 1-word code is ~12 bits, below the floor the
/// burn + 5/min rate-limit relies on). Digits / 1-letter fragments don't count.
export function passwordWordTokens(password) {
  const m = String(password || '').match(/[a-z]{2,}/g)
  return m ? m.length : 0
}

/// STEERING preview for the browser "choose your own code" entry. Uses the
/// shared split + Decision #3 password gate (blocklist + identical-word check).
/// The nameplate is machine-assigned when the user typed none.
export function previewCustomCode(typed, autoNameplate, userName = '') {
  const { password, nameplate, normalized } = splitChosenCode(typed)
  const hasNumber = !!nameplate
  const np = hasNumber ? nameplate : (autoNameplate || '')
  const blockedReason = validateChosenPassword(password, userName)
  return {
    password,
    nameplate: np,
    autoAssigned: !hasNumber,
    strongEnough: !blockedReason && !!password,
    blockedReason: blockedReason || null,
    normalized,
    full: password && np ? `${password}-${np}` : '',
  }
}

/// Split a USER-CHOSEN code into {password, nameplate}. Unlike splitCode (which
/// always strips the trailing group as the nameplate), here the trailing group
/// is the nameplate ONLY if it is numeric (3-5 digits, the server's
/// _NAMEPLATE_RE), otherwise it is part of the words. So `gigantic-element`
/// keeps BOTH words as the password (nameplate machine-assigned), while
/// `gigantic-element-9641` honors the typed number. Delegates to the SHARED
/// Rust→WASM `splitChosenCode` so the browser is byte-identical to the CLI by
/// construction (`pakeReady()` MUST have resolved first; uses WASM).
export function splitChosenCode(typed) {
  const normalized = normCode(typed)
  const [password, nameplate] = wasmSplitChosenCode(normalized)
  return { password, nameplate, normalized }
}
