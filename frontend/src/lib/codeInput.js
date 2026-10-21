// Browser code-only input boundary.
//
// This is deliberately NOT a credential/invitation reader. It only decides
// whether a value may enter the PAKE password path:
//   1. reserve obvious non-code material from the RAW value first, then
//   2. lowercase/separator-clean the remaining ASCII code candidate.
//
// The released WASM `normCode` stays untouched. Code that survives this boundary
// is already [a-z0-9-], so the existing `normCode` is idempotent on it. Keeping
// the transform here, rather than in the crypto norm, lets the browser and the
// CLI share the entry policy without changing released PAKE bytes.

export const CODE_LIMIT = 48

const MESSAGES = {
  invitation: 'That looks like invitation material, not a pairing code.',
  json: 'That looks like JSON or quoted text, not a pairing code.',
  path: 'That looks like a file path, not a pairing code.',
  url: 'That looks like a URL, not a pairing code.',
  colon: 'That contains a colon, so it is not a pairing code.',
  'too-long': 'Codes are limited to 48 characters after cleanup; nothing was truncated. Shorten it.',
}

/** A rejected code entry. The message never contains the input value. */
export class CodeInputError extends RangeError {
  constructor(reason) {
    super(MESSAGES[reason] || 'That is not a pairing code.')
    this.name = 'CodeInputError'
    this.reason = reason
  }
}

const INVITATION_PREFIXES = ['filament-', 'tlninv', 'tunlion-invite']

// The same credential-file extensions the CLI recognises. A dot alone is not a
// path: `brave.otter.3141` is a code candidate, but `brave.otter.3141.txt` is a
// file name and must not become a password.
const FILE_EXTENSIONS = new Set([
  'txt', 'json', 'inv', 'invite', 'key', 'pem', 'crt', 'yaml', 'yml',
  'toml', 'conf', 'cfg', 'env', 'token', 'cred', 'credential',
])

function trimmed(raw) {
  return String(raw ?? '').trim()
}

function extensionOf(text) {
  const dot = text.lastIndexOf('.')
  if (dot < 0) return ''
  const ext = text.slice(dot + 1).toLowerCase()
  return ext.length > 0 && ext.length <= 12 ? ext : ''
}

/**
 * Why the raw value must not enter the code/password path, or null.
 * Checked BEFORE any lowercase/separator cleanup so a path or invitation
 * cannot be transformed into a different, valid-looking code.
 */
export function reservedCodeInput(raw) {
  const text = trimmed(raw)
  if (!text) return null
  const lower = text.toLowerCase()
  const categoryStarts = new Set(['/', '\\', '~', ':', '.', '{', '[', '"'])
  let wrapperLength = 0
  for (const character of lower) {
    if (/[a-z0-9]/.test(character) || categoryStarts.has(character)) break
    wrapperLength += character.length
  }
  const probe = lower.slice(wrapperLength)

  if (INVITATION_PREFIXES.some((prefix) => lower.startsWith(prefix) || probe.startsWith(prefix))) return 'invitation'
  if (['{', '[', '"'].includes(text[0]) || ['{', '[', '"'].includes(probe[0])) return 'json'

  // Explicit paths, UNC/drive paths, and any separator that can never be part
  // of a spoken code. `//` is also protocol-relative URL syntax.
  if (/^[A-Za-z]:[\\/]/.test(text)) return 'path'
  if (text.startsWith('\\\\') || text.startsWith('//')) return 'path'
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(text)) return 'url'
  if (text.startsWith('/') || text.startsWith('./') || text.startsWith('../') || text.startsWith('~/')) return 'path'
  if (text.startsWith('~') || text.includes('/') || text.includes('\\')) return 'path'
  if (FILE_EXTENSIONS.has(extensionOf(text))) return 'path'

  if (text.includes(':')) return 'colon'
  return null
}

/**
 * Partial, display-only cleanup, used while typing/pasting:
 * lowercase; every non-ASCII-alphanumeric character becomes '-'; runs of '-'
 * collapse; leading '-' is dropped; a trailing '-' is KEPT so the caret can stay
 * between words. This never truncates and never applies the reservation guard
 * (the caller checks that separately before accepting the value).
 */
export function formatPartial(raw) {
  let out = ''
  for (const character of String(raw ?? '').toLowerCase()) {
    if (/[a-z0-9]/.test(character)) {
      out += character
    } else if (out && !out.endsWith('-')) {
      out += '-'
    }
  }
  return out
}

function finishPartial(partial) {
  return partial.replace(/-+$/, '')
}

/**
 * Checked FINAL normalization used at submit/parse time. It reserves raw
 * invitation/JSON/path/URL material first, then cleans, trims and enforces the
 * 48-character ceiling. It never truncates.
 *
 * Returns `{ value, code, error, reason }` where `value` is what a field should
 * display (empty for reserved material, the complete over-limit text when too
 * long) and `code` is the canonical value only when there is no error.
 */
export function checkCodeInput(raw) {
  const reason = reservedCodeInput(raw)
  if (reason) {
    return { value: '', code: '', error: MESSAGES[reason], reason }
  }
  const partial = formatPartial(raw)
  // The visible field keeps the familiar uppercase pairing-code presentation;
  // the PAKE value below stays canonical lower-case.
  const value = partial.toUpperCase()
  const code = finishPartial(partial)
  if (code.length > CODE_LIMIT) {
    return { value, code: '', error: MESSAGES['too-long'], reason: 'too-long' }
  }
  return { value, code, error: null, reason: null }
}

/**
 * Final checked normalization for the PAKE path. Throws `CodeInputError`
 * (a `RangeError`) for reserved material or an over-limit code; never truncates
 * and never includes the input in the error.
 */
export function normalizeCodeChecked(raw) {
  const checked = checkCodeInput(raw)
  if (checked.error) throw new CodeInputError(checked.reason)
  return checked.code
}
