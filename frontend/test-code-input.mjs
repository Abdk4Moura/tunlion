// Pure browser code-entry boundary tests. The only application module imported
// is frontend/src/lib/codeInput.js: no WASM, no React/UI, no network.
import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import {
  CODE_LIMIT,
  CodeInputError,
  checkCodeInput,
  formatPartial,
  normalizeCodeChecked,
  reservedCodeInput,
} from './src/lib/codeInput.js'

// Golden cases shared with the Rust boundary. Resolve from this file so the
// test runs from the repo root; `../../crates/...` also covers the same file
// being run from frontend/test/.
const FIXTURE_CANDIDATES = [
  new URL('../crates/filament-pair/tests/code-input-cases.txt', import.meta.url),
  new URL('../../crates/filament-pair/tests/code-input-cases.txt', import.meta.url),
]
const FIXTURE = FIXTURE_CANDIDATES.find((url) => existsSync(url))

const throwsChecked = (raw) => assert.throws(() => normalizeCodeChecked(raw), RangeError)

test('partial formatting lowercases and maps separators/punctuation to dashes', () => {
  assert.equal(formatPartial('Brave Otter 3141'), 'brave-otter-3141')
  assert.equal(formatPartial('brave---otter'), 'brave-otter')
  assert.equal(formatPartial('brave__otter!!3141'), 'brave-otter-3141')
  assert.equal(formatPartial('---BRAVE@@otter---3141--'), 'brave-otter-3141-')
  assert.equal(formatPartial('  leading'), 'leading')
  assert.equal(formatPartial('a   b'), 'a-b')
})

test('partial keeps a single trailing separator but never truncates', () => {
  assert.equal(formatPartial('brave-'), 'brave-')
  assert.equal(formatPartial('brave   '), 'brave-')
  assert.equal(formatPartial('brave---'), 'brave-')
  const long = 'a'.repeat(CODE_LIMIT + 12)
  assert.equal(formatPartial(long), long)
})

test('final normalization trims leading/trailing and collapses separators', () => {
  assert.equal(normalizeCodeChecked('  BRAVE__OTTER!!3141  '), 'brave-otter-3141')
  assert.equal(normalizeCodeChecked('---brave---otter---3141---'), 'brave-otter-3141')
  assert.equal(normalizeCodeChecked('brave.otter.3141'), 'brave-otter-3141')
  assert.equal(normalizeCodeChecked('brave_otter_3141'), 'brave-otter-3141')
  assert.equal(normalizeCodeChecked(''), '')
})

test('non-ASCII letters become separators instead of being silently joined', () => {
  assert.equal(formatPartial('café'), 'caf-')
  assert.equal(normalizeCodeChecked('café'), 'caf')
  assert.equal(normalizeCodeChecked('café-otter-3141'), 'caf-otter-3141')
  assert.equal(normalizeCodeChecked('caféotter-3141'), 'caf-otter-3141')
})

test('exactly 48 characters is accepted; 49 is rejected without truncation', () => {
  const exact = 'a'.repeat(43) + '-1234'
  assert.equal(exact.length, CODE_LIMIT)
  assert.equal(normalizeCodeChecked(exact), exact)

  const over = 'a'.repeat(44) + '-1234'
  assert.equal(over.length, CODE_LIMIT + 1)
  const checked = checkCodeInput(over)
  assert.equal(checked.code, '')
  assert.equal(checked.value, over.toUpperCase(), 'the full over-limit field stays visible')
  assert.match(checked.error, /48/)
  assert.match(checked.error, /nothing was truncated/)
  throwsChecked(over)
})

test('ordinary codes pass the reservation guard', () => {
  for (const raw of ['brave-otter-3141', 'comic otter 1950', 'brave.otter.3141', 'brave_otter_3141']) {
    assert.equal(reservedCodeInput(raw), null, raw)
    assert.equal(checkCodeInput(raw).error, null, raw)
  }
})

test('raw invitation material fails closed and never becomes a password', () => {
  for (const raw of [
    'filament-invite:v2:TOPSECRETPAYLOAD',
    'FILAMENT-INVITE:V2:TOPSECRETPAYLOAD',
    'tlninv-TOPSECRETPAYLOAD',
    'tunlion-invite-TOPSECRETPAYLOAD',
    "'TLNINV-TOPSECRETPAYLOAD'",
  ]) {
    assert.equal(reservedCodeInput(raw), 'invitation', raw)
    const checked = checkCodeInput(raw)
    assert.equal(checked.value, '', 'reserved input is not kept as a code')
    assert.ok(checked.error)
    assert.ok(!checked.error.includes('TOPSECRETPAYLOAD'), 'error must not echo payload')
    throwsChecked(raw)
  }
})

test('raw JSON/quoted material fails closed', () => {
  for (const raw of ['{"code":"TOPSECRETPAYLOAD"}', '["TOPSECRETPAYLOAD"]', '"TOPSECRETPAYLOAD"', '`["TOPSECRETPAYLOAD"]`']) {
    assert.equal(reservedCodeInput(raw), 'json', raw)
    const checked = checkCodeInput(raw)
    assert.equal(checked.value, '')
    assert.ok(checked.error)
    assert.ok(!checked.error.includes('TOPSECRETPAYLOAD'))
    throwsChecked(raw)
  }
})

test('paths, URLs and colon syntax fail closed', () => {
  for (const raw of [
    '/tmp/brave-otter-3141',
    './brave-otter-3141',
    '../brave-otter-3141',
    '~/brave-otter-3141',
    'C:\\brave-otter-3141',
    '\\\\server\\share\\brave-otter-3141',
    'brave/otter/3141',
    'brave-otter-3141.txt',
    'note.json',
    'https://host/brave-otter-3141',
    'key:value',
  ]) {
    assert.ok(reservedCodeInput(raw), raw)
    const checked = checkCodeInput(raw)
    assert.equal(checked.value, '', 'reserved input is not kept as a code')
    assert.ok(checked.error)
    assert.ok(!checked.error.includes('brave-otter-3141'), 'error must not echo material')
    throwsChecked(raw)
  }
})

test('checkCodeInput reports a reason without throwing for UI rendering', () => {
  const rejected = checkCodeInput('https://host/TOPSECRETPAYLOAD')
  assert.equal(rejected.reason, 'url')
  assert.equal(rejected.value, '')
  assert.ok(rejected.error)
  assert.ok(!rejected.error.includes('TOPSECRETPAYLOAD'))

  const tooLong = checkCodeInput('a'.repeat(CODE_LIMIT + 1))
  assert.equal(tooLong.reason, 'too-long')
  assert.ok(tooLong.error)
})

test('CodeInputError is a RangeError and carries no input', () => {
  try {
    normalizeCodeChecked('filament-invite:v2:TOPSECRETPAYLOAD')
    assert.fail('must throw')
  } catch (error) {
    assert.ok(error instanceof RangeError)
    assert.ok(error instanceof CodeInputError)
    assert.equal(error.reason, 'invitation')
    assert.ok(!error.message.includes('TOPSECRETPAYLOAD'))
  }
})

test('shared Rust/browser golden fixtures match exactly', () => {
  assert.ok(FIXTURE, 'code-input-cases.txt fixture is present')
  const lines = readFileSync(FIXTURE, 'utf8').split(/\r?\n/)
  let cases = 0
  for (const line of lines) {
    if (!line.trim() || line.trimStart().startsWith('#')) continue
    const split = line.indexOf('|')
    assert.ok(split >= 0, `fixture line has no separator: ${line}`)
    // The raw field deliberately keeps surrounding whitespace (padding cases).
    const raw = line.slice(0, split)
    const expected = line.slice(split + 1).trim()
    assert.equal(normalizeCodeChecked(raw), expected, JSON.stringify(raw))
    cases++
  }
  assert.ok(cases > 0, 'fixture has at least one case')
})
