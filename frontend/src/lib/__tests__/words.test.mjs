// A code the browser creates must be one the CLI can `join` (launch matrix B04):
// the CLI reads word-word-NNN (three digits) as a transfer code and refuses it,
// and a pairing code ends in exactly four digits (cli/src/main.rs looks_like_pake_code).
import assert from 'node:assert/strict'
import { mintCreatedNameplate, mintNameplate, mintWords } from '../words.js'

for (let i = 0; i < 2000; i++) {
  const np = mintCreatedNameplate()
  assert.match(np, /^[1-9][0-9]{3}$/, `created nameplate not four digits: ${np}`)
  const code = `${mintWords()}-${np}`
  assert.match(code, /^[a-z]+-[a-z]+-[0-9]{4}$/, `created code not in the CLI pairing shape: ${code}`)
}
// The three-digit mint is unchanged for anything that still uses it.
assert.match(mintNameplate(), /^[1-9][0-9]{2}$/)
console.log('words.test: ok')
