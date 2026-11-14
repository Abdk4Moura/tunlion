// node frontend/src/lib/__tests__/dtls-cert.test.mjs
// The PAKE confirmation MACs the two DTLS certificate fingerprints under the
// ceremony key (CONTRACT.md, code ceremony "Binding"). It is fresh per link
// only because every RTCPeerConnection generates its own ephemeral
// certificate. A persistent certificate (RTCPeerConnection.generateCertificate
// passed back in as `certificates`) would repeat the fingerprints, and so the
// MAC, across connections. The CLI pins the same rule in filament-transport
// `peer_connections_carry_no_persistent_dtls_certificate`.
import assert from 'node:assert/strict'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

function sources(dir) {
  const out = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name !== '__tests__' && name !== 'node_modules') out.push(...sources(p))
    } else if (/\.(m?js|ts|svelte|jsx|tsx)$/.test(name)) {
      out.push(p)
    }
  }
  return out
}

const files = sources(SRC)
assert.ok(
  files.some((f) => readFileSync(f, 'utf8').includes('new RTCPeerConnection(')),
  'the scan did not reach the RTCPeerConnection construction, so it proves nothing',
)
for (const f of files) {
  const text = readFileSync(f, 'utf8')
  assert.ok(!/generateCertificate\s*\(/.test(text), `${f} generates a DTLS certificate`)
  assert.ok(!/\bcertificates\s*:/.test(text), `${f} passes a persistent DTLS certificate`)
}
console.log('dtls-cert.test: ok')
