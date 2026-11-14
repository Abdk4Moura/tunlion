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
// Every RTCPeerConnection is built in one place, from an inline options
// literal, so what that literal holds is what every connection gets. An
// options variable, a second construction site or a `certificates` key in any
// spelling (shorthand included) fails here.
const sites = []
for (const f of files) {
  const text = readFileSync(f, 'utf8')
  for (const m of text.matchAll(/new\s+RTCPeerConnection\s*\(\s*(\S)/g)) {
    sites.push({ f, inline: m[1] === '{' })
  }
  assert.ok(!/generateCertificate\s*\(/.test(text), `${f} generates a DTLS certificate`)
  assert.ok(!/\bcertificates\b/.test(text), `${f} names DTLS certificates`)
}
assert.equal(sites.length, 1, `RTCPeerConnection construction sites: ${JSON.stringify(sites)}`)
assert.ok(sites[0].f.endsWith(join('lib', 'webrtc.js')), `constructed outside lib/webrtc.js: ${sites[0].f}`)
assert.ok(sites[0].inline, 'the RTCPeerConnection options must be an inline literal')
console.log('dtls-cert.test: ok')
