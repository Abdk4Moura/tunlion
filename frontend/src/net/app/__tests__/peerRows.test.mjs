// node frontend/src/net/app/__tests__/peerRows.test.mjs
// One row per device: a device in the room twice under one uid (its background
// service plus a CLI command) is shown once, as the copy this browser can use.
import { oneRowPerDevice } from '../peerRows.js'
import { readFileSync } from 'node:fs'

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${got} want ${want}`); ok = false }
  else console.log(`  ${label}: OK`)
}
const daemon = { id: 's1', uid: 'u-vps', name: 'vps', status: 'ready' }
const cli = { id: 's2', uid: 'u-vps', name: 'vps', status: 'ready', verified: 'vps' }
const other = { id: 's3', uid: 'u-pc', name: 'pc', status: 'connecting' }
const noUid = { id: 's4', uid: null, name: 'old', status: 'ready' }
const rows = oneRowPerDevice([daemon, other, cli, noUid])
eq('the vps appears once', rows.filter((p) => p.uid === 'u-vps').length, 1)
eq('the proven copy wins', rows.find((p) => p.uid === 'u-vps').id, 's2')
eq('order follows first appearance', rows.map((p) => p.name).join(','), 'vps,pc,old')
eq('proven wins in either order', oneRowPerDevice([cli, daemon])[0].id, 's2')
eq('ready beats connecting', oneRowPerDevice([{ ...daemon, status: 'connecting' }, { ...daemon, id: 's9' }])[0].id, 's9')
eq('peers without a uid are never merged', oneRowPerDevice([noUid, { ...noUid, id: 's5' }]).length, 2)
const ui = readFileSync(new URL('../../../ui/Tunlion.jsx', import.meta.url), 'utf8')
eq('the page lists one row per device', /const peers = oneRowPerDevice\(/.test(ui), true)
if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
