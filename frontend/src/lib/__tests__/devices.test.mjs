// node frontend/src/lib/__tests__/devices.test.mjs
// Known devices are keyed by local petname. Re-pairing must replace that peer,
// never append a second row; old duplicate records must migrate on load.
class MemoryStore {
  #m = new Map()
  getItem(k) { return this.#m.has(k) ? this.#m.get(k) : null }
  setItem(k, v) { this.#m.set(k, String(v)) }
  removeItem(k) { this.#m.delete(k) }
  clear() { this.#m.clear() }
}

const localStorage = new MemoryStore()
globalThis.localStorage = localStorage

const {
  devicesLoad, devicesStore, devicesStoreV2, devicesForget, deviceRowKey,
} = await import('../devices.js')
import { readFileSync } from 'node:fs'

const KEY = 'filament-known-devices'
const secret = (hex) => hex.repeat(64)
const older = secret('a')
const newer = secret('b')
const third = secret('c')
const fourth = secret('d')

let ok = true
const eq = (label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`)
    ok = false
  } else console.log(`  ${label}: OK`)
}
const stored = () => JSON.parse(localStorage.getItem(KEY) || '[]')

// 1. Existing duplicate localStorage: one row, newest valid record wins, the
//    migration is written back so the next load is already clean.
localStorage.clear()
localStorage.setItem(KEY, JSON.stringify([
  { name: 'dovm', secret: older, addedAt: 100 },
  { name: 'pixel', secret: third, addedAt: 150 },
  { name: 'dovm', secret: newer, addedAt: 200, caps: ['transfer', 'shell'] },
  { name: 'dovm', secret: 'not-a-secret', addedAt: 999 },
]))
const one = devicesLoad()
eq('same-name duplicates load as one row', one.filter((d) => d.name === 'dovm').length, 1)
eq('newest same-name secret wins', one.find((d) => d.name === 'dovm').secret, newer)
eq('distinct names survive', one.map((d) => d.name), ['dovm', 'pixel'])
eq('load migrated duplicate storage', stored().filter((d) => d.name === 'dovm').length, 1)
eq('migrated storage has no invalid record', stored().some((d) => d.secret === 'not-a-secret'), false)

// A missing/invalid addedAt is the oldest record.
localStorage.clear()
localStorage.setItem(KEY, JSON.stringify([
  { name: 'dovm', secret: newer, addedAt: 200 },
  { name: 'dovm', secret: older },
]))
eq('missing addedAt loses to a timestamped record', devicesLoad()[0].secret, newer)
localStorage.clear()
localStorage.setItem(KEY, JSON.stringify([
  { name: 'dovm', secret: older, addedAt: 'nope' },
  { name: 'dovm', secret: newer, addedAt: 1 },
]))
eq('invalid addedAt is oldest', devicesLoad()[0].secret, newer)

// 2. Re-pairing replaces the existing record for the same petname.
localStorage.clear()
devicesStore('dovm', older)
const replaced = devicesStore('dovm', third)
eq('re-pair does not append', replaced.length, 1)
eq('re-pair uses the fresh secret', replaced[0].secret, third)
eq('storage holds one record after re-pair', stored().length, 1)
const v2 = devicesStoreV2('dovm', fourth, ['transfer', 'shell'])
eq('v2 re-pair does not append', v2.length, 1)
eq('v2 re-pair uses the fresh secret', v2[0].secret, fourth)
eq('v2 re-pair keeps caps', v2[0].caps, ['transfer', 'shell'])

// The same-secret path updates the label rather than adding a second entry.
const relabeled = devicesStore('dovm-renamed', fourth)
eq('same secret updates instead of appending', relabeled.length, 1)
eq('same secret takes the new label', relabeled[0].name, 'dovm-renamed')

// 3. Distinct names remain; Forget removes only the chosen peer.
localStorage.clear()
devicesStore('dovm', older)
devicesStore('pixel', newer)
eq('distinct names both remain', devicesLoad().map((d) => d.name).sort(), ['dovm', 'pixel'])
const afterForget = devicesForget('dovm')
eq('forget removes one peer only', afterForget.map((d) => d.name), ['pixel'])
eq('forget persisted one peer only', stored().map((d) => d.name), ['pixel'])

// 4. The newest secret is what a reconnect would use, and row keys are stable
//    and never expose the secret.
localStorage.clear()
localStorage.setItem(KEY, JSON.stringify([
  { name: 'dovm', secret: older, addedAt: 10 },
  { name: 'dovm', secret: newer, addedAt: 20 },
]))
const newest = devicesLoad()[0]
eq('reconnect reads the newest secret', newest.secret, newer)
eq('row key is stable across reads', deviceRowKey(newest), deviceRowKey(devicesLoad()[0]))
eq('row key never contains the secret', deviceRowKey(newest).includes(newer), false)
eq('row key still identifies the row', /^dovm:20$/.test(deviceRowKey(newest)), true)

// 5. The page consumes the deduped list and keys rows without the secret.
const ui = readFileSync(new URL('../../ui/Tunlion.jsx', import.meta.url), 'utf8')
eq('Devices screen dedupes its state list', /devicesDedupe\(state\.knownDevices/.test(ui), true)
eq('device rows use the non-secret stable key', /key=\{deviceRowKey\(d\)\}/.test(ui), true)
eq('device rows no longer key by bare name', /key=\{d\.name\}/.test(ui), false)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('devices.test: ok')
