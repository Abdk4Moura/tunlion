// node frontend/src/lib/__tests__/devices.test.mjs
// Known devices: identity is the pairing SECRET, never the name. A record with
// a different secret is a different device and is never dropped, whatever it
// is called. Only same-secret records collapse. Names are made unique so rows,
// rename and forget are unambiguous; a rename onto a taken name is refused.
// A re-pair replaces an old record only when it is provably the same peer.
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
  devicesLoad, devicesStore, devicesStoreV2, devicesForget, deviceRowKey, devicesDedupe,
  devicesRename, devicesRenameResult, devicesRenameError, uniqueName, findDevice,
} = await import('../devices.js')
import { readFileSync } from 'node:fs'

const KEY = 'filament-known-devices'
const secret = (hex) => hex.repeat(64)
const older = secret('a')
const newer = secret('b')
const third = secret('c')
const fourth = secret('d')
const ipadS = secret('e')
const laptopS = secret('f')

let ok = true
const eq = (label, got, want) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`)
    ok = false
  } else console.log(`  ${label}: OK`)
}
const stored = () => JSON.parse(localStorage.getItem(KEY) || '[]')
const names = (l) => l.map((d) => d.name)
const secrets = (l) => l.map((d) => d.secret).sort()

// 1. The collision that deleted a device: renaming "Abdul's iPad" to
//    "Kabir Laptop" when "Kabir Laptop" is a DIFFERENT device. Refused with a
//    clear message; both records and both secrets survive.
localStorage.clear()
devicesStore('Kabir Laptop', laptopS)
devicesStore("Abdul's iPad", ipadS)
const ipad = devicesLoad().find((d) => d.secret === ipadS)
const r = devicesRenameResult(ipad.id, 'Kabir Laptop')
eq('rename onto a taken name is refused', !!r.error, true)
eq('the refusal names the other device', /already called "Kabir Laptop"/.test(r.error || ''), true)
eq('refused rename keeps both devices', secrets(devicesLoad()), [ipadS, laptopS].sort())
eq('refused rename keeps both labels', names(devicesLoad()).sort(), ["Abdul's iPad", 'Kabir Laptop'])
eq('a case-only clash is a clash too', !!devicesRenameError(devicesLoad(), ipad.id, '  kabir LAPTOP '), true)
eq('devicesRename (list form) refuses as well', secrets(devicesRename(ipad.id, 'Kabir Laptop')), [ipadS, laptopS].sort())
eq('renaming a device to its own name is fine', devicesRenameResult(ipad.id, "Abdul's iPad").error, null)
const ok2 = devicesRenameResult(ipad.id, 'iPad')
eq('a free name renames', [ok2.error, ok2.device.name], [null, 'iPad'])
eq('rename kept the secret and id', [findDevice(devicesLoad(), ipad.id).secret, findDevice(devicesLoad(), 'iPad').id], [ipadS, ipad.id])
eq('rename by unique name still works', devicesRenameResult('iPad', "Abdul's iPad").error, null)
eq('blank rename refused', !!devicesRenameResult(ipad.id, '   ').error, true)

// 2. A NEW pairing suggesting a taken name ("Kabir Laptop") is a different
//    device: it is stored as "Kabir Laptop 2"; the old record stays.
localStorage.clear()
devicesStore('Kabir Laptop', laptopS)
const two = devicesStoreV2('Kabir Laptop', third, ['transfer'])
eq('new pairing under a taken name keeps the old device', secrets(two), [laptopS, third].sort())
eq('new pairing is made unique', two.find((d) => d.secret === third).name, 'Kabir Laptop 2')
eq('old device keeps its name', two.find((d) => d.secret === laptopS).name, 'Kabir Laptop')
const three = devicesStore('kabir laptop', fourth)
eq('a third clash counts on', three.find((d) => d.secret === fourth).name, 'kabir laptop 3')
eq('uniqueName ignores the ids it is told to', uniqueName(devicesLoad(), 'Kabir Laptop', [devicesLoad().find((d) => d.secret === laptopS).id]), 'Kabir Laptop')

// 3. #578's goal: a re-pair of the SAME device must not leave a dead
//    duplicate. Provably the same: the caller saw the peer prove the old
//    secret on the link the new pairing ran on (replaces), or the record
//    carries the same peer uid.
localStorage.clear()
devicesStore('dovm', older)
const oldId = devicesLoad()[0].id
const rep = devicesStoreV2('dovm', newer, ['transfer', 'shell'], { replaces: [oldId] })
eq('proven re-pair replaces the old record', secrets(rep), [newer])
eq('proven re-pair keeps the name', rep[0].name, 'dovm')
localStorage.clear()
devicesStore('dovm', older, { peerUid: 'u-cli-1' })
const byUid = devicesStore('dovm', newer, { peerUid: 'u-cli-1' })
eq('same peer uid replaces', secrets(byUid), [newer])
eq('the record carries the peer uid', byUid[0].peerUid, 'u-cli-1')
localStorage.clear()
devicesStore('dovm', older, { peerUid: 'u-cli-1' })
const otherUid = devicesStore('dovm', newer, { peerUid: 'u-cli-2' })
eq('an unproven re-pair keeps both, visibly', secrets(otherUid), [older, newer].sort())
eq('...under distinct names', names(otherUid).sort(), ['dovm', 'dovm 2'])
const relabel = devicesStore('dovm-renamed', newer)
eq('same secret updates, never appends', relabel.filter((d) => d.secret === newer).length, 1)
eq('same secret takes the new label', relabel.find((d) => d.secret === newer).name, 'dovm-renamed')
eq('same secret keeps its id', relabel.find((d) => d.secret === newer).id, otherUid.find((d) => d.secret === newer).id)

// 4. Loading old storage: different secrets under one name are two devices
//    (the newest keeps the name); same-secret copies collapse to the newest.
localStorage.clear()
localStorage.setItem(KEY, JSON.stringify([
  { name: 'dovm', secret: older, addedAt: 100 },
  { name: 'pixel', secret: third, addedAt: 150 },
  { name: 'dovm', secret: newer, addedAt: 200, caps: ['transfer', 'shell'] },
  { name: 'dovm', secret: 'not-a-secret', addedAt: 999 },
  { name: 'pixel-old-label', secret: third, addedAt: 120 },
]))
const loaded = devicesLoad()
eq('no different-secret record is dropped on load', secrets(loaded), [older, newer, third].sort())
eq('newest of a name clash keeps the name', loaded.find((d) => d.secret === newer).name, 'dovm')
eq('older clashing record is relabeled, not deleted', loaded.find((d) => d.secret === older).name, 'dovm 2')
eq('same-secret copies collapse to the newest', [loaded.filter((d) => d.secret === third).length, loaded.find((d) => d.secret === third).name], [1, 'pixel'])
eq('order is preserved', names(loaded), ['dovm 2', 'pixel', 'dovm'])
eq('invalid records are dropped', loaded.some((d) => d.secret === 'not-a-secret'), false)
eq('load wrote the migration back', stored().map((d) => d.name), names(loaded))
eq('every record has a unique id', new Set(loaded.map((d) => d.id)).size, loaded.length)
eq('ids are stable across loads', devicesLoad().map((d) => d.id), loaded.map((d) => d.id))
eq('two tabs migrating the same storage agree on ids', devicesDedupe(JSON.parse(JSON.stringify([
  { name: 'x', secret: older, addedAt: 5 }, { name: 'x', secret: newer, addedAt: 6 }]))).map((d) => d.id),
  devicesDedupe([{ name: 'x', secret: older, addedAt: 5 }, { name: 'x', secret: newer, addedAt: 6 }]).map((d) => d.id))

// 5. Forget removes exactly the chosen record (by id, or by unique name).
localStorage.clear()
devicesStore('Kabir Laptop', laptopS)
devicesStore('Kabir Laptop', third) // -> "Kabir Laptop 2"
const second = devicesLoad().find((d) => d.secret === third)
eq('forget by id removes only that device', secrets(devicesForget(second.id)), [laptopS])
devicesStore('pixel', newer)
eq('forget by name removes only that device', secrets(devicesForget('pixel')), [laptopS])
eq('forget of an unknown key is a no-op', secrets(devicesForget('nope')), [laptopS])

// 6. Row keys are stable and never expose the secret.
const row = devicesLoad()[0]
eq('row key is stable across reads', deviceRowKey(row), deviceRowKey(devicesLoad()[0]))
eq('row key never contains the secret', deviceRowKey(row).includes(laptopS), false)
eq('row key is the record id', deviceRowKey(row), row.id)

// 7. The page matches live peers to records by id (secret-derived), never by
//    display name, and keys rows without the secret.
const ui = readFileSync(new URL('../../ui/Tunlion.jsx', import.meta.url), 'utf8')
eq('Devices screen dedupes its state list', /devicesDedupe\(state\.knownDevices/.test(ui), true)
eq('device rows use the non-secret stable key', /key=\{deviceRowKey\(d\)\}/.test(ui), true)
eq('live match is by record id', /p\.knownId === d\.id/.test(ui), true)
eq('live match is never by name', /p\.known === d\.name/.test(ui), false)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('devices.test: ok')
