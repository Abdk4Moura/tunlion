// node frontend/src/lib/__tests__/identity.test.mjs
// The device name is a stable browser label; the session generation is never
// persisted and must change on every page load/rotation.
class MemoryStore {
  #m = new Map()
  getItem(k) { return this.#m.has(k) ? this.#m.get(k) : null }
  setItem(k, v) { this.#m.set(k, String(v)) }
  removeItem(k) { this.#m.delete(k) }
  clear() { this.#m.clear() }
}

const localStorage = new MemoryStore()
const sessionStorage = new MemoryStore()
globalThis.localStorage = localStorage
globalThis.sessionStorage = sessionStorage
// Node 22 already exposes the Web Crypto global (randomUUID/getRandomValues).

const {
  loadDeviceName, saveDeviceName, normalizeDeviceName,
  randomDeviceName, loadOwnerToken, saveOwnerToken,
  currentGeneration, rotateGeneration,
} = await import('../identity.js')

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); ok = false }
  else console.log(`  ${label}: OK`)
}

eq('normalizes whitespace', normalizeDeviceName('  my   iPad  '), 'my iPad')
eq('strips control characters', normalizeDeviceName('bad\u0000name'), 'bad name')
eq('blank is empty', normalizeDeviceName('   '), '')
eq('a generated name is two words', /^[a-z]+-[a-z]+$/.test(randomDeviceName()), true)

// First load: a generated default is persisted for the whole browser.
localStorage.clear(); sessionStorage.clear()
const first = loadDeviceName()
eq('first load generates a name', /^[a-z]+-[a-z]+$/.test(first), true)
eq('generated name is persisted', localStorage.getItem('tunlion.deviceName'), first)
eq('legacy per-tab key is mirrored', sessionStorage.getItem('tunlion.name'), first)

// The old per-tab-only name migrates instead of being replaced.
localStorage.clear(); sessionStorage.clear()
sessionStorage.setItem('tunlion.name', 'silken-chickadee')
eq('legacy name migrates', loadDeviceName(), 'silken-chickadee')
eq('migrated name persists', localStorage.getItem('tunlion.deviceName'), 'silken-chickadee')

// A chosen name wins and blank cannot erase the identity.
eq('chosen name saves', saveDeviceName('studio-ipad'), 'studio-ipad')
eq('chosen name loads', loadDeviceName(), 'studio-ipad')
eq('blank keeps current', saveDeviceName('   '), 'studio-ipad')
eq('blank did not clear storage', localStorage.getItem('tunlion.deviceName'), 'studio-ipad')

// The relay-minted ownership token is persisted but is NOT the device name.
eq('no token before the relay mints one', loadOwnerToken(), '')
saveOwnerToken('owner-secret-123')
eq('owner token persists', loadOwnerToken(), 'owner-secret-123')
eq('owner token is not the name', localStorage.getItem('tunlion.deviceName') !== loadOwnerToken(), true)

// Generation: one per page load, rotated explicitly, never in storage.
const g1 = currentGeneration()
eq('generation is a non-empty id', typeof g1 === 'string' && g1.length > 10, true)
eq('currentGeneration is stable', currentGeneration(), g1)
const g2 = rotateGeneration()
eq('rotation changes generation', g2 !== g1, true)
eq('current reflects rotation', currentGeneration(), g2)
eq('generation is not persisted', localStorage.getItem('tunlion.gen'), null)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('identity.test: ok')
