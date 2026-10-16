// node frontend/src/lib/__tests__/signalTransport.test.mjs
import { transportsAfterFailure, SOCKET_TIMEOUT_MS, POLL_AFTER_MS } from '../signalTransport.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

const wsFirst = ['websocket', 'polling']
eq('a fresh socket still tries websocket first', transportsAfterFailure(wsFirst, { attempts: 0, downMs: 0 }), wsFirst)
eq('one failed attempt leads with polling', transportsAfterFailure(wsFirst, { attempts: 1, downMs: 100 }), ['polling', 'websocket'])
eq('a few seconds still down leads with polling', transportsAfterFailure(wsFirst, { attempts: 0, downMs: POLL_AFTER_MS }), ['polling', 'websocket'])
eq('already on polling stays on polling', transportsAfterFailure(['polling', 'websocket'], { attempts: 3, downMs: 20000 }), ['polling', 'websocket'])
eq('a missing list still has a fallback', transportsAfterFailure(null, { attempts: 1 }), ['polling', 'websocket'])
eq('the hung-upgrade bound is under the create-code wait', SOCKET_TIMEOUT_MS < 8000, true)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
