// node frontend/src/lib/__tests__/signalTransport.test.mjs
import { transportsAfterFailure, SOCKET_TIMEOUT_MS, POLL_AFTER_MS, hedgeDelayMs, apiRttFromEntries, HEDGE_MIN_MS, HEDGE_UNKNOWN_MS } from '../signalTransport.js'

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

// The hedge: a held websocket is abandoned after what this network's own
// round trip says an open needs, never later than the old fixed bound.
eq('a hedged attempt leads with polling at once', transportsAfterFailure(wsFirst, { attempts: 0, downMs: 900, pollAfterMs: 0 }), ['polling', 'websocket'])
eq('a fast network hedges at the floor', hedgeDelayMs(20), HEDGE_MIN_MS)
eq('a 300 ms network hedges after three round trips and a margin', hedgeDelayMs(300), 1200)
eq('a very slow network never waits past the old bound', hedgeDelayMs(5000), POLL_AFTER_MS)
eq('an unknown round trip uses the default', hedgeDelayMs(null), HEDGE_UNKNOWN_MS)
eq('the hedge is always earlier than the fixed bound when unknown', HEDGE_UNKNOWN_MS < POLL_AFTER_MS, true)
const entries = [
  { name: 'https://api.example/api/config', duration: 180 },
  { name: 'https://api.example/api/room', duration: 60 },
  { name: 'https://cdn.example/app.js', duration: 5 },
  { name: 'https://other.example/api/room', duration: 1 },
]
eq('the round trip is the fastest API request to this origin', apiRttFromEntries(entries, 'https://api.example'), 60)
eq('no API request means no estimate', apiRttFromEntries([{ name: 'https://cdn.example/x.js', duration: 3 }], 'https://api.example'), null)

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
