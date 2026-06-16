// Characterization tests for the resilience-manager's pure recovery decisions
// (Phase 2). Plain Node ESM:
// node frontend/src/net/app/__tests__/recovery.test.mjs
// Pins the onStall escalation, onStuck retry/second-wind, and link-rebuild
// predicate extracted 1:1 from useFilament.js, so the rewire is behavior-faithful.
import { decideStallEscalation, decideStuckRecovery, shouldRebuildLink, REBUILD_STATES } from '../recovery.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// --- decideStallEscalation: bounded at-most-once relay escalation ---
eq('non-persistent → ignore',
  decideStallEscalation({ reason: 'transient', relayOnly: false, relayedCount: 0 }), { action: 'ignore' })
eq('persistent, fresh → escalate-relay',
  decideStallEscalation({ reason: 'persistent', relayOnly: false, relayedCount: 0 }), { action: 'escalate-relay' })
eq('persistent, already on relay → leave-to-p0',
  decideStallEscalation({ reason: 'persistent', relayOnly: true, relayedCount: 0 }), { action: 'leave-to-p0' })
eq('persistent, relay spent → already-spent',
  decideStallEscalation({ reason: 'persistent', relayOnly: false, relayedCount: 1 }), { action: 'already-spent' })
eq('relayOnly wins over count (leave-to-p0)',
  decideStallEscalation({ reason: 'persistent', relayOnly: true, relayedCount: 5 }), { action: 'leave-to-p0' })

// --- decideStuckRecovery: retry up to maxRetries, then fail (with one second wind) ---
eq('attempt 1 → retry', decideStuckRecovery({ attempts: 1, visible: false, secondWindUsed: false }), { action: 'retry' })
eq('attempt 2 → retry', decideStuckRecovery({ attempts: 2, visible: true, secondWindUsed: false }), { action: 'retry' })
eq('attempt 3 visible, unused → second-wind',
  decideStuckRecovery({ attempts: 3, visible: true, secondWindUsed: false }), { action: 'second-wind' })
eq('attempt 3 hidden → fail',
  decideStuckRecovery({ attempts: 3, visible: false, secondWindUsed: false }), { action: 'fail' })
eq('attempt 3 visible but second-wind spent → fail',
  decideStuckRecovery({ attempts: 3, visible: true, secondWindUsed: true }), { action: 'fail' })
eq('custom maxRetries respected',
  decideStuckRecovery({ attempts: 4, visible: true, secondWindUsed: false, maxRetries: 4 }), { action: 'retry' })

// --- shouldRebuildLink: dead ICE states ---
eq('rebuild states', REBUILD_STATES, ['failed', 'closed', 'disconnected'])
eq('failed → rebuild', shouldRebuildLink('failed'), true)
eq('closed → rebuild', shouldRebuildLink('closed'), true)
eq('disconnected → rebuild', shouldRebuildLink('disconnected'), true)
eq('connected → no rebuild', shouldRebuildLink('connected'), false)
eq('connecting → no rebuild', shouldRebuildLink('connecting'), false)
eq('undefined → no rebuild', shouldRebuildLink(undefined), false)

console.log(ok ? 'RECOVERY TESTS PASS' : 'RECOVERY TESTS FAIL')
process.exit(ok ? 0 : 1)
