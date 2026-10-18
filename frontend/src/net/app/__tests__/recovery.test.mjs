// Characterization tests for the resilience-manager's pure recovery decisions
// (Phase 2). Plain Node ESM:
// node frontend/src/net/app/__tests__/recovery.test.mjs
// Pins the onStall escalation, onStuck retry/second-wind, and link-rebuild
// predicate extracted 1:1 from useTunlion.js, so the rewire is behavior-faithful.
import { decideStallEscalation, decideStuckRecovery, shouldRebuildLink, REBUILD_STATES, linkIsLive, reconcileDigest } from '../recovery.js'

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

// --- linkIsLive: signaling presence != data path ---
const link = (readyState, connectionState) => ({ channel: { readyState }, pc: { connectionState } })
eq('open + connected → live', linkIsLive(link('open', 'connected')), true)
eq('closed channel → not live', linkIsLive(link('closed', 'connected')), false)
eq('disconnected pc → not live', linkIsLive(link('open', 'disconnected')), false)
eq('failed pc → not live', linkIsLive(link('open', 'failed')), false)
eq('missing link → not live', linkIsLive(null), false)

// --- reconcileDigest: a live link absent from the roster is NOT dropped ---
const digest = (opts) => reconcileDigest({
  present: new Set(), channelPids: new Set(), misses: new Map(), links: [], peers: [], ...opts,
})
// The #513 shape: the peer's sid is missing from the digest while its data
// channel still carries the shell. Two (ten) consecutive digests must keep it.
let misses = new Map()
let verdict = null
for (let i = 0; i < 10; i++) {
  verdict = digest({ links: [{ id: 'live', live: true }], misses })
  misses = verdict.misses
}
eq('live link absent ×10 → never dropped', verdict.drops, [])
eq('live link absent ×10 → no half-armed miss count', [...verdict.misses.entries()], [])

// A genuinely dead link is still reaped after two misses (missed peer-left).
verdict = digest({ links: [{ id: 'dead', live: false }] })
eq('dead link, first miss → keep', verdict.drops, [])
eq('dead link, first miss → counted', [...verdict.misses.entries()], [['dead', 1]])
eq('dead link, second miss → drop', digest({ links: [{ id: 'dead', live: false }], misses: verdict.misses }).drops, ['dead'])

// Presence clears a pending miss; a channel-introduced link is room-independent.
eq('present clears the count', [...digest({ present: new Set(['p']), links: [{ id: 'p', live: false }], misses: new Map([['p', 1]]) }).misses.entries()], [])
eq('channel link absent → exempt',
  digest({ channelPids: new Set(['known']), links: [{ id: 'known', live: false }], misses: new Map([['known', 1]]) }), { adopt: [], drops: [], misses: new Map() })

// A live link that then dies starts a fresh two-miss window.
let m = new Map([['p', 1]])
m = digest({ links: [{ id: 'p', live: true }], misses: m }).misses
eq('live absence clears prior history', [...m.entries()], [])
m = digest({ links: [{ id: 'p', live: false }], misses: m }).misses
eq('after death, first miss counts from zero', [...m.entries()], [['p', 1]])

// Roster adoption is unchanged: only peers we do not already link.
eq('adopts a new roster peer', digest({ peers: [{ id: 'new', name: 'n' }] }).adopt.map((p) => p.id), ['new'])
eq('does not adopt an existing link', digest({ peers: [{ id: 'old', name: 'n' }], links: [{ id: 'old', live: true }] }).adopt, [])
console.log(ok ? 'RECOVERY TESTS PASS' : 'RECOVERY TESTS FAIL')
process.exit(ok ? 0 : 1)
