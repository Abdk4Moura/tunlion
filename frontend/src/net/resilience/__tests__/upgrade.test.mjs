// Characterization tests for the relay→direct upgrade prober policy. Plain Node
// ESM: node frontend/src/net/resilience/__tests__/upgrade.test.mjs
// Pins the probe-result classification, the verify-before-commit tick, and the
// backoff cadence extracted 1:1 from webrtc.js _upgradeProbe/_beginUpgradeVerify/
// _backoffUpgrade. (The relay scenario isn't reproducible single-host, so these
// unit tests are the verification floor for this slice.)
import { decideProbeResult, decideUpgradeVerifyTick, nextUpgradeDelay } from '../upgrade.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// --- probe result: non-relay → verify, relay/none → backoff ---
eq('probe local → verify', decideProbeResult('local'), { action: 'verify', route: 'local' })
eq('probe direct → verify', decideProbeResult('direct'), { action: 'verify', route: 'direct' })
eq('probe relayed → backoff', decideProbeResult('relayed'), { action: 'backoff' })
eq('probe null → backoff', decideProbeResult(null), { action: 'backoff' })
eq('probe undefined → backoff', decideProbeResult(undefined), { action: 'backoff' })

// --- verify tick: commit / discard / wait ---
const V = 2000
eq('reverted to relay → discard',
  decideUpgradeVerifyTick({ measuredRoute: 'relayed', hasInflight: false, idleMs: 0, elapsedMs: 500, verifyMs: V }),
  { action: 'discard' })
eq('inflight stalled past window → discard',
  decideUpgradeVerifyTick({ measuredRoute: 'direct', hasInflight: true, idleMs: 2000, elapsedMs: 500, verifyMs: V }),
  { action: 'discard' })
eq('inflight but bytes recent → not discarded (wait)',
  decideUpgradeVerifyTick({ measuredRoute: 'direct', hasInflight: true, idleMs: 400, elapsedMs: 500, verifyMs: V }),
  { action: 'wait' })
eq('held long enough → commit',
  decideUpgradeVerifyTick({ measuredRoute: 'direct', hasInflight: false, idleMs: 0, elapsedMs: 2000, verifyMs: V }),
  { action: 'commit' })
eq('null measurement, window elapsed → commit (idle direct pair is evidence)',
  decideUpgradeVerifyTick({ measuredRoute: null, hasInflight: false, idleMs: 0, elapsedMs: 2500, verifyMs: V }),
  { action: 'commit' })
eq('not yet held → wait',
  decideUpgradeVerifyTick({ measuredRoute: 'direct', hasInflight: false, idleMs: 0, elapsedMs: 1000, verifyMs: V }),
  { action: 'wait' })
// Discard wins over commit when both could apply (regressed even at window end).
eq('relay at window end → discard (not commit)',
  decideUpgradeVerifyTick({ measuredRoute: 'relayed', hasInflight: false, idleMs: 0, elapsedMs: 5000, verifyMs: V }),
  { action: 'discard' })

// --- backoff cadence: double toward the steady cap ---
eq('backoff doubles', nextUpgradeDelay(1000, 30000), 2000)
eq('backoff caps at steady', nextUpgradeDelay(20000, 30000), 30000)
eq('backoff already at cap', nextUpgradeDelay(30000, 30000), 30000)

console.log(ok ? 'UPGRADE TESTS PASS' : 'UPGRADE TESTS FAIL')
process.exit(ok ? 0 : 1)
