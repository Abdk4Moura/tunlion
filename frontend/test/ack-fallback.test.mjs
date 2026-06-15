// P4 silent-data-loss fix: unit tests for decideAckFallback, the pure core of the
// send-completion decision. Run with: node test/ack-fallback.test.mjs
//
// We import the function directly. webrtc.js pulls in browser globals at module
// scope only inside class methods, the top-level export is safe to import under
// node. If that ever changes, this test isolates the function instead.
import assert from 'node:assert/strict'
import { decideAckFallback } from '../src/lib/webrtc.js'

let passed = 0
const t = (name, fn) => { fn(); passed++; console.log('  ok -', name) }

// The cardinal rule: decideAckFallback NEVER returns 'complete'. Only a genuine
// CTRL.DELIVERY_ACK may complete a send.
t('never returns complete (exhaustive over inputs)', () => {
  for (const channelOpen of [true, false])
    for (const connected of [true, false])
      for (const peerHasAcked of [true, false])
        for (const offeredDigest of [true, false])
          for (const reprobed of [true, false]) {
            const d = decideAckFallback({ channelOpen, connected, peerHasAcked, offeredDigest, reprobed })
            assert.notEqual(d.action, 'complete')
            assert.ok(d.action === 'reprobe' || d.action === 'fail')
          }
})

// Unhealthy link (the black-hole case the bug was about): channel/connection not
// healthy -> fail immediately, resumable, never re-probe (no point) and never
// complete. This is the exact scenario that used to falsely complete.
t('unhealthy link fails resumably (the black-hole case)', () => {
  const d = decideAckFallback({ channelOpen: false, connected: false, peerHasAcked: false, offeredDigest: true, reprobed: false })
  assert.equal(d.action, 'fail')
  assert.equal(d.resumable, true)
})
t('channel open but pc not connected -> fail', () => {
  const d = decideAckFallback({ channelOpen: true, connected: false, peerHasAcked: false, offeredDigest: true, reprobed: false })
  assert.equal(d.action, 'fail')
})
t('pc connected but channel closed -> fail', () => {
  const d = decideAckFallback({ channelOpen: false, connected: true, peerHasAcked: false, offeredDigest: true, reprobed: false })
  assert.equal(d.action, 'fail')
})

// Healthy link, first window: the ack may have been lost -> re-probe once.
t('healthy + not yet reprobed -> reprobe', () => {
  const d = decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: true, offeredDigest: true, reprobed: false })
  assert.equal(d.action, 'reprobe')
})

// Healthy link but already re-probed and STILL no ack -> fail resumably, never
// complete. (Even though the link looks alive, silence after a re-probe is a real
// failure, not permission to claim success.)
t('healthy + reprobed + still no ack -> fail resumably', () => {
  const d = decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: true, offeredDigest: true, reprobed: true })
  assert.equal(d.action, 'fail')
  assert.equal(d.resumable, true)
})

// A peer that never acked and no digest offered (the legacy interop case) still
// must not silently complete: it re-probes then fails honestly. The modern fleet
// always offers a digest + acks, so the happy path is the real ack, not this.
t('legacy peer (no ack history, no digest) still re-probes then fails', () => {
  const first = decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: false, offeredDigest: false, reprobed: false })
  assert.equal(first.action, 'reprobe')
  const second = decideAckFallback({ channelOpen: true, connected: true, peerHasAcked: false, offeredDigest: false, reprobed: true })
  assert.equal(second.action, 'fail')
})

console.log(`\n${passed} passed`)
