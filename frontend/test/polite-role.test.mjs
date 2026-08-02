import test from 'node:test'
import assert from 'node:assert/strict'
import { politeRole, legacyPoliteRole } from '../src/lib/webrtc.js'

const pair = (a, b) => {
  assert.notEqual(a, b, 'exactly one side must be polite')
}

test('politeRole is antisymmetric for complete identity tuples', () => {
  pair(
    politeRole({ myUid: 'uid-a', peerUid: 'uid-b', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'uid-b', peerUid: 'uid-a', myId: 'sid-b', peerId: 'sid-a' }),
  )
  pair(
    politeRole({ myUid: 'uid-z', peerUid: 'uid-a', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'uid-a', peerUid: 'uid-z', myId: 'sid-b', peerId: 'sid-a' }),
  )
})

test('politeRole breaks ties for devices sharing a user UID', () => {
  pair(
    politeRole({ myUid: 'same-user', peerUid: 'same-user', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'same-user', peerUid: 'same-user', myId: 'sid-b', peerId: 'sid-a' }),
  )
})

test('politeRole rejects an identical identity tuple', () => {
  assert.throws(() => politeRole({
    myUid: 'same-user', peerUid: 'same-user', myId: 'same-sid', peerId: 'same-sid',
  }), /identity tuple collision/)
})

test('legacy missing-UID path is explicit compatibility only', () => {
  assert.equal(legacyPoliteRole({ myUid: 'uid-z', peerUid: null, myId: 'sid-b', peerId: 'sid-a' }), true)
})
