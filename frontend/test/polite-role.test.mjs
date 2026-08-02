import test from 'node:test'
import assert from 'node:assert/strict'
import { politeRole } from '../src/lib/webrtc.js'

const pair = (a, b) => {
  assert.notEqual(a, b, 'exactly one side must be polite')
}

test('politeRole is antisymmetric for every UID knowledge state', () => {
  pair(
    politeRole({ myUid: 'uid-a', peerUid: 'uid-b', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'uid-b', peerUid: 'uid-a', myId: 'sid-b', peerId: 'sid-a' }),
  )
  pair(
    politeRole({ myUid: 'uid-z', peerUid: 'uid-a', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'uid-a', peerUid: null, myId: 'sid-b', peerId: 'sid-a' }),
  )
  pair(
    politeRole({ myUid: 'uid-z', peerUid: null, myId: 'sid-b', peerId: 'sid-a' }),
    politeRole({ myUid: 'uid-a', peerUid: 'uid-z', myId: 'sid-a', peerId: 'sid-b' }),
  )
  pair(
    politeRole({ myUid: 'uid-a', peerUid: null, myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'uid-b', peerUid: null, myId: 'sid-b', peerId: 'sid-a' }),
  )
})

test('politeRole breaks ties for devices sharing a user UID', () => {
  pair(
    politeRole({ myUid: 'same-user', peerUid: 'same-user', myId: 'sid-a', peerId: 'sid-b' }),
    politeRole({ myUid: 'same-user', peerUid: 'same-user', myId: 'sid-b', peerId: 'sid-a' }),
  )
})
