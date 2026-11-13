// node frontend/src/lib/__tests__/resumeAdmission.test.mjs
// Pins that a resume offer is admitted like any other offer: a transfer id is
// not an identity or a permission, and old bytes are only ever spliced onto a
// transfer that the CURRENT link proved as the same remembered record.
//
// The bug this pins: the receiver auto-accepted any resume whose transfer id
// was in the shared partials store. That store is keyed by transfer id and
// outlives the link, so a sender that knew the id could resume after the peer
// was forgotten or revoked, and on a replacement link.
import { PeerLink } from '../webrtc.js'

// The link's constructor builds a real RTCPeerConnection. This test drives the
// offer and admission paths, never the transport, so a minimal fake is enough.
class FakeChannel {
  constructor() { this.readyState = 'connecting'; this.sent = [] }
  send(x) { this.sent.push(x) }
  close() {}
  addEventListener() {}
  removeEventListener() {}
}
class FakePc {
  constructor() {
    this.connectionState = 'new'
    this.iceConnectionState = 'new'
    this.iceGatheringState = 'new'
    this.signalingState = 'stable'
    this.localDescription = null
    this.remoteDescription = null
    this.channels = []
  }
  createDataChannel() { const c = new FakeChannel(); this.channels.push(c); return c }
  createOffer() { return Promise.resolve({ type: 'offer', sdp: '' }) }
  createAnswer() { return Promise.resolve({ type: 'answer', sdp: '' }) }
  setLocalDescription() { return Promise.resolve() }
  setRemoteDescription() { return Promise.resolve() }
  addIceCandidate() { return Promise.resolve() }
  close() {}
  getStats() { return Promise.resolve([]) }
}
globalThis.RTCPeerConnection = FakePc
globalThis.RTCDataChannel = FakeChannel
globalThis.RTCSessionDescription = class {}

let ok = true
const eq = (label, got, want) => {
  if (got !== want) { console.log(`  !! ${label}: got ${JSON.stringify(got)} want ${JSON.stringify(want)}`); ok = false }
  else console.log(`  ${label}: OK`)
}

const OFFER = {
  type: 'file-offer',
  id: 'tx-1',
  sid: 7,
  name: 'big.bin',
  size: 1024,
  resume: true,
  full: 'digest-1',
}

// A link with just enough surface for the offer path: no socket, no timers.
function makeLink({ partials, proven = false } = {}) {
  const sent = []
  const link = new PeerLink({
    id: 'peer',
    name: 'peer',
    iceServers: [],
    chunkSize: 1024,
    polite: true,
    myUid: 'me',
    peerUid: 'them',
    stores: { partials: partials || new Map(), outgoing: new Map() },
    sendSignal: () => {},
    onStatus: () => {},
    onTransfer: () => {},
  })
  link._proven = proven
  link._control = (m) => sent.push(m)
  return { link, sent }
}

// A resume offer is SURFACED, never auto-accepted, whatever the store holds.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1' }]])
  const { link, sent } = makeLink({ partials })
  let surfaced = 0
  link.onTransfer = () => { surfaced++ }
  link._onControl(OFFER)
  eq('a resume offer is surfaced, not auto-accepted', sent.length, 0)
  eq('the resume offer reaches the offer path', surfaced, 1)
  eq('the transfer is offered, not transferring', link.transfers.get('tx-1').status, 'offered')
  eq('the resume is remembered on the transfer', link.transfers.get('tx-1')._resume, true)
}

// The partial store alone grants nothing: acceptance needs an owner.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1' }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-1', _resume: true })
  link.acceptTransfer('tx-1', null)
  eq('an unbound owner restarts from byte zero', sent[0] && sent[0].offset, 0)
  eq('the old bytes are not reused', link.stores.partials.get('tx-1').received, 0)
}

// The same proved record may reuse the bytes it already holds.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1', owner: { id: 'r1', secret: 's1' } }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-1', _resume: true })
  link.acceptTransfer('tx-1', { id: 'r1', secret: 's1' })
  eq('the same proved record resumes at its offset', sent[0] && sent[0].offset, 512)
}

// A DIFFERENT record, even with the same transfer id, may not reuse the bytes.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1', owner: { id: 'r1', secret: 's1' } }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-1', _resume: true })
  link.acceptTransfer('tx-1', { id: 'r2', secret: 's2' })
  eq('a different record restarts from byte zero', sent[0] && sent[0].offset, 0)
}

// The same record id with a different secret is a different relationship.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1', owner: { id: 'r1', secret: 's1' } }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-1', _resume: true })
  link.acceptTransfer('tx-1', { id: 'r1', secret: 'rotated' })
  eq('a rotated secret restarts from byte zero', sent[0] && sent[0].offset, 0)
}

// A different file, on the same record, may not reuse the bytes either.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1', owner: { id: 'r1', secret: 's1' } }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-OTHER', _resume: true })
  link.acceptTransfer('tx-1', { id: 'r1', secret: 's1' })
  eq('a different whole-file digest restarts from byte zero', sent[0] && sent[0].offset, 0)
}

// A legacy partial with no owner binding cannot be spliced onto anything.
{
  const partials = new Map([['tx-1', { received: 512, buffers: [], size: 1024, full: 'digest-1' }]])
  const { link, sent } = makeLink({ partials })
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'offered', size: 1024, _sid: 7, _full: 'digest-1', _resume: true })
  link.acceptTransfer('tx-1', { id: 'r1', secret: 's1' })
  eq('an unbound legacy partial restarts from byte zero', sent[0] && sent[0].offset, 0)
}

// A transfer that is not an offer is not accepted at all.
{
  const { link, sent } = makeLink()
  link.transfers.set('tx-1', { id: 'tx-1', direction: 'receive', status: 'transferring', size: 1024, _sid: 7 })
  link.acceptTransfer('tx-1', { id: 'r1', secret: 's1' })
  eq('a running transfer is not accepted again', sent.length, 0)
}

if (!ok) { console.log('FAIL'); process.exit(1) }
console.log('PASS')
