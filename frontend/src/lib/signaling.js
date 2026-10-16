// Signaling abstraction.
//
// The rest of the app talks to ONE interface and doesn't care whether the
// signaling actually travels over Socket.IO (our Flask relay) or Firebase
// Firestore. Pick the implementation at runtime from /api/config.
//
//   const sig = await createSignaling()
//   sig.on('welcome',     ({ id, peers }) => {})
//   sig.on('peer-joined', ({ id, name })  => {})
//   sig.on('peer-left',   ({ id })        => {})
//   sig.on('signal',      ({ from, data })=> {})
//   sig.join(room, name)
//   sig.signal(toPeerId, data)
//   sig.leave()
//
// Both implementations emit the SAME four inbound events and accept the same
// join/signal/leave calls, that is the whole point of the abstraction.

import { io } from 'socket.io-client'
import { API_BASE } from './api.js'
import { SOCKET_TIMEOUT_MS, transportsAfterFailure } from './signalTransport.js'

class Emitter {
  #handlers = {}
  on(event, cb) {
    ;(this.#handlers[event] ||= []).push(cb)
    return this
  }
  off(event, cb) {
    const a = this.#handlers[event]
    if (a) this.#handlers[event] = a.filter((h) => h !== cb)
    return this
  }
  _emit(event, payload) {
    ;(this.#handlers[event] || []).forEach((cb) => cb(payload))
  }
}

// ---------------------------------------------------------------- Socket.IO --
class SocketIOSignaling extends Emitter {
  constructor() {
    super()
    this.kind = 'socketio'
    this.room = null
    this.name = null
    // API_BASE === '' → same-origin; otherwise connect to the backend origin.
    // WebSocket FIRST: socket.io's default is HTTP long-poll → upgrade, which
    // costs an extra handshake + upgrade round-trip on every connect (painful at
    // high RTT, e.g. a phone in Lagos to a US/EU origin). Trying `websocket`
    // first connects straight over WS; `polling` stays as the fallback so a
    // network that blocks WS still works (just slower there).
    //
    // A hung upgrade is the other failure. socket.io's default timeout is 20s,
    // and each reconnect starts the transport list over, so a tunnel that holds
    // the websocket leaves the page on "offline, reconnecting" for the whole
    // wait (launch matrix pair1/B03, 2026-10-15: the page never minted a code).
    // Bound that attempt, and after one failure lead with polling. Polling to
    // the same API answers immediately; websocket can still upgrade later.
    this._openedAt = Date.now()
    this._connectErrors = 0
    this.socket = io(API_BASE || undefined, {
      autoConnect: true,
      transports: ['websocket', 'polling'],
      timeout: SOCKET_TIMEOUT_MS,
      reconnectionDelay: 400,
      reconnectionDelayMax: 2000,
    })
    for (const ev of ['welcome', 'peer-joined', 'peer-left', 'signal', 'pair-code', 'pair-ok', 'pair-matched', 'pair-error', 'pair-used', 'known-peer', 'known-peer-left']) {
      this.socket.on(ev, (payload) => this._emit(ev, payload))
    }
    // Resilience: on every (re)connect, rejoin the current room. A reconnect
    // gives us a fresh sid and the server dropped our old membership on
    // disconnect, so without this we'd be connected but in no room. The server
    // re-emits `welcome`, which the hook treats as a fresh roster.
    this.socket.on('connect', () => {
      this._connectErrors = 0
      this._openedAt = Date.now()
      this._emit('status', { connected: true })
      if (this.room) this.socket.emit('join', { room: this.room, name: this.name, uid: this.uid })
    })
    this.socket.on('disconnect', () => {
      this._openedAt = Date.now()
      this._emit('status', { connected: false })
    })
    this.socket.on('connect_error', () => {
      this._connectErrors += 1
      this.#applyTransports()
    })
    // The timeout covers a hung attempt. This covers a socket that never
    // errors and never connects (the attempt just sits). Same decision.
    this._recoverTimer = setInterval(() => {
      if (!this.socket.connected) this.#applyTransports(true)
    }, 2000)
  }
  #applyTransports(nudge) {
    const next = transportsAfterFailure(this.socket.io.opts.transports, {
      attempts: this._connectErrors,
      downMs: Date.now() - this._openedAt,
    })
    const leadChanged = next[0] !== this.socket.io.opts.transports[0]
    this.socket.io.opts.transports = next
    if (leadChanged && this.socket.io.engine) this.socket.io.engine.close()
    if (nudge && !this.socket.connected) this.socket.connect()
  }
  join(room, name, uid) {
    this.room = room
    this.name = name
    this.uid = uid
    this.socket.emit('join', { room, name, uid })
  }
  signal(to, data) {
    this.socket.emit('signal', { to, data })
  }
  leave() {
    this.room = null
    clearInterval(this._recoverTimer)
    this.socket.emit('leave', {})
  }
  // Drop a hung websocket and try polling. Called when a click needs the
  // socket and it is known-down (create-code on a page that loaded offline).
  forceRecover() {
    this.#applyTransports(true)
  }
  // One-time pairing (#11): mint a speakable single-use code / claim one.
  pairCreate(keyword) {
    this.socket.emit('pair-create', { keyword: keyword || null })
  }
  pairClaim(code) {
    this.socket.emit('pair-claim', { code })
  }
  // L1-a (PAKE v2): the CLIENT mints the words; the server allocates ONLY the
  // numeric nameplate (never sees the password). The full code is displayed
  // from our own local mint when pair-ok arrives.
  pairCreateV2(nameplate) {
    this.socket.emit('pair-create', { nameplate, v: 2 })
  }
  // The claimer splits the typed code CLIENT-SIDE and sends ONLY the nameplate.
  pairClaimV2(nameplate) {
    this.socket.emit('pair-claim', { nameplate, v: 2 })
  }
  // C12: raise known-device presence channels (sha256 meeting points; the
  // server never sees a secret). Idempotent; safe to re-send on reconnect.
  // C28: onAck fires with the server's reply, callers verify the emit landed
  // (an unverified subscribe lost in a half-open socket = invisible devices).
  subscribe(channels, onAck) {
    if (channels?.length) this.socket.emit('subscribe', { channels }, (resp) => onAck?.(resp))
  }
  // C30: the convergent session's one idempotent emit. Carries the FULL desired
  // session state ({v, room, name, uid, channels}); the server ensures
  // membership + subscriptions + lease refresh and acks with its resulting
  // digest. Mirrors subscribe's ack shape. lib/session.js owns the loop that
  // decides WHEN to call this; here we only carry the wire.
  sync(state, onAck) {
    this.socket.emit('sync', state, (resp) => onAck?.(resp))
  }
  // Live socket truth, for the session loop's connected-gate (state captured in
  // closures goes stale; this reads the socket directly).
  get connected() {
    return !!this.socket?.connected
  }
  // Force a reconnect attempt (e.g. when a suspended mobile tab resumes).
  reconnect() {
    if (this.socket && !this.socket.connected) this.socket.connect()
  }
}

// ----------------------------------------------------------------- Firebase --
// Serverless signaling over Firestore. Loaded lazily so the Firebase SDK is
// only pulled in when SIGNALING=firebase. Presence + per-peer signal mailboxes
// mirror the Socket.IO event contract exactly.
class FirebaseSignaling extends Emitter {
  constructor(firebaseConfig) {
    super()
    this.kind = 'firebase'
    this.config = firebaseConfig
    this._ready = this.#init()
  }
  async #init() {
    // Optional dependency: only loaded in firebase mode. Install it with
    // `npm install firebase` before setting FIL_SIGNALING=firebase. @vite-ignore
    // keeps the default (socket.io) build from trying to bundle it.
    const [{ initializeApp }, fs] = await Promise.all([
      import(/* @vite-ignore */ 'firebase/app'),
      import(/* @vite-ignore */ 'firebase/firestore'),
    ])
    this.fs = fs
    this.db = fs.getFirestore(initializeApp(this.config))
    this.id = 'fb_' + Math.random().toString(36).slice(2, 10)
  }
  async join(room, name, uid) {
    await this._ready
    const { doc, setDoc, collection, onSnapshot, serverTimestamp } = this.fs
    this.room = room
    this.name = name
    this.uid = uid
    const peersCol = collection(this.db, 'rooms', room, 'peers')

    // Existing peers become our "welcome"; then announce ourselves.
    const { getDocs } = this.fs
    const existing = (await getDocs(peersCol)).docs
      .filter((d) => d.id !== this.id)
      .map((d) => ({ id: d.id, name: d.data().name, uid: d.data().uid }))
    await setDoc(doc(peersCol, this.id), { name, uid, joinedAt: serverTimestamp() })
    this._emit('welcome', { id: this.id, peers: existing })

    // Watch presence.
    this._unsubPeers = onSnapshot(peersCol, (snap) => {
      snap.docChanges().forEach((c) => {
        if (c.doc.id === this.id) return
        if (c.type === 'added') this._emit('peer-joined', { id: c.doc.id, name: c.doc.data().name, uid: c.doc.data().uid })
        if (c.type === 'removed') this._emit('peer-left', { id: c.doc.id })
      })
    })
    // Watch our signal mailbox.
    const mailbox = collection(this.db, 'rooms', room, 'peers', this.id, 'inbox')
    this._unsubInbox = onSnapshot(mailbox, (snap) => {
      snap.docChanges().forEach((c) => {
        if (c.type !== 'added') return
        const { from, data } = c.doc.data()
        this._emit('signal', { from, data })
        this.fs.deleteDoc(c.doc.ref)
      })
    })
  }
  // C30: Firebase has no relay-side session to converge; presence and
  // subscriptions are modeled directly in Firestore by join(). The convergent
  // sync is therefore a no-op that acks IMMEDIATELY: the session loop only
  // re-emits while confirmed stays unconfirmed, so an instant ack lets it go
  // dormant (room/channels already converge via the snapshot listeners). If we
  // never acked, the loop would emit every 5s forever.
  sync(_state, onAck) {
    onAck?.({ v: 1, ok: true, firebase: true })
  }
  // Firebase's socket is always "up" once ready; there is no half-open relay
  // socket to gate against. Reported true so the (dormant) loop isn't blocked.
  get connected() {
    return true
  }
  async signal(to, data) {
    await this._ready
    const { collection, addDoc } = this.fs
    await addDoc(collection(this.db, 'rooms', this.room, 'peers', to, 'inbox'), {
      from: this.id,
      data,
    })
  }
  async leave() {
    await this._ready
    this._unsubPeers?.()
    this._unsubInbox?.()
    const { doc, deleteDoc } = this.fs
    await deleteDoc(doc(this.db, 'rooms', this.room, 'peers', this.id))
  }
}

export async function createSignaling(appConfig) {
  if (appConfig.signaling === 'firebase' && appConfig.firebase) {
    return new FirebaseSignaling(appConfig.firebase)
  }
  return new SocketIOSignaling()
}
