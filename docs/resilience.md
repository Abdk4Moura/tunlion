# Connection resilience & state machines

Tunlion has three interacting state machines:

1. **Room / signaling** — `signaling.py` (server) + `signaling.js` (client). Tracks
   who is in a room and relays opaque WebRTC payloads. Convention: roles are
   assigned by a deterministic tiebreaker (see #1), not by join order.
2. **Per-peer negotiation** — `webrtc.js` `PeerLink`: `new → offer/answer/ICE →
   connected → (disconnected) → failed/closed`.
3. **Per-file transfer** — `webrtc.js`: `offered → transferring → complete |
   declined | failed`.

Most flakiness lives in the *seams* between these, and reconnection stresses
every seam at once. This doc records each failure mode we found and fixed —
problem, then solution — so the reasoning isn't lost.

> The Rust CLI (`../cli/`) reimplements the client side of this protocol and
> keeps its own ledger — including which of the 11 fixes below it has and
> hasn't earned yet: [`cli-resilience.md`](cli-resilience.md).

---

## 1. Glare: both peers offer at once → stuck "connecting"

**Symptom.** Sometimes two devices never connect (both tiles sit at
"connecting"), especially right after a reconnect.

**Problem.** The old design picked the offerer by join order ("the newer peer
initiates"). That only holds if the server's `welcome` reads are serialized.
Two ways it isn't:
- On reconnect both peers come back together; each `welcome` can already list
  the other, so **both** become initiators → both `createOffer` → each receives
  the other's offer while in `have-local-offer` → `setRemoteDescription` throws.
- We run the signaling with Redis for scaling; the eventlet worker **yields at
  every Redis I/O**, so the server's `join` handler is no longer atomic and two
  joins can interleave and each see the other.

The thrown error was swallowed, leaving the peer stuck.

**Solution.** Standard **perfect negotiation** with a deterministic role:
`polite = myId > peerId` (string compare), so exactly one peer per pair is
*impolite* and owns the offer. The impolite peer creates the data channel
(triggering `onnegotiationneeded` → offer); the polite peer answers. On a true
collision the impolite peer **ignores** the incoming offer and the polite peer
rolls back. No reliance on ordering, so it's race-proof.
*Files:* `webrtc.js` (constructor, `onnegotiationneeded`, `_handleSignal`),
`useTunlion.js` (`makeLink` computes `polite` from `myIdRef`).

## 2. Unserialized signals drop ICE candidates

**Symptom.** Intermittent connect failures or needless relay (TURN) fallback.

**Problem.** The hook called `link.accept(data)` per relayed message but never
awaited it, so an `offer` and the `candidate`s that followed it ran
**concurrently**. A candidate that reached `addIceCandidate` before
`setRemoteDescription` resolved threw "remote description is null" and was
**silently dropped**. Lost host candidates hurt connectivity.

**Solution.** A **per-peer FIFO queue** (`enqueueSignal` chains onto
`this._signalQ`) so each signal is fully applied before the next, **plus** a
candidate buffer: candidates that arrive before a remote description is set are
held in `_pendingCandidates` and flushed by `_flushCandidates()` right after
`setRemoteDescription`.
*Files:* `webrtc.js` (`enqueueSignal`, `_handleSignal`, `_flushCandidates`),
`useTunlion.js` (signal handler calls `enqueueSignal`).

## 3. Ghost peer tiles after teardown

**Symptom.** Dead "connecting"/"failed" tiles linger after a peer leaves or you
reconnect.

**Problem.** `upsertPeer` **added if missing**. But a closed `PeerLink`'s async
callbacks still fired afterward — `_detectRoute` reschedules via `setTimeout`
for ~2s, and in-flight `onconnectionstatechange` events arrive late — and each
late `onStatus`/`onRoute` re-`upsert`ed (re-created) the tile we'd just removed.

**Solution.** Two parts: (a) a `_closed` guard — `close()` sets it and replaces
`onStatus`/`onRoute`/`onTransfer` with no-ops, and `_detectRoute` bails when
closed; (b) split the hook's `upsertPeer` into `addPeer` (used only by
`makeLink`) and `updatePeer` (status/route — **never adds**). A late callback
can no longer resurrect a removed tile.
*Files:* `webrtc.js` (`close`, `_detectRoute`), `useTunlion.js` (`addPeer` /
`updatePeer`).

## 4. Concurrent transfers corrupt each other

**Symptom.** Sending/accepting more than one file at once produced corrupt
files or a transfer stuck at "transferring".

**Problem.** The receiver had a **single** `_incoming` slot and binary chunks
carried **no transfer id**, so accepting a second file overwrote the slot and
mixed the byte streams. On the send side, two `_streamFile` loops interleaved
raw bytes on one channel and **clobbered each other's**
`channel.onbufferedamountlow`, hanging one of them.

**Solution.** **Frame every chunk** with a 4-byte stream id (`[uint32 sid]
[payload]`); the receiver keys buffers by `sid` in `_incomingBySid`, so any
number of transfers can interleave safely. Backpressure now uses **one
persistent** `onbufferedamountlow` that resolves a shared `_drainWaiters` list,
so concurrent senders never clobber it.
*Files:* `webrtc.js` (`sendFiles`, `acceptTransfer`, `_streamFile`, `_onMessage`,
`_onControl`, `_setChannel`).

## 5. A drop mid-transfer left an un-clearable "transferring" row

**Symptom.** Lose the connection while a file is moving and the row is stuck at
"transferring" forever — the **clear** button only shows for terminal states, so
it can't even be dismissed.

**Problem.** `onconnectionstatechange('failed')` updated the *peer* status but
nothing walked the transfers, so in-flight ones never reached a terminal state.

**Solution.** `_failActive()` marks any `transferring`/`offered` transfer as
`failed` (making it clearable), clears the incoming/outgoing maps, and unblocks
parked sender loops. It's called on `failed`, on the disconnect grace-timer
expiry, and in `close()`.
*Files:* `webrtc.js` (`_failActive`, `onconnectionstatechange`, `close`).

## 6. Transient `disconnected` was treated as terminal

**Symptom.** A brief network blip (e.g. Wi-Fi ↔ cellular) killed an otherwise
fine connection and forced a full re-pair.

**Problem.** `onconnectionstatechange` lumped `disconnected` in with `failed`.
But `disconnected` is frequently **transient** and ICE can recover on its own.

**Solution.** Treat `disconnected` as soft: show "connecting", have the impolite
peer call `restartIce()` to nudge recovery, and start a **6s grace timer** —
only if it hasn't returned to `connected` by then do we declare failure.
*Files:* `webrtc.js` (`onconnectionstatechange`, `_dcTimer`).

## 7. The signal handler trusted any sender

**Symptom.** Stray "connecting" tiles for peers that had already left.

**Problem.** `linksRef.get(from) || makeLink({ id: from })` created a brand-new
answerer link for **any** sid that sent **any** signal — including a stale or
duplicate message from a departed peer.

**Solution.** Only an incoming **offer** (`description` of type `offer`) may
create a new link; stray answers/candidates from unknown sids are ignored.
*Files:* `useTunlion.js` (signal handler).

## 8. No negotiation watchdog → stuck at "connecting" forever

**Symptom.** Two tiles sit at "connecting" indefinitely (not even reaching
"failed").

**Problem.** ICE only times out (→ `failed`) once offer **and** answer have
been exchanged. If a signaling message is lost — the one offer relayed to a
just-died sid, the peer's tab suspended mid-handshake, an SDP error swallowed
by the signal queue, or a both-polite deadlock from politeness compared over
mismatched (stale) sids — nothing ever starts ICE, nothing ever fails, and
nothing retries. Infinite "connecting".

**Solution.** Three layers:
- A **15s establishment watchdog** in `PeerLink`: not `connected` in time →
  `onStuck` → the hook tears the link down and **recreates it** (fresh offer,
  fresh ICE config), twice, then marks the peer `failed` honestly.
- **Politeness by stable uid** (`politeRole`): roles are compared over the
  per-tab uids, which survive reconnects — so one side holding a stale sid can
  no longer produce two polite peers waiting on each other.
- **Explicit `createOffer()/createAnswer()`** instead of the no-arg
  `setLocalDescription()`, which throws on older Safari and silently killed
  the handshake.
*Files:* `webrtc.js` (`politeRole`, watchdog, `onnegotiationneeded`,
`_handleSignal`), `useTunlion.js` (`onStuck` retry loop, `attemptsRef`).

## 9. Stale TURN credentials in long-lived tabs

**Symptom.** Pairs that need the relay (hard NATs, cellular) connect fine in a
fresh tab but fail in a tab that's been open a while.

**Problem.** `/api/config` was fetched **once at page load**, and TURN
credentials are expiry-stamped HMACs (`FIL_TURN_TTL`). A tab older than the
TTL hands dead credentials to every new connection → coturn rejects the
allocation → no relay candidates → relay-dependent pairs fail.

**Solution.** The hook now refreshes `/api/config` on **every reconnect** and
every **10 minutes** in the background, so new links always carry fresh
credentials; the server-side TTL was raised to 6h so long-running relayed
sessions can keep refreshing their allocations.
*Files:* `useTunlion.js` (status-handler + interval refresh), droplet `.env`
(`FIL_TURN_TTL`).

## 10. Zombie registry entries → duplicate peer tiles

**Symptom.** The same device shows up twice in the peer grid (same name, two
tiles), one of them never connecting.

**Problem.** Registry entries were only removed by the disconnect handler. An
api **restart/crash kills its sockets without running handlers**, orphaning
those entries in the Redis room hash for up to 24h — and every subsequent
`welcome` hands the zombies to clients as roster entries. Confirmed live: the
room hash contained `gentle-fox` under **two sids with the same tab-uid**, one
from a connection that died in an api recreate. A second, transient variant:
during a reconnect, `peer-joined` (new sid) can arrive before `peer-left` (old
sid), briefly duplicating the tile.

**Solution.** Two layers:
- **Server — liveness leases:** every connection holds a `tunlion:live:{sid}`
  key (`EX 120`) refreshed every 45s by the instance that owns it; `peers_in`
  returns only leased entries and **lazily deletes** dead ones the first time
  anyone looks. Orphans now disappear ≤2 minutes after any crash/restart.
- **Client — uid supersede:** a tab has exactly one live connection, so when a
  link arrives for a uid we already display under an older sid, the old
  link/tile is replaced immediately. This also erases the transient
  reconnect-window duplicate.
*Files:* `backend/signaling.py` (`LIVE_TTL`, `refresh`, lease-aware
`peers_in`, `_lease_loop`), `useTunlion.js` (`makeLink` supersede).

## 11. One-time pairing codes (feature)

**Why.** When auto-discovery can't see the person next to you (different
carriers, AP isolation, CGNAT splitting the room hash), the human channel is
the best signaling there is — *say a word across the table*. The old code rooms
were persistent: anyone who overheard the code could join it later.

**How.** `pair-create` registers a speakable code (`clever-lynx-63`, or a
chosen keyword — `SET NX` rejects collisions so strangers can't cross-pair) for
10 minutes. `pair-claim` consumes it **atomically** (`GETDEL`) — exactly one
claim, ever — verifies the creator's liveness lease, then sends the claimer
into the **creator's current room**. Pairing is ADDITIVE: the creator never
moves (nearby/auto-room detection stays intact), each code admits exactly one
person, and minting another code adds another person to the same group. An
overheard code is worthless the moment the real partner claims it; before
that, an attacker must out-race the person physically beside you.

**Bug fixed along the way:** the UI's create button passes the click event as
the first argument — `generateCode(keyword)` must type-guard (`typeof keyword
=== 'string'`) and the server's `_norm_code` must reject non-strings, else the
event object crashed the handler and the button silently did nothing.
*Files:* `backend/signaling.py` (`pair_create`/`pair_claim`, events),
`signaling.js`, `useTunlion.js`, `Tunlion.jsx` ('pair' scope).

## 12. Mobile file-picker backgrounding kills the peer link

**Symptom.** Android: tapping a peer tile opens the system file picker, which
backgrounds the tab; by the time a file is chosen, the other device (iPad)
has watched the connection die — and the chosen file's offer fires into a
dead link.

**Problem.** Two compounding rules tuned for the wrong case: (a) the
6-second disconnected-grace (#6) is right mid-transfer but far too short for
an IDLE link surviving a file-pick round-trip; (b) offers sent while the
channel is down are silently dropped, and the channel-open resume pass must
re-offer never-accepted sends, not only paused ones.

**Solution.** (a) Dynamic grace: 6 s while a transfer is active, 45 s when
idle. (b) The reconnect path (visibilitychange nudge -> rejoin -> uid
supersede -> onChannelOpen) re-offers every unfinished outgoing transfer for
that peer, including status 'offered'.
*Files:* `webrtc.js` (grace), `useTunlion.js` (onChannelOpen re-offer).

---

## 13. A normal reload left a stale session → no reconnect

**Symptom.** Reloading the tab did not connect, but closing it and opening a
new one worked. The old page's session was still present and the replacement
could not claim the device cleanly.

**Problem.** A reload keeps the per-tab `uid` (sessionStorage), so both the
old and new page briefly present the same device. Nothing on the relay let the
new page load take ownership; a late `pagehide`/`disconnect` from the old page
could race the new link. The local name was also generated in sessionStorage
and never shown, so a device could be `silken-chickadee` on the wire while the
UI hid it.

**Solution.**
- **TOKEN-keyed sessions, not uid ownership.** Every page load mints a fresh
  `gen`. On `join`/`sync` the relay keys the session by a server-minted opaque
  `token`; uid/name are display attributes only. A join without a token creates
  a NEW session and returns its token (welcome/sync ack, never a roster). A join
  with a token reattaches that token's session and may replace its previous sid.
  A retired generation for that token is refused. A uid alone is NEVER an
  ownership key: an unrelated client that knows the victim's uid but lacks its
  token gets an independent session and cannot evict, close, or join as the
  victim. A legacy no-token client also gets a new independent session.
  Capacity is on token records only: expired/closed records are evicted first;
  if every record is live a new tokenless session is refused with a capacity
  error instead of superseding a live sid. Eviction loses resume ability, not
  access. gen/sid/token live in one record with one sliding 24h TTL (one Redis
  hash updated by atomic Lua), and retired generations are bounded per token
  with a global 24h TTL/cap. The token is a bearer in localStorage: not rotated,
  no revocation endpoint, expires 24h after the last successful claim.
- **Synchronous pagehide, not unload-dependent.** `pagehide` closes local
  `RTCPeerConnection`s, stops link/session/pairing/config timers, and beacons
  `POST /api/session/close` with `{token, gen}`. The endpoint requires the
  token, honors the configured origin allowlist, and is rate-limited; it only
  acts for that token's current generation, so a late close cannot drop a newer
  session. `pageshow` always revalidates/reconnects; a BFCache
  restore (or any pagehide/pageshow return) rotates generation first.
  `visibilitychange` alone does NOT tear down (backgrounding an iPad is
  normal), and ICE/presence timeouts remain the fallback if `pagehide` never
  fires. A superseded tab stays suspended across `pageshow`/BFCache/storage
  events; only an explicit full reload may take over again.
- **Visible, editable identity.** The device name lives in localStorage (with
  migration from the old per-tab name), is shown on Home/header and in a name
  field with a generated default. Renaming sends the SAME `{uid, gen}` and the
  relay emits `peer-updated`, so peers relabel one row; open tabs also relabel
  from the `storage` event. Names are labels, not identities -- duplicates are
  allowed, and ownership/pairing never depends on the name. No duplicate
  pairing or peer tile. Clearing site data is never part of the recovery path.
  Optional Firebase signaling has no relay-side token/rename/supersede path;
  its Firestore presence remains add/remove only.

*Files:* `frontend/src/lib/identity.js`, `frontend/src/lib/useTunlion.js`,
`frontend/src/lib/session.js`, `frontend/src/lib/signaling.js`,
`frontend/src/ui/Tunlion.jsx`, `backend/signaling.py`, `backend/app.py`.
*Gates:* `frontend/tests/peer-identity.spec.cjs`,
`frontend/tests/peer-reload.spec.cjs`,
`backend/tests/test_session_generation.py`.

## 14. A silently dead polling page stayed a ghost tile for about 85 s

**Symptom.** A page on the socket.io long-polling transport (a network that
holds or blocks websockets) that dies without `pagehide` (a killed renderer, a
mobile OS kill) stayed on every other peer as a "connecting" tile for about
85 s. Websocket pages that die the same way leave at once.

**Problem.** A websocket death ends the engine.io socket on TCP close. A
polling client has no connection of its own to close: its last long-poll GET
sits in the relay until the next ping (25 s), the answer goes nowhere, and only
the ping timeout (60 s) ends the socket. Until then `_eio_alive` called it open
and the lease loop kept refreshing it. The ping values are long on purpose
(slow, high-RTT and backgrounded clients reconnect-stormed at 10 s/5 s), so
they could not simply be shortened.

**Solution.** A separate rule for polling sockets, in the relay
(`signaling.PollWatch`, a WSGI middleware that records each polling GET, plus a
1 s loop). A live engine.io-client always holds one long-poll and sends the next
from the previous one's load callback, not from a timer, so CPU throttling and
background-tab timer throttling do not delay it. The loop answers a GET held
`FIL_POLL_HOLD_S` (2 s) with a NOOP packet, and closes a polling socket that
then has no GET for `FIL_POLL_GRACE_S` (7 s): a live client re-polls within one
round trip, a dead one never does. Closing runs the normal disconnect path, so
the room gets `peer-left`. The ping timeout is unchanged and still covers
websocket half-opens. Upgraded sockets are forgotten; a socket mid-upgrade is
left alone (the client pauses polling then). `FIL_POLL_GRACE_S=0` turns the
rule off.

**Bounds, measured** (`frontend/tests/polling-liveness.spec.cjs`, production
25/60 ping, eventlet): a crashed or silently closed polling page leaves the
other peer in 8.1 to 8.9 s over 12 runs (84 s and 114 s on the old relay). A
polling page at 20x CPU throttling, hidden, never drops: 60 s at 2.5 s added
latency, and 30 s each at 4, 5, 6 and 8 s. Three 3 s offline flaps never
remove the tile (the reconnect supersedes by uid).

**A frozen page is not a dead one.** On Android, choosing a file opens the
system picker; the tab goes to the background and the OS may freeze it, and a
frozen page cannot poll. The 7 s rule alone dropped such a page within seconds
(measured: a 10 s freeze took the tile away for 61 s and the picked file never
arrived), where the ping timeout had let it ride out up to about 60 s. So the
page says it is going out of sight: `away {on: true}` on the signaling socket
at the file-input click (capture phase, while the page still runs) and on
`visibilitychange` hidden, `away {on: false}` when it is visible again. The
relay keys the hint by the socket it arrived on (`request.sid`), so it can only
lengthen that socket's own grace, to `FIL_POLL_AWAY_S` (180 s); inside it the
ping timeout is again what ends a page that never comes back, exactly as
before. A visible page that stops polling (a real crash) still drops in about
8 s. With the hint, a page frozen 10, 30 or 60 s behind the picker keeps its
tile, its sid and its WebRTC link, and the picked file arrives in under 0.5 s;
a 120 s freeze is dropped by the ping timeout and rejoins, the same as before
this rule. Opening the picker sends no session-close and no `leave` on either
transport.

What is left of the trade: a polling client that is visible and whose next
GET takes longer than the grace to reach the relay (a round trip over about
7 s) is closed and reconnects, where before it rode out up to 85 s.

The freeze in the gate is the debugger's pause, not
`Page.setWebLifecycleState frozen`: Chrome silently ignores that on a page it
considers visible, and every page in a Playwright browser is one (measured:
timers and long-polls ran on through the "frozen" state). The gate fails if
the frozen page sends a long-poll.

*Files:* `backend/signaling.py` (`PollWatch`, `poll_check`, the poll loop and
the `away` handler in `register`), `backend/app.py`,
`frontend/src/lib/signaling.js` (`away`), `frontend/src/lib/useTunlion.js`
(`onVisibility`, `onPickerClick`).
*Gates:* `backend/tests/test_poll_liveness.py`,
`frontend/tests/polling-liveness.spec.cjs`.

## Testing

`PeerLink`'s logic is exercised against a mock `RTCPeerConnection` (see the test
run in the PR that introduced these fixes): concurrent-transfer framing
roundtrip with interleaved chunks (#4), candidate buffering + ordering (#2),
impolite glare-ignore (#1), fail-on-drop (#5), and the closed-guard (#3). Full
end-to-end negotiation still needs two real browsers — these state-machine
fixes are unit-tested where they can be, and verified live by reconnect/transfer
testing on two devices.

## Transfer resume (feature, builds on the fixes above)

**Problem.** P2P transfers die with the connection. After the resilience fixes
a drop re-paired automatically, but a half-sent video still restarted from 0 —
on flaky mobile paths that can mean never finishing.

**Solution.** Three pieces:
1. **Stable identity** — each tab mints a session `uid` carried through
   `join`/`welcome`/`peer-joined`, so peers recognize "same device, new
   connection" after a drop (socket ids change every reconnect).
2. **State that outlives the link** — partial receive buffers and unfinished
   outgoing `File`s live in hook-owned stores (`partialsRef`/`outgoingRef`),
   not in the per-connection `PeerLink`. `_failActive` marks such transfers
   `paused` instead of `failed`.
3. **Offset handshake** — when a new channel opens to a peer whose `uid`
   matches a paused send, the sender re-offers with `resume: true`; the
   receiver (which already accepted once) auto-accepts with
   `offset: bytesReceived`; the sender streams `file.slice(offset…)`. Chunk
   framing (#4) keys everything by transfer id, so resumed bytes land in the
   same buffer.

**Limit:** resume requires the sender's *tab* to still be alive — a page reload
revokes the browser's file handle, and there is nothing to stream from. That's
a platform boundary (no filesystem access), not a design choice.

## Known remaining limits (by design)

- **In-flight transfers now pause + resume** across drops (above) when the
  sender's tab survives; a sender reload still loses the transfer — the browser
  revokes file handles on navigation.
- **Multi-instance API scaling** needs the Redis registry (already wired); the
  glare fix (#1) is what makes that safe.
- **Session ownership state is relay state.** If the relay loses its state
  (restart without Redis), existing tokens are unknown: each client starts a
  new independent session. A uid alone never grants access to another session
  in any window. With Redis the 24h token/session TTL state and atomic Lua
  survive restarts.
- **Optional Firebase signaling** remains add/remove presence: it does not
  implement generation/token supersede, in-place rename, or relay-side close.
  Those paths are Socket.IO-only.
