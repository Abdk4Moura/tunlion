# Cloudflare duplicate of the signaling backend

Status: built and drilled on staging; not in front of production. The VPS
(`deploy/`: Flask-SocketIO under gunicorn/eventlet, cloudflared, coturn) stays
the primary. Cloudflare is a hot duplicate that takes over when the VPS is
down and hands back when it returns. Code: `edge/signal/`.

## Shape

```
 client ──► router Worker (route on the API hostname)
              │  origin up:   proxy to ORIGIN_URL (the VPS tunnel), as today
              │  origin down: serve here
              │                 REST (/api/config, /api/room, ...) in the Worker
              │                 /socket.io + /api/session/close in SignalHub
              │
              ├─ HealthState (Durable Object): probes ORIGIN_URL/health,
              │  hysteresis, publishes the up/down flag to KV on a flip
              └─ Cron Trigger, every minute: HealthState.tick()
```

One script, `edge/signal/src/index.ts`, plays both roles. Without
`ORIGIN_URL` it is a complete signaling backend (the staging targets are
this); with it, it is the router.

### SignalHub: the port of `backend/signaling.py`

`edge/signal/src/hub.ts` is engine.io v4 (websocket, HTTP long-polling, and
the polling to websocket upgrade), socket.io v5 framing (CONNECT, EVENT,
ACK, DISCONNECT), and the relay's event handlers in the same order and under
the same names as `register()`. `registry.ts` is `_MemRegistry` method for
method. Every constant the two must agree on is in `policy.ts`, each naming
its Python twin.

One hub, not one object per room or channel. The Python relay is a single
process and its semantics rest on that: a socket's room and its presence
channels are independent (`known-peer` crosses rooms), `signal` may go to any
sid that shares a room or a channel, and nameplates and session tokens are
global. Splitting by room would need a gateway object in front of every
socket fanning each event out to several objects: a new protocol surface and
several billed requests per event. A single object carries up to 32k
websockets and roughly a thousand small events a second, far past launch
traffic; the split is the change to make when one object stops being enough,
not before.

State and hibernation. The hub uses the WebSocket Hibernation API. A
hibernated or evicted object keeps its sockets but loses its heap, so:

- per-socket identity (engine.io id, socket.io sid, namespace state, client
  IP, the #592 legacy session) rides each websocket's attachment;
- sessions, retired generations, room membership, channel subscriptions and
  nameplates are written through to the object's SQLite, and memory is the
  read path (reloaded on the first use after a wake);
- a refresh-only claim (the 30 s daemon sync) does not write: its sliding
  expiry is held in memory and written once it drifts 6 hours
  (`FIL_SESSION_PERSIST_S`), which is 4 session rows a day for an always-on
  device instead of 48;
- liveness is the transport itself (an open websocket or a live polling
  session), the same ground truth `_eio_alive` gives the Python lease loop.
  A row whose transport vanished without a close event is cleaned up the
  next time anyone looks at its room, and by a five-minute sweep, with the
  `peer-left` the room would have heard. Capacity eviction uses the same
  authority: a websocket must be OPEN, accepted, past its upgrade probe and
  namespace-connected; a polling session must have made a request inside the
  engine.io dead window. The stored `last_seen` is only a refresh hint and is
  not used to decide that a live token is dead, because after hibernation it
  can be hours older than the open websocket. A capacity claim frees one
  non-live slot, not a whole dead backlog in one request.

Session validity versus physical rows. A token's authority is its persisted
`exp`, and every persisted refresh is `write_time + SESSION_TTL`. A write is
never later than the last real claim, so the token never resumes after the
Python cutoff `last_claim + 24 h`. The wider spacing can only make it expire
earlier after an eviction: with 6 h spacing the floor is 18 h, and the tests
pin both the never-later and 18 h-floor cases against the old 30 min spacing.
The in-memory `last_seen`/`exp` and the durable `stored_last_seen` are kept
distinct; only the latter decides when a refresh is written.

Pruning is different from validity. It is claim-triggered, at most once per
`PRUNE_INTERVAL` (30 s) while claims keep arriving, and each pass deletes at
most `FIL_SESSION_PRUNE_BATCH` expired sessions (default 256) and the same
number of expired retired tombstones. The total number of deletes does not
change; batching only spreads them. A dead row can therefore remain
indefinitely if no later claim arrives: there is no scheduled sweep and no
`TTL + constant` physical-retention claim. Capacity is separate again: one
expired row is found directly through the `sessions_exp` index, otherwise a
keyset page of at most `FIL_CAPACITY_SCAN` rows (default 64) advances an
in-memory `(exp, rowid)` cursor and deletes only the one-slot deficit. A page
with no dead row fails closed and the next claim continues after it, wrapping
at the end. A closed but unexpired row beyond the page can delay a new
session until cursor progress or expiry; that availability tradeoff is
deliberate. The existing over-cap `capRetired()` path stays unbounded because
bounding it would weaken the tombstone cap; it normally removes one row.

Polling sessions live in memory only: if the object is evicted mid-session,
the client gets `Session ID unknown` and reconnects, as it would after a
Python restart.

Polling liveness mirrors `signaling.PollWatch` from `fix/polling-liveness`
(not yet on main when this was written): a GET held `FIL_POLL_HOLD_S` (2 s)
is answered with a NOOP so a live client re-polls at once, and a polling
session with no GET for `FIL_POLL_GRACE_S` (7 s) is closed as if its ping had
timed out, so a silently dead tab leaves its room in about 8 s instead of
85 s. Same env names and defaults, `FIL_POLL_GRACE_S=0` turns it off. The
cost: a polling client makes a request every ~2 s instead of every 25 s
(table below).

A page hidden on purpose says so with socket.io's `away` event (#608). Only
the socket the event arrived on is affected, and only one that has already
polled: `{"on": true}` extends that session's no-GET limit to
`FIL_POLL_AWAY_S` (180 s), anything else clears it, and a websocket session
accepts and ignores it. The 25 s / 60 s ping timeout still bounds a frozen
page, so the hint only bridges a file picker or a frozen background tab. TEL
`poll-lapsed` carries the socket.io `sid` alongside the engine.io id.

`PollLiveness` has six tests: the silent death, the slow poller inside the
grace, and four `away` cases (own socket only, off restores, only `true`
sets it, a websocket ignores it). The class is gated by
`CONFORMANCE_POLL_LIVENESS=1` until the Python side merges; then drop the
gate.

engine.io pings: the hub's alarm sends `2` every `FIL_PING_INTERVAL` while
any socket is open and closes a transport silent for interval plus timeout.
Defaults are production's 25 s / 60 s (`deploy/docker-compose.yml`), not the
app's 5 s / 10 s: every pong is a billed inbound message here.

Ping batching. Cloudflare's lifecycle rules make any pending `setTimeout`
prevent hibernation, so the old path that spread one alarm's pings over 25
one-second timers kept the single hub duration-billed for the whole interval.
`heartbeat.ts` now sends one batch when the population is at or below
`FIL_PING_SLICE_AT` (default 40) and keeps the bounded slices above it. The
default is the largest population measured in this change, not a claim about
the boundary: the 2026-10-29 data only shows one batch at 1,000 passing and
2,000 shedding 8%. Raise the cap only with a bounded burst.

Measured on `tunlion-signal-loadtest`, both runs 40 devices for 460 s with no
application sync (W1 "idle heartbeat"), values from `durableObjectsPeriodicGroups`
per-minute buckets. "Before" is `49f2dba72`, "after" is `cc441eae2` with the
then-default cap 512 (the code default is now 40):

| W1 | object-active s | duty | apportioned s/device-hour | requests (actual) | rows written | client drops |
|---|---|---|---|---|---|---|
| before | 410.5 | 89% | 80.3 | 965 | 498 | 0 (4 lost at stop) |
| after | 2.1 | 0.46% | 0.41 | ~1,038 | 360 | 0 |

The active seconds are the object's wall clock divided over N device-hours,
not per-device billed seconds; Cloudflare bills the object. Requests are the
analytics counts (actual messages and connections), not the 20:1 billing
ratio. Batching does not reduce requests or rows, and this sample did not:
connect-path writes dominate a short run. A second workload, W2, kept the
real 30 s daemon sync: after was 2,332 requests, 597 rows and 2.3 active s
with one client transport drop. A complete before W2 run is still missing
(the shared worker lease expired mid-run), so no before/after claim is made for it.

The first claim after an idle day can write far more than one connect: in this
measurement the 19:30 minute wrote 14,337 rows once, then zero rows in every
later minute despite alarms. That was `pruneSessions` deleting the ~16k
session records the 2026-10-29 load test had left to expire after 24 h
(`registry.ts`, `claimSession` -> `pruneSessions`), not schema creation or a
version migration. Batching those deletes would smooth the burst but not
reduce the total rows; any change must keep expired rows from filling
capacity or blocking claims.

The `setAlarm()` row-write footnote in Cloudflare's pricing docs did not show
up in these metrics: idle minutes with two or three alarm requests recorded
zero rows written. Treat any alarm-row saving as unmeasured until a dedicated
test shows it.

Engine.io ids minted by the hub start with `cf.` and so do its session
tokens. Python's are base64url and never contain a dot. The router uses the
prefix to keep every request of a session on the backend that minted it.

### The router and stickiness

Both peers of a room must land on the same backend, because the two backends
share no state. Three rules give that (`index.ts`):

1. A new engine.io session goes where the one global flag says.
2. A request for an existing session follows the backend that minted its
   sid (`cf.` prefix). A polling session is never split mid-life; a
   `/api/session/close` beacon follows its token's prefix.
3. On failback the hub closes every transport without a socket.io
   DISCONNECT (which would stop socket.io-client from reconnecting), so each
   client reconnects and follows rule 1 home. The drain waits until every
   router has seen the flip, and for ten minutes afterwards each cron minute
   sweeps any straggler off the hub.

When the origin is down its sockets are already gone, so rule 1 alone moves
everyone over.

Stateless REST (`/api/config`, `/api/room`, `/api/room/code`, `/api/whoami`,
`/api/health`, `/health`) is answered by the Worker itself whenever a
proxied request fails, before any flip: the answers are identical given the
same `FIL_SECRET` and TURN secrets, so a page load never waits on the
hysteresis. Sockets are not failed over per request: splitting a room on
one failed request is worse than a short retry.

Every router response carries `x-tunlion-backend: origin|cf`.
`GET /__router/status` shows the health state machine (phase, streaks, last
probe, the last 20 transitions). No secrets.

### Health, with hysteresis (`health.ts`)

```
up --probe fails, or the router reports a failed proxy--> suspect
suspect --3 consecutive failed probes, 10 s apart--> down
suspect --one good probe--> up
down --3 consecutive good probes, 20 s apart, and >= 60 s down--> up, then drain
```

A probe is `GET ORIGIN_URL/health`, 5 s timeout, healthy only on 200 with
`{"ok": true}`. The cron probes once a minute; while suspect or down the
object's own alarm probes on the faster cadence. Thresholds are env vars
(`HEALTH_*` in `shared.ts`). The router counts only "the origin did not
answer" statuses (502, 504, 52x, 530) as failures, never 503, which the
Python app returns for its SPA fallback.

The decision lives in HealthState, a Durable Object, so it is the same answer
everywhere. The router does not ask it per request: HealthState writes the
flag to KV on a flip, and the router reads it from isolate memory (5 s),
then its colo's Cache API (15 s), then KV (30 s edge cache). Reading the
object directly would keep it awake all day, about 11,000 GB-s, which with
the hub's own duration is over the Free plan's 13,000. Without the `FLAGS`
KV binding the router reads HealthState directly (faster to flip, costs
duration). The drain delay follows: 75 s after a failback with KV, 8 s
without.

### ICE servers

`/api/config` hands out the same list as `config.public_config()`: Google
STUN, coturn REST credentials (HMAC-SHA1 of the expiry with
`FIL_TURN_SECRET`, Worker secret), and Cloudflare Realtime TURN credentials
minted server-side with `FIL_CF_TURN_KEY_ID` / `FIL_CF_TURN_API_TOKEN`,
filtered the same way (TURN only, no port 53), cached per isolate for half
the TTL. `FIL_ICE_SERVERS` overrides, as in Python.

## Mirroring a Python change

| Python | Port |
|---|---|
| a constant in `_MemRegistry` / `register()` | `edge/signal/src/policy.ts` |
| `_MemRegistry.<method>` | `Registry.<camelCase method>` in `registry.ts` |
| an event handler `on_<x>` | `SignalHub.on<X>` in `hub.ts` |
| `_claim_session`, `_do_join`, `_do_leave` | `claimSession`, `doJoin`, `doLeave` |
| `close_session` | `SignalHub.closeSession` |
| `config.public_config` and TURN | `config.ts` |
| engine.io ping / payload settings | env `FIL_PING_*`, `FIL_MAX_DECODE_PACKETS` |

Then add or extend a test in `backend/conformance/` and run it against both.

Known differences, all deliberate:

- Python's in-memory nameplates never expire (the Redis twin does, with
  `EX`); the hub expires them after 10 minutes, as CONTRACT.md says.
- Python's `_do_join` drops the sid from `local_sids`, so its lease is kept
  alive only by later syncs; the hub's liveness is the transport, always.
- Python's capacity `_session_live` also requires `last_seen` inside 120 s;
  the hub deliberately uses the open transport and the unexpired record
  instead, because its `last_seen` is a throttled refresh hint that can be
  stale after hibernation. Capacity frees one dead slot per new claim in both.
- Python's in-memory session expires at exactly `last_claim + 24 h`. The hub's
  persisted row can expire up to `FIL_SESSION_PERSIST_S` earlier after an
  eviction (18 h floor at 6 h spacing), never later, and its expired rows are
  pruned only when a later claim runs, not by a scheduler. `FIL_SESSION_PERSIST_S=1800`
  restores the old 30 min spacing and a 23.5 h floor if needed.
- After an eviction a session's stored expiry can be up to 30 minutes older
  than in memory (the write-through slack). It still lasts a day after use.

## Conformance suite

`backend/conformance/` runs the same tests over the real wire against any
base URL: REST shapes, engine.io facts (open packet, unknown sid, version,
batched POSTs), the Rust CLI's exact framing on a bare websocket (`40`,
`42[...]`, `42<id>[...]`, the `synced` event, #592 session reuse), rooms and
`welcome`/`peer-joined`/`peer-left`, #594 duplicate join, the sync digest,
generations, supersede and retire, the close beacon, signal relay and its
refusals, presence channels, and v2 pairing. `test_limits.py` runs against an
instance with small budgets: the per-socket and per-IP claim budget with the
#592 refresh exemption, the pair-claim budget, the close budget.

```
CONFORMANCE_URL=<base> CONFORMANCE_TRANSPORT=websocket|polling|upgrade \
  python -m unittest backend.conformance.test_conformance -v
CONFORMANCE_URL=<small-budget base> python -m unittest backend.conformance.test_limits -v
```

Results at the head of `feat/cf-signaling` on 2026-10-28, evidence in
`/root/pairing-ux/evidence/cf-signal/final-3a420bb1/`:

- #608's relay `a5244008`: 48/48 with `CONFORMANCE_POLL_LIVENESS=1` on
  websocket, polling and upgrade, so the `away` cases pass on the Python
  side too.
- staging DO: 48/48 with liveness on websocket, polling and upgrade, plus
  3/3 limits on the small-budget instance.
- `PollLiveness` alone: green in two consecutive runs and in the transport
  rerun; the slow-poller case also 4/4 on its own. One earlier run lost a
  `peer-joined` to a network stall and one later run lapsed the slow poller
  once; the same test then passed 4/4 alone, so the suite keeps its bounds.
  This deployment did not stream Durable Object console logs to
  `wrangler tail`, so the wire assertions, not TEL counts, are the evidence.

Browsers through the staging DO, from the CI worker: #608's
`polling-liveness-remote.cjs` with `PL_ONLY=picker,killed`, against a
frontend built from `a5244008` with `VITE_TUNLION_API` set to the staging
hub:

- picker, 30 s frozen behind the file chooser, on both transports: no tile
  gap, same sid, the observer's link kept, no departure, and the picked
  256 KiB file arrived (54 to 214 ms).
- killed, then the same URL reopened: one row on the observer for the
  device, and a send worked (48 to 269 ms).
- One earlier websocket picker run lost the socket for about 20 s and the
  page came back on a new sid. It then passed twice in a row; the CI
  worker's route to Cloudflare drops about 3% of requests, and that run
  recorded no `session-close` and no `leave`, so it was a transport drop,
  not a picker departure.

The Python side needs `FIL_CLAIM_LIMIT>=200 FIL_PAIR_CREATE_LIMIT>=800` (every
client shares one address); the small-budget run uses
`FIL_SESSION_CLAIM_LIMIT=8 FIL_CLAIM_LIMIT=3 FIL_CLOSE_LIMIT=4`.

## Failover drill (staging, 2026-10-28)

`edge/signal/test/failover_drill.py`: four clients in one room through the
router (two socket.io on websocket, one socket.io on long-polling, one with
the Rust CLI's raw framing), then SIGKILL the origin, wait until every client
is on the hub AND sees every other in its roster, restart the origin, wait
until every client is home and sees every other again. The origin was a
throwaway Python relay (this branch's `backend/`, `FIL_TRUSTED_PROXIES=*`)
behind a throwaway same-zone tunnel; the router was on a same-zone staging
route. Evidence: `/root/pairing-ux/evidence/cf-signal/drill-*`.

| run | flag path | kill -> down flip | kill -> all on hub, rosters whole | restart -> up flip | restart -> all home |
|---|---|---|---|---|---|
| drill-4 | KV + Cache API (Free) | 22.3 s | 36.7 s | 49.2 s | 125.4 s |
| drill-5 | HealthState direct | 24.1 s | 30.9 s | 57.5 s | 66.7 s |

Reading it: detection is the router's passive report (first failed proxy)
plus three probes 10 s apart. Failback waits for 60 s down and three good
probes 20 s apart, then the drain: 75 s behind KV, 8 s behind the object.
Clients moved within about 1.5 s of each drain. Tighter numbers are a matter
of the `HEALTH_*` knobs; the hysteresis is there so one slow `/health` does
not split rooms.

What the drills found and fixed: drill-2 showed the long-polling client
never coming home after a failback. The hub ended polling sessions with an
engine.io CLOSE packet, which python-socketio takes as final. A drained or
lapsed polling session now answers 400 `Session ID unknown`, exactly what a
restarted Python server answers, and every client reconnects from that
(drill-3 onwards). The drills also confirmed `CF-Connecting-IP` survives the
same-zone hop: `/api/whoami` through the router returned the caller's
address from the Python origin.

To rerun: recreate a throwaway tunnel and two DNS names in the zone, set
`ORIGIN_URL`, the route and a KV id in `[env.drill]` (the ones committed were
deleted after the drill), `wrangler deploy --env drill`, and run the script
with `ROUTER`, `ORIGIN_CMD_KILL`, `ORIGIN_CMD_START`. Delete the staging
router afterwards: its cron keeps probing and spends free-tier requests.

## Hub load test (staging, 2026-10-29)

`edge/signal/test/hub_loadgen.py` drives `tunlion up`-shaped devices over
the CLI's raw framing (no socket.io library), and `hub-loadtest.yml`
(workflow_dispatch) runs it as a fleet of GitHub runners on one wall-clock
schedule: the idle group ramps the steps, then holds the last one while the
churn group runs pairing bursts on top. Each device joins a solo room,
subscribes to two pair channels, and every 20 s sends a full `sync`, with a
room-null heartbeat `sync` 10 s after it; with the 25 s ping that is 0.14
messages a second per device. A pairing is the VPS test's: create, claim,
join, offer and answer (~3 KB each), 4 ICE candidates each way. Target:
`tunlion-signal-loadtest` (`[env.loadtest]`, rate limits lifted as in the
VPS test). Nothing ran on the VPS beyond 20-device smokes. Raw rows and the
Durable Object analytics are in
`/root/pairing-ux/evidence/cf-signal/loadtest-20261029/`.

Run 1 (run 40874481363, the hub as at `3a420bb1`, one alarm pinging every socket),
4 idle runners and 2 churn runners. Latencies include about 70 ms of round
trip from the runners to the object (the p50 floor):

| devices | connects ok / failed | alive at end | dropped | sync p50 / p99 / max ms | heartbeat p99 ms | client msgs/s |
|---|---|---|---|---|---|---|
| 500 | 500 / 0 | 500 | 0 | 71 / 96 / 316 | 100 | 71 |
| 1,000 | 1,000 / 0 | 1,000 | 0 | 72 / 152 / 435 | 146 | 141 |
| 2,000 | 1,999 / 1 | 1,832 | 167 (abnormal close) | 72 / 180 / 1,581 | 331 | 260 |
| 4,000 | 3,999 / 1 | 0 | 3,832 (518 with 1013, the rest abnormal) | 73 / 743 / 1,045 | 749 | collapsed |

Durable Object analytics for the same minutes: at most 8.4 s of CPU a
minute (14% of one core), at most 35 MB of memory, no exceededCpu, no
exceededMemory. The hub was not short of CPU. What closed the population is
the ping: one alarm sent "2" to every socket at once, so every pong came
back inside one round trip, a burst of N inbound messages queued at a single
object. At 1,000 that passed, at 2,000 it shed 8%, and at 4,000 the object
closed everyone, 518 of them with 1013 (try again later). The VPS holds
4,000 at p99 759 ms because python-engineio pings each socket on its own
timer.

Pairing churn, which in run 1 ran on an emptied hub because the idle
population had already collapsed:

| pairs/s | ok / started | signal p50 / p99 ms | setup p50 / p99 ms |
|---|---|---|---|
| 20 | 600 / 600 | 90 / 110 | 841 / 1,023 |
| 40 | 1,200 / 1,200 | 103 / 192 | 909 / 1,249 |
| 60 | 1,800 / 1,800 | 155 / 269 | 1,262 / 1,826 |
| 80 | 841 / 2,400 (connect timeouts) | 191 / 361 | 1,602 / 3,186 |

The 80 pairs/s step straddled the moment the account crossed the Free
rows-written cap (below), so it does not show the hub's churn ceiling.

The fix (`e4d7ad53`): the alarm still fires once per ping interval, but it
pings the sockets in 25 slices, one a second, on in-memory timers; each
socket is still checked and pinged once per interval, and it is still one
billed alarm per interval. Conformance (all three transports and limits)
passes with it in CI.

Run 2 (run 40878097639, the fix deployed) measured nothing: every connect
got 500, because the account had crossed the Free plan's 100k rows written
per day in Durable Objects ("Exceeded allowed rows written in Durable
Objects free tier", from `wrangler tail`). That cap is account wide, so the
staging and limits workers answer 1101 until 00:00 UTC as well. Rerun the
same dispatch after the reset, or once Workers Paid is active:

```
gh workflow run hub-loadtest.yml --ref feat/cf-signaling -f steps=500,1000,2000,4000 \
  -f idle_shards=4 -f slot=180 -f ramp=60 -f final_hold=240 -f rates=20,40,60 \
  -f churn_shards=2 -f dur=30 -f churn_delay=20
```

That is about 36k rows for the idle ramp and 27k for the churn, inside one
Free day with nothing else running.

Rows written, measured: about 9 rows per device connect (join, session,
two channels, first sync) and about 15 per pairing. 100k rows a day is
therefore about 11,000 device connects or 6,600 pairings, and a failover of
4,000 daemons spends about 36k rows just reconnecting.

## Free plan fit

Free plan limits (Workers and Durable Objects, per day): 100k Worker
requests, 100k Durable Object requests, 13,000 GB-s duration, 5M SQLite rows
read, 100k rows written; KV 100k reads, 1k writes. An incoming websocket
message bills as 1/20 of a request; outgoing messages are free.

Per-client cost on the hub (measured shapes, 25 s pings):

| client | inbound messages | hub requests | Worker requests |
|---|---|---|---|
| CLI daemon, always on (pong every 25 s + sync every 30 s) | ~6,300/day | ~320/day + 1 per reconnect | 1 per reconnect |
| browser tab, per open hour (pong + 30 s session sync) | ~264/h | ~13/h + 1 per load | ~3 per load (config, room, socket) |
| browser on long-polling, per hour (PollWatch 2 s hold) | n/a | ~2,000/h | ~2,000/h |
| the same with `FIL_POLL_GRACE_S=0` (25 s holds) | n/a | ~410/h | ~410/h |

Duration: batching pings at or below `FIL_PING_SLICE_AT` lets the hub
hibernate between alarms, so duration is handler time rather than wall clock
(W1 above: 2.1 s for 460 s with 40 devices). Above the cap the old slicing
still keeps it awake for the interval, and one legacy socket above the cap is
enough; the default of 40 is deliberately conservative, so this is not a
claim for a large always-on population. At the old continuous rate the one
hub is about 0.125 GB x 86,400 s = 10,800 GB-s/day, inside 13,000.
HealthState wakes only for probes.

Rows: a refresh writes nothing until `FIL_SESSION_PERSIST_S` (6 hours) has
passed, so an always-on daemon is about 4 session rows a day instead of 48;
at 4,000 always-on devices that is 16k rather than 192k rows a day. Each
connect measured 9 rows (15 in one run with an extra sync) and a pairing about
15 ("Hub load test" above). A first claim after a stale day can still find a
backlog, but it now deletes at most `FIL_SESSION_PRUNE_BATCH` (256) expired
sessions and retired rows per pass, so the 14,337-row burst above becomes
about 224 batches over later claims; the total rows are unchanged and a row can
remain longer if claims stop. Local SQLite at 50k sessions measured inclusive of the hub cascade, per
batch: 64 -> 193 rows written and about 118 ms, 256 -> 769 rows and about
466 ms, 1,024 -> 3,073 rows and about 1.8 s. The 64 default is chosen for the
worst-case per-claim burst, not throughput. A capacity page of 64 measured
about 130 rows read and 1.6 ms, with no writes when every row is live. These
are local counts, not Cloudflare billed analytics. Reads otherwise come from
memory, a few rows per claim.

What that means:

- Normal operation (VPS up). Only the router runs: one Worker request per
  HTTP request (a websocket is one, its messages ride through unbilled), plus
  about 1,440 probes a day. Page loads (about 3 each), websocket connects and
  any polling traffic share the 100k. That is roughly 25k page loads a day
  with daemon reconnects on top. Configure the route to fail OPEN (below):
  over the daily cap, requests then skip the Worker and reach the VPS
  directly, so the cap can disable failover for the rest of the day but
  never take the API down.
- Failover. The hub's 100k requests cover about 300 always-on daemons for a
  whole day, or 3,000 daemons for about 2.5 hours. At 10,000 devices a
  failover spends the Free daily budget in under an hour, after which the
  hub refuses new work until 00:00 UTC.

So Free covers launch traffic for short outages only. Workers Paid ($5/month,
10M Worker requests and 1M Durable Object requests a month included, then
$0.30/M and $0.15/M) removes the cliff. Estimates for the owner's
10k-device and 50k-device scenarios, if the hub carried everyone all month:
about 96M hub requests/month at 10k devices (~$14) and ~480M at 50k (~$72),
plus $5. If it only carries outages, which is the design, it is the $5 base
plus cents per outage-hour; the earlier ~$7/month at 10k and ~$25/month at
50k sit between the two. Nothing has been bought.

## Putting it in front of production

Not done; for the owner, after review. Order matters: the router must be able
to serve everything before the route sends it anything.

1. Secrets, from stdin only, on the production script:
   `wrangler secret put FIL_SECRET` (the VPS value, or `/api/room` diverges),
   `FIL_TURN_SECRET` (coturn's `static-auth-secret`),
   `FIL_CF_TURN_API_TOKEN`. Vars in `wrangler.toml` `[vars]`: `FIL_TURN_HOST`
   and `FIL_TURN_TTL` (same as `deploy/.env`), `FIL_CF_TURN_KEY_ID`,
   `FIL_CORS_ORIGINS` (same as the VPS), `ORIGIN_URL`.
2. An origin hostname that does not go through the router:
   add `vps-api.tunlion.autumated.com` as a second public hostname on the
   existing tunnel (ingress `http://api:8000`, as `api.tunlion`), in the same
   zone. `ORIGIN_URL=https://vps-api.tunlion.autumated.com`. Same zone is
   required: a same-zone subrequest keeps the client's `CF-Connecting-IP`,
   which the VPS uses for rate limits and `/api/room` (verified on staging:
   `/api/whoami` through the router returned the caller's address).
3. KV for the flag: `wrangler kv namespace create tunlion-signal-flags`,
   bind it as `FLAGS` in the top-level config. Add the cron
   `triggers = { crons = ["* * * * *"] }`.
4. Deploy without a route, then check the hub directly:
   `wrangler deploy`, temporarily with `workers_dev = true`, and run the
   conformance suite and `edge/signal/test/browser-transfer.cjs` against the
   workers.dev URL. `GET /__router/status` shows the probe going green.
5. Add the route `api.tunlion.autumated.com/*` (zone autumated.com) to the
   script and, in the dashboard, set the route's request-limit failure mode
   to Fail open. Repeat for `api.filament.autumated.com/*` if that hostname
   should be covered too. DNS stays as it is: the CNAME to the tunnel keeps
   serving whatever the Worker does not.
6. Watch: `x-tunlion-backend: origin` on every response,
   `wrangler tail` for `health-*` TEL lines. Point the external monitor at
   `vps-api.tunlion.autumated.com/health` (the API hostname now answers 200
   from Cloudflare while the VPS is down).
7. Rollback: remove the route (traffic goes straight to the tunnel again).
   `ROUTER_MODE=origin` keeps the router but disables failover;
   `ROUTER_MODE=cf` sends everything to the hub.
