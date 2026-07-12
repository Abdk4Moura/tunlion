# Transport lifecycle — state machine + proof

The data-plane counterpart to the establishment proof. `establishment_model.py`
proves the **signaling** protocol (offer → answer → ICE → CONNECTED) is
glare-free, deadlock-free and self-healing. This layer picks up where that
leaves off: a pair is already CONNECTED and must now **carry a file over a
transport, confirm whole-file delivery, and tear the transport down** — possibly
reusing it for a second transfer to the same remembered peer.

Model + proof: [`proofs/transport_lifecycle_model.py`](../proofs/transport_lifecycle_model.py).
Liveness classifier it composes with: [`docs/transfer-state-machine.md`](transfer-state-machine.md)
(`resilience.rs::classify`).

## Why this exists

Every bug in the multi-stream throughput push lived in this layer, in a corner
that **neither** the establishment model **nor** the liveness classifier covered.
Each model assumed the *other* owned a transport-less-but-established link, and
the gap between them is where the bugs lived:

| Bug | What happened | Root cause |
|---|---|---|
| **BUG-CORPSE** | 10 GB transfer "never starts"; `transport_up=false workers=0 idle=u64::MAX`; "delivery not confirmed" | A dead link entry persists in `conn.links`; the re-dial that would revive it is suppressed because `start_direct_inner` (`main.rs:3421`) gates on link **existence**, not link **liveness**. `classify()` calls it `Establishing` and defers to "the establishment watchdog", which can't act. The corpse blocks its own resurrection. |
| **BUG-ACKLOSS** | Bytes fully arrive, then `ApplicationClosed(0,"")`; the delivery-ack is lost | QUIC has **no flush-on-close** (RFC 9000 §10.2). The receiver writes the ack on the now-**idle** primary, then drops the connection; the un-flushed ack is discarded. |
| **BUG-ROLE** | Nobody dials; a transport never comes up | Both ends took the ANSWERER role on a symmetric simultaneous-open (`sid_answerer()` true on both). |

Modeling the lifecycle explicitly makes each of these an **unrepresentable** or
**provably-unreachable** state rather than a bug we rediscover.

## The three fixes (and the contract each enforces)

- **role** — `net::polite_role` (a strict total order on uids) picks exactly one
  dialer per pair. *Contract: a pair always has a dialer.*
- **teardown** — the party that **read the last message closes**; the other
  **waits**. Our last message is the delivery-ack (receiver → sender), so the
  **sender** (who reads it) calls `conn.close(0,"done")` + `Endpoint::wait_idle()`,
  and the **receiver** finishes the ack stream then `conn.closed().await` — it
  does **not** close. This is the quinn/iroh rule (["Closing a QUIC Connection"](https://www.iroh.computer/blog/closing-a-quic-connection)),
  mirrored by croc and rsync. *Contract: a whole-file-verified transfer's ack is
  always delivered before any close.*
- **guard** — the re-dial guard is **liveness-aware**: a link entry with no live
  transport (`transport.is_none() && workers.is_empty()`) never blocks a fresh
  dial — it is purged and re-dialed. *Contract: a link in `conn.links` always has
  a live transport, or a dial in flight — never a persistent corpse.*

## 1. The state machine

One link between sender **S** and receiver **R**, across two back-to-back
transfers (`ep ∈ {1,2}` — the "500 MB works, then 10 GB to the same peer fails"
scenario made checkable).

```
transport slot T : NONE ─dial─► DIALING ─up─► LIVE ─sender_close─► CLOSING ─wait_idle─► CLOSED
                     ▲                          │  ▲                                        │
                     │                          │  └───────── redial_reuse (next transfer) ─┘
        redial_dead  │        transport_dies /  ▼
     (guard, if in-  └──────────── DEAD ◄── premature_close (buggy teardown only)
      flight & dead)

sender  X : IDLE ─offer─► OFFERED ─accept─► STREAMING ─deliver&verify─► AWAIT_ACK ─ack_read─► DELIVERED
receiver R : R_IDLE ─────────────────────► R_RECV ──────────────────► R_VERIFIED ─send_ack─► R_ACKED ─recv_release─► R_DONE
ack-on-wire: 0/1   (set by send_ack; cleared by ack_read; DROPPED by premature_close)
```

- A transfer needs `T=LIVE` to make progress (`offer`/`accept`/`deliver` all
  guard on it) → **an offer can never be placed on a dead link** (BUG-warm-reuse
  is unrepresentable, structurally).
- `premature_close` — the buggy teardown — exists **only** when `teardown=False`.
  It drops the connection while the ack is still on the wire (`ack:1→0`, lost) and
  leaves the sender's transport `DEAD` mid-`AWAIT_ACK`. On a **perfect link this
  is entirely self-inflicted** (no fault budget spent).
- `redial_dead` — corpse recovery — exists **only** when `guard=True`.

## 2. Invariants (safety) — checked on every reachable state

- **I-CORPSE** — no in-flight transfer sits on a `NONE`/`DEAD` transport with no
  possible re-dial.
- **I-ACKLOSS** — never `connection gone ∧ receiver verified ∧ sender never got
  the ack ∧ no recovery`.
- **I-HALFOPEN** — never `sender DELIVERED ∧ receiver never verified`.
- **I-OFFER-INTO-DEAD** — enforced *structurally* (the `offer` transition guards
  on `T=LIVE`), so it is not even a reachable state to check.

Plus the two liveness properties from the establishment model's playbook: **no
deadlock** (no non-terminal sink) and **AG EF terminal** (every reachable state
can still reach the clean terminal — both transfers delivered + verified + the
link cleanly closed).

## 3. Theorems (what the checker proves, exhaustively)

**Tier 0 — GoodNet** (perfect DO-vm ↔ DO-vm link: reliable delivery, *no
spontaneous transport death* — the only deaths are the ones the code inflicts on
itself). Over **all 2³ fix combinations**:

> **The lifecycle is correct ⟺ `role ∧ teardown`.**

That is: you need a dialer, **and** the receiver must not drop its own link at the
ack (correct teardown). `guard` does **not** rescue GoodNet — this is the subtle
part, confirmed against a live 5 GB run (the model *predicted* `teardown ∨ guard`
until reality falsified it). When the receiver closes prematurely it is **done**:
it will not re-accept, so the sender's re-dial has no peer to answer ("peer did
not come back within 45 s"). `guard` can only recover a link killed by a *real
fault* where the receiver is still present — not a self-inflicted receiver-gone
close. So under GoodNet `teardown` is **necessary even with `guard` on**.

**Tier 1 — Degraded** (GoodNet minus reliability: up to *K* genuine mid-transfer
transport deaths — real NAT rebind / drop, *receiver still present*):

> With real drops, **`guard` becomes independently necessary** — correct teardown
> cannot resurrect a transport the *network* killed, but the receiver is still
> there to answer a re-dial. All fixes on → the lifecycle **self-heals** to the
> clean terminal in bounded steps. Net: `role ∧ teardown ∧ guard`.

Exhaustive over a bounded model = a definitive result for that bound: the checker
finds **every** corpse / lost-ack / stuck state, not just one we tripped over.

### Latest result

```
GoodNet   role+teardown         -> PROVEN (24 states)     | theorem clean <=> role∧teardown: holds on all 8
GoodNet   role+guard (no teardown) -> COUNTEREXAMPLE       | guard can't rescue a receiver-gone close (matches live 5GB run)
Degraded  all fixes, K=1        -> PROVEN (67 states)     | guard independently necessary (drop it -> counterexample)
Degraded  all fixes, K=2        -> PROVEN (110 states)
```

The exact counterexample the checker replays: `dial → up → offer → accept →
deliver&verify → send_ack → premature_close` ⇒ `T=DEAD, X=AWAIT_ACK, rx_gone` —
stuck, "delivery not confirmed", **even with the liveness guard on**. That
`rx_gone` (receiver tore down its own link and is gone) is the faithfulness fix
that made the model agree with the live system.

## 4. State ↔ code

| Model | Code |
|---|---|
| `T` (transport slot) | `main.rs` `Link.{transport, workers}`; `direct.rs DirectTransport` |
| the re-dial `guard` | `main.rs:3421` `start_direct_inner` (existence vs liveness) |
| `X` (sender transfer) | `main.rs` `OutFile.{accepted_once, sent, acked, done}`; the P4 no-ack window |
| `R` (receiver) | `main.rs` up-loop `verify_incoming → delivery_ack_msg` |
| `ack` teardown | receiver `conn.closed()` waits; sender `conn.close` + `Endpoint::wait_idle` (RFC 9000 §10.2) |
| `role` | `net::polite_role` (CONTRACT.md "newer initiates") |
| aggregate liveness | `detect_stall` `min(idle)` over primary + workers (multi-stream) — `T=LIVE` abstracts "alive if ANY connection moved a byte" |

## Honest boundary (a transition the model assumes the code must guarantee)

The `premature_close`/`transport_dies` transitions assume that closing/dropping a
link **actually tears the connection down** (`T → DEAD`, observed by the peer as
`ConnectionLost`). The code must make that true. A known way it is *not* true: a
detached keepalive task that clones the `quinn::Connection` (`direct.rs`
`keep_endpoint_alive`, and the per-worker `pending()` endpoint keeps) **outlives**
the `DirectTransport`, so `drop_link` drops the transport but the connection keeps
pinging and never closes — a **zombie** (alive at the transport, no data), the
verify-before-accept / silence-watchdog "zombie link" class, *not* the modeled
`T=DEAD`. Recovery
gates on `is_dead()`, which stays false, so it never fires. Two things keep reality
faithful to the model here: (1) the teardown path must use an **explicit**
`conn.close(0, "done")` (which closes regardless of stray clones), not a bare drop;
and (2) the keepalive must be **abortable** — own the endpoint/connection in the
`Link` (lifetime = the Link) or store its `JoinHandle` and abort it in `drop_link`
— so a drop-based teardown also produces a real `ConnectionLost`. Until both hold,
a `drop_link` can silently leak the connection instead of reaching `T=DEAD`.

## Discipline

A change to the transport lifecycle (`start_direct_inner`, the teardown path, the
role assignment, `detect_stall`, the keepalive ownership) must keep this proof
green. If you change the FSM, update `proofs/transport_lifecycle_model.py` + this
table **first**, then make CI pass — the same model-first rule the establishment
proof enforces.
