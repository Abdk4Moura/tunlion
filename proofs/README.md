# Filament establishment proof

An exhaustive, re-runnable correctness check for the peer-to-peer
connection-establishment protocol. Run it:

```
python3 establishment_model.py        # N=2 and N=3, both tiers
python3 establishment_model.py 2      # only the 2-peer runs
```

It explores the **entire** reachable state space of a faithful model and
verifies, for N peers:

| Tier | Assumptions | What is proven |
|---|---|---|
| **0 GoodNet** | reliable bounded delivery, no spurious disconnect, connectivity exists (ICE finds a path), fair scheduling | no invalid state; no deadlock; CONNECTED always reachable; clean-FAIL **never** reached |
| **1 DegradedNet** | GoodNet **minus** reliability: up to K network faults (lost signals, unclean disconnect, black-holed link, peer supersede) | invariants still hold in every state; **no deadlock at any point** (a timer always rescues a wait); every trajectory reaches a terminal in bounded steps; and once faults stop the system **self-heals to CONNECTED** instead of stalling at FAIL |

Exhaustive over a bounded model is a *definitive* result for that bound: the
checker finds **every** stuck/invalid state, not just one we tripped over. This
is the same class of technique as TLA+/TLC or Spin, written as a self-contained
explicit-state checker so it has no external dependencies and is fully auditable.

## Latest result

```
GoodNet  N=2  -> PROVEN (4 states)        GoodNet  N=3  -> PROVEN (64 states)
Degraded N=2  -> PROVEN (K=1,2,3)         Degraded N=3  -> PROVEN (K=1: 4544, K=2: 66976 states)
```
0 invariant violations, 0 deadlocks, 0 unreachable-terminal states, 0 post-fault
states that can't self-heal — in all runs.

## Companion: the transport-lifecycle proof

`establishment_model.py` proves the **signaling** protocol (offer → answer → ICE
→ CONNECTED). Its sibling, `transport_lifecycle_model.py`, proves the **data
plane** that begins once a pair is CONNECTED: carrying a file over a transport,
confirming whole-file delivery, tearing the transport down, and reusing it for a
second transfer. Run it:

```
python3 transport_lifecycle_model.py
```

Every bug in the multi-stream throughput push (a dead-link **corpse** that blocks
its own re-dial; a **lost delivery-ack** from a premature QUIC close; a
**both-answerer role** that dials nothing) lived in the gap *between* the
establishment model and the liveness classifier — each assumed the other owned a
transport-less-but-established link. This model closes that gap. It encodes the
three fixes as independent booleans and checks all 2³ combinations, proving:

- **GoodNet** (perfect DO↔DO link): correct **⟺ `role ∧ (teardown ∨ guard)`** —
  verified on all 8 combos. Each conjunct is necessary; together sufficient.
- **Degraded** (real mid-transfer drops): the liveness-aware re-dial (`guard`)
  becomes *independently* necessary; all fixes on → self-heals in bounded steps.

The design write-up is [`docs/transport-lifecycle-state-machine.md`](../docs/transport-lifecycle-state-machine.md).
Both proofs are required CI gates (`.github/workflows/proof.yml`).

## The properties

- **I1 glare-freedom** (safety, structural): of any pair the lexically-lesser
  uid is the sole OFFERER. `polite_role` is a strict total order, so exactly one
  side offers — glare can't deadlock. (net.rs:1002; webrtc.js:314; CONTRACT.md:66)
- **I2 no half-open** (safety): never one endpoint READY while the other has
  given up (FAIL) or never started (IDLE).
- **No deadlock** (safety): every non-terminal state has an enabled transition —
  a watchdog/grace/stall timer always exists to break a wait. This is *the*
  "never stuck at any point in time" guarantee.
- **Liveness AG-EF**: from every reachable state a terminal is reachable (no
  stuck SCC). GoodNet's terminal is always CONNECTED; Degraded's is CONNECTED or
  an honest clean FAIL, and post-fault states can always still reach CONNECTED.
- **Bounded recovery**: the BFS depth (`depth<=`) is a finite upper bound on
  steps-to-settle — recovery per fault is bounded, never open-ended.

## State <-> code mapping (faithfulness)

The model is extracted from the deployed code; this is the weak link of any such
proof, so it is spelled out. Both clients implement the same protocol
(cross-impl parity is test-pinned), so one canonical FSM models both.

| Model element | Rust (`cli/src/`) | Web (`frontend/src/`) |
|---|---|---|
| role = polite_role total order | `net.rs:1002` | `lib/webrtc.js:314` |
| OFFERER creates offer; ANSWERER waits | `net.rs:1118-1145` | `webrtc.js:451-462,517` |
| glare: impolite ignores / polite rebuilds-or-rolls-back | `net.rs:1233-1252`, `main.rs:4043-4058` | `webrtc.js:540-553` |
| deliver offer -> answer | `net.rs:1254-1281` | `webrtc.js:547-553` |
| deliver answer -> connected (ICE succeeds, A4) | `net.rs:1247-1264` | `webrtc.js:468-471,653` |
| establishment watchdog (15s) -> retry/FAIL | `net.rs:48`, `main.rs:3101` (MAX_ATTEMPTS=3) | `webrtc.js:524`, `useFilament.js:471` (cap 2) |
| disconnect grace (6s) -> retry/FAIL | `main.rs:3870` GraceExpired | `webrtc.js:499-505` |
| stall ladder: repair -> relay (once) -> clean FAIL | `main.rs:3284` correct_stall (STALL_MAX_REPAIRS=5) | `stall.js`, `recovery.js:22-27` |
| supersede on reconnect (same uid, new sid) | `main.rs:2534-2563` | `useFilament.js:292-308` |
| self-heal from FAIL (known-peer / re-pair) | C12 channels, `subscribe` | `lib/devices.js`, digest reconcile |
| fault: lost signal | (network) | (network) |
| fault: black-holed link (the zombie) | the verify-before-accept fix, beta.23 | n/a |

## Honest boundary

This proves the **signaling + establishment logic** as abstracted here. It does
**not** prove WebRTC's own ICE/DTLS stack or the OS network — those are
assumption A4 ("a path exists" = what "good internet" means). It checks bounded
N and a bounded fault budget. The model is hand-extracted, not mechanically
generated from the code, so the mapping table above is the thing to keep honest
as the code changes.

The payoff is the clean separation the whack-a-mole was missing: **every failure
mode we have chased (zombie links, ghost presence, the 15s stall) is a violation
of a Tier-1 assumption — a real network fault — and Tier-1 proves each one
recovers in bounded time. There is no GoodNet failure.** New protocol changes
should update the model + mapping first, re-run this, and stay green.
