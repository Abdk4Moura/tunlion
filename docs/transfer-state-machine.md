# Transfer link liveness — state machine

The status of one link carrying an in-flight transfer, as judged by the
bytes-moved stall watchdog. Modeling it explicitly (rather than inferring it from
scattered fields) makes a whole class of bug — *judging a still-establishing link
by the flowing-transfer threshold* — **unrepresentable**.

Source: `cli/src/resilience.rs` (`Liveness`, `LiveObs`, `classify`,
`phase_threshold`, `decide_stall_action`). Mirrors
`frontend/src/net/resilience/stall.js`.

## Why this exists

The watchdog's job is "no data for too long → correct". But *too long* is not one
number:

- A link still **establishing** (TURN alloc + ICE + DTLS/SCTP handshake + first
  chunk) over a high-RTT relay routinely takes **10–30 s** before its first byte.
- A link that is already **flowing** and then stops is genuinely wedged after a
  few seconds.

Charging an establishing link the tight flowing threshold (6 s) made the watchdog
tear it down and rebuild it — and the rebuild's setup *also* exceeded 6 s, so it
looped forever and delivered **zero bytes** (the exact hang the watchdog exists to
prevent). The fix: the timeout is a property **of the phase**, chosen in exactly
one place (`classify` / `phase_threshold`).

## 1. Liveness phase

Inputs each tick (`LiveObs`): `in_flight`, `transport_up`, `flowed`
(first DATA byte seen), `idle_ms` (since last byte), `grace_ms`, `stall_ms`.

```
                         no transfer in flight
   ─────────────────────────► Idle ◄───────────────────── transfer ends / completes
                                │ transfer starts
                                ▼
   ┌── first byte flows ── (no transport yet  ──► Establishing
   │   & idle < STALL          OR transport up,        │   ▲
   │                            no first byte)          │   │ idle < GRACE
   │                          judged by GRACE (45s)     │   │ (still establishing,
   │                                │ idle ≥ GRACE      │   │  e.g. slow relay setup)
   │                                ▼                   │   │
   │                             Stalled ◄──────────────┘   │
   │                                │   ▲                    │
   │                                │   │ idle ≥ STALL (6s)  │
   ▼                                │   │                    │
 Flowing ⟲ (idle < STALL) ──────────┘   └──── Flowing ───────┘
   │                                                  ▲
   └── idle ≥ STALL (6s) ─► Stalled                   │ first byte over a
                              │                        │ FRESH transport
                              └─► run the LADDER (§2) ──┘ (re-enters Establishing
                                  on repair, GRACE again → loop can't form)
```

States: `Idle · Establishing · Flowing · Stalled`.

- `Idle` — nothing in flight; not watched.
- `Establishing` — in flight, **no first byte yet** (no transport, or transport up
  but pre-first-byte). Judged ONLY by `GRACE`. A link here can never be `Flowing`.
- `Flowing` — a byte moved within the `STALL` window. Healthy.
- `Stalled` — no progress past the phase's threshold → drive the ladder.

`phase_threshold(flowed)` = `GRACE` if `!flowed` else `STALL`. This single mapping
is the invariant: **a not-yet-flowed link is never judged by `STALL`.**

After any repair the new transport reports `flowed = false`, so the machine
re-enters `Establishing` and the generous grace applies again — which is what
breaks the destructive repair loop.

## 2. Correction ladder (once `Stalled`)

`decide_stall_action(attempt, max, warm_eligible, relay_forbidden, already_relayed)`:

```
attempt 0 + warm standby  → WarmCutover              (interactive: instant relay failover)
attempt 0                 → Resume                   (re-offer on the SAME transport)
0 < attempt < MAX         → Repair                   (rebuild the transport in place)
attempt ≥ MAX, relay ok   → RelayEscalate            (re-establish over TURN, keep .part)
attempt ≥ MAX, --no-relay → ExhaustedRelayForbidden  (fail clean, partial kept)
attempt ≥ MAX, on relay   → ExhaustedAlreadyRelay    (fail clean, partial kept)
```

A converging repair (`direct_pending` / the `relayed` latch) suppresses
re-firing; observed progress clears the episode (`note_progress`).

## Invariants (illegal states made impossible)

- The threshold is selected by phase inside `classify`; no call site picks a
  threshold, so "establishing judged by `STALL`" cannot occur.
- A link with no transport is always `Establishing` (the *establishment* watchdog
  C3 / `Ev::Stuck` owns "never connects"), never `Stalled` — the bytes watchdog
  never repairs a link that has nothing to repair.
- `classify` is pure and memoryless: the phase is a function of the observation,
  so there is no stored phase that can drift into a contradictory combination.

## Knobs

- `FILAMENT_STALL_MS` — flowing-transfer no-progress threshold (default 6 000).
- `FILAMENT_ESTABLISH_GRACE_MS` — before-first-byte grace (default 45 000; never
  below `stall_ms`).

## Faults this maps to

- **0%/N% establishment loop on a high-RTT relay** — FIXED: `Establishing` uses
  `GRACE`; the repair loop can't form (beta.12, `cli-v0.2.1-beta.12`). Reproduced
  with `tc netem delay` and verified.
- **Mid-transfer stall on a *direct* high-RTT link (NAT rebind / drop), recovery
  wedges** — under investigation: the recovery/resume path after a flowing link
  drops, distinct from the establishment loop above.

## Tests

`cli/src/resilience.rs` `#[cfg(test)]`: every phase + transition, the regression
(not-flowed, idle past `STALL` but within `GRACE` ⇒ `Establishing`), the
repair-re-enters-grace loop-breaker, and the full ladder table.
