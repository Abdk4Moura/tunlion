# Transfer path: what is broken, what is fixed, what is still unknown

Status as of 2026-08-03. Written so anyone can pick this up without reading the
thread. Claims are marked VERIFIED (checked in source or measured) or
HYPOTHESIS (consistent with evidence, not established).

## The headline

`main` fails `pair_and_transfer_smoke` on **two of three platforms**.

| branch | roster reconciliation | fallback fixes | macOS | ubuntu | windows |
|---|---|---|---|---|---|
| `main` | no | no | FAIL | pass | FAIL |
| PR #73 | no | no | FAIL | pass | - |
| PR #74 | no | yes | FAIL | pass | - |
| PR #71 | yes | yes | PASS | pass | pass |

VERIFIED. Windows fails with the identical signature (`peer did not come back
within 45s`, same `capability_harness.rs:414`) in 50s rather than 647s.

This was framed as a macOS problem for two days. It is not. Ubuntu is the only
platform where the transfer path works, and it is the platform CI is tuned
around.

## The failure, precisely

Option A (`main.rs:10823`) is deliberate and correct by design: after PAKE
authentication, drop the WebRTC link and race direct-QUIC using the PAKE-derived
secret. If direct loses, `expired_direct -> establish` rebuilds WebRTC.

VERIFIED sequence on a failing macOS run:

```
direct authenticated          -> intentional Option A drop
+30s   fallback establish rebuilds, ICE CONNECTS
       ...no second auth, no transfer
+600s  sender hits claim_deadline, exits
+45s   receiver's rejoin window expires   (600 + 45 = 645 vs 647s observed)
```

So the fallback **comes back and cannot authenticate**. It is not "never comes
back". The documented gap is ~5s; observed is 30s, which is a sync interval, not
the 5s budget.

## Why authentication fails on the rebuilt link

VERIFIED: once `pake_done` is true, the ceremony never re-runs
(`main.rs`, `if use_code && !is_direct && !pake_done`). The only remaining auth
path on a rebuilt WebRTC link is the post-channel pair-proof, which requires
`l.expected_secret`.

VERIFIED: `establish()` built every link with `expected_secret: None`. Only the
expiry site restored it, by hand.

VERIFIED (the reason my fix did not work): Option A destroys the link in the
**caller** at `main.rs:10841`, before `start_direct` is entered. So when
`establish()` later reads the previous link's secret to carry it forward, the
slot is already empty.

## Landed on `fix/sender-synced-roster` (PR #71)

VERIFIED in source by `claude-advisor`:

- `establish()` now does all fallible work (including a network round trip to
  signaling) **before** dropping. Drop and insert are adjacent with no `await`
  between, so the destroy-without-rebuild window is eliminated, not narrowed.
- `expected_secret` is carried across every rebuild path instead of only the
  expiry site. Correct on its own terms; **not** sufficient to fix macOS (PR #74
  falsified that prediction).
- Three `let _ = self.establish(...)` discards now log. Two of them are the
  WebRTC fallback by their own comments.
- All three `on_synced` sites reconcile the digest roster; `#[must_use]` makes a
  silent discard a compile error.
- `#[track_caller]` on `drop_link`: a teardown names the call site that ordered
  it. This answered in one CI cycle what a 17-call-site audit had not.
- Gate P (`FILAMENT_TEST_DROP_PUSH`): server-side push dropper, so "can a client
  recover from a missed push" is testable on demand.

## Open, with owners

1. **Move Option A's drop inside `start_direct_inner`** (new-renewer, has the
   token). Delete the caller-side drop at 10841; register `direct_pending`
   first; fix the `link_alive` guard that will otherwise bail early. This is the
   change that makes the carry-forward actually reach a live slot. Ships with:
   force `bind_endpoint` to fail and assert the WebRTC link survives.
2. **Fallback latency**: documented ~5s, observed 30s. Untouched by any fix so
   far. If a green run still shows 30s, this is independent and still open.
3. **Why direct-QUIC never completes on macOS.** Probe pushed (`ce6072f`):
   `local_ip_snapshot` filters out loopback, so same-host peers must UDP-hairpin
   via a real interface address. Linux baseline measured: hairpin works, not the
   blocker there. macOS answer pending. HYPOTHESIS until that reports.
4. **Reap + `channel_peers`** (side branch). `on_synced` returns `peers` and
   drops `channel_peers`, so `known-peer`/`known-peer-left` have no repair path
   at all and `#[must_use]` cannot help them.
5. **PR #72** (#23 copy, verified 52/0 locally) fails ubuntu smoke, which `main`
   passes. Not yet determined whether the copy branch tripped it or it is flaky.

## Ruled out, do not re-investigate

- `SO_RCVBUF` / `kern.ipc.maxsockbuf`. Probed on the actual runner: macOS grants
  6 MiB and **clamps rather than erroring**, so `bind_endpoint`'s fallback chain
  never fails. macOS is more permissive than Linux here (416 KiB).
- Missed `peer-joined` as the macOS cause. The sender authenticated and was
  sending; nothing inbound arrived in the 40ms window before the close.
- A drop/re-adopt loop. Four drops across a six-test job is not once per sync
  interval.
- "macOS runners are slow." Ten minutes is not a timing race, and five sibling
  tests finished inside the same 647s.

## Standing rules earned here

- A green check after a fix cannot distinguish **prevention** from **recovery**.
  PR #71 is green because roster re-adoption routes around the broken fallback.
  Pre-register what a green result would and would not prove, before it exists.
- Verify a fix with a **different query shape** than the one that produced the
  claim. Walking `cgroup.procs` caught a shield that `docker inspect .State.Pid`
  reported as complete.
- The log level of an error path should be a function of what the path
  **destroys**, not how routine the code considers it. The diagnostic for a
  branch that tears down a working link was `trace`, in a job that captures none.
- Model protocol questions in Python first. `experiments/py/hairpin_probe.py`
  and the signaling probe each answered in seconds what a build-and-CI loop
  answers in twenty minutes.
