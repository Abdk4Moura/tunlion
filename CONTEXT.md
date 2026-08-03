# CONTEXT: filament transfer-path work, handoff for a fresh agent

Everything needed to continue without reading any history.

Labels are **SECTIONAL**, not per-claim: a heading marked VERIFIED covers the
items under it. An unlabelled claim is **unclassified, not verified** — check it
before you build on it. (Flagged by `claude-advisor`: most individual claims here
carry no marker, and a reader told "the doc is labelled" will read absence as
confirmation.)

---

## 1. The problem

`pair_and_transfer_smoke` fails on two of three platforms on `main`.

| tree | roster reconciliation | fallback fixes | macOS | ubuntu | windows |
|---|---|---|---|---|---|
| `main` (before #71) | no | no | FAIL | pass | FAIL |
| PR #73 (control) | no | no | FAIL | pass | - |
| PR #74 (control) | no | yes | FAIL | pass | - |
| **PR #71 (MERGED)** | yes | yes | **pass** | pass | **pass** |

VERIFIED. Windows fails with the identical signature (`peer did not come back
within 45s`, `capability_harness.rs:414`) in 50s rather than 647s.

**This was framed as a macOS bug for two days. It is not.** Ubuntu is the only
platform where the transfer path worked, and it is the platform CI is tuned
around.

## 2. The mechanism (VERIFIED)

`main.rs`, "Option A", fires after PAKE authentication:

```rust
// Option A: drop WebRTC link and race direct-quic FIRST.
// If direct fails: expired_direct -> establish -> WebRTC fallback (~5s gap).
conn.drop_link(&from);
conn.start_direct(&from, &from, &sec).await;   // sec = the PAKE secret
```

The teardown is **deliberate and correct by design**. The failure is that the
promised fallback does not arrive:

```
direct authenticated -> intentional Option A drop
+30s   fallback establish rebuilds, ICE CONNECTS
       ...no second auth, no transfer          <- the real defect
+600s  sender hits claim_deadline, exits
+45s   receiver rejoin window expires           (600 + 45 = 645 vs 647 observed)
```

**Why the rebuilt link cannot authenticate:** once `pake_done` is true the
ceremony never re-runs (`if use_code && !is_direct && !pake_done`). The only
remaining auth path is the post-channel pair-proof, which needs
`l.expected_secret`. `establish()` built every link with `expected_secret: None`.

**Why macOS specifically, and this is the HEADLINE (VERIFIED):**
`FILAMENT_DIRECT_PER_OS=0` on macOS in CI, forwarded by `capability_harness` to
every spawned daemon as `FILAMENT_DIRECT` (it reads in six places; an earlier
grep of `cli/src` alone missed it and nearly deleted it as dead).

`FILAMENT_DIRECT=0` is **a documented, supported, user-facing opt-out**:

```rust
direct.rs:57  // Default ON. Opt out with FILAMENT_DIRECT=0.
```

So this is a PRODUCT bug, not a CI artifact. A user who takes the documented
"skip the fast path" option gets: Option A drops the WebRTC link, `start_direct`
returns at the first guard (`!self.direct_ok`, ~165 lines before
`direct_pending.insert`), `expired_direct` has nothing to expire, and the link is
destroyed with no successor. **The transfer wedges for 600 seconds.** The option
offered for AVOIDING the risky path is the one that breaks transfers outright.

An earlier version of this file said macOS CI "tests a configuration no user
runs". That was backwards, corrected by `claude-advisor`: macOS was the ONLY
place testing something realistic, and it is what found this.

`FILAMENT_DIRECT_LOOPBACK_ONLY=1` on ubuntu/windows pins ICE candidates to
loopback, so same-host direct works trivially there; it is 0 on macOS because
webrtc-rs gathers no loopback host candidates on ARM64.

## 3. What landed (PR #71, MERGED into main)

All VERIFIED in source by `claude-advisor`:

- `establish()` does all fallible work (incl. a network round trip) **before**
  dropping. Drop and insert are adjacent with no `await` between, so the
  destroy-without-rebuild window is eliminated, not narrowed.
- `expected_secret` carried across every rebuild path, not just the expiry site.
- Three `let _ = self.establish(...)` discards now log. Two are the WebRTC
  fallback by their own comments.
- All `on_synced` sites reconcile the digest roster; `#[must_use]` makes a
  silent discard a compile error.
- `#[track_caller]` on `drop_link` — a teardown names its call site. Answered in
  one CI cycle what a 17-site audit had not.
- Gate P: `FILAMENT_TEST_DROP_PUSH` server-side push dropper.

**#71 works by RECOVERY, not prevention.** Roster re-adoption re-establishes
after the teardown; the designed fallback is still broken. Do not describe it as
fixed.

## 4. In flight

### PR #78 `fix/promote-intent-v2` — the current candidate, MERGEABLE
Rebuilt on current `main` after #71 squash-merged. Carries the whole chain:

```rust
enum DirectIntent { Normal, Probe, Promote }

// a promotion SUPERSEDES a stale pending: one dialled before PAKE completed
// has no secret and cannot authenticate, so it must not block the promotion
if direct_pending.contains_key(pid) { if intent != Promote { return } ; remove(pid) }
// a live link stops everyone EXCEPT a deliberate promotion
if intent == Normal && has_live_transport(pid) { return }
...all fallible setup, then register direct_pending...
if intent == Promote { drop_link(pid) }      // destroy last, successor armed
```

`start_direct_promote` is the only caller permitted to replace a serving link.
The enum replaced a `(probe, promote)` bool pair on `claude-advisor`'s gate:
four states, three meaningful, one nonsense (`probe && promote` = "a test dial
that tears down a serving link") that nothing rejected.

### PR #77 — the control that decides it
Same tree minus ONLY the roster reconciliation. #78 contains both the promote
fix and roster recovery, so a green #78 says the transfer works, NOT which
change did it. #77 is the only thing separating "the fallback is repaired" from
"roster re-adoption is still masking it".

### CLOSED as superseded or redundant
#70 (winner rule; `answerer_for` is in main 4x via #71, verified by content
because #71 was squashed), #75 and #76 (both stacked on a pre-#71 base, went
CONFLICTING, and **GitHub schedules zero checks on a conflicting PR** — that
reads exactly like "CI pending" and cost two wake cycles).

## 5. Open, in priority order

1. **#78 macOS result**, then **#77's control**. Green on #77 = the designed
   fallback is genuinely repaired rather than routed around.
2. **`FILAMENT_DIRECT=0` wedges transfers** (section 2). Documented opt-out,
   product bug, 600s wedge. #78 fixes the mechanism; needs its own coverage.
3. **Fallback latency**: documented ~5s, observed 30s (a sync interval, not the
   budget). Untouched by any fix so far.
4. **Reap + `channel_peers`** (filament-new-guy, started): `on_synced` returns
   `peers` and drops `channel_peers`, so the five `Ev::KnownPeer` consumers
   (main.rs 3631, 3818, 4044, 4523, 10805) and `KnownPeerLeft` (12938) have NO
   repair path, and `#[must_use]` cannot help them.
5. **PR #72** (#23 copy): ubuntu failure diagnosed by opencode-101 as the
   pre-#71 transfer baseline, NOT copy-induced. Rebase onto current main is the
   discriminating check.
6. **#25** wired by optimizer at `671c6e2` on `task25-current-main`, unbuilt.
7. **Adoption cannot distinguish a deliberate drop** from a missed
   `peer-joined` — guard is `!links.contains_key(pid)`, satisfied after any
   teardown, and Option A drops deliberately on every transfer.
8. **Stall detector** `0f9d031`: real, unmerged, unmeasured. Must NOT be
   validated by its own clean-run hang count; a correct detector and a broken
   one both report zero. Induce a stall.

## 6. RULED OUT — do not re-investigate

- **`SO_RCVBUF` / `kern.ipc.maxsockbuf`.** Probed on the actual runner: macOS
  grants 6 MiB and **clamps rather than erroring**, so `bind_endpoint`'s fallback
  chain never fails. macOS is *more* permissive than Linux (416 KiB).
- **A missed `peer-joined` as the macOS cause.** The sender authenticated and was
  sending; nothing inbound arrived in the 40ms window before the close.
- **A drop/re-adopt loop.** Four drops across a six-test job is not once per sync
  interval.
- **"macOS runners are slow."** Ten minutes is not a timing race; five sibling
  tests finished inside the same 647s.
- **`FILAMENT_DIRECT_PER_OS` being dead.** It is live via the harness.

## 6b. RETRACTED — stated confidently, then withdrawn

Recorded because the reasoning that produced these is available to whoever reads
this next, and most were believed by two agents at the time.

| claim | what was actually true |
|---|---|
| "23 OOM kills today" | **3.** `grep -c` counted log LINES; one event emits many. Count `"Killed process"`. |
| "sccache was OOM-killed" | It was the *rustc child*. sccache reports `Compile terminated by signal 9` and survives. |
| "the harness 600s timeout was an OOM" | Window predated the kills by ten minutes. External prerequisites was the better reading. |
| "first-contact direct is structurally ineligible" | Option A already promotes to direct using the PAKE secret. |
| "the sender never got a peer" | It paired, authenticated and was sending; the link then died. The bail message cannot distinguish the two. |
| "macOS CI tests a config no user runs" | `FILAMENT_DIRECT=0` is a documented opt-out. Inverted the severity. |
| "`FILAMENT_DIRECT_PER_OS` is a dead knob" | Live via `capability_harness`; a grep of `cli/src` alone missed `cli/tests`. |
| "`establish()` was the dominant teardown caller" | `#[track_caller]` had detached onto `has_live_transport`; the instrument was reporting itself. |

The shape they share: **an absence read as a null.** A missing detector read as
no hangs, a missing instrument read as no stalls, an unfetched ref read as an
excluded commit, a grep of the wrong directory read as a dead knob, an
unscheduled check read as a pending one. The rule that covers all of them:
*an empty result is only as strong as your evidence that the thing which
produces results actually ran.*

## 7. Agents (xats bus, `cross-agent-teams` MCP, team `default`)

| name | role | state |
|---|---|---|
| `claude-advisor` | security reviewer, gates | Found most of the sharp defects. Gate its rulings; it has overruled the coordinator correctly many times. |
| `new-renewer` | worker, holds the build token | Owns PR #73/#74/#75 and the macOS controls. |
| `rig-verifier` | worker | Runs measurements. Excellent provenance discipline. |
| `optimizer` | worker | Design notes, capability/grant work. |
| `opencode-101` | worker | Finished #23 (PR #72). |
| `filament-new-guy` | worker | Finished #21. Currently idle. |

## 8. Machine + process rules (earned the hard way)

- **do-vm is 4 cores / 8 GB.** Six agent runtimes plus concurrent Rust builds
  caused 3 OOM kills, one of which took an agent runtime. **One build at a time**
  via a coordinator-held token, `-j2`, isolated `CARGO_TARGET_DIR`.
- Production is OOM-shielded at `oom_score_adj: -800` **in compose** (was a live
  `/proc` write that would silently lapse on `docker compose up -d`). Apply by
  walking `cgroup.procs`, never `docker inspect .State.Pid` — that returns the
  supervisor only and leaves gunicorn's single worker exposed.
- Never `pkill -f filament`; never touch a running `filament up`. Production
  containers: `deploy-api-1`, `deploy-redis-1`, `deploy-coturn-1`,
  `deploy-cloudflared-1`, `formly-cfd`. **Any port you did not start yourself on
  127.0.0.1 belongs to someone else.**
- House style: no em dashes, no AI attribution anywhere (commits, PRs, code).
- **The shared `CARGO_TARGET_DIR` voided a 30-trial run** by swapping the binary
  mid-measurement. Any run whose output is a number: own target dir, record the
  binary sha256, assert it matches the checked-out sha.
- The harness `binary()` ignores `CARGO_TARGET_DIR` and reads
  `<manifest>/target/...`; correct results depend on symlinking that into the
  isolated dir first.

## 9. Method rules that actually caught things

- **A green check after a fix cannot distinguish prevention from recovery.**
  Pre-register what a green result would and would not prove, before it exists.
  This caught #71 being recovery rather than a fix.
- **Verify a fix with a different query shape than the one that produced the
  claim.** Walking `cgroup.procs` caught a shield that `.State.Pid` reported
  complete.
- **Reach for the control before the alarm.** "Was this already failing on the
  base branch?" flipped "CI refutes our fix" into "a pre-existing defect".
- **Before explaining an observation, confirm the code that produced it was in
  the measured commit.** Three wrong root causes came from a log whose build
  predated the fix being discussed.
- **A missing measuring instrument silently rewrites every other number.** A
  branch advertised as "base + stall-detector + winner-rule" lacked the stall
  detector — the component producing the hang count being quoted.
- **Model protocol questions in Python first.** `experiments/py/hairpin_probe.py`
  and a signaling probe each answered in seconds what a build-plus-CI loop
  answers in twenty minutes.
- **"This change cannot affect anything" is a claim about the diff, and a diff
  cannot tell you what a file is FOR.** I twice told the user to merge the
  proof PR immediately because it was proofs-only. True of its contents, false
  of its role: a merged proof is a standing assertion, the same file unmerged
  is a document. Same bytes, different role, and **only the role can rot**. Its
  calibration was about to describe a world the next PR removed. Expect the
  next agent to read a proofs-only diff and reach the same wrong conclusion.
- **Test that the prescribed REMEDY clears the failure, not just that the
  detector fires.** Almost everyone tests a detector against the bug and stops.
  Checking the fix actually worked is what exposed that my expiry check's only
  possible remedy was deleting itself, and then that its replacement remedy was
  a one-line fake.
- **A comment is a claim with no enforcement.** Two defects this week were
  mechanisms that *said* they did something: the offer site promising "the
  Signal handler re-emits ChannelReady" (it never has, a teardown was standing
  in for the dispatch, and that was the whole macOS wedge), and `l3.rs`'s
  "monotonic announce sequence so a peer can ignore a stale re-announce" (the
  seq is signed and no receiver ever compares it). **A signature over a field
  creates a strong presumption that someone verifies it** — grep for the
  consumer before believing it.
- **An invariant maintained by convention at N call sites will be missed at
  call site N+1**, and no test that gives each daemon its own config dir can
  ever catch a same-install filter. Put it in the type or in the signature.
- The recurring error shape, in one line: **a query narrower than the claim it
  supports, where the narrowing is invisible in the result.**
