# 2026-08-04 session handoff

Written to survive the session. If you are picking this up cold, read the
RELEASE section first, then OPEN FINDINGS. The METHOD section is the most
transferable part and the reason most of the rest happened.

---

## RELEASE: what blocks the tag

A release is wanted and is gated on finishing the tasks below. Everything not
listed here is explicitly NOT release-blocking.

> **NUMBERING WARNING, read before citing anything.** Numbers in this document
> are GitHub PRs unless a line says otherwise. There is a separate internal
> task tracker whose numbers OVERLAP and do not correspond. GitHub issue #64 is
> a winget-schema ticket, not the mount bug, and an earlier draft of a registry
> entry nearly cited it as such. The three real issues opened today are:
>
> - **#135** mount: non-UTF-8 filenames are not enumerable through the mount
> - **#134** nat-cone-gate: the emulation drops peer checks, so the gate is not
>   a product signal
> - **#133** ack-loss-repro: assign an actionable verdict
>
> Cite those, never a task number.

**BLOCKING, one item:**

- **mount gate 3, non-UTF-8 filenames through the mount.** Two server-side
  conversions in `safe_open_beneath` (`mount_proto.rs` 937 and 995) refused or
  emptied non-UTF-8 components. Both fixed; `cat` now returns the raw bytes
  exactly. **Directory enumeration still fails**: `find` reports EINVAL and
  finds nothing. rig-verifier owns it and is instrumenting `readdir`.
  The binary-identity check is done (`/proc/<pid>/exe` sha256 matches the
  instrumented build), so the silent instrumentation is a REAL null result,
  not a wrong-binary artifact.
  Decided in advance: marker present means the entry is lost after readdir is
  entered; marker absent means EINVAL comes from before our callback, and the
  search moves to `opendir` and the directory `getattr`.

**AT THE TAG, one check that is owed and would otherwise be lost.** Before
cutting, ask claude-advisor whether anything in the release notes overstates
what shipped. I asked them for this and they accepted; the request existed only
between us and I am leaving, so it is written here instead. This is the same
shape as the deferral recorded in the 0.7.2 release notes that nothing tracked,
and it would have failed the same way.

**NOT blocking, do not let them delay the tag:** the cone-NAT investigation,
the stall-ladder model, the 6.0s figure, the branch audit, the fmt gate, the
alert-path test email, the kernel upgrade, the swap threshold.

**The changelog is already release-ready.** `CHANGELOG.md` `[Unreleased]`
carries the security entry with corrected scope. `.github/workflows/cli-release.yml`
now builds release notes FROM the changelog (#120), so whoever cuts the tag
renames `[Unreleased]` to the version and the notes carry it automatically.
Nobody has to remember anything.

Security is verified release-ready at `b06b11e` by claude-advisor: entry on
main with the corrected two-row platform table, fix on main with 25 reparse
guards, and NO unguarded `.part` open remaining on either platform.

---

## MERGED TODAY (29 PRs)

Product and security:

- **#113** Windows `.part` reparse hardening. **The exploit is demonstrated,
  not inferred**: unhardened code returned `Ok(File)` whose resolved handle
  path was OUTSIDE the download directory. Affects EVERY released version;
  all platforms through 0.7.1, Windows only from 0.7.2 (the unix arm was
  hardened in 0.7.2 and the Windows half was deferred and never closed).
- **#118** Windows `--shell-user` now REFUSES instead of silently ignoring.
  It was a no-op that also DISARMED the owner-equivalence gate and printed a
  note claiming a drop that never happened.
- **#122** raw-byte `InodeMap` keys. Two distinct non-UTF-8 names collided to
  one inode; two files in a mount became one, silently.
- **#108** `pair` mints a 4-digit nameplate so its own router classifies it as
  pairing.
- **#119** startup discloses grant-enabled shell.

Instruments and evidence:

- **#109** ESTABLISH (`#[track_caller]`), ADOPT, STALL-LADDER-EXHAUSTED markers
- **#114** records that the sender's caller line separates fallback from
  adoption and **the receiver's does not** (it goes through `maybe_adopt`)
- **#116** `.context` on both `expired_direct` callers
- **#124** the harness now PRINTS the child output it captures. It used to
  panic without printing, so absence from its log meant nothing.
- **#127 / #130** stall-ladder model, now the FOURTH required proof gate, with
  a coherence guard that reads `MAX_ATTEMPTS` and `WATCHDOG_SECS` from source
  and fails on drift (verified in both directions).
- **#128** warning-ratchet: `|| true` swallowed a compile failure so a tree
  that does not build scored zero warnings; a missing baseline became 9999.
- **#132** the `measure` profile plus `docs/feedback-loop.md`.

Operations:

- **#112** both monitor timers INSTALLED on the droplet. `filament-monitor.timer`
  had been committed since 2026-06-27 and never installed.
  `install-timers.sh verify` requires a SCHEDULED NEXT ELAPSE, and has caught
  an enabled-and-active-but-never-firing timer on **both** occasions it has run
  against a fresh install.
- **#123** memory-pressure monitor, debounced on two consecutive breaches.
- **#120** release notes are generated from the changelog.

---

## OPEN FINDINGS, with exact status

| item | state |
|---|---|
| mount gate 3 | BLOCKING. Third site is readdir/listing. See above. |
| cone NAT gate | Failure LOCATED in the emulation: checks cross the WAN (256 packets, both directions), no client namespace receives any, conntrack reply tuples match and stay UNREPLIED, `rp_filter=2` and `ip_forward=1` everywhere including the WAN. **Retired as product evidence in either direction.** Record in `docs/testing-nat-cone-gate.md`. |
| the original real-NAT pairing failure | **UNTOUCHED.** Real internet, real STUN, production binary. Nothing from the lab work bears on it. |
| stall ladder | SPLIT. ICE/conntrack half CLOSED by arithmetic: the kernel expires an UNREPLIED UDP conntrack entry at 30s, the ladder runs 5×15s=75s, so the entry is gone before rung 3 — and an unreplied entry earns the 120s timeout only by RECEIVING A REPLY, which is exactly what fails. **The ladder retries against a precondition its own duration destroys.** QUIC fd/port half and the data-freeze case remain open. |
| the 6.0s fallback figure | ANSWERED. `total = 1.20 × DIRECT_BUDGET`, confirmed at budgets 1s, 2s and 5s (1.2028 / 2.4037 / 6.0069, spreads under 2ms). It is a **chosen deadline**, not the fallback's cost. The designed route won 10/10 in the forced-block scenario. No change proposed; whether 5s is right needs an argument about real networks a loopback harness cannot supply. |
| `mount-gates.sh` runs nowhere | 19 orphans found by top-level inventory, 31 by recursive enumeration of the semantic roots. Mechanism 1 is being built for this. |
| monitor alert path | Key readable, all five outcome paths stub-tested, **delivery never proven**. Closing it means one test email; the user's call. |
| `safe_open_part` | ZERO production callers. The vulnerability IS fixed because the two guarded helpers are the production paths; what is overstated is coverage. Give it a unix arm and a caller, or delete it with its test. |
| kernel upgrade | 6.8.0-134 running, 6.8.0-136 expected. Reboot takes down signaling, every agent session and any build. The user's call. |
| box shape | ~3.9 GB of agent runtimes resident before any build, on 4 cores / 8 GB. Three resource incidents in three days. Not solvable by scheduling. |

---

## THE FEEDBACK LOOP, measured

```
cold release + test-hooks             9:33     RSS 1.806 GB
touch-one-file rebuild, release       5:01     RSS 1.808 GB
same, sccache OFF                     5:10     (2.9%, inside noise)
cold, measure profile                 8:52     RSS 1.736 GB
touch-one-file, measure profile       6.66 s   RSS  803 MB
```

**Inner-loop floor 3 minutes** (6.66s rebuild + the ~150s #31 run).
**Outer-loop floor 7 minutes**: not theoretical, Capability CI already produced
a complete Windows result in 6:57 while the Test workflow's Windows step took
10:01 to run a binary that executes in 2.15 seconds.

Rejected with measurements, not opinion: **nextest** (unit execution is already
~2s), **sccache tuning** (2.9% inside noise locally; 0% hit rate on our own
crate in CI), **mold** (already in use, already in the 5-minute number).
Crate extraction is real but third: `main.rs` is 18,074 of 46,707 lines.

A named profile gets its own artifact directory, so **the first `measure` build
is cold (~9 min) and 6.66s is the second onward.** Someone who tries it once,
waits nine minutes and concludes it does not work is the failure mode.

**No timing claim may be quoted from the measure profile.** This is enforced,
not documented: the binary stamps its profile into `--version`, and the
fallback timing gate exits nonzero with UNCLASSIFIED rather than passing when
built under measure.

---

## METHOD: the class behind the instances

Four classes, from deep-wisdom's analysis. The unifying statement:
**evidence is open-world, so absence reads as success.**

**A. Artifacts that exist and execute nowhere.** Six found one at a time today;
31 in scope once enumerated recursively. Being in the repo and being wired are
two different facts and only one is visible in a diff.

**B. Lossy conversions in a codebase whose spec forbids them.** `InodeMap`,
`mount_proto` 937 and 995, natprobe's permissive STUN parsing.

**C. Claims with no enforcement.** The nine mechanisms removed this week,
`--shell-user` on Windows, the signed announce seq nobody verified.

**D. Instruments that confidently answer an adjacent question.** The expensive
one. claude-advisor's formulation is the one to keep:

> Each returned a WELL-FORMED answer to a question ADJACENT to the one asked.
> None malfunctioned. At one degree off, the output still looks exactly like
> evidence.

Instances, most of them mine:

| instrument | what it actually asked |
|---|---|
| `fuser -m <dir>` | the mounted FILESYSTEM, not the directory |
| WAN source-port correlation | compared a NAT-TRANSLATED port to an untranslated one |
| `NextElapseUSecRealtime` | CALENDAR timers; these are monotonic |
| a local `false \| tee` demo | bash, not GitHub's `shell: bash` |
| grep for "reparse" per tag | returns zero on tags predating the code |
| `git tag ... \| tail -12` | twelve of seventy-two, truncation invisible |
| a pinned worktree, not re-pinned | history, while believing it is main |
| a task-tracker number as an issue ref | a different tracker entirely |

**The only defence that worked: a differently-SHAPED second query.**
"Run the check again" never catches these. Two of the three worst were caught
only because a second query disagreed with the first.

Other rules earned today:

- **A threshold crossed once is a sample; crossed repeatedly is a state.**
  Sample three times before acting. A single 13 MB swap reading halted five
  agents on a transient.
- **Phrase a review hold as a QUESTION, never as the outcome you expect.**
  A hold stated as "show me EROFS" cannot clear against a system designed to
  write, and never explains why.
- **A test that has never been shown to FAIL has unmeasured discriminating
  power.** `is_err()` on `create_new` against an existing junction could never
  go red. The rebuilt symlink assertion could, and did.
- **Test that the prescribed REMEDY clears the failure**, not just that the
  detector fires.
- **A false POSITIVE of the right shape is worse than a false negative**,
  because its natural response is to do nothing.

---

## WHO IS DOING WHAT (as of handoff)

- **rig-verifier** — mount gate 3 readdir instrumentation. Has the build token.
  RELEASE-BLOCKING.
- **deep-wisdom** — Mechanism 1 phase 1: a registry with five closed
  dispositions (`required`, `diagnostic`, `retired`, `operational`, `support`)
  and a **fail-closed** enumerator. Roots encoded in the VALIDATOR, not in
  registry data, so the registry cannot narrow itself. Authorised to create
  three real GitHub issues for the diagnostics. Not release-blocking.
- **new-renewer** — `#131`'s flaky test. Fix is now test-only: a
  `#[cfg(test)] CAP_GATE_TEST_LOCK` taken by all 11 tests that call
  `cap_gate_effective`. Production untouched. Queued for the token.
- **optimizer, opencode-101, filament-new-guy** — idle by instruction, holding
  no release-blocking work.
- **claude-advisor** — security verified release-ready; other items parked
  until after the tag.

**claude-advisor's review role does not derive from the coordinator and does not
lapse with one.** The user confirmed it first-hand on 2026-07-27 and it has run
continuously since. An incoming coordinator inherits a correspondent, not
authority over the gates, and advisor will treat a relayed instruction the way
they have treated every other relayed claim: by checking it. That is not a
challenge, it is how they work, and it is better read here than discovered.

**The build token is coordinator-held: ONE build at a time.** Release the slot
only when `pgrep -x cargo` and `pgrep -x rustc` are both empty, and gate on
HEADROOM (available minus the incoming build's ~1.2 GB peak) rather than on a
swap-free number, whose floor is set by resident runtimes and cannot be lowered
by anyone waiting.

Persistent per-worktree targets are load-bearing for the 6.66s loop and are
bounded: active branches or in-flight PRs only, merged work sweepable, 15 GB
reserved, cap `min(8, floor((available_GB - 15) / 2.6))`. Sweep procedure:
broadcast the delete list, five-minute objection window, owners speak up.
That worked cleanly for 53 GB this morning.
