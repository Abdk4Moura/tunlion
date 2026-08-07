# 2026-08-06 session handoff

Continues `2026-08-04-session-handoff.md`. Read the RELEASE section first if you
are picking this up cold. The METHOD section is again the transferable part, and
this time it includes three instances committed BY the people cataloguing the
pattern, which is the finding rather than an embarrassment.

---

## RELEASE: 0.7.7 is TAGGED but NOT PUBLISHED

    tag        cli-v0.7.7 -> e213591be402488ef1b9d4838e97f54778b30e87
    release    DOES NOT EXIST
    cause      GitHub Actions major outage. No workflow run was created for
               this repo, for ANY ref, during the window.

Nothing is wrong on our side. The workflow is active, the trigger is present at
the tagged commit, the repo is public with Actions enabled.

**To finish it: run `/root/retrigger-0.7.7.sh`.** Do not do it by hand. The
script exists because a delete-and-recreate is the one moment the tag can
silently move: `git tag cli-v0.7.7` with no argument pins to HEAD, and if HEAD
has advanced the release publishes notes nobody reviewed, with nothing failing.

It refuses on four guards: a release object already exists, Actions is not
operational, the approved commit is missing, or a run for the ref is already
live or succeeded. Guards 1, 2, 3 have been shown to fire. **Guard 4 is
unmeasured** and recorded as such.

**Blocked until Actions returns: every merge.** Required checks cannot run, so
nothing goes green. PR #147 (the #131 lock) and the `task/monitor-install-parity`
branch are both waiting on this, not on review.

**The command-surface freeze runs until PUBLISHED, not TAGGED.** deep-wisdom's
CLI redesign rewrites `mount`, `send`, `receive`, `id` and the front door, which
the notes describe. Nothing describing that surface differently may land on
main — code or docs — until the release object exists.

---

## MERGED TODAY

- **#137** executable artifact registry, fail-closed, 31 artifacts classified
- **#138** preserve non-UTF-8 mount paths (raw bytes to the syscall)
- **#139** delete `safe_open_part`, which had zero production callers
- **#140** monitor alerts: set a `User-Agent`, and change the destination
- **#141** three changelog corrections found by claude-advisor
- **#143** the changelog entry #138 shipped without
- **#144** restore mount directory enumeration — the release blocker
- **#145** ack-loss repro now asserts a verdict
- **#146** changelog for the enumeration fix and the `RESOLVE_BENEATH` correction

---

## THE RELEASE BLOCKER, AND WHY IT HID FOR FOUR RELEASES

`ls` and `find` over a mount returned `EINVAL` and enumerated nothing, for
**every** filename.

```rust
how.mode = if (flags & (libc::O_CREAT | libc::O_TMPFILE)) != 0 { 0o644 } else { 0 };
```

`O_TMPFILE` is `0o20200000` — a multi-bit constant that **contains**
`O_DIRECTORY` — tested with `!= 0`. So every directory open sent a non-zero mode
without `O_CREAT`, which `openat2` rejects with `EINVAL` as documented. File
opens carry no `O_DIRECTORY` bit, kept mode 0, and worked. That asymmetry is why
reading a known path succeeded while listing its directory did not.

Broken in 0.7.3 when the call site moved to `openat2`. **Masked** until 0.7.6 by
a NUL-termination bug in the same call that failed earlier with `EFAULT`; fixing
that unmasked this. Two defects at one call site where fixing the first revealed
the second.

**It hid because no test enumerated a mounted directory.** `mount-gates.sh` had
six gates; the only one that listed anything was the non-UTF-8 name gate, and the
`ls -A` in the teardown gate runs *after* unmount and passes by being empty. So a
total enumeration failure could only ever present as a name-encoding problem, and
it did: the issue was titled "non-UTF-8 filenames are not enumerable" until an
ASCII-only control was run. Gate 1b now lists a plain ASCII directory.

**The generalisable move**: the fix came from a control designed to disprove the
current framing, not from deeper investigation of it. One command settled it.

---

## `RESOLVE_BENEATH` WAS NEVER APPLIED, AND WAS NOT A VULNERABILITY

The constants were declared as `RESOLVE_BENEATH = 0x02` and
`RESOLVE_NO_MAGICLINKS = 0x04`. Those values are really `NO_MAGICLINKS` and
`NO_SYMLINKS`. `RESOLVE_BENEATH` never reached the kernel, 0.7.3 through 0.7.6,
while a comment on the non-Linux arm stated Linux was relying on it.

**No release was exposed.** Peer paths are normalized and rejected by a lexical
`starts_with(root)` guard before the syscall, so no `..` component ever reaches
it, and the value set by mistake was `NO_SYMLINKS`, which is *stricter* on
symlinks than `RESOLVE_BENEATH`. Every vector it would have covered was covered
by something else. Filed **Fixed, not Security**, with no affected-versions
table, because a table invites readers to determine whether they were exposed
and the answer is nobody.

**The trap in the fix**: `safe_open_beneath` is shared with `safe_create_part`
and `safe_resume_part`, the `.part` write paths this release's Security entry is
about. Correcting the flags is a *permissive* move there — `BENEATH` allows
symlinks that stay beneath the root where `NO_SYMLINKS` refused all of them. The
first version of the fix would have made the shipped Security entry false on
Linux the moment it shipped. The resolve set is now a per-call-site parameter,
and the `.part` sites carry a comment saying *do not unify these without the
security entry*.

---

## METHOD: the pattern, and three instances committed by its own cataloguers

The 08-04 doc named class D: instruments that confidently answer an adjacent
question. This session sharpens the statement and then demonstrates that knowing
it confers no immunity.

> **A query that cannot DISTINGUISH the thing you are asking about from a
> neighbouring thing will confidently return the neighbour.** The neighbour is
> not an error. It is the correct answer to what was actually asked.

This is more useful than "answers an adjacent question" because it names the
cause — a missing discriminator — and therefore the fix. In every instance below
the discriminator was cheap once named. The expensive part was noticing the
question had a neighbour.

| instrument | missing discriminator |
|---|---|
| `gh run list --limit 1` | the ref. Read a six-day-old `cli-v0.7.6` success as 0.7.7 and announced a release that never happened |
| `grep -q` under `pipefail` | consuming all input. SIGPIPEs `systemctl`, so a PRESENT timer reads as NOT SCHEDULED. 23/80 false misses |
| `head -6` over sorted tags | the sample. Six alphabetically-first tags were uniformly lightweight, producing "every earlier tag is lightweight" |
| local-vs-remote tag count | the *filter*. Compared location when the difference was scope; the same filter on both operands cannot find a scope mismatch |
| the gate suite | any ASCII listing. Only the non-UTF-8 gate listed anything |
| monitor `send_alert` | a `User-Agent`. `check_health` set one and worked; the alert half never did |

**Three of these were committed by people who had spent the week cataloguing the
pattern, two of them inside messages describing it.** That is the finding. Knowing
the shape is not protection, and having *just* been caught by it is not either.
The only thing that has reliably caught these is a second person running a
differently-shaped query.

### Rules earned, beyond the 08-04 set

- **A mechanism observed only REFUSING has its entire working path unmeasured.**
  Refusal is the execution path that touches nothing, and it is the cheapest
  behaviour to demonstrate, so "I tested it" and "I watched it decline to act"
  feel identical from the inside. Derived jointly with claude-advisor after a
  guarded script was called verified on the strength of one guard firing — while
  the defect sat in the twenty unexecuted lines after it.
  - Corollary: for a mechanism whose purpose is a *rare recovery*, the working
    path may be unexecutable until it matters. The answer is not a cleverer
    test. It is reading it, by someone who did not write it.
- **When two numbers disagree, the reconciliation must vary the axis you
  suspect.** "I checked and they agree" is worth nothing until you can say which
  axis was varied.
- **Caution that declines to look is not caution.** Deferring to a second reader
  *adds* a reading; declining to run a test *removes* one. The first is
  sometimes wrong because it is slow. The second is almost always wrong.
- **Only the FIRST failing assertion in a test is ever observed.** Every
  assertion after it is unmeasured in exactly the run that was supposed to
  measure it. So order assertions by what you are trying to PROVE, not by the
  order the code does things. Found by opencode-worker on #148: their first red
  run panicked on the `Err` arm before the outside-state assertion could run,
  so the arm that proves the mutation actually landed had never executed, in
  red or green. The output looks identical either way.
- **A claim with no mechanism survives on politeness.** See the build token,
  below.

---

## OPEN, WITH EXACT STATUS

| item | state |
|---|---|
| 0.7.7 release | TAGGED, not published. Run `/root/retrigger-0.7.7.sh` when Actions is operational. |
| PR #147, #131 lock | Open, cannot merge. A/B proven: 2/60 failures without the lock, 0/60 with. |
| `task/monitor-install-parity` | Pushed, not merged. **Production runs `d5d9845`, which is NOT an ancestor of main.** Merge it after the tag so the deployed-commit stamp resolves on main. |
| #142, `join` ceiling | Open. `join` cannot express a bounded principal; a joined device is `OwnerDevice` (everything) or `Delegated` with an in-memory ceiling that vanishes on reconnect. Gates the redesign's `join`. deep-wisdom has agreed `join` stays ABSENT rather than shipping unbounded with warning copy. |
| build token | **A claim with no enforcement.** Nothing in the repo, filesystem or daemon knows who holds it. Two agents held contradictory beliefs about it today; only one build ran, and only because the other asked first. Needs a lock file plus a wrapper that refuses to exec cargo without it. |
| xats cursor skip | On re-register the daemon sets the new row's cursor to current max, silently skipping anything from the outage. `agents_identity_idx` is already unique on `(device, team, name)` — that is the key the cursor belongs on. The schema default is `0`, replay-everything, so skip-to-max is a deliberate override at one call site, not a missing feature. |
| agent_id ledger | Interim, per-agent. `/root/.xats-agent-ids-chief-ux.txt`. Implemented, one live clean run, discriminating power MEASURED via a synthetic row plus a negative control showing the message is invisible to an agent knowing only its current id. Degrades every time a new agent joins, since none can retrofit it. |
| #148, mount mutating ops | **Fixed on `design/mount-containment`, cannot merge.** Five handlers ran raw `std::fs` on a lexically-checked path, so a pre-existing symlink inside a share was followed and the write landed outside it. Now parent-dirfd + bare-name `*at`; `do_truncate` reuses `safe_open_beneath`, which is byte-for-byte untouched (verified by md5). Five tests shown RED on the outside-unchanged arms, then green. Write mounts only. |
| #149, config-dir key clone | **Fixed on PR #150, cannot merge.** `FILAMENT_CONFIG_DIR` set to a fresh path, from a shell with cwd `$HOME`, silently cloned the production identity into it — `migrate_legacy()` used a **cwd-relative** legacy path that resolved to the live config. Now refuses under an override and pins legacy to `home_dir()`. Regression test shown RED with keys actually appearing in the override. |
| kernel 6.8.0-136 | Not done. Owner asked for it before the release; deferred behind the release itself, then the outage. The reboot takes down signaling, every agent session, and any build. |
| Claude Code reaping | **Fixed for chief-ux only.** `/root/xats-heartbeat-chief-ux.sh`, a detached pinger, closes the gap CLAUDE.md records as "fix pending". Five reaps in under an hour before it; none after. It re-reads the agent_id each cycle rather than capturing it, so it survives the id changing. Every other CC agent on the bus still has this problem. |
| `is_err()` in the new symlink test | Weak assertion, the form rig-verifier themselves caught on #113. It discriminates today and was shown red. Assert the error kind if you touch it. |

---

## OPERATIONS

**Monitors now deploy to `/usr/local/lib/filament-monitor`** with the deployed
commit stamped, and `install-timers.sh verify` FAILS if a unit points into a git
worktree. Before this, production monitoring executed out of `/root/stunning-tribble`,
so a `git checkout` silently changed production behaviour with no deploy step.

**The alert path was dead for its entire life** until #140. All three monitors
POSTed to Resend with no `User-Agent`, so Cloudflare answered 403 (error 1010)
before the request reached Resend. Every alert they ever raised was discarded at
the edge, including during the three resource incidents. Delivery is now proven
end to end by an owner-confirmed test mail.

**The `verify` timer check was manufacturing its own findings.** `grep -q` under
`pipefail` false-missed 23/80. The 08-04 doc credits that check with catching a
dead timer on both occasions it ran; those were most likely this flake.

**Worktrees swept, 74 → 6.** The rule, since the distinction is easy to get
wrong: `git worktree remove` deletes a DIRECTORY, not a branch, so committed work
on a branch is never lost. Keep anything dirty; keep a detached HEAD reachable
from NO ref (removal orphans its commits); sweep the rest. Verify nothing has a
cwd inside a target, twice, the second time immediately before deleting.

Note for the next sweeper: this was **not** disk pressure — 2.0 GB against 46 GB
free. The 08-04 sweep of 53 GB was CARGO TARGET DIRS, a different operation
sharing the same name. The real reasons are legibility, git speed, and a stale
worktree being a place to read history while believing it is main.
