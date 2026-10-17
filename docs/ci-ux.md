# tunlion for CI: the contract, and where the UX hurts

Status: first pass, 2026-10-17. This describes the CI caller, not the human one.
It exists because `.github/workflows/ci-dogfood.yml` runs the whole pipeline
through tunlion and the friction showed up in the order below.

## The shape

A CI box is a temporary machine with no account, no SSH, and an outbound network
only. It joins the mesh with a bounded invitation, receives a job, runs it, sends
the artifacts back, and dies.

```
# owner, once per pool
tunlion add --for runner --reuse 20 --expires 30m --out pool.inv

# the box
tunlion join pool.inv --name ci-<run>
tunlion up --detach --dir "$WORK"        # receives into $WORK, stays connected
# wait for the job payload to land in $WORK
# run the declared command
# send the bundle back
tunlion send bundle.tar --to <owner-device> --timeout 600 --json
tunlion down -y
```

That works today. The rest of this file is what it costs.

## What a CI caller needs from the CLI

1. **No prompts, ever.** Everything must work at a non-TTY. Mostly true:
   `--no-interactive`, `-y` where confirmation is needed, `--json` on the verbs
   that carry it.
2. **Bounded waits.** A job that hangs burns the whole workflow. `send` has
   `--timeout`; `receive` and `up` do not, so a CI script has to wrap them in
   `timeout(1)`. That is the single most annoying gap.
3. **A verifiable result.** The caller needs to know the bytes arrived intact.
   There is no `--expect-sha256` and no manifest, so every caller reimplements
   hashing and comparison.
4. **One job, then exit.** `receive` is one-shot by default (good), but there is
   no "wait for one payload from this sender, for at most N seconds, and tell me
   what arrived".
5. **A way to wait for a peer.** The owner cannot say "block until the runner
   joins". It polls `tunlion devices --json`. That is a loop in every script.
6. **Cleanup.** A dead box leaves a record the owner must forget, and an
   invitation cohort has no single "retire this file and stop its renewals"
   action.
7. **Error text for machines.** The exit-code table in
   `cli/skills/tunlion/SKILL.md` is good. What is missing is an exit code for
   "nobody arrived before the deadline" distinct from "the peer went away".

## What the dogfood run actually does

`ci-dogfood.yml` is dispatched by `scripts/ci-dogfood.sh`. The owner mints one
single-use runner invitation, sets it as the `TUNLION_INVITE` secret, dispatches,
waits for the device to appear, and sends a payload tarball. The box joins, runs
`up --detach --dir`, waits for the payload, executes `job.json`'s declared
`cmd`, bundles the outputs with their hashes, and sends one bundle back. The
owner verifies `sha256sum -c` and prints the build info.

The point is not that a CI box can build; it is that the transport, the admission,
the execution and the return trip are all tunlion's, and the result is checkable
on both ends.

## The fix list, in order

1. `receive --timeout <secs>` and an exit code meaning "deadline, nothing
   arrived". Removes the `timeout(1)` wrapper from every caller.
2. `receive --expect-sha256 <hex>` (and `--expect-name <name>`): refuse to report
   success unless the received bytes match. Removes hand-rolled verification.
3. `up` has no `--json`. A CI box starts the daemon and then has to poll
   `status --json` to learn whether it came up, because `up --json` is refused as
   unimplemented (exit 2). Either give `up` a machine-readable result or make
   `up --detach` print the daemon pid and state.
4. `tunlion wait <device> --timeout <secs>`: block until a named device is
   online. Removes the `devices --json` polling loop.
5. `receive --json` should end with one object naming every file it wrote and its
   sha256, so a caller has a manifest without hashing again.
6. A cohort action: retire an invitation and stop renewal for every device it
   admitted. Today the record carries no provenance, so this needs the field
   first.
7. A `tunlion job` verb wrapping (2)+(3)+(4) and the manifest, so the box side is
   one command instead of a script.

## What is deliberately out of scope

- General-purpose command execution on CI runners. The workflow takes an
  enumerated job spec, never an arbitrary command string.
- Secrets in argv. Invitation material arrives as a secret written to a `0600`
  file and is passed by path, as everywhere else.
- Replacing the runner in `runner/`. That one is for long-lived boxes with
  planted secrets; this is for boxes that join, work, and die.
