# Chaos fuzzer (stage 1)

Real tunlion daemons, real kernel networking, faults on a schedule, rules
checked after every heal. See the module docstring of `chaos.py` for the
design; this file is only how to run it.

## Run

From the owner box, against a leased test machine (never on the owner box):

    fuzz/chaos/run-on-lease.sh <worker> canary           # does the instrument work?
    fuzz/chaos/run-on-lease.sh <worker> replay           # every schedule in corpus/
    fuzz/chaos/run-on-lease.sh <worker> explore --budget-min 60

`replay` and `explore` run the canary once, on world 0, while the other
worlds already work; if it fails the whole job exits 4.

One job runs several independent worlds at once (`--worlds N`; default 2 per
core, at most one per GiB available, at most 16). Each world has its own
slot: namespaces `chz<k>_*`, subnet `10.(90+k).0.0/16`, backend port
`8155+k`, chains `CHZ<k>*`, lock `/run/tunlion-chaos.slot<k>.lock`, so two
jobs can share a machine as long as slots are free. `throughput.json` in the
results records runs per hour and the machine's load.

The campaign runs detached on the worker (its own session and log), so a
dropped `tunlion exec` link does not end it: `run-on-lease.sh` reattaches,
follows it to the end and fetches the results.

### Build

The script builds the daemon with the `fuzz` profile (root `Cargo.toml`): no
LTO, incremental, workspace code at -O2 and dependencies at -O3, line tables
kept. On a 4-core lease, after the first build, a one-line change rebuilds in
about 22 s (in `cli/`) or 7 s (in `crates/filament-peerloop`), against 280 to
320 s for `--release`. To keep it that fast, the worker keeps ONE source dir
(`src-stable`, updated with `rsync --checksum` so unchanged files keep their
mtimes) and ONE target dir, and you should keep using the same worker: a new
lease starts cold (about 400 s), or, when the worker workflow restored
`cargo-target` from the Actions cache, rebuilds only the workspace crates
(about 190 s when the dependencies are already built).

Knobs, each part of the binary cache key:

    CHAOS_PROFILE=release   the shipped fat-LTO build (minutes per rebuild)
    CHAOS_FEATURES="a b"    extra cargo features on top of test-hooks
    CHAOS_RUSTFLAGS=...     e.g. "--cfg tokio_unstable"; gets its own target dir
    CHAOS_SYMBOLS=1         line tables and no strip (already so for `fuzz`)

Exit codes: 0 clean, 1 hard finding, 3 refused (a precondition is unmet, so
there is no result), 4 the canary was not detected (the instrument is broken).

The baseline runs before any fault. A daemon that is RUNNING but has not
answered its control socket 60 s after start is a hard finding
(O3-unresponsive-at-start, with its thread dump), not a refusal: no fault was
injected, so the product is at fault, not the fixture. An exited daemon or a
signaling link that is down still refuses, naming which. (Until 2026-11-26
every case refused as "signaling not ready ... noanswer"; the cause was the
daemon misreading /proc/locks under lock churn and not serving its socket.)

## Coverage carries over

`explore` keeps a schedule only when it reaches a behaviour (a daemon log
line reduced to its kind: timestamps, numbers, paths, quoted values, hex and
session ids replaced; task and thread dump lines ignored) that no campaign has
reached before. The behaviours already covered are in `seen.json`, and the
schedules that reached them are in `corpus-grown/`, which `explore` seeds
from. After a campaign, fold it back in so the next one starts where it
stopped instead of re-covering the same cases:

    python3 -I fuzz/chaos/absorb.py chaos-results/<job>/out
    git add fuzz/chaos/seen.json fuzz/chaos/corpus-grown && git commit

The summary's `new_behaviours` is what the campaign added. A campaign that
adds little is a sign the mutator, not the product, has run out of ground.

## Findings

Each finding is a directory under `chaos-results/<job>/out/findings/<id>/`
with `schedule.json` (replay it with `replay <file>`), `verdict.json` (which
rule fired, every operation's exit code and stderr, every fault, its window and
whether it bit) and every daemon's log. An explore finding's `schedule.json` is
the MINIMIZED schedule, while the logs and `verdict.json` come from the run that
failed first; when minimization dropped a fault, that run's schedule is in
`run-schedule.json` (`verdict.json` names it as `schedule_of_this_run`). Read
the logs against that one: a fault it holds is absent from `schedule.json`. To keep a finding as a regression test, copy its
`schedule.json` into `corpus/` with an `origin` line saying what it caught.

## Visitors

A `visit` op brings a transient device through a world: a fresh namespace
joins with the run's reusable runner invitation (alpha mints one per run with
`add --for runner --reuse <visits+1>`), runs `up`, proves alpha answers it
(`reach alpha`), optionally sends one file (`"act": "send"`), stays `stay`
seconds and vanishes with no goodbye (its traffic is dropped before its
processes die, so not even a FIN leaves). Visits run like any op, so they can
be sequential or overlap:

    {"at": 2.0, "op": "visit", "src": "alpha", "dst": "vis1", "stay": 5.0, "act": "none"}

A schedule with visits turns on alpha's debug log and adds two rules:

- O12-redial-departed: in the 150 s that start 5 s after the last visitor
  left, alpha must not establish any peer id other than a live device's more
  than MAX_ATTEMPTS (5) times: the stuck-retry ladder gives up after that.
- O13-enrollment-starved: one more visitor, after all of them left, must enroll
  within 60 s and be answered; so must any visitor that comes after another one
  engaged.
- O14-failed-unfaulted: an op that ran with no fault active, nor one healed within 30 s before it, must succeed (hooks are recoverable by definition)

A visitor that cannot engage before any other visitor did refuses the run, as
does a missing ESTABLISH line in alpha's log (the rule would be blind).
`corpus/transient-visitors-sequential.json` is the 2026-11-26 production case.

## Sends to stdout

A send op with `"via": "stdout"` runs `send <file> --word ...` on `src` and a
one-shot `receive <code> -y -o -` on `dst`, reading its stdout slowly so the
pipe fills (the shape of gate T3). Stdout cannot be rewound, so O7
(false success) judges what the reader got: either end exiting 0 while those
bytes are not the source file is a finding. `random_op` picks it for about a
third of sends; `corpus/send-stdout.json` is the T3 case.

    {"at": 1.0, "op": "send", "via": "stdout", "src": "alpha", "dst": "bravo", "kib": 5120}

## Exec variants

The delegates grant each other shell at setup, so an exec goes to the owner
(a paired device) or to the other delegate (a fleet sibling). Flags vary it;
`random_op` draws each blindly, so explore reaches them like any op:

- `"oneshot": true`: the command runs as a ONE-SHOT dialer, with a copy of the
  device's config dir minus the daemon's runtime files (so no control socket
  to ride or to broker through) and `TUNLION_NO_WARM_REUSE=1`: a machine with
  no `up`, as on Windows. To a sibling it dials the fleet secret.
  `corpus/exec-oneshot-fleet-sibling.json` is the Revoke Gates sibling-shell
  case (#757), `corpus/exec-from-degraded-machine-oneshot.json` the #749 one.
- `"out_mib": N` (with `"stall_s"`): the command cats N MiB of random bytes on
  `dst`, and the CLI's stdout on `src` is read slowly (it stops `stall_s`
  after the first 4 MiB, then reads at 8 MB/s). The output must arrive whole
  and byte-exact with rc 0 (O7 judges a 0 with other bytes). The hang rule for
  a stream is no progress for the op's deadline, with a 600 s cap.
  `corpus/exec-bulk-output-slow-reader.json` is the #760 case.

    {"at": 35.0, "op": "exec", "src": "bravo", "dst": "charlie", "oneshot": true}
    {"at": 35.0, "op": "exec", "src": "bravo", "dst": "alpha", "out_mib": 40, "stall_s": 15.0}

## Retiring a hand-written gate

Only when reverting that gate's original fix makes `replay` of the matching
corpus schedule go red. Until then both run.

## Unit checks (no root, no machine)

    python3 -I fuzz/chaos/chaos.py selftest
