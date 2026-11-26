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

## Findings

Each finding is a directory under `chaos-results/<job>/out/findings/<id>/`
with `schedule.json` (replay it with `replay <file>`), `verdict.json` (which
rule fired, every operation's exit code and stderr, every fault and whether it
bit) and every daemon's log. To keep a finding as a regression test, copy its
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

A visitor that cannot engage before any other visitor did refuses the run, as
does a missing ESTABLISH line in alpha's log (the rule would be blind).
`corpus/transient-visitors-sequential.json` is the 2026-11-26 production case.

## Retiring a hand-written gate

Only when reverting that gate's original fix makes `replay` of the matching
corpus schedule go red. Until then both run.

## Unit checks (no root, no machine)

    python3 -I fuzz/chaos/chaos.py selftest
