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

Exit codes: 0 clean, 1 hard finding, 3 refused (a precondition is unmet, so
there is no result), 4 the canary was not detected (the instrument is broken).

## Findings

Each finding is a directory under `chaos-results/<job>/out/findings/<id>/`
with `schedule.json` (replay it with `replay <file>`), `verdict.json` (which
rule fired, every operation's exit code and stderr, every fault and whether it
bit) and every daemon's log. To keep a finding as a regression test, copy its
`schedule.json` into `corpus/` with an `origin` line saying what it caught.

## Retiring a hand-written gate

Only when reverting that gate's original fix makes `replay` of the matching
corpus schedule go red. Until then both run.

## Unit checks (no root, no machine)

    python3 -I fuzz/chaos/chaos.py selftest
