#!/usr/bin/env python3
"""Model the stall correction ladder, including what each rung destroys.

The ladder retries a stuck transfer five times, with a 15-second watchdog per
rung. This model does not assume that "stuck while connecting" has one cause:
transience and failure type are explicit environment parameters. A retry can
only benefit from a transient condition if it preserves the state that the
next attempt needs.

Run this file directly. Gate 0 first reproduces the observed #31, #50, and #38
outcomes before the model prints any recommendation.
"""
from dataclasses import dataclass
from itertools import combinations, product
import os
import re


MAX_ATTEMPTS = 5
WATCHDOG_SECS = 15
TRANSIENT, PERSISTENT = "transient", "persistent"
UNDETERMINED = "undetermined"

FAILURE_STATE = {
    "data-freeze": "transport",
    "ice-connect": "ice",
    "roster-re-adoption": "roster",
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def source_ladder_constants():
    """Read the ladder bounds from the Rust tree this model claims to describe."""
    main = open(os.path.join(ROOT, "cli", "src", "main.rs")).read()
    net = open(os.path.join(ROOT, "cli", "src", "net.rs")).read()
    attempts = re.search(r"const\s+MAX_ATTEMPTS:\s*u32\s*=\s*(\d+)", main)
    watchdog = re.search(r"pub\s+const\s+WATCHDOG_SECS:\s*u64\s*=\s*(\d+)", net)
    if not attempts or not watchdog:
        raise SystemExit("LADDER COHERENCE FAILED: could not find MAX_ATTEMPTS or WATCHDOG_SECS")
    return int(attempts.group(1)), int(watchdog.group(1))


def coherence_guard():
    source_attempts, source_watchdog = source_ladder_constants()
    if (source_attempts, source_watchdog) != (MAX_ATTEMPTS, WATCHDOG_SECS):
        raise SystemExit(
            "LADDER COHERENCE FAILED: source changed to "
            f"MAX_ATTEMPTS={source_attempts}, WATCHDOG_SECS={source_watchdog}; "
            "recalibrate this model before changing its constants"
        )
    print(f"COHERENCE: source MAX_ATTEMPTS={source_attempts}, WATCHDOG_SECS={source_watchdog}")


@dataclass(frozen=True)
class Environment:
    transience: str
    failure_type: str
    discarded_state: frozenset[str]


@dataclass(frozen=True)
class Result:
    recovered: bool
    attempts: int
    elapsed_secs: int
    terminal: str


def run_ladder(environment: Environment, attempts=MAX_ATTEMPTS) -> Result:
    """Run the ladder; return whether the ladder itself recovered the transfer."""
    required = FAILURE_STATE[environment.failure_type]
    for rung in range(1, attempts + 1):
        # A persistent condition never clears. A transient condition clears after
        # the first failed cycle, but only retained state can make that useful.
        condition_cleared = environment.transience == TRANSIENT and rung > 1
        state_available = required not in environment.discarded_state
        if condition_cleared and state_available:
            return Result(True, rung, rung * WATCHDOG_SECS, "recovered")
    return Result(False, attempts, attempts * WATCHDOG_SECS, "ladder-exhausted")


CALIBRATIONS = {
    # These observations establish the terminal shape, not transience. Both a
    # persistent condition and a transient condition whose required state was
    # discarded produce five failed rungs.
    "#31 data freeze": Environment(UNDETERMINED, "data-freeze", frozenset({"transport"})),
    # #50 directly observed new sockets, new mapped ports, and invalidated
    # conntrack state on every drop. Whether ICE itself was transient remains
    # unmeasured.
    "#50 NAT ICE": Environment(UNDETERMINED, "ice-connect", frozenset({"ice", "conntrack"})),
    "#38 roster re-adoption": Environment(UNDETERMINED, "roster-re-adoption", frozenset({"roster"})),
}


def gate_0():
    """Reproduce the observed terminal behavior before making recommendations."""
    expected = (False, MAX_ATTEMPTS, MAX_ATTEMPTS * WATCHDOG_SECS)
    failures = []
    for name, observation in CALIBRATIONS.items():
        for transience in (PERSISTENT, TRANSIENT):
            environment = Environment(transience, observation.failure_type, observation.discarded_state)
            result = run_ladder(environment)
            if (result.recovered, result.attempts, result.elapsed_secs) != expected:
                failures.append(f"{name} ({transience}): expected {expected}, got {result}")
    if failures:
        raise SystemExit("GATE 0 FAILED: model does not reproduce observations\n" + "\n".join(failures))
    print("GATE 0: PASS (#31, #50, #38 all exhaust 5 rungs without ladder recovery)")


def explore():
    """Show whether any modeled environment lets a later rung recover."""
    outcomes = []
    all_states = sorted(set(FAILURE_STATE.values()))
    discarded_states = [
        frozenset(subset)
        for size in range(len(all_states) + 1)
        for subset in combinations(all_states, size)
    ]
    for transience, failure_type, discarded in product(
        (PERSISTENT, TRANSIENT),
        sorted(FAILURE_STATE),
        discarded_states,
    ):
        result = run_ladder(Environment(transience, failure_type, discarded))
        outcomes.append((transience, failure_type, bool(discarded), result))
    return outcomes


def main():
    coherence_guard()
    gate_0()
    for name, observation in CALIBRATIONS.items():
        outcomes = [
            run_ladder(Environment(transience, observation.failure_type, observation.discarded_state))
            for transience in (PERSISTENT, TRANSIENT)
        ]
        external = "; #38 later recovery is external roster adoption" if name == "#38 roster re-adoption" else ""
        print(f"{name}: persistent={outcomes[0].terminal}, transient+discarded={outcomes[1].terminal}{external}")

    later_rung_successes = [
        row for row in explore() if row[3].recovered and row[3].attempts > 1
    ]
    print(f"TRANSIENT + RETAINED STATE: later-rung recoveries={len(later_rung_successes)}")
    print("OBSERVED FAILURES: indistinguishable between (a) persistent conditions and (b) transient conditions whose required state the teardown discarded.")
    print("SEPARATING MEASUREMENT: measure whether the transient window exceeds one watchdog rung while preserving the candidate's ICE/conntrack state.")
    print("#50 evidence: each drop destroyed ICE progress, sockets, mapped ports, and conntrack state; whether the underlying ICE condition was transient remains unmeasured.")
    print("RECOMMENDATION: do not raise MAX_ATTEMPTS or WATCHDOG_SECS until transience is measured; persistent failure favors fail-fast, transient+discarded state favors preserving state.")


if __name__ == "__main__":
    main()
