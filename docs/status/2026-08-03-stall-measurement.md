# Stall Detector Measurement Finding

## Scope

Commit `0f9d031` is the `Transport::idle_ms_tracked` single-sample fix. It is
not the stall detector as a whole. A passing measurement would license a claim
about this idle-sampling input path, not the complete production detector.

## Finding

The detector cannot currently be measured by an instrument that exists.

The old instrument, `runner/sim/data_freeze_test.sh`, is unreferenced by the
GitHub workflows. Its last changes are in the older P0/verbosity history
(`0c39902`, `0fdbb38`), not alongside the maintained capability harness. A run
with the built detector binary failed during setup before the freeze engaged:

```text
sender: no peer connected within 60s
receiver: code rejected: invalid, codes burn after one use
```

This is the third instance found today of an instrument that exists on disk but
is not part of a maintained execution path.

The maintained `cli/tests/capability_harness.rs` runs in Capability CI, but its
transfer path uses blocking `wait_with_output`. It has no cross-platform child
timeout or live log capture. Consequently it cannot distinguish a detected
stall that never recovers from a child that simply hangs. Adding a freeze test
without those capabilities would produce an unverifiable result.

## Required Classification

A future capability-harness measurement must report these states separately:

1. Armed marker absent: **UNCLASSIFIED**, instrument absent.
2. Armed marker present, freeze absent: **UNCLASSIFIED**, no stall injected.
3. Armed marker and freeze present, no stall event: **FAIL**, detector ran and missed.
4. Armed marker, freeze, and stall event present, no completion: **DETECTED_NOT_RECOVERED**.
5. Armed marker, freeze, stall event, and verified completion: **PASS**.

The independent `STALL_WATCHDOG_ARMED idle_ms_tracked` marker is required. A
detection marker alone cannot distinguish an absent detector from a detector
that ran and missed.

## Limits

Even a valid measurement would not establish that recovery works without the
test hook, or that an uninstrumented production stall is detected.
