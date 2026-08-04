# Fast feedback without weak evidence

The CLI's `measure` profile exists for repeated functional experiments against
a real binary:

```sh
CARGO_TARGET_DIR=/root/.cargo-target-measure/<worktree-id> \
  cargo build --profile measure --features test-hooks -j2
```

It inherits the release profile, then uses `opt-level=1`, disables LTO and debug
information, and enables incremental compilation. Every binary includes an
explicit profile in `filament --version`, including `profile=release`. Timing
gates must print the profile beside every figure or fail as unclassified. The
capability fallback timing gate is deliberately red outside the release profile;
functional completion without its timing assertion is not latency coverage.

## Evidence boundary

Do not quote timing, throughput, resource use, binary size, or another
optimization-sensitive claim from `measure`. It is a different binary. Use it to
iterate on functional and causal behavior, then repeat every performance and
timing claim with `--release`.

The profile is not permission to accelerate an unqualified experiment. The
investigation that introduced it lost more time to wrong hypotheses and probes
that answered adjacent questions than to warm compilation. The operating order
is:

> Qualify the question, then pay 7 seconds instead of 5 minutes to answer it.

## Persistent targets, with a bound

Warm target state is load-bearing. The measured warm rebuild was 6.66 seconds;
the same profile in a cold target took 8 minutes 52 seconds.

- Keep a dedicated target only while its worktree has an open branch or an
  in-flight PR.
- Merged and abandoned work has no target exemption and is sweepable.
- Never share a measurement target between active worktrees. A shared target
  replaced the measured binary during an earlier acceptance run.
- Before deleting targets, broadcast the proposed list and wait five minutes for
  active owners to object. Delete only the announced, unclaimed targets.

A measurement target is about 2.6 GB. Keep at least 15 GB of filesystem space
free, and cap live measurement targets at:

```text
min(8, floor((available_GB - 15) / 2.6))
```

At adoption the filesystem had 36 GB available, so the ceiling was eight live
targets. Recompute the ceiling from current free space before creating a ninth;
do not preserve an exception list from memory.

## Measurements

All runs used the same checkout, the same isolated target, and `-j2`:

```text
cold release + test-hooks                    9:33.61   RSS 1.806 GB
touch-one-file rebuild, normal release       5:01.16   RSS 1.808 GB
same rebuild, sccache OFF                    5:10.07   RSS 1.807 GB
cold, measurement profile                    8:52.48   RSS 1.736 GB
touch-one-file, measurement profile          6.66 SEC  RSS 803 MB
```

The warm profile removes about 4 minutes 54 seconds from the repeated build
segment. It does not improve the cold build. sccache changed the dominant local
rebuild by 8.91 seconds, 2.9 percent and within run noise.

## Rejected optimizations

Ordered by measured value and effort:

1. Keep the persistent measurement profile. It is the measured 45x warm-loop
   improvement.
2. Compile the application once per OS and exact feature/profile class in CI.
   Windows release compilation, not test execution, owns the critical path.
3. Extract semantic cores into library crates selectively. `main.rs` is 18,074
   of 46,707 Rust lines, so a release edit still recompiles a large binary crate.
4. Keep sccache for dependency reuse, but do not tune its local cache expecting
   minutes. The dominant application rebuild was effectively unchanged.
5. Keep mold. It was already active during the five-minute release rebuild.
6. Do not add nextest for speed. Unit execution measured 2.02 seconds on Linux
   and 2.15 seconds on Windows; compilation dominates.
7. Keep cold and release builds serialized. The release rebuild peaked at 1.808
   GB on an 8 GB host with several resident agent runtimes. Two concurrent
   `measure` builds need their own measured safety result before the token is
   relaxed.

## Floors

For the recurring stall experiment, 6.66 seconds of warm build plus about 150
seconds of real-process observation gives a three-minute inner-loop floor after
fixture and provenance overhead. That 150-second observation remains physical
until the scenario is redesigned.

Recent full cross-platform boards took about 9 to 11 minutes. The capability
workflow already completed its Windows path in 6 minutes 57 seconds, including a
5 minute 35 second build and a 34 second harness. Seven minutes is therefore the
practical outer-loop floor on the current hosted runners once duplicate slower
compile paths are removed. Going below it requires a faster Windows compile or
runner, or weaker evidence.
