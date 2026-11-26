# DST Search Guidance Benchmark and Drop Rule Report

Branch: `spike/dst` (rebased onto `origin/main`; commits `427b4a3c8..1df37e09b`)
Hardware: `devbox` (`4 cores, 31 GiB RAM, rustc 1.100.0`)
Runtime: `tokio` `current_thread` with `start_paused(true)` and deterministic `rng_seed` (`RUSTFLAGS="--cfg tokio_unstable"`, `--features sim`)

## 1. Scope and Guardrail Compliance

- **Guidance vs. Oracles**: `GuideFlags` in `crates/filament-peerloop/src/sim/fuzz.rs` steers only schedule generation and corpus mutation (`swarm`, `timer_edges`, `sometimes`, `hill_climb`, `target_phase`). Correctness oracles (`evaluate_oracles` in `crates/filament-peerloop/src/sim/assertions.rs`), `recv/loop_budget.rs::BUDGET` (1 s), and pass/fail thresholds are never altered or weakened.
- **Bit-Exact Replay and Labeling**: Every finding emitted by `Fuzzer::run` is immediately re-executed under `SimWorld::run` with the identical seed and fault schedule; `Fuzzer::run` asserts `replay.trace_hash == outcome.trace_hash` and stamps `label: "sim-only"`.
- **One Commit per Guide Behind Explicit Flags**:
  - `ef76a1392`: `swarm` - per-run fault-mask subset selection (including 35% noise-free subsets without packet impair or UDP partitions)
  - `ce7c126dc`: `timer_edges` - virtual-time boundary snapping against harvested protocol window constants
  - `0507720d2`: `sometimes` - inverse-frequency rarity weighting over non-trivial `sometimes!` protocol milestones
  - `bf71c1a12`: `hill_climb` - continuous telemetry scoring (loop busy ms capped under 1000 ms, `cap_status` latency, phase/event coverage)
- **Determinism Fixes (`a083f43bb`)**: Switched `WarmHold` (`warm.rs`) to `SimHashMap`/`SimHashSet`, switched `SimNetwork` collections to `BTreeMap`/`BTreeSet`, and switched `recv/signaling_health.rs::jitter_unit()` under `sim` to per-world seeded `sim_rt::next_sim_u64()` so replays are 100% bit-exact across all campaign runs.
- **Dependencies**: Zero new crates added; `Cargo.lock` is untouched.

## 2. Verification Summary on `devbox`

All final checks ran against the committed clean workspace on `devbox` (`CARGO_TARGET_DIR="$HOME/dst-work/target"`), with the source-revert test compiled in an isolated `CARGO_TARGET_DIR="$HOME/dst-work/target-mut-pre729"` so mutated artifacts cannot be reused by clean builds:

| Check | Command Scope | Outcome | Key Numbers |
|---|---|---|---|
| Workspace check | `cargo check --locked --workspace` | Exit 0 | Finished in `1m 08s` |
| Determinism & replay tests | `cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture` | 5 passed, 0 failed | `DST_BENCHMARK: runs=100 wall_ms=597 runs_per_sec=167.23` (`0.60s`) |
| Unit test suite (`sim` enabled) | `cargo test --locked -p tunlion-peerloop --features sim --lib` | 928 passed, 0 failed | `13.12s` |
| Clean-build 0-FP (40 runs, `allow_gather_hang: false`) | `test_clean_build_zero_false_positives` (`dst_fuzz_bench`) | Passed | `findings=0`, `wall_ms=2238`, `max_busy_ms=0`, `max_status_ms=0`, 14 `sometimes!` milestones |
| Canary planted bug | `test_canary_planted_bug_found_and_replays_bit_exact` (`dst_fuzz_bench`) | Passed | `run=11`, `wall_ms=687`, `label=sim-only`, `replay_verified=true` |
| Guidance benchmark matrix (5 targets x 6 configs x 5 seeds) | `test_guidance_benchmark_matrix` (`dst_fuzz_bench`) | Passed | Total binary runtime `115.40s` |
| Real `pre-#729` source revert | `test_real_pre729_campaign_hook -- --ignored` in `mut-pre729` (reverted `dispatch.rs:3740` to inline `net::heartbeat`) | 1 passed, 0 failed | Detected `5/5` across all configs (`7.12s`) |

Clean-build 40-run `sometimes!` milestone counts (`findings=0`):
`sig_connected=40`, `direct_paired=40`, `reconnect_after_peer_restart=28`, `signaling_healed_after_blackhole=25`, `heartbeat_fired_under_blackhole=17`, `cap_status_during_blackhole=12`, `webrtc_fallback_attempted=10`, `clean_restart_no_partition=8`, `peer_restarted_during_blackhole=8`, `blackhole_boundary_silence=7`, `multi_fault_overlap=7`, `direct_after_partition_heal=6`, `impair_under_partition=4`, `gather_during_blackhole=1`.

## 3. Rediscovery Benchmark Results

Each cell aggregates `5` independent seeds (`budget = 40` runs per seed; undetected seeds count as `41`). Speedup is `unguided mean_runs / guide mean_runs`. Here `married` is the post-Drop-Rule default (`swarm: true`, all other guides `false`).

### 3.1 Final Benchmark Table (6 Targets x 6 Configs)

| Target | Guide | Detected | Mean Runs | Median Runs | Mean Wall (ms) | Speedup vs Unguided |
|---|---|---:|---:|---:|---:|---:|
| `gather_live_main` | `unguided` | 5/5 | 8.80 | 8.0 | 530.0 | 1.00x |
| `gather_live_main` | `swarm` | 5/5 | 7.80 | 9.0 | 477.8 | 1.13x |
| `gather_live_main` | `timer_edges` | 5/5 | 13.20 | 4.0 | 765.8 | 0.67x |
| `gather_live_main` | `sometimes` | 4/5 | 17.40 | 17.0 | 956.6 | 0.51x |
| `gather_live_main` | `hill_climb` | 4/5 | 19.00 | 23.0 | 1077.0 | 0.46x |
| `gather_live_main` | `married` | 5/5 | 7.80 | 9.0 | 482.0 | 1.13x |
| `pre729_heartbeat` | `unguided` | 5/5 | 6.00 | 7.0 | 383.6 | 1.00x |
| `pre729_heartbeat` | `swarm` | 5/5 | 3.20 | 4.0 | 243.6 | 1.88x |
| `pre729_heartbeat` | `timer_edges` | 5/5 | 6.60 | 7.0 | 422.8 | 0.91x |
| `pre729_heartbeat` | `sometimes` | 5/5 | 4.20 | 4.0 | 286.4 | 1.43x |
| `pre729_heartbeat` | `hill_climb` | 5/5 | 8.40 | 5.0 | 533.2 | 0.71x |
| `pre729_heartbeat` | `married` | 5/5 | 3.20 | 4.0 | 227.2 | 1.88x |
| `noise_sensitive_restart` | `unguided` | 5/5 | 6.40 | 6.0 | 393.4 | 1.00x |
| `noise_sensitive_restart` | `swarm` | 5/5 | 5.20 | 6.0 | 337.4 | 1.23x |
| `noise_sensitive_restart` | `timer_edges` | 5/5 | 9.80 | 7.0 | 605.2 | 0.65x |
| `noise_sensitive_restart` | `sometimes` | 5/5 | 5.60 | 6.0 | 362.0 | 1.14x |
| `noise_sensitive_restart` | `hill_climb` | 5/5 | 12.60 | 8.0 | 751.6 | 0.51x |
| `noise_sensitive_restart` | `married` | 5/5 | 5.20 | 6.0 | 329.0 | 1.23x |
| `timer_edge_silence` | `unguided` | 1/5 | 34.80 | 41.0 | 1860.4 | 1.00x |
| `timer_edge_silence` | `swarm` | 1/5 | 38.80 | 41.0 | 2079.0 | 0.90x |
| `timer_edge_silence` | `timer_edges` | 0/5 | 41.00 | 41.0 | 2200.4 | 0.85x |
| `timer_edge_silence` | `sometimes` | 0/5 | 41.00 | 41.0 | 2182.0 | 0.85x |
| `timer_edge_silence` | `hill_climb` | 1/5 | 35.20 | 41.0 | 1870.0 | 0.99x |
| `timer_edge_silence` | `married` | 1/5 | 38.80 | 41.0 | 2040.4 | 0.90x |
| `post_heal_liveness` | `unguided` | 5/5 | 1.40 | 1.0 | 132.2 | 1.00x |
| `post_heal_liveness` | `swarm` | 5/5 | 2.20 | 2.0 | 184.2 | 0.64x |
| `post_heal_liveness` | `timer_edges` | 5/5 | 1.40 | 1.0 | 128.0 | 1.00x |
| `post_heal_liveness` | `sometimes` | 5/5 | 3.20 | 1.0 | 231.8 | 0.44x |
| `post_heal_liveness` | `hill_climb` | 5/5 | 3.20 | 1.0 | 226.4 | 0.44x |
| `post_heal_liveness` | `married` | 5/5 | 2.20 | 2.0 | 179.4 | 0.64x |
| `real_pre729_source_revert` | `unguided` | 5/5 | 3.20 | 3.0 | 231.2 | 1.00x |
| `real_pre729_source_revert` | `swarm` | 5/5 | 3.20 | 4.0 | 234.2 | 1.00x |
| `real_pre729_source_revert` | `timer_edges` | 5/5 | 5.40 | 5.0 | 359.2 | 0.59x |
| `real_pre729_source_revert` | `sometimes` | 5/5 | 2.20 | 2.0 | 182.6 | 1.45x |
| `real_pre729_source_revert` | `hill_climb` | 5/5 | 2.20 | 2.0 | 181.4 | 1.45x |
| `real_pre729_source_revert` | `married` | 5/5 | 3.20 | 4.0 | 232.8 | 1.00x |

## 4. Keep / Drop Verdicts and Root Causes

Under the Drop Rule (disable in `GuideFlags::married()` any guide that fails to beat `unguided` or degrades `married()`):

| Guide | Status in `married()` | Empirical Evidence | Root Cause |
|---|---|---|---|
| `swarm` | **KEPT** (`true`) | Beat or tied `unguided` on 4 of 6 targets: `pre729_heartbeat` (`1.88x`), `noise_sensitive_restart` (`1.23x`), `gather_live_main` (`1.13x`), `real_pre729_source_revert` (`1.00x`). | Per-run fault-masking gives 35% clean-network subsets (no packet impair or UDP partitions), eliminating masking noise around restart/blackhole bugs. |
| `sometimes` | **DROPPED** (`false`) | Alone it beat `unguided` on `real_pre729_source_revert` (`1.45x`), `pre729_heartbeat` (`1.43x`), `noise_sensitive_restart` (`1.14x`), but lost heavily on `gather_live_main` (`0.51x`, `4/5`) and `post_heal_liveness` (`0.44x`). When combined with `swarm` (`swarm + sometimes`, prior `devbox` ablation before `7cee86188`), `married` degraded on all 6 targets vs. `swarm` alone (`gather_live_main` `1.13x -> 0.75x`, `pre729_heartbeat` `1.88x -> 1.58x`, `noise_sensitive_restart` `1.23x -> 0.64x`, `timer_edge_silence` `0.90x -> 0.85x`, `post_heal_liveness` `0.64x -> 0.58x`, `real_pre729_source_revert` `1.00x -> 0.76x`). | Corpus entries captured on multi-fault overlap milestones retain `partition = Some(...)` across 5 of 6 single-field mutations, undoing `swarm` clean-subset masking. Kept behind `--features sim` `GuideFlags::sometimes_only()` for standalone exploration campaigns. |
| `timer_edges` | **DROPPED** (`false`) | Lost or tied on 6 of 6 targets (`0.67x`, `0.91x`, `0.65x`, `0.85x` `0/5`, `1.00x`, `0.59x`). In earlier all-4 ablation (`ee8d2d9a1`), `married` was dragged down on `real_pre729_source_revert` (`0.89x`). | Snapping blackhole end times independently and clamping `end` at `duration_ms - 5_000` shifts exact durations and reduces alignment between independent events such as `blackhole` boundary and `status_query`. Kept behind `GuideFlags::timer_edges_only()`. |
| `hill_climb` | **DROPPED** (`false`) | Lost on 5 of 6 targets (`0.46x` `4/5`, `0.71x`, `0.51x`, `0.99x`, `0.44x`; only helped `real_pre729_source_revert` `1.45x`). | **Virtual-time step function**: under Tokio `start_paused(true)`, healthy synchronous handlers finish in `0 ms` virtual time (`max_busy_ms=0`, `max_status_ms=0` across all 40 clean runs). PR `#731` `busy_ms` jumps directly from `0 ms` to `>= 1000 ms` on a blocking await, leaving `hill_climb` without a smooth gradient and forcing fallback onto noisy `phases_hit.len()`. Kept behind `GuideFlags::hill_climb_only()`. |

## 5. Reproduction Commands (`devbox`)

```bash
export RUSTFLAGS="--cfg tokio_unstable"
cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture
cargo test --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench -- --nocapture --test-threads=1
```

To run the real `pre-#729` source revert check without polluting the primary target directory:

1. Copy the source tree to a scratch directory (e.g. `~/dst-work/mut-pre729`).
2. Replace the spawned `tokio::spawn(async move { net::heartbeat(&sio, payload, tx).await });` block in `crates/filament-peerloop/src/recv/dispatch.rs` (`~line 3741`) with inline `net::heartbeat(&sio, sess.heartbeat_payload(), tx.clone()).await;`.
3. Run with a separate `CARGO_TARGET_DIR`:

```bash
CARGO_TARGET_DIR="$HOME/dst-work/target-mut-pre729" \
  RUSTFLAGS="--cfg tokio_unstable" \
  cargo test --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench \
  test_real_pre729_campaign_hook -- --ignored --nocapture
```
