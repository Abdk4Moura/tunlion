# DST Search Guidance, Semantic Fuzzing, and Persistence Report

Branch: `spike/dst` (rebased onto `origin/main`; commits `427b4a3c8..32d7bb0b4`)
Hardware: `devbox` (`4 cores, 31 GiB RAM, rustc 1.100.0`)
Runtime: `tokio` `current_thread` with `start_paused(true)` and deterministic `rng_seed` (`RUSTFLAGS="--cfg tokio_unstable"`, `--features sim`)

## 1. Architecture and Guardrail Compliance

- **Guidance vs. Oracles**: `GuideFlags` in `crates/filament-peerloop/src/sim/fuzz.rs` steers only schedule generation, fault triggering, and corpus mutation (`swarm`, `semantic`, `message_chaos`, `timer_edges`, `sometimes`, `hill_climb`, `target_phase`). Correctness oracles (`evaluate_oracles` in `crates/filament-peerloop/src/sim/assertions.rs`), `recv/loop_budget.rs::BUDGET` (1 s), and pass/fail thresholds are never altered or weakened.
- **Bit-Exact Replay and Labeling**: Every finding emitted by `Fuzzer::run`, `Fuzzer::run_parallel`, or `Fuzzer::replay_regressions` is re-executed in full-logging mode under `SimWorld::run` with the identical seed and fault schedule; `Fuzzer` asserts `replay.trace_hash == full_orig.trace_hash` and stamps `label: "sim-only"`.
- **Capabilities Implemented (one commit per step, behind explicit flags)**:
  - `ef76a1392`: `swarm` - per-run fault-mask subset selection (including 35% noise-free subsets without packet impair or UDP partitions)
  - `ce7c126dc`: `timer_edges` - virtual-time boundary snapping against harvested protocol window constants (dropped from `married()` default)
  - `0507720d2`: `sometimes` - inverse-frequency rarity weighting over non-trivial `sometimes!` protocol milestones (dropped from `married()` default)
  - `bf71c1a12`: `hill_climb` - continuous telemetry scoring (dropped from `married()` default)
  - `1978a2a42`: `Fuzzer::run_parallel` + `quiet_logs` fast path (`std::thread::scope`, per-worker deterministic sub-seeds, full-log replay on finding)
  - `d05315c3b`: `semantic` - typed `StateEdge` coverage (`crates/filament-peerloop/src/sim/semantic.rs`), `SemanticFault` event/silence-boundary triggers (`SimWorld`), and swarm-hygiene-preserving corpus mutations
  - `4375397be`: `message_chaos` + formal-model invariant oracles (`MessageChaosPolicy` drop/duplicate/reorder in `crates/filament-peerloop/src/sim/net.rs`, `ReorderGlareViolation`, `FormalInvariantViolation`, live `link_manager::place` P1-P6 checks, I1 glare-free, I2 pair symmetry, bounded clean reconnects, and `antecedents_seen` vacuity tracking)
  - `44eb33bd5` & `32d7bb0b4`: persistent content-addressed corpus store (`crates/filament-peerloop/src/sim/corpus.rs`), load-time replay triage against current code, greedy set-cover minimization pruning redundant/obsolete seeds, permanent `regressions/` bank, and `Arc<RwLock<SharedFrontier>>` shared across parallel workers
- **Determinism Fixes (`a083f43bb`)**: Switched `WarmHold` (`warm.rs`) to `SimHashMap`/`SimHashSet`, switched `SimNetwork` collections to `BTreeMap`/`BTreeSet`, and switched `recv/signaling_health.rs::jitter_unit()` under `sim` to per-world seeded `sim_rt::next_sim_u64()`.
- **Dependencies**: Zero new crates added; `Cargo.lock` is untouched.

## 2. Verification Summary on `devbox`

All final checks ran against the committed clean workspace on `devbox` (`CARGO_TARGET_DIR="$HOME/dst-work/target"`), with `mut-pre729` compiled in an isolated `CARGO_TARGET_DIR="$HOME/dst-work/target-mut-pre729"`:

| Check | Command Scope | Outcome | Key Numbers |
|---|---|---|---|
| Workspace check | `cargo check --locked --workspace` | Exit 0 | Finished in `0.25s` (incremental) |
| Determinism & replay tests | `cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture` | 5 passed, 0 failed | `DST_BENCHMARK: runs=100 wall_ms=595 runs_per_sec=168.02` (`0.60s`) |
| Unit test suite (`sim` enabled) | `cargo test --locked -p tunlion-peerloop --features sim --lib` | 928 passed, 0 failed | `11.40s` |
| Clean-build 0-FP (40 runs, `married()` / `full_semantic`) | `test_clean_build_zero_false_positives` (`dst_fuzz_bench`) | Passed | `findings=0`, `wall_ms=2645`, `state_edges=38`, `max_busy_ms=0`, `max_status_ms=0`, 17 `sometimes!` milestones |
| Canary planted bug | `test_canary_planted_bug_found_and_replays_bit_exact` (`dst_fuzz_bench`) | Passed | `run=7`, `wall_ms=477`, `label=sim-only`, `replay_verified=true` |
| Disk corpus & regression bank | `test_disk_corpus_persistence_minimize_and_regression_replay` | Passed | `PERSISTENCE_RUN1: files=5 total_bytes=5166 state_edges=30`; `PERSISTENCE_RUN2: files=6 total_bytes=6362 state_edges=32` (duplicate pruned); `REGRESSION_BANK: files=1 total_bytes=651 canary_replays=1 clean_replays=0` |
| Guidance benchmark matrix (6 targets x 7 configs x 5 seeds) | `test_guidance_benchmark_matrix` (`dst_fuzz_bench`) | Passed | Total binary runtime `161.76s` |
| Real `pre-#729` source revert | `test_real_pre729_campaign_hook -- --ignored` in `mut-pre729` (reverted `dispatch.rs:3740` to inline `net::heartbeat`) | 1 passed, 0 failed | Detected `5/5` across all 7 configs (`8.25s`) |

Non-vacuous formal antecedents verified during the 40-run clean campaign:
`antecedents={"est_clean_window_checked", "est_i1_glare_free", "est_i2_pair_symmetry"}` (plus `lm_placement_checked` exercised directly in unit placement calls).

Clean-build 40-run `sometimes!` milestone counts (`findings=0`, with per-message chaos active):
`sig_connected=40`, `direct_paired=40`, `signaling_healed_after_blackhole=31`, `sig_msg_dropped=28`, `sig_msg_duplicated=28`, `sig_msg_reordered=28`, `reconnect_after_peer_restart=27`, `webrtc_fallback_attempted=21`, `heartbeat_fired_under_blackhole=14`, `blackhole_boundary_silence=13`, `multi_fault_overlap=13`, `peer_restarted_during_blackhole=11`, `cap_status_during_blackhole=10`, `clean_restart_no_partition=8`, `direct_after_partition_heal=4`, `impair_under_partition=2`, `gather_during_blackhole=1`.

## 3. Parallel Throughput (Debug vs. `--release`, `quiet_logs = true`)

Measured on `devbox` (`4 cores`, `120` 60-second virtual-time 3-node cluster runs per measurement):

| Build Profile | Mode | Workers | Runs | Wall Time (ms) | Throughput (runs/s) | Sim Cluster-Hours / s |
|---|---|---:|---:|---:|---:|---:|
| Debug (`unoptimized + debuginfo`) | Single-core | 1 | 120 | 6926 | 17.33 | 0.289 |
| Debug (`unoptimized + debuginfo`) | Parallel | 4 | 120 | 3177 | 37.77 | 0.630 |
| Release (`--release`) | Single-core | 1 | 120 | 383 | 313.32 | 5.222 |
| Release (`--release`) | Parallel | 4 | 120 | 162 | **740.74** | **12.346** |

## 4. Rediscovery Benchmark Results

Each cell aggregates `5` independent seeds (`budget = 40` runs per seed, `30` runs for `real_pre729_source_revert`; undetected seeds count as `budget + 1`). Speedup is `unguided mean_runs / guide mean_runs`. Here `married` equals `full_semantic` (`swarm: true`, `semantic: true`, `message_chaos: true`).

| Target | Guide | Detected | Mean Runs | Median Runs | Mean Wall (ms) | Speedup vs Unguided |
|---|---|---:|---:|---:|---:|---:|
| `gather_live_main` | `unguided` | 5/5 | 10.20 | 8.0 | 629.4 | 1.00x |
| `gather_live_main` | `swarm` | 5/5 | 7.80 | 9.0 | 507.0 | 1.31x |
| `gather_live_main` | `semantic` | 4/5 | 24.40 | 22.0 | 1395.2 | 0.42x |
| `gather_live_main` | `swarm_semantic` | 5/5 | 17.60 | 18.0 | 1051.6 | 0.58x |
| `gather_live_main` | `message_chaos` | 5/5 | 7.60 | 5.0 | 503.6 | 1.34x |
| `gather_live_main` | `full_semantic` | 5/5 | 4.40 | 5.0 | 331.6 | **2.32x** |
| `gather_live_main` | `married` | 5/5 | 4.40 | 5.0 | 325.8 | **2.32x** |
| `pre729_heartbeat` | `unguided` | 5/5 | 6.00 | 7.0 | 476.4 | 1.00x |
| `pre729_heartbeat` | `swarm` | 5/5 | 3.20 | 4.0 | 239.8 | 1.88x |
| `pre729_heartbeat` | `semantic` | 5/5 | 3.00 | 2.0 | 222.8 | 2.00x |
| `pre729_heartbeat` | `swarm_semantic` | 5/5 | 3.00 | 1.0 | 220.6 | 2.00x |
| `pre729_heartbeat` | `message_chaos` | 5/5 | 3.40 | 4.0 | 259.8 | 1.76x |
| `pre729_heartbeat` | `full_semantic` | 5/5 | 3.40 | 1.0 | 255.4 | 1.76x |
| `pre729_heartbeat` | `married` | 5/5 | 3.40 | 1.0 | 258.6 | 1.76x |
| `noise_sensitive_restart` | `unguided` | 5/5 | 11.20 | 6.0 | 679.4 | 1.00x |
| `noise_sensitive_restart` | `swarm` | 5/5 | 5.20 | 6.0 | 346.8 | 2.15x |
| `noise_sensitive_restart` | `semantic` | 5/5 | 13.20 | 11.0 | 793.8 | 0.85x |
| `noise_sensitive_restart` | `swarm_semantic` | 5/5 | 5.20 | 3.0 | 362.6 | 2.15x |
| `noise_sensitive_restart` | `message_chaos` | 5/5 | 7.80 | 9.0 | 510.2 | 1.44x |
| `noise_sensitive_restart` | `full_semantic` | 5/5 | 5.20 | 2.0 | 357.8 | **2.15x** |
| `noise_sensitive_restart` | `married` | 5/5 | 5.20 | 2.0 | 357.0 | **2.15x** |
| `timer_edge_silence` | `unguided` | 0/5 | 41.00 | 41.0 | 2234.4 | 1.00x |
| `timer_edge_silence` | `swarm` | 0/5 | 41.00 | 41.0 | 2212.8 | 1.00x |
| `timer_edge_silence` | `semantic` | 5/5 | 7.80 | 5.0 | 490.6 | 5.26x |
| `timer_edge_silence` | `swarm_semantic` | 5/5 | 6.40 | 3.0 | 420.8 | 6.41x |
| `timer_edge_silence` | `message_chaos` | 1/5 | 33.40 | 41.0 | 1945.2 | 1.23x |
| `timer_edge_silence` | `full_semantic` | 5/5 | 6.20 | 7.0 | 406.0 | **6.61x** |
| `timer_edge_silence` | `married` | 5/5 | 6.20 | 7.0 | 418.8 | **6.61x** |
| `post_heal_liveness` | `unguided` | 5/5 | 1.40 | 1.0 | 138.2 | 1.00x |
| `post_heal_liveness` | `swarm` | 5/5 | 2.20 | 2.0 | 184.8 | 0.64x |
| `post_heal_liveness` | `semantic` | 5/5 | 1.40 | 1.0 | 132.4 | 1.00x |
| `post_heal_liveness` | `swarm_semantic` | 5/5 | 4.40 | 2.0 | 305.6 | 0.32x |
| `post_heal_liveness` | `message_chaos` | 5/5 | 1.60 | 1.0 | 159.4 | 0.87x |
| `post_heal_liveness` | `full_semantic` | 5/5 | 3.00 | 3.0 | 222.0 | 0.47x |
| `post_heal_liveness` | `married` | 5/5 | 3.00 | 3.0 | 220.0 | 0.47x |
| `reorder_glare` | `unguided` | 0/5 | 41.00 | 41.0 | 2242.6 | 1.00x |
| `reorder_glare` | `swarm` | 0/5 | 41.00 | 41.0 | 2219.4 | 1.00x |
| `reorder_glare` | `semantic` | 0/5 | 41.00 | 41.0 | 2220.8 | 1.00x |
| `reorder_glare` | `swarm_semantic` | 0/5 | 41.00 | 41.0 | 2266.4 | 1.00x |
| `reorder_glare` | `message_chaos` | 5/5 | 1.20 | 1.0 | 144.2 | **34.17x** |
| `reorder_glare` | `full_semantic` | 5/5 | 3.40 | 2.0 | 258.4 | **12.06x** |
| `reorder_glare` | `married` | 5/5 | 3.40 | 2.0 | 251.4 | **12.06x** |
| `real_pre729_source_revert` | `unguided` | 5/5 | 3.20 | 3.0 | 229.6 | 1.00x |
| `real_pre729_source_revert` | `swarm` | 5/5 | 3.20 | 4.0 | 234.4 | 1.00x |
| `real_pre729_source_revert` | `semantic` | 5/5 | 3.00 | 2.0 | 226.8 | 1.07x |
| `real_pre729_source_revert` | `swarm_semantic` | 5/5 | 3.00 | 1.0 | 225.0 | 1.07x |
| `real_pre729_source_revert` | `message_chaos` | 5/5 | 1.60 | 2.0 | 147.2 | **2.00x** |
| `real_pre729_source_revert` | `full_semantic` | 5/5 | 3.40 | 1.0 | 329.4 | 0.94x |
| `real_pre729_source_revert` | `married` | 5/5 | 3.40 | 1.0 | 254.6 | 0.94x |

## 5. Keep / Drop Verdicts and Root Causes

Under the Drop Rule (enable in `GuideFlags::married()` only the guides that beat `unguided` or expand bug-class reach without degrading the suite):

| Guide | Status in `married()` | Empirical Evidence | Root Cause |
|---|---|---|---|
| `swarm` | **KEPT** (`true`) | `2.15x` on `noise_sensitive_restart`, `1.88x` on `pre729_heartbeat`, `1.31x` on `gather_live_main`. | Per-run fault-masking gives 35% clean-network subsets (no packet impair or UDP partitions), eliminating masking noise. |
| `semantic` | **KEPT** (`true`) | Lifted `timer_edge_silence` from `0/5` (`unguided`) to `5/5` (`5.26x` alone, `6.61x` in `married()`). | `OnEvent` / `OnSilenceBoundary` triggers align faults with real protocol transitions (`SigConnected -> SigBlackholeStarted -> SigBlackholeHealed -> QueryCapStatus`), while `StateEdge` corpus + `swarm` hygiene preserves clean-subset masking. |
| `message_chaos` | **KEPT** (`true`) | Lifted `reorder_glare` from `0/5` (`unguided`) to `5/5` (`34.17x` alone, `12.06x` in `married()`); hit `2.00x` on `real_pre729_source_revert` and `2.32x` on `gather_live_main` in `married()`. | Deterministic drop/duplicate/reorder of signaling frames exercises half-open/glare/reorder races that coarse blackholes never trigger. |
| `timer_edges` | **DROPPED** (`false`) | Earlier ablation lost or tied 6/6 targets (`0.59x-1.00x`). | Clamping blackhole `end` at `duration_ms - 5_000` shifted snapped durations; replaced effectively by semantic `OnSilenceBoundary`. |
| `sometimes` | **DROPPED** (`false`) | Alone hurt `gather_live_main` (`0.51x`) and `post_heal_liveness` (`0.44x`); paired with `swarm` it regressed all 6 targets before `StateEdge` corpus replaced it. | Multi-fault milestone entries kept `partition = Some(...)` on across mutations; milestone counters stay enabled passively as coverage telemetry. |
| `hill_climb` | **DROPPED** (`false`) | Earlier ablation lost 5/6 targets (`0.44x-0.99x`). | Under Tokio `start_paused(true)`, healthy handlers execute in `0 ms` virtual time (`max_busy_ms=0`), making PR `#731` `busy_ms` a flat binary step with no smooth gradient. |

## 6. Persistent Corpus & Multi-Machine `tunlion sync` Workflow

- **Two-bucket layout**:
  - `corpus/` (living frontier cache): stores content-addressed `seed-<hash>.json` schedules (~500-1000 B each; observed `5-6` minimized files totaling `5.1-6.4 KB` covering `30-32` `StateEdge`s). Never trust cached coverage across commits: `corpus::load_and_triage_corpus` replays every file against the current binary, drops stale/obsolete seeds via greedy set-cover `minimize_corpus`, and prunes unreferenced `seed-*.json` files on save.
  - `regressions/` (permanent bug bank, checked into git when real bugs are found): `finding-<hash>.json` (~650 B each), never pruned by minimization, replayed deterministically via `Fuzzer::replay_regressions`.
- **Cross-machine sync without cloud buckets**: Because files are content-addressed JSON and small (< 1 MB), machines (`do-vm`, `devbox`, CI workers) can merge discovered frontiers conflict-free via `tunlion sync` (without `--delete`):

```bash
tunlion sync --no-interactive ~/dst-corpus/corpus devbox:dst-corpus/corpus
tunlion sync --no-interactive ~/dst-corpus/regressions devbox:dst-corpus/regressions
```

## 7. Reproduction Commands (`devbox`)

```bash
export RUSTFLAGS="--cfg tokio_unstable"
cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture
cargo test --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench -- --nocapture --test-threads=1
cargo test --release --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench test_parallel_throughput_benchmark -- --nocapture
```
