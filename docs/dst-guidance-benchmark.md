# DST Search Guidance, Real-Bug Rediscovery, and Persistence Report

Base Branch: `origin/main` (`de61fd533`)
Runtime: `tokio` `current_thread` with `start_paused(true)` and deterministic `rng_seed` (`RUSTFLAGS="--cfg tokio_unstable"`, `--features sim`)

## 1. Architecture and Guardrail Compliance

- **Guidance vs. Oracles**: `GuideFlags` in `crates/filament-peerloop/src/sim/fuzz.rs` steers only schedule generation, fault triggering, and corpus mutation (`swarm`, `message_chaos`, and opt-in `semantic`). Dropped guides from exploratory spikes (`timer_edges`, `sometimes`-guided corpus mutation, and `hill_climb`) are completely omitted from `main`; `sometimes!` remains passive telemetry only. Correctness oracles (`evaluate_oracles` in `crates/filament-peerloop/src/sim/assertions.rs`), `recv/loop_budget.rs::BUDGET` (1 s), and pass/fail thresholds are never altered or weakened.
- **Bit-Exact Replay and Labeling**: Every finding emitted by `Fuzzer::run`, `Fuzzer::run_parallel`, or `Fuzzer::replay_regressions` is re-executed in full-logging mode under `SimWorld::run` with the identical seed and fault schedule; `Fuzzer` asserts `replay.trace_hash == full_orig.trace_hash` and stamps `label: "sim-only"`.
- **Capabilities Retained**:
  - `swarm`: per-run fault-mask subset selection (including 35% clean-network subsets without packet impair or UDP partitions to avoid masking).
  - `message_chaos` + formal-model invariant oracles: `MessageChaosPolicy` drop/duplicate/reorder in `crates/filament-peerloop/src/sim/net.rs`, `ReorderGlareViolation`, `FormalInvariantViolation`, live `link_manager::place` P1-P6 checks, I1 glare-free, I2 pair symmetry, bounded clean reconnects, and `antecedents_seen` vacuity tracking.
  - `semantic` (opt-in, off by default in `married()`): typed `StateEdge` coverage (`crates/filament-peerloop/src/sim/semantic.rs`), `SemanticFault` event/silence-boundary triggers, and edge-rarity corpus mutations. Available via `GuideFlags::semantic_only()`, `GuideFlags::swarm_semantic()`, and `GuideFlags::full_semantic()`.
  - `Fuzzer::run_parallel` + `quiet_logs` fast path (`std::thread::scope`, per-worker deterministic sub-seeds, full-log replay on finding).
  - Persistent content-addressed corpus store (`crates/filament-peerloop/src/sim/corpus.rs`): load-time replay triage against current code, greedy set-cover minimization pruning redundant/obsolete seeds, permanent `regressions/` bank, and `Arc<RwLock<SharedFrontier>>` shared across parallel workers.
- **Dependencies**: Zero new crates added; `Cargo.lock` is untouched.

## 2. Real-Bug Rediscovery Benchmark (Primary Promotion Gate)

Measured on `linux-devloop` (`--release --locked -p tunlion-peerloop --features sim`, budget = `40` runs per seed, `DST_MAX_RUNS=40`) against real bug fixes from `main` reverted one at a time in isolated copies and isolated `CARGO_TARGET_DIR`s (`/tmp/target-real-729`, `/tmp/target-real-738`), with zero oracle or threshold modifications:

- **`#729` (`de7381cb3`)**: reverted `tokio::spawn(async move { net::heartbeat(&sio, payload, tx).await });` back to inline `net::heartbeat(&sio, sess.heartbeat_payload(), tx.clone()).await;` in `crates/filament-peerloop/src/recv/dispatch.rs`.
- **`#738` (`5166927aa`, inline candidate gather)**: reverted off-loop candidate gathering in `Conn::start_direct_inner` (`crates/filament-peerloop/src/conn.rs`) back to inline `direct::gather_candidates(&self.transport_context, &self.server, port).await;` (`DST_ALLOW_GATHER_HANG=1`).

In these tables, `swarm_msg_chaos` (`swarm: true, semantic: false, message_chaos: true`) is the configuration promoted to `GuideFlags::married()`, and `married (all 3)` denotes `GuideFlags::full_semantic()` (`swarm: true, semantic: true, message_chaos: true`). Undetected seeds count as `budget + 1` (`41`).

### 2.1 Primary 20-Seed Benchmark (with Pairwise Ablations)

| Target | Guide | Detected | Mean Runs | Median Runs | Mean Wall (ms) | Speedup vs Unguided |
|---|---|---:|---:|---:|---:|---:|
| `#729` (`real_pre729_s20`) | `unguided` | 20/20 | 2.70 | 2.0 | 10.9 | 1.00x |
| `#729` (`real_pre729_s20`) | `swarm` | 20/20 | 2.60 | 2.0 | 10.9 | 1.04x |
| `#729` (`real_pre729_s20`) | `semantic` | 20/20 | 3.65 | 2.0 | 14.5 | 0.74x |
| `#729` (`real_pre729_s20`) | `message_chaos` | 20/20 | 2.75 | 2.0 | 11.4 | 0.98x |
| `#729` (`real_pre729_s20`) | `swarm_msg_chaos` (**promoted `married`**) | **20/20** | **2.10** | **2.0** | **9.6** | **1.29x** |
| `#729` (`real_pre729_s20`) | `swarm_semantic` | 20/20 | 3.10 | 1.5 | 12.8 | 0.87x |
| `#729` (`real_pre729_s20`) | `semantic_msg_chaos` | 20/20 | 6.25 | 2.0 | 23.6 | 0.43x |
| `#729` (`real_pre729_s20`) | `full_semantic` (`swarm+semantic+msg_chaos`) | 20/20 | 4.95 | 2.5 | 19.4 | 0.55x |
| `#738` (`real_pre738_s20`) | `unguided` | 20/20 | 11.00 | 10.0 | 37.1 | 1.00x |
| `#738` (`real_pre738_s20`) | `swarm` | 20/20 | 8.05 | 5.5 | 28.0 | 1.37x |
| `#738` (`real_pre738_s20`) | `semantic` | 16/20 | 20.70 | 19.0 | 66.0 | 0.53x |
| `#738` (`real_pre738_s20`) | `message_chaos` | 19/20 | 9.65 | 6.5 | 33.5 | 1.14x |
| `#738` (`real_pre738_s20`) | `swarm_msg_chaos` (**promoted `married`**) | **20/20** | **5.20** | **4.0** | **20.2** | **2.12x** |
| `#738` (`real_pre738_s20`) | `swarm_semantic` | 20/20 | 11.20 | 6.0 | 38.0 | 0.98x |
| `#738` (`real_pre738_s20`) | `semantic_msg_chaos` | 18/20 | 17.30 | 15.5 | 57.6 | 0.64x |
| `#738` (`real_pre738_s20`) | `full_semantic` (`swarm+semantic+msg_chaos`) | 20/20 | 9.15 | 5.0 | 33.0 | 1.20x |

### 2.2 5-Seed Slice (`seeds = [101, 202, 303, 404, 505]`)

| Target | Guide | Detected | Mean Runs | Median Runs | Mean Wall (ms) | Speedup vs Unguided |
|---|---|---:|---:|---:|---:|---:|
| `#729` (`real_pre729_s5`) | `unguided` | 5/5 | 3.20 | 3.0 | 12.8 | 1.00x |
| `#729` (`real_pre729_s5`) | `swarm` | 5/5 | 3.20 | 4.0 | 12.4 | 1.00x |
| `#729` (`real_pre729_s5`) | `semantic` | 5/5 | 3.00 | 2.0 | 12.2 | 1.07x |
| `#729` (`real_pre729_s5`) | `message_chaos` | 5/5 | 1.60 | 2.0 | 7.6 | 2.00x |
| `#729` (`real_pre729_s5`) | `full_semantic` (`swarm+semantic+msg_chaos`) | 5/5 | 3.40 | 1.0 | 13.8 | 0.94x |
| `#738` (`real_pre738_s5`) | `unguided` | 5/5 | 10.20 | 8.0 | 34.4 | 1.00x |
| `#738` (`real_pre738_s5`) | `swarm` | 5/5 | 7.80 | 9.0 | 27.6 | 1.31x |
| `#738` (`real_pre738_s5`) | `semantic` | 4/5 | 23.80 | 22.0 | 75.8 | 0.43x |
| `#738` (`real_pre738_s5`) | `message_chaos` | 5/5 | 7.60 | 5.0 | 26.8 | 1.34x |
| `#738` (`real_pre738_s5`) | `full_semantic` (`swarm+semantic+msg_chaos`) | 5/5 | 6.00 | 6.0 | 22.8 | 1.70x |

## 3. Explicit Per-Target Exclusions

Per the real-bug benchmark criteria, fixes whose failure seam is not modeled by `SimWorld` / `SimNetwork` are explicitly excluded without substituting constructed analogs and without adding or relaxing oracles:

- **`#733` (`e777ada49`, delivery-ack flush inline in `dispatch.rs`)**: Excluded because `SimWorld` models daemon signaling, connection establishment, `warm_hold`, and `CapStatus`, and does not execute file transfers (`file-offer` / `file-accept` / `Control:file-end` / `t.flush()`).
- **`#735` (`6031d266a`, owner retry storm / `MAX_LINKS` eviction / `stuck_episode`) & `#740` (`43ec7a966`, `warm_hold` dialing departed sids)**: Excluded because `SimWorld` runs a fixed 3-node topology (`links.len() <= 2 < MAX_LINKS`), `restart_node` returns within 1-7 s rather than churning permanently departed sids into `MAX_LINKS` exhaustion, and `evaluate_oracles` (`sim/assertions.rs`) has no retry-storm or redundant-warm-dial oracle.
- **`#742` (`f1d9854e9`, data channel `is_dead` / `transport_severed` + `lingering` file re-offer)**: Excluded because `SimTransport` models an in-memory bidirectional stream rather than `webrtc-rs` SCTP `RTCDataChannel` half-open (`closed_not_dead`) buffering, and `SimWorld` runs no active file-transfer stall ladder (`detect_stall` `has_tx`).
- **`#748` (`956f6705f`, CLI `send` re-dialing signaling after server outage)**: Excluded because the fix and regression live in `cli/src/` (`send_redial.rs`, `send_cmd.rs`, `main.rs`), whereas `SimWorld` executes `filament-peerloop::recv::dispatch::drive` daemons rather than CLI `send`.
- **`#738` (`5166927aa`) non-blocking sub-fixes (`spawn_state_ping` and `PcState` `restart_ice`)**: Excluded individually because `SimTransport::send_control` and `SimPeer::restart_ice` are non-blocking in the simulator, leaving the inline `gather_candidates` sub-fix (`HangSite::GatherCandidates`) as the modeled `#738` seam.

## 4. Drop Rule Verdicts

Under the Drop Rule (a guide that does not beat or tie `unguided` across the real targets stays off by default):

| Guide | Default in `married()` | Empirical Basis on Real Targets (`20` seeds) | Notes |
|---|---|---|---|
| `swarm` | **ON** (`true`) | Beats `unguided` on both `#729` (`1.04x`) and `#738` (`1.37x`). | 35% clean-network subsets remove interfering partition/impair noise. |
| `message_chaos` | **ON** (`true`) | Ties `#729` (`0.98x`, `2.00x` on 5s) and beats `#738` (`1.14x`); combined `swarm + message_chaos` achieves **`1.29x`** on `#729` and **`2.12x`** on `#738` (20/20 on both). | Signaling frame drop/duplicate/reorder exercises real reconnect and gather timing windows cleanly. |
| `semantic` | **OFF** (`false`, opt-in) | Loses to `unguided` on both `#729` (`0.74x`) and `#738` (`0.53x`, `16/20`), and degrades `swarm + message_chaos` (`1.29x -> 0.55x` on `#729`; `2.12x -> 1.20x` on `#738`). | Triggering blackholes only after `SigConnected(1)` and pinning `GatherCandidates` hangs reduces diversity relative to `swarm + message_chaos`; remains available via `full_semantic()`. |
| `timer_edges`, `sometimes` mutation, `hill_climb` | **EXCLUDED** from `main` | Dropped in pre-landing ablation. | Not present in `crates/filament-peerloop/src/sim/fuzz.rs`. |

## 5. Clean `origin/main` 1,000-Run Verification and Parallel Throughput

Verified on rebased `dst/07-married-corpus` (`0966a2a5` on `linux-devloop`, `RUSTFLAGS="--cfg tokio_unstable"`, `DEVRESULT ok code=0 secs=486`):

- **Workspace & feature checks (`--locked`)**: `workspace`, `--no-default-features`, `--features dispatch`, and `--features mesh` all passed.
- **Unit & DST suites (`--locked --features sim`)**: `tunlion-signal --lib`, `tunlion-transport --lib`, `tunlion-peerloop --lib`, `dst_sim`, and `dst_fuzz_bench -- --test-threads=1` (`5 passed, 0 failed, 2 ignored, 132.04s`) all passed, plus `proofs/{establishment_model,link_manager_model,stall_ladder_model}.py`.
- **Clean `origin/main` 1,000-run stress (`--release`, `test_clean_main_1000_runs_married`, promoted `married()` + `allow_gather_hang: true`)**:
  - `CLEAN_MAIN_1000: runs=1000 workers=4 findings=0 wall_ms=1442 state_edges=57 max_busy_ms=0 max_status_ms=0` (`1.44s`, **0 findings / 0 false positives**).
- **120-run Parallel Throughput (`quiet_logs = true`)**:

| Build Profile | Mode | Workers | Runs | Wall Time (ms) | Throughput (runs/s) | Sim Cluster-Hours / s |
|---|---|---:|---:|---:|---:|---:|
| Debug (`unoptimized + debuginfo`) | Single-core | 1 | 120 | 6280 | 19.11 | 0.318 |
| Debug (`unoptimized + debuginfo`) | Parallel | 4 | 120 | 2759 | 43.49 | 0.725 |
| Release (`--release`) | Single-core | 1 | 120 | 395 | 303.80 | 5.063 |
| Release (`--release`) | Parallel | 4 | 120 | 179 | **670.39** | **11.173** |

## 6. Constructed-Target Reference Matrix (Secondary, Not Used for Promotion)

Secondary synthetic/mutant matrix (`dst_fuzz_bench::test_guidance_benchmark_matrix`, debug build, 5 seeds `[101, 202, 303, 404, 505]`, budget = 40, not used for default preset promotion):

| Target | Guide | Detected | Mean Runs | Median Runs | Mean Wall (ms) | Speedup vs Unguided |
|---|---|---:|---:|---:|---:|---:|
| `pre729_heartbeat` | `message_chaos` | 5/5 | 3.40 | 4.0 | 233.2 | 1.76x |
| `pre729_heartbeat` | `married` | 5/5 | 1.60 | 2.0 | 142.8 | 3.75x |
| `pre729_heartbeat` | `full_semantic` | 5/5 | 3.40 | 1.0 | 236.4 | 1.76x |
| `noise_sensitive_restart` | `unguided` | 5/5 | 11.20 | 6.0 | 623.6 | 1.00x |
| `noise_sensitive_restart` | `swarm` | 5/5 | 5.20 | 6.0 | 313.2 | 2.15x |
| `noise_sensitive_restart` | `semantic` | 5/5 | 13.20 | 11.0 | 724.4 | 0.85x |
| `noise_sensitive_restart` | `swarm_semantic` | 5/5 | 5.20 | 3.0 | 322.2 | 2.15x |
| `noise_sensitive_restart` | `message_chaos` | 5/5 | 7.80 | 9.0 | 465.2 | 1.44x |
| `noise_sensitive_restart` | `married` | 5/5 | 4.60 | 2.0 | 297.8 | 2.43x |
| `noise_sensitive_restart` | `full_semantic` | 5/5 | 5.20 | 2.0 | 325.2 | 2.15x |
| `timer_edge_silence` | `unguided` | 0/5 | 41.00 | 41.0 | 2049.6 | 1.00x |
| `timer_edge_silence` | `swarm` | 0/5 | 41.00 | 41.0 | 2033.8 | 1.00x |
| `timer_edge_silence` | `semantic` | 5/5 | 7.80 | 5.0 | 445.8 | 5.26x |
| `timer_edge_silence` | `swarm_semantic` | 5/5 | 6.40 | 3.0 | 387.6 | 6.41x |
| `timer_edge_silence` | `message_chaos` | 1/5 | 33.40 | 41.0 | 1762.6 | 1.23x |
| `timer_edge_silence` | `married` | 1/5 | 38.60 | 41.0 | 2064.4 | 1.06x |
| `timer_edge_silence` | `full_semantic` | 5/5 | 6.60 | 7.0 | 399.2 | 6.21x |
| `post_heal_liveness` | `unguided` | 5/5 | 1.40 | 1.0 | 125.4 | 1.00x |
| `post_heal_liveness` | `swarm` | 5/5 | 2.20 | 2.0 | 167.4 | 0.64x |
| `post_heal_liveness` | `semantic` | 5/5 | 1.40 | 1.0 | 119.8 | 1.00x |
| `post_heal_liveness` | `swarm_semantic` | 5/5 | 4.40 | 2.0 | 275.8 | 0.32x |
| `post_heal_liveness` | `message_chaos` | 5/5 | 1.60 | 1.0 | 143.2 | 0.87x |
| `post_heal_liveness` | `married` | 5/5 | 3.80 | 2.0 | 253.8 | 0.37x |
| `post_heal_liveness` | `full_semantic` | 5/5 | 3.00 | 3.0 | 206.6 | 0.47x |
| `reorder_glare` | `unguided` | 0/5 | 41.00 | 41.0 | 2027.4 | 1.00x |
| `reorder_glare` | `swarm` | 0/5 | 41.00 | 41.0 | 2009.2 | 1.00x |
| `reorder_glare` | `semantic` | 0/5 | 41.00 | 41.0 | 2024.6 | 1.00x |
| `reorder_glare` | `swarm_semantic` | 0/5 | 41.00 | 41.0 | 2059.6 | 1.00x |
| `reorder_glare` | `message_chaos` | 5/5 | 1.20 | 1.0 | 128.2 | 34.17x |
| `reorder_glare` | `married` | 5/5 | 1.20 | 1.0 | 119.2 | 34.17x |
| `reorder_glare` | `full_semantic` | 5/5 | 2.20 | 2.0 | 172.8 | 18.64x |

*(Note: earlier `pre729_heartbeat` rows for `unguided`/`swarm`/`semantic`/`swarm_semantic` scrolled past the devloop tail limit while `dst_fuzz_bench` exited 0 with 5 passed, 0 failed.)*

## 7. Persistent Corpus & Multi-Machine `tunlion sync` Workflow

- **Two-bucket layout**:
  - `corpus/` (living frontier cache): stores content-addressed `seed-<hash>.json` schedules. `corpus::load_and_triage_corpus` replays every file against the current binary, drops stale/obsolete seeds via greedy set-cover `minimize_corpus`, and prunes unreferenced `seed-*.json` files on save.
  - `regressions/` (permanent bug bank): `finding-<hash>.json`, never pruned by minimization, replayed deterministically via `Fuzzer::replay_regressions`.
- **Cross-machine sync without cloud buckets**: Because files are content-addressed JSON and small (< 1 MB), machines can merge discovered frontiers conflict-free via `tunlion sync` (without `--delete`):

```bash
tunlion sync --no-interactive ~/dst-corpus/corpus devbox:dst-corpus/corpus
tunlion sync --no-interactive ~/dst-corpus/regressions devbox:dst-corpus/regressions
```

## 8. Reproduction Commands

```bash
export RUSTFLAGS="--cfg tokio_unstable"
cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture
cargo test --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench -- --nocapture --test-threads=1
cargo test --release --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench test_clean_main_1000_runs_married -- --ignored --nocapture
cargo test --release --locked -p tunlion-peerloop --features sim --test dst_fuzz_bench test_parallel_throughput_benchmark -- --nocapture
```
