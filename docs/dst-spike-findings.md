# Deterministic Simulation Testing (DST) Spike Findings

Branch: `spike/dst` (branched from `origin/main` at `0325210cb`)
Runtime target: single `current_thread` Tokio runtime with `start_paused(true)` and `rng_seed` (`RUSTFLAGS="--cfg tokio_unstable"`).

## 1. Architecture and Seams (`sim` Cargo Feature)

All simulation seams sit behind `--features sim` across `tunlion-signal`, `tunlion-transport`, and `tunlion-peerloop` with zero external crate additions and no changes to `Cargo.lock`:

1. **Clock and Runtime Determinism (`crates/filament-transport/src/clock.rs`, `crates/filament-peerloop/src/sim_rt.rs`)**:
   - Under `sim`, `clock::Instant` aliases `tokio::time::Instant` rather than `std::time::Instant`. Because `tokio::time::Instant::now()` reads virtual runtime time, `clock::now_ms()` computes milliseconds since a thread-local `SIM_EPOCH` reset at the start of every `SimWorld::run` via `clock::reset_sim_epoch()` (avoiding a process-global `OnceLock` shared across sequential runs).
   - `SimHashMap<K, V>` and `SimHashSet<K>` use a fixed 64-bit FNV-1a hasher (`DetBuildHasher`) under `sim` for deterministic iteration order, and `HashMap` in default builds.
   - `sim_rt::run_blocking` and `WriterTasks::spawn` (`recv/dispatch.rs:1084`) execute blocking closures inline only when `SIM_BLOCKING_INLINE` is armed inside `SimWorld::run`, falling back to `tokio::task::spawn_blocking` otherwise so regular unit tests with gated blocking writers pass under `--features sim`.
   - `sim_rt::set_sim_watchdog_disabled(true)` suppresses spawning the real-time OS `loop-watchdog` thread inside DST.
   - `SimLoopBudget` in `recv/dispatch.rs` mirrors PR `#731`'s 1 s busy-iteration oracle in virtual time and emits `LOOP-BUDGET-EXCEEDED <busy_ms> <phase>/<event> slowest_ms=<n> budget_ms=1000` on violations.

2. **Signaling (`crates/filament-signal/src/lib.rs`, `crates/filament-transport/src/context.rs`)**:
   - `SignalingBackend` trait + `Client::from_sim_backend(id, backend)` + `SignalingConnector` on `TransportContext`.
   - `SimNetwork` implements an in-memory signaling router (`welcome`, `subscribe` -> `known-peer`, `sync` -> `synced` + ack, `signal` forwarding, `peer-left` on node kill, `blackhole` blocking `emit_with_ack` until timeout).

3. **HTTP Backend (`TransportContext::with_http_backend`)**:
   - `HttpBackend` intercepts `net::http_get_json` for `/api/whoami`, `/api/config`, and `/api/room`, enabling blackhole and virtual-time hang injection.

4. **WebRTC Peer Lifecycle (`PeerBackend` / `PeerFactory` in `crates/filament-transport/src/net.rs`)**:
   - `PeerFactory::connect` and `PeerBackend` replace real ICE/DTLS/SCTP `RTCPeerConnection` setup in `Conn` under `sim`.

5. **Direct QUIC Path (`DirectBackend` + `UnreadTransport::from_sim_with_reader` in `crates/filament-transport/src/direct.rs`)**:
   - Replaces real UDP binds, candidate gathering, and QUIC simultaneous-open dialing (`gather_candidates`, `bind_endpoint_with_context`, `local_ip_snapshot_with_context`, `race_connect_labeled`).
   - Paired `SimTransport` endpoints deliver `Ev::Sourced` `Control` and `Chunk` events over virtual-time delayed channels; the reader future is deferred inside `UnreadTransport::from_sim_with_reader` until `UnreadTransport::announce` queues `Ev::DirectReady`, preserving race-free ordering.

## 2. Static-State and Hermeticity Audit

Multi-daemon in-process DST exposes every piece of process-global state in `crates/filament-{peerloop,transport,signal}/src`:

| Symbol / Location | Classification | Impact in DST | Action / Status |
|---|---|---|---|
| `NEXT_CONN_ID` (`filament-signal/src/lib.rs:52`) | Tolerated monotonic ID (if not surfaced in traces) | Caused `run1` vs `run2` trace divergence across sequential runs and parallel test threads when formatted directly into `sim-sid-<N>` | Fixed in `SimNetwork` with per-world `next_sid` counter (`alloc_conn_id()` kept internal) |
| `SourceId::next`, `AttemptId::next` (`net.rs:293,323`) | Tolerated monotonic IDs | Sequential under `current_thread`; not printed in trace messages | Tolerated (keep out of normalized trace strings) |
| Monotonic request/stream counters (`net.rs:928,3711`, `direct.rs:1349,3125`, `conn.rs:3037`, `daemon_ctl.rs:101`, `sync.rs:1264,2388`, `mount/mod.rs:383`, `mount_proto.rs:4213`) | Tolerated monotonic counters | Deterministic on a single thread when not leaked into trace assertions | Tolerated |
| `SIM_EPOCH` (`clock.rs`), `SIM_BLOCKING_INLINE`, `SIM_DISABLE_WATCHDOG`, `SIM_INLINE_STALL_MS` (`sim_rt.rs`) | Harness thread-local controls | Reset at start/end of every `SimWorld::run` | Handled by `SimWorld::run` |
| `lan::enabled` setting check (`lan.rs:1747`) | Config-driven hermeticity hazard | Reads `"network.transports"`, NOT `"lan"`; leaving it unset opened real multicast sockets and injected `lan-*` peers into the trace | Set `"network.transports" = "direct,relay"` in both `SimNetwork::node_context` and `SimHost::settings_get_str` |
| `conn.rs:9736` (`thread_local! INLINE`) | Harness-safe on single thread | Only affects current-thread inline toggle | Safe under current harness |
| `l2/mux.rs:841` (`WARM_EXECS_LIVE`) | Real per-daemon static blocker | Global exec counter shared across all daemons in one process | Move onto `Conn` or daemon state in Phase 2 |
| `daemon_ctl.rs:465` (`WARM_PTY_END_REASONS`) | Real per-daemon static blocker | Global `OnceLock<Mutex<HashMap<..>>>` shared across daemons | Scope per daemon instance in Phase 2 |
| `recv/store.rs:90,102` (`DELISTED_CACHE`, `DELISTED_WRITE_ERROR`) | Real per-daemon static blocker | Bypassed by `NoStore`, blocks running real `DeviceStore` multi-daemon | Move onto store instance in Phase 2 |
| `l3/mod.rs:1298` (`NATIVE_V4_PROBLEM`) | Real per-daemon static blocker | Global diagnostic latch across daemons | Scope per daemon / `RecvEnv` in Phase 2 |
| `transport/direct.rs:92,93,177,1131` (`DIED_ONCE`, `TOTAL_DIRECT_BYTES`, `FROZE_ONCE`, `TEST_STALL_MS`) | Real shared test-hook statics | Process-global across daemons under `test-hooks` | Move into `TransportContext` if combining `sim` + `test-hooks` |
| `transport/net.rs:32` (`STALL_WATCHDOG_ARMED`), `transport/hooks.rs:10..78` (`OnceLock` hooks) | Real shared process hooks | Process-global `OnceLock` loggers/resolvers | Use `TransportContext` / `LogSink` per daemon |
| `peerloop/test_hooks.rs:40,62,103,125,168` | Real shared test-hook statics | Global one-shot latches under `test-hooks` | Scope per world if needed |
| `transport/lan.rs:183,1340` (`SEAMS`, `START`) | Disabled in sim | Not reached when `network.transports = "direct,relay"` | Disabled in DST |

## 3. Determinism Guarantees and Caveats

- **Thread-per-world execution**: `SimWorld::run` runs 2 to 3 real `recv::dispatch::drive` tasks inside one `Builder::new_current_thread().enable_all().start_paused(true)` runtime with `.rng_seed(...)`. Calling `cargo test` in parallel across multiple tests requires isolating any state that enters event traces inside `SimNetwork` / `SimWorld` (never format process-global atomic counters into peer IDs).
- **Control channel (`ReqKind::CapStatus`)**: `SimHost::serve_control` captures `ctl_tx` and `send_cap_status` sends real `Req` values over `tokio::net::UnixStream::pair()`. Calling `tokio::task::yield_now().await` immediately after `tx.send(req)` lets the daemon loop answer on the current tick instead of advancing virtual timers across `PollEvented` readiness.
- **No external runtime leakage**: Once `"network.transports"` is set to `"direct,relay"` and `LoopWatchdog` is disabled, zero background OS threads or multicast UDP sockets remain active during simulation.

## 4. Measured Results on `devbox`

All measurements were run on `devbox` (`4 cores, 31 GiB RAM, rustc 1.100.0`):

- **`dst_sim` integration suite** (`RUSTFLAGS="--cfg tokio_unstable" cargo test --locked -p tunlion-peerloop --features sim --test dst_sim -- --nocapture`):
  - **5 passed, 0 failed, 0 ignored in 0.66s**
  - `test_two_daemon_connect_and_determinism`: same seed (`42`) produced bit-exact identical `events` and identical 64-bit FNV-1a `trace_hash`.
  - `test_replay_loop_stall_under_loss`: replayed corpus `loop-stall-under-loss-debug.json` (seed `391743414`, 48 s simulated time, `alpha`/`bravo`), 0 budget violations, both `CapStatus` checks `< 1000 ms`.
  - `test_replay_status_stall_blackhole_plus_peer_restart`: replayed corpus `status-stall-blackhole-plus-peer-restart.json` (seed `950782088`, 60 s simulated time, 3 daemons `alpha`/`bravo`/`charlie`, `Udp` partition, `charlie` signaling blackhole `4.9s..54.6s`, `bravo` kill/restart `18.5s..21.8s`, `CapStatus` on `charlie` at `39.1s`), 0 budget violations and `ok: true` in `< 1000 ms`.
  - `test_oracle_catches_injected_inline_stall`: arming `set_sim_inline_stall_ms(1500)` triggered `LOOP-BUDGET-EXCEEDED ... budget_ms=1000`.
  - `test_throughput_benchmark`: `DST_BENCHMARK: runs=100 wall_ms=660 runs_per_sec=151.41`.
- **Workspace default & unit test regression verification**:
  - `cargo check --locked --workspace`: exited 0.
  - `cargo test --locked -p tunlion-signal -p tunlion-transport --lib`: 21 passed (`tunlion-signal`), 87 passed (`tunlion-transport`).
  - `RUSTFLAGS="--cfg tokio_unstable" cargo test --locked -p tunlion-peerloop --features sim --lib`: **920 passed, 0 failed, 0 ignored in 12.47s**.

### Pre-#729 Inline-Await Reproduction vs `main`

In a scratch copy on `devbox` (`~/dst-work/pre729-check`), reverting commit `19855e841`'s spawned heartbeat (`dispatch.rs:3740`) back to inline `net::heartbeat(&sio, payload, tx).await;` caused `test_replay_status_stall_blackhole_plus_peer_restart` to **fail in 0.05s (`PRE729_EXIT_CODE=101`)** with exact 5 s loop stalls while `main` passed:

```text
loop stall detected under blackhole+restart: [
  "charlie@21008ms: [critical] LOOP-BUDGET-EXCEEDED 5000 signaling-heal/none slowest_ms=5000 budget_ms=1000",
  "charlie@42212ms: [critical] LOOP-BUDGET-EXCEEDED 5000 signaling-heal/none slowest_ms=5000 budget_ms=1000"
]
```

### Bonus Discovery: Remaining Inline `gather_candidates` Await (`conn.rs:5992`)

When injecting a 3000 ms hang on `HangSite::GatherCandidates` during `test_replay_status_stall_blackhole_plus_peer_restart`, `main` itself triggered:

```text
charlie@59532ms: [critical] LOOP-BUDGET-EXCEEDED 3000 handler/known-peer slowest_ms=3000 budget_ms=1000
```

Inspection of `crates/filament-peerloop/src/conn.rs:5992` confirms `Conn::start_direct` still awaits `direct::gather_candidates(&self.transport_context, &self.server, port)` inline inside the `Ev::KnownPeer` handler before spawning the race task. In real runs on `main`, `a88efe2f9` avoids this only when `/api/whoami` hits the 300 s `PubIpEntry` cache; on a cold cache miss under blackhole, a slow HTTP `/api/whoami` stall can still block `KnownPeer`. Moving `gather_candidates` + `srflx` gathering inside the spawned `race_task` is a clean follow-up improvement.

## 5. Phase 2 Recommendations

1. Add `RUSTFLAGS="--cfg tokio_unstable" cargo test --locked -p tunlion-peerloop --features sim --test dst_sim` to PR CI (~0.7 s execution after compile), plus a multi-seed property fuzz test sweeping hundreds of seeds with randomized fault schedules and active data transfers (`SendEngine` + `RecvPorts`).
2. Move `gather_candidates` inside the spawned race task in `Conn::start_direct` (`conn.rs:5992`) so cold `/api/whoami` stalls cannot trigger `LOOP-BUDGET-EXCEEDED` in `handler/known-peer`.
3. Eliminate the remaining per-daemon globals (`WARM_EXECS_LIVE`, `WARM_PTY_END_REASONS`, `DELISTED_CACHE`, `NATIVE_V4_PROBLEM`) to allow running full `CliHost` / L2 / L3 / store scenarios concurrently inside one DST process.
