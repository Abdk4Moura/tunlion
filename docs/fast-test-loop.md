# Test Loop Optimization: Measurement and Architecture (Project 1)

## 1. Empirical Bottleneck Analysis (`main` at `e6b5648e2`)

### 1.1 CI Breakdown (PR #770 `Test/cargo test (linux)`: `1,769s` / `29m 29s`)
Even at **99.57% `sccache` hit rate**, **`96.4%` (`~28m 25s`) of CI wall time was compilation and single-threaded fat-LTO linking**, while actual test execution across ~2,000 unit tests was ~`18s`:

| Step in `test.yml` | Total Time | Test Run Time | Root Bottleneck |
|---|---:|---:|---|
| `Test` (`cli` unit + 21 integration bins) | `7m 48s` | `8.96s` units + `0.76s` (18 int bins) + `10.38s` (`timeout_tests`) + `25.37s` (`pty_flows`) | `--release` (`lto="fat", codegen-units=1`) linked 22 separate binaries with GNU `ld` |
| `Test the local crates` (13 crates loop) | `12m 05s` | `< 9s` total (`8.33s` in `tunlion-peerloop`) | Sequential per-crate `--release` fat-LTO links (`4m 08s` for `tunlion-peerloop` alone) |
| `L3 overlay library` (`tunlion-peerloop --features l3`) | `4m 28s` | `8.34s` | Whole-crate `--release` rebuild/fat-LTO link under `--features l3` |
| `L3 CLI state` (`cargo test --release -p tunlion --test l3_state_cli`) | `4m 51s` | **`0.01s`** | Working-directory / feature-hash mismatch triggered a full `cli` release rebuild+link for 2 tests |

### 1.2 Toolchain & Linker Benchmarks (4-core `ubuntu-latest`, `tunlion-peerloop --lib`)

| Configuration | Cold Build | 1-Line `conn.rs` Edit (`--no-run`) | Test Run (`964` tests) | Notes |
|---|---:|---:|---:|---|
| Baseline stable debug (`GNU ld`, `debug=2`, O0 deps) | `95.00s` | `6.42s` | `16.32s` (`cargo test`) / `13.50s` (`nextest`) | Total 1-line edit+run: `19.92s` (`nextest`) |
| Stable + `mold 2.40.4` + `debug=0` + deps `opt-level=2` | `170.13s` | `4.98s` | `15.04s` (`nextest`) | `-22%` rebuild+link vs GNU `ld` |
| Nightly LLVM (`-Zthreads=4`, `mold`, `debug=0`, deps `opt-level=2`) | `25.14s` (ws) | `4.35s` | `n/a` | Near-parity with Cranelift on incremental single-CGU edits |
| Nightly **Hybrid Cranelift** (`workspace=cranelift`, `deps=llvm -O2`, `-Zthreads=4`, `mold`, `debug=0`) | `166.24s` | **`4.21s`** | **`10.60s`** (`nextest`) | Total **`~14.8s`** warm inner loop for `tunlion-peerloop` |
| `cli --bin tunlion` (nightly LLVM, `mold`, `debug=0`, deps `-O2`) | `29.73s` (vs `422s` release LTO) | `1.97s` | `9.36s` (`979` unit tests) | Linking all `21` `cli/tests/*.rs` binaries added `14.55s` even with `mold` + `debug=0` |

### 1.3 Key Toolchain Caveats Discovered Empirically
1. **Global Cranelift hits crypto AVX-512 abort:** Compiling third-party crypto crates (`curve25519-dalek` / `ring`) with Cranelift aborted at runtime (`llvm.x86.avx512.vpmadd52l.uq.256`, `rustc_codegen_cranelift#171`). Using Cargo `-Z codegen-backend` to keep dependencies on **LLVM (`opt-level=2`)** while compiling workspace crates with **Cranelift** resolved the crash (`963/964` passed on the initial run, `1` unrelated failure under investigation).
2. **`cli` under Cranelift hits Clap stack overflow:** `tunlion --bin tunlion` hit `fatal runtime error: stack overflow` under Cranelift on Clap's deep command tree. `scripts/fast-test.sh` automatically keeps `cli` on LLVM (`fast-test` + `mold`) while enabling hybrid Cranelift for `tunlion-peerloop` and library crates.

## 2. Changes Implemented in PR 1

1. **`[profile.ci-test]` and `[profile.fast-test]` in `Cargo.toml`:**
   - Keeps `[profile.release]` (`lto = "fat"`, `codegen-units = 1`, `strip = true`) untouched for all shipping `cross-build` / release artifacts.
   - `ci-test`: inherits `release` (`debug_assertions = false`, deps at `opt-level = 2`), disables LTO (`lto = false`), sets `opt-level = 1` + `codegen-units = 256` + `debug = "line-tables-only"` for fast CI test compilation without changing release runtime semantics.
   - `fast-test`: inherits `dev` (`opt-level = 0`, `debug = 0`, `codegen-units = 256`, `incremental = true`) with third-party deps optimized at `opt-level = 2`.
2. **`cli/tests/cli_integration.rs`:** Consolidates 18 standalone CLI integration test binaries into one integration test binary (leaving `capability_harness.rs`, `pty_flows.rs`, and `windows_menu_smoke.rs` separate). Eliminates 17 redundant link passes of `tokio + webrtc + quinn + ring + smoltcp + clap`.
3. **`.github/workflows/test.yml`:**
   - Installs `mold` + `clang` on Linux `cargo test (linux)`.
   - Switches `cargo test (linux)`, `cargo test (windows)`, and `pty-flows` from `--release` fat-LTO to `--profile ci-test --locked`.
   - Changes `L3 CLI state` to reuse the already-compiled `cli_integration` binary (`--test cli_integration l3_state_cli::`) and asserts `test result: ok. 2 passed`.
4. **`scripts/fast-test.sh`:** Local / Colab Pro fast inner-loop runner (`--setup`, `--cranelift`, `mold`, `cargo-nextest`, `--profile fast-test`).

## 3. PR 2 & PR 3 Measured CI Impact

Across PR #770 (baseline `--release` fat-LTO), PR #774 (`ci-test` + `mold` + single-binary `cli_integration`), PR #783 (3-way `gate-suite`, 2-way `revoke-gates`, uniform Linux `sccache` C/Rust env, `target/ci-test` caching, `daemon_identity_tests` `ETXTBSY` fix), and PR #3 (4-way `gate-suite` + 3-way `revoke-gates`):

| Workflow / Job | PR #770 Baseline | PR #774 | PR #783 Measured | PR #3 Target |
|---|---:|---:|---:|---:|
| `Test/cargo test (linux)` | `29m 29s` | `23m 50s` (cold) | **`12m 10s`** | `~10-12m` |
| `Test/cargo test (windows)` | `~22m+` | `22m 33s` (cold) | **`6m 12s`** | `~6m` |
| `Gate Suite/gate suite` (longest shard) | `~50m+` | `50m 13s` | `23m 52s` (`net`; `core-web` `10m 19s`, `daemon` `10m 47s`) | **`~10-12m`** (splits `lan-discovery` & `lan-pairing`) |
| `Revoke Gates/revoke gates` (longest shard) | `~23m+` | `22m 49s` | `15m 04s` (`core`; `fleet` `8m 11s`) | **`~8-10m`** (splits `core-a` & `core-b`) |
| `Capability CI/smoke (ubuntu)` | `~14m` | `12m 57s` | `14m 03s` (`--release` retained) | `14m 03s` |

### Empirical Constraints Preserved
1. **`capability_harness` keeps `--release`:** `cli/tests/capability_harness.rs` requires `profile == "release"` for `direct_blocked_falls_back_to_webrtc_promptly`, and Windows `LOOP-BUDGET-EXCEEDED` (1,000 ms event-loop budget) exceeded 1 s at `1,026 ms` under `ci-test` `opt-level = 1`. Both `capability-ci.yml` jobs remain on `--release`.
2. **`daemon_identity_tests` Unix `ETXTBSY` race fixed:** Consolidating 18 CLI integration tests into one binary increased concurrent `fork()` calls during test execution; copying `real_bin()` via a short-lived Unix `cp` child process plus bounded `ExecutableFileBusy` retry eliminated the flake.

## 4. Reaching the ~12s Inner Loop: Local / Colab Pro Workflow and Delegable Phase 3 Roadmap

### 4.1 Colab Pro / High-Core Inner Loop Setup
Run `scripts/fast-test.sh` on a Colab Pro or multi-core Linux VM to get ~14-15s edit+test loops on `tunlion-peerloop` (`964` tests) and sub-12s runs on targeted filters:

```bash
# One-time setup (mold + clang + cargo-nextest + nightly hybrid Cranelift + optional wild linker)
scripts/fast-test.sh --setup --nightly --wild

# Warm inner loop (Hybrid Cranelift workspace + O2 LLVM deps, mold, nextest, /dev/shm tmpfs when >= 8 GiB free)
scripts/fast-test.sh --cranelift --ramdisk peerloop

# CLI binary + cli_integration (keeps LLVM automatically to avoid Clap Cranelift stack overflow)
scripts/fast-test.sh --ramdisk cli

# Experimental wild linker
scripts/fast-test.sh --cranelift --linker wild peerloop
```

### 4.2 Remaining Delegable Optimization Levers (Project 1 Phase 3)
1. **Replace real wall-clock sleeps in unit & CLI integration tests (`virtual time`):**
   - `cli/tests/cli_integration/daemon_identity_tests.rs` holds a `TcpListener` thread asleep for `20s`, and `cli/tests/cli_integration/timeout_tests.rs` waits `~10s` real time against an unreachable peer.
   - `crates/filament-peerloop/src/l2/{mux,warm_send,warm_exec}.rs` and `sync.rs` contain multi-second `tokio::time::interval` / `timeout` constants; converting internal protocol timer tests to `tokio::time::pause()` + `advance()` (coordinated after structural splits land) removes ~10-20s of idle wall-clock sleeping per test run.
2. **Adopt `cargo-nextest` in `.github/workflows/test.yml`:** Runs unit + `cli_integration` suites across all vCPUs cleanly and isolates per-process failures without `ETXTBSY`/shared-process contention.
3. **Crate-graph impact filtering in `scripts/ci_changes.py`:** Upgrade binary `rust=true|false` classification to fail-open per-crate outputs (while keeping required status check names green) so leaf-crate changes skip unrelated heavy suites.
4. **Prelinked dynamic dependency crate (`dylib` monolith) for `--profile fast-test`:** Extract heavy third-party dependencies (`tokio`, `webrtc`, `quinn`, `rustls`, `reqwest`, `serde_json`, `clap`) into an opt-in workspace `dylib` dev-only wrapper so 1-line workspace edits only relink thin test binaries instead of re-linking 100+ static `.rlib` archives.
