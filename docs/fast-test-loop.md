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
