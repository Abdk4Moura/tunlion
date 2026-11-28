#!/usr/bin/env bash
# Fast inner-loop test runner for developers, Colab Pro workers, and CI agents.
# Uses `--profile fast-test` (O0 workspace + O2 third-party deps, debug=0),
# `mold` (or `wild`) linker, `cargo-nextest` if installed, and optional hybrid
# nightly Cranelift (`workspace=cranelift`, `deps=llvm -O2`) for non-CLI crates.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/fast-test.sh --setup [--nightly] [--wild]
  scripts/fast-test.sh [--cranelift] [--linker auto|mold|wild] [--ramdisk] [target] [filter...]

Targets:
  peerloop    Test tunlion-peerloop --lib (supports --cranelift)
  cli         Test tunlion bin + cli_integration (auto-keeps LLVM; avoids Cranelift Clap stack overflow)
  cap         Test filament-cap --lib (supports --cranelift)
  dst         Run clean_main 1000-run DST smoke (--profile ci-test --features sim)
  workspace   Test all crates/* library suites
  <pkg>       Any Cargo package name (passed to -p <pkg>)

Flags:
  --setup            Install mold, clang, cargo-nextest (and nightly Cranelift / wild 0.11.0 with --nightly / --wild)
  --cranelift        Enable nightly hybrid per-package Cranelift + -Zthreads for non-CLI targets
  --linker MODE      Select linker: auto (default: mold), mold, or wild
  --ramdisk          Use /dev/shm/tunlion-fast-target when >= 8 GiB RAM disk is free (Colab Pro / tmpfs)
  --no-run           Compile only (skip executing tests)
  -h, --help         Show this help
EOF
}

if [ "${1:-}" = "--setup" ]; then
  shift
  SETUP_NIGHTLY=0
  SETUP_WILD=0
  while [ $# -gt 0 ]; do
    case "$1" in
      --nightly) SETUP_NIGHTLY=1; shift ;;
      --wild) SETUP_WILD=1; shift ;;
      *) echo "unknown setup flag: $1" >&2; exit 2 ;;
    esac
  done
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y -qq mold clang
  fi
  mkdir -p "${HOME}/.cargo/bin"
  if ! command -v cargo-nextest >/dev/null 2>&1; then
    curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C "${HOME}/.cargo/bin"
  fi
  if [ "$SETUP_NIGHTLY" -eq 1 ]; then
    rustup toolchain install nightly --profile minimal --component rustc-codegen-cranelift-preview
  fi
  if [ "$SETUP_WILD" -eq 1 ] && ! command -v wild >/dev/null 2>&1; then
    tmpdir=$(mktemp -d)
    if curl -fsSL https://github.com/wild-linker/wild/releases/download/0.11.0/wild-linker-0.11.0-x86_64-unknown-linux-gnu.tar.gz \
        | tar -xzC "$tmpdir" -f -; then
      wbin=$(find "$tmpdir" -type f -name wild | head -n1 || true)
      if [ -n "$wbin" ]; then
        install -m 755 "$wbin" "${HOME}/.cargo/bin/wild"
      fi
    fi
    rm -rf "$tmpdir"
  fi
  echo "fast-test setup complete"
  exit 0
fi

USE_CRANELIFT=0
NO_RUN=0
LINKER_MODE=auto
USE_RAMDISK=0
while [ $# -gt 0 ]; do
  case "$1" in
    --cranelift) USE_CRANELIFT=1; shift ;;
    --linker)
      LINKER_MODE="${2:?--linker requires auto, mold, or wild}"
      shift 2
      ;;
    --linker=*)
      LINKER_MODE="${1#--linker=}"
      shift
      ;;
    --ramdisk) USE_RAMDISK=1; shift ;;
    --no-run) NO_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) break ;;
  esac
done

TARGET="${1:-peerloop}"
if [ $# -gt 0 ]; then
  shift
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
export CARGO_INCREMENTAL=1

if [ "$USE_RAMDISK" -eq 1 ]; then
  shm_avail_mb=$(df -Pm /dev/shm 2>/dev/null | awk 'NR==2 {print $4}' || echo 0)
  if [ "${shm_avail_mb:-0}" -ge 8192 ]; then
    export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/dev/shm/tunlion-fast-target}"
  else
    echo "fast-test: /dev/shm has ${shm_avail_mb:-0} MiB free (<8192 MiB); using default target dir" >&2
  fi
fi

# Configure fast linker via clang without clobbering existing RUSTFLAGS.
case "$LINKER_MODE" in
  auto|mold)
    if command -v mold >/dev/null 2>&1 && command -v clang >/dev/null 2>&1; then
      case "${RUSTFLAGS:-}" in
        *-fuse-ld=mold*|*--ld-path=*) ;;
        *) export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Clinker=clang -Clink-arg=-fuse-ld=mold" ;;
      esac
    elif [ "$LINKER_MODE" = "mold" ]; then
      echo "fast-test: mold and clang are required for --linker mold" >&2
      exit 2
    fi
    ;;
  wild)
    WILD_BIN=$(command -v wild || true)
    if [ -z "$WILD_BIN" ] || ! command -v clang >/dev/null 2>&1; then
      echo "fast-test: wild and clang are required for --linker wild (run --setup --wild)" >&2
      exit 2
    fi
    case "${RUSTFLAGS:-}" in
      *--ld-path=*|*-fuse-ld=*) ;;
      *) export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Clinker=clang -Clink-arg=--ld-path=${WILD_BIN}" ;;
    esac
    ;;
  *)
    echo "fast-test: invalid --linker mode '$LINKER_MODE' (expected auto, mold, or wild)" >&2
    exit 2
    ;;
esac

COMMON_ARGS=(--locked --profile fast-test)
RUNNER_SUB=(test)
if [ "$NO_RUN" -eq 0 ] && command -v cargo-nextest >/dev/null 2>&1; then
  RUNNER_SUB=(nextest run)
fi

if [ "$USE_CRANELIFT" -eq 1 ] && [ "$TARGET" != "cli" ] && [ "$TARGET" != "dst" ]; then
  export RUSTUP_TOOLCHAIN=nightly
  export CARGO_UNSTABLE_CODEGEN_BACKEND=true
  THREADS=$(nproc 2>/dev/null || echo 4)
  case "${RUSTFLAGS:-}" in
    *-Zthreads=*) ;;
    *) export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }-Zthreads=${THREADS}" ;;
  esac
  COMMON_ARGS+=(
    --config 'profile.fast-test.codegen-backend="cranelift"'
    --config 'profile.fast-test.package."*".codegen-backend="llvm"'
  )
fi

case "$TARGET" in
  peerloop)
    PKG_ARGS=(-p tunlion-peerloop --lib)
    ;;
  cap)
    PKG_ARGS=(-p filament-cap --lib)
    ;;
  cli)
    PKG_ARGS=(-p tunlion --bin tunlion --test cli_integration)
    ;;
  dst)
    exec env RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--cfg tokio_unstable" \
      cargo test --locked --profile ci-test -p tunlion-peerloop --features sim \
      --test dst_fuzz_bench test_clean_main_1000_runs_married -- --ignored --nocapture
    ;;
  workspace)
    PKG_ARGS=(--workspace --exclude tunlion)
    ;;
  *)
    PKG_ARGS=(-p "$TARGET" --lib)
    ;;
esac

if [ "$NO_RUN" -eq 1 ]; then
  exec cargo test "${COMMON_ARGS[@]}" "${PKG_ARGS[@]}" --no-run
fi

if [ "${RUNNER_SUB[0]}" = "nextest" ]; then
  exec cargo nextest run "${COMMON_ARGS[@]}" "${PKG_ARGS[@]}" "$@"
else
  exec cargo test "${COMMON_ARGS[@]}" "${PKG_ARGS[@]}" "$@"
fi
