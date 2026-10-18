#!/usr/bin/env bash
# Local runner for the shell/link durability soak (test-only).
#
#   (cd cli && cargo build --release --features test-hooks)
#   scripts/durability-soak.sh --runs 2 --stable-secs 150
#
# Does NOT build: this repo's target dir is shared in some dev environments and
# a surprise build in the middle of a soak is not a test result. Build first.
# Evidence (daemon/client logs + summary.json) is always kept under
# /tmp/tunlion-durability-soak; override with DURABILITY_WORK_ROOT.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -n "${TUNLION_BIN:-}" ]; then
  BIN="$TUNLION_BIN"
elif [ -n "${FILAMENT_BIN:-}" ]; then
  BIN="$FILAMENT_BIN"
elif [ -x "$ROOT/target/release/tunlion" ]; then
  BIN="$ROOT/target/release/tunlion"
else
  BIN="$ROOT/cli/target/release/tunlion"
fi

if [ ! -x "$BIN" ]; then
  echo "no executable tunlion at $BIN" >&2
  echo "build the gate binary first: (cd $ROOT/cli && cargo build --release --features test-hooks)" >&2
  exit 2
fi

exec python3 "$ROOT/cli/tests/durability_soak.py" --bin "$BIN" "$@"
