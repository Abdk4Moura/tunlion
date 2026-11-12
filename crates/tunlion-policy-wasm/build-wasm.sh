#!/usr/bin/env bash
# Build the shared transfer-admission policy to WASM and emit wasm-bindgen
# bindings into the frontend. Run from anywhere. Regenerate after any change to
# crates/filament-policy or crates/tunlion-policy-wasm.
#
# Output: frontend/src/policy/ (tunlion_policy_wasm.js, _bg.wasm, .d.ts)
# These are COMMITTED so a plain `npm run build` needs no Rust toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/frontend/src/policy"
TARGET="${CARGO_TARGET_DIR:-$ROOT/target}"

cd "$ROOT"
cargo build --locked -p tunlion-policy-wasm --release --lib --target wasm32-unknown-unknown
mkdir -p "$OUT"
rm -f "$OUT/tunlion_policy_wasm.js" "$OUT/tunlion_policy_wasm_bg.wasm" \
      "$OUT/tunlion_policy_wasm.d.ts" "$OUT/tunlion_policy_wasm_bg.wasm.d.ts"
wasm-bindgen --target web --out-dir "$OUT" \
  "$TARGET/wasm32-unknown-unknown/release/tunlion_policy_wasm.wasm"

# No wasm-opt: its output depends on the binaryen version, and CI
# (.github/workflows/policy-wasm.yml) rebuilds this module and diffs it against
# the committed one, so the build must be reproducible from the pinned Rust and
# wasm-bindgen alone.
echo "wasm size: $(wc -c < "$OUT/tunlion_policy_wasm_bg.wasm") bytes"
echo "wrote bindings to $OUT"
