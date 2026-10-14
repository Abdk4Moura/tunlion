#!/usr/bin/env bash
# Build the shared SPAKE2 core to WASM and emit wasm-bindgen JS bindings into
# the frontend. Run from anywhere. Regenerate after any change to pake/src.
#
# Output: frontend/src/pake/  (filament_pake.js, filament_pake_bg.wasm, .d.ts)
# These are COMMITTED so a plain `npm run build` needs no Rust toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/../frontend/src/pake"

# --lib: the module is the library. The GATE4 parity bins under src/bin are
# native-only tools and are not part of what the browser loads.
cargo build --manifest-path "$HERE/Cargo.toml" --release --lib --target wasm32-unknown-unknown
mkdir -p "$OUT"
wasm-bindgen --target web --out-dir "$OUT" \
  "$HERE/target/wasm32-unknown-unknown/release/filament_pake.wasm"

# No wasm-opt: its output depends on the binaryen version, and CI
# (.github/workflows/pake-wasm.yml) rebuilds this module and diffs it against
# the committed one, so the build must be reproducible from the pinned Rust and
# wasm-bindgen alone.
echo "wasm size: $(wc -c < "$OUT/filament_pake_bg.wasm") bytes"
echo "wrote bindings to $OUT"
