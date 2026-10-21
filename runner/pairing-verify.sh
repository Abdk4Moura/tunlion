#!/usr/bin/env bash
# Run ONLY on the existing CI worker, via scripts/ci-worker-exec.sh.
# Prereqs: its cached Rust toolchain, tools/backend venv and tools/terminal npm
# packages (@xterm/headless + @xterm/xterm 6.0.0, Playwright 1.63.0), Chromium.
set -euo pipefail
if [ ! -f "${TUNLION_WORKER_ROOT:-/nonexistent}/worker.env" ]; then
  echo 'Refusing a local build: run this through scripts/ci-worker-exec.sh.' >&2
  exit 2
fi
source "$TUNLION_WORKER_ROOT/worker.env"
cd "$(dirname "$0")/.."
OUT="$TUNLION_WORKER_ROOT/results/validation-$(date -u +%Y%m%dT%H%M%S)-$$"
mkdir -p "$OUT"
printf 'validation=%s\nworker=' "$OUT"
hostname
{ hostname; rustc --version; cargo --version; git rev-parse HEAD; } > "$OUT/worker.txt"
sha256sum cli/src/codeentry.rs cli/src/pair_cmd.rs cli/src/ui.rs cli/src/join_entry.rs \
  cli/src/join_input.rs cli/src/identity_flow.rs cli/src/file_io.rs cli/src/main.rs cli/src/dispatch.rs \
  cli/src/send_cmd.rs cli/src/recv_cmd.rs crates/filament-pair/src/lib.rs \
  crates/filament-peerloop/src/recv/dispatch.rs \
  crates/filament-pair/tests/code-input-cases.txt runner/join-entry-pty.py runner/join-input-boundary.py runner/pairing-* \
  frontend/src/lib/codeInput.js frontend/src/lib/pairing.js frontend/src/lib/useTunlion.js frontend/src/ui/Tunlion.jsx frontend/test-code-input.mjs \
  runner/terminal-probe.cjs runner/terminal-visual-review.cjs > "$OUT/SOURCE_SHA256"
cargo test -p filament-cli --bin tunlion codeentry::tests --locked
cargo test -p filament-cli --bin tunlion join_entry::tests --locked
cargo test -p filament-cli --bin tunlion join_input::tests --locked
cargo test -p filament-cli --bin tunlion explicit_code_surface --locked
cargo test -p filament-cli --bin tunlion identity_flow::join_input_tests --locked
cargo test -p filament-cli --bin tunlion file_io::invitation --locked
cargo test -p filament-cli --bin tunlion ui:: --locked
cargo test -p filament-pair --locked
cargo build -p filament-cli --bin tunlion --locked
cargo test -p filament-cli --bin tunlion --no-run --locked --message-format=json > "$OUT/artifacts.jsonl"
binary=$(python3 - "$OUT/artifacts.jsonl" <<'PY'
import json, sys
artifacts = [json.loads(line) for line in open(sys.argv[1]) if line.startswith('{')]
binaries = [row['executable'] for row in artifacts
            if row.get('reason') == 'compiler-artifact' and row.get('target', {}).get('name') == 'tunlion'
            and row.get('profile', {}).get('test') and row.get('executable')]
assert len(binaries) == 1, binaries
print(binaries[0])
PY
)
export NODE_PATH="$TUNLION_WORKER_ROOT/tools/terminal/node_modules"
python3 runner/pairing-inline-pty.py "$binary"
python3 runner/join-entry-pty.py "$binary"
python3 runner/join-input-boundary.py "$CARGO_TARGET_DIR/debug/tunlion" "$OUT/join-boundaries"
node frontend/test-code-input.mjs
python3 runner/pairing-resize-pty.py "$binary" "$OUT/terminal"
python3 runner/pairing-code-e2e.py "$CARGO_TARGET_DIR/debug/tunlion" \
  "$TUNLION_WORKER_ROOT/tools/backend/bin/python" "$OUT/e2e"
export CHROME_BIN
CHROME_BIN=$(command -v google-chrome || command -v chromium || true)
node runner/terminal-visual-review.cjs "$OUT/terminal"
printf '%s\n' "$OUT" > "$TUNLION_WORKER_ROOT/results/latest-pairing-validation"
printf 'PASS: all pairing UX checks on the same remote worker; evidence=%s\n' "$OUT"
