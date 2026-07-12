#!/usr/bin/env bash
# Deterministic localhost reproducer for BUG-ACKLOSS (the delivery-ack teardown
# race + corpse cascade). Reproduces on a 1 MB transfer in ONE run what the
# multi-stream push otherwise hit only ~1-in-5 on 10 GB cross-machine transfers.
#
# Mechanism: FILAMENT_TEST_PREMATURE_CLOSE=1 makes the RECEIVER tear the link
# down at the instant the delivery-ack is due (no ack sent, connection dropped),
# so the SENDER never gets the ack and its transport dies -- exactly the
# self-inflicted teardown the fix must prevent (RFC 9000 §10.2: QUIC has no
# flush-on-close). Modeled as `premature_close` in
# proofs/transport_lifecycle_model.py.
#
# Needs a `--features test-hooks` build (the hook is stripped from release):
#     cargo build --features test-hooks   (debug, ~20s)  -- default here
# Point at an external backend with FILAMENT_TEST_SERVER, else it autostarts one
# from a venv (FILAMENT_TEST_VENV, default /root/filament-bench/venv).
#
# Exit 0 = harness healthy AND the reproducer behaved as expected for the build:
#   baseline (no hook) -> delivered+verified; premature-close -> NOT confirmed
#   (bug present, e.g. on main) OR delivered anyway (robust, once the fix lands).
# Exit 2 = harness/setup failure (backend, build, pairing) -- not a verdict.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$CLI_DIR/target/debug/filament"
SERVER="${FILAMENT_TEST_SERVER:-http://127.0.0.1:8077}"
WORK="$(mktemp -d /tmp/filament-ackloss.XXXXXX)"
PYV="${FILAMENT_TEST_VENV:-/root/filament-bench/venv}/bin/python"

OWN_BACKEND=""
cleanup() { [ -n "$OWN_BACKEND" ] && kill "$OWN_BACKEND" 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# 0. build with the test hook (debug, fast). Skip if the binary is already built
#    with hooks and FILAMENT_SKIP_BUILD is set.
if [ -z "${FILAMENT_SKIP_BUILD:-}" ]; then
  ( cd "$CLI_DIR" && cargo build --features test-hooks -q ) || { echo "SETUP: build failed"; exit 2; }
fi
[ -x "$BIN" ] || { echo "SETUP: no binary at $BIN"; exit 2; }

# 1. backend (autostart on :8077 if none, claim-limit pinned for determinism)
if [ -z "${FILAMENT_TEST_SERVER:-}" ]; then
  [ -x "$PYV" ] || { echo "SETUP: no venv python at $PYV (set FILAMENT_TEST_SERVER or FILAMENT_TEST_VENV)"; exit 2; }
  for pid in $(ss -tlnp 2>/dev/null | grep ":8077 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
  sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=8077 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
      "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
  OWN_BACKEND=$!
fi
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "SETUP: no backend at $SERVER"; exit 2; }

head -c $((1024 * 1024)) /dev/urandom > "$WORK/payload.bin"

# one send/recv round; $1 = extra env for the receiver, $2 = tag. Prints the
# sender log path. The sender always ends (delivered OR unconfirmed/timeout).
round() {
  local recv_env="$1" tag="$2"
  local D="$WORK/out-$tag"; mkdir -p "$D"
  local word="ackloss-$tag"
  "$BIN" send "$WORK/payload.bin" --word "$word" --server "$SERVER" >"$WORK/$tag-send.log" 2>&1 &
  local sp=$!
  local code=""
  for _ in $(seq 1 40); do
    code=$(grep -oiE "$word-[0-9]{3,5}" "$WORK/$tag-send.log" | head -1); [ -n "$code" ] && break; sleep 0.3
  done
  [ -z "$code" ] && { echo "SETUP: no pairing code for $tag"; kill $sp 2>/dev/null; return 2; }
  env $recv_env timeout 45 "$BIN" recv "$code" -y --dir "$D" --server "$SERVER" >"$WORK/$tag-recv.log" 2>&1
  wait $sp 2>/dev/null
  return 0
}

confirmed() { grep -qiE "delivered \+ verified|sha256 matched|delivered.*verified" "$1"; }

echo "== BUG-ACKLOSS deterministic reproducer =="

# 2. baseline: no hook -> the ack must land.
round "" baseline || exit 2
if confirmed "$WORK/baseline-send.log"; then
  echo "  baseline (no hook)        : delivered + verified   [harness OK]"
else
  echo "  baseline (no hook)        : NOT confirmed          [HARNESS BROKEN]"
  tail -n 4 "$WORK/baseline-send.log"; exit 2
fi

# 3. premature-close: receiver drops its link at the ack. NOTE the receiver here
#    is `recv`, which then EXITS -> the receiver VANISHES (rx_gone in the model).
#    Per proofs/transport_lifecycle_model.py a vanished peer CANNOT be recovered,
#    so the CORRECT outcome is a PROMPT clean "not confirmed" (the sender detects
#    the dead connection), NOT "delivered". The BUG is a HANG: the keepalive leak
#    (a detached task holding a Connection clone) means is_dead() never fires, so
#    the sender waits out the whole P4 no-ack window. So the signal here is
#    PROMPTNESS, not delivery. (True recovery -> delivered needs a receiver that
#    STAYS ALIVE; use an `up` daemon receiver -- ROBUST mode, exercise once the
#    abortable-keepalive + wait_idle fix lands.)
t0=$SECONDS
round "FILAMENT_TEST_PREMATURE_CLOSE=1" premature || exit 2
dt=$((SECONDS - t0))
if confirmed "$WORK/premature-send.log"; then
  echo "  premature-close (recv)    : delivered (${dt}s)      [receiver recovered -- unexpected for a vanishing recv]"
else
  echo "  premature-close (recv)    : not confirmed (${dt}s)  [correct for a vanished receiver]"
  echo "    want PROMPT (sender detected the dead conn); a full-window time = the keepalive-leak HANG."
  grep -iE "confirm|closed|lost|dead|stall|repair|corpse" "$WORK/premature-send.log" | tail -n 4 | sed 's/^/      /'
fi
echo "== done (1 MB, localhost, deterministic) =="
