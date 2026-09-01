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
# Verdicts:
#   baseline (no hook)          -> delivered+verified  (harness OK); else exit 2.
#   premature-close (vanished recv) -> the CORRECT outcome is PROMPT "not
#     confirmed" (sender detects the dead conn, never re-probes). Exit 0 only
#     for that.
#     Exit 1 with "HANG"   = the sender re-probed (link looked alive) = the
#     keepalive leak reproduced.
#     Exit 1 with "UNEXPECTED" = delivered, impossible for a vanished receiver
#     (hook did not engage or the model is wrong).
#   Exit 2 = harness/setup failure (backend, build, pairing) -- not a verdict.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# Ask cargo where the target dir actually IS, rather than assuming ./target.
# This box sets a shared `target-dir` in ~/.cargo/config.toml, so the hardcoded
# path did not exist: the script BUILT fine and then looked for the binary
# somewhere cargo never writes, failing setup (exit 2) before any verdict. That
# is a second, independent reason this reproducer produced no signal here.
TARGET_DIR="${CARGO_TARGET_DIR:-$(cd "$CLI_DIR" && cargo metadata --format-version 1 --no-deps 2>/dev/null | tr ',' '\n' | sed -n 's/.*"target_directory":"\([^"]*\)".*/\1/p' | head -1)}"
# FILAMENT_BIN overrides the binary outright. Needed because the #161 debug_assert
# in capability.rs PANICS the receiver on plain code-based receive (WORK-STATE
# 1v), which kills this harness in its BASELINE round before any verdict. That
# assertion is compiled out in release, so a `--release --features test-hooks`
# build has the injection hooks AND no panic, which is the only way to get a
# verdict out of this script until the ordering question is settled.
BIN="${FILAMENT_BIN:-${TARGET_DIR:-$CLI_DIR/target}/debug/filament}"
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

# one send/recv round; $1 = extra env for the SENDER, $2 = extra env for the
# RECEIVER, $3 = tag. The sender always ends (delivered OR unconfirmed/timeout).
round() {
  local send_env="$1" recv_env="$2" tag="$3"
  local D="$WORK/out-$tag"; mkdir -p "$D"
  local word="ackloss-$tag"
  env $send_env "$BIN" send "$WORK/payload.bin" --word "$word" --server "$SERVER" >"$WORK/$tag-send.log" 2>&1 &
  local sp=$!
  local code=""
  for _ in $(seq 1 40); do
    code=$(grep -oiE "$word-[0-9]{3,5}" "$WORK/$tag-send.log" | head -1); [ -n "$code" ] && break; sleep 0.3
  done
  [ -z "$code" ] && { echo "SETUP: no pairing code for $tag"; kill $sp 2>/dev/null; return 2; }
  env $recv_env timeout 45 "$BIN" receive "$code" -y --dir "$D" --server "$SERVER" >"$WORK/$tag-recv.log" 2>&1
  wait $sp 2>/dev/null
  return 0
}

confirmed() { grep -qiE "delivered \+ verified|sha256 matched|delivered.*verified" "$1"; }

echo "== BUG-ACKLOSS deterministic reproducer =="

# 2. baseline: no hook -> the ack must land.
round "" "" baseline || exit 2
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
round "FILAMENT_LOG=debug" "FILAMENT_TEST_PREMATURE_CLOSE=1" premature || exit 2
dt=$((SECONDS - t0))
# Intended verdict from proofs/transport_lifecycle_model.py (rx_gone) and the
# P4 no-ack window in main.rs: ack_wait=15s (FILAMENT_ACK_TIMEOUT), ack_reprobe=5s.
# A VANISHED recv cannot deliver; not-confirmed is correct ONLY if PROMPT. The
# keepalive leak means is_dead() never fires, the link looks alive, and the sender
# burns the whole ack_wait+ack_reprobe window (Reprobe then give up). A detected
# dead conn gives up at the first ack_wait (no reprobe). So the PRIMARY verdict is
# load-independent: did the sender RE-PROBE? The re-probe line fires only when
# link_alive was true at the first window, which is exactly the leak. Wall-clock
# dt is printed as corroboration only (the window constants: main.rs:10988
# ack_wait = FILAMENT_ACK_TIMEOUT, default 15s; main.rs:10996 ack_reprobe = 5s).
reprobe_marker=$(grep -m1 "no delivery-ack yet, re-probing (re-sending file-end)" "$WORK/premature-send.log")
if confirmed "$WORK/premature-send.log"; then
  echo "  premature-close (recv)    : delivered (${dt}s)      [UNEXPECTED: a vanished receiver cannot deliver; hook/model regression]"
  exit 1
elif [ -n "$reprobe_marker" ]; then
  echo "  premature-close (recv)    : not confirmed (${dt}s)  [HANG: sender re-probed (link looked alive) = keepalive-leak, BUG-ACKLOSS present]"
  grep -iE "confirm|closed|lost|dead|stall|repair|corpse|re-probing" "$WORK/premature-send.log" | tail -n 4 | sed 's/^/      /'
  exit 1
else
  echo "  premature-close (recv)    : not confirmed (${dt}s)  [PROMPT: sender detected the dead conn, no re-probe -- correct]"
fi
echo "== done (1 MB, localhost, deterministic) =="
exit 0
