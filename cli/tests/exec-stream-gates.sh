#!/usr/bin/env bash
# `tunlion exec` streams a LARGE output to a SLOW reader to completion, over a
# healthy link, on both the warm (daemon) and the cold path. Standalone,
# hermetic, fixture port 8109 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./exec-stream-gates.sh
#
# The defect this pins: fetching a tens-of-MB `base64 -w0` over a warm exec
# into `base64 -d | tar -x` died midway with "link to '<peer>' died during exec
# (the warm link died)" and a truncated stream, while the link was fine. The
# acceptor sent output as fast as the link allowed; the initiator's inbound
# pipe is bounded and fed with a never-parking try_send, so a reader slower
# than the link overflowed it and the stream was reset as "flooded", which the
# warm path then reported as link death. The fix is an output window: the
# acceptor keeps a bounded number of frames in flight beyond what the
# initiator consumed, so the reader's pace becomes the command's pace.
#
# Gates (each: rc 0, exact byte count, exact sha256):
#   W1 warm exec, 40 MB to a reader that stops for 15 s after 4 MB (longer
#      than the 12 s peer-silence bound, so a watchdog that counts a slow
#      reader as a dead peer fails here too). The warm path is asserted to
#      have been taken (the instrument, not assumed).
#   W2 warm exec, 40 MB to a reader that never reads faster than ~8 MB/s.
#   C1 cold exec (TUNLION_NO_WARM_REUSE=1), same stalled reader as W1.
#
# Topology: A = acceptor (`up` with L2), B joins with a shell grant and runs
# exec. W1/W2 run with B's own daemon up (warm), C1 without reuse.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# shellcheck source=cli/tests/lib/backend.sh
source "$HERE/lib/backend.sh"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8109
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-exec-stream.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== exec-stream gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() {
  backend_stop "${BACKEND_PID:-}"
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for d in "$WORK"/cfg-*; do
    [ -d "$d" ] && TUNLION_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1
  done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
backend_start "$CLI_DIR/../backend" "$PYV" "$WORK/backend.log" \
  PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=60 FIL_PING_INTERVAL=25
pids+=("$BACKEND_PID")
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

DA="$WORK/cfg-A"; DB="$WORK/cfg-B"; mkdir -p "$DA" "$DB"
env TUNLION_CONFIG_DIR="$DA" "$BIN" init --name boxa --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1
env TUNLION_L2=1 TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/A-drop" >"$WORK/A-up.log" 2>&1 &
pids+=($!)
sleep 4
env TUNLION_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for boxb --allow shell --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1
env TUNLION_CONFIG_DIR="$DB" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" --name boxb --no-interactive >"$WORK/join.log" 2>&1
if ! TUNLION_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q boxb; then
  echo "setup: boxb did not join"; tail -5 "$WORK/add.log" "$WORK/join.log"; exit 2
fi
env TUNLION_CONFIG_DIR="$DA" "$BIN" grant boxb shell -y >"$WORK/grant.log" 2>&1 \
  || { echo "setup: grant failed"; cat "$WORK/grant.log"; exit 2; }

# The remote command: 40 MB of deterministic text, so the expected digest is
# computed here with the same pipeline.
TOTAL=40000000
REMOTE=(sh -c "yes 0123456789abcdefghijklmnopqrstuvwxyz | head -c $TOTAL")
WANT=$("${REMOTE[@]}" | sha256sum | cut -d' ' -f1)

# A reader that prints "<bytes> <sha256>". $1 = stall | slow.
#   stall: read 4 MB, stop reading for 15 s, then read the rest.
#   slow:  never faster than ~8 MB/s (64 KiB reads, 8 ms apart).
reader() {
  "$PYV" -c '
import hashlib, sys, time
mode = sys.argv[1]
h = hashlib.sha256(); n = 0; stalled = False
f = sys.stdin.buffer
while True:
    b = f.read1(65536) if hasattr(f, "read1") else f.read(65536)
    if not b:
        break
    h.update(b); n += len(b)
    if mode == "stall" and not stalled and n >= 4_000_000:
        stalled = True
        time.sleep(15)
    elif mode == "slow":
        time.sleep(0.008)
print(n, h.hexdigest())
' "$1"
}

# $1 label, $2 reader mode, rest: extra env for the initiator.
run_exec() {
  local label=$1 mode=$2; shift 2
  local t0; t0=$(date +%s)
  env "$@" TUNLION_LOG=debug TUNLION_CONFIG_DIR="$DB" timeout 240 \
    "$BIN" --server "$SERVER" exec boxa -- "${REMOTE[@]}" 2>"$WORK/$label.err" </dev/null \
    | reader "$mode" >"$WORK/$label.out"
  local codes=("${PIPESTATUS[@]}")
  rc=${codes[0]}
  took=$(( $(date +%s) - t0 ))
  read -r got sum <"$WORK/$label.out" || { got=0; sum=none; }
  echo "## $label rc=$rc bytes=$got/$TOTAL sha=${sum:0:12} took=${took}s"
}

check() {  # $1 gate label, $2 description
  if [ "$rc" = 0 ] && [ "$got" = "$TOTAL" ] && [ "$sum" = "$WANT" ]; then
    ok "$1: $2 streamed whole (rc=0, $got bytes, sha256 matches, ${took}s)"
  else
    bad "$1: $2 (rc=$rc, $got/$TOTAL bytes)"
    grep -v "frame for unknown sid" "$WORK/$1.err" | tail -15
    echo "  ($(grep -c "frame for unknown sid" "$WORK/$1.err") 'unknown sid' lines: output dropped after a reset)"
  fi
}

# B's own daemon: exec rides its warm link.
env TUNLION_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$WORK/B-drop" >"$WORK/B-up.log" 2>&1 &
pids+=($!)
sleep 4
# Warm the link with a tiny exec first, so W1 measures streaming, not setup.
env TUNLION_CONFIG_DIR="$DB" timeout 60 "$BIN" --server "$SERVER" exec boxa -- true </dev/null >/dev/null 2>&1

# ===================================================================== W1 ======
say "W1: warm exec, 40 MB to a reader that stops for 15 s"
run_exec W1 stall
if ! grep -q "riding the local daemon's warm link" "$WORK/W1.err"; then
  bad "W1: the warm path was not taken, so nothing about it was measured"
  tail -10 "$WORK/W1.err"
else
  check W1 "warm exec to a stalled reader"
fi

# ===================================================================== W2 ======
say "W2: warm exec, 40 MB to a reader capped near 8 MB/s"
run_exec W2 slow
if ! grep -q "riding the local daemon's warm link" "$WORK/W2.err"; then
  bad "W2: the warm path was not taken, so nothing about it was measured"
  tail -10 "$WORK/W2.err"
else
  check W2 "warm exec to a slow reader"
fi

# ===================================================================== C1 ======
say "C1: cold exec, 40 MB to a reader that stops for 15 s"
run_exec C1 stall TUNLION_NO_WARM_REUSE=1
if grep -q "riding the local daemon's warm link" "$WORK/C1.err"; then
  bad "C1: the cold path was not taken (it rode the warm link)"
else
  check C1 "cold exec to a stalled reader"
fi

echo
echo "exec-stream gates: $PASS passed, $FAIL failed${FAILED:+; failed:$FAILED}"
[ "$FAIL" = 0 ]
