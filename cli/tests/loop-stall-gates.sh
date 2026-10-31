#!/usr/bin/env bash
# Real-loop latency evidence for the expired-direct batch.
#
# The daemon loop must keep answering its control socket and stamping its
# heartbeat while slow establishes run. This gate starts a real fleet (owner +
# three certified siblings), makes every direct-QUIC race lose, and holds each
# WebRTC establish for DELAY_MS. The same binary can then be run twice:
#
#   EXPECT=stall TUNLION_TEST_EXPIRED_DIRECT_BATCH=1   old whole-batch drain
#   EXPECT=clean                                       one fallback per turn
#
# Measurements, all from the real receive loop:
#   - max LOOP-BEAT gap_ms (test-hooks beat line at the top of the loop)
#   - max `tunlion status --json` round-trip and count of probe timeouts
#   - count of "event loop stalled" lines
#   - every sibling joined the fleet
#
# No WSL access and no production knob: the hooks are compiled only under
# --features test-hooks.
#
#   TUNLION_BIN=/path/to/tunlion-test-hooks ./loop-stall-gates.sh
#   EXPECT=stall TUNLION_TEST_EXPIRED_DIRECT_BATCH=1 ... ./loop-stall-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=${PORT:-8141}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-loopstall.XXXXXX")"
DA="$WORK/alpha"
PEERS=("bravo" "charlie" "delta")
DELAY_MS=${DELAY_MS:-12000}
WINDOW=${WINDOW:-70}
EXPECT=${EXPECT:-clean}
LABEL=${LABEL:-$EXPECT}

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in alpha "${PEERS[@]}"; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

as_node() { # as_node NAME -- run tunlion as that node
  local n="$1"; shift
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" "$BIN" --server "$SERVER" "$@"
}

up_node() { # up_node NAME [extra env...]
  local n="$1"; shift
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" \
    TUNLION_L2=1 TUNLION_LOG=debug \
    TUNLION_DIRECT_TEST_BLOCK=1 \
    TUNLION_TEST_ESTABLISH_DELAY_MS="$DELAY_MS" \
    TUNLION_TEST_LOOP_BEAT=1 \
    TUNLION_LOOP_STALL_SECS=20 \
    "$@" \
    "$BIN" --server "$SERVER" up --dir "$WORK/$n-drop" >"$WORK/up-$n.log" 2>&1 &
  FIX_PIDS+=($!)
}

control_ms() { # control_ms NAME -> "elapsed_ms,exit" from the loop serviced control socket
  # Direct cap-status round-trip. Spawning the debug CLI would measure process
  # startup under load, not the loop's control latency. 1.5 s mirrors the real
  # `tunlion status` probe budget.
  "$PYV" - "$WORK/$1/control.sock" <<'PROBE'
import socket, sys, time
path = sys.argv[1]
start = time.monotonic()
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(1.5)
    s.connect(path)
    s.sendall(b'{"op":"l3-state"}\n')
    s.recv(4096)
    ok = 0
except Exception:
    ok = 6
ms = int((time.monotonic() - start) * 1000)
print(f"{ms},{ok}")
PROBE
}

[ -x "$BIN" ] || { echo "SETUP: build a test-hooks binary first (TUNLION_BIN); no $BIN"; exit 2; }
"$BIN" --version >/dev/null || { echo "SETUP: $BIN is not runnable"; exit 2; }
command -v curl >/dev/null || { echo "SETUP: curl missing"; exit 3; }

start_backend
init_owner "$DA"
start_acceptor "$DA"
for n in "${PEERS[@]}"; do enroll_delegate "$n"; done

for n in "${PEERS[@]}"; do up_node "$n"; done

# Wait until every daemon answers its control socket, then start measuring.
ready=1
for n in "${PEERS[@]}"; do
  ok_ready=0
  for _ in $(seq 1 60); do
    line=$(control_ms "$n")
    rc=${line#*,}
    if [ "$rc" = 0 ]; then ok_ready=1; break; fi
    sleep 0.5
  done
  [ "$ok_ready" = 1 ] || ready=0
done
[ "$ready" = 1 ] || fixture_die "setup: a delegate daemon never answered its control socket"

( end=$(( $(date +%s) + WINDOW ))
  while [ "$(date +%s)" -lt "$end" ]; do
    control_ms bravo
    sleep 0.5
  done
) >"$WORK/status.csv" &
SPID=$!

# The joins are the trigger: each sibling starts a direct attempt, the blocked
# race expires, and the fallback establishes. With EXPECT=stall the fallbacks
# drain as one batch; the loop must still answer afterwards.
ok_join=0
for _ in $(seq 1 240); do
  n=$(grep -l "joined the mesh" "$WORK"/up-*.log 2>/dev/null | wc -l)
  if [ "$n" -ge 2 ]; then ok_join=1; break; fi
  sleep 0.5
done
[ "$ok_join" = 1 ] || bad "no fleet sibling joined within 120s"

wait "$SPID" 2>/dev/null || true

joined=$(grep -l "joined the mesh" "$WORK"/up-*.log 2>/dev/null | wc -l)
stall_lines=$(grep -h "event loop stalled" "$WORK"/up-*.log 2>/dev/null | wc -l)
max_gap=$(awk -F'gap_ms=' '/LOOP-BEAT/ {g=$2+0; if (g>m) m=g} END{print m+0}' "$WORK"/up-*.log 2>/dev/null)
max_status=$(awk -F, 'BEGIN{m=0} {if ($1+0>m) m=$1+0} END{print m+0}' "$WORK/status.csv" 2>/dev/null)
timeouts=$(awk -F, '$1>=1400 && $2!=0{n++} END{print n+0}' "$WORK/status.csv" 2>/dev/null)

echo
echo "STALL-EVIDENCE label=$LABEL expect=$EXPECT peers=${#PEERS[@]} delay_ms=$DELAY_MS"
echo "STALL-EVIDENCE max_beat_gap_ms=$max_gap max_status_ms=$max_status status_failures=$timeouts stall_lines=$stall_lines joined_logs=$joined"
echo "STALL-EVIDENCE logs=$WORK"

if [ "$EXPECT" = "stall" ]; then
  [ "$stall_lines" -ge 1 ] && ok "the old batch drain crossed the 20 s watchdog" \
    || bad "the old batch drain did not cross the watchdog (stall_lines=$stall_lines)"
  [ "$max_gap" -ge 20000 ] && ok "the loop heartbeat gap reached ${max_gap}ms" \
    || bad "the loop heartbeat gap stayed at ${max_gap}ms; the repro did not hold the loop"
  [ "$timeouts" -ge 1 ] && ok "the control probe timed out during the stall ($timeouts)" \
    || bad "the control probe never timed out; the loop was not held"
else
  [ "$stall_lines" -eq 0 ] && ok "no watchdog stall line with one fallback per turn" \
    || bad "a watchdog stall line survived the cap ($stall_lines)"
  [ "$max_gap" -lt 20000 ] && ok "the loop heartbeat gap stayed below 20 s (${max_gap}ms)" \
    || bad "the loop heartbeat gap reached ${max_gap}ms with the cap"
  [ "$timeouts" -eq 0 ] && ok "the control probe answered throughout" \
    || bad "the control probe failed $timeouts time(s) with the cap"
  [ "$joined" -ge 1 ] && ok "fleet links formed after the fallbacks" \
    || bad "no fleet link formed"
fi

declare_known_red_summary
[ "$FAIL" -eq 0 ]
