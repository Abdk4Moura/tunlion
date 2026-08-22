#!/usr/bin/env bash
# #235-shape for l2-open: a revoked certificate must stop an ALREADY-ESTABLISHED
# forward stream. The denial arrives as a stream close (the client's connection
# breaks), never a hang. Standalone, hermetic, fixture port 8114 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./l2-revoke-gates.sh
#
# Gates:
#   A  the forward streams before the revoke           (positive control)
#   A2 a healthy forward survives its own recheck       (no-revoke control)
#   B  after the revoke the client's connection closes within the bound
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8114
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-l2-revoke.XXXXXX")"
DA="$WORK/A"
GRACE=12
COUNTER_PORT=9011

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell

# A counter server on the acceptor host (127.0.0.1:$COUNTER_PORT): each fresh
# TICK-N proves continuous data-plane liveness, not a buffer replay.
python3 -c "
import socket,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$COUNTER_PORT)); s.listen(5)
while True:
    c,_=s.accept(); c.settimeout(60)
    i=0
    try:
        while True:
            i+=1; c.sendall(('TICK-%d\n'%i).encode()); time.sleep(1)
    except Exception: pass
    c.close()
" >/dev/null 2>&1 &
FIX_PIDS+=($!)
sleep 1

env FILAMENT_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" forward "alpha:$COUNTER_PORT" --lport 9123 >"$WORK/fwd.log" 2>&1 &
FIX_PIDS+=($!)
sleep 3

# ===================================================================== GATE A ==
say A
( timeout 45 nc 127.0.0.1 9123 >"$WORK/counter.out" 2>/dev/null ) &
NC_PID=$!; FIX_PIDS+=($NC_PID)
sleep 6
echo "## before revoke: $(tail -3 "$WORK/counter.out" | tr '\n' ' ')"
if tail -3 "$WORK/counter.out" | grep -q "TICK-"; then
  ok "gateA: the live forward streams before the revoke"
else
  bad "gateA: forward never established, the rest proves nothing"
  echo "-- fwd.log --"; tail -5 "$WORK/fwd.log"
  exit 1
fi

# ==================================================================== GATE A2 ==
say A2
sleep 8
if kill -0 "$NC_PID" 2>/dev/null && tail -1 "$WORK/counter.out" | grep -qE "TICK-1[2-9]|TICK-2"; then
  ok "gateA2: a healthy forward survives a recheck cycle (no false close)"
else
  bad "gateA2: the recheck closed a forward that was NOT revoked"
fi

# ===================================================================== GATE B ==
# The stream must close (the client's connection breaks), not keep flowing and
# not hang. A still-alive nc after the bound is a live stream (the bug); an nc
# that cannot be reaped is a wedge.
say B
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
sleep "$GRACE"
if kill -0 "$NC_PID" 2>/dev/null; then
  bad "gateB: the revoked forward still streams (nc alive after ${GRACE}s)"
else
  ok "gateB: the revoked forward closed the client's connection within ${GRACE}s"
fi

echo
echo "==========================================="
echo "l2-revoke gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
