#!/usr/bin/env bash
# #235-shape for pty-open: a revoked certificate must stop an ALREADY-ESTABLISHED
# shell, and the denial must reach the initiator as a nonzero exit with a reason,
# never as a clean exit or a hang. Standalone, hermetic, fixture port 8113 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./pty-revoke-gates.sh
#
# The discriminator is a streaming counter, not a single post-revoke command: a
# fresh TICK-N proves continuous data-plane liveness (not a buffer replay).
#
# Gates:
#   A  the live shell streams before the revoke          (positive control)
#   A2 a healthy shell survives its own recheck           (no-revoke control)
#   B  after the revoke the shell exits nonzero with "access revoked" on stderr
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8113
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-pty-revoke.XXXXXX")"
DA="$WORK/A"
GRACE=12   # > REVOKE_RECHECK, with slack for a slow box

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell

shell_tick() {
  env FILAMENT_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" shell alpha -- \
    'for i in $(seq 1 60); do echo TICK-$i; sleep 1; done'
}

# ===================================================================== GATE A ==
say A
shell_tick >"$WORK/pty.out" 2>"$WORK/pty.err" &
SHELL_PID=$!; FIX_PIDS+=($SHELL_PID)
sleep 6
echo "## before revoke: $(tail -3 "$WORK/pty.out" | tr '\n' ' ')"
if tail -3 "$WORK/pty.out" | grep -q "TICK-"; then
  ok "gateA: the live shell streams before the revoke"
else
  bad "gateA: shell never established, the rest proves nothing"
  echo "-- pty.err --"; tail -5 "$WORK/pty.err"
  exit 1
fi

# ==================================================================== GATE A2 ==
# The recheck's OTHER half. Let the shell run past the recheck interval with
# nothing revoked; a healthy session must survive its own recheck, or a fix that
# closes every session would score green here.
say A2
sleep 8
if kill -0 "$SHELL_PID" 2>/dev/null && tail -1 "$WORK/pty.out" | grep -qE "TICK-1[2-9]|TICK-2"; then
  ok "gateA2: a healthy shell survives a recheck cycle (no false close)"
else
  bad "gateA2: the recheck closed a shell that was NOT revoked"
fi

# ===================================================================== GATE B ==
# The denial must arrive as a denial: the shell stops, exits nonzero, and the
# reason reaches the initiator's stderr. Exit 0 is the #223 false success; a
# still-running process is a wedge (the terminal stopped but cannot be reaped).
say B
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
sleep "$GRACE"
wait "$SHELL_PID" 2>/dev/null; rc=$?
echo "## shell exit code after revoke: $rc"
echo "## tail: $(tail -4 "$WORK/pty.out" | tr '\n' ' ')"
if [ "$rc" = "0" ]; then
  bad "gateB: the revoked shell exited 0 (false success)"
elif grep -q "access revoked" "$WORK/pty.err"; then
  ok "gateB: revoked shell exited nonzero with 'access revoked' on stderr"
elif ! kill -0 "$SHELL_PID" 2>/dev/null; then
  bad "gateB: shell exited nonzero but no reason reached the initiator"
else
  bad "gateB: shell did NOT exit (wedged) within ${GRACE}s"
fi

echo
echo "==========================================="
echo "pty-revoke gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
