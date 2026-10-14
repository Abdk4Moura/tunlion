#!/usr/bin/env bash
# A bulk transfer must not hold up interactive requests to the same daemon.
# Standalone, hermetic, fixture port 8183 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./exec-latency-gates.sh
#
# The receiving daemon used to sync and re-hash a finished file INSIDE its
# event loop. For a large file that is seconds, and every exec, shell and new
# link to that daemon waited behind it (measured in the lab: one exec took
# 11 s against about 1 s idle, the next could not even establish for 7 s).
#
# Method: time `exec -- true` while idle, then fire one every 0.4 s from the
# moment a 1.5 GB send starts until it ends (so the file-end check is covered),
# and compare the slowest busy exec with the idle ones.
#
# Gates:
#   L0  the send itself delivers and verifies (positive control)
#   L1  the slowest exec during the send stays within max(3 x idle median,
#       idle median + 2.5 s), and every exec during the send succeeds
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8183
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-exec-latency.XXXXXX")"
DA="$WORK/A"
SIZE_MB="${EXEC_LATENCY_MB:-1500}"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow transfer,shell

ms_now() { date +%s%3N; }
one_exec() {  # prints "<ms> <rc>"
  local t0 rc
  t0=$(ms_now)
  timeout 60 env TUNLION_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" exec alpha -- true >/dev/null 2>&1
  rc=$?
  echo "$(( $(ms_now) - t0 )) $rc"
}

say "idle"
idle=()
for i in 1 2 3 4 5; do
  read -r ms rc < <(one_exec)
  [ "$rc" = "0" ] || fixture_die "setup: idle exec failed (rc $rc); the gate measures nothing"
  idle+=("$ms")
done
median=$(printf '%s\n' "${idle[@]}" | sort -n | sed -n 3p)
bound=$(( median * 3 )); [ $(( median + 2500 )) -gt "$bound" ] && bound=$(( median + 2500 ))
echo "## idle exec ms: ${idle[*]} (median $median, bound $bound)"

say "busy"
head -c "$((SIZE_MB * 1024 * 1024))" /dev/zero > "$WORK/big.bin"
env TUNLION_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" send "$WORK/big.bin" --to alpha >"$WORK/send.log" 2>&1 &
SEND=$!; FIX_PIDS+=($SEND)
busy=(); fails=0
while kill -0 "$SEND" 2>/dev/null; do
  read -r ms rc < <(one_exec)
  busy+=("$ms"); [ "$rc" = "0" ] || fails=$((fails + 1))
  sleep 0.4
done
wait "$SEND"; send_rc=$?
worst=$(printf '%s\n' "${busy[@]:-0}" | sort -n | tail -1)
echo "## busy exec ms (${#busy[@]} during the send): ${busy[*]}"
echo "## slowest $worst ms, failures $fails, send rc $send_rc"

if [ "$send_rc" = "0" ] && grep -q "verified" "$WORK/send.log"; then
  ok "L0: the ${SIZE_MB} MB send delivered and verified"
else
  bad "L0: the send failed (rc $send_rc): $(tail -2 "$WORK/send.log" | tr '\n' ' ')"
fi
if [ "${#busy[@]}" -lt 3 ]; then
  bad "L1: only ${#busy[@]} execs ran during the send, too few to judge"
elif [ "$fails" -gt 0 ]; then
  bad "L1: $fails exec(s) failed during the send"
elif [ "$worst" -le "$bound" ]; then
  ok "L1: interactive requests kept flowing during the send (slowest ${worst} ms, bound ${bound} ms)"
else
  bad "L1: an exec took ${worst} ms during the send (idle median ${median} ms, bound ${bound} ms)"
fi

echo
echo "==========================================="
echo "exec-latency gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
rm -rf "$WORK/big.bin" "$WORK/Adrop"
[ "$FAIL" = "0" ]
