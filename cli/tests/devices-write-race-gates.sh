#!/usr/bin/env bash
# #238: a revoke that reports success must persist. `revoke --certificate` and the
# daemon's periodic liveness sweep both read-modify-write devices.json; before the
# sidecar lock the sweep could clobber the freshly-written `certRevoked`, so a
# revoke intermittently reported success and did not stick. Standalone, hermetic,
# fixture port 8117 ONLY.
#
#   FILAMENT_BIN=/path/to/filament ./devices-write-race-gates.sh
#
# Vacuity guard: the race only exists while the daemon's 8s liveness sweep is
# actually running against a live link. The gate keeps a live shell open for the
# whole loop and asserts `lastSeen` advanced (the sweep wrote it), so a green
# "zero revokes lost" cannot be explained by the sweep never having run.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8117
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-devices-race.XXXXXX")"
DA="$WORK/A"
CYCLES=20

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell

json_get() { python3 -c "import json,sys; d=json.load(open('$1')); r=[x for x in d if x['name']=='bravo']; print(r[0].get('$2')) if r else print('')"; }

# A live shell keeps the link up so the daemon's liveness sweep keeps rewriting
# devices.json (lastSeen) every 8s, the exact condition under which #238 bites.
env FILAMENT_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" shell alpha -- \
  'for i in $(seq 1 120); do echo TICK-$i; sleep 1; done' >"$WORK/pty.out" 2>/dev/null &
FIX_PIDS+=($!)
sleep 5

LASTSEEN_START=$(json_get "$DA/devices.json" lastSeen)
MISSES=0
for i in $(seq 1 "$CYCLES"); do
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >/dev/null 2>&1
  sleep 1
  if [ "$(json_get "$DA/devices.json" certRevoked)" != "True" ]; then
    MISSES=$((MISSES+1))
  fi
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices restore bravo >/dev/null 2>&1
  sleep 1
done
LASTSEEN_END=$(json_get "$DA/devices.json" lastSeen)

echo "## lastSeen start=$LASTSEEN_START end=$LASTSEEN_END (sweep ran if end > start)"
echo "## revokes lost: $MISSES / $CYCLES"

if [ "$LASTSEEN_END" -le "$LASTSEEN_START" ] 2>/dev/null; then
  bad "vacuity: the liveness sweep did NOT run (lastSeen did not advance); this gate proves nothing"
else
  ok "vacuity: the liveness sweep ran (lastSeen advanced $((LASTSEEN_END - LASTSEEN_START))s)"
fi

if [ "$MISSES" -gt 0 ]; then
  bad "a revoke reported success but did not persist ($MISSES/$CYCLES lost)"
else
  ok "every revoke persisted across $CYCLES concurrent-sweep cycles"
fi

echo
echo "==========================================="
echo "devices-write-race gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
