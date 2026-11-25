#!/usr/bin/env bash
# A wedged daemon loop must end the process, not leave a live pid serving
# nothing. A Windows peer stayed "up" for ~33 h after its loop stalled: peers saw
# it offline, `up` attached to it, and nothing restarted it.
#
# The daemon runs with a test hook that holds its loop ONCE for
# TUNLION_TEST_STALL_LOOP_MS (compiled only with --features test-hooks). The
# warning threshold and the hard limit are shortened through their env knobs
# (TUNLION_LOOP_STALL_SECS, TUNLION_LOOP_STALL_EXIT_SECS); production uses 20 s
# and LOOP_STALL_EXIT_SECS (120 s).
#
#   S1  a stall SHORTER than the limit warns, recovers, and the daemon keeps
#       serving (still alive, `status` exits 0)
#   S2  a stall LONGER than the limit logs the critical line and exits with
#       DAEMON_LOOP_STALLED (14) within the bound
#   S3  after that exit the pidfile is gone, `status` says not running (11),
#       and a plain `up --detach` starts a fresh daemon that answers
#   S4  `up` over a daemon whose loop is held (exit disabled) says "not
#       responding" with DAEMON_NOT_RESPONDING (15), never the settings
#       conflict (10); `down -y` then stops it
#   S5  the per-iteration loop budget (recv::loop_budget) sees the hold: S1's
#       daemon logged LOOP-BUDGET-EXCEEDED naming the held phase, and with
#       TUNLION_TEST_LOOP_BUDGET_PANIC=1 a short hold ends the daemon with a
#       panic that carries the same line. This proves the instrument CI relies
#       on is present, so its silence elsewhere means something.
#
# The holds here are deliberate, so every daemon this gate stalls runs with the
# budget's CI env (panic, record file) removed; S5 sets its own.
#
# Standalone, hermetic, fixture port 8199 ONLY. Needs a test-hooks binary.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8199
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-stallexit.XXXXXX")"
WARN_SECS=2
LIMIT_SECS=6
SHORT_MS=5000
# The exit must land within LIMIT + this slack of the hold starting.
SLACK_SECS=8
STALLED_EXIT=14

source "$HERE/lib/fixture.sh"
trap 'stop_all; fixture_cleanup' EXIT
KNOWN_RED_ALLOW=()
now() { date +%s; }

as_dir() { # as_dir DIR -- run the CLI against that config dir
  local d="$1"; shift
  env TUNLION_CONFIG_DIR="$d" "$BIN" --server "$SERVER" "$@"
}

stop_all() {
  local d p
  for d in "$WORK"/s1 "$WORK"/s2 "$WORK"/s4 "$WORK"/s5; do
    [ -d "$d" ] || continue
    timeout 20 env TUNLION_CONFIG_DIR="$d" "$BIN" --server "$SERVER" down -y >/dev/null 2>&1 || true
    p=$(head -1 "$d/up.pid" 2>/dev/null)
    [ -n "$p" ] && kill -9 "$p" 2>/dev/null || true
  done
}

start_daemon() { # start_daemon DIR HOLD_MS [LIMIT] -- foreground `up`, rc recorded
  local d="$1" hold="$2" limit="${3:-$LIMIT_SECS}"
  mkdir -p "$d-drop"
  ( env -u TUNLION_TEST_LOOP_BUDGET_PANIC -u TUNLION_TEST_LOOP_BUDGET_RECORD \
      TUNLION_CONFIG_DIR="$d" \
      TUNLION_LOOP_STALL_SECS="$WARN_SECS" \
      TUNLION_LOOP_STALL_EXIT_SECS="$limit" \
      TUNLION_TEST_STALL_LOOP_MS="$hold" \
      "$BIN" --server "$SERVER" up --dir "$d-drop" </dev/null >"$d.log" 2>&1
    echo $? >"$d.rc" ) &
  FIX_PIDS+=($!)
}

wait_for_line() { # wait_for_line FILE PATTERN SECS
  local i
  for i in $(seq 1 $(($3 * 4))); do
    grep -q "$2" "$1" 2>/dev/null && return 0
    sleep 0.25
  done
  return 1
}

[ -x "$BIN" ] || { echo "SETUP: build a test-hooks binary first (TUNLION_BIN); no $BIN"; exit 2; }
start_backend

# ---------------------------------------------------------------- S1
say "S1: a stall shorter than the limit recovers without exiting"
S1="$WORK/s1"
init_owner "$S1"
start_daemon "$S1" "$SHORT_MS"
wait_for_line "$S1.log" "LOOP-STALL-HOLD" 40 || fixture_die "S1: the hold hook never fired (not a test-hooks build?)"
wait_for_line "$S1.log" "event loop stalled" 10 \
  && ok "S1: the warning fired during the ${SHORT_MS}ms hold" \
  || bad "S1: no stall warning during the hold"
wait_for_line "$S1.log" "event loop recovered" 15 \
  && ok "S1: the loop recovered" \
  || bad "S1: the loop never logged recovery"
# Wait out the hard limit measured from the hold, plus slack.
sleep $((LIMIT_SECS + 2))
if [ -f "$S1.rc" ]; then
  bad "S1: the daemon exited (rc=$(cat "$S1.rc")) although the stall was shorter than the limit"
else
  ok "S1: the daemon is still running past the limit"
fi
grep -q "past the ${LIMIT_SECS}s limit" "$S1.log" \
  && bad "S1: the hard-limit line was logged for a short stall" \
  || ok "S1: no hard-limit line for a short stall"
timeout 20 env TUNLION_CONFIG_DIR="$S1" "$BIN" --server "$SERVER" status >"$WORK/s1-status.out" 2>&1
rc=$?
[ "$rc" = 0 ] && ok "S1: status answers (exit 0)" || bad "S1: status exit $rc after recovery: $(tail -3 "$WORK/s1-status.out")"
timeout 20 env TUNLION_CONFIG_DIR="$S1" "$BIN" --server "$SERVER" down -y >/dev/null 2>&1 || true
# S5 (first half): the budget saw S1's hold and named it. The hold is the only
# deliberately slow iteration, so its line must be there, about SHORT_MS long.
budget_line=$(grep -aoE "LOOP-BUDGET-EXCEEDED [0-9]+ test-stall-hold/[^ ]*" "$S1.log" | head -1)
budget_ms=$(echo "$budget_line" | awk '{print $2}')
if [ -n "$budget_line" ] && [ "${budget_ms:-0}" -ge $((SHORT_MS - 500)) ]; then
  ok "S5: the loop budget reported the hold ($budget_line)"
else
  bad "S5: no LOOP-BUDGET-EXCEEDED line naming test-stall-hold for the ${SHORT_MS}ms hold: $(grep -a LOOP-BUDGET "$S1.log" | head -3)"
fi

# ---------------------------------------------------------------- S2
say "S2: a stall past the limit exits with $STALLED_EXIT"
S2="$WORK/s2"
init_owner "$S2"
start_daemon "$S2" 600000
wait_for_line "$S2.log" "LOOP-STALL-HOLD" 40 || fixture_die "S2: the hold hook never fired"
T_HOLD=$(now)
for _ in $(seq 1 $(((LIMIT_SECS + SLACK_SECS) * 4))); do
  [ -f "$S2.rc" ] && break
  sleep 0.25
done
T_END=$(now)
if [ -f "$S2.rc" ]; then
  rc=$(cat "$S2.rc")
  [ "$rc" = "$STALLED_EXIT" ] && ok "S2: exited with $STALLED_EXIT after $((T_END - T_HOLD))s" \
    || bad "S2: exited with $rc, wanted $STALLED_EXIT"
  [ $((T_END - T_HOLD)) -ge "$LIMIT_SECS" ] && ok "S2: not before the limit" \
    || bad "S2: exited after $((T_END - T_HOLD))s, before the ${LIMIT_SECS}s limit"
else
  bad "S2: still running $((T_END - T_HOLD))s into a stall past the ${LIMIT_SECS}s limit"
fi
grep -q "past the ${LIMIT_SECS}s limit" "$S2.log" \
  && ok "S2: the critical line names the limit" \
  || bad "S2: no critical hard-limit line: $(tail -5 "$S2.log")"

# ---------------------------------------------------------------- S3
say "S3: the next up starts fresh"
[ ! -e "$S2/up.pid" ] && ok "S3: the pidfile was removed" || bad "S3: up.pid survived the stall exit"
timeout 20 env TUNLION_CONFIG_DIR="$S2" "$BIN" --server "$SERVER" status >/dev/null 2>&1
rc=$?
[ "$rc" = 11 ] && ok "S3: status says not running (11)" || bad "S3: status exit $rc after the stall exit"
timeout 60 env TUNLION_CONFIG_DIR="$S2" "$BIN" --server "$SERVER" up --detach --dir "$S2-drop" >"$WORK/s3-up.out" 2>&1
rc=$?
[ "$rc" = 0 ] && ok "S3: up --detach started a fresh daemon" || bad "S3: up --detach exit $rc: $(tail -5 "$WORK/s3-up.out")"
timeout 20 env TUNLION_CONFIG_DIR="$S2" "$BIN" --server "$SERVER" status >/dev/null 2>&1
rc=$?
[ "$rc" = 0 ] && ok "S3: the fresh daemon answers" || bad "S3: status exit $rc for the fresh daemon"

# ---------------------------------------------------------------- S4
say "S4: up over a silent daemon says not responding, not a settings conflict"
S4="$WORK/s4"
init_owner "$S4"
start_daemon "$S4" 600000 0
wait_for_line "$S4.log" "LOOP-STALL-HOLD" 40 || fixture_die "S4: the hold hook never fired"
timeout 60 env TUNLION_CONFIG_DIR="$S4" "$BIN" --server "$SERVER" up --dir "$S4-drop" \
  </dev/null >"$WORK/s4-up.out" 2>&1
rc=$?
[ "$rc" = 15 ] && ok "S4: up exited 15 (not responding)" \
  || bad "S4: up exited $rc over a silent daemon, wanted 15: $(tail -5 "$WORK/s4-up.out")"
grep -q "not responding" "$WORK/s4-up.out" && ok "S4: the message says not responding" \
  || bad "S4: no 'not responding' in: $(tail -5 "$WORK/s4-up.out")"
grep -q "different settings" "$WORK/s4-up.out" && bad "S4: still called a settings conflict" \
  || ok "S4: not called a settings conflict"
grep -q "tunlion down" "$WORK/s4-up.out" && ok "S4: points at tunlion down" \
  || bad "S4: no tunlion down hint"
timeout 60 env TUNLION_CONFIG_DIR="$S4" "$BIN" --server "$SERVER" down -y >"$WORK/s4-down.out" 2>&1
rc=$?
[ "$rc" = 0 ] && ok "S4: down -y stopped the silent daemon" \
  || bad "S4: down -y exit $rc: $(tail -5 "$WORK/s4-down.out")"
timeout 20 env TUNLION_CONFIG_DIR="$S4" "$BIN" --server "$SERVER" status >/dev/null 2>&1
rc=$?
[ "$rc" = 11 ] && ok "S4: status says not running after down" || bad "S4: status exit $rc after down"

# ---------------------------------------------------------------- S5
say "S5: with the budget fatal, a held iteration ends the daemon with a panic"
S5="$WORK/s5"
init_owner "$S5"
mkdir -p "$S5-drop"
( env -u TUNLION_TEST_LOOP_BUDGET_RECORD \
    TUNLION_TEST_LOOP_BUDGET_PANIC=1 \
    TUNLION_CONFIG_DIR="$S5" \
    TUNLION_LOOP_STALL_EXIT_SECS=0 \
    TUNLION_TEST_STALL_LOOP_MS=1500 \
    "$BIN" --server "$SERVER" up --dir "$S5-drop" </dev/null >"$S5.log" 2>&1
  echo $? >"$S5.rc" ) &
FIX_PIDS+=($!)
wait_for_line "$S5.log" "LOOP-STALL-HOLD" 40 || fixture_die "S5: the hold hook never fired"
for _ in $(seq 1 80); do [ -f "$S5.rc" ] && break; sleep 0.25; done
if [ -f "$S5.rc" ]; then
  rc=$(cat "$S5.rc")
  [ "$rc" != 0 ] && ok "S5: the daemon ended (rc=$rc) after a held iteration" \
    || bad "S5: the daemon exited 0 after a held iteration under the fatal budget"
else
  bad "S5: the daemon is still running 20s after a held iteration under the fatal budget"
  timeout 20 env TUNLION_CONFIG_DIR="$S5" "$BIN" --server "$SERVER" down -y >/dev/null 2>&1 || true
fi
grep -aq "panicked" "$S5.log" && grep -aqE "LOOP-BUDGET-EXCEEDED [0-9]+ test-stall-hold/" "$S5.log" \
  && ok "S5: the panic carries the budget line" \
  || bad "S5: no panic with the budget line: $(grep -aE 'LOOP-BUDGET|panicked' "$S5.log" | head -3)"

declare_known_red_summary
[ "$FAIL" -eq 0 ]
