#!/usr/bin/env bash
# Fixture cleanup: a gate's backend must be the process the gate records, the
# gate's build-lock descriptors must reach no child, and when the gate exits the
# lock must be free and no backend must survive.
#
# This gate is deliberately not a unit test of the helper alone. It runs a real
# converted inline gate (cap-verbs-gates.sh) under an inherited fd 3 and fd 9
# lock, and it runs the central fixture launcher in a real sourced fixture. In
# both the normal and forced-failure paths it asserts:
#   - the backend PID is `python app.py`, not the wrapper subshell
#   - the backend was the gate's child while it lived
#   - the backend held neither inherited lock descriptor
#   - the locks were unavailable WHILE the gate was live
#   - after the gate exited the locks were immediately free and the backend gone
#
# It also proves scripts/cargo-locked.sh keeps fd 9 for itself and closes it for
# cargo, and that backend_stop refuses a recycled PID.
#
# Linux only, because /proc and flock describe the property. Refuses (exit 2)
# when a precondition is missing; it never silently skips a cell.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
ROOT="$(dirname "$CLI_DIR")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-fixture-cleanup.XXXXXX")"
HELPER="$HERE/lib/backend.sh"
# shellcheck source=cli/tests/lib/backend.sh
source "$HELPER"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== fixture cleanup gate: %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

STRAY_BACKEND_PID=""
cleanup() {
  backend_stop "${STRAY_BACKEND_PID:-}"
  rm -rf "$WORK"
}
trap cleanup EXIT

# --- preconditions, named rather than skipped -------------------------------
[ -d /proc/self ] || { echo "REFUSED: /proc is required"; exit 2; }
command -v flock >/dev/null 2>&1 || { echo "REFUSED: flock is required"; exit 2; }
command -v ss >/dev/null 2>&1 || { echo "REFUSED: ss is required"; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "REFUSED: curl is required"; exit 2; }
[ -x "$BIN" ] || { echo "REFUSED: no tunlion binary at $BIN (set TUNLION_BIN)"; exit 2; }
"$PYV" -c 'import flask, flask_socketio' >/dev/null 2>&1 \
  || { echo "REFUSED: $PYV cannot import the backend dependencies (flask, flask_socketio)"; exit 2; }
[ -x "$HERE/cap-verbs-gates.sh" ] || { echo "REFUSED: the real gate cli/tests/cap-verbs-gates.sh is missing"; exit 2; }
[ -x "$ROOT/scripts/cargo-locked.sh" ] || { echo "REFUSED: scripts/cargo-locked.sh is missing"; exit 2; }

# cap-verbs pins 8104. The other cells use ephemeral ports picked by the OS so
# a shared worker's foreign backend cannot make this gate refuse or be killed.
read -r PORT_CENTRAL PORT_CENTRAL_FAIL PORT_REUSE < <("$PYV" - <<'PY'
import socket
ports = []
while len(ports) < 3:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    if p != 8104 and p not in ports:
        ports.append(p)
print(*ports)
PY
)
[ -n "${PORT_CENTRAL:-}" ] && [ -n "${PORT_CENTRAL_FAIL:-}" ] && [ -n "${PORT_REUSE:-}" ] \
  || { echo "REFUSED: could not allocate three free fixture ports"; exit 2; }
for p in 8104 "$PORT_CENTRAL" "$PORT_CENTRAL_FAIL" "$PORT_REUSE"; do
  if ss -tln 2>/dev/null | grep -q ":$p "; then
    echo "REFUSED: port $p is already in use; refusing to disturb a foreign listener"
    exit 2
  fi
done

listener_pid() {  # $1 = port
  ss -tlnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | head -1
}
gone() {  # $1 = pid: absent, or a zombie waiting to be reaped
  local st
  st=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null)
  [ -z "$st" ] || [ "$st" = "Z" ]
}
lock_busy() { ! flock -n "$1" true 2>/dev/null; }

# Run "$@" in a subshell that owns fd 3 and fd 9 on the given lock files. The
# gate inherits both. When the wrapper exits its copies close, so a surviving
# descendant still holding one is exactly what the post-exit probe detects.
RUN_PID=""
run_under_locks() {  # $1 = tag, rest = command
  local tag="$1"; shift
  rm -f "$WORK/$tag.ready"
  (
    exec 3>"$WORK/$tag.lock3"
    exec 9>"$WORK/$tag.lock9"
    flock -n 3 || exit 90
    flock -n 9 || exit 91
    : >"$WORK/$tag.ready"
    "$@"
    rc=$?
    exit "$rc"
  ) &
  RUN_PID=$!
}

wait_ready() {  # $1 = tag; bounded, explicit failure when the wrapper dies first
  local i=0
  while [ "$i" -lt 100 ]; do
    [ -f "$WORK/$1.ready" ] && return 0
    kill -0 "$RUN_PID" 2>/dev/null || return 1
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

wait_pid_file() {  # $1 = file, $2 = timeout deciseconds; echoes "<backend> <gate>"
  local i=0
  while [ "$i" -lt "${2:-100}" ]; do
    [ -s "$1" ] && { cat "$1"; return 0; }
    sleep 0.1
    i=$((i + 1))
  done
  return 1
}

# --- 1/2. central fixture launcher, normal exit ------------------------------
say "central fixture: normal exit"
cat > "$WORK/central-gate.sh" <<'SH'
set -uo pipefail
PORT="$1"; WORK="$2"; CLI_DIR="$3"; BIN="$4"; PYV="$5"; DA="$6"; MODE="$7"
SERVER="http://127.0.0.1:$PORT"
source "$CLI_DIR/tests/lib/fixture.sh"
trap fixture_cleanup EXIT
start_backend
printf '%s %s\n' "$BACKEND_PID" "$$" > "$WORK/central.pid"
sleep 5
[ "$MODE" = "fail" ] && exit 1
exit 0
SH
mkdir -p "$WORK/central-work"
run_under_locks central bash "$WORK/central-gate.sh" "$PORT_CENTRAL" "$WORK/central-work" "$CLI_DIR" "$BIN" "$PYV" "$WORK/central-DA" ok
if wait_ready central; then
  if ids=$(wait_pid_file "$WORK/central-work/central.pid" 100); then
    BACKEND_PID_C=$(printf '%s' "$ids" | awk '{print $1}')
    GATE_PID_C=$(printf '%s' "$ids" | awk '{print $2}')
    if [ "$(ps -o ppid= -p "$BACKEND_PID_C" 2>/dev/null | tr -d ' ')" = "$GATE_PID_C" ] \
       && [ "$(cat "/proc/$BACKEND_PID_C/comm" 2>/dev/null)" = "python3" -o "$(cat "/proc/$BACKEND_PID_C/comm" 2>/dev/null)" = "python" ]; then
      ok "central fixture: the recorded PID is the python backend and the gate's own child, not a wrapper"
    else
      bad "central fixture: recorded PID $BACKEND_PID_C is not the gate's python child"
    fi
    if ls -l "/proc/$BACKEND_PID_C/fd" 2>/dev/null | grep -qE "central.lock(3|9)"; then
      bad "central fixture: backend inherited a build-lock descriptor (fd 3 or 9)"
    else
      ok "central fixture: backend child holds neither fd 3 nor fd 9"
    fi
  else
    bad "central fixture: gate started but did not record its backend PID"
    BACKEND_PID_C=""
  fi
  if lock_busy "$WORK/central.lock3" && lock_busy "$WORK/central.lock9"; then
    ok "central fixture: fd 3 and fd 9 locks are held while the gate is live"
  else
    bad "central fixture: a lock was free while the gate was live"
  fi
  wait "$RUN_PID"; RC=$?
  [ "$RC" -eq 0 ] || bad "central fixture: normal gate exited $RC"
  if ! lock_busy "$WORK/central.lock3" && ! lock_busy "$WORK/central.lock9"; then
    if [ -n "${BACKEND_PID_C:-}" ] && gone "$BACKEND_PID_C"; then
      ok "central fixture: after the gate exits both locks are free and the backend is gone"
    else
      bad "central fixture: lock free but the recorded backend $BACKEND_PID_C survived"
    fi
  else
    bad "central fixture: a lock is still held after the gate exited"
  fi
else
  bad "central fixture: lock wrapper never became ready"
  wait "$RUN_PID" 2>/dev/null || true
fi

# --- 3. central fixture, forced failure --------------------------------------
say "central fixture: forced failure"
rm -f "$WORK/centralfail-work/central.pid"
mkdir -p "$WORK/centralfail-work"
run_under_locks centralfail bash "$WORK/central-gate.sh" "$PORT_CENTRAL_FAIL" "$WORK/centralfail-work" "$CLI_DIR" "$BIN" "$PYV" "$WORK/centralfail-DA" fail
if wait_ready centralfail; then
  if ids=$(wait_pid_file "$WORK/centralfail-work/central.pid" 100); then
    BACKEND_PID_CF=$(printf '%s' "$ids" | awk '{print $1}')
  else
    BACKEND_PID_CF=""
  fi
  wait "$RUN_PID"; RC=$?
  [ "$RC" -eq 1 ] || bad "central fixture: forced-failure gate exited $RC, want 1"
  if ! lock_busy "$WORK/centralfail.lock3" && ! lock_busy "$WORK/centralfail.lock9" \
     && { [ -z "$BACKEND_PID_CF" ] || gone "$BACKEND_PID_CF"; }; then
    ok "central fixture: forced failure still releases both locks and kills the backend"
  else
    bad "central fixture: forced failure left a lock held or the backend alive"
  fi
else
  bad "central fixture: forced-failure wrapper never became ready"
  wait "$RUN_PID" 2>/dev/null || true
fi

# --- 4/5. the real converted inline gate -------------------------------------
say "real inline gate: cap-verbs normal exit"
CAP_LOG="$WORK/cap.out"
run_under_locks cap env TUNLION_BIN="$BIN" TUNLION_TEST_VENV="$PYV" bash "$HERE/cap-verbs-gates.sh" >"$CAP_LOG" 2>&1
REAL_BACKEND_PID=""
if wait_ready cap; then
  i=0
  while [ "$i" -lt 100 ]; do
    REAL_BACKEND_PID=$(listener_pid 8104)
    [ -n "$REAL_BACKEND_PID" ] && break
    sleep 0.1
    i=$((i + 1))
  done
  if [ -n "$REAL_BACKEND_PID" ]; then
    if [ "$(cat "/proc/$REAL_BACKEND_PID/comm" 2>/dev/null)" = "python3" -o "$(cat "/proc/$REAL_BACKEND_PID/comm" 2>/dev/null)" = "python" ]; then
      ok "real inline gate: port 8104 is served by python PID $REAL_BACKEND_PID (not a wrapper)"
    else
      bad "real inline gate: PID on 8104 is not python"
    fi
  else
    bad "real inline gate: never observed its backend on 8104"
  fi
  if lock_busy "$WORK/cap.lock3" && lock_busy "$WORK/cap.lock9"; then
    ok "real inline gate: fd 3 and fd 9 locks are held while the gate is live"
  else
    bad "real inline gate: a lock was free while the gate was live"
  fi
  wait "$RUN_PID"; RC=$?
  CPASS=$(grep -c '^PASS:' "$CAP_LOG" || true)
  if [ "$RC" -eq 0 ] && [ "$CPASS" -eq 4 ]; then
    ok "real inline gate: cap-verbs exited 0 with 4/4 assertions"
  else
    bad "real inline gate: cap-verbs exited $RC with $CPASS PASS (want 0 and 4); log follows"
    tail -40 "$CAP_LOG"
  fi
  if ! lock_busy "$WORK/cap.lock3" && ! lock_busy "$WORK/cap.lock9" \
     && [ -z "$(listener_pid 8104)" ] \
     && { [ -z "$REAL_BACKEND_PID" ] || gone "$REAL_BACKEND_PID"; }; then
    ok "real inline gate: after exit both locks are free, 8104 is free, and its backend is gone"
  else
    bad "real inline gate: after exit a lock, the port, or the backend survived"
  fi
else
  bad "real inline gate: lock wrapper never became ready"
  wait "$RUN_PID" 2>/dev/null || true
fi

# --- 6. the real gate's forced-failure path ----------------------------------
say "real inline gate: forced failure"
CAP_FAIL_LOG="$WORK/cap-fail.out"
run_under_locks capfail env TUNLION_BIN=/nonexistent/tunlion TUNLION_TEST_VENV="$PYV" bash "$HERE/cap-verbs-gates.sh" >"$CAP_FAIL_LOG" 2>&1
FAIL_BACKEND_PID=""
if wait_ready capfail; then
  i=0
  while [ "$i" -lt 100 ]; do
    FAIL_BACKEND_PID=$(listener_pid 8104)
    [ -n "$FAIL_BACKEND_PID" ] && break
    sleep 0.1
    i=$((i + 1))
  done
  wait "$RUN_PID"; RC=$?
  [ "$RC" -eq 2 ] || bad "real inline gate: forced-failure run exited $RC, want 2"
  if ! lock_busy "$WORK/capfail.lock3" && ! lock_busy "$WORK/capfail.lock9" \
     && [ -z "$(listener_pid 8104)" ] \
     && { [ -z "$FAIL_BACKEND_PID" ] || gone "$FAIL_BACKEND_PID"; }; then
    ok "real inline gate: forced failure releases both locks, frees 8104, and kills its backend"
  else
    bad "real inline gate: forced failure left a lock, the port, or the backend alive"
  fi
else
  bad "real inline gate: forced-failure wrapper never became ready"
  wait "$RUN_PID" 2>/dev/null || true
fi

# --- 7. cargo-locked keeps fd 9 and closes it for cargo ----------------------
say "cargo-locked: fd 9 is parent-only"
mkdir -p "$WORK/fakebin" "$WORK/state"
cat > "$WORK/fakebin/cargo" <<'SH'
#!/usr/bin/env bash
if [ -e /proc/self/fd/9 ]; then
  echo open > "$FAKE_CARGO_RESULT"
  exit 90
fi
echo closed > "$FAKE_CARGO_RESULT"
sleep 2
exit 0
SH
chmod +x "$WORK/fakebin/cargo"
FAKE_CARGO_RESULT="$WORK/cargo-fd9.txt"
FAKE_CARGO_RESULT="$FAKE_CARGO_RESULT" \
PATH="$WORK/fakebin:$PATH" XDG_STATE_HOME="$WORK/state" \
TUNLION_BUILD_LOCK_WAIT_SECS=2 \
  "$ROOT/scripts/cargo-locked.sh" build >"$WORK/cargo-locked.out" 2>&1 &
CARGO_WRAPPER=$!
CARGO_LOCK="$WORK/state/tunlion/cargo-build.lock"
CARGO_HELD=0
i=0
while [ "$i" -lt 50 ]; do
  [ -e "$CARGO_LOCK" ] && lock_busy "$CARGO_LOCK" && { CARGO_HELD=1; break; }
  sleep 0.1
  i=$((i + 1))
done
wait "$CARGO_WRAPPER"; CARGO_RC=$?
if [ "$CARGO_HELD" = "1" ]; then
  if [ "$(cat "$FAKE_CARGO_RESULT" 2>/dev/null)" = "closed" ] && [ "$CARGO_RC" -eq 0 ]; then
    ok "cargo-locked: cargo child had no fd 9, and the parent held the lock while it ran"
  else
    bad "cargo-locked: child fd9=$(cat "$FAKE_CARGO_RESULT" 2>/dev/null) rc=$CARGO_RC (want closed, 0)"
  fi
else
  bad "cargo-locked: never observed the wrapper holding its lock"
fi
if ! lock_busy "$CARGO_LOCK"; then
  ok "cargo-locked: lock is free after the wrapper exits"
else
  bad "cargo-locked: lock still held after the wrapper exits"
fi

# --- 8. backend_stop refuses a recycled PID ----------------------------------
say "backend_stop: PID reuse guard"
mkdir -p "$WORK/dummy"
cat > "$WORK/dummy/app.py" <<'PY'
import time
time.sleep(60)
PY
backend_start "$WORK/dummy" "$PYV" "$WORK/dummy.log" PORT="$PORT_REUSE"
STRAY_BACKEND_PID=$BACKEND_PID
if [ -n "$STRAY_BACKEND_PID" ] && [ -d "/proc/$STRAY_BACKEND_PID" ]; then
  backend_stop "$STRAY_BACKEND_PID" 1
  if kill -0 "$STRAY_BACKEND_PID" 2>/dev/null; then
    ok "backend_stop: a live PID with a mismatched start time was not signalled"
  else
    bad "backend_stop: killed a live PID whose start time did not match"
  fi
  backend_stop "$STRAY_BACKEND_PID" "$BACKEND_START"
  if gone "$STRAY_BACKEND_PID"; then
    ok "backend_stop: the recorded PID was stopped and reaped"
  else
    bad "backend_stop: the recorded PID survived its own stop"
  fi
  STRAY_BACKEND_PID=""
else
  bad "backend_stop: dummy backend did not start"
fi

say "summary"
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo "FAILED:$FAILED"
  exit 1
fi
[ "$PASS" -ge 1 ] || { echo "FAIL: no assertions ran"; exit 1; }
exit 0
