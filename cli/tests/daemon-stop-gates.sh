#!/usr/bin/env bash
# Daemon stop/start truth gates: `down`, `up` and `status` say what is actually
# true about the daemon process, including when it is suspended or cut off.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/daemon-stop-gates.sh
#
# THE DEFECTS (blind test on a hostile container):
#   - with the daemon SIGSTOPped, `down --yes` printed "stopped (pid N)" and
#     exited 0 in 6 ms while the process still existed (state T). Then
#     `up --detach` printed "daemon already running (starting); nothing to do"
#     and `status` printed "not running": nothing was serving, and every command
#     said something different.
#   - a daemon stuck re-dialing the signaling server answered on its control
#     socket, so `status` said "up" and `doctor` said healthy.
#
# Gates:
#   A  `down` on a SIGSTOPped daemon: exit 0 only once the process is GONE, and
#      it says it had to resume it.
#   B  the `up --detach` after that starts a fresh daemon ("detached") rather
#      than claiming one is already running, and `status` agrees.
#   C  the state the old `down` left behind (a suspended daemon holding the
#      lock, its pidfile deleted): `up --detach` refuses and names it suspended
#      instead of "already running (starting)", and `down` still finds and stops
#      it.
#   D  a daemon whose signaling server went away: `status` says degraded (and
#      `status --json` carries the reason), `doctor --json` reports the daemon
#      degraded, and once the server is back `status` says up again.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8134
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-dstop.XXXXXX")"
D="$WORK/cfg"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== daemon-stop gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && { kill -CONT "$p" 2>/dev/null; kill -9 "$p" 2>/dev/null; }; done
  for p in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
[ -d /proc/self ] || { echo "REFUSED: these gates read process state from /proc"; exit 2; }

start_backend() {
  for p in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$p" 2>/dev/null; done
  sleep 1
  ( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
      FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=10 FIL_PING_INTERVAL=5 \
      exec "$PYV" app.py >>"$WORK/backend.log" 2>&1 ) &
  for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && return 0; sleep 0.5; done
  echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2
}
stop_backend() {
  for p in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill -9 "$p" 2>/dev/null; done
}
T() { env FILAMENT_CONFIG_DIR="$D" timeout "$1" "$BIN" "${@:2}"; }
# Gone: no /proc entry, or a zombie waiting to be reaped.
gone() { local st; st=$(awk '{print $3}' "/proc/$1/stat" 2>/dev/null); [ -z "$st" ] || [ "$st" = "Z" ]; }
daemon_pid() { for _ in $(seq 1 40); do [ -s "$D/up.pid" ] && { head -1 "$D/up.pid"; return 0; }; sleep 0.25; done; return 1; }

start_backend
mkdir -p "$D"
env FILAMENT_CONFIG_DIR="$D" "$BIN" init --name stopper --recovery-file "$WORK/rec.txt" --yes >/dev/null 2>&1 \
  || { echo "init failed"; exit 2; }

# ===================================================================== GATE A ==
say "A: down on a suspended daemon"
T 30 --server "$SERVER" up --detach --dir "$WORK/drop" >"$WORK/upA.log" 2>&1
P1=$(daemon_pid) || { echo "setup: no daemon pid"; cat "$WORK/upA.log"; exit 2; }
pids+=("$P1")
sleep 2
kill -STOP "$P1"
echo "## daemon $P1 state before down: $(awk '{print $3}' /proc/$P1/stat)"
outA=$(T 60 down --yes 2>&1); rcA=$?
stA=$(awk '{print $3}' "/proc/$P1/stat" 2>/dev/null || echo gone)
echo "## down rc=$rcA, process state after: ${stA:-gone}"; echo "$outA" | sed 's/^/    /'
if [ "$rcA" = "0" ] && gone "$P1" && echo "$outA" | grep -q "stopped (pid $P1)" && echo "$outA" | grep -q "SIGSTOP"; then
  ok "gateA: down on a suspended daemon returns only once it is gone, and says it resumed it"
else
  bad "gateA: down on a suspended daemon (rc=$rcA, state after=${stA:-gone})"
fi

# ===================================================================== GATE B ==
say "B: the next up --detach starts a daemon"
outB=$(T 30 --server "$SERVER" up --detach --dir "$WORK/drop" 2>&1); rcB=$?
echo "## up rc=$rcB"; echo "$outB" | sed 's/^/    /'
P2=$(daemon_pid); [ -n "$P2" ] && pids+=("$P2")
stB=$(T 20 status 2>&1)
echo "$stB" | head -3 | sed 's/^/    /'
if [ "$rcB" = "0" ] && echo "$outB" | grep -q "daemon detached" && ! echo "$outB" | grep -q "already running" \
   && [ -n "$P2" ] && [ "$P2" != "$P1" ] && ! gone "$P2" && echo "$stB" | grep -q "up (pid $P2)"; then
  ok "gateB: after down, up --detach starts a fresh daemon (pid $P2) and status agrees"
else
  bad "gateB: up --detach after down (rc=$rcB, new pid=${P2:-none})"
fi

# ===================================================================== GATE C ==
say "C: a suspended daemon holding the lock with its pidfile gone"
kill -STOP "$P2"
rm -f "$D/up.pid"
outC=$(T 30 --server "$SERVER" up --detach --dir "$WORK/drop" 2>&1); rcC=$?
echo "## up rc=$rcC"; echo "$outC" | sed 's/^/    /'
outC2=$(T 60 down --yes 2>&1); rcC2=$?
echo "## down rc=$rcC2"; echo "$outC2" | sed 's/^/    /'
if [ "$rcC" != "0" ] && echo "$outC" | grep -q "suspended" && ! echo "$outC" | grep -q "already running" \
   && [ "$rcC2" = "0" ] && echo "$outC2" | grep -q "stopped (pid $P2)" && gone "$P2"; then
  ok "gateC: up refuses to call a suspended lock holder running, and down still stops it"
else
  bad "gateC: orphaned suspended holder (up rc=$rcC, down rc=$rcC2, gone=$(gone "$P2" && echo yes || echo no))"
fi

# ===================================================================== GATE D ==
say "D: a daemon cut off from its server is degraded, not up"
T 30 --server "$SERVER" up --detach --dir "$WORK/drop" >"$WORK/upD.log" 2>&1
P3=$(daemon_pid) || { bad "gateD: setup, no daemon"; P3=""; }
[ -n "$P3" ] && pids+=("$P3")
sleep 3
st0=$(T 20 status 2>&1)
stop_backend
degraded=""
for _ in $(seq 1 40); do
  stD=$(T 20 status 2>&1)
  echo "$stD" | grep -q "degraded" && { degraded=yes; break; }
  sleep 0.5
done
stDj=$(T 20 status --json 2>/dev/null)
docj=$(T 60 doctor --json 2>/dev/null)
echo "## before: $(echo "$st0" | head -1)"
echo "## cut off: $(echo "$stD" | head -1)"
echo "## doctor daemon: $(echo "$docj" | "$PYV" -c 'import json,sys; print(json.load(sys.stdin).get("daemon"))' 2>/dev/null)"
start_backend
back=""
for _ in $(seq 1 90); do
  stE=$(T 20 status 2>&1)
  if echo "$stE" | grep -q "up (pid $P3)" && ! echo "$stE" | grep -q "degraded"; then back=yes; break; fi
  sleep 0.5
done
echo "## server back: $(echo "$stE" | head -1)"
if echo "$st0" | grep -q "up (pid $P3)" && [ "$degraded" = "yes" ] \
   && echo "$stDj" | "$PYV" -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d.get("degraded") else 1)' \
   && echo "$docj" | "$PYV" -c 'import json,sys; d=json.load(sys.stdin)["daemon"]; sys.exit(0 if d["state"]=="degraded" and not d["healthy"] else 1)' \
   && [ "$back" = "yes" ]; then
  ok "gateD: cut off, status and doctor say degraded; reconnected, status says up"
else
  bad "gateD: degraded reporting (degraded=$degraded, back=$back)"
  tail -8 "$D/daemon.log" 2>/dev/null
fi
T 30 down --yes >/dev/null 2>&1

echo
echo "==========================================="
echo "daemon-stop gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
