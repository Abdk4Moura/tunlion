#!/usr/bin/env bash
# Signaling-freeze gates: a daemon that was frozen (SIGSTOP) long enough for the
# server to drop its socket must come back on its own, quickly and quietly.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/signaling-freeze-gates.sh
#
# THE DEFECT. A blind test froze a paired daemon for ~80 s and resumed it. It
# never recovered: daemon.log repeated "signaling link closed, reconnecting..."
# and "signaling reconnected, re-announcing presence" about 2.5 times a second
# for as long as it ran (97 -> 351 -> 625 lines over 6 minutes), the peer's
# `send --to` failed after 60 s with exit 6, and only a restart fixed it. The
# cause: every signaling connection shares the daemon's event channel, the
# freeze armed the silence watchdog and the close path at once, and the close
# of the connection the watchdog had just replaced was taken as the NEW one
# going down. Each re-dial then closed a live connection whose own close landed
# after the next re-dial, forever.
#
# Gates (B is the frozen daemon; A is its paired owner, also running):
#   0  baseline: A -> B send works before the freeze (setup, so a later failure
#      is the freeze and not the fixture).
#   1  after SIGCONT, B reports its signaling link connected within 30 s.
#   2  no reconnect storm, measured OUTSIDE the daemon: from the resume through
#      a further 45 s the server logs at most 3 Socket.IO connects, the daemon
#      holds a connection (ss, by pid) in most samples, and its own re-dial
#      count agrees. The storm made ~2.5 connects a second.
#   3  daemon.log after the resume holds at most 4 reconnect lines, counting
#      any the log collapsed. The storm wrote ~150 a minute.
#   4  A -> B send works after the resume, byte-exact.
#
# The backend runs with the server's production ping settings (10 s timeout,
# 5 s interval) rather than the 120 s the other fixtures use: the server has to
# actually drop the frozen socket for the freeze to mean anything.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8133
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-freeze.XXXXXX")"
FREEZE_SECS="${FREEZE_SECS:-80}"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== signaling-freeze gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && { kill -CONT "$p" 2>/dev/null; kill "$p" 2>/dev/null; }; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
command -v ss >/dev/null || { echo "REFUSED: gate 2 counts connections with ss, which is missing"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=10 FIL_PING_INTERVAL=5 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# The `signaling` object of a daemon's cap-status reply, or null.
sig_state() {
  "$PYV" - "$1/control.sock" <<'PY'
import json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(3)
    s.connect(sys.argv[1])
    s.sendall(b'{"op":"cap-status"}\n')
    buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    print(json.dumps(json.loads(buf).get("signaling")))
except Exception:
    print("null")
PY
}
field() { "$PYV" -c 'import json,sys; d=json.loads(sys.argv[1] or "null") or {}; v=d.get(sys.argv[2]); print("" if v is None else v)' "$1" "$2"; }

# Local ports of the established TCP connections pid $1 holds to the server.
conn_ports() {
  ss -tnpH state established "( dport = :$PORT )" 2>/dev/null \
    | grep "pid=$1," | awk '{print $3}' | awk -F: '{print $NF}' | sort -u
}

hashof() { sha256sum "$1" | cut -d' ' -f1; }

# ============================================================ fixture ==
DA="$WORK/cfg-A"; DB="$WORK/cfg-B"; mkdir -p "$DA" "$DB" "$WORK/Adrop" "$WORK/Bdrop"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name boxA --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1 \
  || { echo "init failed"; exit 2; }
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/A-up.log" 2>&1 &
APID=$!; pids+=($APID)
sleep 3
env FILAMENT_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for boxB --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1
env FILAMENT_CONFIG_DIR="$DB" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" --name boxB --no-interactive >"$WORK/join.log" 2>&1
if ! FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q boxB; then
  echo "setup: boxB did not join"; tail -5 "$WORK/add.log" "$WORK/join.log"; exit 2
fi
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$WORK/Bdrop" >"$WORK/B-up.log" 2>&1 &
BPID=$!; pids+=($BPID)
sleep 5

send_ok() { # $1 = file, $2 = label
  local out rc
  out=$(env FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$1" --to boxB 2>&1); rc=$?
  echo "## $2: send rc=$rc"; echo "$out" | tail -4 | sed 's/^/    /'
  [ "$rc" = "0" ] && [ -f "$WORK/Bdrop/$(basename "$1")" ] \
    && [ "$(hashof "$1")" = "$(hashof "$WORK/Bdrop/$(basename "$1")")" ]
}

# ============================================================= GATE 0 ==
say "0: baseline send before the freeze"
head -c 200000 /dev/urandom >"$WORK/before.bin"
if send_ok "$WORK/before.bin" "before"; then
  ok "gate0: A -> B send works before the freeze"
else
  bad "gate0: baseline send failed, the fixture is broken"
  tail -10 "$WORK/B-up.log"
fi
pre_ports="$(conn_ports "$BPID" | tr '\n' ' ')"
echo "## B daemon pid $BPID, connections to the server before the freeze: [$pre_ports]"

# THE PEER LINK IS PART OF THE REPRODUCTION. The finding was a daemon frozen
# "while a peer is connected", and the link is what seeds the storm: on resume
# its QUIC idle timer fires at once, so a link event reaches the loop between
# the silence probe and the old socket's close, the watchdog re-dials first,
# and the late close then tears down the fresh connection. Measured: with no
# held link (the one-shot send above closes its own) the unfixed daemon made
# one clean reconnect, so without this precondition the gate proves nothing.
held=""
for _ in $(seq 1 60); do
  held=$("$PYV" - "$DB/control.sock" <<'PY'
import json, socket, sys
try:
    s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(sys.argv[1])
    s.sendall(b'{"op":"list-warm"}\n'); buf = b""
    while not buf.endswith(b"\n"):
        c = s.recv(65536)
        if not c:
            break
        buf += c
    links = json.loads(buf).get("links", [])
    print(" ".join(sorted(l.get("name") or "?" for l in links)))
except Exception:
    print("")
PY
)
  [ -n "$held" ] && break
  sleep 1
done
if [ -z "$held" ]; then
  echo "REFUSED: B never held a link to boxA within 60s, so the freeze would not reproduce the finding"
  tail -20 "$WORK/B-up.log"; tail -20 "$WORK/A-up.log"
  exit 2
fi
echo "## B holds a link to: $held"

# ============================================================= GATE 1 ==
say "1: SIGSTOP ${FREEZE_SECS}s, SIGCONT, and the link comes back"
log_lines_before=$(wc -l <"$WORK/B-up.log")
kill -STOP "$BPID"
sleep "$FREEZE_SECS"
backend_lines_at_resume=$(wc -l <"$WORK/backend.log")
kill -CONT "$BPID"
t0=$(date +%s)
recovered=""
sig="null"
for _ in $(seq 1 60); do
  sig="$(sig_state "$DB")"
  if [ "$(field "$sig" state)" = "connected" ] && [ -n "$(conn_ports "$BPID")" ]; then
    recovered=$(( $(date +%s) - t0 )); break
  fi
  sleep 0.5
done
echo "## signaling after resume: $sig"
if [ -n "$recovered" ]; then
  ok "gate1: B reports its signaling link connected ${recovered}s after SIGCONT"
else
  bad "gate1: B did not report a connected signaling link within 30s of SIGCONT (last: $sig)"
fi

# ============================================================= GATE 2 ==
say "2: no reconnect storm (counted by the server, and by ss)"
# Measured OUTSIDE the daemon. The server logs one TEL "connect" per Socket.IO
# connection; nothing else connects in this window (A sends nothing, A's daemon
# was never frozen), so every connect from the resume onward is B re-dialing.
# ss, by pid, checks the daemon actually HOLDS a connection most of the time:
# a quiet server log from a daemon that is simply off the server would
# otherwise read as a pass.
samples_with_conn=0
for _ in $(seq 1 90); do
  [ -n "$(conn_ports "$BPID")" ] && samples_with_conn=$((samples_with_conn+1))
  sleep 0.5
done
connects=$(tail -n +"$((backend_lines_at_resume + 1))" "$WORK/backend.log" | grep -c '"ev":"connect"' || true)
setup_connects=$(head -n "$backend_lines_at_resume" "$WORK/backend.log" | grep -c '"ev":"connect"' || true)
sig="$(sig_state "$DB")"
redials="$(field "$sig" redials)"
echo "## since the resume: $connects server connect(s); the daemon held a connection in $samples_with_conn/90 samples"
echo "## daemon's own count: redials=$redials state=$(field "$sig" state)"
if [ "$setup_connects" -lt 2 ]; then
  # The instrument: the server must have logged the setup's own connects, or a
  # zero after the resume means nothing.
  bad "gate2: the server logged $setup_connects connects during setup, so its count cannot be trusted"
elif [ "$samples_with_conn" -lt 60 ]; then
  bad "gate2: the daemon held a server connection in only $samples_with_conn of 90 samples"
elif [ "$connects" -le 3 ] && [ -n "$redials" ] && [ "$redials" -le 3 ]; then
  ok "gate2: one stable connection after the resume ($connects server connects, $redials re-dials)"
else
  bad "gate2: reconnect storm: $connects server connects since the resume, daemon re-dials=${redials:-unknown}"
fi

# ============================================================= GATE 3 ==
say "3: the log does not grow with every cycle"
tail -n +"$((log_lines_before + 1))" "$WORK/B-up.log" >"$WORK/B-after.log"
echo "## B's log from the resume (first 20 lines):"
head -20 "$WORK/B-after.log" | sed 's/^/    /'
lines=$(grep -ci "reconnecting\|reconnected" "$WORK/B-after.log" || true)
collapsed=$(grep -oE "and [0-9]+ more like it" "$WORK/B-after.log" | awk '{s+=$2} END{print s+0}')
total=$(( lines + ${collapsed:-0} ))
bytes=$(wc -c <"$WORK/B-after.log")
echo "## after resume: $lines reconnect lines written, $collapsed collapsed, ${bytes}B of log"
if [ "$total" -le 4 ]; then
  ok "gate3: $total reconnect events logged after the resume"
else
  bad "gate3: $total reconnect events after the resume ($lines lines written)"
fi

# ============================================================= GATE 4 ==
say "4: a send works after the resume"
head -c 300000 /dev/urandom >"$WORK/after.bin"
if send_ok "$WORK/after.bin" "after"; then
  ok "gate4: A -> B send works after the freeze, byte-exact"
else
  bad "gate4: send after the freeze failed"
  tail -15 "$WORK/B-up.log"
fi

echo
echo "==========================================="
echo "signaling-freeze gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
