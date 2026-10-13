#!/usr/bin/env bash
# The daemon (`--to`) path answers, promptly and with its reason, even when the
# network has left a GHOST of the receiver on the server. Found by the blind
# launch run (two containers, both daemons up):
#   - `send f --to b` with b's disk full waited 61 s, then "no peer connected"
#     (exit 6); b's log said only "identity verified: 'a' / ok a", no refusal.
#   - the first `send --to b` after 10 idle minutes did the same, right after
#     b's daemon had reconnected its signaling socket; the retry took 1.5 s.
# Root cause: a daemon whose signaling socket the network drops WITHOUT a close
# reconnects on a fresh session while the server keeps listing the dead one
# until its ping timeout. The sender gave its one "active" slot to whichever
# session the server listed first; when that was the ghost, the real daemon's
# link came up as a mere responder: b verified a, and nothing was ever offered.
#
#   P1  ghost + disk full: the sender exits 4 with reason no_space within 10 s.
#   P2  ghost + a send that fits: delivered within 10 s.
#       Both first PROVE the ghost was there (the sender saw two sessions for
#       b), so a run where the network did not leave one cannot pass silently.
#   E1  exec b -> a works (positive control for E2-F1).
#   E2  exec running when a's daemon is kill -9'd: exits 6 within 16 s.
#   E3  exec to a's dead daemon: exits 6 within 20 s (was 45 s).
#   F1  exec running when a forgets b: exits 4 with the refusal, not
#       "link died" (6).
#   F2  after a forgets b, b's `send --to a` is refused within 15 s, exit 4,
#       naming the reason (was 62 s, exit 6 "is 'a' online?").
#
# Needs passwordless sudo (iptables for the blackhole, mount for the tmpfs);
# without it the script REFUSES (exit 2) rather than report what it did not
# measure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8153
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-daemon-path.XXXXXX")"
export FILAMENT_SHUTDOWN_GRACE_MS=1500

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== daemon-path gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=(); MOUNTS=(); RULES=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for r in "${RULES[@]:-}"; do [ -n "$r" ] && sudo -n iptables -D INPUT $r 2>/dev/null; done
  for d in "$WORK"/cfg-*; do
    [ -d "$d" ] && FILAMENT_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1
  done
  for m in "${MOUNTS[@]:-}"; do [ -n "$m" ] && sudo -n umount -l "$m" 2>/dev/null; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
sudo -n true 2>/dev/null || { echo "REFUSED: needs passwordless sudo (iptables, tmpfs)"; exit 2; }
command -v iptables >/dev/null || { echo "REFUSED: iptables is required"; exit 2; }

ts() { date +%s.%N; }
since() { "$PYV" -c "import sys;print(int(float(sys.argv[2])-float(sys.argv[1])))" "$1" "$(ts)"; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
# The production ping settings: a session whose socket died silently stays
# listed for up to interval + timeout, which is the window a ghost lives in.
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=60 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# ================================================================ fixture ======
# Owner A serves exec (FILAMENT_L2=1 + a grant); B joins A's fleet with shell
# in its ceiling and runs its daemon on a 2 MiB disk.
DA="$WORK/cfg-A"; DB="$WORK/cfg-B"; mkdir -p "$DA" "$DB"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name boxA --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1
start_a() {
  env FILAMENT_L2=1 FILAMENT_LOG=debug FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/A-drop" >>"$WORK/A-up.log" 2>&1 &
  ADAEMON=$!; pids+=($ADAEMON)
  sleep 4
}
start_a
env FILAMENT_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for boxB --allow shell --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1
env FILAMENT_CONFIG_DIR="$DB" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" --name boxB --no-interactive >"$WORK/join.log" 2>&1
if ! FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q boxB; then
  echo "setup: boxB did not join"; tail -5 "$WORK/add.log" "$WORK/join.log"; exit 2
fi
env FILAMENT_CONFIG_DIR="$DA" "$BIN" grant boxB shell -y >"$WORK/grant.log" 2>&1 \
  || { echo "setup: grant failed"; cat "$WORK/grant.log"; exit 2; }
TINY="$WORK/tiny"; mkdir -p "$TINY"
sudo -n mount -t tmpfs -o "size=2m,uid=$(id -u),gid=$(id -g),mode=0700" tmpfs "$TINY" \
  || { echo "REFUSED: cannot mount a tmpfs at $TINY"; exit 2; }
MOUNTS+=("$TINY")
env FILAMENT_LOG=debug FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$TINY" >>"$WORK/B-up.log" 2>&1 &
BDAEMON=$!; pids+=($BDAEMON)
sleep 8

head -c 200000 /dev/urandom >"$WORK/small.bin"
head -c 3000000 /dev/urandom >"$WORK/three.bin"

# Blackhole B daemon's signaling socket WITHOUT closing it: the server keeps
# listing that session (the ghost) while B reconnects on a fresh one.
blackhole_b() {
  local p
  for p in $(ss -tnp 2>/dev/null | grep "pid=$BDAEMON," | awk -v s="127.0.0.1:$PORT" '$5==s {print $4}' | grep -oE '[0-9]+$' | sort -u); do
    for r in "-p tcp --sport $PORT --dport $p -j DROP" "-p tcp --sport $p --dport $PORT -j DROP"; do
      # shellcheck disable=SC2086
      sudo -n iptables -I INPUT $r && RULES+=("$r")
    done
    echo "## blackholed B's signaling socket (local port $p)"
  done
}
reconnects() { grep -c "signaling reconnected" "$WORK/B-up.log"; }
# Did this sender see more than one session for boxB? (the instrument check)
saw_ghost() { [ "$(grep -oE 'ADOPT peer=[^ ]+' "$1" | sort -u | wc -l)" -ge 2 ]; }

say "ghost: B's signaling socket goes silent, B reconnects, the old session stays listed"
n0=$(reconnects)
blackhole_b
for _ in $(seq 1 75); do [ "$(reconnects)" -gt "$n0" ] && break; sleep 1; done
[ "$(reconnects)" -gt "$n0" ] && echo "## B reconnected its signaling" || echo "## B did NOT reconnect"
sleep 2

# ===================================================================== P1 ======
say "P1: disk full behind a ghost: exit 4, no_space, within 10 s"
t0=$(ts)
env FILAMENT_LOG=debug FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$WORK/three.bin" --to boxB --json >"$WORK/p1.json" 2>"$WORK/p1.err"
rc=$?; took=$(since "$t0")
echo "## rc=$rc in ${took}s"; cat "$WORK/p1.json"
if ! saw_ghost "$WORK/p1.err"; then
  bad "P1: the ghost was not reproduced (the sender saw one session for boxB), so nothing was measured"
  grep -E "ADOPT|reconnect" "$WORK/p1.err" | head
elif [ "$rc" = 4 ] && [ "$took" -le 10 ] && "$PYV" - "$WORK/p1.json" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0])
assert d["ok"] is False and d["error"]["code"] == "denied" and d["error"]["exit"] == 4, d
assert d["error"].get("reason") == "no_space", d["error"]
assert d["files"][0]["refusal"]["reason"] == "no_space", d["files"][0]
PY
then
  ok "P1: behind a ghost session the full receiver's refusal reached the sender in ${took}s (exit 4, no_space)"
else
  bad "P1: disk-full refusal behind a ghost (rc=$rc in ${took}s)"
  grep -v "still waiting" "$WORK/p1.err" | tail -25
fi

# ===================================================================== P2 ======
say "P2: a send that fits, behind the same ghost: delivered within 10 s"
t0=$(ts)
env FILAMENT_LOG=debug FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$WORK/small.bin" --to boxB >"$WORK/p2.out" 2>"$WORK/p2.err"
rc=$?; took=$(since "$t0")
echo "## rc=$rc in ${took}s"
if ! saw_ghost "$WORK/p2.err"; then
  bad "P2: the ghost was not reproduced (the sender saw one session for boxB), so nothing was measured"
elif [ "$rc" = 0 ] && [ "$took" -le 10 ] && cmp -s "$WORK/small.bin" "$TINY/small.bin"; then
  ok "P2: behind a ghost session the send was delivered in ${took}s"
else
  bad "P2: send behind a ghost (rc=$rc in ${took}s)"
  grep -v "still waiting" "$WORK/p2.err" | tail -25
fi
for r in "${RULES[@]:-}"; do [ -n "$r" ] && sudo -n iptables -D INPUT $r 2>/dev/null; done
RULES=()

# ===================================================================== E1 ======
say "E1: exec b -> a works (positive control)"
OUT=$(env FILAMENT_CONFIG_DIR="$DB" timeout 40 "$BIN" --server "$SERVER" exec boxA -- /bin/echo E1-OK 2>"$WORK/e1.err" </dev/null); rc=$?
if [ "$rc" = 0 ] && [ "$OUT" = "E1-OK" ]; then
  ok "E1: exec b -> a ran"
else
  bad "E1: exec b -> a (rc=$rc out='$OUT')"; tail -8 "$WORK/e1.err"
fi

# ===================================================================== E2 ======
say "E2: exec running when the serving daemon is kill -9'd: exit 6 within 16 s"
env FILAMENT_CONFIG_DIR="$DB" timeout 90 "$BIN" --server "$SERVER" exec boxA -- /bin/sleep 80 >/dev/null 2>"$WORK/e2.err" </dev/null &
EP=$!
sleep 5
kill -9 "$ADAEMON"; t0=$(ts)
wait "$EP"; rc=$?; took=$(since "$t0")
echo "## rc=$rc ${took}s after the kill"; tail -3 "$WORK/e2.err"
if [ "$rc" = 6 ] && [ "$took" -le 16 ] && grep -q "died during exec" "$WORK/e2.err"; then
  ok "E2: the exec noticed its daemon was gone in ${took}s (exit 6)"
else
  bad "E2: exec vs a kill -9'd daemon (rc=$rc in ${took}s)"
fi

# ===================================================================== E3 ======
say "E3: exec to a dead daemon: exit 6 within 20 s"
t0=$(ts)
env FILAMENT_CONFIG_DIR="$DB" timeout 90 "$BIN" --server "$SERVER" exec boxA -- /bin/echo SHOULD-NOT-RUN >"$WORK/e3.out" 2>"$WORK/e3.err" </dev/null
rc=$?; took=$(since "$t0")
echo "## rc=$rc in ${took}s"; tail -3 "$WORK/e3.err"
if [ "$rc" = 6 ] && [ "$took" -le 20 ] && ! grep -q SHOULD-NOT-RUN "$WORK/e3.out"; then
  ok "E3: exec to a dead daemon answered in ${took}s (exit 6)"
else
  bad "E3: exec to a dead daemon (rc=$rc in ${took}s)"
fi
start_a
sleep 6

# ===================================================================== F1 ======
say "F1: exec running when a forgets b: exit 4 with the refusal"
env FILAMENT_CONFIG_DIR="$DB" timeout 90 "$BIN" --server "$SERVER" exec boxA -- /bin/sleep 80 >/dev/null 2>"$WORK/f1.err" </dev/null &
EP=$!
sleep 6
if kill -0 "$EP" 2>/dev/null; then
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices forget boxB -y >"$WORK/forget.log" 2>&1; frc=$?; t0=$(ts)
  wait "$EP"; rc=$?; took=$(since "$t0")
  echo "## forget rc=$frc; exec rc=$rc ${took}s after it"; tail -3 "$WORK/f1.err"
  if [ "$frc" = 0 ] && [ "$rc" = 4 ] && [ "$took" -le 10 ] && grep -q "not recognized" "$WORK/f1.err" \
     && ! grep -q "died during exec" "$WORK/f1.err"; then
    ok "F1: the running exec ended as a refusal in ${took}s (exit 4, not recognized)"
  else
    bad "F1: exec when forgotten (forget rc=$frc, exec rc=$rc in ${took}s)"
  fi
else
  wait "$EP"; bad "F1: the exec ended before the forget (rc=$?)"; tail -5 "$WORK/f1.err"
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices forget boxB -y >"$WORK/forget.log" 2>&1
fi
sleep 3

# ===================================================================== F2 ======
say "F2: after a forgets b, b's send --to a is refused within 15 s, exit 4"
t0=$(ts)
env FILAMENT_LOG=debug FILAMENT_CONFIG_DIR="$DB" timeout 90 "$BIN" --server "$SERVER" send "$WORK/small.bin" --to boxA --json >"$WORK/f2.json" 2>"$WORK/f2.err"
rc=$?; took=$(since "$t0")
echo "## rc=$rc in ${took}s"; cat "$WORK/f2.json"
if [ "$rc" = 4 ] && [ "$took" -le 15 ] && "$PYV" - "$WORK/f2.json" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0])
assert d["ok"] is False and d["error"]["code"] == "denied" and d["error"]["exit"] == 4, d
assert "not recognized" in d["error"]["message"], d["error"]
PY
then
  ok "F2: a forgotten device's send was refused in ${took}s (exit 4, not recognized)"
else
  bad "F2: send from a forgotten device (rc=$rc in ${took}s)"
  grep -v "still waiting" "$WORK/f2.err" | tail -20
fi

echo
echo "daemon-path gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
[ "$FAIL" -eq 0 ]
