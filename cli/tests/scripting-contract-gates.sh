#!/usr/bin/env bash
# Scripting-contract gates: what a blind DevOps tester scripting the launch
# candidate relied on, end to end against the real binary.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/scripting-contract-gates.sh
#
# Gates:
#   J1a  `send f --to B 2>&1 | head -1` (the reader leaves after one line):
#        exit 0 only when the file was delivered, byte for byte; any other
#        outcome is nonzero and nothing delivered. It exited 0 in 0.6 s with
#        nothing delivered.
#   J1b  the same with --json and stdout closed after one byte.
#   J2   `reach B --json` with no local daemon (a cold probe): ok and exit 0
#        agree, and the JSON says what the human line says: warm false, link
#        "cold", a connect time, and the path the probe took. It said
#        established true with route, addr and rtt all null.
#   J3a  `send --json` interrupted by SIGINT: exit 130 and ONE JSON failure
#        object on stdout, code "interrupted". It printed nothing.
#   J3b  the same for SIGTERM: exit 143.
#   J5   a send into a receiver whose disk is too small, with --json: exit 4,
#        error.reason "no_space", the receiver's sentence (with both sizes) in
#        error.message and in files[0].refusal. It said "failed (denied)".
#   K1   `receive -y --json` into a disk too small for the offer: exit 12
#        (local_resource, reason no_space) within seconds. It held the line
#        25 s and then blamed the sender: "unreachable", exit 6.
#   K2   `receive --json` with no tty and no -y: exit 2 (usage, reason
#        no_tty) naming -y, within seconds. It was the same exit 6 after 30 s.
#   K3   a corrupt devices.json: `devices`, `devices --json` and `send --to`
#        exit 2 naming the file, and nothing writes over it. It listed no
#        devices with exit 0 and `send --to` said "no such device" (3).
#   K5   an EMPTY devices.json or revoked-keys.json, or a corrupt caps.json:
#        exit 2 (corrupt_state) naming the file, which stays as it was. An
#        empty devices.json listed "No devices yet." with exit 0 and an
#        empty revoked-keys.json silently dropped every revocation.
#   K4   `send --code --json`: the code arrives on stdout as an event line
#        first, then the result object. It was on stderr only.
#
# J5 mounts a small tmpfs, so it needs passwordless sudo (GitHub's ubuntu
# runners have it). Without it the script REFUSES (exit 2) rather than report
# a result it did not measure.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8147
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-scripting.XXXXXX")"
# A bounded teardown on interrupt, so J3 measures the JSON, not a long grace.
export FILAMENT_SHUTDOWN_GRACE_MS=1500

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== scripting-contract gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

MOUNTS=()
pids=()
cleanup() {
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
  for d in "$WORK"/cfg-*; do
    [ -d "$d" ] && FILAMENT_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1
  done
  for m in "${MOUNTS[@]:-}"; do [ -n "$m" ] && sudo -n umount -l "$m" 2>/dev/null; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
sudo -n true 2>/dev/null || { echo "REFUSED: gate J5 mounts a tmpfs and needs passwordless sudo"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

# ================================================================ fixture ======
# Owner A; B joins A's fleet and runs a daemon. A sends as a one-shot, with NO
# daemon of its own (that is also J2's "local daemon down").
DA="$WORK/cfg-A"; DB="$WORK/cfg-B"; mkdir -p "$DA" "$DB"
A() { env FILAMENT_CONFIG_DIR="$DA" "$@"; }
env FILAMENT_CONFIG_DIR="$DA" "$BIN" init --name boxA --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/A-drop" >"$WORK/A-up.log" 2>&1 &
ADAEMON=$!; pids+=($ADAEMON)
sleep 3
env FILAMENT_CONFIG_DIR="$DA" timeout 45 "$BIN" --server "$SERVER" add --for boxB --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1
env FILAMENT_CONFIG_DIR="$DB" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" --name boxB --no-interactive >"$WORK/join.log" 2>&1
kill "$ADAEMON" 2>/dev/null; sleep 2
if ! FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q boxB; then
  echo "setup: boxB did not join"; tail -5 "$WORK/add.log" "$WORK/join.log"; exit 2
fi
DROP="$WORK/B-drop"; mkdir -p "$DROP"
start_b() {
  env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" up --dir "$1" >>"$WORK/B-up.log" 2>&1 &
  BDAEMON=$!; pids+=($BDAEMON)
  sleep 4
}
start_b "$DROP"

# A delivery check: the file landed under its name, byte-identical.
delivered() { [ -f "$DROP/$(basename "$1")" ] && cmp -s "$1" "$DROP/$(basename "$1")"; }

# ==================================================================== J1a ======
say "J1a: send 2>&1 | head -1 is truthful"
head -c 200000 /dev/urandom >"$WORK/pipetest.txt"
env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/pipetest.txt" --to boxB 2>&1 | head -1 >"$WORK/j1a.head"
rc=${PIPESTATUS[0]}
sleep 1
d=no; delivered "$WORK/pipetest.txt" && d=yes
echo "## rc=$rc delivered=$d first line: $(cat "$WORK/j1a.head")"
if { [ "$rc" = 0 ] && [ "$d" = yes ]; } || { [ "$rc" != 0 ] && [ "$rc" != 124 ] && [ "$d" = no ]; }; then
  ok "J1a: send through a closed pipe exits $rc and delivered=$d (0 only with the bytes on the far side)"
else
  bad "J1a: send through a closed pipe (rc=$rc delivered=$d)"
  tail -8 "$WORK/B-up.log"
fi

# ==================================================================== J1b ======
say "J1b: send --json | head -c 1 is truthful"
head -c 200000 /dev/urandom >"$WORK/pipejson.txt"
env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/pipejson.txt" --to boxB --json 2>"$WORK/j1b.err" | head -c 1 >/dev/null
rc=${PIPESTATUS[0]}
sleep 1
d=no; delivered "$WORK/pipejson.txt" && d=yes
echo "## rc=$rc delivered=$d"
if { [ "$rc" = 0 ] && [ "$d" = yes ]; } || { [ "$rc" != 0 ] && [ "$rc" != 124 ] && [ "$d" = no ]; }; then
  ok "J1b: send --json into a closed stdout exits $rc and delivered=$d"
else
  bad "J1b: send --json into a closed stdout (rc=$rc delivered=$d)"
  tail -5 "$WORK/j1b.err"
fi

# ===================================================================== J2 ======
say "J2: reach --json with no local daemon"
env FILAMENT_CONFIG_DIR="$DA" timeout 60 "$BIN" --server "$SERVER" reach boxB --json >"$WORK/j2.json" 2>"$WORK/j2.err"
rc=$?
echo "## rc=$rc"; cat "$WORK/j2.json"
if "$PYV" - "$WORK/j2.json" "$rc" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0]); rc = int(sys.argv[2])
assert d["ok"] is (rc == 0), f"ok={d['ok']} but exit {rc}"
assert rc == 0, "B's daemon is up: the cold probe must connect"
assert d["warm"] is False and d["link"] == "cold", d
assert isinstance(d["connect_ms"], int) and d["connect_ms"] > 0, d
assert d["data"]["connect_ms"] == d["connect_ms"], d
assert d["data"]["route"] is not None, d["data"]
assert d["data"]["direct"] is (d["data"]["route"] != "relay"), d["data"]
assert d["data"]["rtt_ms"] is None, "an establish time is not an RTT"
PY
then
  ok "J2: a cold reach --json says cold, its connect time and its path, ok == (exit 0)"
else
  bad "J2: cold reach --json (rc=$rc)"
  tail -5 "$WORK/j2.err"
fi

# ===================================================================== J3 ======
# The send waits on stdin (a producer that never finishes), so the signal
# lands while the command is mid-work, every run.
j3() {  # $1 signal name, $2 expected exit
  local out="$WORK/j3-$1.json" rc
  ( sleep 60 ) | env FILAMENT_CONFIG_DIR="$DA" timeout --preserve-status -s "$1" 4 \
      "$BIN" --server "$SERVER" send - --to boxB --json >"$out" 2>"$WORK/j3-$1.err"
  rc=${PIPESTATUS[1]}
  echo "## $1: rc=$rc stdout: $(cat "$out")"
  "$PYV" - "$out" "$rc" "$2" "SIG$1" <<'PY'
import json, sys
out, rc, want, sig = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
docs = [l for l in open(out) if l.strip()]
assert rc == want, f"exit {rc}, want {want}"
assert len(docs) == 1, f"{len(docs)} JSON documents on stdout"
d = json.loads(docs[0])
assert d["ok"] is False and d["verb"] == "send", d
assert d["error"]["code"] == "interrupted" and d["error"]["exit"] == want, d
assert d["error"]["signal"] == sig, d
PY
}
say "J3a: send --json interrupted by SIGINT"
if j3 INT 130; then ok "J3a: SIGINT under --json exits 130 with one failure object"; else bad "J3a: SIGINT under --json"; tail -3 "$WORK/j3-INT.err"; fi
say "J3b: send --json terminated by SIGTERM"
if j3 TERM 143; then ok "J3b: SIGTERM under --json exits 143 with one failure object"; else bad "J3b: SIGTERM under --json"; tail -3 "$WORK/j3-TERM.err"; fi

# ===================================================================== J5 ======
say "J5: a full receiver's typed reason reaches --json"
kill "$BDAEMON" 2>/dev/null; sleep 2
TINY="$WORK/tiny"; mkdir -p "$TINY"
sudo -n mount -t tmpfs -o "size=2m,uid=$(id -u),gid=$(id -g),mode=0700" tmpfs "$TINY" \
  || { echo "REFUSED: cannot mount a tmpfs at $TINY"; exit 2; }
MOUNTS+=("$TINY")
start_b "$TINY"
head -c 3000000 /dev/urandom >"$WORK/three.bin"
env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/three.bin" --to boxB --json >"$WORK/j5.json" 2>"$WORK/j5.err"
rc=$?
echo "## rc=$rc"; cat "$WORK/j5.json"
if "$PYV" - "$WORK/j5.json" "$rc" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0]); rc = int(sys.argv[2])
assert rc == 4, f"exit {rc}"
assert d["ok"] is False and d["error"]["code"] == "denied" and d["error"]["exit"] == 4, d
assert d["error"].get("reason") == "no_space", d["error"]
msg = d["error"]["message"]
assert "out of disk space" in msg and "needs" in msg and "failed (denied)" not in msg, msg
f = d["files"][0]
assert f["refused"] is True and f["declined"] is False and f["delivered"] is False, f
assert f["refusal"]["reason"] == "no_space" and "needs" in f["refusal"]["message"], f
PY
then
  ok "J5: disk full under --json: exit 4, error.reason no_space, the receiver's sentence per file and at the top"
else
  bad "J5: disk-full reason in --json (rc=$rc)"
  tail -5 "$WORK/j5.err"; tail -5 "$WORK/B-up.log"
fi

# ===================================================================== K* ======
# The receiver tells the truth about itself, and state files are never "empty".
# The receivers below are fresh config dirs with no identity and no pairing,
# meeting the sender in an explicit room, so nothing auto-accepts.
kill "$BDAEMON" 2>/dev/null; sleep 2
since() { echo $(( $(date +%s) - $1 )); }

# One receive --json result object, checked against what the gate expects.
# $1 json file, $2 rc, $3 want exit, $4 want code, $5 want reason, $6 elapsed, $7 bound
check_recv() {
  "$PYV" - "$@" <<'PY'
import json, sys
out, rc, want, code, reason, took, bound = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5], int(sys.argv[6]), int(sys.argv[7])
docs = [l for l in open(out) if l.strip()]
assert rc == want, f"exit {rc}, want {want}"
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0])
assert d["ok"] is (rc == 0) and d["verb"] == "receive", d
e = d["error"]
assert e["code"] == code and e["exit"] == want and e.get("reason") == reason, e
assert "unreachable" not in e["message"], e["message"]
f = d["files"][0]
assert f["received"] is False and f["refusal"]["reason"] == reason, f
assert took < bound, f"took {took}s: the receive held the line after refusing"
PY
}

say "K1: receive into a full disk: exit 12 with its reason, promptly, in --json"
TINY2="$WORK/tiny2"; mkdir -p "$TINY2"
sudo -n mount -t tmpfs -o "size=2m,uid=$(id -u),gid=$(id -g),mode=0700" tmpfs "$TINY2" \
  || { echo "REFUSED: cannot mount a tmpfs at $TINY2"; exit 2; }
MOUNTS+=("$TINY2")
DK1="$WORK/cfg-K1"; mkdir -p "$DK1"
t0=$(date +%s)
env FILAMENT_CONFIG_DIR="$DK1" timeout 90 "$BIN" --server "$SERVER" receive --room k1room --dir "$TINY2" -y --json \
  >"$WORK/k1.json" 2>"$WORK/k1.err" &
K1PID=$!
sleep 4
env FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$WORK/three.bin" --room k1room >"$WORK/k1-send.log" 2>&1
src=$?
wait "$K1PID"; rc=$?
took=$(since "$t0")
echo "## receive rc=$rc in ${took}s, send rc=$src"; cat "$WORK/k1.json"; tail -3 "$WORK/k1.err"
if check_recv "$WORK/k1.json" "$rc" 12 local_resource no_space "$took" 30; then
  ok "K1: a receiver out of disk space exits 12 (local_resource, no_space) at once, not 6 after holding the line"
else
  bad "K1: receive disk full (rc=$rc, ${took}s)"
fi

say "K2: receive with no tty and no -y: exit 2 naming -y, promptly, in --json"
DK2="$WORK/cfg-K2"; mkdir -p "$DK2" "$WORK/k2-drop"
head -c 1000 /dev/urandom >"$WORK/small.bin"
t0=$(date +%s)
env FILAMENT_CONFIG_DIR="$DK2" timeout 90 "$BIN" --server "$SERVER" receive --room k2room --dir "$WORK/k2-drop" --json \
  </dev/null >"$WORK/k2.json" 2>"$WORK/k2.err" &
K2PID=$!
sleep 4
env FILAMENT_CONFIG_DIR="$DA" timeout 90 "$BIN" --server "$SERVER" send "$WORK/small.bin" --room k2room >"$WORK/k2-send.log" 2>&1
src=$?
wait "$K2PID"; rc=$?
took=$(since "$t0")
echo "## receive rc=$rc in ${took}s, send rc=$src"; cat "$WORK/k2.json"; tail -3 "$WORK/k2.err"
if check_recv "$WORK/k2.json" "$rc" 2 usage no_tty "$took" 30 \
   && grep -q -- "-y" "$WORK/k2.json"; then
  ok "K2: a receive that cannot ask exits 2 (usage, no_tty) naming -y, not 6 after 30 s"
else
  bad "K2: receive without a tty or -y (rc=$rc, ${took}s)"
fi

say "K3: a corrupt devices.json is an error naming it, and is never written over"
DK3="$WORK/cfg-K3"; cp -a "$DA" "$DK3"
printf '{garbage\n' >"$DK3/devices.json"
env FILAMENT_CONFIG_DIR="$DK3" timeout 20 "$BIN" devices >"$WORK/k3-dev.out" 2>"$WORK/k3-dev.err"; r1=$?
env FILAMENT_CONFIG_DIR="$DK3" timeout 20 "$BIN" devices --json >"$WORK/k3-json.out" 2>"$WORK/k3-json.err"; r2=$?
env FILAMENT_CONFIG_DIR="$DK3" timeout 30 "$BIN" --server "$SERVER" send "$WORK/small.bin" --to boxB >"$WORK/k3-send.out" 2>&1; r3=$?
env FILAMENT_CONFIG_DIR="$DK3" timeout 20 "$BIN" grant boxB shell -y >"$WORK/k3-grant.out" 2>&1; r4=$?
echo "## devices rc=$r1 devices --json rc=$r2 send rc=$r3 grant rc=$r4"
cat "$WORK/k3-dev.err" "$WORK/k3-json.out"
if [ "$r1" = 2 ] && [ "$r2" = 2 ] && [ "$r3" = 2 ] && [ "$r4" != 0 ] \
   && grep -q "devices.json" "$WORK/k3-dev.err" && grep -q "devices.json" "$WORK/k3-send.out" \
   && [ "$(cat "$DK3/devices.json")" = "{garbage" ] \
   && "$PYV" - "$WORK/k3-json.out" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, docs
d = json.loads(docs[0])
assert d["ok"] is False and d["error"]["code"] == "corrupt_state" and d["error"]["exit"] == 2, d
assert "devices.json" in d["error"]["message"], d
PY
then
  ok "K3: corrupt devices.json: devices, devices --json and send exit 2 naming it; nothing overwrote it"
else
  bad "K3: corrupt devices.json (devices=$r1 json=$r2 send=$r3 grant=$r4)"
  cat "$WORK/k3-send.out" "$WORK/k3-grant.out"
fi

say "K5: an EMPTY devices.json / revoked-keys.json, or a corrupt caps.json, is refused by name and left alone"
DK5="$WORK/cfg-K5"; cp -a "$DA" "$DK5"
: >"$DK5/devices.json"
env FILAMENT_CONFIG_DIR="$DK5" timeout 20 "$BIN" devices >"$WORK/k5-dev.out" 2>"$WORK/k5-dev.err"; r1=$?
env FILAMENT_CONFIG_DIR="$DK5" timeout 20 "$BIN" devices --json >"$WORK/k5-json.out" 2>"$WORK/k5-json.err"; r2=$?
env FILAMENT_CONFIG_DIR="$DK5" timeout 30 "$BIN" --server "$SERVER" send "$WORK/small.bin" --to boxB >"$WORK/k5-send.out" 2>&1; r3=$?
DK5R="$WORK/cfg-K5R"; cp -a "$DA" "$DK5R"
: >"$DK5R/revoked-keys.json"
env FILAMENT_CONFIG_DIR="$DK5R" timeout 20 "$BIN" devices >"$WORK/k5-rev.out" 2>"$WORK/k5-rev.err"; r4=$?
DK5C="$WORK/cfg-K5C"; cp -a "$DA" "$DK5C"
printf '[{' >"$DK5C/caps.json"
env FILAMENT_CONFIG_DIR="$DK5C" timeout 20 "$BIN" devices >"$WORK/k5-caps.out" 2>"$WORK/k5-caps.err"; r5=$?
echo "## empty devices.json: devices=$r1 json=$r2 send=$r3; empty revoked-keys.json: devices=$r4; corrupt caps.json: devices=$r5"
cat "$WORK/k5-dev.err" "$WORK/k5-json.out" "$WORK/k5-rev.err" "$WORK/k5-caps.err"
if [ "$r1" = 2 ] && [ "$r2" = 2 ] && [ "$r3" = 2 ] && [ "$r4" = 2 ] && [ "$r5" = 2 ] \
   && grep -q "devices.json" "$WORK/k5-dev.err" && grep -q "devices.json" "$WORK/k5-send.out" \
   && grep -q "revoked-keys.json" "$WORK/k5-rev.err" && grep -q "caps.json" "$WORK/k5-caps.err" \
   && [ -e "$DK5/devices.json" ] && [ ! -s "$DK5/devices.json" ] \
   && [ -e "$DK5R/revoked-keys.json" ] && [ ! -s "$DK5R/revoked-keys.json" ] \
   && [ "$(cat "$DK5C/caps.json")" = "[{" ] \
   && ! grep -qi "no devices yet" "$WORK/k5-dev.out" \
   && "$PYV" - "$WORK/k5-json.out" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, docs
d = json.loads(docs[0])
assert d["ok"] is False and d["error"]["code"] == "corrupt_state" and d["error"]["exit"] == 2, d
assert "devices.json" in d["error"]["message"], d
PY
then
  ok "K5: empty devices.json, empty revoked-keys.json and corrupt caps.json exit 2 (corrupt_state) naming the file; none was written over"
else
  bad "K5: empty/truncated state file (devices=$r1 json=$r2 send=$r3 revoked=$r4 caps=$r5)"
  cat "$WORK/k5-dev.out" "$WORK/k5-send.out" "$WORK/k5-rev.out" "$WORK/k5-caps.out"
fi

say "K4: send --json with a code prints the code on stdout before it ends"
DK4="$WORK/cfg-K4"; mkdir -p "$DK4" "$WORK/k4-drop"
env FILAMENT_CONFIG_DIR="$DA" timeout 120 "$BIN" --server "$SERVER" send "$WORK/small.bin" --code --json \
  >"$WORK/k4.json" 2>"$WORK/k4.err" &
K4PID=$!
CODE=""
for _ in $(seq 1 30); do
  CODE=$("$PYV" -c 'import json,sys
l=open(sys.argv[1]).readline()
d=json.loads(l) if l.strip() else {}
print(d.get("code","") if d.get("event")=="code" else "")' "$WORK/k4.json" 2>/dev/null)
  [ -n "$CODE" ] && break
  sleep 0.5
done
echo "## code from stdout: '$CODE'"
[ -n "$CODE" ] && env FILAMENT_CONFIG_DIR="$DK4" timeout 60 "$BIN" --server "$SERVER" receive "$CODE" -y --dir "$WORK/k4-drop" \
  >"$WORK/k4-recv.log" 2>&1
wait "$K4PID"; rc=$?
echo "## send rc=$rc"; cat "$WORK/k4.json"
if [ -n "$CODE" ] && "$PYV" - "$WORK/k4.json" "$rc" "$CODE" <<'PY'
import json, sys
docs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
rc, code = int(sys.argv[2]), sys.argv[3]
assert len(docs) == 2, f"{len(docs)} lines"
ev, res = docs
assert ev["event"] == "code" and ev["code"] == code and ev["expires_in_secs"] == 600, ev
assert "ok" not in ev, ev
assert res["ok"] is True and rc == 0 and res["verb"] == "send", (rc, res)
PY
then
  ok "K4: code send --json: the code event first on stdout, then the result object"
else
  bad "K4: code send --json (rc=$rc code='$CODE')"
  tail -5 "$WORK/k4.err"; tail -5 "$WORK/k4-recv.log"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "scripting-contract gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
[ "$FAIL" = 0 ]
