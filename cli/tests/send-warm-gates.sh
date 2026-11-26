#!/usr/bin/env bash
# `tunlion send --to <device>` rides the local daemon's warm direct link.
# Hermetic, fixture port 8124 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./send-warm-gates.sh
#
# A send to a paired device asks its own `up` daemon for the live direct QUIC
# link that daemon already holds to the device, and carries the transfer over
# it instead of building a link of its own (cli/src/send_warm.rs,
# crates/filament-peerloop/src/l2/warm_send.rs). Found by the chaos fuzzer: on
# a slow lossy path the send's own direct dial missed its budget and fell to a
# data channel moving a few hundred bytes a second, while the daemons' link
# carried traffic fine.
#
#   S1  WARM: with A's daemon holding the link, `send --to boxb` rides it: rc 0,
#       the file lands byte-exact, --json says ok with the receiver's verified
#       sha256, and the send never went looking on the server for boxb.
#   S2  COLD, explicit: TUNLION_NO_WARM_REUSE=1 builds its own link exactly as
#       before (rc 0, byte-exact, no warm claim).
#   S3  TWO AT ONCE: two warm sends of different files to the same device over
#       the one daemon link both land byte-exact (each gets its own stream ids).
#   S4  THE WARM LINK DIES MID-TRANSFER: A's daemon is killed while a slowed
#       transfer rides its link. The send falls back to its own link, resumes,
#       and still ends with the receiver's whole-file delivery-ack: rc 0 and the
#       file byte-exact (never a false success, never a corrupt file).
#   S5  NO DAEMON: with A's daemon gone, a send builds its own link (rc 0,
#       byte-exact, no warm claim).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# shellcheck source=cli/tests/lib/backend.sh
source "$HERE/lib/backend.sh"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8124
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-send-warm.XXXXXX")"
export TUNLION_SHUTDOWN_GRACE_MS=1500

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== send-warm gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=()
cleanup() {
  backend_stop "${BACKEND_PID:-}"
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
if uname -s | grep -qiE "mingw|msys|cygwin|windows"; then
  # The warm path needs the Unix control socket; Windows always builds its own
  # link, which every other send gate covers.
  echo "SKIP: the warm send path is unix only"; exit 0
fi

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
backend_start "$CLI_DIR/../backend" "$PYV" "$WORK/backend.log" \
  PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25
pids+=("$BACKEND_PID")
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB" "$WORK/Adrop" "$WORK/Bdrop"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxb","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxa","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"
A_ENV=(env TUNLION_CONFIG_DIR="$DA" TUNLION_NAME=boxa)

env TUNLION_LOG=debug TUNLION_CONFIG_DIR="$DB" TUNLION_NAME=boxb \
  "$BIN" up --dir "$WORK/Bdrop" --server "$SERVER" >"$WORK/upB.log" 2>&1 &
pids+=($!)
env TUNLION_CONFIG_DIR="$DA" "$BIN" set auto-warm on >"$WORK/set.log" 2>&1 || true
start_a() {
  env TUNLION_LOG=debug TUNLION_CONFIG_DIR="$DA" TUNLION_NAME=boxa \
    "$BIN" up --dir "$WORK/Adrop" --server "$SERVER" >>"$WORK/upA.log" 2>&1 &
  APID=$!; pids+=($APID)
  # The daemon holds the link to boxb (warm-hold), and it is direct.
  local i
  for i in $(seq 1 60); do
    grep -qE "warm-hold: (established connection to|skip) 'boxb'" "$WORK/upA.log" && return 0
    sleep 0.5
  done
  echo "-- upA.log --"; tail -20 "$WORK/upA.log"
  return 1
}
start_a || echo "## A's daemon never reported a held link to boxb; S1 will say what happened"
sleep 2

# $1 file name in Bdrop, $2 local source: landed byte-exact?
landed() {
  local i
  for i in $(seq 1 20); do
    [ -f "$WORK/Bdrop/$1" ] && cmp -s "$WORK/Bdrop/$1" "$2" && return 0
    sleep 0.25
  done
  return 1
}
sha() { sha256sum "$1" | cut -d' ' -f1; }
WARM="riding the local daemon's warm link to 'boxb'"
SERVER_LOOK="found 'boxb' on the tunlion server"

# ===================================================================== S1 ======
say "S1: warm"
head -c 3000000 /dev/urandom >"$WORK/s1.bin"
timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s1.bin" --to boxb --json \
  >"$WORK/s1.json" 2>"$WORK/s1.err" </dev/null
rc=$?
echo "## rc=$rc"
if [ "$rc" = 0 ] && landed s1.bin "$WORK/s1.bin" \
   && grep -q "$WARM" "$WORK/s1.err" && ! grep -q "$SERVER_LOOK" "$WORK/s1.err" \
   && "$PYV" - "$WORK/s1.json" "$(sha "$WORK/s1.bin")" <<'PY'
import json, sys
docs = [l for l in open(sys.argv[1]) if l.strip()]
assert len(docs) == 1, f"{len(docs)} documents"
d = json.loads(docs[0])
assert d["ok"] is True and d["verb"] == "send", d
assert sys.argv[2] in json.dumps(d), ("the verified sha256 is not in the result", d)
PY
then
  ok "S1: the send rode A's daemon link (rc 0, byte-exact, --json ok with the verified sha256)"
else
  echo "-- s1.json --"; cat "$WORK/s1.json"; echo "-- s1.err --"; tail -40 "$WORK/s1.err"
  echo "-- upA.log --"; grep -i "warm" "$WORK/upA.log" | tail -20
  bad "S1: warm send (rc=$rc)"
fi

# ===================================================================== S2 ======
say "S2: explicit cold"
head -c 1000000 /dev/urandom >"$WORK/s2.bin"
TUNLION_NO_WARM_REUSE=1 timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s2.bin" --to boxb \
  >"$WORK/s2.out" 2>"$WORK/s2.err" </dev/null
rc=$?
echo "## rc=$rc"
if [ "$rc" = 0 ] && landed s2.bin "$WORK/s2.bin" && ! grep -q "$WARM" "$WORK/s2.err"; then
  ok "S2: TUNLION_NO_WARM_REUSE=1 built its own link (rc 0, byte-exact, no warm claim)"
else
  echo "-- s2.err --"; tail -30 "$WORK/s2.err"
  bad "S2: explicit cold send (rc=$rc)"
fi

# ===================================================================== S3 ======
say "S3: two warm sends at once"
head -c 2000000 /dev/urandom >"$WORK/s3a.bin"
head -c 2000000 /dev/urandom >"$WORK/s3b.bin"
( TUNLION_TEST_TRANSFER_STALL_MS=20 timeout 90 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s3a.bin" --to boxb \
    >/dev/null 2>"$WORK/s3a.err" </dev/null; echo $? >"$WORK/s3a.rc" ) &
P3A=$!
( TUNLION_TEST_TRANSFER_STALL_MS=20 timeout 90 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s3b.bin" --to boxb \
    >/dev/null 2>"$WORK/s3b.err" </dev/null; echo $? >"$WORK/s3b.rc" ) &
P3B=$!
wait "$P3A" "$P3B"
ra=$(cat "$WORK/s3a.rc"); rb=$(cat "$WORK/s3b.rc")
echo "## rc=$ra,$rb"
if [ "$ra" = 0 ] && [ "$rb" = 0 ] && landed s3a.bin "$WORK/s3a.bin" && landed s3b.bin "$WORK/s3b.bin" \
   && grep -q "$WARM" "$WORK/s3a.err" && grep -q "$WARM" "$WORK/s3b.err"; then
  ok "S3: two concurrent sends over the one daemon link both landed byte-exact"
else
  echo "-- s3a.err --"; tail -20 "$WORK/s3a.err"; echo "-- s3b.err --"; tail -20 "$WORK/s3b.err"
  bad "S3: concurrent warm sends (rc=$ra,$rb)"
fi

# ===================================================================== S4 ======
# Slowed so the transfer is still riding the warm link when A's daemon dies:
# 4 MiB at about 60 ms per 64 KiB is about 4 s of streaming.
say "S4: the warm link dies mid-transfer"
head -c 4000000 /dev/urandom >"$WORK/s4.bin"
( TUNLION_TEST_TRANSFER_STALL_MS=60 timeout 120 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s4.bin" --to boxb --json \
    >"$WORK/s4.json" 2>"$WORK/s4.err" </dev/null; echo $? >"$WORK/s4.rc" ) &
P4=$!
for _ in $(seq 1 50); do
  grep -q "$WARM" "$WORK/s4.err" 2>/dev/null && [ -f "$WORK/Bdrop/s4.bin.part" ] && break
  sleep 0.1
done
sleep 1
echo "## killing A's daemon with $(stat -c %s "$WORK/Bdrop/s4.bin.part" 2>/dev/null || echo '?') bytes in boxb's partial"
kill -9 "$APID" 2>/dev/null
wait "$P4"
rc=$(cat "$WORK/s4.rc")
echo "## rc=$rc"
if [ "$rc" = 0 ] && landed s4.bin "$WORK/s4.bin" \
   && grep -q "$WARM" "$WORK/s4.err" \
   && grep -q "warm link ended" "$WORK/s4.err" \
   && "$PYV" - "$WORK/s4.json" "$(sha "$WORK/s4.bin")" <<'PY'
import json, sys
d = json.loads([l for l in open(sys.argv[1]) if l.strip()][0])
assert d["ok"] is True, d
assert sys.argv[2] in json.dumps(d), d
PY
then
  ok "S4: the warm link died mid-transfer; the send resumed on its own link and the receiver verified the whole file"
else
  echo "-- s4.json --"; cat "$WORK/s4.json"; echo "-- s4.err --"; tail -40 "$WORK/s4.err"
  echo "-- upB.log --"; tail -30 "$WORK/upB.log"
  ls -la "$WORK/Bdrop"
  bad "S4: warm link death mid-transfer (rc=$rc)"
fi

# ===================================================================== S5 ======
say "S5: no daemon"
head -c 1000000 /dev/urandom >"$WORK/s5.bin"
timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" -v send "$WORK/s5.bin" --to boxb \
  >"$WORK/s5.out" 2>"$WORK/s5.err" </dev/null
rc=$?
echo "## rc=$rc"
if [ "$rc" = 0 ] && landed s5.bin "$WORK/s5.bin" && ! grep -q "$WARM" "$WORK/s5.err"; then
  ok "S5: with no daemon the send built its own link (rc 0, byte-exact, no warm claim)"
else
  echo "-- s5.err --"; tail -30 "$WORK/s5.err"
  bad "S5: send with no daemon (rc=$rc)"
fi

echo
echo "send-warm gates: $PASS passed, $FAIL failed${FAILED:+ ($FAILED)}"
[ "$FAIL" = 0 ]
