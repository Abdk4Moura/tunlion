#!/usr/bin/env bash
# Concurrent code-send gates: what the final lab pass of the release candidate
# (build 6319bcd) met. Two `tunlion send f --code` running at once on ONE
# device interfered: a receiver claiming code 1 handshook with BOTH senders,
# so code 2's sender (never claimed) exited "transfer REFUSED: key
# confirmation failed", or code 1's sender latched code 2's receiver and both
# receives hung, one ending in a false "the other device uses an older
# version". Root cause: the server moves a claimer into its creator's CURRENT
# room, which for a code send is the auto room every sender on that network
# shares, and the sender's one SPAKE2 ceremony and its transfer slot went to
# whichever room peer spoke first.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/concurrent-code-gates.sh
#
# Gates:
#   C1  two receivers (one config dir) claiming two concurrent codes from one
#       sender config dir each get THEIR file, byte for byte, exit 0
#   C2  both claimed senders exit 0 with every file delivered and verified
#       (send --json: ok, delivered, the sha256 the receiver acknowledged)
#   C3  a third concurrent sender whose code nobody claimed keeps waiting: it
#       is alive, refused nothing, and no process said "older version"
#   C4  both concurrent transfers finished within a bound
#   C5  that third code, claimed afterwards, delivers (it was healthy, not
#       merely alive)
#   H   `status --json` on the sending device lists EVERY send outcome: the
#       three delivered, one that timed out and one interrupted, the failed
#       ones with their reason (4 delivered + 3 failed used to show 5 rows)
#   J   `join` names the inviting device, never its signaling id
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8176
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-concur.XXXXXX")"
DA="$WORK/owner"
export TUNLION_NONINTERACTIVE=1
export TUNLION_SHUTDOWN_GRACE_MS=1500

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend

# A session-id-shaped token: 20 base64url characters mixing cases.
sid_like() { grep -oE '\b[A-Za-z0-9_-]{20}\b' "$1" | grep '[A-Z]' | grep '[a-z]' | grep -E '[A-Z].*[A-Z].*[A-Z]' | head -1; }

# The code a `send --json` printed as its first stdout line.
code_of() {
  "$PYV" -c 'import json,sys
try:
    l=open(sys.argv[1]).readline()
    d=json.loads(l) if l.strip() else {}
except Exception:
    d={}
print(d.get("code","") if d.get("event")=="code" else "")' "$1" 2>/dev/null
}
wait_code() {  # $1 = json file; echoes the code or nothing after ~30 s
  local c=""
  for _ in $(seq 1 60); do c=$(code_of "$1"); [ -n "$c" ] && break; sleep 0.5; done
  echo "$c"
}
# rc 0 when the send's result object says every file was delivered with the
# sha256 of the local file.
send_delivered() {  # $1 = json file, $2 = local file
  "$PYV" - "$1" "$2" <<'PY'
import hashlib, json, sys
docs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
res = docs[-1]
want = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
assert res.get("ok") is True, res
assert res["files"] and all(f["delivered"] for f in res["files"]), res
assert res["files"][0]["sha256"] == want, (res["files"][0]["sha256"], want)
PY
}

DS="$WORK/sender"; DR="$WORK/receiver"; mkdir -p "$DS" "$DR" "$WORK/r1" "$WORK/r2" "$WORK/r3"
for i in 1 2 3; do head -c $((40000 + i * 7919)) /dev/urandom >"$WORK/f$i.bin"; done
snd() {  # $1 = n; runs send n from the ONE sender config dir
  env TUNLION_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" send "$WORK/f$1.bin" --code --json \
    </dev/null >"$WORK/s$1.json" 2>"$WORK/s$1.err" &
  eval "SP$1=\$!"; FIX_PIDS+=($!)
}
rcv() {  # $1 = n, $2 = code; runs receive n from the ONE receiver config dir
  ( start=$(date +%s)
    timeout 120 env TUNLION_CONFIG_DIR="$DR" "$BIN" --server "$SERVER" receive "$2" -y --dir "$WORK/r$1" \
      </dev/null >"$WORK/rcv$1.log" 2>&1
    echo "$? $(( $(date +%s) - start ))" >"$WORK/rcv$1.rc" ) &
  eval "RP$1=\$!"; FIX_PIDS+=($!)
}

# ------------------------------------------------------------- C1..C4 --
say "C: two concurrent code sends from one device, two receivers, one unclaimed code"
snd 1; snd 2; snd 3
C1=$(wait_code "$WORK/s1.json"); C2=$(wait_code "$WORK/s2.json"); C3=$(wait_code "$WORK/s3.json")
echo "## codes: '$C1' '$C2' '$C3'"
if [ -z "$C1" ] || [ -z "$C2" ] || [ -z "$C3" ]; then
  bad "C setup: a sender minted no code"; cat "$WORK"/s*.err
  declare_known_red_summary; exit 1
fi
# Every sender is in the room before anyone claims, so each receiver meets
# all three of them: the shape the lab hit.
sleep 2
rcv 1 "$C1"; rcv 2 "$C2"
wait "$RP1" "$RP2"
wait "$SP1"; rs1=$?
wait "$SP2"; rs2=$?
read -r rr1 t1 <"$WORK/rcv1.rc"; read -r rr2 t2 <"$WORK/rcv2.rc"
echo "## receive 1 rc=$rr1 (${t1}s), receive 2 rc=$rr2 (${t2}s), send 1 rc=$rs1, send 2 rc=$rs2"
for n in 1 2; do echo "--- receive $n"; cat "$WORK/rcv$n.log"; echo "--- send $n"; cat "$WORK/s$n.err"; done

if [ "$rr1" = 0 ] && [ "$rr2" = 0 ] \
   && cmp -s "$WORK/f1.bin" "$WORK/r1/f1.bin" && cmp -s "$WORK/f2.bin" "$WORK/r2/f2.bin" \
   && [ ! -e "$WORK/r1/f2.bin" ] && [ ! -e "$WORK/r2/f1.bin" ] && [ ! -e "$WORK/r1/f3.bin" ] && [ ! -e "$WORK/r2/f3.bin" ]; then
  ok "C1: each concurrent receiver got its own code's file, byte for byte, and nothing else"
else
  bad "C1 concurrent receives (rc $rr1/$rr2)"; ls -la "$WORK/r1" "$WORK/r2"
fi

if [ "$rs1" = 0 ] && [ "$rs2" = 0 ] && send_delivered "$WORK/s1.json" "$WORK/f1.bin" && send_delivered "$WORK/s2.json" "$WORK/f2.bin"; then
  ok "C2: both claimed senders exited 0 with their file delivered and its sha256 acknowledged"
else
  bad "C2 concurrent senders (rc $rs1/$rs2)"; cat "$WORK/s1.json" "$WORK/s2.json"
fi

sleep 3
S3_ALIVE=0; kill -0 "$SP3" 2>/dev/null && S3_ALIVE=1
echo "--- send 3 (unclaimed) so far"; cat "$WORK/s3.err"
if [ "$S3_ALIVE" = 1 ] && ! grep -qE "REFUSED|Error:|older version" "$WORK/s3.err" \
   && ! grep -qi "older version" "$WORK"/s*.err "$WORK"/rcv*.log; then
  ok "C3: the concurrent sender whose code nobody claimed is still waiting, refused nothing, and nobody said 'older version'"
else
  bad "C3 unclaimed sender (alive=$S3_ALIVE)"
fi

BOUND=60
if [ "${t1:-999}" -le "$BOUND" ] && [ "${t2:-999}" -le "$BOUND" ]; then
  ok "C4: both concurrent transfers finished within ${BOUND}s (${t1}s, ${t2}s)"
else
  bad "C4 concurrent transfers took ${t1}s and ${t2}s (bound ${BOUND}s)"
fi

# ------------------------------------------------------------------ C5 --
say "C5: the code nobody claimed still works when claimed"
rcv 3 "$C3"
wait "$RP3"
wait "$SP3"; rs3=$?
read -r rr3 t3 <"$WORK/rcv3.rc"
echo "## receive 3 rc=$rr3 (${t3}s), send 3 rc=$rs3"
if [ "$rr3" = 0 ] && [ "$rs3" = 0 ] && cmp -s "$WORK/f3.bin" "$WORK/r3/f3.bin" && send_delivered "$WORK/s3.json" "$WORK/f3.bin"; then
  ok "C5: the third code, claimed after the others finished, delivered its file"
else
  bad "C5 the late claim (rc $rr3/$rs3)"; cat "$WORK/rcv3.log" "$WORK/s3.err"
fi

# ------------------------------------------------------------------- H --
say "H: status lists every send outcome, failed ones with their reason"
echo "times out $$" >"$WORK/f4.txt"
timeout 60 env TUNLION_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" send "$WORK/f4.txt" --code --timeout 4 \
  </dev/null >"$WORK/s4.log" 2>&1; rs4=$?
echo "interrupted $$" >"$WORK/f5.txt"
env TUNLION_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" send "$WORK/f5.txt" --code --json \
  </dev/null >"$WORK/s5.json" 2>"$WORK/s5.err" &
SP5=$!; FIX_PIDS+=($SP5)
C5CODE=$(wait_code "$WORK/s5.json")
sleep 1
kill -INT "$SP5" 2>/dev/null
wait "$SP5"; rs5=$?
env TUNLION_CONFIG_DIR="$DS" "$BIN" status --json >"$WORK/status.json" 2>"$WORK/status.err"
echo "## timed-out send rc=$rs4, interrupted send rc=$rs5 (code '$C5CODE')"
if "$PYV" - "$WORK/status.json" <<'PY'
import json, sys
st = json.load(open(sys.argv[1]))
rows = [r for r in st["recent"] if r["direction"] == "out"]
for r in rows:
    print("##", r["file"], r["ok"], r.get("error"))
files = {r["file"]: r for r in rows}
for f in ("f1.bin", "f2.bin", "f3.bin"):
    assert files[f]["ok"] is True, files.get(f)
for f in ("f4.txt", "f5.txt"):
    assert files[f]["ok"] is False and files[f].get("error"), files.get(f)
assert "interrupted" in files["f5.txt"]["error"], files["f5.txt"]
assert len(rows) == 5, len(rows)
PY
then
  [ "$rs4" != 0 ] && [ "$rs5" = 130 ] \
    && ok "H: status recorded all five sends: three delivered, a timed-out and an interrupted one with their reasons" \
    || bad "H exit codes (timed out rc=$rs4, interrupted rc=$rs5)"
else
  bad "H status history is missing send outcomes"; cat "$WORK/status.json"; cat "$WORK/s4.log" "$WORK/s5.err"
fi

# ------------------------------------------------------------------- J --
say "J: join names the inviting device, never its signaling id"
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate guestj
JL=$(grep "sent enrollment request to" "$WORK/guestj-join.log" | head -1)
echo "## $JL"
printf '%s\n' "$JL" >"$WORK/j-line.txt"
JSID=$(sid_like "$WORK/j-line.txt")
if [ -n "$JL" ] && [ -z "$JSID" ]; then
  ok "J: join's enrollment line names the device, with no raw signaling id"
else
  bad "J join names the peer by id ('$JSID')"; cat "$WORK/guestj-join.log"
fi

declare_known_red_summary
echo
echo "== concurrent-code gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
