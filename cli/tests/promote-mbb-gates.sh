#!/usr/bin/env bash
# Make-before-break promotion gates. After a code's PAKE confirms, the transfer
# must start on the WebRTC link that just authenticated, instead of that link
# being torn down so the transfer can wait for direct QUIC ("Option A", which
# put 1.35 to 1.5 s between `authenticated` and the first byte of every
# cross-network code transfer). When QUIC does come up the stream moves to it at
# a frame boundary; when it never does, WebRTC simply keeps serving.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/promote-mbb-gates.sh
#
# Same host, fixture signaling. TUNLION_TEST_DIRECT_DELAY_MS models a
# cross-network QUIC race that takes a while to win; TUNLION_DIRECT_TEST_BLOCK
# models one that never does.
#
# Gates:
#   M1  QUIC held back 4 s: the whole file is delivered and its sha256
#       acknowledged before the direct link is even up (authenticated ->
#       acknowledged well inside the delay), on the link the ceremony
#       authenticated (neither end tears a link down in between: that teardown
#       was Option A), and it is byte-identical
#   M2  QUIC held back 0.7 s with a file still in flight then: both ends log the
#       handoff at a frame boundary, the offer was answered before it, and the
#       file is byte-identical
#   M3  QUIC blocked: no stall and no fallback rebuild (authenticated ->
#       acknowledged well inside the 5 s direct budget), the file is
#       byte-identical
#   M4  QUIC unimpeded (the default path): byte-identical, both ends exit 0
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8211
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-promote.XXXXXX")"
DA="$WORK/unused"
export TUNLION_NONINTERACTIVE=1
export TUNLION_COLOR=never

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend

# Run a command with every output line prefixed by seconds since $1 (one clock
# for both ends, so their timelines line up).
cat >"$WORK/stamp.py" <<'PY'
import subprocess, sys, time
t0 = float(sys.argv[1]); out = open(sys.argv[2], "w")
p = subprocess.Popen(sys.argv[3:], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                     stdin=subprocess.DEVNULL, text=True, errors="replace")
for line in p.stdout:
    out.write("%8.3f %s" % (time.time() - t0, line)); out.flush()
sys.exit(p.wait())
PY

# Seconds at which the first line matching $2 appears in log $1 (empty if none).
at() { grep -m1 -E "$2" "$1" 2>/dev/null | awk '{print $1}'; }
# a < b, as floats.
lt() { "$PYV" -c 'import sys; sys.exit(0 if float(sys.argv[1]) < float(sys.argv[2]) else 1)' "$1" "$2"; }
sub() { "$PYV" -c 'import sys; print("%.3f" % (float(sys.argv[1]) - float(sys.argv[2])))' "$1" "$2"; }

# One code transfer. $1 = case name, $2 = payload, rest = env for BOTH ends.
# Leaves $WORK/$1/{send,recv}.log, rc files and the received copy.
transfer() {
  local name=$1 file=$2; shift 2
  local d="$WORK/$name"; mkdir -p "$d/sc" "$d/rc" "$d/in"
  local t0; t0=$(date +%s.%N)
  env "$@" TUNLION_CONFIG_DIR="$d/sc" TUNLION_LOG=debug \
    "$PYV" "$WORK/stamp.py" "$t0" "$d/send.log" timeout 150 "$BIN" --server "$SERVER" send "$file" --code --json &
  local sp=$!; FIX_PIDS+=($sp)
  local code=""
  for _ in $(seq 1 60); do
    code=$(grep -oE '"code" *: *"[a-z]+-[a-z0-9-]+"' "$d/send.log" 2>/dev/null | head -1 | sed -E 's/.*"([a-z]+-[a-z0-9-]+)"$/\1/')
    [ -n "$code" ] && break; sleep 0.5
  done
  if [ -z "$code" ]; then echo "## $name: the sender minted no code"; kill "$sp" 2>/dev/null; return 1; fi
  env "$@" TUNLION_CONFIG_DIR="$d/rc" TUNLION_LOG=debug \
    "$PYV" "$WORK/stamp.py" "$t0" "$d/recv.log" timeout 120 "$BIN" --server "$SERVER" receive "$code" -y --dir "$d/in"
  echo $? >"$d/recv.rc"
  wait "$sp"; echo $? >"$d/send.rc"
  echo "## $name: code $code, send rc $(cat "$d/send.rc"), receive rc $(cat "$d/recv.rc")"
}

same() { cmp -s "$1" "$2"; }
# rc 0 when a line matching $4 appears in log $1 after the first match of $2
# and before the first match of $3.
between() {
  awk -v a="$2" -v b="$3" -v x="$4" '
    !in_ && $0 ~ a { in_ = 1; next }
    in_ && $0 ~ b { exit }
    in_ && $0 ~ x { found = 1; exit }
    END { exit !found }' "$1"
}
show() {  # the timeline lines that matter
  grep -hE "authenticated|PROMOTE|DIRECT-|verified|delivered|done" "$WORK/$1/send.log" "$WORK/$1/recv.log" | head -40
}

SMALL="$WORK/small.bin"; head -c 262144 /dev/urandom >"$SMALL"
BIG="$WORK/big.bin";     head -c $((128 * 1024 * 1024)) /dev/urandom >"$BIG"
MID="$WORK/mid.bin";     head -c $((8 * 1024 * 1024)) /dev/urandom >"$MID"

# ------------------------------------------------------------------- M1 --
say "M1: QUIC held back 4 s, the file still arrives right after authentication"
transfer m1 "$SMALL" TUNLION_TEST_DIRECT_DELAY_MS=4000
S="$WORK/m1/send.log"; R="$WORK/m1/recv.log"
# The sender's "delivered + verified" is the receiver's whole-file sha256
# acknowledgement arriving: the bytes are known to have landed.
auth=$(at "$S" "authenticated, sending"); landed=$(at "$S" "delivered \+ verified")
ended=$(at "$R" "ctl rx file-end"); standby=$(at "$R" "PROMOTE-STANDBY")
echo "## m1: authenticated ${auth:-?}s, file-end ${ended:-?}s, delivery acked ${landed:-?}s, receiver's direct link ${standby:-never}"
if [ "$(cat "$WORK/m1/recv.rc")" = 0 ] && [ "$(cat "$WORK/m1/send.rc")" = 0 ] \
   && same "$SMALL" "$WORK/m1/in/small.bin" \
   && [ -n "$auth" ] && [ -n "$landed" ] && [ -n "$ended" ] && lt "$(sub "$landed" "$auth")" 2.0 \
   && { [ -z "$standby" ] || lt "$ended" "$standby"; } \
   && ! between "$S" "authenticated, sending" "delivered" "drop_link" \
   && ! between "$R" "authenticated, receiving" "ctl rx file-end" "drop_link"; then
  ok "M1: delivered and acknowledged $(sub "$landed" "$auth")s after authentication on the link it authenticated (nothing torn down), before the 4 s direct link existed, byte-identical"
else
  bad "M1 the first byte waited on QUIC"; show m1
fi

# ------------------------------------------------------------------- M2 --
say "M2: QUIC comes up mid-file, the stream moves to it at a frame boundary"
transfer m2 "$BIG" TUNLION_TEST_DIRECT_DELAY_MS=700
S="$WORK/m2/send.log"; R="$WORK/m2/recv.log"
s_moved=$(at "$S" "PROMOTED peer=.*frame boundary"); r_moved=$(at "$R" "PROMOTED peer=")
offered=$(at "$R" "ctl rx file-offer"); ver=$(at "$R" "verified \(whole-file sha256 matched\)")
echo "## m2: offer answered ${offered:-?}s, sender moved ${s_moved:-never}s, receiver moved ${r_moved:-never}s, verified ${ver:-?}s"
if [ "$(cat "$WORK/m2/recv.rc")" = 0 ] && [ "$(cat "$WORK/m2/send.rc")" = 0 ] \
   && same "$BIG" "$WORK/m2/in/big.bin" \
   && [ -n "$s_moved" ] && [ -n "$r_moved" ] && [ -n "$offered" ] && [ -n "$ver" ] \
   && lt "$offered" "$s_moved" && lt "$s_moved" "$ver"; then
  ok "M2: the transfer started on WebRTC, moved to QUIC mid-file, byte-identical"
else
  bad "M2 mid-file handoff"; show m2
fi

# ------------------------------------------------------------------- M3 --
say "M3: QUIC never comes up, the transfer stays on WebRTC with no stall"
transfer m3 "$SMALL" TUNLION_DIRECT_TEST_BLOCK=1
S="$WORK/m3/send.log"
auth=$(at "$S" "authenticated, sending"); landed=$(at "$S" "delivered \+ verified")
echo "## m3: authenticated ${auth:-?}s, delivery acked ${landed:-?}s"
if [ "$(cat "$WORK/m3/recv.rc")" = 0 ] && [ "$(cat "$WORK/m3/send.rc")" = 0 ] \
   && same "$SMALL" "$WORK/m3/in/small.bin" \
   && [ -n "$auth" ] && [ -n "$landed" ] && lt "$(sub "$landed" "$auth")" 2.0 \
   && ! grep -q "DIRECT-FALLBACK" "$WORK/m3/send.log" "$WORK/m3/recv.log" \
   && ! grep -q "PROMOTED peer=" "$WORK/m3/send.log" "$WORK/m3/recv.log"; then
  ok "M3: delivered $(sub "$landed" "$auth")s after authentication on WebRTC, no fallback rebuild, byte-identical"
else
  bad "M3 a blocked direct path stalled the transfer"; show m3
fi

# ------------------------------------------------------------------- M4 --
say "M4: the default path, QUIC unimpeded"
transfer m4 "$MID"
if [ "$(cat "$WORK/m4/recv.rc")" = 0 ] && [ "$(cat "$WORK/m4/send.rc")" = 0 ] \
   && same "$MID" "$WORK/m4/in/mid.bin"; then
  ok "M4: delivered byte-identical, both ends exit 0"
else
  bad "M4 default code transfer"; show m4
fi

echo
echo "================ RESULT: $PASS passed, $FAIL failed ================"
[ -n "$FAILED" ] && echo "failed:$FAILED"
echo "logs + work dir: $WORK"
[ "$FAIL" -eq 0 ]
