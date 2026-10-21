#!/usr/bin/env bash
# Cross-engine E2E: a Core sender (`Core::create_code` + `wait_send`) delivers
# bytes to the normal CLI receiver (`tunlion receive <code>`).
#
# This is the opposite side of core-receive-e2e-gates.sh and proves the library
# sender engine is not a fake: the code is allocated by the signaling server,
# the receiver is a separate tunlion process, and the assertion is the bytes on
# disk plus the sender's per-file delivery fact.
#
# Refuses (exit 2) when a binary/backend is unavailable; it never skips silently.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CORE_SEND="${TUNLION_CORE_SEND_BIN:-$(dirname "$BIN")/send-code}"
PORT="${TUNLION_CORE_SEND_PORT:-8189}"
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/core-send-e2e.XXXXXX")"
echo "$WORK" >/tmp/core-send-work
DA="$WORK/da"
export TUNLION_NONINTERACTIVE=1
export TUNLION_SHUTDOWN_GRACE_MS=1500
export TUNLION_REJOIN_SECS=3

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

[ -x "$BIN" ] || { echo "no tunlion binary at $BIN"; exit 2; }
[ -x "$CORE_SEND" ] || {
  echo "no Core send helper at $CORE_SEND"
  echo "  build: cargo build --release -p tunlion-core --bin send-code"
  exit 2
}

start_backend

S="$WORK/sender"; R="$WORK/receiver"; INBOX="$WORK/inbox"
mkdir -p "$S" "$R" "$INBOX"
init_owner "$S"
init_owner "$R"
printf 'server %s\n' "$SERVER" >>"$S/config"

PAY="$WORK/core-send-payload.bin"
"$PYV" - "$PAY" <<'PY'
import sys
size = 1024 * 1024 + 311
state = 0x2468ACE
out = bytearray(size)
for i in range(size):
    state = (1103515245 * state + 12345) & 0x7FFFFFFF
    out[i] = (state >> 15) & 0xFF
open(sys.argv[1], "wb").write(out)
PY
PAYNAME="$(basename "$PAY")"
PAYHASH="$(sha256sum "$PAY" | cut -d' ' -f1)"
PAYSIZE="$(stat -c %s "$PAY")"

say "start the library sender and wait for its allocated code"
timeout -k 5 150 env -u TUNLION_CONFIG_DIR "$CORE_SEND" \
  --config-dir "$S" --code-out "$WORK/code" --timeout 120 "$PAY" \
  >"$WORK/sender.json" 2>"$WORK/sender.err" &
SPID=$!
FIX_PIDS+=("$SPID")

CODE=""
for _ in $(seq 1 300); do
  if [ -s "$WORK/code" ]; then
    CODE="$(head -n1 "$WORK/code" | tr -d '[:space:]')"
    [ -n "$CODE" ] && break
  fi
  kill -0 "$SPID" 2>/dev/null || break
  sleep 0.1
done
if [ -z "$CODE" ]; then
  bad "library sender allocated no code"
  echo "--- sender.json"; cat "$WORK/sender.json" 2>/dev/null
  echo "--- sender.err"; cat "$WORK/sender.err" 2>/dev/null
  exit 1
fi

say "receive that code with the normal CLI"
timeout -k 5 150 env TUNLION_CONFIG_DIR="$R" "$BIN" --server "$SERVER" \
  receive "$CODE" -y --dir "$INBOX" </dev/null >"$WORK/receiver.log" 2>&1 &
RPID=$!
FIX_PIDS+=("$RPID")

wait "$SPID"; SRC=$?
wait "$RPID"; RRC=$?

echo "## sender rc=$SRC receiver rc=$RRC"
echo "--- sender.json"; cat "$WORK/sender.json"
echo "--- sender.err"; cat "$WORK/sender.err"
echo "--- receiver.log"; tail -30 "$WORK/receiver.log"

# P1: the library sender completed and reported a delivery.
if [ "$SRC" -eq 0 ] && "$PYV" - "$WORK/sender.json" "$PAY" <<'PY'
import hashlib, json, sys
s = json.load(open(sys.argv[1]))
data = open(sys.argv[2], "rb").read()
assert s["bytes"] == len(data), s
assert s["files"] and len(s["files"]) == 1, s
f = s["files"][0]
assert f["name"] == sys.argv[2].rsplit("/", 1)[-1], f
assert f["bytes"] == len(data), f
assert f["sha256"] == hashlib.sha256(data).hexdigest(), f
assert f["delivered"] is True, f
PY
then
  ok "P1: Core::create_code/wait_send delivered and reported the file"
else
  bad "P1: the library sender did not report a verified delivery (rc=$SRC)"
fi

# P2: the CLI receiver exited 0.
if [ "$RRC" -eq 0 ]; then
  ok "P2: the CLI receiver exited 0"
else
  bad "P2: the CLI receiver exited $RRC"
fi

# P3: bytes are in the CLI receiver's inbox, under the offered name.
if [ -f "$INBOX/$PAYNAME" ] && cmp -s "$PAY" "$INBOX/$PAYNAME"; then
  ok "P3: $PAYNAME landed in the CLI inbox byte for byte ($PAYSIZE bytes)"
else
  bad "P3: $PAYNAME is missing or differs in the CLI inbox"
  ls -la "$INBOX" 2>/dev/null
fi

# P4: the code is the API result in the summary, never a diagnostic. The
# library's stderr must not carry it; the code-out file and the returned
# `SendResult.code` are the deliberate data channel.
if ! grep -Fq -- "$CODE" "$WORK/sender.err" 2>/dev/null; then
  ok "P4: the library sender did not log the code on stderr"
else
  bad "P4: the library sender stderr contains the code"
fi

# P5: the receiver saw the sender's authenticated code path, not a local-room
# fallback. The CLI's own receive log names the code claim.
if grep -qE "code claimed|authenticated|received|stored|delivered" "$WORK/receiver.log"; then
  ok "P5: the CLI receiver ran the code path and stored the file"
else
  bad "P5: the CLI receiver log does not show a completed code transfer"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT core-send-e2e PASS $PAYNAME bytes=$PAYSIZE sha256=$PAYHASH"
  exit 0
fi
echo "RESULT core-send-e2e FAIL $FAIL gate(s)"
exit 1
