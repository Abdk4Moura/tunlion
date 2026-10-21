#!/usr/bin/env bash
# E2E: a real CLI `tunlion send --code` delivers a file to a receiver running
# the library engine through `Core::receive_code`, not `tunlion receive`.
#
# The receiver is the `receive-code` binary built from crates/tunlion-core. It
# opens an explicit config dir, takes the same-root lease, and runs the real
# `recv::dispatch::drive` with the reduced CoreHost/ports/identity/store. The
# sender is the normal CLI, minting a code with the same ephemeral PAKE the
# product uses. The assertions are about bytes on disk, the returned summary,
# and the sender's exit, not about a code claim alone.
#
# Requires a built CLI and core helper in the same target directory:
#   cargo build --release -p tunlion --bin tunlion
#   cargo build --release -p tunlion-core --bin receive-code
#
# Honors: TUNLION_BIN, TUNLION_CORE_BIN, TUNLION_TEST_VENV.
# Refuses (exit 2) when either binary or the backend is unavailable; it never
# silently skips.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CORE_BIN="${TUNLION_CORE_BIN:-$(dirname "$BIN")/receive-code}"
PORT="${TUNLION_CORE_E2E_PORT:-8188}"
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/core-receive-e2e.XXXXXX")"
DA="$WORK/da"
export TUNLION_NONINTERACTIVE=1
export TUNLION_SHUTDOWN_GRACE_MS=1500
export TUNLION_REJOIN_SECS=3

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

[ -x "$BIN" ] || { echo "no tunlion binary at $BIN (build: cargo build --release -p tunlion)"; exit 2; }
[ -x "$CORE_BIN" ] || {
  echo "no Core receive helper at $CORE_BIN"
  echo "  build: cargo build --release -p tunlion-core --bin receive-code"
  exit 2
}

start_backend

S="$WORK/sender"; R="$WORK/receiver"; INBOX="$WORK/inbox"
mkdir -p "$S" "$R" "$INBOX"
init_owner "$S"
init_owner "$R"
# Core reads only the explicit config dir. `init` already wrote the identity;
# this is the signaling endpoint the library's dispatch must use.
printf 'server %s\n' "$SERVER" >>"$R/config"

PAY="$WORK/core-e2e-payload.bin"
# Deterministic, non-repeating bytes: a fixed reported sha256 makes a failed
# run comparable, and a pattern still catches an offset/corruption bug that all
# zeros would hide.
"$PYV" - "$PAY" <<'PY'
import sys
size = 1024 * 1024 + 137
state = 0x12345678
out = bytearray(size)
for i in range(size):
    state = (1103515245 * state + 12345) & 0x7FFFFFFF
    out[i] = (state >> 16) & 0xFF
open(sys.argv[1], "wb").write(out)
PY
PAYNAME="$(basename "$PAY")"
PAYHASH="$(sha256sum "$PAY" | cut -d' ' -f1)"
PAYSIZE="$(stat -c %s "$PAY")"

# The code a `send --json` printed as its `code` event, if any.
code_of() {
  "$PYV" - "$1" 2>/dev/null <<'PY'
import json, sys
try:
    lines = open(sys.argv[1], errors="replace")
except OSError:
    raise SystemExit(0)
for line in lines:
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("event") == "code" and d.get("code"):
        print(d["code"])
        break
PY
}

say "start a real CLI sender for a code transfer"
timeout -k 5 120 env TUNLION_CONFIG_DIR="$S" "$BIN" --server "$SERVER" send "$PAY" \
  --code --word gigantic-element --json </dev/null >"$WORK/send.json" 2>"$WORK/send.err" &
SPID=$!
FIX_PIDS+=("$SPID")

CODE=""
for _ in $(seq 1 300); do
  CODE="$(code_of "$WORK/send.json")"
  [ -n "$CODE" ] && break
  kill -0 "$SPID" 2>/dev/null || break
  sleep 0.1
done
if [ -z "$CODE" ]; then
  bad "sender minted no code"
  echo "--- send.json"; cat "$WORK/send.json" 2>/dev/null
  echo "--- send.err"; cat "$WORK/send.err" 2>/dev/null
  exit 1
fi
echo "## sender minted a code; it stays in shell variables and the sender's own output"

say "run Core::receive_code against the same server"
timeout -k 5 120 env -u TUNLION_CONFIG_DIR "$CORE_BIN" \
  --config-dir "$R" --dir "$INBOX" --code "$CODE" --yes --timeout 90 \
  >"$WORK/receiver.json" 2>"$WORK/receiver.err" &
RPID=$!
FIX_PIDS+=("$RPID")

wait "$SPID"; SRC=$?
wait "$RPID"; RRC=$?

echo "## sender rc=$SRC receiver rc=$RRC"
echo "--- receiver.json"; cat "$WORK/receiver.json"
echo "--- receiver.err"; cat "$WORK/receiver.err"

# P1: the sender says every file was delivered with its sha256.
if [ "$SRC" -eq 0 ] && "$PYV" - "$WORK/send.json" "$PAY" <<'PY'
import hashlib, json, sys
docs = []
for line in open(sys.argv[1], errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        docs.append(json.loads(line))
    except Exception:
        pass
res = next((d for d in reversed(docs) if d.get("verb") == "send" and "ok" in d), None)
assert res is not None, docs
assert res["ok"] is True, res
assert res["files"] and all(f["delivered"] for f in res["files"]), res
want = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
assert res["files"][0]["sha256"] == want, (res["files"][0]["sha256"], want)
PY
then
  ok "P1: the CLI sender exited 0 with every file delivered and its sha256 acknowledged"
else
  bad "P1: the CLI sender did not report a verified delivery (rc=$SRC)"
  echo "--- send.err"; cat "$WORK/send.err" 2>/dev/null
fi

# P2: bytes really landed in the library receiver's inbox, under the offered name.
if [ -f "$INBOX/$PAYNAME" ] && cmp -s "$PAY" "$INBOX/$PAYNAME"; then
  ok "P2: $PAYNAME landed in the receiver inbox byte for byte ($PAYSIZE bytes)"
else
  bad "P2: $PAYNAME is missing or differs in the receiver inbox"
  ls -la "$INBOX" 2>/dev/null
fi

# P3: the summary came from RecvReport and carries the stored fact and sha.
SUMMARY="$("$PYV" - "$WORK/receiver.json" "$PAY" <<'PY' 2>"$WORK/summary.err"
import hashlib, json, os, sys
lines = [line for line in open(sys.argv[1], errors="replace") if line.strip()]
assert lines, "receiver printed no summary"
s = json.loads(lines[-1])
want = os.path.basename(sys.argv[2])
data = open(sys.argv[2], "rb").read()
assert s.get("bytes") == len(data), s
assert s.get("refused") == [], s
stored = s.get("stored")
assert stored and len(stored) == 1, s
f = stored[0]
assert f["name"] == want, f
assert f["stored_name"] == want, f
assert f["bytes"] == len(data), f
assert f["sha256"] == hashlib.sha256(data).hexdigest(), f
print("stored=%s bytes=%d sha256=%s" % (f["stored_name"], f["bytes"], f["sha256"]))
PY
)"
if [ "$RRC" -eq 0 ] && [ -n "$SUMMARY" ]; then
  ok "P3: Core::receive_code returned the stored summary and sha256 ($SUMMARY)"
else
  bad "P3: Core::receive_code did not return the expected summary (rc=$RRC)"
  cat "$WORK/summary.err" 2>/dev/null
fi

# P4: cancellation is a separate path, but a successful call must not print the
# claim either. The helper's only stdout line is the summary; the library log is
# NoLog. A match here is a real leak.
if ! grep -Fq -- "$CODE" "$WORK/receiver.json" "$WORK/receiver.err" 2>/dev/null; then
  ok "P4: the receiver did not log the code"
else
  bad "P4: the receiver output contains the code"
  grep -Fn -- "$CODE" "$WORK/receiver.json" "$WORK/receiver.err" 2>/dev/null
fi

# P5: the receiver exited 0 only after the bytes and summary were proven above.
if [ "$RRC" -eq 0 ]; then
  ok "P5: the library receiver exited 0 after completing the one-shot"
else
  bad "P5: the library receiver exited $RRC"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT core-receive-e2e PASS $PAYNAME bytes=$PAYSIZE sha256=$PAYHASH"
  exit 0
fi
echo "RESULT core-receive-e2e FAIL $FAIL gate(s)"
exit 1
