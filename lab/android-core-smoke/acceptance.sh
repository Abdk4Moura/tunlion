#!/usr/bin/env bash
# Run inside android-emulator-runner after assembling both APKs. No Android CLI
# binary is installed: the test APK loads the real cdylib through UniFFI/JNA.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLI_DIR="$ROOT/cli"
BIN="${TUNLION_BIN:-$ROOT/target/release/tunlion}"
PYV=python3
PORT=8188
SERVER="http://127.0.0.1:$PORT"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/android-core.XXXXXX")"
DA="$WORK/unused"
source "$CLI_DIR/tests/lib/fixture.sh"
trap fixture_cleanup EXIT
export TUNLION_NONINTERACTIVE=1
start_backend
init_owner "$WORK/sender"
PAY="$WORK/android-core-payload.bin"
python3 - "$PAY" <<'PY'
import sys
size = 1024 * 1024 + 137
state = 0x12345678
payload = bytearray(size)
for i in range(size):
    state = (1103515245 * state + 12345) & 0x7fffffff
    payload[i] = (state >> 16) & 0xff
open(sys.argv[1], 'wb').write(payload)
PY
SHA="$(sha256sum "$PAY" | cut -d' ' -f1)"
BYTES="$(stat -c %s "$PAY")"
timeout -k 5 300 env TUNLION_CONFIG_DIR="$WORK/sender" "$BIN" --server "$SERVER" \
    send "$PAY" --code --json >"$WORK/send.json" 2>"$WORK/send.err" &
SENDER=$!
FIX_PIDS+=("$SENDER")
CODE=""
for _ in $(seq 1 300); do
    CODE="$(python3 - "$WORK/send.json" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    try:
        event = json.loads(line)
    except ValueError:
        continue
    if event.get('event') == 'code' and event.get('code'):
        print(event['code'])
        break
PY
)"
    [ -n "$CODE" ] && break
    kill -0 "$SENDER" 2>/dev/null || { echo 'sender exited before minting a code'; exit 1; }
    sleep 0.1
done
[ -n "$CODE" ] || { echo 'sender code deadline expired'; exit 1; }
echo "::add-mask::$CODE"
timeout -k 5 240 gradle -p "$ROOT/lab/android-core-smoke" --console plain \
    connectedDebugAndroidTest \
    "-Pandroid.testInstrumentationRunnerArguments.code=$CODE" \
    "-Pandroid.testInstrumentationRunnerArguments.sha256=$SHA" \
    "-Pandroid.testInstrumentationRunnerArguments.bytes=$BYTES"
wait "$SENDER"
python3 - "$WORK/send.json" "$SHA" <<'PY'
import json, sys
results = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
result = next(r for r in reversed(results) if r.get('verb') == 'send' and 'ok' in r)
assert result['ok'], result
assert len(result['files']) == 1, result
assert result['files'][0]['delivered'], result
assert result['files'][0]['sha256'] == sys.argv[2], result
PY
echo "PASS: Android APK loaded the Core .so, started/stopped/released its lease and received $BYTES verified bytes sha256=$SHA"
