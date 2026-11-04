#!/usr/bin/env bash
# Run only inside the CI emulator job or an approved leased Android worker.
# Desktop CLI is a reference peer, never installed or executed inside the app.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${TUNLION_BIN:-$ROOT/target/release/tunlion}"
WORK="$(mktemp -d "${RUNNER_TEMP:-/tmp}/android-native-app.XXXXXX")"
RESULTS="$ROOT/android/acceptance/results"
mkdir -p "$RESULTS"
PIDS=()
cleanup() { for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done; }
trap 'status=$?; cleanup || true; exit "$status"' EXIT
export TUNLION_NONINTERACTIVE=1
adb wait-for-device
adb install -r "$ROOT/app-apk/app-debug.apk"
adb install -r "$ROOT/test-apk/app-debug-androidTest.apk"
adb shell am instrument -w -e class com.tunlion.android.NativeCoreAcceptanceTest,com.tunlion.android.DeviceAuthorityUiTest \
    com.tunlion.android.test/androidx.test.runner.AndroidJUnitRunner | tee "$RESULTS/native-core-ui.txt"
grep -F 'OK (5 tests)' "$RESULTS/native-core-ui.txt"

(cd "$ROOT/backend"; exec timeout -k 5 480 env PORT=8188 FIL_ASYNC_MODE=eventlet \
    FIL_SELF_MONKEYPATCH=1 FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 \
    FIL_PING_INTERVAL=25 python3 app.py >"$WORK/backend.log" 2>&1) &
PIDS+=("$!")
healthy=false
for _ in $(seq 1 30); do
    if curl --connect-timeout 1 --max-time 2 -fsS http://127.0.0.1:8188/api/health >/dev/null 2>&1; then healthy=true; break; fi
    sleep 0.5
done
[ "$healthy" = true ] || { echo 'Signaling fixture failed bounded health check'; exit 1; }
mkdir -p "$WORK/sender"
timeout -k 5 45 env TUNLION_CONFIG_DIR="$WORK/sender" "$BIN" init --name desktop-native-proof \
    --recovery-file "$WORK/sender/recovery.txt" --yes >/dev/null
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
timeout -k 5 420 env TUNLION_CONFIG_DIR="$WORK/sender" "$BIN" --server http://127.0.0.1:8188 \
    send "$PAY" --code --json >"$WORK/send.json" 2>"$WORK/send.err" &
SENDER=$!
PIDS+=("$SENDER")
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
    kill -0 "$SENDER" 2>/dev/null || { echo 'Sender exited before code allocation'; exit 1; }
    sleep 0.1
done
[ -n "$CODE" ] || { echo 'Sender code deadline expired'; exit 1; }
echo "::add-mask::$CODE"
adb shell am instrument -w -e class com.tunlion.android.NativeAdapterAcceptanceTest \
    -e code "$CODE" -e sha256 "$SHA" -e bytes "$BYTES" -e server http://10.0.2.2:8188 \
    com.tunlion.android.test/androidx.test.runner.AndroidJUnitRunner | tee "$RESULTS/native-adapter.txt"
grep -F 'OK (1 test)' "$RESULTS/native-adapter.txt"
wait "$SENDER"
python3 - "$WORK/send.json" "$SHA" "$RESULTS/desktop-ack.json" <<'PY'
import json, sys
events = [json.loads(line) for line in open(sys.argv[1]) if line.strip()]
result = next(event for event in reversed(events) if event.get('verb') == 'send' and 'ok' in event)
assert result['ok'], 'Desktop sender failed'
assert len(result['files']) == 1, 'Expected one actual delivered file'
assert result['files'][0]['delivered'], 'Receiver did not acknowledge delivery'
assert result['files'][0]['sha256'] == sys.argv[2], 'Desktop and Android digest differ'
with open(sys.argv[3], 'w') as output:
    json.dump({'delivered': True, 'sha256': sys.argv[2]}, output)
PY
git -C "$ROOT" rev-parse HEAD > "$RESULTS/SOURCE_HEAD"
echo "PASS: native Android adapter received and published $BYTES verified bytes; desktop delivery acknowledgment confirmed"
