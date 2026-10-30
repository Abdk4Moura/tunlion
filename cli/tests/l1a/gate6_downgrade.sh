#!/usr/bin/env bash
# GATE 6 (downgrade-refused): with both sides v2, a server that STRIPS the v:2
# flag (FIL_FORCE_V1) cannot force the legacy readable-secret path. A v2 client
# gets a legacy `pair-code` instead of `pair-ok` and ABORTS with a clear
# "update to pair securely" message — storing NOTHING.
#
# Part A (runtime): v2 creator vs a v:2-stripping server → refuse, no store.
# Part B (structural): the v2 pair_cmd never SENDS a pair-keep and its pair-keep
#         receive arm is a bail! — so no v2 code path stores a server-readable
#         secret. Together: the server can only DoS, never downgrade auth.
set -uo pipefail
# Configurable for any environment (defaults resolve relative to this script):
#   BIN     path to the release tunlion binary
#   SERVER  signaling backend base (port pinned to 8093 below; this gate restarts it)
#   PY      python that runs the LOCAL fixture backend (a throwaway venv)
#   MAIN    cli/src/pair_cmd.rs for the structural (source) assertions
#           (pair_cmd lived in main.rs until the 2026-09-12 decomposition)
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=cli/tests/lib/backend.sh
source "$HERE/../lib/backend.sh"
BIN=${BIN:-$HERE/../../target/release/tunlion}
PY=${PY:-${TUNLION_TEST_VENV:-python3}}
MAIN=${MAIN:-$HERE/../../src/pair_cmd.rs}
BACKEND_DIR=${BACKEND_DIR:-$HERE/../../../backend}
T=${T:-/tmp/l1a-gate6}
rm -rf "$T/g6"; mkdir -p "$T/g6/cfg"

# Stop our own 8093 listener and restart it with the v2-stripping flag.
for pid in $(ss -tlnp 2>/dev/null | grep ":8093 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
backend_start "$BACKEND_DIR" "$PY" "$T/g6/backend-forcev1.log" \
  PORT=8093 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  FIL_CLAIM_LIMIT=1000000 FIL_FORCE_V1=1
printf '%s\n' "$BACKEND_PID" > "$T/g6/backend-forcev1.pid"
for i in $(seq 1 20); do curl -s http://127.0.0.1:8093/api/config >/dev/null 2>&1 && break; sleep 0.3; done

# A v2 creator against the stripping server.
TUNLION_CONFIG_DIR=$T/g6/cfg TUNLION_PAIR_GRACE_SECS=10 \
  "$BIN" --server http://127.0.0.1:8093 pair --name v </dev/null >"$T/g6/creator.log" 2>&1 &
CRE=$!
for i in $(seq 1 30); do kill -0 $CRE 2>/dev/null || break; sleep 0.3; done
wait $CRE 2>/dev/null
RC=$?

echo "--- creator log ---"; cat "$T/g6/creator.log"
REFUSED=$(grep -ciE 'pair securely|legacy|update' "$T/g6/creator.log")
STORED=$(cat "$T/g6/cfg/devices.json" 2>/dev/null | grep -c '"secret"')
echo "creator exit code     : $RC (want nonzero)"
echo "refused w/ message    : $REFUSED (want >=1)"
echo "secret stored         : $STORED (want 0)"

# Restore the normal 8093 backend for the remaining gates.
for pid in $(ss -tlnp 2>/dev/null | grep ":8093 " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
backend_start "$BACKEND_DIR" "$PY" "$T/backend-8093.log" \
  PORT=8093 FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  FIL_CLAIM_LIMIT=1000000
# This standalone l1a fixture is intentionally left running for the gates that
# follow gate6. The PID is recorded so the owner can stop exactly this process
# (kill "$(cat "$T/backend-8093.pid")"); the backend still closes fd3/fd9, so a
# forgotten fixture cannot hold a worker build lock.
printf '%s\n' "$BACKEND_PID" > "$T/backend-8093.pid"
for i in $(seq 1 20); do curl -s http://127.0.0.1:8093/api/config >/dev/null 2>&1 && break; sleep 0.3; done

# Part B: structural assertions on the v2 pair_cmd.
# 1) v2 ceremony never SENDS a pair-keep (no secret over the DataChannel).
KEEP_SENDS=$(awk '/^async fn pair_cmd/,/^}/' "$MAIN" | grep -c 'send_control.*pair-keep')
# 2) the pair-keep RECEIVE arm bails (refuses) — no store.
KEEP_BAILS=$(awk '/^async fn pair_cmd/,/^}/' "$MAIN" | grep -A2 '"pair-keep")' | grep -c 'bail!')
echo "v2 pair-keep sends    : $KEEP_SENDS (want 0)"
echo "v2 pair-keep bails    : $KEEP_BAILS (want >=1)"

if [ "$REFUSED" -ge 1 ] && [ "$STORED" = "0" ] && [ "$RC" -ne 0 ] && [ "$KEEP_SENDS" = "0" ] && [ "$KEEP_BAILS" -ge 1 ]; then
  echo "GATE6 PASS: v2-stripping server is refused; no v2 path stores a server-readable secret"
  exit 0
fi
echo "GATE6 FAIL"; exit 1
