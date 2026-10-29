#!/usr/bin/env bash
# Gate 16: known-device rendezvous + remember consent (C12/C20/C27, web half).
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/known-device-gates.sh
#
# A real Chromium tab (known-device.js) receives a `send --word --remember`
# code, consents to remember the sender, and is then found by a fresh
# `send --to <name>` in an isolated room, with no code: only the remembered
# secret's presence channel can connect them, and the known device must be
# recognised (one stored record), not added again. A third sender is declined
# with "Not now" and must discard its half.
#
# Needs playwright in cli/tests (npm ci) with Chromium, the backend's Python
# deps, and a SAME-ORIGIN frontend/dist (VITE_TUNLION_API= npm run build).
# gates.sh runs this as its gate 16; .github/workflows/browser-gates.yml runs it
# on its own. TUNLION_TEST_SERVER points it at a running backend instead of
# starting one.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/debug/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT="${KD_PORT:-8189}"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="${KD_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/wt-known.XXXXXX")}"; mkdir -p "$WORK"
export TUNLION_NONINTERACTIVE=1

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

[ -d "$HERE/node_modules/playwright" ] || { echo "REFUSED: no playwright in $HERE (npm ci there, then npx playwright install chromium)"; exit 3; }
FRONT="$CLI_DIR/../frontend"
[ -f "$FRONT/dist/index.html" ] || { echo "REFUSED: no frontend/dist (VITE_TUNLION_API= npm run build in frontend/)"; exit 3; }
if grep -qs "api\.tunlion\.autumated\.com" "$FRONT"/dist/assets/*.js; then
  echo "REFUSED: frontend/dist signals to production; rebuild it same-origin (VITE_TUNLION_API= npm run build)"; exit 3
fi
if [ -n "${TUNLION_TEST_SERVER:-}" ]; then
  SERVER="$TUNLION_TEST_SERVER"
  curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; exit 2; }
else
  SERVER="http://127.0.0.1:$PORT"
  start_backend
fi

CODE_WORD="gigantic-element"
wait_code() {
  local log="$1" code="" i
  for i in $(seq 1 60); do
    code=$(grep -oiE "$CODE_WORD-[0-9]{3,5}" "$log" | head -1 | tr 'A-Z' 'a-z')
    [ -n "$code" ] && { echo "$code"; return 0; }
    sleep 0.3
  done
  return 1
}

SMALL="$WORK/small.bin"; head -c $((1024 * 1024)) /dev/urandom > "$SMALL"
C16="$WORK/g16cfg"; mkdir -p "$C16"
say "16: known-device rendezvous + remember consent (C12/C20/C27 web)"
G16=0
# Phase 1 sender: mints the code (a 2-word phrase + machine nameplate) and
# offers a pair-keep secret, which the browser must NOT store until the human
# clicks Remember (C27).
TUNLION_CONFIG_DIR="$C16" timeout 150 "$BIN" send "$SMALL" --word "$CODE_WORD" --remember pwdev --server "$SERVER" >"$WORK/g16-s1.log" 2>&1 &
S16=$!; FIX_PIDS+=($S16)
W16=$(wait_code "$WORK/g16-s1.log") || { echo "no code minted"; tail -n 5 "$WORK/g16-s1.log"; exit 1; }
# Phase 3's decline sender starts later; the harness polls its log for the code.
( cd "$HERE" && node known-device.js "$SERVER" "$W16" "@$WORK/g16-s3.log" >"$WORK/g16-pw.log" 2>&1 ) &
PW16=$!; FIX_PIDS+=($PW16)
wait $S16 || { echo "phase 1 sender exited $?"; G16=1; }
# Phase 2: fresh session, ISOLATED room, no code. Only the secret-derived
# channel can find the browser; the same config dir holds 'pwdev'.
env ${KD_DEBUG:+TUNLION_LOG=debug} TUNLION_CONFIG_DIR="$C16" timeout 120 "$BIN" send "$SMALL" --to pwdev --room "g16iso$$" --server "$SERVER" >"$WORK/g16-s2.log" 2>&1 || { echo "phase 2 sender exited $?"; G16=1; }
# Phase 3 (C27 decline): the browser clicks Not now; the ack must make this
# sender DISCARD its stored half.
TUNLION_CONFIG_DIR="$C16" timeout 60 "$BIN" send "$SMALL" --word "$CODE_WORD" --remember declinedev --server "$SERVER" >"$WORK/g16-s3.log" 2>&1 &
S16B=$!; FIX_PIDS+=($S16B)
wait $PW16 || { echo "browser harness exited $?"; G16=1; }
kill $S16B 2>/dev/null; wait $S16B 2>/dev/null
cat "$WORK/g16-pw.log"
if [ $G16 -eq 0 ] && grep -q "SECRET STORED" "$WORK/g16-pw.log" \
   && grep -q "PHASE2 COMPLETE" "$WORK/g16-pw.log" \
   && grep -q "PHASE3 DECLINED" "$WORK/g16-pw.log" \
   && grep -q "declined to be remembered" "$WORK/g16-s3.log" \
   && ! grep -rq "declinedev" "$C16"; then
  ok "consent-gated store; --to found it cross-room as the one known device; decline purged the sender's half"
else
  bad "known-device"; tail -n 6 "$WORK/g16-s1.log" "$WORK/g16-s2.log" "$WORK/g16-s3.log"
fi
echo
echo "== known-device gate: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
