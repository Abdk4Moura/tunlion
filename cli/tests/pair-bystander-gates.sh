#!/usr/bin/env bash
# Pairing with a bystander in the room: `tunlion join <code>` must pair with the
# browser that showed the code, even when another browser in the same room
# links first (see pair-bystander.js for how that order is forced).
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/pair-bystander-gates.sh
#
# Needs: the backend's Python deps, a built web app in frontend/dist, and
# Playwright's Chromium (frontend/node_modules/playwright).
#
# Gates:
#   P1 P2 P3  three rounds, each with a fresh creator page and a fresh claimer;
#             in every round the CLI's first link is the bystander (asserted),
#             and the pairing still completes with the creator on both sides.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8193
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-pairby.XXXXXX")"
export TUNLION_NONINTERACTIVE=1

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

[ -f "$CLI_DIR/../frontend/dist/index.html" ] || { echo "build the web app first: (cd frontend && VITE_TUNLION_API= npm run build)"; exit 2; }
start_backend

node "$HERE/pair-bystander.js" "$SERVER/" "$BIN" "$SERVER" "$WORK" 3
rc=$?
[ $rc -eq 0 ] || { echo "--- backend log tail"; tail -n 20 "$WORK/backend.log"; }
exit $rc
