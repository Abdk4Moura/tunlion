#!/usr/bin/env bash
# Offer-first, no PeerLink, no transport-hint: a raw RTCPeerConnection joins
# the isolated fleet channel and sends the first SDP; the daemon must answer it
# and open the data channel.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/measure/tunlion}"
PORT=${PORT:-8145}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-offer.XXXXXX")"
DA="$WORK/alpha"
# Test-only: no daemon may adopt this raw sender from the server's discovery
# push. The raw client still receives known-peer to learn the daemon sid.
export TUNLION_TEST_SUPPRESS_KNOWN_PEER=1
source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()
for n in alpha bravo; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

up_node() {
  local n="$1"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" \
    TUNLION_L2=1 TUNLION_LOG=debug TUNLION_DIRECT_TEST_BLOCK=1 \
    "$BIN" --server "$SERVER" up --dir "$WORK/$n-drop" >"$WORK/up-$n.log" 2>&1 &
  FIX_PIDS+=($!)
}

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo
up_node bravo
for _ in $(seq 1 240); do
  grep -q "joined the mesh" "$WORK/up.log" "$WORK/up-bravo.log" 2>/dev/null && break
  sleep 0.5
done
[ -f "$WORK/bravo/fleet.rv" ] || fixture_die "no fixture fleet secret on bravo"
secret=$(cat "$WORK/bravo/fleet.rv")
channel=$(printf 'filament-pair:%s' "$secret" | sha256sum | cut -d' ' -f1)
unset secret

out=$(fs_bounded 40 env \
  RAW_SERVER="$SERVER" RAW_CHANNEL="$channel" RAW_UID="raw-uid-$RANDOM" \
  RAW_CHROME="${RAW_CHROME:-/usr/bin/chromium}" \
  node "$CLI_DIR/../frontend/tests/raw-offer-first.spec.cjs" 2>&1)
state=$(fs_state)
echo "$out" | tail -6
[ "$state" = ok ] && ok "raw offer-first link opened through the daemon responder" \
  || bad "raw offer-first did not open (state=$state)"
case "$out" in
  *"\"first\":\"description\""*|*"\"first\": \"description\""*) ok "the first raw signal was the SDP offer" ;;
  *) bad "the first raw signal was not the SDP offer" ;;
esac
case "$out" in
  *"transport-hint"*) bad "a transport-hint was sent" ;;
  *) ok "no transport-hint was sent" ;;
esac

declare_known_red_summary
[ "$FAIL" -eq 0 ]
