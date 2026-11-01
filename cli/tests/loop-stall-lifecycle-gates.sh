#!/usr/bin/env bash
# End-to-end vouch (introduce_cmd) over an off-loop build. The command knows
# both devices, opens/uses verified links, and must not rely on a caller tick.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/measure/tunlion}"
PORT=${PORT:-8144}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-vouch.XXXXXX")"
DA="$WORK/alpha"
source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in alpha bravo charlie; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

up_node() {
  local n="$1"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" \
    TUNLION_L2=1 TUNLION_LOG=debug \
    "$BIN" --server "$SERVER" up --dir "$WORK/$n-drop" >"$WORK/up-$n.log" 2>&1 &
  FIX_PIDS+=($!)
}

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo
enroll_delegate charlie
for n in bravo charlie; do up_node "$n"; done

joined=0
for _ in $(seq 1 240); do
  if [ "$(grep -l "joined the mesh" "$WORK"/up-*.log 2>/dev/null | wc -l)" -ge 2 ]; then joined=1; break; fi
  sleep 0.5
done
[ "$joined" = 1 ] || fixture_die "fleet links did not form for vouch"

# Enrollment needs the owner daemon; the vouch command must be the only process
# using the owner identity, or the daemon and CLI glare on the same channels.
pid=$(pgrep -f "$WORK/Adrop" | head -1)
[ -n "$pid" ] && kill -TERM "$pid"
for _ in $(seq 1 40); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done

out=$(fs_bounded 90 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" \
  "$BIN" --server "$SERVER" devices vouch bravo charlie -y --no-interactive 2>&1)
state=$(fs_state)
echo "$out" | tail -8
[ "$state" = ok ] && ok "vouch completed through the off-loop links" \
  || bad "vouch did not complete (state=$state)"
case "$out" in
  *"vouched to"*) ok "vouch reported delivery to both devices" ;;
  *) bad "vouch produced no delivery line" ;;
esac

declare_known_red_summary
[ "$FAIL" -eq 0 ]
