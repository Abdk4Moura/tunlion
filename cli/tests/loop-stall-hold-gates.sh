#!/usr/bin/env bash
# Live publication race: hold an actual built WebRTC candidate, invalidate the
# peer while it is held, then release it. A candidate must not install after a
# forget, and the daemon must still answer.
#
#   TUNLION_BIN=target/measure/tunlion TUNLION_TEST_VENV=venv/bin/python \
#     bash cli/tests/loop-stall-hold-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/measure/tunlion}"
PORT=${PORT:-8143}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-hold.XXXXXX")"
DA="$WORK/alpha"
HOLD_MS=${HOLD_MS:-8000}
ACTION=${ACTION:-forget}
DELAY_MS=""
[ "$ACTION" = "peerleft" ] && DELAY_MS="$HOLD_MS"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()
for n in alpha bravo; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

up_with_hold() { # dir log extra env...
  local dir="$1" log="$2"; shift 2
  env HOME="$WORK/home-$(basename "$dir")" TUNLION_CONFIG_DIR="$dir" \
    TUNLION_L2=1 TUNLION_LOG=debug \
    TUNLION_DIRECT_TEST_BLOCK=1 \
    TUNLION_TEST_BUILD_HOLD_MS="$HOLD_MS" \
    TUNLION_TEST_ESTABLISH_DELAY_MS="${DELAY_MS:-}" \
    "$@" \
    "$BIN" --server "$SERVER" up --dir "$WORK/$(basename "$dir")-drop" >"$log" 2>&1 &
  FIX_PIDS+=($!)
}

start_backend
init_owner "$DA"
# Owner acceptor, also holding its candidate.
up_with_hold "$DA" "$WORK/up.log"
sleep 2
enroll_delegate bravo
up_with_hold "$WORK/bravo" "$WORK/up-bravo.log"

# Wait for a candidate to actually be built and held.
held=0
marker="BUILD-HOLD"
[ "$ACTION" = "peerleft" ] && marker="BUILD-DELAY"
for _ in $(seq 1 80); do
  if grep -q "$marker" "$WORK/up.log" "$WORK/up-bravo.log" 2>/dev/null; then held=1; break; fi
  sleep 0.5
done
[ "$held" = 1 ] || fixture_die "no build reached the $marker point"

held_pid=$(grep -m1 -oP "$marker peer=\K[^ ]+" "$WORK/up.log" "$WORK/up-bravo.log" 2>/dev/null | head -1 | sed 's/^[^:]*://')
[ -n "$held_pid" ] || fixture_die "BUILD-HOLD had no peer id"
before_alpha=$(grep -c "tunlion: ESTABLISH peer=$held_pid" "$WORK/up.log" 2>/dev/null || true)
before_bravo=$(grep -c "tunlion: ESTABLISH peer=$held_pid" "$WORK/up-bravo.log" 2>/dev/null || true)
echo "held: pid=$held_pid alpha_establish_before=$before_alpha bravo_establish_before=$before_bravo"

# Invalidate the peer while its candidate is held.
case "$ACTION" in
  forget)
    out=$(fs_bounded 20 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" "$BIN" devices forget bravo -y 2>&1)
    state=$(fs_state)
    [ "$state" = ok ] || echo "forget state=$state out=$out"
    ;;
  peerleft)
    pid=$(pgrep -f "$WORK/bravo-drop" | head -1)
    [ -n "$pid" ] && kill -TERM "$pid" || echo "no bravo pid for peer-left"
    observed=0
    for _ in $(seq 1 80); do
      if grep -q "peer-left invalidated build pid=$held_pid" "$WORK/up.log" 2>/dev/null; then observed=1; break; fi
      sleep 0.25
    done
    [ "$observed" = 1 ] && ok "observed peer-left for held pid $held_pid with generation" \
      || bad "peer-left was never observed for held pid $held_pid"
    ;;
  shutdown)
    fs_bounded 20 env HOME="$WORK/home-bravo" TUNLION_CONFIG_DIR="$WORK/bravo" "$BIN" down -y >/dev/null 2>&1 || true
    ;;
  demote)
    out=$(fs_bounded 25 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" "$BIN" demote bravo --to cut -y --no-interactive 2>&1)
    state=$(fs_state)
    [ "$state" = ok ] || echo "demote state=$state out=$out"
    ;;
  *) echo "unknown ACTION=$ACTION"; exit 2 ;;
esac
sleep $(( HOLD_MS / 1000 + 6 ))

after_alpha=$(grep -c "tunlion: ESTABLISH peer=$held_pid" "$WORK/up.log" 2>/dev/null || true)
after_bravo=$(grep -c "tunlion: ESTABLISH peer=$held_pid" "$WORK/up-bravo.log" 2>/dev/null || true)
echo "released: alpha_establish_after=$after_alpha bravo_establish_after=$after_bravo"

# The owner must not publish a new link for the forgotten peer, and it must
# still answer its control socket.
[ "$after_alpha" -le "$before_alpha" ] && ok "$ACTION held: no candidate installed after invalidation" \
  || bad "a held candidate installed after $ACTION (alpha)"
timeout 3 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" "$BIN" status --json >/dev/null 2>&1 \
  && ok "owner still answers after the held-build forget" \
  || bad "owner stopped answering after the held-build forget"

declare_known_red_summary
[ "$FAIL" -eq 0 ]
