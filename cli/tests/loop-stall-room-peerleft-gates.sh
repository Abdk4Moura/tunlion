#!/usr/bin/env bash
# True room-scoped peer-left coverage on a supported non-daemon topology:
# `send --room R` and `receive --room R` both join the same explicit room.
#
# The sender builds a WebRTC candidate. A test-only barrier publishes an atomic
# ready.<sid>.<generation> marker and blocks publication until the fixture
# releases it. The fixture proves the receiver leaves the room while that exact
# candidate is held, requires the sender's peer-left invalidated-build trace,
# then releases and requires observable cancellation before asserting no install
# for that generation.
#
# This is intentionally separate from the normal-daemon peerleft cell: daemons
# join distinct solo rooms and only share presence channels, so a room-scoped
# peer-left is not their departure event.
#
#   TUNLION_BIN=target/measure/tunlion TUNLION_TEST_VENV=venv/bin/python \
#     bash cli/tests/loop-stall-room-peerleft-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/measure/tunlion}"
PORT=${PORT:-8146}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-roomleft.XXXXXX")"
ROOM="roomleft-$RANDOM-$RANDOM"
BARRIER="$WORK/barrier"
BARRIER_MAX_MS=${BARRIER_MAX_MS:-120000}
RECV_PID=""
SEND_PID=""
RECV_SID=""
RECV_ROOM=""
RECV_GEN=""
READY_KEY=""
READY_GEN=""
SEND_LOG="$WORK/send.log"
RECV_LOG="$WORK/receive.log"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in sender receiver; do
  mkdir -p "$WORK/home-$n" "$WORK/$n"
done
mkdir -m 700 "$BARRIER"
export HOME="$WORK/home-sender"
printf 'room-peerleft-payload\n' > "$WORK/payload"
printf 'receiver inbox\n' > "$WORK/inbox-marker"

tel_join_since() { # offset in backend.log -> "sid room gen" for the first new join
  "$PYV" - "$WORK/backend.log" "$1" <<'PY'
import json, sys
path, start = sys.argv[1], int(sys.argv[2])
with open(path, encoding="utf-8", errors="replace") as f:
    for n, line in enumerate(f, 1):
        if n <= start or not line.startswith("TEL "):
            continue
        try:
            d = json.loads(line[4:])
        except Exception:
            continue
        if d.get("ev") == "join":
            print(d.get("sid", ""), d.get("room", ""), d.get("gen", ""))
            break
PY
}

wait_join() { # offset
  local offset="$1" line
  for _ in $(seq 1 240); do
    line=$(tel_join_since "$offset")
    if [ -n "$line" ]; then printf '%s\n' "$line"; return 0; fi
    sleep 0.25
  done
  fixture_die "setup: no backend join event appeared within 60s"
}

start_backend
init_owner "$WORK/sender"
init_owner "$WORK/receiver"
mkdir -p "$WORK/inbox"

recv_offset=$(wc -l < "$WORK/backend.log")
env HOME="$WORK/home-receiver" TUNLION_CONFIG_DIR="$WORK/receiver" \
  TUNLION_LOG=debug TUNLION_DIRECT_TEST_BLOCK=1 \
  "$BIN" --server "$SERVER" receive --room "$ROOM" --dir "$WORK/inbox" --yes --timeout 120 \
  >"$RECV_LOG" 2>&1 &
RECV_PID=$!
FIX_PIDS+=("$RECV_PID")

recv_join=$(wait_join "$recv_offset")
read -r RECV_SID RECV_ROOM RECV_GEN <<< "$recv_join"
[ -n "$RECV_SID" ] && [ -n "$RECV_ROOM" ] || fixture_die "setup: receiver join had no sid/room"
[ "$RECV_ROOM" = "$ROOM" ] || fixture_die "setup: receiver joined '$RECV_ROOM', expected '$ROOM'"

send_offset=$(wc -l < "$WORK/backend.log")
env HOME="$WORK/home-sender" TUNLION_CONFIG_DIR="$WORK/sender" \
  TUNLION_LOG=debug TUNLION_DIRECT_TEST_BLOCK=1 \
  TUNLION_TEST_BUILD_BARRIER_DIR="$BARRIER" \
  TUNLION_TEST_BUILD_BARRIER_MAX_MS="$BARRIER_MAX_MS" \
  TUNLION_TEST_BUILD_HOLD_MS=0 \
  "$BIN" --server "$SERVER" send --room "$ROOM" --timeout 0 "$WORK/payload" \
  >"$SEND_LOG" 2>&1 &
SEND_PID=$!
FIX_PIDS+=("$SEND_PID")

send_join=$(wait_join "$send_offset")
read -r send_sid send_room send_gen <<< "$send_join"
[ -n "$send_sid" ] && [ -n "$send_room" ] || fixture_die "setup: sender join had no sid/room"
[ "$send_room" = "$ROOM" ] || fixture_die "setup: sender joined '$send_room', expected '$ROOM'"
[ "$send_room" = "$RECV_ROOM" ] || fixture_die "setup: sender/receiver rooms differ ('$send_room' vs '$RECV_ROOM')"
echo "room: sender=$send_sid receiver=$RECV_SID room=$ROOM receiver_gen=$RECV_GEN"
echo "pids: send=$SEND_PID receiver=$RECV_PID"

ready=""
for _ in $(seq 1 240); do
  ready=$(find "$BARRIER" -maxdepth 1 -type f -name "ready.$RECV_SID.*" -print -quit)
  [ -n "$ready" ] && break
  sleep 0.25
done
[ -n "$ready" ] || fixture_die "setup: no pre-install ready marker for receiver sid $RECV_SID"
key=${ready##*/}
key=${key#ready.}
case "$key" in
  "$RECV_SID".*) ;;
  *) fixture_die "setup: ready marker key '$key' does not match receiver sid '$RECV_SID'" ;;
esac
READY_KEY="$key"
READY_GEN=${key#"$RECV_SID".}
[ -n "$READY_GEN" ] || fixture_die "setup: ready marker had no generation"
case "$READY_GEN" in
  ''|*[!0-9]*) fixture_die "setup: ready generation '$READY_GEN' is not numeric" ;;
esac
ready_contents=$(cat "$ready" 2>/dev/null || true)
[ "$ready_contents" = "gen=$READY_GEN" ] \
  || fixture_die "setup: ready marker content '$ready_contents' does not agree with generation $READY_GEN"
echo "held: sender=$send_sid receiver=$RECV_SID generation=$READY_GEN backend_join_gen=$RECV_GEN"
echo "note: backend TEL gen ($RECV_GEN) is the receiver's join generation, not the candidate generation ($READY_GEN)"

before=$(grep -c "ESTABLISH peer=$RECV_SID" "$SEND_LOG" 2>/dev/null || true)
before=${before:-0}
[ "$before" -eq 0 ] || fixture_die "setup: candidate installed before the pre-install barrier (ESTABLISH count=$before)"
ok "no candidate installed before the pre-install barrier"
kill -0 "$SEND_PID" 2>/dev/null \
  || fixture_die "setup: send process exited before peer-left evidence"
kill -0 "$RECV_PID" 2>/dev/null \
  || fixture_die "setup: receiver process $RECV_PID was not alive before peer-left"
ok "send/receiver processes are alive while the candidate is held"

# Terminate the recorded receiver process, not a pgrep guess.
kill -TERM "$RECV_PID" 2>/dev/null \
  || fixture_die "setup: could not terminate recorded receiver process $RECV_PID"

expected="peer-left invalidated build pid=$RECV_SID gen=$READY_GEN"
observed=0
for _ in $(seq 1 240); do
  if grep -Fq "$expected" "$SEND_LOG" 2>/dev/null; then observed=1; break; fi
  sleep 0.25
done

if [ "$observed" != 1 ]; then
  bad "room peer-left was never observed for held sid=$RECV_SID generation=$READY_GEN; release withheld"
else
  ok "observed exact room peer-left for held sid+generation: $expected"

  # Release only after the invalidation receipt. If cancellation already retired
  # the task, the release is a no-op; it must not be what causes publication.
  release="$BARRIER/release.$READY_KEY"
  release_tmp="$BARRIER/.release.$READY_KEY.$$"
  printf 'release\n' > "$release_tmp" && mv "$release_tmp" "$release" \
    && ok "released the held candidate after invalidation" \
    || bad "could not write the release marker"

  cleaned=0
  for _ in $(seq 1 240); do
    if grep -Fq "BUILD-CLEANUP-COMPLETE peer=$RECV_SID gen=$READY_GEN" "$SEND_LOG" 2>/dev/null; then
      cleaned=1
      break
    fi
    if grep -Fq "BUILD-CLEANUP-FAILED peer=$RECV_SID gen=$READY_GEN" "$SEND_LOG" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [ "$cleaned" = 1 ]; then
    ok "observed exact sid+generation cleanup-complete trace"
  elif grep -Fq "BUILD-CLEANUP-FAILED peer=$RECV_SID gen=$READY_GEN" "$SEND_LOG" 2>/dev/null; then
    bad "candidate cleanup FAILED (timeout is not quiescence)"
  else
    bad "no exact sid+generation cleanup-complete trace after peer-left"
  fi

  # A released-before-cancel path would let the candidate publish; make that a
  # named failure rather than hiding it behind a no-install assertion.
  if grep -Fq "BUILD-BARRIER-RELEASED peer=$RECV_SID gen=$READY_GEN" "$SEND_LOG" 2>/dev/null; then
    bad "barrier released the candidate despite peer-left invalidation"
  else
    ok "candidate did not reach release/publish after invalidation"
  fi

  after=$(grep -c "ESTABLISH peer=$RECV_SID" "$SEND_LOG" 2>/dev/null || true)
  after=${after:-0}
  [ "$after" -eq 0 ] && ok "no generation install after observed invalidation" \
    || bad "a generation installed after observed invalidation (ESTABLISH count=$after)"
fi

kill -0 "$SEND_PID" 2>/dev/null && ok "send process remained alive through evidence collection" \
  || bad "send process exited before evidence collection completed"

declare_known_red_summary
[ "$FAIL" -eq 0 ]
