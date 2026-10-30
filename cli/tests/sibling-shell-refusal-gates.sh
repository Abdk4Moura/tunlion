#!/usr/bin/env bash
# A fleet sibling asking for a shell it was never granted is REFUSED, fast and
# by name, instead of timing out as "can't reach". Standalone, hermetic,
# fixture port 8127.
#
#   TUNLION_BIN=/path/to/tunlion ./sibling-shell-refusal-gates.sh
#
# Owner report: a fleet sibling (Windows, so no daemon control socket and no
# brokered rendezvous) ran `tunlion shell ci-worker-N` against a CI worker
# serving `up --userspace --shell-only <owner>`, saw "waiting for known
# device..." and then "can't reach ... couldn't establish a link in 45s",
# although the worker was online.
#
# Topology, every node with its own HOME and config dir:
#
#   alpha    owner (`tunlion init`), its own acceptor
#   bravo    enrolled device, the dialing sibling
#   charlie  enrolled device, serving `up --userspace --shell-only alpha`
#
# Gates:
#   B   brokered: bravo's daemon is reachable, so the dial meets charlie on a
#       private brokered rendezvous; shell is refused within the bound, names
#       the refusal, and prints the grant command
#   W   Windows-shaped: bravo's control socket is hidden (the daemon keeps
#       running, as on Windows), so the dial falls back to the fleet secret
#       and meets every fleet device on the shared channel; same expectations,
#       repeated because which device answers first is a race
#   G   no authorization was weakened: no attempt produced a shell, and after
#       charlie grants bravo shell (`tunlion grant bravo shell`, the printed
#       command) bravo's shell runs, brokered and over the fleet secret
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=${PORT:-8127}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-sibshell.XXXXXX")"
DA="$WORK/alpha"
# A refusal arrives in milliseconds once the link is up; the link itself takes
# a few seconds. Well under the 45 s connect timeout the bug produced.
REFUSE_SECS=${REFUSE_SECS:-20}

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in alpha bravo charlie; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

as_node() {
  local n="$1"; shift
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" "$BIN" --server "$SERVER" "$@"
}
wait_log() {
  local i
  for i in $(seq 1 $(( $3 * 2 ))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.5; done
  return 1
}

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo
enroll_delegate charlie --allow transfer,shell

say "setup: bravo plain up, charlie up --userspace --shell-only alpha"
env HOME="$WORK/home-bravo" TUNLION_CONFIG_DIR="$WORK/bravo" TUNLION_LOG=debug \
  "$BIN" --server "$SERVER" up --dir "$WORK/bravo-drop" >"$WORK/up-bravo.log" 2>&1 &
FIX_PIDS+=($!)
env HOME="$WORK/home-charlie" TUNLION_CONFIG_DIR="$WORK/charlie" TUNLION_LOG=debug \
  "$BIN" --server "$SERVER" up --userspace --dir "$WORK/charlie-drop" \
  --shell-only alpha --i-know --no-interactive >"$WORK/up-charlie.log" 2>&1 &
FIX_PIDS+=($!)
wait_log "$WORK/up-bravo.log" "fleet device 'charlie' joined the mesh" 60 \
  || fixture_die "setup: bravo never admitted charlie: $(grep -iE 'fleet|roster' "$WORK/up-bravo.log" | tail -5)"
wait_log "$WORK/up-charlie.log" "fleet device 'bravo' joined the mesh" 30 \
  || fixture_die "setup: charlie never admitted bravo"

# Shell, non-interactive (stdin not a tty): `-- echo` runs one command.
try_shell() { # try_shell TAG MARK
  local t0 t1
  t0=$(date +%s)
  fs_cli 60 env TUNLION_CONNECT_SECS=45 ${SHELL_LOG:+TUNLION_LOG="$SHELL_LOG"} HOME="$WORK/home-bravo" TUNLION_CONFIG_DIR="$WORK/bravo" \
    "$BIN" --server "$SERVER" shell charlie -- echo "$2" </dev/null
  t1=$(date +%s)
  echo $(( t1 - t0 )) > "$WORK/$1.secs"
  fs_out > "$WORK/$1.out"
}
assert_refused() { # assert_refused TAG MARK
  local secs out
  secs=$(cat "$WORK/$1.secs"); out="$WORK/$1.out"
  if grep -q "$2" "$out"; then bad "gate$1-1: an ungranted sibling got a shell"; return; fi
  if [ "$(fs_rc)" != 0 ] && [ "$secs" -le "$REFUSE_SECS" ] && ! grep -q "can't reach" "$out"; then
    ok "gate$1-1: refused in ${secs}s, not reported as unreachable"
  else bad "gate$1-1: rc=$(fs_rc) after ${secs}s: $(tail -4 "$out" | tr '\n' ' ')"; fi
  if grep -q "tunlion grant bravo shell" "$out"; then ok "gate$1-2: names the exact grant command"
  else bad "gate$1-2: no 'tunlion grant bravo shell' hint: $(tail -4 "$out" | tr '\n' ' ')"; fi
}

say "B: brokered dial (bravo's daemon answers its control socket)"
try_shell B SHELL-MARK-B
assert_refused B SHELL-MARK-B

# Which fleet device answers the fleet channel first is a race (the owner's
# daemon and the dialer's own daemon sit on it too), so one attempt can pass by
# luck. Several attempts, each asserted.
W_REPS=${W_REPS:-4}
hide_sock() { [ -S "$WORK/bravo/control.sock" ] && mv "$WORK/bravo/control.sock" "$WORK/bravo-control.sock.hidden"; }
show_sock() { [ -S "$WORK/bravo-control.sock.hidden" ] && mv "$WORK/bravo-control.sock.hidden" "$WORK/bravo/control.sock"; }

say "W: Windows-shaped dial (no control socket: fleet-secret fallback), x$W_REPS"
hide_sock
for i in $(seq 1 "$W_REPS"); do try_shell "W$i" SHELL-MARK-W; assert_refused "W$i" SHELL-MARK-W; done
show_sock

say "G: the refusal is the grant decision, not a broken link"
as_node charlie grant bravo shell >/dev/null 2>&1 || bad "gateG-setup: charlie could not grant bravo shell"
sleep 2
try_shell G SHELL-MARK-G
if [ "$(fs_rc)" = 0 ] && grep -q SHELL-MARK-G "$WORK/G.out"; then ok "gateG1: shell runs once charlie granted it"
else bad "gateG1: granted shell rc=$(fs_rc): $(tail -4 "$WORK/G.out" | tr '\n' ' ')"; fi
hide_sock
for i in $(seq 1 "$W_REPS"); do
  try_shell "GW$i" SHELL-MARK-GW
  if [ "$(fs_rc)" = 0 ] && grep -q SHELL-MARK-GW "$WORK/GW$i.out"; then ok "gateGW$i: granted shell over the fleet-secret dial"
  else bad "gateGW$i: granted fleet-secret shell rc=$(fs_rc): $(tail -4 "$WORK/GW$i.out" | tr '\n' ' ')"; fi
done
show_sock

declare_known_red_summary
echo
echo "sibling-shell-refusal: $PASS passed, $FAIL failed${FAILED:+ ($FAILED )}"
echo "work dir: $WORK"
[ "$FAIL" = 0 ]
