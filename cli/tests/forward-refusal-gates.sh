#!/usr/bin/env bash
# #232/#268: what `forward` tells the user when the peer says no.
#
#   FILAMENT_BIN=/path/to/filament ./forward-refusal-gates.sh
#
# This gate exists because there was none. Every other gate in this directory is
# a same-host fixture, and a same-host fixture cannot produce the state that
# broke: a peer whose L2 acceptor is OFF. #268 was found by hand across two
# machines over a WAN, and nothing in CI would have caught it or would catch its
# return. The acceptor here runs with L2 genuinely disabled, in its own config
# dir, which reproduces that state on one host.
#
# Gates:
#   A  a forward to an acceptor with L2 OFF fails FAST, it does not hang   (#268)
#   B  and the user is told the peer refused, with a reason                (#232)
#   C  the accept-time line does not claim the peer forwarded anything     (#232)
#   D  with L2 ON and a live target, the same forward still works          (control)
#
# D is the control that matters. A, B and C could all be satisfied by a build
# that refuses everything, which would "pass" while destroying the feature.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# The default path is a trap on this box: ~/.cargo/config.toml sets a SHARED
# `target-dir = /root/.cargo-target`, so `cargo build` does NOT write to
# cli/target/release. Running the gate without FILAMENT_BIN silently picked up a
# three-day-old binary and failed every assertion for reasons that had nothing
# to do with the code under test. Prefer the shared dir when it holds a newer
# build, and say which one was chosen.
_default_bin() {
    local a="$CLI_DIR/target/release/filament"
    local b="/root/.cargo-target/release/filament"
    if [ -x "$b" ] && { [ ! -x "$a" ] || [ "$b" -nt "$a" ]; }; then echo "$b"; else echo "$a"; fi
}
BIN="${FILAMENT_BIN:-$(_default_bin)}"
PORT=8116
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-fwd-refusal.XXXXXX")"
DA="$WORK/A"
# The bound that separates "refused" from "hung". #268 hung until curl's own
# timeout at 25s; a refusal lands in single digits.
FAST=12

source "$HERE/lib/fixture.sh"
trap 'fixture_cleanup; pkill -f "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT

[ -x "$BIN" ] || { echo "no filament binary at $BIN; build first"; exit 2; }
echo "## binary under test: $BIN"
"$BIN" --version | sed 's/^/##   /'

start_backend
init_owner "$DA"

BDIR="$WORK/bravo"
# There is no `forward` capability: the canonical set is shell/transfer/mount,
# and the L2 acceptor gates an l2-open on `trusted` alone (see the TODO(L1-a
# caps) in l2.rs). Asking for one made `add --for` fail, and enroll_delegate
# sends its errors to /dev/null, so setup failed silently and every later gate
# measured a forward that never started.
# Alpha must be SERVING for a join to complete: `add --for` says so itself
# ("the always-on receiver is not running; start `filament up` before anyone
# claims this invitation"). Omitting it is why the first run of this gate could
# not enrol bravo at all.
start_acceptor "$DA"
enroll_delegate bravo --allow transfer,mount

# ...and then stop it, deliberately. With a local daemon up, `forward` takes the
# WARM path (ctl::try_open bridges through the daemon) instead of the cold one,
# and the refusal reporting under test lives in serve_cold_connection. Leaving
# the daemon running would exercise a different path from the one being
# asserted, which is exactly the warm/cold confound that briefly made an earlier
# A/B look like a fix. Stop it so the path is the one named in the assertions.
env FILAMENT_CONFIG_DIR="$DA" "$BIN" down >/dev/null 2>&1
sleep 2

# Assert the precondition rather than discovering it three gates later. Without
# this, gateA "passed" in 0.0s with curl rc=7, connection refused because
# nothing was listening, which is indistinguishable in the assertion from a
# fast, correct refusal by the peer.
if ! env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q bravo; then
  echo "setup failed: bravo did not enrol, so nothing below would prove anything"
  sed 's/^/    /' "$WORK/bravo-join.log" 2>/dev/null | tail -5
  exit 2
fi

# $1 = "on"|"off" (L2 on the acceptor), starts bravo's daemon in its own dir
ACCEPTOR_PID=""
start_acceptor_l2() {
  # Kill the PREVIOUS acceptor by pid. `pkill -f FILAMENT_CONFIG_DIR=...` matched
  # nothing: `env VAR=v prog` execs prog, so the assignment is in the
  # environment and never in argv. The old daemon survived, the second `up`
  # found its pidfile and printed "daemon already running; following its log"
  # instead of serving, and the control could never run.
  if [ -n "$ACCEPTOR_PID" ]; then
    kill "$ACCEPTOR_PID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$ACCEPTOR_PID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$ACCEPTOR_PID" 2>/dev/null
  fi
  env FILAMENT_CONFIG_DIR="$BDIR" "$BIN" down >/dev/null 2>&1
  sleep 2
  if [ "$1" = on ]; then
    env FILAMENT_CONFIG_DIR="$BDIR" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/bdrop" \
      >"$WORK/up-$1.log" 2>&1 &
  else
    # No FILAMENT_L2, no --shell: l2_enabled is false. This is the #268 state.
    env FILAMENT_CONFIG_DIR="$BDIR" "$BIN" --server "$SERVER" up --dir "$WORK/bdrop" \
      >"$WORK/up-$1.log" 2>&1 &
  fi
  ACCEPTOR_PID=$!
  FIX_PIDS+=($ACCEPTOR_PID)
  sleep 6
  # "daemon already running ... following its log" is NOT serving, so match the
  # banner a real acceptor prints and reject the follow-mode message explicitly.
  if grep -qs 'already running' "$WORK/up-$1.log" || ! grep -qs 'filament up,' "$WORK/up-$1.log"; then
    echo "acceptor ($1) did not start:"; sed 's/^/    /' "$WORK/up-$1.log" | tail -5; exit 2
  fi
}

# $1 = local port, $2 = remote port. Leaves the log in $WORK/fwd-$1.log.
run_forward() {
  local lport="$1" rport="$2"
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" forward "bravo:$rport" --lport "$lport" \
    >"$WORK/fwd-$lport.log" 2>&1 &
  echo $! >"$WORK/fwd.pid"
  FIX_PIDS+=($!)
  sleep 6
  # The forward must actually be listening before the client speaks, or curl's
  # ECONNREFUSED reads exactly like a fast refusal from the peer and every
  # assertion below becomes a coin flip. Same reason the cross-machine rig
  # aborts when the acceptor fails to come up.
  if ! grep -qsE 'ready|listening on' "$WORK/fwd-$lport.log"; then
    echo "## forward did not start listening:"; sed 's/^/    /' "$WORK/fwd-$lport.log" | tail -5
    FORWARD_UP=0
    return
  fi
  FORWARD_UP=1
  local t0 t1
  t0=$(date +%s.%N)
  timeout "$FAST" curl -s -o /dev/null "http://127.0.0.1:$lport/" >/dev/null 2>&1
  CURL_RC=$?
  t1=$(date +%s.%N)
  ELAPSED=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
  sleep 2
  kill "$(cat "$WORK/fwd.pid")" 2>/dev/null
}

# ------------------------------------------------------------ gates A, B, C
say "forward-refusal gates A/B/C: acceptor with L2 OFF"
start_acceptor_l2 off
run_forward 39801 39999
fwd=$(tr -d '\r' <"$WORK/fwd-39801.log" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g')
echo "## forward said:"; printf '%s\n' "$fwd" | grep -avE '^\s*$' | sed 's/^/   /' | tail -6
echo "## curl rc=$CURL_RC after ${ELAPSED}s (rc=124 is the timeout, i.e. a hang)"

if [ "${FORWARD_UP:-0}" -ne 1 ]; then
  bad "gateA: the forward never listened, so this case measured nothing"
elif [ "$CURL_RC" -eq 124 ]; then
  bad "gateA: the client hung for the full ${FAST}s instead of being refused (#268)"
else
  ok "gateA: refused in ${ELAPSED}s, no hang"
fi

if printf '%s\n' "$fwd" | grep -qi 'refused the connection'; then
  ok "gateB: the refusal reached the user with a reason"
else
  bad "gateB: the peer refused and the forward never said so (#232)"
fi

if printf '%s\n' "$fwd" | grep -q 'first connection forwarded'; then
  bad "gateC: still claims the peer FORWARDED it, at accept time (#232)"
else
  ok "gateC: no false success claim at accept time"
fi

# ---------------------------------------------------------------- gate D
say "forward-refusal gate D: acceptor with L2 ON and a live target (control)"
start_acceptor_l2 on
# A real target on the acceptor side, so a working forward has something to serve.
( cd "$WORK" && $PYV -m http.server 39777 >/dev/null 2>&1 & echo $! >"$WORK/http.pid" )
FIX_PIDS+=($(cat "$WORK/http.pid"))
sleep 2
run_forward 39802 39777
fwd2=$(tr -d '\r' <"$WORK/fwd-39802.log" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g')
echo "## curl rc=$CURL_RC after ${ELAPSED}s"
if [ "${FORWARD_UP:-0}" -ne 1 ]; then
  bad "gateD: the forward never listened, so the control measured nothing"
elif [ "$CURL_RC" -eq 0 ]; then
  ok "gateD: a permitted forward to a live target still works"
else
  bad "gateD: the control failed (rc=$CURL_RC); A/B/C prove nothing if every forward is refused"
fi
if printf '%s\n' "$fwd2" | grep -qi 'refused the connection'; then
  bad "gateD2: cried refusal on a forward that should have worked"
else
  ok "gateD2: no false refusal on the working path"
fi

echo
echo "==========================================="
echo "forward-refusal gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
