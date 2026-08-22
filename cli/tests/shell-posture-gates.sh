#!/usr/bin/env bash
# #244: `revoke <device> shell` must not report success while `up --shell` keeps
# handing that device a shell. The operator ran the security verb, saw a success
# line, and lost nothing.
#
#   FILAMENT_BIN=/path/to/filament ./shell-posture-gates.sh
#
# The subject is a VOUCH-SHAPED record: a petname holding a secret with no
# certificate and no enrollment ceiling. That shape matters, and is why the test
# writes devices.json directly instead of enrolling a delegate: `revoke <dev>
# <cap>` bails early for any device that HAS a ceiling ("its access comes from
# the enrollment ceiling"), so a delegated device never reaches the code under
# test. A vouch leaves exactly this record (#243), and it is the population #244
# is about.
#
# Gates, and note two of the three are controls. The failure mode of a warning
# is crying wolf, so a gate that only proves the warning CAN appear is worth
# little:
#   A  daemon serving `up --shell`: the caution appears and names a real remedy
#   B  daemon serving plain `up`:   NO caution (the shell really is revoked)
#   C  no daemon at all:            NO caution (we do not know, so we do not say)
#
# C is the one that keeps this honest. `--shell` is a launch flag that never
# reaches the settings file, so the posture can only come from the running
# daemon. Guessing from local config would be confidently wrong in exactly the
# case that matters, and inventing a reassurance when nothing answers would
# repeat #244 one layer up.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8114
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-shell-posture.XXXXXX")"
DA="$WORK/A"
DEV=vouched

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend
init_owner "$DA"

# The vouch shape: {name, secret}, no deviceCert, no ceiling. 64 hex chars is
# what pair-intro requires of a secret.
seed_vouched_record() {
  local sec
  sec=$(printf 'a%.0s' $(seq 1 64))
  printf '[{"name":"%s","secret":"%s"}]\n' "$DEV" "$sec" > "$DA/devices.json"
}

# Re-grant before each case: a revoke clears the cap, and gate B/C must revoke a
# cap that is actually present or they would pass for the wrong reason.
grant_shell() {
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" grant "$DEV" shell --yes >/dev/null 2>&1
}

stop_daemon() {
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" down >/dev/null 2>&1
  pkill -f "FILAMENT_CONFIG_DIR=$DA" >/dev/null 2>&1
  for p in "${FIX_PIDS[@]:-}"; do
    if ps -o args= -p "$p" 2>/dev/null | grep -q ' up '; then kill "$p" 2>/dev/null; fi
  done
  sleep 2
}

# $1 = a label for the log, rest = extra `up` flags. The label is separate
# because `up-$1.log` with no arguments trips `set -u` and the daemon never
# starts, which made the no-policy control pass for the wrong reason: nothing
# was serving, so of course nothing warned.
start_daemon() {
  local label="$1"; shift
  env FILAMENT_CONFIG_DIR="$DA" FILAMENT_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/drop" "$@" \
    >"$WORK/up-$label.log" 2>&1 &
  FIX_PIDS+=($!)
  sleep 5
  # `up --shell` as root REFUSES without --shell-user/--i-know (the PTY would run
  # as the owner). A silently dead daemon is indistinguishable from a daemon that
  # simply never warns, so assert it is actually serving before testing it.
  if ! grep -qs 'filament up' "$WORK/up-$label.log"; then
    echo "daemon ($label) did not start:"; sed 's/^/    /' "$WORK/up-$label.log"; exit 2
  fi
}

revoke_shell_output() {
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke "$DEV" shell --yes 2>&1
}

CAUTION='still has shell access'

# ---------------------------------------------------------------- gate A
say "shell-posture gate A: up --shell is serving"
seed_vouched_record; grant_shell
start_daemon shell --shell --i-know
outA="$(revoke_shell_output)"
echo "## revoke under --shell:"; printf '%s\n' "$outA" | sed 's/^/   /'
if printf '%s\n' "$outA" | grep -q "$CAUTION"; then
  if printf '%s\n' "$outA" | grep -q 'devices forget'; then
    ok "gateA: the caution appears and names a remedy that removes the access"
  else
    bad "gateA: the caution appears but names no remedy"
  fi
else
  bad "gateA: revoke reported success and never said the policy still grants the shell (#244)"
fi
stop_daemon

# ---------------------------------------------------------------- gate B
say "shell-posture gate B: plain up is serving (no false alarm)"
seed_vouched_record; grant_shell
start_daemon plain
outB="$(revoke_shell_output)"
echo "## revoke under plain up:"; printf '%s\n' "$outB" | sed 's/^/   /'
if printf '%s\n' "$outB" | grep -q "$CAUTION"; then
  bad "gateB: cried wolf, warned about a policy that is not serving"
else
  ok "gateB: no caution when the shell really is revoked"
fi
stop_daemon

# ---------------------------------------------------------------- gate C
say "shell-posture gate C: no daemon (unknown is not reassurance)"
seed_vouched_record; grant_shell
outC="$(revoke_shell_output)"
echo "## revoke with no daemon:"; printf '%s\n' "$outC" | sed 's/^/   /'
if printf '%s\n' "$outC" | grep -q "$CAUTION"; then
  bad "gateC: claimed a posture with no daemon to read it from"
else
  ok "gateC: silent when the posture cannot be known"
fi

echo
echo "==========================================="
echo "shell-posture gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
