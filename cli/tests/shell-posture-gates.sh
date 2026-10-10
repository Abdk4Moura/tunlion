#!/usr/bin/env bash
# #244: `revoke <device> shell` must not report success while `up --shell` keeps
# handing that device a shell. The operator ran the security verb, saw a success
# line, and lost nothing.
#
#   FILAMENT_BIN=/path/to/tunlion ./shell-posture-gates.sh
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
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
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
#
# That premise was never checked: the grant's output went to /dev/null. It is
# checked now, and it FAILS: `grant` refuses a vouch-shaped record ("peer
# identity for 'vouched' is not available ... the grant requires a known user
# key to target"), so no cap was ever present and every revoke below removes a
# grant that does not exist, while still printing "revoked 'shell' from
# 'vouched'". The setup slot below records that as a tracked KNOWN-RED rather
# than letting B and C keep passing on a false premise in silence.
GRANT_OK=""
grant_shell() {
  local out rc
  out="$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" grant "$DEV" shell --yes 2>&1)"; rc=$?
  echo "## grant $DEV shell rc=$rc"
  if [ "$rc" != "0" ]; then printf '%s\n' "$out" | sed 's/^/    /'; fi
  if [ -z "$GRANT_OK" ]; then
    if [ "$rc" = "0" ]; then
      GRANT_OK=yes
      ok "setup-grant: grant $DEV shell succeeded, so the revokes below remove a cap that was present"
    else
      GRANT_OK=no
      bad "setup-grant: grant $DEV shell FAILED (rc $rc), so the revokes below remove a cap that was never granted"
    fi
  fi
}

# Tracked, not silent: the slot prints KNOWN-RED while grant refuses this record
# shape, and fails the run the moment it starts passing so the entry is removed
# with evidence (see declare_known_red_summary in lib/fixture.sh).
KNOWN_RED_ALLOW=(
  "setup-grant: grant $DEV shell succeeded|setup-grant: grant $DEV shell FAILED"
)

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
  if ! grep -qs 'tunlion up' "$WORK/up-$label.log"; then
    echo "daemon ($label) did not start:"; sed 's/^/    /' "$WORK/up-$label.log"; exit 2
  fi
}

revoke_shell_output() {
  env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke "$DEV" shell --yes 2>&1
}

CAUTION='still has shell access'
# What a successful `revoke <dev> shell` prints. Gates B and C pass on the
# ABSENCE of the caution, and a revoke that failed outright (unknown device,
# store error, usage error) prints no caution either, so without this they
# would score a crashed revoke as "no false alarm".
REVOKED="revoked 'shell' from '$DEV'"

revoke_succeeded() {  # $1 = rc, $2 = output
  [ "$1" = "0" ] && printf '%s\n' "$2" | grep -qF "$REVOKED"
}

# ---------------------------------------------------------------- gate A
# The caution must name a remedy, and the remedy must WORK: grepping for the
# words `devices forget` passed while proving nothing about whether typing it
# removes anything. So the printed command is extracted, run exactly as printed
# (only the fixture's config dir and server are supplied, as for every other
# call here), and the access it claims to remove is checked to be gone.
#
# "Gone" is checked at the record: the subject is a synthetic vouch-shaped
# record with no live peer behind it, so there is no peer to attempt a shell.
# Under `up --shell` the only thing that admits a device is its pairing record
# (the secret it authenticates with); with the record deleted there is nothing
# left to authenticate, which is the access the remedy promises to remove.
say "shell-posture gate A: up --shell is serving"
seed_vouched_record; grant_shell
start_daemon shell --shell --i-know
outA="$(revoke_shell_output)"; rcA=$?
echo "## revoke under --shell (rc $rcA):"; printf '%s\n' "$outA" | sed 's/^/   /'
remedy="$(printf '%s\n' "$outA" | grep -oE 'tunlion devices forget [^ ]+' | head -1)"
echo "## printed remedy: ${remedy:-<none>}"
if ! revoke_succeeded "$rcA" "$outA"; then
  bad "gateA: the revoke itself did not succeed (rc $rcA), so the caution is not about a revoked grant"
elif ! printf '%s\n' "$outA" | grep -q "$CAUTION"; then
  bad "gateA: revoke reported success and never said the policy still grants the shell (#244)"
elif [ "$remedy" != "tunlion devices forget $DEV" ]; then
  bad "gateA: the caution appears but its remedy is not 'tunlion devices forget $DEV' (got: ${remedy:-nothing})"
else
  # Run it as printed: drop the leading program name, keep every word after it.
  read -r -a remedy_args <<<"${remedy#tunlion }"
  outR="$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" "${remedy_args[@]}" 2>&1)"; rcR=$?
  echo "## ran remedy (rc $rcR):"; printf '%s\n' "$outR" | sed 's/^/   /'
  if [ "$rcR" != "0" ]; then
    bad "gateA: the printed remedy '$remedy' failed when typed (rc $rcR)"
  elif python3 - "$DA/devices.json" "$DEV" <<'PY'
import json, sys
try:
    devs = json.load(open(sys.argv[1]))
except FileNotFoundError:
    devs = []
sys.exit(0 if any(d.get("name") == sys.argv[2] for d in devs) else 1)
PY
  then
    bad "gateA: the remedy exited 0 but '$DEV' is still in devices.json, so its access was not removed"
  else
    ok "gateA: the caution names a remedy that runs as printed and removes the device's record"
  fi
fi
stop_daemon

# ---------------------------------------------------------------- gate B
say "shell-posture gate B: plain up is serving (no false alarm)"
seed_vouched_record; grant_shell
start_daemon plain
outB="$(revoke_shell_output)"; rcB=$?
echo "## revoke under plain up (rc $rcB):"; printf '%s\n' "$outB" | sed 's/^/   /'
if ! revoke_succeeded "$rcB" "$outB"; then
  bad "gateB: the revoke did not succeed (rc $rcB), so the absence of a caution proves nothing"
elif printf '%s\n' "$outB" | grep -q "$CAUTION"; then
  bad "gateB: cried wolf, warned about a policy that is not serving"
else
  ok "gateB: the revoke succeeded and gave no caution, the shell really is revoked"
fi
stop_daemon

# ---------------------------------------------------------------- gate C
say "shell-posture gate C: no daemon (unknown is not reassurance)"
seed_vouched_record; grant_shell
outC="$(revoke_shell_output)"; rcC=$?
echo "## revoke with no daemon (rc $rcC):"; printf '%s\n' "$outC" | sed 's/^/   /'
if ! revoke_succeeded "$rcC" "$outC"; then
  bad "gateC: the revoke did not succeed (rc $rcC), so the absence of a caution proves nothing"
elif printf '%s\n' "$outC" | grep -q "$CAUTION"; then
  bad "gateC: claimed a posture with no daemon to read it from"
else
  ok "gateC: the revoke succeeded and stayed silent when the posture cannot be known"
fi

declare_known_red_summary

echo
echo "==========================================="
echo "shell-posture gates: $PASS passed, $FAIL failed, ${#KNOWN_RED_HIT[@]} known-red${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
