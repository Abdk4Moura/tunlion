#!/usr/bin/env bash
# The advice for widening a joined device's ceiling must WORK, end to end.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/reenrol-advice-gates.sh
#
# The dead end this closes: a device enrolled without shell could not exec on
# its owner; the refusal said `grant <dev> shell`, which fails on the invitation
# ceiling; that error said `add --for <dev> --allow shell`, whose invitation the
# joined device then rejected ("already joined an identity"). Three commands,
# none of which could work. The advice is now the full re-enrolment, and this
# gate runs exactly the commands it prints.
#
# Gates:
#   A  a device enrolled without shell is refused exec on its owner (nonzero)
#   B  `grant <dev> shell` refuses and prints the re-enrolment steps, every one
#      of them a real command: forget, add --for with shell, down, reset, join
#   C  every printed command, run VERBATIM from a script (no terminal, no flag
#      added by the gate), exits 0; then the device runs `exec` on the owner
#      (rc=0, exact) under its own name
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8132
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-reenrol.XXXXXX")"
DA="$WORK/A"
# shellcheck source=lib/fixture.sh
. "$HERE/lib/fixture.sh"
trap 'fixture_cleanup; for d in "$WORK"/delta; do FILAMENT_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1; done' EXIT

DEV=delta
DD="$WORK/$DEV"
D_ENV=(env FILAMENT_CONFIG_DIR="$DD")
A_ENV=(env FILAMENT_CONFIG_DIR="$DA")

start_backend
init_owner "$DA"
start_acceptor "$DA"
# The default ceiling (transfer, mount): no shell.
enroll_delegate "$DEV"
start_spoke "$DD" "$DEV"
sleep 4

# ===================================================================== GATE A ==
say "A: a device enrolled without shell cannot exec on its owner"
OUTA=$(timeout 60 "${D_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (exec) rc=$rcA out='$OUTA'"; sed 's/^/    /' "$WORK/A.err" | tail -8
if [ "$rcA" != "0" ] && ! echo "$OUTA" | grep -q SHOULD-NOT-RUN; then
  ok "gateA: exec outside the ceiling refused (rc=$rcA)"
else
  bad "gateA: exec outside the ceiling was not refused (rc=$rcA)"
fi

# ===================================================================== GATE B ==
say "B: grant explains the re-enrolment, with real commands"
OUTB=$("${A_ENV[@]}" "$BIN" --server "$SERVER" grant "$DEV" shell 2>&1)
rcB=$?
echo "## (grant) rc=$rcB"; echo "$OUTB" | sed 's/^/    /'
need=( "tunlion devices forget $DEV"
       "tunlion add --for $DEV --allow"
       "--out $DEV-invite.txt"
       "tunlion down"
       "tunlion reset -y"
       "tunlion join --invite-file $DEV-invite.txt --name $DEV"
       "tunlion up --detach" )
missing=""
for n in "${need[@]}"; do echo "$OUTB" | grep -qF -- "$n" || missing="$missing [$n]"; done
ALLOW=$(echo "$OUTB" | grep -oE "add --for $DEV --allow [^ ]+" | head -1 | awk '{print $NF}')
if [ "$rcB" != "0" ] && [ -z "$missing" ] && echo "$ALLOW" | grep -q shell; then
  ok "gateB: grant refuses and prints the full re-enrolment (allow: $ALLOW)"
else
  bad "gateB: grant advice incomplete (rc=$rcB, missing:$missing)"
fi

# ===================================================================== GATE C ==
say "C: the printed steps work, run EXACTLY as printed from a script"
# Each command line of the advice is executed verbatim: no flag added here, no
# terminal (stdin is /dev/null), each on the machine its `on X:` label names,
# each from its own working directory so the invitation really has to be
# carried across by the one non-command line, "(copy <file> to <dev>)". The
# server comes from FILAMENT_SERVER, the environment a user's shell provides,
# so not a word of a command is changed. This gate used to append --yes to
# `add` and -y to `down` itself, which is exactly why it stayed green while a
# tester running the printed text got "refusing ... without --yes".
OWN_CWD="$WORK/c-owner"; DEV_CWD="$WORK/c-device"; DEV_HOME="$WORK/c-device-home"
mkdir -p "$OWN_CWD" "$DEV_CWD" "$DEV_HOME"
printf '%s\n' "$OUTB" > "$WORK/c-recipe.txt"
: > "$WORK/c-steps.log"
side=""; nsteps=0; failed_step=""
while IFS= read -r line; do
  case "$line" in
    *"on alpha:"*) side=owner ;;
    *"on $DEV:"*)  side=device ;;
  esac
  if [[ "$line" =~ \(copy[[:space:]]+([^[:space:]]+)[[:space:]]+to ]]; then
    cp "$OWN_CWD/${BASH_REMATCH[1]}" "$DEV_CWD/" 2>>"$WORK/c-steps.log" \
      || { failed_step="${failed_step:-copy ${BASH_REMATCH[1]}}"; }
    continue
  fi
  [[ "$line" =~ ^[[:space:]]*(on[^:]*:)?[[:space:]]*tunlion[[:space:]](.*)$ ]] || continue
  args="${BASH_REMATCH[2]}"
  nsteps=$((nsteps+1))
  if [ "$side" = owner ]; then
    ( cd "$OWN_CWD" && env FILAMENT_CONFIG_DIR="$DA" FILAMENT_SERVER="$SERVER" \
        timeout 60 "$BIN" $args </dev/null ) >"$WORK/c-step$nsteps.log" 2>&1
  else
    ( cd "$DEV_CWD" && env HOME="$DEV_HOME" FILAMENT_CONFIG_DIR="$DD" FILAMENT_SERVER="$SERVER" \
        timeout 60 "$BIN" $args </dev/null ) >"$WORK/c-step$nsteps.log" 2>&1
  fi
  rc=$?
  echo "[$side] tunlion $args -> rc=$rc" | tee -a "$WORK/c-steps.log"
  [ "$rc" = "0" ] || { failed_step="${failed_step:-tunlion $args (rc=$rc)}"; tail -4 "$WORK/c-step$nsteps.log" | sed 's/^/      /'; }
done < "$WORK/c-recipe.txt"
# The owner indexes the re-enrolled device on its next tick.
sleep 5
OUTC=$(timeout 60 "${D_ENV[@]}" HOME="$DEV_HOME" "$BIN" --server "$SERVER" exec alpha -- /bin/echo REENROL-OK 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## steps run: $nsteps; first failure: ${failed_step:-none}; (exec) rc=$rcC out='$OUTC'"
# The device must come back under its own name: the forget at the top of the
# advice frees it, and a re-enrolled device filed as "$DEV-2" beside its stale
# record is the advice not working.
NAMES=$("${A_ENV[@]}" "$BIN" devices --json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
if isinstance(d, dict):
    d = d.get("devices") or (d.get("data") or {}).get("devices") or []
print(" ".join(sorted(x["name"] for x in d)))' 2>/dev/null)
echo "## owner devices after re-enrolment: [$NAMES]"
if [ -z "$failed_step" ] && [ "$nsteps" -ge 6 ] \
   && echo " $NAMES " | grep -q " $DEV " && ! echo " $NAMES " | grep -q " $DEV-2 " \
   && [ "$rcC" = "0" ] && [ "$OUTC" = "REENROL-OK" ]; then
  ok "gateC: every printed step ran as printed (rc=0 each, $nsteps steps) and the device runs exec on its owner"
else
  echo "-- C.err --"; tail -6 "$WORK/C.err"
  bad "gateC: the printed re-enrolment did not work as printed (first failure: ${failed_step:-none}, steps=$nsteps, devices=[$NAMES], exec rc=$rcC)"
fi

echo
echo "==========================================="
echo "re-enrol advice gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
