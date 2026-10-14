#!/usr/bin/env bash
# The advice for widening a joined device's ceiling must WORK, end to end.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/reenrol-advice-gates.sh
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
#   A2 the same exec against an owner NOT serving shells advises the
#      re-enrolment too (exit 4), never `grant <dev> shell`, which the ceiling
#      refuses
#   B  `grant <dev> shell` refuses and prints the re-enrolment steps, every one
#      of them a real command: forget, add --for with shell, down, reset, join
#   C  every printed command, run VERBATIM from a script (no terminal, no flag
#      added by the gate), exits 0; then the device runs `exec` on the owner
#      (rc=0, exact) under its own name
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8132
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-reenrol.XXXXXX")"
DA="$WORK/A"
# shellcheck source=lib/fixture.sh
. "$HERE/lib/fixture.sh"
trap 'fixture_cleanup; for d in "$WORK"/delta; do TUNLION_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1; done' EXIT

DEV=delta
DD="$WORK/$DEV"
D_ENV=(env TUNLION_CONFIG_DIR="$DD")
A_ENV=(env TUNLION_CONFIG_DIR="$DA")

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

# ==================================================================== GATE A2 ==
# The same exec against an owner that is NOT serving shells (plain `up`, no
# shell grant anywhere: the blind acceptance run's state). The refusal there is
# "serving is off", whose usual remedy is `grant <dev> shell`, and for this
# device that grant is refused by the ceiling. So the advice must be the
# re-enrolment itself, never the grant that would fail.
say "A2: with shell serving off, the advice is the re-enrolment, not a grant"
OWNER_PID=$(cat "$DA/up.pid" 2>/dev/null)
kill "$OWNER_PID" 2>/dev/null
sleep 2
env TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/up-off.log" 2>&1 &
FIX_PIDS+=($!)
sleep 4
OUTA2=$(timeout 60 "${D_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/A2.err" </dev/null)
rcA2=$?
echo "## (exec, serving off) rc=$rcA2 out='$OUTA2'"; sed 's/^/    /' "$WORK/A2.err" | tail -12
if [ "$rcA2" = "4" ] && ! echo "$OUTA2" | grep -q SHOULD-NOT-RUN \
   && grep -qF "tunlion add --for $DEV --allow" "$WORK/A2.err" \
   && ! grep -q "tunlion grant" "$WORK/A2.err"; then
  ok "gateA2: serving off + shell outside the ceiling advises the re-enrolment (exit 4, no grant advice)"
else
  bad "gateA2: serving-off refusal advised a grant the ceiling refuses, or did not refuse as denied (rc=$rcA2)"
fi
kill "$(cat "$DA/up.pid" 2>/dev/null)" 2>/dev/null
sleep 2
start_acceptor "$DA"
sleep 4

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
if [ "$rcB" = "4" ] && [ -z "$missing" ] && echo "$ALLOW" | grep -q shell; then
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
# server comes from TUNLION_SERVER, the environment a user's shell provides,
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
    ( cd "$OWN_CWD" && env TUNLION_CONFIG_DIR="$DA" TUNLION_SERVER="$SERVER" \
        timeout 60 "$BIN" $args </dev/null ) >"$WORK/c-step$nsteps.log" 2>&1
  else
    ( cd "$DEV_CWD" && env HOME="$DEV_HOME" TUNLION_CONFIG_DIR="$DD" TUNLION_SERVER="$SERVER" \
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
