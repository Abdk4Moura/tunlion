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
#   C  following those steps, the device runs `exec` on the owner (rc=0, exact)
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
       "tunlion join --invite-file $DEV-invite.txt --name $DEV" )
missing=""
for n in "${need[@]}"; do echo "$OUTB" | grep -qF -- "$n" || missing="$missing [$n]"; done
ALLOW=$(echo "$OUTB" | grep -oE "add --for $DEV --allow [^ ]+" | head -1 | awk '{print $NF}')
if [ "$rcB" != "0" ] && [ -z "$missing" ] && echo "$ALLOW" | grep -q shell; then
  ok "gateB: grant refuses and prints the full re-enrolment (allow: $ALLOW)"
else
  bad "gateB: grant advice incomplete (rc=$rcB, missing:$missing)"
fi

# ===================================================================== GATE C ==
say "C: the printed steps work"
cd "$WORK" || exit 2
# On the owner, exactly as printed (plus --yes: no terminal to confirm on).
"${A_ENV[@]}" "$BIN" --server "$SERVER" devices forget "$DEV" >"$WORK/c-forget.log" 2>&1
rcF=$?
"${A_ENV[@]}" timeout 45 "$BIN" --server "$SERVER" add --for "$DEV" --allow "${ALLOW:-shell}" --out "$DEV-invite.txt" --yes >"$WORK/c-add.log" 2>&1
# On the device, exactly as printed.
"${D_ENV[@]}" timeout 20 "$BIN" down -y >"$WORK/c-down.log" 2>&1
sleep 1
"${D_ENV[@]}" "$BIN" reset -y >"$WORK/c-reset.log" 2>&1
"${D_ENV[@]}" timeout 45 "$BIN" --server "$SERVER" join --invite-file "$DEV-invite.txt" --name "$DEV" --no-interactive >"$WORK/c-join.log" 2>&1
rcJ=$?
# The owner indexes the re-enrolled device on its next tick.
sleep 5
OUTC=$(timeout 60 "${D_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo REENROL-OK 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (join) rc=$rcJ (exec) rc=$rcC out='$OUTC'"
# The first printed step must itself succeed, and the device must come back
# under its own name. This gate used to ignore the forget's exit code, so it
# stayed green while `forget` refused (a live certificate) and the re-enrolled
# device was quietly filed as "$DEV-2" beside its stale record.
NAMES=$("${A_ENV[@]}" "$BIN" devices --json 2>/dev/null | python3 -c '
import sys, json
d = json.load(sys.stdin)
if isinstance(d, dict):
    d = d.get("devices") or (d.get("data") or {}).get("devices") or []
print(" ".join(sorted(x["name"] for x in d)))' 2>/dev/null)
echo "## (forget) rc=$rcF; owner devices after re-enrolment: [$NAMES]"
if [ "$rcF" = "0" ] && echo " $NAMES " | grep -q " $DEV " && ! echo " $NAMES " | grep -q " $DEV-2 " \
   && [ "$rcC" = "0" ] && [ "$OUTC" = "REENROL-OK" ]; then
  ok "gateC: after the printed re-enrolment the device runs exec on its owner"
else
  for f in c-forget c-add c-down c-reset c-join; do echo "-- $f --"; tail -4 "$WORK/$f.log"; done
  echo "-- C.err --"; tail -6 "$WORK/C.err"
  bad "gateC: the printed re-enrolment did not work as printed (forget rc=$rcF devices=[$NAMES] join rc=$rcJ exec rc=$rcC)"
fi

echo
echo "==========================================="
echo "re-enrol advice gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
