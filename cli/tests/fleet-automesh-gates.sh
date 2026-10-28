#!/usr/bin/env bash
# Fleet auto-mesh, live: devices certified by ONE owner key connect to each
# other with no pairing between them. Standalone, hermetic, fixture port 8125.
#
#   TUNLION_BIN=/path/to/tunlion ./fleet-automesh-gates.sh
#   CHARLIE_BIN=/path/to/tunlion-0.9.1 ...   mixed versions: charlie runs 0.9.1
#
# Topology, every node with its OWN HOME, config dir and receive dir (a shared
# inbox cannot say WHICH node accepted a file, and once produced a false
# authorization finding):
#
#   alpha    owner (`tunlion init`)
#   bravo    joined device  (add --for bravo   / join --invite-file)
#   charlie  joined device  (add --for charlie / join --invite-file)
#   dave     uncertified: paired with bravo by an ordinary code, no identity
#
# bravo and charlie never exchange a code, an invitation or a secret.
#
# Gates:
#   E   enrolment: bravo and charlie hold certificates chained to alpha
#   M   mesh: bravo and charlie meet on the fleet channel, admitted on their
#       certificates; neither holds a pair secret for the other
#   R   reach: `reach` works between the siblings, both directions
#   S   shell: refused without a grant on the target, works with one
#   T   transfer: refused without a grant (nothing lands ANYWHERE), lands at
#       the named device only with one; and the other direction stays refused
#   V   revocation: `devices revoke charlie` on the OWNER cuts bravo<->charlie
#       (link closed, exec refused, no file lands either way, no re-admission)
#       while bravo<->alpha keeps working (the network did not just break)
#   U   uncertified: dave gets nothing new (no fleet secret, no siblings, the
#       siblings unknown to it) and its ordinary pairing with bravo still works
#
# Mixed mode (CHARLIE_BIN set): charlie is a released 0.9.1. Its OWN policy
# decisions are 0.9.1's (it admits an ungranted sibling transfer, its `reach`
# prints the 0.9.1 line), so those two assertions are made only against the
# new binary; everything bravo decides is asserted in full, and charlie's
# daemon must still be alive and unconfused at the end.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CBIN="${CHARLIE_BIN:-$BIN}"
MIXED=0; [ "$CBIN" != "$BIN" ] && MIXED=1
PORT=${PORT:-8125}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-automesh.XXXXXX")"
DA="$WORK/alpha"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in alpha bravo charlie dave; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
# The fixture's own calls (init/add/join for the owner side) run as alpha.
export HOME="$WORK/home-alpha"

as_node() { # as_node NAME -- run tunlion as that node, with its own HOME and config
  local n="$1"; shift
  local b="$BIN"; [ "$n" = charlie ] && b="$CBIN"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" "$b" --server "$SERVER" "$@"
}
up_node() {
  local n="$1" b="$BIN"; [ "$n" = charlie ] && b="$CBIN"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" TUNLION_L2=1 TUNLION_LOG=debug \
    "$b" --server "$SERVER" up --dir "$WORK/$n-drop" >"$WORK/up-$n.log" 2>&1 &
  FIX_PIDS+=($!)
  eval "PID_$n=$!"
}
wait_log() { # wait_log FILE REGEX SECS
  local i
  for i in $(seq 1 $(( $3 * 2 ))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.5; done
  return 1
}
landed() { [ -f "$WORK/$1-drop/$2" ]; }
nowhere() { # the file landed in no node's receive dir at all
  local n
  for n in alpha bravo charlie dave; do landed "$n" "$1" && return 1; done
  [ ! -f "$WORK/Adrop/$1" ]
}

echo "bin=$BIN ($(sha256sum "$BIN" | cut -c1-16)) charlie=$CBIN ($(sha256sum "$CBIN" | cut -c1-16)) mixed=$MIXED"
"$BIN" --version; "$CBIN" --version

start_backend
init_owner "$DA"
# The owner daemon serves alpha's own drop as $WORK/Adrop (fixture).
start_acceptor "$DA"
enroll_delegate bravo
# charlie joins with ITS binary (0.9.1 in mixed mode).
out=$(fs_bounded 45 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for charlie --out "$WORK/charlie-inv.txt" --yes)
[ "$(fs_state)" = ok ] || fixture_die "setup: add --for charlie: $out"
mkdir -p "$WORK/charlie"
out=$(fs_bounded 45 as_node charlie join --invite-file "$WORK/charlie-inv.txt" --name charlie --no-interactive)
[ "$(fs_state)" = ok ] || fixture_die "setup: charlie join: $out"

say "E: enrolment"
assert_certified "$DA" "$WORK/bravo" bravo
assert_certified "$DA" "$WORK/charlie" charlie

# dave: an ordinary code pairing with bravo. No init, no certificate.
CODE_WORD=quiet-harbor
timeout 90 env HOME="$WORK/home-bravo" TUNLION_CONFIG_DIR="$WORK/bravo" "$BIN" --server "$SERVER" add --name dave --word "$CODE_WORD" </dev/null >"$WORK/dave-add.log" 2>&1 &
PADD=$!
code=""
for _ in $(seq 1 60); do code=$(grep -oiE "$CODE_WORD-[0-9]{3,5}" "$WORK/dave-add.log" | head -1); [ -n "$code" ] && break; sleep 0.3; done
[ -n "$code" ] || fixture_die "setup: no pairing code for dave: $(tail -3 "$WORK/dave-add.log")"
mkdir -p "$WORK/dave"
timeout 90 env HOME="$WORK/home-dave" TUNLION_CONFIG_DIR="$WORK/dave" "$BIN" --server "$SERVER" join "$code" --name bravo </dev/null >"$WORK/dave-join.log" 2>&1 || { cat "$WORK/dave-join.log" "$WORK/dave-add.log"; fixture_die "setup: dave join failed"; }
wait $PADD || fixture_die "setup: bravo add --name dave failed: $(tail -3 "$WORK/dave-add.log")"

for n in bravo charlie dave; do up_node "$n"; done

say "M: siblings meet on their certificates, unpaired"
if wait_log "$WORK/up-bravo.log" "fleet device 'charlie' joined the mesh" 60; then
  ok "gateM1: bravo admitted charlie over the fleet channel"
else bad "gateM1: bravo never admitted charlie"; grep -iE "fleet|roster" "$WORK/up-bravo.log" | tail -20; fi
if wait_log "$WORK/up-charlie.log" "fleet device 'bravo' joined the mesh" 30; then
  ok "gateM2: charlie admitted bravo over the fleet channel"
else bad "gateM2: charlie never admitted bravo"; grep -iE "fleet|roster" "$WORK/up-charlie.log" | tail -20; fi
if python3 - "$WORK/bravo/devices.json" charlie "$WORK/charlie/devices.json" bravo <<'PY'
import json,sys
for path, name in ((sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])):
    recs = [d for d in json.load(open(path)) if d.get("name") == name]
    assert recs, f"{name} not indexed in {path}"
    assert all(not d.get("secret") for d in recs), f"{name} carries a pair secret in {path}"
    assert all(d.get("deviceCert") for d in recs), f"{name} indexed without its certificate"
PY
then ok "gateM3: each sibling is indexed by its certificate with NO pair secret (never paired)"
else bad "gateM3: sibling records are not certificate-only index entries"; fi

say "R: reach between siblings"
fs_cli 45 as_node bravo reach charlie --json; rc=$(fs_rc)
if [ "$rc" = 0 ] && fs_out | grep -qE '"ok": ?true'; then ok "gateR1: bravo reaches charlie (rc=0, ok:true)"
else bad "gateR1: bravo reach charlie rc=$rc: $(fs_out | tail -5)"; fi
fs_cli 45 as_node bravo reach charlie; rc=$(fs_rc)
if [ "$rc" = 0 ] && ! fs_out | grep -q "not in this release"; then ok "gateR2: human reach works and no longer says 'not in this release'"
else bad "gateR2: bravo reach charlie (human) rc=$rc: $(fs_out | tail -4)"; fi
if [ "$MIXED" = 0 ]; then
  fs_cli 45 as_node charlie reach bravo --json; rc=$(fs_rc)
  if [ "$rc" = 0 ] && fs_out | grep -qE '"ok": ?true'; then ok "gateR3: charlie reaches bravo (rc=0, ok:true)"
  else bad "gateR3: charlie reach bravo rc=$rc: $(fs_out | tail -5)"; fi
fi

say "T: transfer needs an explicit grant (checked BEFORE any grant exists)"
echo "t1-$$" > "$WORK/t1.txt"
fs_cli 90 as_node bravo send "$WORK/t1.txt" --to charlie; rc=$(fs_rc)
sleep 2
if [ "$MIXED" = 0 ]; then
  if [ "$rc" = 4 ] && nowhere t1.txt; then ok "gateT1: ungranted bravo->charlie refused (rc=$rc) and landed nowhere"
  else bad "gateT1: ungranted bravo->charlie rc=$rc, landed: $(ls "$WORK"/*-drop "$WORK/Adrop" | tr '\n' ' ')"; fi
else
  echo "  (mixed: charlie is 0.9.1 and applies its own 0.9.1 policy; rc=$rc, charlie-drop: $(ls "$WORK/charlie-drop" | tr '\n' ' '))"
fi
echo "t1r-$$" > "$WORK/t1r.txt"
fs_cli 90 as_node charlie send "$WORK/t1r.txt" --to bravo; rc=$(fs_rc)
sleep 2
# In mixed mode the SENDER is 0.9.1, and a 0.9.1 daemon brokers its one-shot's
# meeting place over whichever link carries the target's name, which after T1
# can be bravo's lingering one-shot (fixed in this release, on the sender side).
# The send then never reaches bravo: exit 6, nothing lands. That is 0.9.1's own
# behaviour, unchanged by this release, so mixed mode asserts only that nothing
# crossed.
if [ "$MIXED" = 1 ]; then
  if [ "$rc" != 0 ] && nowhere t1r.txt; then ok "gateT2: (mixed) ungranted 0.9.1 charlie->bravo landed nowhere (rc=$rc)"
  else bad "gateT2: (mixed) ungranted charlie->bravo rc=$rc, landed: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
elif [ "$rc" = 4 ] && nowhere t1r.txt; then ok "gateT2: ungranted charlie->bravo refused by bravo (rc=$rc) and landed nowhere"
else bad "gateT2: ungranted charlie->bravo rc=$rc, landed: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
# The refusal must be bravo's capability gate deciding about charlie, not a
# link that never formed (exit 4 alone could in principle come from elsewhere).
if [ "$MIXED" = 1 ]; then
  echo "  (mixed: the 0.9.1 sender's offer does not reach bravo, see gateT2)"
elif grep -qE "transfer-gate: from=charlie allowed=false" "$WORK/up-bravo.log"; then
  ok "gateT2b: bravo's transfer gate itself refused charlie (allowed=false)"
else bad "gateT2b: no transfer-gate refusal of charlie in bravo's log"; grep -E "transfer-gate" "$WORK/up-bravo.log" | tail -3; fi

say "S: shell is the target's own grant decision"
fs_cli 60 as_node bravo exec charlie -- echo EXEC-MARK-PRE; rc=$(fs_rc)
if [ "$rc" = 4 ] && ! fs_out | grep -q EXEC-MARK-PRE; then ok "gateS1: ungranted exec refused (rc=$rc)"
else bad "gateS1: ungranted exec was not refused (rc=$rc): $(fs_out | tail -3)"; fi
as_node charlie grant bravo shell >/dev/null 2>&1 || bad "gateS-setup: charlie could not grant bravo shell"
as_node charlie grant bravo transfer >/dev/null 2>&1 || bad "gateT-setup: charlie could not grant bravo transfer"
sleep 2
fs_cli 60 as_node bravo exec charlie -- echo EXEC-MARK-OK; rc=$(fs_rc)
if [ "$rc" = 0 ] && fs_out | grep -q EXEC-MARK-OK; then ok "gateS2: exec works once charlie granted shell"
else bad "gateS2: granted exec rc=$rc: $(fs_out | tail -3)"; fi
echo "t2-$$" > "$WORK/t2.txt"
fs_cli 90 as_node bravo send "$WORK/t2.txt" --to charlie; rc=$(fs_rc)
sleep 2
if [ "$rc" = 0 ] && landed charlie t2.txt && ! landed alpha t2.txt && ! landed bravo t2.txt && ! landed dave t2.txt && [ ! -f "$WORK/Adrop/t2.txt" ] \
   && [ "$(cat "$WORK/charlie-drop/t2.txt")" = "t2-$$" ]; then
  ok "gateT3: granted bravo->charlie landed at charlie ONLY, content intact"
else bad "gateT3: granted send rc=$rc: $(fs_out | tail -3); drops: $(ls "$WORK"/*-drop "$WORK/Adrop" | tr '\n' ' ')"; fi
# charlie's grant to bravo says nothing about bravo's inbox.
echo "t2r-$$" > "$WORK/t2r.txt"
fs_cli 90 as_node charlie send "$WORK/t2r.txt" --to bravo; rc=$(fs_rc)
sleep 2
if { [ "$rc" = 4 ] || { [ "$MIXED" = 1 ] && [ "$rc" != 0 ]; }; } && nowhere t2r.txt; then ok "gateT4: charlie->bravo still refused: a grant is one-directional"
else bad "gateT4: charlie->bravo rc=$rc after charlie granted bravo; landed: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi

say "U: an uncertified pairing gets nothing new"
if [ ! -e "$WORK/dave/fleet.rv" ]; then ok "gateU1: dave holds no fleet rendezvous secret"
else bad "gateU1: dave holds a fleet secret"; fi
if ! grep -q "joined the mesh" "$WORK/up-dave.log"; then ok "gateU2: dave admitted no fleet device"
else bad "gateU2: dave admitted a fleet device: $(grep 'joined the mesh' "$WORK/up-dave.log")"; fi
fs_cli 30 as_node dave reach charlie; rc=$(fs_rc)
if [ "$rc" = 3 ]; then ok "gateU3: charlie is an unknown device to dave (exit 3)"
else bad "gateU3: dave reach charlie rc=$rc: $(fs_out | tail -3)"; fi
if ! grep -qE "fleet device 'dave'" "$WORK/up-bravo.log" "$WORK/up-charlie.log"; then ok "gateU4: no sibling admitted dave"
else bad "gateU4: dave was admitted as a fleet device"; fi
echo "u1-$$" > "$WORK/u1.txt"
fs_cli 90 as_node dave send "$WORK/u1.txt" --to bravo; rc=$(fs_rc)
sleep 2
if [ "$rc" = 0 ] && landed bravo u1.txt; then ok "gateU5: dave->bravo, the ordinary pairing, still delivers"
else bad "gateU5: dave->bravo rc=$rc: $(fs_out | tail -3)"; fi

say "V: revoking charlie on the OWNER cuts bravo<->charlie"
as_node alpha devices revoke charlie --yes </dev/null >"$WORK/revoke.log" 2>&1 || bad "gateV-setup: owner revoke failed: $(cat "$WORK/revoke.log")"
T0=$(date +%s)
if wait_log "$WORK/up-bravo.log" "closed the link to 'charlie'" 30; then
  ok "gateV1: bravo closed its link to charlie within $(( $(date +%s) - T0 ))s of the owner's revoke"
else bad "gateV1: bravo kept its link to charlie"; grep -iE "roster|charlie" "$WORK/up-bravo.log" | tail -15; fi
sleep 3
fs_cli 60 as_node bravo exec charlie -- echo EXEC-MARK-REVOKED; rc=$(fs_rc)
if [ "$rc" != 0 ] && ! fs_out | grep -q EXEC-MARK-REVOKED; then ok "gateV2: exec to revoked charlie refused (rc=$rc)"
else bad "gateV2: exec to revoked charlie rc=$rc: $(fs_out | tail -3)"; fi
echo "t3-$$" > "$WORK/t3.txt"
fs_cli 90 as_node bravo send "$WORK/t3.txt" --to charlie; rc=$(fs_rc)
echo "t4-$$" > "$WORK/t4.txt"
as_node bravo grant charlie transfer >/dev/null 2>&1   # even WITH a grant at bravo
fs_cli 90 as_node charlie send "$WORK/t4.txt" --to bravo; rc4=$(fs_rc)
sleep 2
if nowhere t3.txt && nowhere t4.txt; then ok "gateV3: no file crosses bravo<->charlie after the revoke (rc=$rc/$rc4), even with grants on both ends"
else bad "gateV3: a file crossed after revoke: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
sleep 15
n_after=$(awk -v t="$T0" '/fleet device .charlie. joined the mesh/ {print}' "$WORK/up-bravo.log" | wc -l)
if grep -q "fleet-hello from .* refused: device revoked\|closed the link to 'charlie'" "$WORK/up-bravo.log" \
   && ! tail -n +"$(grep -n "closed the link to 'charlie'" "$WORK/up-bravo.log" | tail -1 | cut -d: -f1)" "$WORK/up-bravo.log" | grep -q "fleet device 'charlie' joined the mesh"; then
  ok "gateV4: charlie was not re-admitted after the cut ($n_after admissions in total, all before it)"
else bad "gateV4: charlie re-admitted after the revoke"; fi
echo "t5-$$" > "$WORK/t5.txt"
fs_cli 90 as_node bravo send "$WORK/t5.txt" --to alpha; rc=$(fs_rc)
sleep 2
if [ "$rc" = 0 ] && [ -f "$WORK/Adrop/t5.txt" ]; then ok "gateV5: CONTROL bravo->alpha still delivers after the revoke"
else bad "gateV5: CONTROL bravo->alpha rc=$rc: $(fs_out | tail -3)"; fi

say "health"
for n in bravo charlie dave; do
  eval "p=\$PID_$n"
  if kill -0 "$p" 2>/dev/null; then ok "gateH-$n: $n daemon still running"; else bad "gateH-$n: $n daemon exited: $(tail -5 "$WORK/up-$n.log")"; fi
done
if ! grep -qiE "panicked|RUST_BACKTRACE" "$WORK"/up*.log; then ok "gateH-panic: no daemon panicked"
else bad "gateH-panic: $(grep -iE 'panicked' "$WORK"/up*.log | head -3)"; fi

echo
echo "fleet-automesh-gates: $PASS passed, $FAIL failed (mixed=$MIXED)"
declare_known_red_summary
[ "$FAIL" = 0 ]
