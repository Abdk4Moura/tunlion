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
#   echo     joined device  (add --for echo), the sibling NOT revoked in V:
#            the positive control on a live sibling link
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
#   T   transfer: the FleetSibling default, at the named device only, both
#       ways, with no grant and no pairing; a grant stays one-directional
#   V   revocation: `demote charlie --to cut` on the OWNER cuts bravo<->charlie
#       (link closed, exec refused, no file lands either way, no re-admission,
#       also after bravo's sweep removed charlie's record) while bravo<->alpha
#       and the unrevoked sibling echo->bravo keep working on live links
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

for n in alpha bravo charlie dave echo; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
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
  for n in alpha bravo charlie dave echo; do landed "$n" "$1" && return 1; done
  [ ! -f "$WORK/Adrop/$1" ]
}

echo "bin=$BIN ($(sha256sum "$BIN" | cut -c1-16)) charlie=$CBIN ($(sha256sum "$CBIN" | cut -c1-16)) mixed=$MIXED"
"$BIN" --version; "$CBIN" --version

start_backend
init_owner "$DA"
# The owner daemon serves alpha's own drop as $WORK/Adrop (fixture).
start_acceptor "$DA"
enroll_delegate bravo
# echo: a second sibling, never revoked. Setup only (no gate of its own, so the
# gate count is unchanged); it is V's positive control on a live sibling link.
enroll_delegate echo
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

for n in bravo charlie dave echo; do up_node "$n"; done

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

say "T: transfer is the FleetSibling kind's one default (checked BEFORE any grant exists)"
# 0.9.2 fleet trust (owner decision): a sibling may transfer with no grant, to
# the NAMED device only. This gate asserted the opposite while auto-mesh shipped
# grant-only transfer; the rule changed by decision, not to make a test pass.
echo "t1-$$" > "$WORK/t1.txt"
fs_cli 90 as_node bravo send "$WORK/t1.txt" --to charlie; rc=$(fs_rc)
sleep 2
if [ "$rc" = 0 ] && landed charlie t1.txt && ! landed alpha t1.txt && ! landed bravo t1.txt && ! landed dave t1.txt && [ ! -f "$WORK/Adrop/t1.txt" ]; then
  ok "gateT1: ungranted bravo->charlie landed at charlie ONLY"
else bad "gateT1: ungranted bravo->charlie rc=$rc, landed: $(ls "$WORK"/*-drop "$WORK/Adrop" | tr '\n' ' ')"; fi
echo "t1r-$$" > "$WORK/t1r.txt"
fs_cli 90 as_node charlie send "$WORK/t1r.txt" --to bravo; rc=$(fs_rc)
sleep 2
# In mixed mode the SENDER is 0.9.1, whose daemon brokers its one-shot's meeting
# place over whichever link carries the target's name (fixed in this release,
# on the sender side). Mixed mode asserts only that nothing was misdelivered.
if [ "$MIXED" = 1 ]; then
  if nowhere t1r.txt || { landed bravo t1r.txt && ! landed charlie t1r.txt && ! landed dave t1r.txt; }; then ok "gateT2: (mixed) 0.9.1 charlie->bravo misdelivered nothing (rc=$rc)"
  else bad "gateT2: (mixed) misdelivery: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
elif [ "$rc" = 0 ] && landed bravo t1r.txt && ! landed charlie t1r.txt && ! landed dave t1r.txt && [ ! -f "$WORK/Adrop/t1r.txt" ]; then
  ok "gateT2: ungranted charlie->bravo landed at bravo ONLY"
else bad "gateT2: ungranted charlie->bravo rc=$rc, landed: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
if [ "$MIXED" = 1 ]; then
  echo "  (mixed: see gateT2)"
else
  # After both transfers (and whatever identity proofs they caused), bravo's
  # LIVE link to charlie must still be a sibling link. Read off the daemon's
  # own warm-hold line (every 10s), so a handler that relabels the link is
  # caught here, not only at the pure decision function.
  LT2=$(( $(wc -l < "$WORK/up-bravo.log") + 1 ))
  kind_line=""
  for _ in $(seq 1 50); do
    kind_line=$(tail -n +"$LT2" "$WORK/up-bravo.log" | grep -E "warm-hold: skip 'charlie' .*principal=" | tail -1)
    [ -n "$kind_line" ] && break; sleep 0.5
  done
  if grep -qE "transfer-gate: from=charlie allowed=true .*trusted=false" "$WORK/up-bravo.log" \
     && printf '%s\n' "$kind_line" | grep -qE "principal=FleetSibling sibling=true"; then
    ok "gateT2b: bravo's transfer gate admitted charlie on the kind, on an UNTRUSTED link (no pairing), and the live link is still a sibling link"
  else bad "gateT2b: transfer-gate admission of charlie missing, or its live link is no longer a sibling link (${kind_line:-no warm-hold line in 25s})"
    grep -E "transfer-gate|identity proven for peer" "$WORK/up-bravo.log" | tail -4; fi
fi

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
LT3b=$(( $(wc -l < "$WORK/up-bravo.log") + 1 )); LT3c=$(( $(wc -l < "$WORK/up-charlie.log") + 1 ))
fs_cli 90 as_node bravo send "$WORK/t2.txt" --to charlie; rc=$(fs_rc)
sleep 2
if [ "$rc" = 0 ] && landed charlie t2.txt && ! landed alpha t2.txt && ! landed bravo t2.txt && ! landed dave t2.txt && ! landed echo t2.txt && [ ! -f "$WORK/Adrop/t2.txt" ] \
   && [ "$(cat "$WORK/charlie-drop/t2.txt")" = "t2-$$" ]; then
  ok "gateT3: granted bravo->charlie landed at charlie ONLY, content intact"
else bad "gateT3: granted send rc=$rc: $(fs_out | tail -3); drops: $(ls "$WORK"/*-drop "$WORK/Adrop" | tr '\n' ' ')"
  # Evidence only (the verdict above stands): what each daemon did for this
  # send, and the sender's own debug trail, which the one-line summary hides.
  echo "## evidence: daemons during the gateT3 send"
  tail -n +"$LT3b" "$WORK/up-bravo.log" | grep -E "rendezvous|signaling|refus|drop_link|died|closed|transfer-gate|charlie" | tail -12 | sed 's/^/  bravo: /'
  tail -n +"$LT3c" "$WORK/up-charlie.log" | grep -E "rendezvous|signaling|refus|drop_link|died|closed|transfer-gate|bravo" | tail -12 | sed 's/^/  charlie: /'
  echo "t2d-$$" > "$WORK/t2d.txt"
  env HOME="$WORK/home-bravo" TUNLION_CONFIG_DIR="$WORK/bravo" TUNLION_LOG=debug timeout 60 "$BIN" --server "$SERVER" send "$WORK/t2d.txt" --to charlie </dev/null 2>&1 | tail -15 | sed 's/^/  debug-send: /'
fi
# charlie's shell grant to bravo says nothing about bravo's shell.
fs_cli 60 as_node charlie exec bravo -- echo EXEC-MARK-REV; rc=$(fs_rc)
if [ "$rc" != 0 ] && ! fs_out | grep -q EXEC-MARK-REV; then ok "gateT4: charlie->bravo exec still refused: a grant is one-directional"
else bad "gateT4: charlie->bravo exec rc=$rc after charlie granted bravo"; fi

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
# The positive control needs echo on a live sibling link BEFORE the revoke.
wait_log "$WORK/up-bravo.log" "fleet device 'echo' joined the mesh" 60 || echo "  (echo never joined bravo's mesh; gateV5 will say so)"
# charlie's device key, read while bravo still holds its record.
CHARLIE_KEY=$(python3 - "$WORK/bravo/devices.json" <<'PY'
import json,sys
print(next((d["deviceCert"]["devicePub"] for d in json.load(open(sys.argv[1])) if d.get("name") == "charlie" and d.get("deviceCert")), ""))
PY
)
# Everything V asserts about bravo's log is read from here on: a line before the
# revoke proves nothing about it.
LV0=$(( $(wc -l < "$WORK/up-bravo.log") + 1 ))
since_revoke() { tail -n +"$LV0" "$WORK/up-bravo.log"; }
# grep WITHOUT -q reads all of its input: under pipefail an early -q exit can
# SIGPIPE the tail and turn a match into a miss, which a negated check would
# then report as a pass.
post_has() { since_revoke | grep -E "$1" >/dev/null; }
wait_since() { # wait_since REGEX SECS: like wait_log, on bravo's post-revoke lines only
  local i
  for i in $(seq 1 $(( $2 * 2 ))); do post_has "$1" && return 0; sleep 0.5; done
  return 1
}
as_node alpha demote charlie --to cut --yes </dev/null >"$WORK/revoke.log" 2>&1 || bad "gateV-setup: owner revoke failed: $(cat "$WORK/revoke.log")"
T0=$(date +%s)
if wait_since "closed the link to 'charlie'" 30 && ! post_has "closed the link to 'echo'"; then
  ok "gateV1: bravo closed its link to charlie within $(( $(date +%s) - T0 ))s of the owner's revoke, and kept echo's"
else bad "gateV1: bravo kept its link to charlie, or cut echo's too"; since_revoke | grep -iE "roster|charlie|echo" | tail -15; fi
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
# The denied arm is also read off bravo's own transfer gate, not only off the
# drop dirs: an admission of charlie after the revoke is the failure itself.
if nowhere t3.txt && nowhere t4.txt && ! post_has "transfer-gate: from=charlie allowed=true"; then ok "gateV3: no file crosses bravo<->charlie after the revoke (rc=$rc/$rc4), even with grants on both ends"
else bad "gateV3: a file crossed after revoke: $(ls "$WORK"/*-drop | tr '\n' ' ')"; since_revoke | grep -E "transfer-gate: from=charlie" | tail -3; fi
sleep 15
n_after=$(since_revoke | grep -c "fleet device 'charlie' joined the mesh" || true)
# Re-admission is judged on every post-revoke line, NOT from the close line on
# (a missing close line made `tail -n +` fail and this pass vacuously). Then the
# record sweep: once bravo removed charlie's record (the instrument must fire),
# the revocation must survive it: a delisted-sibling entry names charlie's key
# and a fresh charlie->bravo offer is still refused.
v4_why=""
post_has "fleet device 'charlie' joined the mesh" && v4_why="re-admitted after the revoke ($n_after)"
# Budget: the record sweep runs every 30s, so allow 90s for it (one missed tick
# and slack); with the 60s refusal wait below V4 adds at most ~3 minutes to a
# suite that ran in ~3.5 under its 600s step timeout.
if [ -z "$v4_why" ]; then
  for _ in $(seq 1 180); do grep -q '"name": *"charlie"' "$WORK/bravo/devices.json" || break; sleep 0.5; done
  if grep -q '"name": *"charlie"' "$WORK/bravo/devices.json"; then v4_why="bravo still holds charlie's record 90s on (its record sweep never removed it)"
  elif ! post_has "device\(s\) lapsed or ended"; then v4_why="charlie's record went without bravo's sweep saying so (instrument did not fire)"; fi
fi
if [ -z "$v4_why" ] && { [ -z "$CHARLIE_KEY" ] || ! grep -q "$CHARLIE_KEY" "$WORK/bravo/delisted-siblings.json" 2>/dev/null; }; then v4_why="removing charlie's record left no delisted-sibling entry (key=${CHARLIE_KEY:-unread})"; fi
# The denied arm must be a REFUSAL, not mere unreachability. After the sweep
# line, charlie's one-shot is sent over the fleet channel itself
# (TUNLION_FLEET_SEND=1: it presents charlie's certificate in a fleet-hello
# rather than giving up for want of a broker), so bravo is MADE to judge
# charlie's key now instead of waiting on a warm re-dial. It must fail, land
# nowhere, and bravo must refuse charlie's key by name: with the record gone,
# only the kept revocation says "device revoked"; without it the hello is only
# held as unlisted. The refusal wait is 30s (a re-dial would come on the 10s
# warm tick as well); with the 90s send bound this arm adds at most ~2 minutes,
# far inside the 600s step timeout.
if [ -z "$v4_why" ]; then
  LSW=$(since_revoke | grep -nE "device\(s\) lapsed or ended" | tail -1 | cut -d: -f1)
  LSW=$(( LV0 + ${LSW:-1} - 1 ))
  echo "t6-$$" > "$WORK/t6.txt"
  export TUNLION_FLEET_SEND=1
  fs_cli 90 as_node charlie send "$WORK/t6.txt" --to bravo; rc6=$(fs_rc)  # broker retry 12s + fleet path 45s
  unset TUNLION_FLEET_SEND
  sleep 2
  if [ "$rc6" = 0 ] || ! nowhere t6.txt \
     || post_has "transfer-gate: from=charlie allowed=true|fleet device 'charlie' joined the mesh"; then
    v4_why="after the record sweep charlie->bravo was admitted (rc=$rc6)"
  else
    refused=""
    for _ in $(seq 1 60); do
      tail -n +"$LSW" "$WORK/up-bravo.log" | grep -E "fleet-hello from .* refused: device revoked \(device $CHARLIE_KEY\)" >/dev/null && { refused=1; break; }
      sleep 0.5
    done
    [ -n "$refused" ] || v4_why="after the record sweep bravo never refused charlie's key by name within 30s of charlie's hello (rc=$rc6; unreachable is not a refusal)"
  fi
fi
if [ -z "$v4_why" ]; then
  ok "gateV4: charlie was not re-admitted after the cut, nor after bravo's sweep removed its record (rc=$rc6)"
else bad "gateV4: $v4_why"; since_revoke | grep -E "charlie|lapsed or ended|transfer-gate" | tail -10; fi
echo "t5-$$" > "$WORK/t5.txt"
fs_cli 90 as_node bravo send "$WORK/t5.txt" --to alpha; rc=$(fs_rc)
sleep 2
# Positive control on a LIVE SIBLING link: echo, never revoked, still lands a
# file at bravo, admitted by bravo's transfer gate after charlie's revoke.
echo "e1-$$" > "$WORK/e1.txt"
fs_cli 90 as_node echo send "$WORK/e1.txt" --to bravo; rce=$(fs_rc)
sleep 2
v5_why=""
if ! { [ "$rc" = 0 ] && [ -f "$WORK/Adrop/t5.txt" ]; }; then v5_why="the owner control bravo->alpha failed (rc=$rc)"; fi
if ! { [ "$rce" = 0 ] && landed bravo e1.txt && ! landed charlie e1.txt && ! landed echo e1.txt; }; then
  v5_why="${v5_why:+$v5_why; }the sibling control echo->bravo did not land at bravo only (rc=$rce)"
elif ! post_has "transfer-gate: from=echo allowed=true .*trusted=false"; then
  # Delivered, but not shown to be admitted as an untrusted SIBLING.
  v5_why="${v5_why:+$v5_why; }echo->bravo landed but bravo's gate did not admit echo as a sibling (no allowed=true ... trusted=false)"
fi
if [ -z "$v5_why" ]; then
  ok "gateV5: CONTROL bravo->alpha and the unrevoked sibling echo->bravo still deliver after the revoke"
else bad "gateV5: $v5_why: $(fs_out | tail -3)"; since_revoke | grep -E "transfer-gate: from=echo|echo" | tail -5; fi

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
