#!/usr/bin/env bash
# Fleet trust, live: the FleetSibling principal kind and owner-signed grant
# sets. Standalone, hermetic, fixture port 8126.
#
#   TUNLION_BIN=/path/to/tunlion ./fleet-trust-gates.sh
#   CHARLIE_BIN=/path/to/tunlion-0.9.1 ...   mixed versions: charlie runs 0.9.1
#
# alpha is the owner; bravo and charlie are joined devices that were never
# paired with each other. Each node has its OWN HOME, config and receive dir.
#
#   K1  bravo and charlie meet as siblings
#   K2  the kind's one default: an ungranted sibling file lands, at the named
#       device only
#   K3  and nothing else: an ungranted sibling exec is refused
#   K4  the device view says "your device", not owner-equivalent
#   K5  `grant bravo shell --on charlie` on the OWNER: charlie accepts the
#       owner-signed set and bravo's exec works with NO grant made on charlie
#   K6  charlie's capability store is byte-identical before and after (the
#       grant never entered it: no network write)
#   K7  a local deny on charlie outranks the owner's grant
#   K8  `grant charlie shell --on bravo`, then K9 `revoke ... --on bravo`
#       withdraws it from bravo while the owner is linked
#   K10 owner offline past the set's validity: the grant lapses on bravo
#   K11 while the kind's own default (transfer) needs no owner and keeps working
#   K12 revoking charlie on the owner ends charlie's sibling access to bravo
#
# Mixed mode (CHARLIE_BIN): charlie is a released 0.9.1. It does not know
# grant sets, so K5 must REFUSE there and charlie must stay healthy; its own
# receive policy is 0.9.1's. Everything bravo decides is asserted in full.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CBIN="${CHARLIE_BIN:-$BIN}"
MIXED=0; [ "$CBIN" != "$BIN" ] && MIXED=1
PORT=${PORT:-8126}
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-fleettrust.XXXXXX")"
DA="$WORK/alpha"
# Short owner-side validity so K10 can watch a set lapse in under a minute.
TTL=40
export TUNLION_ROSTER_TTL_SECS=$TTL

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()

for n in alpha bravo charlie; do mkdir -p "$WORK/home-$n" "$WORK/$n-drop"; done
export HOME="$WORK/home-alpha"

as_node() { # as_node NAME ARGS... -- tunlion as that node, own HOME and config
  local n="$1"; shift
  local b="$BIN"; [ "$n" = charlie ] && b="$CBIN"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" "$b" --server "$SERVER" "$@"
}
up_node() {
  local n="$1" b="$BIN"; [ "$n" = charlie ] && b="$CBIN"
  env HOME="$WORK/home-$n" TUNLION_CONFIG_DIR="$WORK/$n" TUNLION_L2=1 TUNLION_LOG=debug \
    "$b" --server "$SERVER" up --dir "$WORK/$n-drop" >>"$WORK/up-$n.log" 2>&1 &
  FIX_PIDS+=($!)
  eval "PID_$n=$!"
}
wait_log() { local i; for i in $(seq 1 $(( $3 * 2 ))); do grep -qE "$2" "$1" 2>/dev/null && return 0; sleep 0.5; done; return 1; }
landed() { [ -f "$WORK/$1-drop/$2" ]; }
only_at() { # only_at NODE FILE
  local n
  for n in alpha bravo charlie; do
    if [ "$n" = "$1" ]; then landed "$n" "$2" || return 1; else landed "$n" "$2" && return 1; fi
  done
  [ ! -f "$WORK/Adrop/$2" ]
}
nowhere() { local n; for n in alpha bravo charlie; do landed "$n" "$1" && return 1; done; [ ! -f "$WORK/Adrop/$1" ]; }
exec_is() { # exec_is FROM TO MARK -> sets rc and leaves output in fs_out
  fs_cli 60 as_node "$1" exec "$2" -- echo "$3"
}
cap_hash() { sha256sum "$WORK/$1/caps.json" 2>/dev/null | cut -c1-16 || echo none; }

echo "bin=$BIN ($(sha256sum "$BIN" | cut -c1-16)) charlie=$CBIN ($(sha256sum "$CBIN" | cut -c1-16)) mixed=$MIXED"

start_backend
init_owner "$DA"
start_acceptor "$DA"
PID_alpha=${FIX_PIDS[-1]}
enroll_delegate bravo
out=$(fs_bounded 45 env HOME="$WORK/home-alpha" TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" add --for charlie --out "$WORK/charlie-inv.txt" --yes)
[ "$(fs_state)" = ok ] || fixture_die "setup: add --for charlie: $out"
mkdir -p "$WORK/charlie"
out=$(fs_bounded 45 as_node charlie join --invite-file "$WORK/charlie-inv.txt" --name charlie --no-interactive)
[ "$(fs_state)" = ok ] || fixture_die "setup: charlie join: $out"
assert_certified "$DA" "$WORK/bravo" bravo
assert_certified "$DA" "$WORK/charlie" charlie
up_node bravo; up_node charlie

say "K1: siblings"
if wait_log "$WORK/up-bravo.log" "fleet device 'charlie' joined the mesh" 60 \
   && wait_log "$WORK/up-charlie.log" "fleet device 'bravo' joined the mesh" 30; then
  ok "gateK1: bravo and charlie admitted each other as siblings"
else bad "gateK1: the siblings never met"; fi

say "K2/K3: the FleetSibling kind implies transfer and nothing else"
echo "k2-$$" > "$WORK/k2.txt"
fs_cli 90 as_node bravo send "$WORK/k2.txt" --to charlie; rc=$(fs_rc); sleep 2
if [ "$rc" = 0 ] && only_at charlie k2.txt; then ok "gateK2: ungranted sibling transfer landed at charlie only"
else bad "gateK2: rc=$rc: $(fs_out | tail -3); drops: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
echo "k2r-$$" > "$WORK/k2r.txt"
fs_cli 90 as_node charlie send "$WORK/k2r.txt" --to bravo; rc=$(fs_rc); sleep 2
if [ "$MIXED" = 1 ]; then
  # A 0.9.1 sender brokers over whatever link carries the name (its own bug,
  # fixed on the sender side in this release): only "nothing misdelivered".
  if nowhere k2r.txt || only_at bravo k2r.txt; then ok "gateK2r: (mixed) 0.9.1 charlie->bravo misdelivered nothing (rc=$rc)"
  else bad "gateK2r: (mixed) misdelivery: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
elif [ "$rc" = 0 ] && only_at bravo k2r.txt; then ok "gateK2r: and the other direction (charlie->bravo) lands at bravo only"
else bad "gateK2r: rc=$rc: $(fs_out | tail -3)"; fi
exec_is bravo charlie K3-MARK; rc=$(fs_rc)
if [ "$rc" = 4 ] && ! fs_out | grep -q K3-MARK; then ok "gateK3: ungranted sibling exec refused (exit 4)"
else bad "gateK3: rc=$rc: $(fs_out | tail -3)"; fi

say "K4: device view"
if [ "$MIXED" = 0 ]; then
  as_node charlie devices >"$WORK/k4.txt" 2>&1
  if grep -E "^\s*. bravo " "$WORK/k4.txt" | grep -q "your device" && ! grep -E "^\s*. bravo " "$WORK/k4.txt" | grep -q "OWNER-EQUIVALENT"; then
    ok "gateK4: charlie lists bravo as 'your device', not owner-equivalent"
  else bad "gateK4: $(grep bravo "$WORK/k4.txt")"; fi
fi

say "K5/K6: an owner-signed grant about charlie"
H0=$(cap_hash charlie)
as_node alpha grant bravo shell --on charlie >"$WORK/k5-grant.txt" 2>&1 || bad "gateK5-setup: $(cat "$WORK/k5-grant.txt")"
if [ "$MIXED" = 0 ]; then
  if wait_log "$WORK/up-charlie.log" "fleet-grants: epoch [0-9]+ from .*: Accept" 30; then
    ok "gateK5a: charlie accepted the owner-signed set"
  else bad "gateK5a: charlie never accepted a set"; grep -i "fleet-grants" "$WORK/up-charlie.log" | tail -3; fi
  sleep 1
  exec_is bravo charlie K5-MARK; rc=$(fs_rc)
  if [ "$rc" = 0 ] && fs_out | grep -q K5-MARK; then ok "gateK5b: bravo execs on charlie on the owner's grant alone"
  else bad "gateK5b: rc=$rc: $(fs_out | tail -3)"; fi
else
  sleep 12
  exec_is bravo charlie K5-MARK; rc=$(fs_rc)
  if [ "$rc" != 0 ] && kill -0 "$PID_charlie" 2>/dev/null; then ok "gateK5: (mixed) 0.9.1 charlie ignores the set: exec still refused, charlie healthy"
  else bad "gateK5: (mixed) rc=$rc, charlie alive=$(kill -0 "$PID_charlie" 2>/dev/null && echo y || echo n)"; fi
fi
H1=$(cap_hash charlie)
if [ "$H0" = "$H1" ]; then ok "gateK6: charlie's capability store unchanged by the owner's grant ($H1)"
else bad "gateK6: charlie's caps.json changed: $H0 -> $H1"; fi

if [ "$MIXED" = 0 ]; then
  say "K7: a local deny outranks the owner"
  as_node charlie revoke bravo shell --yes >"$WORK/k7-revoke.txt" 2>&1 </dev/null \
    || bad "gateK7-setup: charlie could not record the deny: $(cat "$WORK/k7-revoke.txt")"
  # The premise, asserted: the deny is on charlie's record and the owner's grant
  # is still held there, so K7 can only pass because the deny outranks it.
  if python3 - "$WORK/charlie/devices.json" "$WORK/charlie/fleet-grants-held.json" <<'PY'
import json,sys
recs=[d for d in json.load(open(sys.argv[1])) if d.get("name")=="bravo"]
assert recs and "shell" in (recs[0].get("deniedCaps") or []), "no deny recorded"
held=json.load(open(sys.argv[2]))
assert any(g["cap"]=="shell" for g in held["grants"]), "owner grant not held"
PY
  then ok "gateK7-premise: deny recorded on charlie AND the owner's shell grant still held"
  else bad "gateK7-premise: premise not met"; fi
  sleep 2
  exec_is bravo charlie K7-MARK; rc=$(fs_rc)
  if [ "$rc" = 4 ] && ! fs_out | grep -q K7-MARK; then ok "gateK7: charlie's own deny wins over the owner-signed grant"
  else bad "gateK7: rc=$rc: $(fs_out | tail -3)"; fi
fi

say "K8/K9: grant on bravo, then withdraw it"
as_node alpha grant charlie shell --on bravo >/dev/null 2>&1 || bad "gateK8-setup: grant --on bravo failed"
wait_log "$WORK/up-bravo.log" "fleet-grants: epoch [0-9]+ from .*: Accept" 30
sleep 1
exec_is charlie bravo K8-MARK; rc=$(fs_rc)
if [ "$rc" = 0 ] && fs_out | grep -q K8-MARK; then ok "gateK8: charlie execs on bravo on the owner's grant"
else bad "gateK8: rc=$rc: $(fs_out | tail -3)"; fi
n_acc=$(grep -cE "fleet-grants: epoch [0-9]+ from .*: Accept" "$WORK/up-bravo.log")
as_node alpha revoke charlie shell --on bravo >/dev/null 2>&1 || bad "gateK9-setup: revoke --on bravo failed"
for _ in $(seq 1 40); do [ "$(grep -cE "fleet-grants: epoch [0-9]+ from .*: Accept" "$WORK/up-bravo.log")" -gt "$n_acc" ] && break; sleep 0.5; done
sleep 1
exec_is charlie bravo K9-MARK; rc=$(fs_rc)
if [ "$rc" = 4 ] && ! fs_out | grep -q K9-MARK; then ok "gateK9: withdrawn on the owner, refused on bravo"
else bad "gateK9: rc=$rc: $(fs_out | tail -3)"; fi

say "K10/K11: the owner goes offline past the set's validity"
as_node alpha grant charlie shell --on bravo >/dev/null 2>&1
n_acc=$(grep -cE "fleet-grants: epoch [0-9]+ from .*: Accept" "$WORK/up-bravo.log")
for _ in $(seq 1 40); do [ "$(grep -cE "fleet-grants: epoch [0-9]+ from .*: Accept" "$WORK/up-bravo.log")" -gt "$n_acc" ] && break; sleep 0.5; done
exec_is charlie bravo K10-PRE; rc_pre=$(fs_rc)
kill "$PID_alpha" 2>/dev/null; wait "$PID_alpha" 2>/dev/null
sleep $(( TTL + 8 ))
exec_is charlie bravo K10-MARK; rc=$(fs_rc)
if [ "$rc_pre" = 0 ] && [ "$rc" = 4 ] && ! fs_out | grep -q K10-MARK; then ok "gateK10: worked before (rc=0), lapsed once the set expired with the owner offline (rc=4)"
else bad "gateK10: before rc=$rc_pre, after rc=$rc: $(fs_out | tail -3)"; fi
echo "k11-$$" > "$WORK/k11.txt"
fs_cli 90 as_node bravo send "$WORK/k11.txt" --to charlie; rc=$(fs_rc); sleep 2
if [ "$rc" = 0 ] && only_at charlie k11.txt; then ok "gateK11: the kind's transfer default needs no owner online"
else bad "gateK11: rc=$rc: $(fs_out | tail -3)"; fi

say "K12: revoking charlie on the owner"
start_acceptor "$DA"
PID_alpha=${FIX_PIDS[-1]}
sleep 6
as_node alpha devices revoke charlie --yes </dev/null >/dev/null 2>&1 || bad "gateK12-setup: revoke failed"
if wait_log "$WORK/up-bravo.log" "closed the link to 'charlie'" 40; then
  echo "k12-$$" > "$WORK/k12.txt"
  fs_cli 90 as_node charlie send "$WORK/k12.txt" --to bravo; rc=$(fs_rc); sleep 2
  if nowhere k12.txt; then ok "gateK12: bravo cut charlie, and charlie's file lands nowhere (rc=$rc)"
  else bad "gateK12: a file from revoked charlie landed: $(ls "$WORK"/*-drop | tr '\n' ' ')"; fi
else bad "gateK12: bravo never closed its link to charlie"; fi

say "health"
for n in bravo charlie; do
  eval "p=\$PID_$n"
  if kill -0 "$p" 2>/dev/null; then ok "gateH-$n: $n daemon still running"; else bad "gateH-$n: $n exited: $(tail -5 "$WORK/up-$n.log")"; fi
done
if ! grep -qiE "panicked" "$WORK"/up*.log; then ok "gateH-panic: no daemon panicked"
else bad "gateH-panic: $(grep -iE 'panicked' "$WORK"/up*.log | head -3)"; fi

echo
echo "fleet-trust-gates: $PASS passed, $FAIL failed (mixed=$MIXED)"
declare_known_red_summary
[ "$FAIL" = 0 ]
