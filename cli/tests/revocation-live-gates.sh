#!/usr/bin/env bash
# Forget takes effect in the RUNNING daemon, and a used invitation stays used.
# Standalone, hermetic, fixture port 8151 ONLY.
#
#   FILAMENT_BIN=/path/to/tunlion ./revocation-live-gates.sh
#
# WHY THIS EXISTS. A blind test of the launch candidate found both of these by
# hand, and no gate could have: every forget gate restarted a daemon somewhere
# between the forget and the check, and the restart is exactly what hid them.
#
#   S1  `devices forget beta` on the owner printed "that device key is refused
#       here", rc=0. A minute later beta's `send` was delivered, and the owner's
#       log read "known device 'beta' appeared, connecting". The daemon was
#       deciding with the (name, pair secret) list it loaded at start, and the
#       links already up were never re-examined. Only `down` + `up` made the
#       forget real (revocation_live.rs).
#   S2  after that restart, beta's USED invitation enrolled a wiped beta again
#       ("joined": true). The one-use marker was process memory
#       (filament_cap::ephemeral::burn_auth_key: "a daemon restart clears all
#       burn state"), so the restart forget needed was the restart that reset
#       it (invite_burn.rs).
#
# So these gates never restart the owner between a forget and its check (S1),
# and DO restart it between a use and its replay (S2), because that is the
# order a real owner runs them in.
#
# Gates:
#   enrolment x3  the spoke is a certified fleet device (lib/fixture.sh)
#   LA   POSITIVE send   -- before the forget, the spoke's file is delivered
#   LA2  POSITIVE exec   -- and its exec runs
#   LB   the forget says the RUNNING daemon applied it ("in effect now", at
#        least one link closed) and does not promise "never met you"
#   LC   the forgotten spoke's send is refused within seconds, nothing lands,
#        and the owner daemon is the SAME process (no restart did this)
#   LD   the forgotten spoke's exec is refused, nothing runs
#   LE   the owner names the link it closed
#   LF   the owner never re-dials the forgotten pair secret ("known device
#        '<spoke>' appeared" stops after the forget)
#   IA   POSITIVE: a fresh invitation enrols (the join path works at all)
#   IB   after forget + owner restart, the USED invitation is refused for a
#        brand-new device key ("already been used"), nothing is enrolled
#   IC   and for the SAME device key, nothing is enrolled
#   ID   CONTROL: on the restarted owner a fresh invitation still enrols, so
#        IB/IC are the burn and not a broken enrolment path
#
# PLATFORM: unix-only in practice (the fixture backend, ss), like every other
# *-gates.sh here. The property is platform-independent.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8151
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-revlive.XXXXXX")"
DA="$WORK/owner"
SPOKE=beta
DS="$WORK/$SPOKE"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

KNOWN_RED_ALLOW=()

O_ENV=(env FILAMENT_CONFIG_DIR="$DA")
S_ENV=(env FILAMENT_CONFIG_DIR="$DS")

start_backend
init_owner "$DA"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"

enroll_delegate "$SPOKE" --allow shell,transfer
start_spoke "$DS" "$SPOKE"
sleep 6

say "enrolment: a certified fleet relationship, built by the product"
assert_certified "$DA" "$DS" "$SPOKE"

# ==================================================================== GATE LA ==
say "LA: before the forget, the spoke's send is delivered"
echo "before-forget $$" >"$WORK/before-forget.txt"
timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" send "$WORK/before-forget.txt" --to alpha \
  >"$WORK/LA.out" 2>&1 </dev/null
rcLA=$?
sleep 1
echo "## (send before forget) rc=$rcLA"
if [ "$rcLA" = "0" ] && [ -f "$WORK/Adrop/before-forget.txt" ]; then
  ok "gateLA: the spoke's send was delivered before the forget"
else
  echo "-- LA.out --"; cat "$WORK/LA.out"; ls -la "$WORK/Adrop" 2>/dev/null
  bad "gateLA: the positive send did not land (rc=$rcLA), so the refusals below would prove nothing"
fi

# =================================================================== GATE LA2 ==
say "LA2: before the forget, the spoke's exec runs"
OUTLA2=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo LIVE-EXEC-OK 2>"$WORK/LA2.err" </dev/null)
rcLA2=$?
echo "## (exec before forget) rc=$rcLA2 out='$OUTLA2'"
if [ "$rcLA2" = "0" ] && [ "$OUTLA2" = "LIVE-EXEC-OK" ]; then
  ok "gateLA2: the spoke's exec ran before the forget"
else
  echo "-- LA2.err --"; cat "$WORK/LA2.err"
  bad "gateLA2: the positive exec did not run (rc=$rcLA2 out='$OUTLA2')"
fi

# ==================================================================== GATE LB ==
# The spoke's daemon stays UP throughout, and so does the owner's: this is the
# whole point. A restart anywhere from here to LF would hide S1.
say "LB: forget while both daemons run; the running daemon confirms it"
LOG_MARK=$(wc -l <"$WORK/up.log")
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices forget "$SPOKE" >"$WORK/forget.log" 2>&1
rcLB=$?
echo "## (forget) rc=$rcLB"; cat "$WORK/forget.log"
if [ "$rcLB" = "0" ] \
   && grep -q "in effect now" "$WORK/forget.log" \
   && grep -qE "closed [1-9][0-9]* link" "$WORK/forget.log" \
   && ! grep -q "never met you" "$WORK/forget.log"; then
  ok "gateLB: the forget was applied by the running daemon and says what the device will see"
else
  bad "gateLB: the forget did not report the running daemon applying it (rc=$rcLB)"
fi

# ==================================================================== GATE LC ==
say "LC: the forgotten spoke's send is refused, without any restart"
sleep 3
echo "after-forget $$" >"$WORK/after-forget.txt"
timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" send "$WORK/after-forget.txt" --to alpha \
  >"$WORK/LC.out" 2>&1 </dev/null
rcLC=$?
sleep 2
OWNER_SAME=0; kill -0 "$OWNER_PID" 2>/dev/null && OWNER_SAME=1
LANDED=0; ls "$WORK/Adrop" 2>/dev/null | grep -q "after-forget" && LANDED=1
echo "## (send after forget) rc=$rcLC landed=$LANDED owner_same_process=$OWNER_SAME"
if [ "$rcLC" != "0" ] && [ "$LANDED" = "0" ] && [ "$OWNER_SAME" = "1" ]; then
  ok "gateLC: the forgotten spoke's send was refused by the same running daemon, nothing landed"
else
  echo "-- LC.out --"; cat "$WORK/LC.out"
  echo "-- owner log since the forget --"; tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | tail -20
  bad "gateLC: the forgotten spoke could still deliver, or the owner restarted (rc=$rcLC landed=$LANDED same=$OWNER_SAME)"
fi

# ==================================================================== GATE LD ==
say "LD: the forgotten spoke's exec is refused"
OUTLD=$(timeout 60 "${S_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/LD.err" </dev/null)
rcLD=$?
echo "## (exec after forget) rc=$rcLD out='$OUTLD'"
if [ "$rcLD" != "0" ] && ! echo "$OUTLD" | grep -q "SHOULD-NOT-RUN" && kill -0 "$OWNER_PID" 2>/dev/null; then
  ok "gateLD: the forgotten spoke's exec was refused by the same running daemon"
else
  echo "-- LD.err --"; cat "$WORK/LD.err"
  bad "gateLD: the forgotten spoke's exec was NOT refused (rc=$rcLD out='$OUTLD')"
fi

# ==================================================================== GATE LE ==
say "LE: the owner names the link it closed"
if tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep -q "closed the link to '.*': it was forgotten or revoked here"; then
  ok "gateLE: the owner logged closing the forgotten device's link"
else
  echo "-- owner log since the forget --"; tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | tail -20
  bad "gateLE: the owner did not log closing the forgotten device's link"
fi

# ==================================================================== GATE LF ==
# The measured S1 symptom, asserted directly: the owner re-dialed the forgotten
# device on the pair secret it still held in memory.
say "LF: the owner never re-dials the forgotten pair secret"
REDIAL=$(tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep -c "known device '$SPOKE' appeared" || true)
echo "## owner re-dial lines after the forget: $REDIAL"
if [ "$REDIAL" = "0" ]; then
  ok "gateLF: no 'known device $SPOKE appeared' after the forget"
else
  tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep "appeared" | tail -5
  bad "gateLF: the owner re-dialed the forgotten device $REDIAL time(s)"
fi

# ==================================================================== GATE IA ==
GAMMA=gamma
DG="$WORK/$GAMMA"
say "IA: a fresh invitation enrols (positive control for the join path)"
enroll_delegate "$GAMMA" --allow transfer
if grep -q "\"name\": *\"$GAMMA\"" "$DA/devices.json"; then
  ok "gateIA: a fresh invitation enrolled '$GAMMA'"
else
  bad "gateIA: the fresh invitation did not enrol '$GAMMA'"
fi
# Keep the joined device's own state, to replay the invitation with its key.
cp -a "$DG" "$WORK/$GAMMA-samekey"
rm -f "$WORK/$GAMMA-samekey/identity/device-cert.json" "$WORK/$GAMMA-samekey/devices.json"

# The owner forgets it and restarts, the order S2 was found in. The restart is
# what used to clear the one-use marker.
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices forget "$GAMMA" >"$WORK/forget-gamma.log" 2>&1
kill "$OWNER_PID" 2>/dev/null
sleep 2
cp "$WORK/up.log" "$WORK/up-before-restart.log"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"
sleep 4

# ==================================================================== GATE IB ==
say "IB: the used invitation is refused for a NEW device key, after forget and restart"
mkdir -p "$WORK/$GAMMA-newkey"
fs_bounded 45 env FILAMENT_CONFIG_DIR="$WORK/$GAMMA-newkey" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/$GAMMA-inv.txt" --name "$GAMMA" --no-interactive >"$WORK/IB.out" 2>&1
stIB=$(fs_state); rcIB=$(fs_rc)
REC_IB=$(grep -c "\"name\": *\"$GAMMA" "$DA/devices.json" || true)
echo "## (replay, new key) state=$stIB rc=$rcIB records=$REC_IB"
if [ "$stIB" = "err" ] && grep -qi "already been used" "$WORK/IB.out" && [ "$REC_IB" = "0" ]; then
  ok "gateIB: the used invitation was refused for a new key ('already been used'), nothing enrolled"
else
  echo "-- IB.out --"; cat "$WORK/IB.out"
  bad "gateIB: a used invitation enrolled a new key after forget+restart (state=$stIB rc=$rcIB records=$REC_IB)"
fi

# ==================================================================== GATE IC ==
say "IC: the used invitation is refused for the SAME device key"
fs_bounded 45 env FILAMENT_CONFIG_DIR="$WORK/$GAMMA-samekey" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/$GAMMA-inv.txt" --name "$GAMMA" --no-interactive >"$WORK/IC.out" 2>&1
stIC=$(fs_state); rcIC=$(fs_rc)
REC_IC=$(grep -c "\"name\": *\"$GAMMA" "$DA/devices.json" || true)
echo "## (replay, same key) state=$stIC rc=$rcIC records=$REC_IC"
if [ "$stIC" = "err" ] && grep -qiE "already been used|revoked" "$WORK/IC.out" && [ "$REC_IC" = "0" ]; then
  ok "gateIC: the used invitation was refused for the same key, nothing enrolled"
else
  echo "-- IC.out --"; cat "$WORK/IC.out"
  bad "gateIC: a used invitation re-enrolled the same key after forget+restart (state=$stIC rc=$rcIC records=$REC_IC)"
fi

# ==================================================================== GATE ID ==
say "ID: on the restarted owner, a fresh invitation still enrols"
enroll_delegate delta --allow transfer
if grep -q "\"name\": *\"delta\"" "$DA/devices.json"; then
  ok "gateID: a fresh invitation enrolled on the restarted owner, so IB/IC were the burn"
else
  bad "gateID: the restarted owner enrolled nothing, so IB/IC prove nothing"
fi

declare_known_red_summary
KNOWN_RED_N=${#KNOWN_RED_HIT[@]}

echo
echo "==========================================="
echo "revocation-live gates: $PASS passed, $FAIL failed, $KNOWN_RED_N known-red${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
