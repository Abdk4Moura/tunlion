#!/usr/bin/env bash
# The expiry/close race, held still. When an invitation ends during a live
# `exec`, the owner cuts the session and the link can close in the same moment.
# If the close outruns the cut message, the initiator only sees a dead link, and
# it used to report that as an unreachable peer (exit 6) instead of the expiry
# (exit 4). The matrix saw exactly that with a local signaling server (cell C24).
#
# This gate removes the luck: the owner runs with a test hook that closes the
# link BEFORE sending the cut (TUNLION_TEST_EXPIRY_CLOSE_FIRST, compiled only with
# --features test-hooks), so the bad order happens every time.
#
#   R0  the hook fired on the owner (otherwise R1 proves nothing)
#   R1  the held exec ended exit 4, naming the expiry, within the bound
#
# Standalone, hermetic, fixture port 8197 ONLY. Needs a test-hooks binary.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8197
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-exprace.XXXXXX")"
DA="$WORK/owner"
GUEST=guest
DG="$WORK/$GUEST"
EXP=30
BOUND=20

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

KNOWN_RED_ALLOW=()
G_ENV=(env TUNLION_CONFIG_DIR="$DG")
now() { date +%s; }

start_backend
init_owner "$DA"
TUNLION_TEST_EXPIRY_CLOSE_FIRST=1 start_acceptor "$DA"

T_MINT=$(now)
enroll_delegate "$GUEST" --allow shell,transfer --expires "${EXP}s"
start_spoke "$DG" "$GUEST"
sleep 3
END=$((T_MINT + EXP))

( timeout $((EXP + 90)) "${G_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/sleep 600 \
    </dev/null >"$WORK/held.out" 2>"$WORK/held.err"; echo $? >"$WORK/held.rc" ) &
FIX_PIDS+=($!)

# Wait past the end by the bound, or until the exec ends.
for _ in $(seq 1 $((EXP + BOUND + 10))); do
  [ -f "$WORK/held.rc" ] && break
  [ "$(now)" -ge $((END + BOUND)) ] && break
  sleep 1
done
sleep 1

say "R0: the hook closed the link before the cut message"
if grep -q "test hook: expiry closes the link before the cut message" "$WORK/up.log"; then
  ok "gateR0: the owner closed the link first at the end (the bad order, held still)"
else
  tail -20 "$WORK/up.log"
  bad "gateR0: the hook never fired (not a test-hooks build, or the session was not cut), so R1 would prove nothing"
fi

say "R1: the held exec reports the expiry, not an unreachable peer"
rc=$(cat "$WORK/held.rc" 2>/dev/null)
echo "## held exec rc='$rc'"; cat "$WORK/held.err" 2>/dev/null
if [ "$rc" = "4" ] && grep -qi "expired" "$WORK/held.err"; then
  ok "gateR1: a link closed at the end ahead of the cut reads as the expiry (exit 4)"
else
  bad "gateR1: the held exec ended rc='$rc', not 4 naming the expiry"
fi

declare_known_red_summary
echo
echo "== expiry-race gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
