#!/usr/bin/env bash
# An invitation's --expires is the END of the device's access, on every path.
# Standalone, hermetic, fixture port 8171 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./invite-expiry-gates.sh
#
# WHY THIS EXISTS. A real two-machine test (owner-a, guest-b invited with
# `add guest-b --allow transfer,shell --expires 4m`) found access outliving the
# invitation on every path but file transfer:
#
#   * exec ran ~2m38s past the end. The owner renewed the guest's certificate
#     for the original lifetime counted from NOW (never clamped to the
#     invitation end), and a parked exec denied for the expiry was re-driven
#     and RUN once the guest proved its key, because the proof re-bound the
#     link from the renewed certificate.
#   * forward ignored the expiry entirely: new `forward` / `forward --stdio`
#     opens kept working for minutes, a stream opened before the end was never
#     cut, and one refused cold forward exited 0 with no message.
#   * refusals said "outside the device's invitation ceiling" for a capability
#     that was inside it and had simply expired.
#
# So this gate holds an exec and a forward stream open ACROSS the end and then
# asserts, against one running owner daemon and one running guest daemon:
#
#   X0  premise: the owner records the invitation end (devices --json)
#   PA  POSITIVE exec runs before the end
#   PB  POSITIVE send is delivered before the end
#   PC  POSITIVE forward --stdio streams before the end
#   C0  CONTROL: the held exec and the held forward are both still alive just
#       before the end (a gate that closes everything always proves nothing)
#   X1  the held exec is cut within the bound, exit 4, saying it expired
#   X2  the held forward stream is cut within the bound, and the owner names
#       the expiry as the reason
#   X3  a NEW exec is refused, exit 4, saying it expired, nothing runs
#   X4  a NEW forward is refused, exit 4, saying it expired
#   X5  a NEW forward --stdio is refused, exit 4, saying it expired
#   X6  a NEW send is refused, exit 4, saying it expired, nothing lands
#   X7  the owner's devices --json says expired, effective caps [], and the
#       certificate was never renewed past the invitation end
#   X8  the owner never re-drove a parked open after the end
#   X9  the expired guest's refused exec filed no access request, and
#       approving a request from it exits 4 naming the expiry (RC lab item 2)
#   X10 owner and guest device lists say the access expired, no capability
#       badge, no "EXTERNAL" relabel of the owner (RC lab item 8)
#   X11 exec and forward give the same remedy for the expiry (RC lab item 9)
#   X12 exec, forward and send print the SAME re-invite line, with --allow
#       and --expires (concurrent-code lab pass)
#
# The invitation lives EXP seconds. That is longer than the ~20 s the defect
# needs, because the positive controls must all finish inside it on a shared CI
# runner (a cold exec can take several seconds to establish); the gate refuses
# to report rather than pass vacuously if setup ate the window.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8171
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-invexp.XXXXXX")"
DA="$WORK/owner"
GUEST=guest
DG="$WORK/$GUEST"
EXP=40
# The live re-check runs every 5 s (revoke_recheck_interval) and the daemon's
# store scan every 2 s; 15 s is that cadence with room for a loaded runner.
BOUND=15
COUNTER_PORT=9171
FWD_LPORT=9172
FWD2_LPORT=9173

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

KNOWN_RED_ALLOW=()
O_ENV=(env TUNLION_CONFIG_DIR="$DA")
G_ENV=(env TUNLION_CONFIG_DIR="$DG")

now() { date +%s; }

start_backend
init_owner "$DA"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"

# A counter on the owner host: each fresh TICK-N proves the stream is live,
# not a buffer replay.
python3 -c "
import socket,threading,time
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('127.0.0.1',$COUNTER_PORT)); s.listen(16)
def serve(c):
    i=0
    try:
        while True:
            i+=1; c.sendall(('TICK-%d\n'%i).encode()); time.sleep(1)
    except Exception: pass
    c.close()
while True:
    c,_=s.accept(); threading.Thread(target=serve,args=(c,),daemon=True).start()
" >/dev/null 2>&1 &
FIX_PIDS+=($!)

T_MINT=$(now)
enroll_delegate "$GUEST" --allow shell,transfer --expires "${EXP}s"
start_spoke "$DG" "$GUEST"
sleep 3

# ==================================================================== GATE X0 ==
say "X0: the owner records when the guest's invitation ends"
END=$("${O_ENV[@]}" "$BIN" devices --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d['data']['devices']:
    if r['name']==sys.argv[1]:
        print(r.get('invitationEnds') or ''); break
" "$GUEST" 2>/dev/null)
echo "## minted at $T_MINT, invitation ends at '${END}', now $(now)"
if [ -n "$END" ] && [ "$END" -ge "$T_MINT" ] && [ "$END" -le $((T_MINT + EXP + 5)) ]; then
  ok "gateX0: the owner holds the guest's invitation end ($END, ${EXP}s after the mint)"
else
  "${O_ENV[@]}" "$BIN" devices --json 2>&1 | head -40
  fixture_die "gateX0: the owner does not record the invitation end, so nothing below can be timed"
fi

# ==================================================================== GATE PA ==
say "PA: before the end, the guest's exec runs"
OUTPA=$(timeout 30 "${G_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo LIVE-EXEC-OK 2>"$WORK/PA.err" </dev/null)
rcPA=$?
echo "## exec rc=$rcPA out='$OUTPA'"
if [ "$rcPA" = "0" ] && [ "$OUTPA" = "LIVE-EXEC-OK" ]; then
  ok "gatePA: the guest's exec ran before the end"
else
  cat "$WORK/PA.err"
  bad "gatePA: the positive exec did not run (rc=$rcPA), so the refusals below would prove nothing"
fi

# ==================================================================== GATE PB ==
say "PB: before the end, the guest's send is delivered"
echo "before-end $$" >"$WORK/before-end.txt"
timeout 30 "${G_ENV[@]}" "$BIN" --server "$SERVER" send "$WORK/before-end.txt" --to alpha \
  >"$WORK/PB.out" 2>&1 </dev/null
rcPB=$?
sleep 1
if [ "$rcPB" = "0" ] && [ -f "$WORK/Adrop/before-end.txt" ]; then
  ok "gatePB: the guest's send was delivered before the end"
else
  cat "$WORK/PB.out"
  bad "gatePB: the positive send did not land (rc=$rcPB)"
fi

# ==================================================================== GATE PC ==
say "PC: before the end, forward --stdio streams"
timeout 6 "${G_ENV[@]}" "$BIN" --server "$SERVER" forward "alpha:$COUNTER_PORT" --stdio \
  </dev/null >"$WORK/PC.out" 2>"$WORK/PC.err"
if grep -q "TICK-" "$WORK/PC.out"; then
  ok "gatePC: forward --stdio streamed from the owner before the end"
else
  cat "$WORK/PC.err"
  bad "gatePC: the positive forward --stdio did not stream"
fi

# ======================================================== HELD SESSIONS ==
say "holding an exec and a forward stream open across the end"
( timeout $((EXP + 120)) "${G_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/sleep 600 \
    </dev/null >"$WORK/held-exec.out" 2>"$WORK/held-exec.err"; echo $? >"$WORK/held-exec.rc" ) &
HELD_EXEC=$!
FIX_PIDS+=($HELD_EXEC)
"${G_ENV[@]}" "$BIN" --server "$SERVER" forward "alpha:$COUNTER_PORT" --lport "$FWD_LPORT" \
  >"$WORK/held-fwd.log" 2>&1 &
HELD_FWD=$!
FIX_PIDS+=($HELD_FWD)
sleep 3
( timeout $((EXP + 120)) nc 127.0.0.1 "$FWD_LPORT" </dev/null >"$WORK/held-nc.out" 2>/dev/null ) &
HELD_NC=$!
FIX_PIDS+=($HELD_NC)

LEFT=$((END - $(now)))
echo "## ${LEFT}s of the invitation left once both sessions are held"
if [ "$LEFT" -lt 4 ]; then
  fixture_die "setup used the whole ${EXP}s window (${LEFT}s left), so the held-session gates cannot be measured; refusing to report"
fi

# ==================================================================== GATE C0 ==
say "C0: both held sessions are alive just before the end"
sleep $((LEFT - 2))
ticks_before=$(grep -c "TICK-" "$WORK/held-nc.out" 2>/dev/null || true)
if kill -0 "$HELD_NC" 2>/dev/null && [ "${ticks_before:-0}" -ge 1 ] && [ ! -f "$WORK/held-exec.rc" ]; then
  ok "gateC0: the held exec and the held forward ($ticks_before ticks) are alive 2s before the end"
else
  echo "## nc alive: $(kill -0 "$HELD_NC" 2>/dev/null && echo yes || echo no), ticks=$ticks_before, exec rc=$(cat "$WORK/held-exec.rc" 2>/dev/null)"
  cat "$WORK/held-exec.err" 2>/dev/null; tail -5 "$WORK/held-fwd.log"
  bad "gateC0: a held session was already gone BEFORE the end, so a cut after it proves nothing"
fi
LOG_MARK=$(wc -l <"$WORK/up.log")

# Past the end, by the bound.
sleep $((END - $(now) + BOUND))
echo "## now $(now), end $END"

# ==================================================================== GATE X1 ==
say "X1: the held exec was cut, exit 4, saying it expired"
rcX1=$(cat "$WORK/held-exec.rc" 2>/dev/null)
echo "## held exec rc='$rcX1'"; cat "$WORK/held-exec.err" 2>/dev/null
if [ "$rcX1" = "4" ] && grep -qi "expired" "$WORK/held-exec.err"; then
  ok "gateX1: the exec held across the end was cut within ${BOUND}s, exit 4, naming the expiry"
else
  bad "gateX1: the held exec was not cut as an expiry (rc='$rcX1')"
fi

# ==================================================================== GATE X2 ==
say "X2: the held forward stream was cut, and the owner names the expiry"
if kill -0 "$HELD_NC" 2>/dev/null; then
  bad "gateX2: the forward stream opened before the end still streams $BOUND s after it"
elif ! tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep -q "l2: peer access expired, closing the live stream"; then
  tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | tail -15
  bad "gateX2: the client's stream closed, but the owner never logged closing it for the expiry"
else
  ok "gateX2: the forward stream held across the end was closed by the owner for the expiry"
fi

# ==================================================================== GATE X3 ==
say "X3: a new exec is refused, exit 4, saying it expired"
OUTX3=$(timeout 60 "${G_ENV[@]}" "$BIN" --server "$SERVER" exec alpha -- /bin/echo SHOULD-NOT-RUN 2>"$WORK/X3.err" </dev/null)
rcX3=$?
echo "## exec rc=$rcX3 out='$OUTX3'"; cat "$WORK/X3.err"
if [ "$rcX3" = "4" ] && ! echo "$OUTX3" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "expired" "$WORK/X3.err" && ! grep -q "outside the device's invitation ceiling" "$WORK/X3.err"; then
  ok "gateX3: a new exec after the end was refused (exit 4) as expired, not as a ceiling"
else
  bad "gateX3: a new exec after the end was not refused as expired (rc=$rcX3)"
fi

# ==================================================================== GATE X4 ==
say "X4: a new forward is refused, exit 4, saying it expired"
"${G_ENV[@]}" "$BIN" --server "$SERVER" forward "alpha:$COUNTER_PORT" --lport "$FWD2_LPORT" \
  >"$WORK/X4.log" 2>&1 &
X4_PID=$!
FIX_PIDS+=($X4_PID)
sleep 3
( timeout 5 nc 127.0.0.1 "$FWD2_LPORT" </dev/null >/dev/null 2>&1 ) || true
for _ in $(seq 1 "$BOUND"); do kill -0 "$X4_PID" 2>/dev/null || break; sleep 1; done
if kill -0 "$X4_PID" 2>/dev/null; then
  tail -5 "$WORK/X4.log"
  bad "gateX4: a new forward after the end is still running"
else
  wait "$X4_PID"; rcX4=$?
  echo "## forward rc=$rcX4"; tail -5 "$WORK/X4.log"
  if [ "$rcX4" = "4" ] && grep -qi "expired" "$WORK/X4.log"; then
    ok "gateX4: a new forward after the end exited 4, naming the expiry"
  else
    bad "gateX4: a new forward after the end did not exit 4 naming the expiry (rc=$rcX4)"
  fi
fi

# ==================================================================== GATE X5 ==
say "X5: a new forward --stdio is refused, exit 4, saying it expired"
timeout 60 "${G_ENV[@]}" "$BIN" --server "$SERVER" forward "alpha:$COUNTER_PORT" --stdio \
  </dev/null >"$WORK/X5.out" 2>"$WORK/X5.err"
rcX5=$?
echo "## forward --stdio rc=$rcX5"; cat "$WORK/X5.err"
if [ "$rcX5" = "4" ] && ! grep -q "TICK-" "$WORK/X5.out" && grep -qi "expired" "$WORK/X5.err"; then
  ok "gateX5: a new forward --stdio after the end exited 4, naming the expiry, and carried nothing"
else
  bad "gateX5: a new forward --stdio after the end was not refused as expired (rc=$rcX5)"
fi

# ==================================================================== GATE X6 ==
say "X6: a new send is refused, exit 4, saying it expired"
echo "after-end $$" >"$WORK/after-end.txt"
timeout 60 "${G_ENV[@]}" "$BIN" --server "$SERVER" send "$WORK/after-end.txt" --to alpha \
  >"$WORK/X6.out" 2>&1 </dev/null
rcX6=$?
sleep 1
LANDED=0; ls "$WORK/Adrop" 2>/dev/null | grep -q "after-end" && LANDED=1
echo "## send rc=$rcX6 landed=$LANDED"; cat "$WORK/X6.out"
if [ "$rcX6" = "4" ] && [ "$LANDED" = "0" ] && grep -qi "expired" "$WORK/X6.out"; then
  ok "gateX6: a new send after the end was refused (exit 4) with the expiry as its reason"
else
  bad "gateX6: a new send after the end was not refused as expired (rc=$rcX6 landed=$LANDED)"
fi

# ==================================================================== GATE X7 ==
say "X7: the owner's device list agrees with the gate, and renewal stayed inside the end"
"${O_ENV[@]}" "$BIN" devices --json >"$WORK/X7.json" 2>/dev/null
if python3 - "$GUEST" "$WORK/X7.json" <<'PY'
import json,sys
name,path=sys.argv[1],sys.argv[2]
d=json.load(open(path))
r=[x for x in d['data']['devices'] if x['name']==name][0]
print('##', {k:r.get(k) for k in ('state','caps','grantedCaps','certExpires','accessUntil','invitationEnds')})
ok = (r.get('state')=='expired' and r.get('caps')==[]
      and r.get('certExpires') is not None and r.get('invitationEnds') is not None
      and r['certExpires'] <= r['invitationEnds'])
sys.exit(0 if ok else 1)
PY
then
  ok "gateX7: devices --json shows expired with no effective caps, and the cert never ran past the invitation end"
else
  bad "gateX7: devices --json disagrees with the gate, or the cert was renewed past the end"
fi

# ==================================================================== GATE X8 ==
say "X8: no parked open was re-driven after the end"
REDRIVE=$(tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep -c "open proven; re-driving" || true)
echo "## re-drives after the end: $REDRIVE"
if [ "$REDRIVE" = "0" ] && kill -0 "$OWNER_PID" 2>/dev/null; then
  ok "gateX8: the owner (same process) re-drove no parked open after the end"
else
  tail -n +"$((LOG_MARK + 1))" "$WORK/up.log" | grep -E "parked|re-driving" | tail -10
  bad "gateX8: the owner re-drove $REDRIVE parked open(s) after the end, or restarted"
fi

# ==================================================================== GATE X9 ==
# RC lab item 2: the refused exec of an expired device filed "[extern] guest
# wants to OWNER-EQUIVALENT shell", and approving it exited 0 with "ok guest can
# act as you" while the gate still refused it.
say "X9: an expired device files no request, and approving one is refused"
NOW=$(now)
FILED=$(python3 - "$DA/requests.json" "$GUEST" <<'PY'
import json,sys
try: reqs=json.load(open(sys.argv[1]))
except Exception: reqs=[]
print(sum(1 for r in reqs if r.get('peer')==sys.argv[2] and r.get('status')=='pending'))
PY
)
# A request filed BEFORE the end (seeded here: the daemon no longer files one
# after it) must not be approvable once the device has expired.
python3 - "$DA/requests.json" "$GUEST" "$NOW" <<'PY'
import json,sys
p,peer,now=sys.argv[1],sys.argv[2],int(sys.argv[3])
try: reqs=json.load(open(p))
except Exception: reqs=[]
reqs.append({"id":977,"peer":peer,"capability":"shell","timestamp":now,"status":"pending","granted_at":None})
json.dump(reqs,open(p,"w"))
PY
"${O_ENV[@]}" "$BIN" requests approve 977 --allow shell --for 1h >"$WORK/X9.out" 2>&1
rcX9=$?
STATUS977=$(python3 -c "
import json,sys
r=[x for x in json.load(open(sys.argv[1])) if x.get('id')==977]
print(r[0]['status'] if r else 'gone')" "$DA/requests.json" 2>/dev/null)
"${O_ENV[@]}" "$BIN" requests >"$WORK/X9-list.out" 2>&1
echo "## pending from $GUEST after the refused exec: $FILED; approve rc=$rcX9; request status: $STATUS977"; cat "$WORK/X9.out"
if [ "$FILED" = "0" ] && [ "$rcX9" = "4" ] && grep -qi "expired" "$WORK/X9.out" \
   && grep -q "tunlion add --for $GUEST" "$WORK/X9.out" && ! grep -q "can act as you" "$WORK/X9.out" \
   && [ "$STATUS977" != "pending" ] && [ "$STATUS977" != "approved" ] && ! grep -q "wants to" "$WORK/X9-list.out"; then
  ok "gateX9: no request filed for the expired guest; approving one exits 4 naming the expiry and the re-invite, and withdraws it"
else
  cat "$WORK/X9-list.out"
  bad "gateX9: an expired device's request was filed or approvable (filed=$FILED rc=$rcX9 status=$STATUS977)"
fi

# =================================================================== GATE X10 ==
# RC lab item 8: the owner listed the expired guest under FLEET with an
# "OWNER-EQUIVALENT shell" badge beside "lapsed"; the guest relabelled its
# owner "EXTERNAL / other people".
say "X10: both device lists say the access expired, with no capability badge"
"${O_ENV[@]}" "$BIN" devices >"$WORK/X10-owner.out" 2>&1
"${G_ENV[@]}" "$BIN" devices >"$WORK/X10-guest.out" 2>&1
GROW=$(grep -E "^\s+\S+ $GUEST\b" "$WORK/X10-owner.out" | head -1)
AROW=$(grep -E "^\s+\S+ alpha\b" "$WORK/X10-guest.out" | head -1)
echo "## owner row: $GROW"; echo "## guest row: $AROW"
if [ -n "$GROW" ] && echo "$GROW" | grep -q "expired" && ! echo "$GROW" | grep -q "OWNER-EQUIVALENT" \
   && ! echo "$GROW" | grep -q "lapsed" \
   && [ -n "$AROW" ] && echo "$AROW" | grep -q "your access expired" && ! grep -q "EXTERNAL" "$WORK/X10-guest.out"; then
  ok "gateX10: the owner shows the guest as expired with no capability badge; the guest shows its owner with 'your access expired'"
else
  cat "$WORK/X10-owner.out" "$WORK/X10-guest.out"
  bad "gateX10: a device list misstates the expiry"
fi

# =================================================================== GATE X11 ==
# RC lab item 9: for the same expiry, exec printed forget + add + reset and
# forward said "with a fresh invitation". One cause, one remedy.
say "X11: exec and forward give the same remedy for the expiry"
same_steps=1
for f in "$WORK/X3.err" "$WORK/X5.err"; do
  for step in "tunlion devices forget " "tunlion add --for " "tunlion reset -y" "tunlion join --invite-file " "tunlion up --detach"; do
    grep -qF "$step" "$f" || { same_steps=0; echo "## $(basename "$f") lacks: $step"; }
  done
  grep -q "with a fresh invitation" "$f" && { same_steps=0; echo "## $(basename "$f") still says: with a fresh invitation"; }
done
if [ "$same_steps" = "1" ]; then
  ok "gateX11: exec and forward refusals for the expiry carry the same re-admission steps"
else
  cat "$WORK/X3.err" "$WORK/X5.err"
  bad "gateX11: exec and forward remedy the same expiry differently"
fi

# =================================================================== GATE X12 ==
# Concurrent-code lab pass: exec's expiry remedy was `add --for guest --allow
# transfer,shell --expires 2m ...` and send's `add --for guest --out
# guest-invite.txt --yes`. Every path now builds it from the same data (the
# owner's record, carried in the reason), so the add line is ONE line.
say "X12: exec, forward and send print the same re-invite, with its caps and lifetime"
ADD_X3=$(grep -o "tunlion add --for .*" "$WORK/X3.err" | head -1)
ADD_X5=$(grep -o "tunlion add --for .*" "$WORK/X5.err" | head -1)
ADD_X6=$(grep -o "tunlion add --for .*" "$WORK/X6.out" | head -1)
echo "## exec:    $ADD_X3"; echo "## forward: $ADD_X5"; echo "## send:    $ADD_X6"
if [ -n "$ADD_X3" ] && [ "$ADD_X3" = "$ADD_X5" ] && [ "$ADD_X3" = "$ADD_X6" ] \
   && echo "$ADD_X3" | grep -q -- "--allow " && echo "$ADD_X3" | grep -q -- "--expires "; then
  ok "gateX12: exec, forward and send give one re-invite line, with --allow and --expires"
else
  bad "gateX12: the expiry's re-invite differs between exec, forward and send"
fi

declare_known_red_summary
echo
echo "== invite-expiry gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
