#!/usr/bin/env bash
# A box joined with a runner invitation is an EPHEMERAL device: the owner can
# reach it by name while it exists, nobody else ever lists it, its access ends
# at its lease, and the owner removes it when it leaves or its lease ends.
# Standalone, hermetic, fixture port 8179 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./ephemeral-runner-gates.sh
#
# WHY THIS EXISTS. The CI workers were minted `--for device` (reusable, 30d),
# because a runner was not recorded on the owner and so could not be addressed
# by name. So every lease became a permanent fleet member: listed under FLEET on
# the owner and on every other device, a certificate for the invitation's whole
# remaining lifetime (21-30 days for a lease of two hours), and a record nobody
# removed. Against one owner daemon, two runner boxes and one fleet device:
#
#   E0  premise: the owner records the box as ephemeral, access ending at its
#       lease (TUNLION_LEASE), not at the invitation's end
#   E1  POSITIVE the owner reaches the box by name (exec runs)
#   E2  the owner lists it under EPHEMERAL, not FLEET
#   E3  the box holds no fleet meeting point
#   E4  a fleet device's list names the other fleet device (control) and
#       never the box
#   E5  `down` on the box removes it at the owner, within the bound
#   E6  POSITIVE a second box from the same invitation is reachable under a
#       suffixed name
#   E7  that box's lease ends while it is still running: the owner removes it
#       and a new exec to it is refused, nothing runs
#   E8  the second box's certificate ends at its lease, not the invitation's

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8179
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-ephem.XXXXXX")"
DA="$WORK/owner"
W1="$WORK/w1"
W2="$WORK/w2"
LEASE1=600
LEASE2=40
# The owner's sweep runs every 30 s; a goodbye is answered at once.
BOUND=45

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

KNOWN_RED_ALLOW=()
O_ENV=(env TUNLION_CONFIG_DIR="$DA")

now() { date +%s; }

# $1 = name: the owner's `devices --json` record, one line of JSON, or empty.
owner_record() {
  "${O_ENV[@]}" "$BIN" devices --json 2>/dev/null | python3 -c "
import json,sys
d=json.load(sys.stdin)
for r in d['data']['devices']:
    if r['name']==sys.argv[1]:
        print(json.dumps(r)); break
" "$1" 2>/dev/null
}

# $1 = name, $2 = seconds: wait until the owner no longer lists it.
wait_gone() {
  local i
  for i in $(seq 1 "$2"); do
    [ -z "$(owner_record "$1")" ] && return 0
    sleep 1
  done
  return 1
}

# $1 = config dir, $2 = lease, $3 = log name. A box that joins and serves in
# one command, exactly as the CI workflow does it.
start_runner() {
  env TUNLION_CONFIG_DIR="$1" TUNLION_AUTHKEY="$(cat "$WORK/runner-inv.txt")" TUNLION_LEASE="$2" \
    "$BIN" --server "$SERVER" up --dir "$1-drop" --shell-only alpha --i-know --no-interactive \
    >"$WORK/$3.log" 2>&1 &
  FIX_PIDS+=($!)
}

start_backend
init_owner "$DA"
start_acceptor "$DA"

# A fleet device with its own daemon (the owner's roster reaches it), and a
# second fleet device so its roster has a positive control.
enroll_delegate laptop --allow transfer
enroll_delegate desk --allow transfer
start_spoke "$WORK/laptop" laptop

fs_cli 45 "${O_ENV[@]}" "$BIN" --server "$SERVER" add --for runner --name worker \
  --allow transfer,shell --reuse 3 --expires 1h --out "$WORK/runner-inv.txt" --yes --no-interactive \
  || fixture_die "setup: minting the runner invitation failed: $(fs_out | tail -2 | tr '\n' ' ')"

T1=$(now)
start_runner "$W1" "${LEASE1}s" runner1
for _ in $(seq 1 40); do [ -n "$(owner_record worker)" ] && break; sleep 1; done
sleep 3

# ==================================================================== GATE E0 ==
say "E0: the owner records the box as ephemeral, until its lease ends"
REC=$(owner_record worker)
echo "## worker record: $REC"
END=$(printf '%s' "$REC" | python3 -c "import json,sys; r=json.load(sys.stdin); print(r.get('invitationEnds') or '')" 2>/dev/null)
EPH=$(printf '%s' "$REC" | python3 -c "import json,sys; r=json.load(sys.stdin); print(r.get('ephemeral'))" 2>/dev/null)
if [ "$EPH" = "True" ] && [ -n "$END" ] && [ "$END" -ge $((T1 + LEASE1 - 5)) ] && [ "$END" -le $((T1 + LEASE1 + 60)) ]; then
  ok "gateE0: the box is recorded ephemeral, access ending at its lease"
else
  tail -20 "$WORK/runner1.log"
  bad "gateE0: the box is not recorded as ephemeral with a lease-bound end (ephemeral=$EPH end=$END, lease ends ~$((T1 + LEASE1)))"
fi

# ==================================================================== GATE E1 ==
say "E1: the owner reaches the box by name"
OUT1=$(timeout 40 "${O_ENV[@]}" "$BIN" --server "$SERVER" exec worker -- /bin/echo EPH-EXEC-OK 2>"$WORK/E1.err" </dev/null)
rc1=$?
echo "## exec rc=$rc1 out='$OUT1'"
if [ "$rc1" = "0" ] && [ "$OUT1" = "EPH-EXEC-OK" ]; then
  ok "gateE1: exec to the ephemeral box by name ran"
else
  cat "$WORK/E1.err"
  bad "gateE1: exec to the ephemeral box did not run (rc=$rc1), so the removals below would prove nothing"
fi

# ==================================================================== GATE E2 ==
say "E2: the owner lists it under EPHEMERAL, not FLEET"
"${O_ENV[@]}" "$BIN" devices >"$WORK/E2.out" 2>&1
SECTIONS=$(python3 - "$WORK/E2.out" <<'PY'
import re,sys
text=re.sub(r'\x1b\[[0-9;]*m','',open(sys.argv[1]).read())
section=None; seen={}
for line in text.splitlines():
    m=re.match(r'\s+\S+\s+([A-Z][A-Z ]+?)\s+/',line)
    if m: section=m.group(1).strip(); continue
    if not line.strip(): section=None; continue
    for name in ('worker','laptop'):
        if re.search(r'\s'+name+r'\s',line+' '): seen[name]=section
print(seen.get('worker'), seen.get('laptop'))
PY
)
echo "## sections (worker laptop): $SECTIONS"
if [ "$SECTIONS" = "EPHEMERAL FLEET" ]; then
  ok "gateE2: the box is under EPHEMERAL, the fleet device under FLEET"
else
  cat "$WORK/E2.out"
  bad "gateE2: the box is not listed apart from the fleet (got: $SECTIONS)"
fi

# ==================================================================== GATE E3 ==
say "E3: the box holds no fleet meeting point"
if [ -f "$W1/identity/device-cert.json" ] && [ ! -e "$W1/fleet.rv" ]; then
  ok "gateE3: the box joined (it holds a certificate) and holds no fleet meeting point"
else
  ls -la "$W1" "$W1/identity" 2>&1 | head -30
  bad "gateE3: the box did not join, or it was given the fleet meeting point"
fi

# ==================================================================== GATE E4 ==
say "E4: a fleet device never lists the box"
LAPTOP_LIST=""
for _ in $(seq 1 30); do
  LAPTOP_LIST=$(env TUNLION_CONFIG_DIR="$WORK/laptop" "$BIN" devices 2>&1)
  printf '%s' "$LAPTOP_LIST" | grep -q 'desk' && break
  sleep 1
done
printf '%s\n' "$LAPTOP_LIST" >"$WORK/E4.out"
if grep -q 'desk' "$WORK/E4.out" && ! grep -q 'worker' "$WORK/E4.out"; then
  ok "gateE4: the fleet device lists the other fleet device and not the box"
else
  cat "$WORK/E4.out"
  bad "gateE4: the fleet device's list is missing desk (control) or names the box"
fi

# ==================================================================== GATE E5 ==
say "E5: down on the box removes it at the owner"
env TUNLION_CONFIG_DIR="$W1" "$BIN" --server "$SERVER" down -y >"$WORK/E5.out" 2>&1 </dev/null
rc5=$?
if [ "$rc5" = "0" ] && wait_gone worker "$BOUND"; then
  ok "gateE5: down departed and the owner removed the box"
else
  cat "$WORK/E5.out"; tail -20 "$WORK/up.log"
  bad "gateE5: after down (rc=$rc5) the owner still lists the box: $(owner_record worker)"
fi

# ==================================================================== GATE E6 ==
say "E6: a second box from the same invitation is reachable under its own name"
T2=$(now)
start_runner "$W2" "${LEASE2}s" runner2
for _ in $(seq 1 30); do [ -n "$(owner_record worker-2)" ] && break; sleep 1; done
sleep 2
OUT6=$(timeout 30 "${O_ENV[@]}" "$BIN" --server "$SERVER" exec worker-2 -- /bin/echo EPH-EXEC-2 2>"$WORK/E6.err" </dev/null)
rc6=$?
echo "## exec rc=$rc6 out='$OUT6'"
if [ "$rc6" = "0" ] && [ "$OUT6" = "EPH-EXEC-2" ]; then
  ok "gateE6: exec to the second box (worker-2) ran"
else
  cat "$WORK/E6.err"; tail -20 "$WORK/runner2.log"
  bad "gateE6: exec to the second box did not run (rc=$rc6), so E7 would prove nothing"
fi

# ==================================================================== GATE E8 ==
say "E8: the second box's certificate ends at its lease"
CERT_END=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['cert']['expires'])" "$W2/identity/device-cert.json" 2>/dev/null)
echo "## cert expires $CERT_END, lease ends ~$((T2 + LEASE2)), invitation ends ~$((T1 + 3600))"
if [ -n "$CERT_END" ] && [ "$CERT_END" -le $((T2 + LEASE2 + 30)) ]; then
  ok "gateE8: the box's certificate ends with its lease, not the invitation"
else
  bad "gateE8: the box's certificate outlives its lease (expires $CERT_END)"
fi

# ==================================================================== GATE E7 ==
say "E7: the lease ends with the box still running: removed, and exec refused"
sleep $(( T2 + LEASE2 - $(now) > 0 ? T2 + LEASE2 - $(now) : 0 ))
if wait_gone worker-2 "$BOUND"; then
  GONE=1
else
  GONE=0
fi
kill -0 "${FIX_PIDS[-1]}" 2>/dev/null && ALIVE=1 || ALIVE=0
rm -f "$W2-drop/E7-ran"
OUT7=$(timeout 30 "${O_ENV[@]}" "$BIN" --server "$SERVER" exec worker-2 -- /bin/sh -c "touch '$W2-drop/E7-ran'; echo RAN" 2>"$WORK/E7.err" </dev/null)
rc7=$?
echo "## gone=$GONE box-alive=$ALIVE exec rc=$rc7 out='$OUT7'"; cat "$WORK/E7.err"
if [ "$GONE" = "1" ] && [ "$ALIVE" = "1" ] && [ "$rc7" != "0" ] && [ ! -e "$W2-drop/E7-ran" ]; then
  ok "gateE7: the running box was removed at its lease end and nothing ran"
else
  tail -20 "$WORK/up.log"
  bad "gateE7: at the lease end the box was not removed or an exec still ran (gone=$GONE alive=$ALIVE rc=$rc7)"
fi

declare_known_red_summary
echo
echo "== ephemeral-runner gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
