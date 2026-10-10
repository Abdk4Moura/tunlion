#!/usr/bin/env bash
# `tunlion shell` (native PTY) denial + positive gates. Standalone, hermetic,
# fixture port 8103 ONLY. Proves that a shell refusal reaches the initiator as a
# nonzero exit + a reason, instead of an empty success (the #219/#223 defect).
#
#   FILAMENT_BIN=/path/to/tunlion ./shell-gates.sh
#
# Gates:
#   A  NEGATIVE no-cap — a paired device WITHOUT a shell grant is refused; exit
#      nonzero and the reason names the capability.
#   B  POSITIVE granted — `tunlion shell <peer> -- 'echo HELLO'` returns 0 with
#      HELLO on stdout.
#   C  NEIGHBOUR `-- true` — a legitimately fast-exiting remote command stays
#      exit 0 with no output; it must NOT be reported as a denial.
#   D  NEGATIVE revoked — after `revoke <peer> shell`, the shell is refused
#      (nonzero, reason).
#   A1 PRECISE no-cap — that refusal names the real cause (no grant there) and
#      the exact fix to run on the other device (`tunlion grant boxA shell`),
#      and never claims serving is off (it is on).
#   E  NEGATIVE acceptor off — peer runs plain `up` (no --shell) with NO shell
#      grant; the initiator is told the acceptor is not serving, nonzero.
#   E2 LIVE grant — the grant is issued AFTER the daemon is already up (#219
#      repro order) and takes effect WITHOUT a restart: the same shell now runs.
#      (This used to be asserted the other way round, "still refused", which
#      pinned the very defect: a grant the running daemon never applied.)
#   F  `up --detach --shell --i-know` while a plain daemon runs: returns at once
#      (never follows the log), exits 10 (DAEMON_CONFLICT in the exit-code
#      taxonomy; 3 is "unknown device"), and says the flags were not applied and
#      the exact restart command, --server included.
#   F2 `up --detach` with matching settings while it runs: returns at once, 0.
#   F3 `up --detach --userspace` while it runs with the SAME shell posture: the
#      daemon reports its launch flags, so the unapplied --userspace is named
#      (exit 10) instead of passing as "same settings".
#
# Topology: side B = acceptor, side A = initiator, reciprocal pair secret
# (same-owner fleet, not a delegated device) so B trusts A. Gate E restarts the
# acceptor on plain `up`.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8103
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-shell-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== shell gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

DA="$WORK/A"; DB="$WORK/B"; mkdir -p "$DA" "$DB"
SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
printf '[{"name":"boxB","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
printf '[{"name":"boxA","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"

A_ENV=(env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA)

start_acceptor() {  # $1 = 1 (serve shell, grant-required) | 0 (plain up)
  local l2_env=""
  [ "$1" = "1" ] && l2_env="FILAMENT_L2=1"
  local drop="$WORK/Bdrop"; mkdir -p "$drop"
  env $l2_env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB \
    "$BIN" up --dir "$drop" --server "$SERVER" >"$WORK/up.log" 2>&1 &
  pids+=($!)
  sleep 3
}

# ===================================================================== GATE A ==
# NEGATIVE: no shell grant yet, acceptor serving shell. Refused, nonzero, reason
# names the capability.
say A
start_acceptor 1
OUTA=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo SHOULD-NOT-RUN' 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (no-cap) rc=$rcA out='$OUTA'"
if [ "$rcA" != "0" ] \
   && ! echo "$OUTA" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/A.err"; then
  ok "gateA: no-cap device REFUSED a shell (nonzero + reason)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: no-cap refusal NOT clean (rc=$rcA)"
fi

# ==================================================================== GATE A1 ==
# The SAME refusal, read for what it tells the user: the acceptor IS serving
# (FILAMENT_L2=1), so "serving is off" would be false; the cause is the missing
# grant and the fix is one command on boxB, naming boxA as boxB knows it.
say A1
if grep -q "tunlion grant boxA shell" "$WORK/A.err" \
   && ! grep -qi "serving is off" "$WORK/A.err"; then
  ok "gateA1: no-cap refusal names the grant fix (tunlion grant boxA shell), not 'serving is off'"
else
  echo "-- A.err --"; cat "$WORK/A.err"
  bad "gateA1: no-cap refusal did not name the precise cause and fix"
fi

# ===================================================================== grant ===
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# ===================================================================== GATE B ==
# POSITIVE: granted, one-shot exec returns the command output, rc=0.
say B
OUTB=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo HELLO' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (granted) rc=$rcB out='$OUTB'"
if [ "$rcB" = "0" ] && echo "$OUTB" | grep -q "HELLO"; then
  ok "gateB: granted shell ran a remote command (rc=0, output)"
else
  echo "-- B.err --"; cat "$WORK/B.err"; tail -5 "$WORK/up.log"
  bad "gateB: granted shell FAILED (rc=$rcB)"
fi

# ===================================================================== GATE A2 ==
# POSITIVE via daemon: the same one-shot, but routed through an
# initiator-side daemon (warm path) instead of a cold establish. Used to
# fail with "peer closed the shell request" although the acceptor granted
# (inbound L2 frames misrouted on a non-serving daemon closed the verify
# pipe). Asserts CLIENT rc/output, never the server log.
say A2
# Own PID variable (NOT pids+=): gate E kills pids[-1] expecting the
# acceptor, and a lingering initiator daemon would also reroute later
# gates onto the warm path. Clean up at the end of this gate.
env FILAMENT_CONFIG_DIR="$DA" FILAMENT_NAME=boxA "$BIN" up --dir "$WORK/Adrop" --server "$SERVER" >"$WORK/upA.log" 2>&1 &
ADPID=$!
sleep 3
OUTA2=$(timeout 40 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo DAEMON-WARM-OK' 2>"$WORK/A2.err" </dev/null)
rcA2=$?
kill "$ADPID" 2>/dev/null
wait "$ADPID" 2>/dev/null
echo "## (daemon warm) rc=$rcA2 out='$OUTA2'"
if [ "$rcA2" = "0" ] && echo "$OUTA2" | grep -q "DAEMON-WARM-OK"; then
  ok "gateA2: daemon-mediated one-shot shell ran (rc=0, output)"
else
  echo "-- A2.err --"; cat "$WORK/A2.err"; tail -5 "$WORK/up.log"
  bad "gateA2: daemon-mediated one-shot FAILED (rc=$rcA2 out='$OUTA2')"
fi

# ===================================================================== GATE C ==
# NEIGHBOUR: `-- true` must stay exit 0, empty, NOT a denial.
say C
OUTC=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'true' 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (-- true) rc=$rcC out='$OUTC'"
if [ "$rcC" = "0" ] && [ -z "$OUTC" ]; then
  ok "gateC: -- true stayed exit 0 with no output (not a false denial)"
else
  echo "-- C.err --"; cat "$WORK/C.err"
  bad "gateC: -- true mis-reported (rc=$rcC)"
fi

# ===================================================================== GATE D ==
# NEGATIVE: revoke the grant, then the same shell is refused.
say D
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTD=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo AFTER' 2>"$WORK/D.err" </dev/null)
rcD=$?
echo "## (revoked) rc=$rcD out='$OUTD'"
if [ "$rcD" != "0" ] \
   && ! echo "$OUTD" | grep -q "AFTER" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/D.err"; then
  ok "gateD: revoked shell REFUSED (nonzero + reason)"
else
  echo "-- D.err --"; cat "$WORK/D.err"; tail -5 "$WORK/up.log"
  bad "gateD: revoked shell NOT refused (rc=$rcD)"
fi

# ===================================================================== GATE E ==
# NEGATIVE: acceptor OFF (plain `up`, no --shell) and NO shell grant on it (gate D
# revoked the only one). The initiator is told the acceptor is not serving.
say E
kill "${pids[-1]}" 2>/dev/null; sleep 1   # stop the --shell acceptor
start_acceptor 0                           # plain up
OUTE=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo X' 2>"$WORK/E.err" </dev/null)
rcE=$?
echo "## (acceptor off) rc=$rcE out='$OUTE'"
# Message is "shell serving is off there..." since the acceptor wording change;
# match it alongside the older variants.
if [ "$rcE" != "0" ] && ! echo "$OUTE" | grep -q "^X$" \
   && grep -qi "acceptor off\|not serving\|serving is off" "$WORK/E.err"; then
  ok "gateE: acceptor-off shell REFUSED with 'acceptor off' reason (nonzero)"
else
  echo "-- E.err --"; cat "$WORK/E.err"; tail -5 "$WORK/up.log"
  bad "gateE: acceptor-off refusal NOT clean (rc=$rcE)"
fi

# ==================================================================== GATE E2 ==
# LIVE: grant on the RUNNING plain daemon (#219 repro order), no restart. The
# grant must apply at once, and the grant command must say no restart is needed.
say E2
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant2.log" 2>&1
OUTE2=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" shell boxB -- 'echo LIVE-GRANT-OK' 2>"$WORK/E2.err" </dev/null)
rcE2=$?
echo "## (granted live, no restart) rc=$rcE2 out='$OUTE2'"
if [ "$rcE2" = "0" ] && echo "$OUTE2" | grep -q "LIVE-GRANT-OK" \
   && grep -q "no restart needed" "$WORK/grant2.log"; then
  ok "gateE2: a grant on the running daemon applied without a restart (rc=0, output)"
else
  echo "-- grant2.log --"; cat "$WORK/grant2.log"
  echo "-- E2.err --"; cat "$WORK/E2.err"; tail -5 "$WORK/up.log"
  bad "gateE2: grant did not apply to the running daemon (rc=$rcE2)"
fi

# ===================================================================== GATE F ==
# `up --detach` with DIFFERENT flags while a daemon runs: must not block, must
# not claim success, must name the restart. The plain daemon above is running.
# The restart must carry EVERY daemon flag, --server included (#391's argv):
# without it the restarted daemon would go to the default server.
say F
t0=$(date +%s)
timeout 20 env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB "$BIN" --server "$SERVER" \
  up --detach --shell --i-know >"$WORK/F.out" 2>&1 </dev/null
rcF=$?
tF=$(( $(date +%s) - t0 ))
echo "## (up --detach --shell over a plain daemon) rc=$rcF in ${tF}s"
if [ "$rcF" = "10" ] \
   && grep -q "different settings" "$WORK/F.out" \
   && grep -qF "tunlion down --yes && tunlion up --detach --server=$SERVER --shell --i-know" "$WORK/F.out" \
   && ! grep -q "following its log" "$WORK/F.out"; then
  ok "gateF: up --detach with new flags returned at once (exit 10) and named the restart"
else
  echo "-- F.out --"; cat "$WORK/F.out"
  bad "gateF: up --detach with new flags blocked or misreported (rc=$rcF)"
fi

# ==================================================================== GATE F2 ==
say F2
timeout 20 env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB "$BIN" --server "$SERVER" \
  up --detach >"$WORK/F2.out" 2>&1 </dev/null
rcF2=$?
echo "## (up --detach, same settings) rc=$rcF2"
if [ "$rcF2" = "0" ] && grep -q "already running" "$WORK/F2.out" \
   && ! grep -q "following its log" "$WORK/F2.out"; then
  ok "gateF2: up --detach over a matching daemon returned at once (exit 0)"
else
  echo "-- F2.out --"; cat "$WORK/F2.out"
  bad "gateF2: up --detach over a matching daemon blocked or failed (rc=$rcF2)"
fi

# ==================================================================== GATE F3 ==
# The posture gap: a flag other than the shell posture, given over a daemon whose
# shell posture matches, used to read as "nothing to do" and was dropped.
say F3
timeout 20 env FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB "$BIN" --server "$SERVER" \
  up --detach --userspace >"$WORK/F3.out" 2>&1 </dev/null
rcF3=$?
echo "## (up --detach --userspace, same shell posture) rc=$rcF3"
if [ "$rcF3" = "10" ] && grep -q "different settings" "$WORK/F3.out" \
   && grep -q -- "--userspace (running without it)" "$WORK/F3.out" \
   && grep -qF "tunlion down --yes && tunlion up --detach --server=$SERVER --userspace" "$WORK/F3.out" \
   && ! grep -q "nothing to do" "$WORK/F3.out"; then
  ok "gateF3: up --detach --userspace over a kernel-overlay daemon named the unapplied flag (exit 10)"
else
  echo "-- F3.out --"; cat "$WORK/F3.out"
  bad "gateF3: --userspace over a running daemon was not reported (rc=$rcF3)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "shell gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
