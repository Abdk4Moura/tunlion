#!/usr/bin/env bash
# `tunlion exec` end-to-end gates. Standalone, hermetic, fixture port 8104 ONLY.
# Proves argv[] crosses EXACTLY (spaces/quotes/globs intact on both platforms by
# construction -- the vector is never joined, split, or re-parsed), stdout and
# stderr stay separate, exit codes surface, and real byte traffic works.
#
#   FILAMENT_BIN=/path/to/tunlion ./exec-gates.sh
#
# Gates:
#   A  NEGATIVE no-grant -- acceptor serving, initiator NOT granted: refused,
#      nonzero, reason names the capability (exercises authorize_exec live).
#   B  SPACES -- an argument with spaces arrives as ONE argv element.
#   C  QUOTES -- single and double quotes inside one argument survive byte-exact.
#   D  GLOB LITERAL -- `*.log` arrives literally (proves no shell expansion).
#   E  STDERR SPLIT -- bytes written to each stream land on the right local
#      descriptor, exit code intact.
#   F  EXIT CODES -- remote `exit 3` surfaces as our rc=3.
#   G  SIGNAL DEATH -- remote kill -9 surfaces as 137 (unix only: no portable
#      Windows equivalent exists; the 128+signal MAPPING is unit-tested).
#   H  BULK BYTES -- 1 MiB through `cat` matches local sha256 (binary-safe bulk).
#   I  RSYNC-OVER-EXEC -- real rsync across the link (skipped cleanly when rsync
#      is absent on PATH). `rsync -e '<tunlion> exec'` appends
#      `boxB rsync --server ...`, which our trailing-argv shape takes directly --
#      itself an argv-exactness proof under a real workload.
#   J  NEGATIVE revoked -- grant revoked, same command refused again.
#   K  REVOKED MID-SESSION -- a live exec ends when the grant is revoked.
#   L  SHELL-USER -- a root acceptor with `--shell-user nobody` runs the exec
#      as nobody (unix; needs root or passwordless sudo, as CI runners have).
#   M  KILL -9 THE INITIATOR -- the remote process tree is gone within 20 s.
#   N  SIGTERM THE INITIATOR (timeout 5) -- rc 124, remote gone within 5 s.
#   O  CTRL-C -- forwarded as SIGINT, rc 130, remote tree gone.
#   P  | head -2 -- the remote producer is gone within 5 s of head exiting.
#   Q1 KILL -9 THE SERVING DAEMON -- its served command is gone within 5 s,
#      with no restart (Linux: parent-death signal).
#   Q2 ...and a restarted daemon ends the tree the dead one left, then holds
#      no record of it.
#   R  FORGET -- granted exec works, then after `devices forget` the same exec
#      is refused within seconds as an unrecognized device (exit 4), with no
#      "tunnel up" claim and no "serving is off" / grant advice.
#
# PLATFORM NOTE, stated honestly: executed here on Linux. The wire property
# under test (array preserved, never re-parsed) is platform-independent code --
# no cfg branches touch the argv path -- but the test BINARIES differ per
# platform (/bin/echo vs cmd builtins). The ECHO/SH/CAT variables below are the
# single porting point; the kill-137 gate is uname-guarded to unix.
#
# Topology: side B = acceptor, side A = initiator, reciprocal pair secret
# (same-owner fleet, not a delegated device) so B trusts A.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8104
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-exec-gates.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== exec gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

# --- platform command mapping (the single porting point) ---
if uname -s | grep -qiE "mingw|msys|cygwin|windows"; then
    PLATFORM="windows"
    ECHO_BIN="cmd"; ECHO_PREFIX="/c echo"
    SH_BIN="cmd"; SH_C="/C"
    CAT_BIN="cmd"; CAT_PREFIX="/C type"
else
    PLATFORM="unix"
    ECHO_BIN="/bin/echo"; ECHO_PREFIX=""
    SH_BIN="/bin/sh"; SH_C="-c"
    CAT_BIN="/bin/cat"; CAT_PREFIX=""
fi

pids=()
cleanup() {
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

# --- own fixture backend on $PORT ---
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
for _ in $(seq 1 10); do ss -tln 2>/dev/null | grep -q ":$PORT " || break; sleep 0.1; done  # the old listener is gone (was: sleep 1)
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

start_acceptor() { # [log file name, default up.log]
  local drop="$WORK/Bdrop"; mkdir -p "$drop"
  env FILAMENT_L2=1 FILAMENT_CONFIG_DIR="$DB" FILAMENT_NAME=boxB \
    "$BIN" up --dir "$drop" --server "$SERVER" >"$WORK/${1:-up.log}" 2>&1 &
  pids+=($!)
  sleep 3
}

# ===================================================================== GATE A ==
# NEGATIVE: serving acceptor, initiator with NO grant. Refused, nonzero, reason.
say A
start_acceptor
OUTA=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" SHOULD-NOT-RUN 2>"$WORK/A.err" </dev/null)
rcA=$?
echo "## (no-grant) rc=$rcA out='$OUTA'"
if [ "$rcA" != "0" ] \
   && ! echo "$OUTA" | grep -q "SHOULD-NOT-RUN" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/A.err"; then
  ok "gateA: ungranted exec REFUSED (nonzero + reason)"
else
  echo "-- A.err --"; cat "$WORK/A.err"; tail -5 "$WORK/up.log"
  bad "gateA: ungranted exec NOT refused cleanly (rc=$rcA)"
fi

# =================================================================== grant ====
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grant.log" 2>&1
grep -q '"shell"' "$DB/devices.json" || { echo "## grant did not persist"; cat "$DB/devices.json"; }

# ===================================================================== GATE B ==
# SPACES: one argv element with spaces arrives whole.
say B
OUTB=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" 'hello world' 2>"$WORK/B.err" </dev/null)
rcB=$?
echo "## (spaces) rc=$rcB out='$OUTB'"
if [ "$rcB" = "0" ] && [ "$OUTB" = "hello world" ]; then
  ok "gateB: spaced argument arrived as ONE argv element"
else
  echo "-- B.err --"; cat "$WORK/B.err"
  bad "gateB: spaces NOT preserved (rc=$rcB out='$OUTB')"
fi

# ===================================================================== GATE C ==
# QUOTES: single and double quotes inside one argument survive byte-exact.
say C
OUTC=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" 'say "hi" and '"'"'bye'"'" 2>"$WORK/C.err" </dev/null)
rcC=$?
echo "## (quotes) rc=$rcC out='$OUTC'"
if [ "$rcC" = "0" ] && [ "$OUTC" = 'say "hi" and '"'"'bye'"'" ]; then
  ok "gateC: quotes survived byte-exact (no shell re-parse)"
else
  echo "-- C.err --"; cat "$WORK/C.err"
  bad "gateC: quotes NOT preserved (rc=$rcC out='$OUTC')"
fi

# ===================================================================== GATE D ==
# GLOB LITERAL: `*.log` arrives literally -- proves no shell expansion.
say D
OUTD=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" '*.log' 2>"$WORK/D.err" </dev/null)
rcD=$?
echo "## (glob) rc=$rcD out='$OUTD'"
if [ "$rcD" = "0" ] && [ "$OUTD" = '*.log' ]; then
  ok "gateD: glob arrived literally (no shell expansion)"
else
  echo "-- D.err --"; cat "$WORK/D.err"
  bad "gateD: glob NOT literal (rc=$rcD out='$OUTD')"
fi

# ===================================================================== GATE E ==
# STDERR SPLIT: each stream lands on the right local descriptor.
say E
OUTE=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'echo out; echo err >&2' 2>"$WORK/E.err" </dev/null)
rcE=$?
echo "## (split) rc=$rcE out='$OUTE' err='$(cat "$WORK/E.err")'"
if [ "$rcE" = "0" ] && [ "$OUTE" = "out" ] && grep -qx "err" "$WORK/E.err"; then
  ok "gateE: stdout/stderr split correctly"
else
  echo "-- E.err --"; cat "$WORK/E.err"
  bad "gateE: streams NOT split (rc=$rcE out='$OUTE')"
fi

# ================================================================== GATE E2 ==
# STDIN ROUND-TRIP: bytes on our stdin reach the remote child's stdin and
# come back (the rsync gate's precondition, isolated -- every earlier gate
# uses empty stdin).
say E2
OUTE2=$(echo "STDIN-ROUNDTRIP-67890" | timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$CAT_BIN" 2>"$WORK/E2.err")
rcE2=$?
echo "## (stdin) rc=$rcE2 out='$OUTE2'"
if [ "$rcE2" = "0" ] && [ "$OUTE2" = "STDIN-ROUNDTRIP-67890" ]; then
  ok "gateE2: stdin bytes reached the remote child and returned"
else
  echo "-- E2.err --"; cat "$WORK/E2.err"
  bad "gateE2: stdin round-trip FAILED (rc=$rcE2 out='$OUTE2')"
fi

# ================================================================== GATE E3 ==
# EPIPE: a flooded stdin against an early-exiting child (`yes | head -1`)
# must end cleanly (output + rc 0), not hang: a write error to the dead
# child's stdin is treated as EOF and the loop still waits for its exit.
say E3
yes | timeout 20 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- head -n 1 >"$WORK/E3.out" 2>"$WORK/E3.err"
rcE3=${PIPESTATUS[1]}
OUTE3=$(cat "$WORK/E3.out")
echo "## (epipe) rc=$rcE3 out='$OUTE3'"
if [ "$rcE3" = "0" ] && [ "$OUTE3" = "y" ]; then
  ok "gateE3: flooded stdin vs early exit ended cleanly (output + rc 0)"
else
  echo "-- E3.err --"; cat "$WORK/E3.err"
  bad "gateE3: EPIPE case hung or mis-reported (rc=$rcE3 out='$OUTE3')"
fi

# ===================================================================== GATE F ==
# EXIT CODES: remote exit status becomes our exit code.
say F
timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'exit 3' 2>"$WORK/F.err" </dev/null
rcF=$?
echo "## (exit 3) rc=$rcF"
if [ "$rcF" = "3" ]; then
  ok "gateF: remote exit 3 surfaced as our rc=3"
else
  echo "-- F.err --"; cat "$WORK/F.err"
  bad "gateF: exit code NOT surfaced (rc=$rcF)"
fi

# ===================================================================== GATE G ==
# SIGNAL DEATH -> 137. Unix only: no portable Windows equivalent exists, and
# the 128+signal MAPPING itself is unit-tested (status_mapping_is_shell_convention).
say G
if [ "$PLATFORM" = "unix" ]; then
  timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SH_BIN" "$SH_C" 'kill -9 $$' 2>"$WORK/G.err" </dev/null
  rcG=$?
  echo "## (kill -9) rc=$rcG"
  if [ "$rcG" = "137" ]; then
    ok "gateG: signal death surfaced as 137 (128+SIGKILL)"
  else
    echo "-- G.err --"; cat "$WORK/G.err"
    bad "gateG: signal death NOT 137 (rc=$rcG)"
  fi
else
  echo "SKIP gateG: signal-death has no portable Windows equivalent (mapping is unit-tested)"
fi

# ===================================================================== GATE H ==
# BULK BYTES: 1 MiB through `cat` matches local sha256 (binary-safe bulk).
say H
head -c 1048576 /dev/urandom > "$WORK/bulk.bin"
sha256sum "$WORK/bulk.bin" | awk '{print $1}' > "$WORK/bulk.want"
timeout 60 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$CAT_BIN" "$WORK/bulk.bin" 2>"$WORK/H.err" </dev/null | sha256sum | awk '{print $1}' > "$WORK/bulk.got"
rcH=${PIPESTATUS[0]}
echo "## (bulk) rc=$rcH"
if [ "$rcH" = "0" ] && cmp -s "$WORK/bulk.want" "$WORK/bulk.got"; then
  ok "gateH: 1 MiB bulk bytes match sha256"
else
  echo "-- H.err --"; cat "$WORK/H.err"
  bad "gateH: bulk bytes MISMATCH (rc=$rcH)"
fi

# ===================================================================== GATE I ==
# RSYNC-OVER-EXEC: real rsync across the link; skipped cleanly without rsync.
say I
if command -v rsync >/dev/null 2>&1; then
  mkdir -p "$WORK/rsrc" "$WORK/rdest"
  echo "rsync-payload-$(date +%s)" > "$WORK/rsrc/payload.txt"
  timeout 60 ${A_ENV[@]} rsync -av -e "$BIN --server $SERVER exec" "$WORK/rsrc/" "boxB:$WORK/rdest/" >"$WORK/I.log" 2>&1
  rcI=$?
  echo "## (rsync) rc=$rcI"
  if [ "$rcI" = "0" ] && cmp -s "$WORK/rsrc/payload.txt" "$WORK/rdest/payload.txt"; then
    ok "gateI: rsync-over-exec transferred byte-identical"
  else
    echo "-- I.log --"; cat "$WORK/I.log"
    bad "gateI: rsync-over-exec FAILED (rc=$rcI)"
  fi
else
  echo "SKIP gateI: no rsync on PATH"
fi

# ============================================================ LIFETIME GATES ==
# A remote command never outlives its initiator. Before, `exec boxB -- sleep
# 300` killed locally (kill -9 OR a plain SIGTERM from `timeout`) left the
# sleep running as a child of boxB's daemon for the full five minutes, and a
# `seq` behind `| head -2` was still producing 19 s after head exited. Unix
# only: the gates find the remote processes with pgrep by their exact argv
# (both ends share this host, so the patterns are anchored at the program path
# and never match the initiator's own `tunlion exec ...` command line).
gone_within() { # <seconds> <pgrep -f pattern>...: 0 once none of them match
  local secs=$1; shift
  local end=$(( $(date +%s) + secs ))
  while :; do
    local alive=0
    for pat in "$@"; do pgrep -f -- "$pat" >/dev/null 2>&1 && alive=1; done
    [ "$alive" = 0 ] && return 0
    [ "$(date +%s)" -ge "$end" ] && return 1
    sleep 0.25
  done
}
started_within() { # <seconds> <pattern>: 0 once it matches
  local secs=$1 pat=$2
  local end=$(( $(date +%s) + secs ))
  until pgrep -f -- "$pat" >/dev/null 2>&1; do
    [ "$(date +%s)" -ge "$end" ] && return 1
    sleep 0.25
  done
}

# ===================================================================== GATE M ==
# KILL -9 THE INITIATOR: the remote TREE (a shell, a backgrounded child and a
# foreground child) is gone within 20 s. Nothing reaches the acceptor from a
# SIGKILLed process, so this is the heartbeat bound, and the backgrounded
# child proves the whole process group is ended, not only its leader.
say M
if [ "$PLATFORM" = "unix" ]; then
  "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sh -c '/bin/sleep 3011 & /bin/sleep 3012; wait' \
    >/dev/null 2>"$WORK/M.err" </dev/null &
  MPid=$!
  if started_within 30 '^/bin/sleep 3012$'; then
    kill -9 "$MPid" 2>/dev/null; wait "$MPid" 2>/dev/null
    t0=$(date +%s)
    if gone_within 20 '^/bin/sleep 3011$' '^/bin/sleep 3012$'; then
      ok "gateM: kill -9 of the initiator ended the whole remote tree in $(( $(date +%s) - t0 ))s"
    else
      echo "-- M.err --"; cat "$WORK/M.err"; tail -15 "$WORK/up.log"
      pkill -f '^/bin/sleep 301[12]$' 2>/dev/null
      bad "gateM: the remote tree outlived a SIGKILLed initiator by 20s"
    fi
  else
    kill -9 "$MPid" 2>/dev/null
    echo "-- M.err --"; cat "$WORK/M.err"
    bad "gateM: the remote command never started"
  fi
else
  echo "SKIP gateM: the remote process check uses pgrep (unix)"
fi

# ===================================================================== GATE N ==
# SIGTERM THE INITIATOR (`timeout 5`, the tester's exact shape): rc 124, and the
# remote sleep is gone within 5 s, because the initiator forwards the signal
# and closes the session before it exits rather than waiting on a heartbeat.
say N
if [ "$PLATFORM" = "unix" ]; then
  timeout 5 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sleep 3013 \
    >/dev/null 2>"$WORK/N.err" </dev/null
  rcN=$?
  t0=$(date +%s)
  if [ "$rcN" = "124" ] && gone_within 5 '^/bin/sleep 3013$'; then
    ok "gateN: SIGTERM to the initiator ended the remote command in $(( $(date +%s) - t0 ))s (rc=$rcN)"
  else
    echo "-- N.err --"; cat "$WORK/N.err"; tail -15 "$WORK/up.log"
    pkill -f '^/bin/sleep 3013$' 2>/dev/null
    bad "gateN: the remote command outlived a SIGTERMed initiator (rc=$rcN)"
  fi
else
  echo "SKIP gateN: the remote process check uses pgrep (unix)"
fi

# ===================================================================== GATE O ==
# CTRL-C: SIGINT to the initiator reaches the remote command as SIGINT (a
# trap there sees it), the initiator exits 130, and nothing is left running.
say O
if [ "$PLATFORM" = "unix" ]; then
  MARK="$WORK/O.int"
  "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sh -c \
    "trap 'echo INT > $MARK; exit 130' INT; /bin/sleep 3014 & wait" \
    >/dev/null 2>"$WORK/O.err" </dev/null &
  OPid=$!
  if started_within 30 '^/bin/sleep 3014$'; then
    sleep 1
    kill -INT "$OPid" 2>/dev/null
    wait "$OPid"; rcO=$?
    gone_within 5 '^/bin/sleep 3014$'; goneO=$?
    if [ "$rcO" = "130" ] && [ "$goneO" = "0" ] && [ -s "$MARK" ]; then
      ok "gateO: Ctrl-C was forwarded as SIGINT, rc=130, remote tree gone"
    else
      echo "-- O.err --"; cat "$WORK/O.err"; tail -15 "$WORK/up.log"
      pkill -f '^/bin/sleep 3014$' 2>/dev/null
      bad "gateO: Ctrl-C not forwarded (rc=$rcO gone=$goneO trap=$( [ -s "$MARK" ] && echo yes || echo no))"
    fi
  else
    kill -9 "$OPid" 2>/dev/null
    echo "-- O.err --"; cat "$WORK/O.err"
    bad "gateO: the remote command never started"
  fi
else
  echo "SKIP gateO: the remote process check uses pgrep (unix)"
fi

# ===================================================================== GATE P ==
# A CLOSED LOCAL STDOUT: `exec ... | head -2` prints two lines, and the remote
# producer is gone within 5 s of head exiting (EPIPE semantics over the link),
# not still counting toward ten million.
say P
if [ "$PLATFORM" = "unix" ] && command -v seq >/dev/null 2>&1; then
  SEQ=$(command -v seq)
  OUTP=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$SEQ" 1 99999917 2>"$WORK/P.err" </dev/null | head -2)
  t0=$(date +%s)
  if [ "$OUTP" = "$(printf '1\n2')" ] && gone_within 5 "^$SEQ 1 99999917\$"; then
    ok "gateP: | head -2 printed two lines and the remote producer was gone in $(( $(date +%s) - t0 ))s"
  else
    echo "-- P.err --"; cat "$WORK/P.err"; tail -15 "$WORK/up.log"
    pkill -f "^$SEQ 1 99999917\$" 2>/dev/null
    bad "gateP: the remote producer outlived a closed local stdout (out='$OUTP')"
  fi
else
  echo "SKIP gateP: needs unix and seq"
fi

# ===================================================================== GATE J ==
# NEGATIVE revoked: same command refused again after revoke.
say J
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revoke.log" 2>&1
OUTJ=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" AFTER 2>"$WORK/J.err" </dev/null)
rcJ=$?
echo "## (revoked) rc=$rcJ out='$OUTJ'"
if [ "$rcJ" != "0" ] \
   && ! echo "$OUTJ" | grep -q "AFTER" \
   && grep -qi "refused\|not granted\|no shell cap" "$WORK/J.err"; then
  ok "gateJ: revoked exec REFUSED (nonzero + reason)"
else
  echo "-- J.err --"; cat "$WORK/J.err"
  bad "gateJ: revoked exec NOT refused (rc=$rcJ)"
fi

# ===================================================================== GATE K ==
# REVOKED MID-SESSION: a long exec dies (nonzero + revoked reason) when the
# shell grant is revoked underneath it -- the receiver ticker re-asks the
# gate instead of letting the child run out its clock.
say K
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grantK.log" 2>&1
timeout 40 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sleep 30 2>"$WORK/K.err" </dev/null &
KPid=$!
sleep 5
env FILAMENT_CONFIG_DIR="$DB" "$BIN" revoke boxA shell -y >"$WORK/revokeK.log" 2>&1
wait "$KPid"
rcK=$?
echo "## (revoked mid-session) rc=$rcK"
if [ "$rcK" != "0" ] && [ "$rcK" != "124" ] && grep -qi "revoked" "$WORK/K.err"; then
  ok "gateK: mid-session revoke ended the exec (nonzero + reason)"
else
  echo "-- K.err --"; cat "$WORK/K.err"
  bad "gateK: revoked session NOT ended (rc=$rcK)"
fi

# ===================================================================== GATE Q ==
# KILL -9 THE SERVING DAEMON: nothing it served outlives it. Found by the blind
# acceptance run: `exec alpha -- sleep 304`, then `kill -9` of alpha's daemon,
# left the sleep running with PPID 1, and it survived a fresh `up`. Two shapes
# at once. Q1, a lone command (the reported one): gone within 5 s of the kill,
# with no restart (the kernel's parent-death signal, Linux). Q2, a tree whose
# leader forked: the leader is gone with Q1, and the children it left are
# ended by the NEXT daemon at its start, which also finds nothing left over
# afterwards (the served-groups record is cleared).
say Q
if [ "$PLATFORM" = "unix" ] && [ "$(uname -s)" = "Linux" ]; then
  env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grantQ.log" 2>&1
  "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sleep 3017 \
    >/dev/null 2>"$WORK/Q1.err" </dev/null &
  Q1Pid=$!
  "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- /bin/sh -c '/bin/sleep 3018 & /bin/sleep 3019; wait' \
    >/dev/null 2>"$WORK/Q2.err" </dev/null &
  Q2Pid=$!
  if started_within 30 '^/bin/sleep 3017$' && started_within 30 '^/bin/sleep 3019$'; then
    DPID=$(cat "$DB/up.pid" 2>/dev/null)
    GROUPS_BEFORE=$(wc -l <"$DB/exec.groups" 2>/dev/null || echo 0)
    kill -9 "$DPID" 2>/dev/null
    t0=$(date +%s)
    gone_within 5 '^/bin/sleep 3017$'; goneQ1=$?
    gone_within 5 "^/bin/sh -c /bin/sleep 3018 & /bin/sleep 3019; wait\$"; goneLeader=$?
    echo "## (kill -9 daemon pid=$DPID) recorded groups=$GROUPS_BEFORE lone gone=$goneQ1 leader gone=$goneLeader after $(( $(date +%s) - t0 ))s"
    if [ "$goneQ1" = "0" ] && [ "$goneLeader" = "0" ] && [ "$GROUPS_BEFORE" -ge 2 ]; then
      ok "gateQ1: kill -9 of the serving daemon ended its served command in $(( $(date +%s) - t0 ))s, no restart"
    else
      ps -eo pid,ppid,pgid,args | grep -E '/bin/sleep 301[789]|sleep 3018' | grep -v grep
      bad "gateQ1: a served command outlived the SIGKILLed daemon (lone gone=$goneQ1 leader gone=$goneLeader groups=$GROUPS_BEFORE)"
    fi
    kill -9 "$Q1Pid" "$Q2Pid" 2>/dev/null; wait "$Q1Pid" "$Q2Pid" 2>/dev/null
    start_acceptor up-Q.log
    t1=$(date +%s)
    gone_within 10 '^/bin/sleep 3018$' '^/bin/sleep 3019$'; goneQ2=$?
    if [ "$goneQ2" = "0" ] && [ ! -e "$DB/exec.groups" ] \
       && grep -q "remote command(s) a previous daemon left running" "$WORK/up-Q.log"; then
      ok "gateQ2: the restarted daemon ended the dead daemon's leftover tree and holds no record after"
    else
      ps -eo pid,ppid,pgid,args | grep -E '/bin/sleep 301[89]' | grep -v grep
      echo "-- up-Q.log --"; head -20 "$WORK/up-Q.log"; ls -la "$DB/exec.groups" 2>/dev/null
      bad "gateQ2: leftovers survived the restart (gone=$goneQ2 record=$([ -e "$DB/exec.groups" ] && echo kept || echo cleared))"
    fi
    pkill -f '^/bin/sleep 301[789]$' 2>/dev/null
  else
    kill -9 "$Q1Pid" "$Q2Pid" 2>/dev/null
    echo "-- Q1.err --"; cat "$WORK/Q1.err"; echo "-- Q2.err --"; cat "$WORK/Q2.err"
    bad "gateQ1: the remote commands never started"
    bad "gateQ2: the remote commands never started"
  fi
else
  echo "SKIP gateQ1/Q2: the parent-death signal and /proc process checks are Linux"
fi

# ===================================================================== GATE R ==
# FORGET ENDS EXEC, AS AN IDENTITY REFUSAL. Found by the blind acceptance run:
# after `devices forget bravo`, bravo's exec printed "tunnel up to 'alpha'" and
# alpha refused with "shell serving is off", a fix that cannot apply to a
# device alpha no longer knows. Positive control first (granted, exec runs),
# then the forget, then the same exec: refused within seconds, exit 4
# (denied), naming the identity, with no "tunnel up" claim and nothing run.
say R
env FILAMENT_CONFIG_DIR="$DB" "$BIN" grant boxA shell >"$WORK/grantR.log" 2>&1
OUTR0=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" BEFORE-FORGET 2>"$WORK/R0.err" </dev/null)
rcR0=$?
cp "$DB/devices.json" "$WORK/devices.before-forget.json"
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$SERVER" devices forget boxA -y >"$WORK/forgetR.log" 2>&1
rcRF=$?
sleep 3
t0=$(date +%s)
OUTR=$(timeout 40 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- "$ECHO_BIN" SHOULD-NOT-RUN 2>"$WORK/R.err" </dev/null)
rcR=$?
elR=$(( $(date +%s) - t0 ))
echo "## (before forget) rc=$rcR0 out='$OUTR0'; (forget) rc=$rcRF; (after forget) rc=$rcR in ${elR}s out='$OUTR'"
if [ "$rcR0" = "0" ] && [ "$OUTR0" = "BEFORE-FORGET" ] && [ "$rcRF" = "0" ] \
   && [ "$rcR" = "4" ] && [ "$elR" -lt 20 ] \
   && ! echo "$OUTR" | grep -q "SHOULD-NOT-RUN" \
   && grep -q "not recognized" "$WORK/R.err" \
   && ! grep -qi "tunnel up\|serving is off\|tunlion grant" "$WORK/R.err"; then
  ok "gateR: after forget, exec was refused as an unrecognized device in ${elR}s (exit 4, no tunnel claim, nothing ran)"
else
  echo "-- R0.err --"; cat "$WORK/R0.err"; echo "-- forgetR.log --"; cat "$WORK/forgetR.log"
  echo "-- R.err --"; cat "$WORK/R.err"; tail -15 "$WORK/up-Q.log" 2>/dev/null
  bad "gateR: a forgotten device's exec was not refused as unrecognized (before rc=$rcR0, after rc=$rcR in ${elR}s)"
fi
# Gate L below re-uses boxB's pairing with boxA.
cp "$WORK/devices.before-forget.json" "$DB/devices.json"

# ===================================================================== GATE L ==
# --shell-user REACHES EXEC: a ROOT acceptor started with `--shell-user nobody`
# must run `exec -- id -un` as nobody. Before the fix exec ignored the flag and
# spawned as the daemon user (root), while help and the security doc promised
# the drop. Unix only (Windows refuses exec under --shell-user instead; that
# decision is unit-tested). Needs root: on a box with neither root nor
# passwordless sudo the gate is skipped, and CI's count assertion catches that.
# The root daemon gets its OWN config dir (root-owned files would break the
# other gates' dir) and an isolated HOME, so it writes nothing of the runner's.
say L
if [ "$PLATFORM" != "unix" ]; then
  echo "SKIP gateL: --shell-user exec drop is unix only (refusal is unit-tested)"
elif [ "$(id -u)" != "0" ] && ! sudo -n true 2>/dev/null; then
  echo "SKIP gateL: needs root or passwordless sudo"
else
  if [ "$(id -u)" = "0" ]; then AS_ROOT=(); else AS_ROOT=(sudo -n); fi
  # Stop the unprivileged acceptor so only the root one answers as boxB (the
  # backend in $pids keeps running; the acceptor is matched by its drop dir).
  for p in $(pgrep -f -- "--dir $WORK/Bdrop" 2>/dev/null); do kill "$p" 2>/dev/null; done
  sleep 2
  DR="$WORK/Broot"; RHOME="$WORK/Broot-home"; RDROP="$WORK/Broot-drop"
  mkdir -p "$DR" "$RHOME" "$RDROP"
  cp "$DB/devices.json" "$DR/devices.json"
  "${AS_ROOT[@]}" env HOME="$RHOME" XDG_CONFIG_HOME="$RHOME/.config" FILAMENT_CONFIG_DIR="$DR" \
    "$BIN" grant boxA shell >"$WORK/grantL.log" 2>&1
  "${AS_ROOT[@]}" env HOME="$RHOME" XDG_CONFIG_HOME="$RHOME/.config" FILAMENT_L2=1 \
    FILAMENT_CONFIG_DIR="$DR" FILAMENT_NAME=boxB \
    "$BIN" up --dir "$RDROP" --server "$SERVER" --shell-user nobody >"$WORK/upL.log" 2>&1 &
  sleep 4
  OUTL=$(timeout 30 "${A_ENV[@]}" "$BIN" --server "$SERVER" exec boxB -- id -un 2>"$WORK/L.err" </dev/null)
  rcL=$?
  echo "## (--shell-user nobody) rc=$rcL out='$OUTL'"
  if [ "$rcL" = "0" ] && [ "$OUTL" = "nobody" ]; then
    ok "gateL: exec under --shell-user nobody ran as nobody"
  else
    echo "-- L.err --"; cat "$WORK/L.err"; echo "-- upL.log --"; tail -20 "$WORK/upL.log"
    bad "gateL: exec did NOT run as the --shell-user account (rc=$rcL out='$OUTL')"
  fi
  # The daemon is root's: stop it as root. Matched by its unique drop dir.
  for p in $(pgrep -f -- "--dir $RDROP" 2>/dev/null); do "${AS_ROOT[@]}" kill "$p" 2>/dev/null; done
  sleep 1
  "${AS_ROOT[@]}" chown -R "$(id -u):$(id -g)" "$DR" "$RHOME" "$RDROP" 2>/dev/null
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "exec gates: $PASS passed, $FAIL failed${FAILED:+ — failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
