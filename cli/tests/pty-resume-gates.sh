#!/usr/bin/env bash
# A shell must outlive the link it was opened on, without losing or repeating
# output, and a detached shell must still answer to the gate. Standalone,
# hermetic, fixture port 8181 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./pty-resume-gates.sh
#
# The link is broken by SIGSTOPping the CLIENT past the direct link's idle
# timeout (21 s): the acceptor sees the link die and detaches the session, the
# client sees its own transport dead on SIGCONT and reattaches. The remote
# command prints a numbered tick every second, so "intact" is checkable: every
# tick from 1 to the last one appears, in order, exactly once.
#
# Gates:
#   R1  the session survives a link replacement: ticks keep coming after it
#   R2  output is intact: ticks are contiguous, none missing, none repeated
#       (a reattach that replays the whole buffer repeats; one that loses the
#       detached period has a gap)
#   X1  a second device asking for the same session name gets its own shell,
#       never the first device's (sessions are scoped to the proven device)
#   X2  ...and the first device's detached shell is untouched by that ask
#   V1  a detached shell keeps running while nobody is attached (control)
#   V2  revoking the device ends its DETACHED shell within the recheck bound,
#       not at the end of the detach window
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8181
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-pty-resume.XXXXXX")"
DA="$WORK/A"
DETACH_WAIT=35   # > the 21 s direct-link idle timeout, so the acceptor detaches
GRACE=12         # > the revoke recheck interval, with slack for a slow box

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

command -v script >/dev/null || fixture_die "setup: util-linux 'script' is needed to give the client a terminal"

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow shell
enroll_delegate charlie --allow shell

# Run `tunlion shell alpha -- <cmd>` for device $1 on a real terminal (the
# resuming path needs one), recording the terminal to $2 and the CLIENT's pid
# to $2.pid. $4, when given, names the session (TUNLION_SHELL_SESSION).
tty_shell() {
  local dev="$1" out="$2" cmd="$3" session="${4:-}"
  local inner
  inner=$(printf 'echo $$ > %q; exec env TUNLION_SHELL_SESSION=%q TUNLION_CONFIG_DIR=%q %q --server %q shell alpha -- %q' \
    "$out.pid" "$session" "$WORK/$dev" "$BIN" "$SERVER" "$cmd")
  script -qfec "sh -c $(printf '%q' "$inner")" "$out" >/dev/null 2>&1 &
  FIX_PIDS+=($!)
  echo $! > "$out.spid"
  local i
  for i in $(seq 1 50); do [ -s "$out.pid" ] && break; sleep 0.2; done
  FIX_PIDS+=("$(cat "$out.pid" 2>/dev/null)")
}

# Stop and continue the CLIENT. util-linux `script` mirrors a stopped child by
# stopping itself, and then nobody would copy the client's output to the file,
# so it is continued too.
client_stop() { kill -STOP "$(cat "$1.pid")"; }
client_cont() { kill -CONT "$(cat "$1.pid")" "$(cat "$1.spid")" 2>/dev/null; }

wait_for() {  # $1 = seconds, $2 = file, $3 = extended regex
  local i
  for i in $(seq 1 "$1"); do grep -qE "$3" "$2" 2>/dev/null && return 0; sleep 1; done
  return 1
}

file_age() { echo $(( $(date +%s) - $(stat -c %Y "$1" 2>/dev/null || echo 0) )); }

# ===================================================================== R1/R2 ==
say "R1/R2"
tty_shell bravo "$WORK/r.tty" 'for i in $(seq 1 120); do echo TICK-$i; sleep 1; done'
RPID=$(cat "$WORK/r.tty.pid")
if ! wait_for 30 "$WORK/r.tty" 'TICK-5'; then
  bad "R1: the shell never streamed, the rest proves nothing"
  tail -c 600 "$WORK/r.tty"
  declare_known_red_summary; exit 1
fi
client_stop "$WORK/r.tty"
stopped_at=$(grep -oE 'TICK-[0-9]+' "$WORK/r.tty" | tail -1 | cut -d- -f2)
echo "## client stopped after TICK-$stopped_at; holding ${DETACH_WAIT}s"
sleep "$DETACH_WAIT"
client_cont "$WORK/r.tty"
target=$((stopped_at + DETACH_WAIT + 10))
if wait_for 60 "$WORK/r.tty" "TICK-$target\b"; then
  ok "R1: the shell survived the link replacement (TICK-$target arrived after it)"
else
  bad "R1: no tick past the break arrived within 60s"
  tail -c 800 "$WORK/r.tty" | tr -d '\r'
fi
kill "$RPID" 2>/dev/null
ticks=$(grep -oE 'TICK-[0-9]+' "$WORK/r.tty" | cut -d- -f2)
n=$(printf '%s\n' "$ticks" | grep -c .)
max=$(printf '%s\n' "$ticks" | sort -n | tail -1)
dups=$(printf '%s\n' "$ticks" | sort -n | uniq -d | tr '\n' ' ')
expected=$(seq 1 "${max:-0}" | tr '\n' ' ')
got=$(printf '%s\n' "$ticks" | tr '\n' ' ')
echo "## ticks seen: $n, highest $max, repeated: [${dups}]"
if [ "${max:-0}" -le "$stopped_at" ]; then
  bad "R2: nothing arrived after the break, so intactness across it is unproven"
elif [ -n "$dups" ]; then
  bad "R2: output repeated after the reattach (ticks seen twice: $dups)"
elif [ "$got" != "$expected" ]; then
  bad "R2: output has a gap or is out of order"
  echo "   got:      $got" | cut -c1-400
else
  ok "R2: output intact across the reattach (TICK-1..TICK-$max, each exactly once)"
fi

# ===================================================================== X1/X2 ==
say "X1/X2"
tty_shell bravo "$WORK/x.tty" \
  "echo BRAVO-MARK; while :; do date +%s > $WORK/beat-x; sleep 1; done" shared
XPID=$(cat "$WORK/x.tty.pid")
wait_for 30 "$WORK/x.tty" 'BRAVO-MARK' || fixture_die "X1: setup: bravo's named shell never started"
client_stop "$WORK/x.tty"
sleep "$DETACH_WAIT"
out=$(fs_bounded 45 env TUNLION_SHELL_SESSION=shared TUNLION_CONFIG_DIR="$WORK/charlie" \
  "$BIN" --server "$SERVER" shell alpha -- 'echo CHARLIE-RAN')
if printf '%s' "$out" | grep -q 'BRAVO-MARK'; then
  bad "X1: charlie asked for session 'shared' and got bravo's shell"
elif printf '%s' "$out" | grep -q 'CHARLIE-RAN'; then
  ok "X1: the same session name on another device opened that device's own shell"
else
  bad "X1: charlie's shell did not run (state $(fs_state)): $(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
fi
age=$(file_age "$WORK/beat-x")
if [ "$age" -le 4 ]; then
  ok "X2: bravo's detached shell kept running through charlie's ask (beat ${age}s old)"
else
  bad "X2: bravo's detached shell stopped (beat ${age}s old)"
fi
client_cont "$WORK/x.tty"; kill "$XPID" 2>/dev/null

# ===================================================================== V1/V2 ==
say "V1/V2"
tty_shell bravo "$WORK/v.tty" "while :; do date +%s > $WORK/beat-v; sleep 1; done"
VPID=$(cat "$WORK/v.tty.pid")
for i in $(seq 1 30); do [ -s "$WORK/beat-v" ] && break; sleep 1; done
client_stop "$WORK/v.tty"
sleep "$DETACH_WAIT"
age=$(file_age "$WORK/beat-v")
if [ "$age" -le 4 ]; then
  ok "V1: the detached shell keeps running with nobody attached (beat ${age}s old)"
else
  bad "V1: the shell died when its link did (beat ${age}s old); V2 would prove nothing"
fi
env TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" revoke bravo --certificate --yes >"$WORK/revoke.out" 2>&1
revoke_rc=$?
sleep "$GRACE"
age=$(file_age "$WORK/beat-v")
if [ "$revoke_rc" != "0" ]; then
  bad "V2: the revoke itself failed (rc $revoke_rc)"
  tail -3 "$WORK/revoke.out"
elif [ "$age" -ge 5 ]; then
  ok "V2: revoking the device ended its detached shell within ${GRACE}s (beat ${age}s old)"
else
  bad "V2: the revoked device's detached shell is still running ${GRACE}s after the revoke"
fi
client_cont "$WORK/v.tty"; kill "$VPID" 2>/dev/null

echo
echo "==========================================="
echo "pty-resume gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
