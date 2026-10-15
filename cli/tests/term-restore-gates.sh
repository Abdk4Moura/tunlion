#!/usr/bin/env bash
# A remote program can switch on modes in the LOCAL terminal (mouse reporting,
# bracketed paste, the alternate screen). When the session ends without the
# program switching them off again, the client must: otherwise the terminal
# keeps sending mouse reports as typed text (`35;84;9M...`) into the next
# prompt. Standalone, hermetic, fixture port 8188 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./term-restore-gates.sh
#
# The remote command turns mouse reporting (1003) and the alternate screen
# (1049) on and never turns them off. The client's terminal is recorded with
# util-linux `script`, so what the client wrote to it is checkable.
#
# Gates:
#   T0  control: the remote really turned mouse reporting on (else T1-T3 prove nothing)
#   T1  the remote shell exits normally: the client turns mouse reporting off after it
#   T2  the client is terminated (SIGTERM): it still turns mouse reporting off
#   T3  the link dies and the terminal goes away (SIGHUP): it still turns it off
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8188
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-term-restore.XXXXXX")"
DA="$WORK/A"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

command -v script >/dev/null || fixture_die "setup: util-linux 'script' is needed to give the client a terminal"

start_backend
init_owner "$DA"
start_acceptor "$DA"
ACCEPTOR_PID="${FIX_PIDS[-1]}"
enroll_delegate bravo --allow shell

# Run `tunlion shell alpha -- <cmd>` for bravo on a real terminal, recording it
# to $1 and the client's pid to $1.pid.
tty_shell() {
  local out="$1" cmd="$2" inner
  inner=$(printf 'echo $$ > %q; exec env TUNLION_CONFIG_DIR=%q %q --server %q shell alpha -- %q' \
    "$out.pid" "$WORK/bravo" "$BIN" "$SERVER" "$cmd")
  script -qfec "sh -c $(printf '%q' "$inner")" "$out" >/dev/null 2>&1 &
  FIX_PIDS+=($!)
  echo $! > "$out.spid"
  local i
  for i in $(seq 1 50); do [ -s "$out.pid" ] && break; sleep 0.2; done
  FIX_PIDS+=("$(cat "$out.pid" 2>/dev/null)")
}

wait_for() {  # $1 = seconds, $2 = file, $3 = fixed string
  local i
  for i in $(seq 1 "$1"); do grep -qF "$3" "$2" 2>/dev/null && return 0; sleep 1; done
  return 1
}

wait_gone() {  # $1 = seconds, $2 = pid
  local i
  for i in $(seq 1 "$1"); do kill -0 "$2" 2>/dev/null || return 0; sleep 1; done
  return 1
}

ON=$'\e[?1003h'
OFF=$'\e[?1003l'
# The remote program: mouse reporting and the alternate screen on, a marker,
# then (for T2/T3) wait. It never switches either mode off.
MOUSE_ON='printf "\033[?1049h\033[?1003hMOUSE-ON\n"'

# Did the client switch mouse reporting off AFTER the remote last switched it on?
off_after_on() {  # $1 = recorded terminal
  python3 - "$1" "$ON" "$OFF" <<'PY'
import sys
data = open(sys.argv[1], 'rb').read()
on, off = sys.argv[2].encode(), sys.argv[3].encode()
last_on = data.rfind(on)
sys.exit(0 if last_on >= 0 and data.find(off, last_on) > last_on else 1)
PY
}

# ===================================================================== T0/T1 ==
say "T0/T1"
tty_shell "$WORK/t1.tty" "$MOUSE_ON; sleep 1"
P1=$(cat "$WORK/t1.tty.pid")
if ! wait_for 30 "$WORK/t1.tty" "MOUSE-ON"; then
  bad "T0: the remote command never ran, the rest proves nothing"
  tail -c 600 "$WORK/t1.tty" | tr -d '\r'
  declare_known_red_summary; exit 1
fi
if grep -qF "$ON" "$WORK/t1.tty"; then
  ok "T0: the remote switched mouse reporting on in the local terminal"
else
  bad "T0: the remote's mouse request never reached the local terminal"
fi
if wait_gone 30 "$P1" && off_after_on "$WORK/t1.tty"; then
  ok "T1: after a normal exit the client switched mouse reporting off"
else
  bad "T1: the session ended and mouse reporting was left on"
fi

# ======================================================================== T2 ==
say "T2"
tty_shell "$WORK/t2.tty" "$MOUSE_ON; sleep 120"
P2=$(cat "$WORK/t2.tty.pid")
if wait_for 30 "$WORK/t2.tty" "MOUSE-ON"; then
  kill -TERM "$P2" 2>/dev/null
  if wait_gone 20 "$P2" && off_after_on "$WORK/t2.tty"; then
    ok "T2: a terminated client switched mouse reporting off"
  else
    bad "T2: a terminated client left mouse reporting on"
  fi
else
  bad "T2: the remote command never ran"
fi

# ======================================================================== T3 ==
say "T3"
tty_shell "$WORK/t3.tty" "$MOUSE_ON; sleep 120"
P3=$(cat "$WORK/t3.tty.pid")
if wait_for 30 "$WORK/t3.tty" "MOUSE-ON"; then
  kill -KILL "$ACCEPTOR_PID" 2>/dev/null   # the link dies under the session
  sleep 3
  kill -HUP "$P3" 2>/dev/null               # then the terminal goes away
  if wait_gone 20 "$P3" && off_after_on "$WORK/t3.tty"; then
    ok "T3: after the link died, the closing client switched mouse reporting off"
  else
    bad "T3: after the link died, mouse reporting was left on"
  fi
else
  bad "T3: the remote command never ran"
fi

echo
echo "==========================================="
echo "term-restore gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
