#!/usr/bin/env bash
# `tunlion demo` gates: the guided tour plays offline in a real terminal, is
# safe to run anywhere, and keeps the exit-code contract.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/demo-gates.sh
#
# Each run gets its own HOME and TMPDIR, so the isolation gate can see every
# file the demo would have written. No signaling server is started: the demo
# must not need one.
#
# Gates:
#   A  `demo --auto` in a pty completes, exits 0, shows every step header
#      (1/N .. N/N) and the closing "That's the tour."
#   T  `demo` with stdin not a terminal exits 2 and names --auto; `--auto`
#      through a pipe works and carries no escape sequences.
#   I  interactive in a pty: pressing Enter for every prompt walks the whole
#      tour (each command is typed for you) and exits 0.
#   C  Ctrl-C at an interactive prompt exits 130 and restores the terminal
#      (cursor shown, raw mode off).
#   N  NO_COLOR and TERM=dumb: no color and no in-place redraw sequences.
#   Z  isolation: nothing is written under HOME (no ~/.config/tunlion), and the
#      private temp config directory is gone afterwards.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-demo.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
PASS=0; FAIL=0
say() { printf '\n== %s ==\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

# A pty driver: runs the binary under a pseudo-terminal, optionally sends keys
# (one write per key, a short gap between), and records output and exit code.
cat >"$WORK/pty.py" <<'PY'
import os, pty, select, sys, time, json
args = json.loads(sys.argv[1])
cmd, env_extra, keys, gap, bound, outpath = args["cmd"], args["env"], args["keys"], args["gap"], args["bound"], args["out"]
env = dict(os.environ); env.update(env_extra)
pid, fd = pty.fork()
if pid == 0:
    os.execvpe(cmd[0], cmd, env)
out = b""; start = time.time(); ki = 0; last_key = time.time()
status = None
while True:
    if time.time() - start > bound:
        os.kill(pid, 9); status = "HUNG"; break
    r, _, _ = select.select([fd], [], [], 0.02)
    if r:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            chunk = b""
        if not chunk:
            pass
        out += chunk
    if ki < len(keys) and time.time() - last_key >= gap:
        try:
            os.write(fd, keys[ki].encode().decode("unicode_escape").encode("latin-1"))
        except OSError:
            pass
        ki += 1; last_key = time.time()
    done, st = os.waitpid(pid, os.WNOHANG)
    if done:
        # drain what is left
        while True:
            r, _, _ = select.select([fd], [], [], 0.05)
            if not r: break
            try:
                c = os.read(fd, 65536)
            except OSError:
                break
            if not c: break
            out += c
        status = os.waitstatus_to_exitcode(st)
        break
open(outpath, "wb").write(out)
print(status)
PY
# $1 = json spec; prints the exit status (or HUNG)
pty_run() { python3 -I "$WORK/pty.py" "$1"; }

N_STEPS=10
mkenv() { local h="$WORK/home-$1"; mkdir -p "$h/tmp"; echo "$h"; }

# ---------------------------------------------------------------------- A --
say "A: --auto in a terminal plays the whole tour"
H="$(mkenv a)"
st=$(pty_run "{\"cmd\":[\"$BIN\",\"demo\",\"--auto\",\"--speed\",\"0\"],\"env\":{\"HOME\":\"$H\",\"TMPDIR\":\"$H/tmp\",\"TERM\":\"xterm-256color\",\"LANG\":\"C.UTF-8\"},\"keys\":[],\"gap\":0,\"bound\":60,\"out\":\"$WORK/a.out\"}")
headers=0
for i in $(seq 1 $N_STEPS); do grep -aq "$i/$N_STEPS" "$WORK/a.out" && headers=$((headers+1)); done
if [ "$st" = 0 ] && [ "$headers" = "$N_STEPS" ] && grep -aq "That's the tour." "$WORK/a.out"; then
  ok "A: demo --auto exits 0 with all $N_STEPS step headers and the closing lines"
else
  bad "A auto play (status $st, $headers/$N_STEPS headers)"; tail -c 2000 "$WORK/a.out"
fi

# ---------------------------------------------------------------------- T --
say "T: no terminal: demo refuses with 2, demo --auto plays plain"
H="$(mkenv t)"
HOME="$H" TMPDIR="$H/tmp" "$BIN" demo </dev/null >"$WORK/t1.out" 2>&1; r1=$?
HOME="$H" TMPDIR="$H/tmp" "$BIN" demo --auto --speed 0 </dev/null >"$WORK/t2.out" 2>"$WORK/t2.err"; r2=$?
esc=$(grep -c $'\x1b' "$WORK/t2.out" || true)
if [ "$r1" = 2 ] && grep -q -- "--auto" "$WORK/t1.out" && [ "$r2" = 0 ] && [ "$esc" = 0 ] \
   && grep -q "1/$N_STEPS" "$WORK/t2.out" && grep -q "That's the tour." "$WORK/t2.out"; then
  ok "T: demo without a terminal exits 2 naming --auto; --auto through a pipe exits 0 with no escapes"
else
  bad "T no-tty contract (demo rc $r1, --auto rc $r2, escapes $esc)"; cat "$WORK/t1.out"; head -20 "$WORK/t2.out"; cat "$WORK/t2.err"
fi

# ---------------------------------------------------------------------- I --
say "I: interactive: Enter at every prompt walks the tour"
H="$(mkenv i)"
keys=$(python3 -c 'import json; print(json.dumps(["\\r"]*80))')
st=$(pty_run "{\"cmd\":[\"$BIN\",\"demo\",\"--speed\",\"0\"],\"env\":{\"HOME\":\"$H\",\"TMPDIR\":\"$H/tmp\",\"TERM\":\"xterm-256color\",\"LANG\":\"C.UTF-8\"},\"keys\":$keys,\"gap\":0.08,\"bound\":60,\"out\":\"$WORK/i.out\"}")
if [ "$st" = 0 ] && grep -aq "$N_STEPS/$N_STEPS" "$WORK/i.out" && grep -aq "That's the tour." "$WORK/i.out" \
   && grep -aq "tunlion devices revoke old-phone" "$WORK/i.out"; then
  ok "I: an interactive run driven by Enter alone reaches the end and exits 0"
else
  bad "I interactive walk (status $st)"; tail -c 2000 "$WORK/i.out"
fi

# ---------------------------------------------------------------------- C --
say "C: Ctrl-C at a prompt exits 130 and restores the terminal"
H="$(mkenv c)"
st=$(pty_run "{\"cmd\":[\"$BIN\",\"demo\"],\"env\":{\"HOME\":\"$H\",\"TMPDIR\":\"$H/tmp\",\"TERM\":\"xterm-256color\",\"LANG\":\"C.UTF-8\"},\"keys\":[\"\\\\x03\"],\"gap\":1.5,\"bound\":30,\"out\":\"$WORK/c.out\"}")
# The last cursor-visibility sequence must be "show".
last_cur=$(grep -ao $'\x1b\[?25[hl]' "$WORK/c.out" | tail -1)
if [ "$st" = 130 ] && [ "$last_cur" = $'\x1b[?25h' ]; then
  ok "C: Ctrl-C at the first prompt exits 130 and leaves the cursor shown"
else
  bad "C Ctrl-C (status $st, last cursor seq '$(printf %q "$last_cur")')"; tail -c 800 "$WORK/c.out" | od -c | tail -5
fi

# ---------------------------------------------------------------------- N --
say "N: NO_COLOR and TERM=dumb"
H="$(mkenv n)"
st1=$(pty_run "{\"cmd\":[\"$BIN\",\"demo\",\"--auto\",\"--speed\",\"0\"],\"env\":{\"HOME\":\"$H\",\"TMPDIR\":\"$H/tmp\",\"TERM\":\"xterm-256color\",\"NO_COLOR\":\"1\"},\"keys\":[],\"gap\":0,\"bound\":60,\"out\":\"$WORK/n1.out\"}")
st2=$(pty_run "{\"cmd\":[\"$BIN\",\"demo\",\"--auto\",\"--speed\",\"3\"],\"env\":{\"HOME\":\"$H\",\"TMPDIR\":\"$H/tmp\",\"TERM\":\"dumb\"},\"keys\":[],\"gap\":0,\"bound\":180,\"out\":\"$WORK/n2.out\"}")
color1=$(grep -ac $'\x1b\[[0-9;]*38;' "$WORK/n1.out" || true)
color2=$(grep -ac $'\x1b\[[0-9;]*38;' "$WORK/n2.out" || true)
redraw2=$(grep -ac $'\x1b\[2K' "$WORK/n2.out" || true)
if [ "$st1" = 0 ] && [ "$st2" = 0 ] && [ "$color1" = 0 ] && [ "$color2" = 0 ] && [ "$redraw2" = 0 ]; then
  ok "N: NO_COLOR prints no color; TERM=dumb prints no color and no line redraws"
else
  bad "N plain terminals (status $st1/$st2, color $color1/$color2, redraws $redraw2)"
fi

# ---------------------------------------------------------------------- Z --
say "Z: nothing written outside a private temp directory, and that is removed"
leftover=0; written=0
for h in "$WORK"/home-*; do
  [ -e "$h/.config/tunlion" ] && written=$((written+1))
  [ -n "$(find "$h" -mindepth 1 -not -path "$h/tmp" -not -path "$h/tmp/*" 2>/dev/null | head -1)" ] && written=$((written+1))
  [ -n "$(ls -A "$h/tmp" 2>/dev/null)" ] && leftover=$((leftover+1))
done
if [ "$written" = 0 ] && [ "$leftover" = 0 ]; then
  ok "Z: every run left HOME untouched and removed its temp config directory"
else
  bad "Z isolation ($written HOMEs written, $leftover temp dirs left)"
  for h in "$WORK"/home-*; do find "$h" -mindepth 1 | head -5; done
fi

echo
echo "== demo gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
