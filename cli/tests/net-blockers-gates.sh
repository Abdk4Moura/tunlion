#!/usr/bin/env bash
# Launch blockers from the final blind acceptance test: nothing on the mesh may
# hold a client open with no answer, and status says what is really bound.
#
#   FILAMENT_BIN=/path/to/tunlion ./net-blockers-gates.sh
#
# Gates:
#   S1  after a restart, every port in expose.json that `status --json` calls
#       bound is one the daemon reported binding, and an applied `expose`
#       survives the restart (startup used to refuse expose.json after a
#       userspace fallback while the live apply bound the same port)
#   S2  with the daemon down, status reports nothing as bound
#   L1  `tunlion logs -f | head -2` exits within 5 s of head exiting
#   P1  SOCKS CONNECT to a peer port it did not expose and does not tunnel
#       gets REP 0x02 (not allowed by ruleset) within 5 s. It used to hang.
#   P2  SOCKS CONNECT to an unknown peer gets REP 0x04 within 2 s
#   P3  (control) SOCKS CONNECT to a permitted live port carries HTTP
#   P4  SOCKS CONNECT to a permitted port with nothing listening gets 0x05
#   F1  (control) a forward to a live peer carries HTTP
#   F2  with the peer killed, a connection to the forward is CLOSED within
#       the 10 s bound (+ slack), not held open until the client gives up
#   F3  while the peer is known unreachable, the next connection is closed
#       at once
#   F4  the forward says so on its stderr
#   P5  SOCKS CONNECT to the offline peer gets REP 0x04 within the bound
#   P6  SOCKS CONNECT to a port the peer EXPOSED with nothing listening gets
#       REP 0x05 within 5 s. It got 0x00 and then 0 bytes until the client
#       gave up (the overlay listener took the handshake, and a dropped
#       userspace stream never sent its FIN)
#   P7  (control) the same exposed port with a listener carries HTTP
#
# P3/F1/P7 are the controls: P1/P2/P4/P6/F2/F3 could all pass on a build that
# refuses everything.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8161
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-net-blockers.XXXXXX")"
DA="$WORK/A"
BDIR="$WORK/bravo"
SOCKS_PORT=39180

source "$HERE/lib/fixture.sh"
cleanup() {
  env FILAMENT_CONFIG_DIR="$BDIR" timeout 15 "$BIN" down -y >/dev/null 2>&1
  fixture_cleanup
  pkill -f "$WORK" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "no tunlion binary at $BIN; build first"; exit 2; }
echo "## binary under test: $BIN"
"$BIN" --version | sed 's/^/##   /'

# A minimal SOCKS5 client that reports the REP byte and how long the reply
# took. curl folds every failure into one exit code; the gates need the byte.
cat >"$WORK/socks.py" <<'PY'
import socket, sys, time
host, port, pw, dst, dport = sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(), sys.argv[4].encode(), int(sys.argv[5])
t = time.time()
s = socket.create_connection((host, port), timeout=40)
def need(n):
    b = b""
    while len(b) < n:
        c = s.recv(n - len(b))
        if not c:
            raise EOFError("closed after %d bytes" % len(b))
        b += c
    return b
got = None
try:
    s.sendall(b"\x05\x01\x02"); assert need(2) == b"\x05\x02"
    s.sendall(b"\x01" + bytes([7]) + b"tunlion" + bytes([len(pw)]) + pw); assert need(2) == b"\x01\x00"
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(dst)]) + dst + dport.to_bytes(2, "big"))
    r = need(10); got = r[1]
    out = "rep=%d secs=%.1f" % (r[1], time.time() - t)
    if r[1] == 0:
        s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
        line = s.makefile("rb").readline().decode(errors="replace").strip()
        out += " http=%s" % (line.split(" ")[1] if " " in line else "none")
    print(out)
except socket.timeout:
    if got is None:
        print("rep=none secs=%.1f (no reply: hung)" % (time.time() - t))
    else:
        print("rep=%d secs=%.1f http=none (granted, then held: no data and no close)" % (got, time.time() - t))
except Exception as e:
    print("rep=none secs=%.1f (%s)" % (time.time() - t, e))
PY
# $1 = host.mesh, $2 = port. Prints "rep=N secs=S [http=CODE]".
socks() { "$PYV" "$WORK/socks.py" 127.0.0.1 "$SOCKS_PORT" "$(cat "$DA/proxy.token" 2>/dev/null)" "$1" "$2"; }
rep_of()  { printf '%s' "$1" | sed -n 's/.*rep=\([0-9a-z]*\).*/\1/p'; }
secs_of() { printf '%s' "$1" | sed -n 's/.*secs=\([0-9.]*\).*/\1/p'; }
http_of() { printf '%s' "$1" | sed -n 's/.*http=\([0-9a-z]*\).*/\1/p'; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a != "" && a+0 <= b+0)}'; }

start_backend
init_owner "$DA"
start_acceptor "$DA"
enroll_delegate bravo --allow transfer,mount
if ! env FILAMENT_CONFIG_DIR="$DA" "$BIN" devices 2>/dev/null | grep -q bravo; then
  echo "setup failed: bravo did not enrol, so nothing below would prove anything"
  sed 's/^/    /' "$WORK/bravo-join.log" 2>/dev/null | tail -5
  exit 2
fi

status_json() { env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 "$BIN" status --json 2>/dev/null; }
# $1 = port. Prints true|false|missing for that port's `bound` in status --json.
bound_of() {
  status_json | "$PYV" -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: print('missing'); sys.exit()
e=[x for x in d.get('exposed',[]) if x.get('port')==int(sys.argv[1])]
print(str(e[0].get('bound')).lower() if e else 'missing')
" "$1"
}
bravo_up_detached() {
  env FILAMENT_CONFIG_DIR="$BDIR" FILAMENT_AUTO_PROXY=0 timeout 40 "$BIN" --server "$SERVER" up --detach --dir "$WORK/bdrop" \
    >"$WORK/bravo-detach.out" 2>&1
  for _ in $(seq 1 30); do
    env FILAMENT_CONFIG_DIR="$BDIR" timeout 5 "$BIN" status >/dev/null 2>&1 && break
    sleep 0.5
  done
  sleep 3
}

# ----------------------------------------------------------------- S1 / S2
say "S1/S2: status reports the exposed ports the daemon actually bound"
bravo_up_detached
env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 "$BIN" expose 39555 >"$WORK/expose.out" 2>&1
sed 's/^/   /' "$WORK/expose.out"
live=$(bound_of 39555)
env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 "$BIN" down -y >/dev/null 2>&1
sleep 2
bravo_up_detached
after=$(bound_of 39555)
echo "## L3 mode: $(grep -ohE 'L3 overlay [^ ]+ \([a-z]+' "$BDIR/daemon.log" 2>/dev/null | tail -1)"
echo "## bound before restart=$live after restart=$after"
grep -E 'expos|NOT honored' "$BDIR/daemon.log" 2>/dev/null | sed 's/^/   /' | tail -4
if [ "$after" = "true" ] && [ "$live" = "true" ] && ! grep -q 'NOT honored' "$BDIR/daemon.log" 2>/dev/null; then
  ok "S1: an applied expose is still bound after a restart, and status says so"
else
  bad "S1: expose live=$live after-restart=$after (status and the daemon disagree, or the restart dropped it)"
fi

# ---------------------------------------------------------------------- L1
say "L1: logs -f exits when its reader goes away"
t0=$(date +%s.%N)
env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 sh -c "'$BIN' logs -f | head -2" >"$WORK/logs.out" 2>&1
rcL=$?
t1=$(date +%s.%N)
el=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
echo "## logs -f | head -2: rc=$rcL after ${el}s, $(wc -l <"$WORK/logs.out") lines"
if [ "$rcL" -ne 124 ] && le "$el" 5; then
  ok "L1: logs -f | head -2 exited ${el}s after head took its lines"
else
  bad "L1: logs -f | head -2 did not exit when head closed (rc=$rcL, ${el}s)"
fi

env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 "$BIN" down -y >/dev/null 2>&1
sleep 2
down_state=$(bound_of 39555)
echo "## with the daemon down: bound=$down_state"
if [ "$down_state" = "false" ]; then
  ok "S2: with the daemon down, status reports the exposed port as not bound"
else
  bad "S2: status reports bound=$down_state for a port nothing serves"
fi

# --------------------------------------------------------------- SOCKS proxy
# bravo's daemon in the foreground, L2 OFF first (no FILAMENT_L2): every
# loopback tunnel is refused by policy, and 39090 is not exposed.
BPID=""
start_bravo() {  # $1 = on|off (L2)
  if [ -n "$BPID" ]; then
    kill "$BPID" 2>/dev/null
    for _ in $(seq 1 20); do kill -0 "$BPID" 2>/dev/null || break; sleep 0.5; done
    kill -9 "$BPID" 2>/dev/null
  fi
  env FILAMENT_CONFIG_DIR="$BDIR" timeout 15 "$BIN" down -y >/dev/null 2>&1
  sleep 2
  if [ "$1" = on ]; then
    env FILAMENT_CONFIG_DIR="$BDIR" FILAMENT_L2=1 FILAMENT_AUTO_PROXY=0 "$BIN" --server "$SERVER" up --dir "$WORK/bdrop" >"$WORK/up-b-$1.log" 2>&1 &
  else
    env FILAMENT_CONFIG_DIR="$BDIR" FILAMENT_AUTO_PROXY=0 "$BIN" --server "$SERVER" up --dir "$WORK/bdrop" >"$WORK/up-b-$1.log" 2>&1 &
  fi
  BPID=$!
  FIX_PIDS+=($BPID)
  sleep 6
  grep -qs 'tunlion up,' "$WORK/up-b-$1.log" || { echo "bravo ($1) did not start:"; tail -5 "$WORK/up-b-$1.log"; exit 2; }
}
# Wait until alpha's daemon holds a link to bravo (bounded).
await_link() {
  for _ in $(seq 1 30); do
    env FILAMENT_CONFIG_DIR="$DA" timeout 15 "$BIN" --server "$SERVER" reach bravo >/dev/null 2>&1 && return 0
    sleep 1
  done
  echo "## alpha never reached bravo"; return 1
}

say "P1/P2: SOCKS answers a denied port and an unknown peer fast"
start_bravo off
# The documented shape, `tunlion forward <device>:<port> --socks`: the target
# is required by the parser and the proxy then serves every <peer>.mesh. It is
# the same proxy_serve the daemon's auto-proxy runs, on a port of our own so
# the two daemons on this runner cannot race for 1080.
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" forward bravo:39777 --socks --port "$SOCKS_PORT" >"$WORK/proxy.log" 2>&1 &
FIX_PIDS+=($!)
for _ in $(seq 1 20); do grep -qs "SOCKS5 proxy on" "$WORK/proxy.log" && break; sleep 0.5; done
grep -qs "SOCKS5 proxy on" "$WORK/proxy.log" || { echo "proxy did not start:"; tail -5 "$WORK/proxy.log"; exit 2; }
await_link

r=$(socks bravo.mesh 39090); echo "## P1 bravo.mesh:39090 -> $r"
if [ "$(rep_of "$r")" = "2" ] && le "$(secs_of "$r")" 5; then
  ok "P1: a port bravo did not expose got REP 0x02 in $(secs_of "$r")s"
else
  bad "P1: denied port answered '$r' (want rep=2 within 5s)"
fi
r=$(socks nosuch.mesh 80); echo "## P2 nosuch.mesh:80 -> $r"
if [ "$(rep_of "$r")" = "4" ] && le "$(secs_of "$r")" 2; then
  ok "P2: an unknown peer got REP 0x04 in $(secs_of "$r")s"
else
  bad "P2: unknown peer answered '$r' (want rep=4 within 2s)"
fi

say "P6/P7: an EXPOSED port, nothing listening and then something (L2 off: only the overlay carries it)"
env FILAMENT_CONFIG_DIR="$BDIR" timeout 20 "$BIN" expose 39557 >"$WORK/expose-p6.out" 2>&1
sed 's/^/   /' "$WORK/expose-p6.out"
sleep 3
r=$(socks bravo.mesh 39557); echo "## P6 bravo.mesh:39557 (exposed, nothing listening) -> $r"
if [ "$(rep_of "$r")" = "5" ] && le "$(secs_of "$r")" 5; then
  ok "P6: an exposed port with nothing listening got REP 0x05 in $(secs_of "$r")s, not 'granted' and then held"
else
  bad "P6: exposed port with nothing listening answered '$r' (want rep=5 within 5s)"
fi
( cd "$WORK" && $PYV -m http.server 39557 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! >"$WORK/http-p7.pid" )
FIX_PIDS+=($(cat "$WORK/http-p7.pid"))
sleep 2
r=$(socks bravo.mesh 39557); echo "## P7 bravo.mesh:39557 (exposed, live) -> $r"
if [ "$(rep_of "$r")" = "0" ] && [ "$(http_of "$r")" = "200" ]; then
  ok "P7: the same exposed port, now live, is carried (HTTP 200)"
else
  bad "P7: the control failed ('$r'); P6 proves nothing if the exposed port is never carried"
fi

say "P3/P4: L2 on, a live port and a closed one"
start_bravo on
( cd "$WORK" && $PYV -m http.server 39777 --bind 127.0.0.1 >/dev/null 2>&1 & echo $! >"$WORK/http.pid" )
FIX_PIDS+=($(cat "$WORK/http.pid"))
sleep 2
await_link
r=$(socks bravo.mesh 39777); echo "## P3 bravo.mesh:39777 -> $r"
if [ "$(rep_of "$r")" = "0" ] && [ "$(http_of "$r")" = "200" ]; then
  ok "P3: a permitted live port is carried (HTTP 200)"
else
  bad "P3: the control failed ('$r'); P1/P2/P4 prove nothing if every CONNECT fails"
fi
r=$(socks bravo.mesh 39998); echo "## P4 bravo.mesh:39998 -> $r"
if [ "$(rep_of "$r")" = "5" ] && le "$(secs_of "$r")" 5; then
  ok "P4: nothing listening on the peer's port got REP 0x05 in $(secs_of "$r")s"
else
  bad "P4: closed port answered '$r' (want rep=5 within 5s)"
fi

# ------------------------------------------------------------------ forward
say "F1-F4: a forward to a peer that dies closes its clients"
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" forward bravo:39777 --lport 39802 >"$WORK/fwd.log" 2>&1 &
FIX_PIDS+=($!)
for _ in $(seq 1 24); do grep -qsE 'ready|listening on' "$WORK/fwd.log" && break; sleep 0.5; done
code=$(timeout 20 curl -s -o /dev/null -w '%{http_code}' -m 15 http://127.0.0.1:39802/ 2>/dev/null)
echo "## F1 curl via the forward: $code"
if [ "$code" = "200" ]; then
  ok "F1: the forward carries HTTP while the peer is up"
else
  bad "F1: the control failed (http=$code); F2/F3 prove nothing if the forward never worked"
fi

kill -9 "$BPID" 2>/dev/null
sleep 1
curl_close() {  # prints "rc=N secs=S"
  local t0 t1 rc
  t0=$(date +%s.%N)
  curl -s -o /dev/null -m 40 http://127.0.0.1:39802/ >/dev/null 2>&1
  rc=$?
  t1=$(date +%s.%N)
  echo "rc=$rc secs=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')"
}
c1=$(curl_close); echo "## F2 first connection after the kill: $c1"
rc1=$(printf '%s' "$c1" | sed -n 's/rc=\([0-9]*\).*/\1/p')
if [ "$rc1" != "28" ] && [ "$rc1" != "0" ] && le "$(secs_of "$c1")" 15; then
  ok "F2: the connection was closed in $(secs_of "$c1")s (curl rc=$rc1), not held open"
else
  bad "F2: a connection to a forward whose peer is dead: $c1 (want closed within 15s)"
fi
c2=$(curl_close); echo "## F3 next connection: $c2"
rc2=$(printf '%s' "$c2" | sed -n 's/rc=\([0-9]*\).*/\1/p')
if [ "$rc2" != "28" ] && [ "$rc2" != "0" ] && le "$(secs_of "$c2")" 4; then
  ok "F3: while the peer is unreachable, the next connection closed at once ($(secs_of "$c2")s)"
else
  bad "F3: the next connection: $c2 (want closed within 4s)"
fi
fwd=$(tr -d '\r' <"$WORK/fwd.log" | sed 's/\x1b\[[0-9;]*[A-Za-z]//g')
printf '%s\n' "$fwd" | grep -avE '^\s*$' | sed 's/^/   /' | tail -6
if printf '%s\n' "$fwd" | grep -q "cannot reach bravo"; then
  ok "F4: the forward said on stderr that it cannot reach bravo"
else
  bad "F4: the forward never said the peer is unreachable"
fi

say "P5: SOCKS to the offline peer"
r=$(socks bravo.mesh 39777); echo "## P5 bravo.mesh:39777 (bravo dead) -> $r"
if [ "$(rep_of "$r")" = "4" ] && le "$(secs_of "$r")" 15; then
  ok "P5: the offline peer got REP 0x04 in $(secs_of "$r")s"
else
  bad "P5: offline peer answered '$r' (want rep=4 within 15s)"
fi

echo
echo "==========================================="
echo "net-blockers gates: $PASS passed, $FAIL failed${FAILED:+ -- failed:$FAILED}"
[ "$FAIL" = "0" ]
