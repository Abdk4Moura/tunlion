#!/usr/bin/env bash
# #237: the signaling server's `/api/whoami` answer is an UNSIGNED assertion
# about US that goes straight into the advertised candidate set, unchecked.
# Standalone, hermetic, fixture ports 8709 (backend) + 8710 (lying proxy) ONLY.
#
#   FILAMENT_BIN=/path/to/filament-something ./whoami-candidate-gates.sh
#
# WHAT THIS GATE CLAIMS, AND WHAT IT DOES NOT.
#
# It claims the PREMISE: the server's answer is load-bearing and unchecked. It
# proves that by showing the peer emits real packets at an address it was told
# about by the server and by nothing else. `gather_candidates` (direct.rs)
# appends `public_ip(server):local_port` with no cross-check, and `public_ip` is
# a plain GET of `{server}/api/whoami`.
#
# It does NOT demonstrate the downgrade-to-relay consequence. That follows by
# INFERENCE - a candidate that cannot carry traffic cannot win the race, so the
# connection lands on a lower rung - and inference is a weaker claim than
# measurement. It is labelled as such here and must stay labelled in the
# write-up. An earlier version of this gate tried to demonstrate the downgrade by
# emptying the local candidate set with `filament set only <nonexistent-iface>`;
# that lever starves the link of everything rather than isolating the public
# candidate, and its CONTROL arm did not link even with a truthful whoami, so
# nothing downstream of it was attributable. The namespace-with-a-NAT version is
# the trustworthy control for the consequence, and is deliberately deferred.
#
# WHY THERE IS NO SECOND OPINION TO CATCH A WRONG ANSWER. rung-2's STUN srflx is
# gated on FILAMENT_HOLEPUNCH, default OFF (holepunch.rs). The WebRTC path's STUN
# list is whatever `{server}/api/config` returns (net.rs `fetch_config`), so the
# signaling server names its own contradictors. Two sources chosen by one party
# are one source.
#
# INJECTION POINT. The lie is told by the SERVER, over the wire, at the real
# trust boundary: a proxy in front of the fixture backend answers /api/whoami
# itself and byte-splices everything else (including the socket.io websocket).
# Deliberately NOT FILAMENT_PUBLIC_IP, which short-circuits `public_ip` before
# the fetch and would bypass the very request under test.
#
# OBSERVABLE. tcpdump, not a log line. Nothing in the product prints the
# advertised candidate set today, and adding that print as part of the fix would
# make the red run impossible to capture with the same instrument as the green
# one. Outbound UDP to the asserted address is visible without touching product
# code, and it is a stronger fact than a log line anyway: the packets are the
# client acting on the assertion.
#
# Gates:
#   A   CONTROL: with a truthful whoami the peers link over the direct path, and
#       ZERO packets go to the lie address. Fixes the reference for gate B.
#   A2  INSTRUMENT: the injector actually served /api/whoami in both arms. A lie
#       nobody fetched proves nothing, and a silent injector would rewrite every
#       other number here.
#   B   THE PREMISE (characterization, NOT a regression that flips): with the
#       server asserting an address that is NOT ours, the client sends packets to
#       it. Adopted on the server's say-so alone. NOTE this gate is expected to
#       keep passing after the agreed fix, because `whoami` legitimately remains a
#       bootstrap HINT for FIRST contact, when no peer has observed us yet. The
#       gate that must flip is C. The regression gate for the fix itself - a
#       peer-observed address SUPERSEDES the server's answer on the next
#       connection, so no packets go to the stale one - does not exist yet and
#       has to be added with the fix.
#   C   THE NON-NEGOTIABLE: nothing tells the user an advertised address came
#       from an unverified source or never worked. Silent today.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PORT=8709
SERVER="http://127.0.0.1:$PORT"
PROXY_PORT=8710
PROXY="http://127.0.0.1:$PROXY_PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-whoami.XXXXXX")"
DA="$WORK/owner"

# TEST-NET-3 (RFC 5737). Routable-looking, documentation-only, never ours.
LIE_IP="203.0.113.7"

. "$HERE/lib/fixture.sh"
trap 'fixture_cleanup' EXIT
echo "## bin:  $BIN"
echo "## work: $WORK"

# The binary must be named so `is_filament_process` recognises the daemon, or no
# control.sock is created and every warm-link lookup silently reads as "no link".
case "$(basename "$BIN")" in
  *filament*) ;;
  *) echo "FILAMENT_BIN basename must contain 'filament' (see lib/fixture.sh); got '$(basename "$BIN")'"; exit 2 ;;
esac
command -v tcpdump >/dev/null || { echo "tcpdump is required for the wire observable"; exit 2; }

claim_port "$PORT" "$PROXY_PORT"
start_backend

# ------------------------------------------------------------- lying proxy --
echo "127.0.0.1" > "$WORK/whoami.ip"
"$PYV" - "$PROXY_PORT" "$PORT" "$WORK" >"$WORK/proxy.log" 2>&1 <<'PY' &
import asyncio, sys, json
listen_port, backend_port, work = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]

def current_ip():
    with open(f"{work}/whoami.ip") as f:
        return f.read().strip()

def note(ip):
    with open(f"{work}/proxy.hits", "a") as f:
        f.write(ip + "\n")

async def splice(r, w):
    try:
        while True:
            b = await r.read(65536)
            if not b:
                break
            w.write(b)
            await w.drain()
    except Exception:
        pass
    finally:
        try:
            w.close()
        except Exception:
            pass

async def handle(cr, cw):
    try:
        head = b""
        while b"\r\n\r\n" not in head:
            ch = await cr.read(1)
            if not ch:
                return
            head += ch
        line = head.split(b"\r\n", 1)[0].decode("latin1")
        parts = line.split(" ")
        path = parts[1] if len(parts) > 1 else ""
        if path.startswith("/api/whoami"):
            ip = current_ip()
            note(ip)
            body = json.dumps({"ip": ip}).encode()
            cw.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                + b"X-Filament-Gate-Injector: whoami-237\r\n"
                + b"Content-Length: " + str(len(body)).encode()
                + b"\r\nConnection: close\r\n\r\n" + body
            )
            await cw.drain()
            cw.close()
            return
        br, bw = await asyncio.open_connection("127.0.0.1", backend_port)
        bw.write(head)
        await bw.drain()
        await asyncio.gather(splice(cr, bw), splice(br, cw))
    except Exception:
        try:
            cw.close()
        except Exception:
            pass

async def main():
    srv = await asyncio.start_server(handle, "127.0.0.1", listen_port)
    async with srv:
        await srv.serve_forever()

asyncio.run(main())
PY
FIX_PIDS+=($!)
for _ in $(seq 1 30); do curl -fsS "$PROXY/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$PROXY/api/health" >/dev/null || { echo "no proxy at $PROXY"; cat "$WORK/proxy.log"; exit 2; }
SEEN=$(curl -fsS -D "$WORK/whoami.hdr" "$PROXY/api/whoami")
echo "## injector says: $SEEN"
# Verify by HEADER: a real backend also answers /api/whoami with an ip, so the
# body cannot distinguish our injector from somebody else's server.
grep -qi "^X-Filament-Gate-Injector: whoami-237" "$WORK/whoami.hdr" || {
  echo "the process answering $PROXY is NOT this gate's injector"; cat "$WORK/proxy.log"; exit 2; }

# ------------------------------------------------------------- the two peers --
init_owner "$DA"
mkdir -p "$WORK/Adrop" "$WORK/Bdrop"
# The owner's daemon must be UP to answer the enrollment, or join just times out.
env FILAMENT_CONFIG_DIR="$DA" FILAMENT_L2=1 "$BIN" --server "$PROXY" up --dir "$WORK/Adrop" \
    >"$WORK/enroll-alpha.log" 2>&1 &
ENROLL_PID=$!; FIX_PIDS+=("$ENROLL_PID")
sleep 3
env FILAMENT_CONFIG_DIR="$DA" "$BIN" --server "$PROXY" add --for bravo --allow mount \
    --out "$WORK/inv.txt" --yes >/dev/null 2>&1
DB="$WORK/bravo"; mkdir -p "$DB"
env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$PROXY" join --invite-file "$WORK/inv.txt" \
    --name bravo --no-interactive >"$WORK/join.log" 2>&1
kill "$ENROLL_PID" 2>/dev/null; sleep 2
grep -q "joined as" "$WORK/join.log" || {
  echo "enrollment failed, nothing below would mean anything:"; cat "$WORK/join.log"; exit 2; }

# One arm: capture the wire, run both daemons, read the route, count packets
# aimed at the lie address.
#   $1 = the IP the server will assert   $2 = arm label
run_arm() {
  local ip="$1" label="$2"
  echo "$ip" > "$WORK/whoami.ip"
  : > "$WORK/proxy.hits"
  tcpdump -n -l -i any "udp and host $LIE_IP" >"$WORK/$label.wire" 2>"$WORK/$label.wire.err" &
  local tp=$!; FIX_PIDS+=("$tp")
  sleep 2
  # FILAMENT_UID is REQUIRED: without it `is_self_uid` sees two processes of one
  # install and takes the tcp-localhost shortcut, which gathers no public
  # candidate at all - the path under test would be skipped entirely.
  env FILAMENT_CONFIG_DIR="$DA" FILAMENT_UID="alpha$$" FILAMENT_L2=1 \
      "$BIN" --server "$PROXY" up --dir "$WORK/Adrop" >"$WORK/$label-alpha.log" 2>&1 &
  local ap=$!; FIX_PIDS+=("$ap")
  env FILAMENT_CONFIG_DIR="$DB" FILAMENT_UID="bravo$$" FILAMENT_L2=1 \
      "$BIN" --server "$PROXY" up --dir "$WORK/Bdrop" >"$WORK/$label-bravo.log" 2>&1 &
  local bp=$!; FIX_PIDS+=("$bp")
  sleep 18
  env FILAMENT_CONFIG_DIR="$DB" "$BIN" --server "$PROXY" reach alpha --json \
      >"$WORK/$label-reach.json" 2>"$WORK/$label-reach.err"
  kill "$ap" "$bp" 2>/dev/null
  sleep 2
  kill "$tp" 2>/dev/null
  sleep 1
}

route_of() { python3 -c "
import json,sys
try: v=json.load(open('$WORK/$1-reach.json'))
except Exception: print(''); raise SystemExit
print(v.get('route','') if isinstance(v,dict) else '')
" 2>/dev/null; }
warm_of() { python3 -c "
import json,sys
try: v=json.load(open('$WORK/$1-reach.json'))
except Exception: print('false'); raise SystemExit
print(str(v.get('warm',False)).lower())
" 2>/dev/null; }
# `grep -c` PRINTS 0 and EXITS 1 when there are no matches, so a trailing
# `|| echo 0` emits a second zero and every numeric test downstream breaks on
# "0\n0". Capture the output and ignore the status instead.
hits_of() { local n; n=$(wc -l < "$WORK/proxy.hits" 2>/dev/null | tr -d ' '); echo "${n:-0}"; }
pkts_of() { local n; n=$(grep -c "$LIE_IP" "$WORK/$1.wire" 2>/dev/null); echo "${n:-0}"; }

# ===================================================================== GATE A ==
say "whoami gate A (control: the server tells the truth)"
run_arm "127.0.0.1" truthful
RA="$(route_of truthful)"; WA="$(warm_of truthful)"; HA="$(hits_of)"; PA="$(pkts_of truthful)"
echo "## route='$RA' warm=$WA  whoami-served=${HA}x  packets-to-$LIE_IP=$PA"
if [ "$WA" = "true" ] && [ -n "$RA" ] && [ "$PA" = "0" ]; then
  ok "gateA: truthful server -> a real link ('$RA') and ZERO packets to $LIE_IP"
else
  bad "gateA: control did not hold (warm=$WA route='$RA' stray-packets=$PA) - nothing below is attributable"
  echo "-- reach --"; cat "$WORK/truthful-reach.json" 2>/dev/null
  echo "-- bravo --"; tail -10 "$WORK/truthful-bravo.log"
  echo; echo "==========================================="
  echo "whoami gates: $PASS passed, $FAIL failed --$FAILED"; echo "work: $WORK"
  exit 1
fi

# ===================================================================== GATE B ==
say "whoami gate B (premise: the server asserts an address that is not ours)"
run_arm "$LIE_IP" lying
RB="$(route_of lying)"; WB="$(warm_of lying)"; HB="$(hits_of)"; PB="$(pkts_of lying)"
echo "## route='$RB' warm=$WB  whoami-served=${HB}x  packets-to-$LIE_IP=$PB"
[ "$PB" -gt 0 ] && { echo "## first packets aimed at the asserted address:"; head -3 "$WORK/lying.wire" | sed 's/^/    /'; }

# ==================================================================== GATE A2 ==
say "whoami gate A2 (instrument: the lie was actually served)"
echo "## whoami served: truthful arm ${HA}x, lying arm ${HB}x"
if [ "${HA:-0}" -gt 0 ] && [ "${HB:-0}" -gt 0 ]; then
  ok "gateA2: the injector served /api/whoami in both arms"
else
  bad "gateA2: the client never fetched /api/whoami through the injector - gates A and B prove NOTHING"
fi

if [ "$PB" -gt 0 ]; then
  ok "gateB: the client sent $PB packet(s) to $LIE_IP - an address adopted on the server's say-so alone (#237)"
else
  bad "gateB: no packets to $LIE_IP; the assertion was not adopted, or not reached for"
fi

# ===================================================================== GATE C ==
say "whoami gate C (the non-negotiable: an unverified address must be stated)"
# Strip the work path BEFORE grepping. $WORK is /tmp/wt-whoami.XXXX, so every
# line that merely prints a path under it matched "whoami" and this gate passed
# on the banner "filament up, 1 known device -> /tmp/wt-whoami.../Bdrop". The one
# gate that must never pass by accident was passing on its own scratch directory.
SAID=$(cat "$WORK/lying-bravo.log" "$WORK/lying-alpha.log" "$WORK/lying-reach.json" \
            "$WORK/lying-reach.err" 2>/dev/null \
       | sed "s|$WORK||g" \
       | grep -i "public candidate\|whoami\|reported address\|unverified\|never worked\|server-asserted" | head -5)
echo "## anything said about the unverified advertised address:"
if [ -n "$SAID" ]; then echo "$SAID" | sed 's/^/    /'; else echo "    (nothing)"; fi
if [ -n "$SAID" ]; then
  ok "gateC: the client states that its advertised address is unverified / never worked"
else
  bad "gateC: SILENT - the client dials a server-chosen address and never says so (#237)"
fi

echo
echo "==========================================="
if [ "$FAIL" = "0" ]; then
  echo "whoami gates: $PASS passed, 0 failed"
else
  echo "whoami gates: $PASS passed, $FAIL failed --$FAILED"
fi
echo "work: $WORK"
[ "$FAIL" = "0" ]
