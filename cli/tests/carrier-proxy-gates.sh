#!/usr/bin/env bash
# E2E: a CLI whose only egress is an authenticating HTTP proxy pairs, transfers
# and runs exec (docs/carriers.md, profile "proxy-only").
#
#   ns 10.216.<n>.2 --veth-- host 10.216.<n>.1
#     host: signaling backend :PORT, coturn (UDP/TCP 3478, TLS 443), squid :3129
#     ns:   OUTPUT drops everything except TCP to squid
#
# squid is configured like a corporate proxy: Basic auth required, CONNECT
# only to 443 and the signaling port. So inside the namespace the only way to
# the relay is TURN over TLS 443 through CONNECT, and the only way to signaling
# is through the proxy. Nothing here touches production.
#
# Every claim is read off an instrument:
#   - the ns firewall counters (UDP dropped, TCP to anything but the proxy);
#   - squid's access log (TCP_TUNNEL to :443 and the signaling port, the 403 to
#     TURN TCP 3478);
#   - the sender's route line ("relay (TURN over tls via proxy)");
#   - sha256 of what landed; the exec's own stdout.
#
# Gates:
#   P1  join through the proxy (enrolment over proxied signaling)
#   P2  send to the owner: byte for byte, route says "via proxy"
#   P3  exec on the owner: exact stdout, rc 0
#   P4  the block was real: UDP was attempted and dropped
#   P5  no direct TCP attempt beside the proxy (sandbox-polite)
#   P6  squid tunnelled TLS 443 and signaling, and refused TURN TCP 3478
#   P7  without credentials: exit 7 and one line naming the proxy and the 407
#   P8  doctor --json in the ns: signaling ok via proxy, a TLS relay row ok via proxy
#
# Requires: passwordless sudo, ip, iptables, squid, turnserver (coturn),
# openssl, python3 with backend/requirements.txt. Refuses (exit 2) when one is
# missing. Honors TUNLION_BIN, TUNLION_TEST_VENV, CARRIER_GATE_EVIDENCE.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="$(realpath "${TUNLION_BIN:?set TUNLION_BIN to the tunlion binary under test}")"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/carrier-proxy.XXXXXX")"
chmod 755 "$WORK"
EVID="${CARRIER_GATE_EVIDENCE:-$WORK/evidence}"
mkdir -p "$EVID"
ME="$(id -un)"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n== %s ==\n' "$*" | tee -a "$EVID/summary.txt"; }
ok()  { echo "PASS: $1" | tee -a "$EVID/summary.txt"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1" | tee -a "$EVID/summary.txt"; FAIL=$((FAIL+1)); FAILED="$FAILED $2"; }
note() { echo "  $1" | tee -a "$EVID/summary.txt"; }
run_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi; }

N=$((BASHPID % 200 + 20))
NET="10.216.$N"; H="$NET.1"
NS="cpg$N"; H_IF="cph$N"; N_IF="cpn$N"
PORT=$((8300 + N % 100))
PPORT=3129
PIDS=(); ROOT_PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  for p in "${ROOT_PIDS[@]:-}"; do run_root kill "$p" 2>/dev/null || true; done
  [ -f "$WORK/squid/squid.pid" ] && run_root kill -9 "$(cat "$WORK/squid/squid.pid")" 2>/dev/null
  [ -f "$WORK/turn.pid" ] && run_root kill -9 "$(cat "$WORK/turn.pid")" 2>/dev/null
  run_root ip netns del "$NS" 2>/dev/null || true
  run_root ip link del "$H_IF" 2>/dev/null || true
  for f in "$WORK"/*.log "$WORK"/squid/*.log; do run_root cat "$f" >"$EVID/${f##*/}" 2>/dev/null; done
  rm -rf "$WORK/home-"* 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------- preflight
for cmd in ip iptables squid turnserver openssl python3 sha256sum curl; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "REFUSED: $cmd is required"; exit 2; }
done
[ -x "$BIN" ] || { echo "REFUSED: no tunlion binary at $BIN"; exit 2; }
if [ "$(id -u)" -ne 0 ]; then sudo -n true 2>/dev/null || { echo "REFUSED: passwordless sudo is required"; exit 2; }; fi
NCSA="$(ls /usr/lib/squid/basic_ncsa_auth /usr/lib64/squid/basic_ncsa_auth 2>/dev/null | head -1)"
[ -n "$NCSA" ] || { echo "REFUSED: squid's basic_ncsa_auth helper is missing"; exit 2; }

# ------------------------------------------------------------------ topology
run_root ip netns add "$NS"
run_root ip -n "$NS" link set lo up
run_root ip link add "$H_IF" type veth peer name "$N_IF"
run_root ip link set "$N_IF" netns "$NS"
run_root ip addr add "$H/30" dev "$H_IF"
run_root ip link set "$H_IF" up
run_root ip -n "$NS" addr add "$NET.2/30" dev "$N_IF"
run_root ip -n "$NS" link set "$N_IF" up
run_root ip -n "$NS" route add default via "$H"
run_root ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
nsx() { run_root ip netns exec "$NS" "$@"; }
nsx iptables -F OUTPUT
nsx iptables -A OUTPUT -o lo -j ACCEPT
nsx iptables -A OUTPUT -p tcp -d "$H" --dport "$PPORT" -m comment --comment proxy -j ACCEPT
nsx iptables -A OUTPUT -p udp -m comment --comment udpdrop -j DROP
nsx iptables -A OUTPUT -p tcp -m comment --comment tcpdrop -j DROP
nsx iptables -A OUTPUT -m comment --comment otherdrop -j DROP
# Inbound too: a sandbox is not reachable from outside. Without this the
# owner's direct-QUIC dial INTO the namespace succeeds and the profile tests
# "one side reachable" instead of "proxy only" (the first run did exactly that).
nsx iptables -F INPUT
nsx iptables -A INPUT -i lo -j ACCEPT
nsx iptables -A INPUT -p tcp -s "$H" --sport "$PPORT" -j ACCEPT
nsx iptables -A INPUT -m comment --comment indrop -j DROP
counter() { nsx iptables -L -v -n -x | grep -F "/* $1 */" | awk '{s+=$1} END {print s+0}'; }

# ------------------------------------------------------------ TLS for coturn
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=carrier gate CA" \
  -keyout "$WORK/ca.key" -out "$WORK/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=$H" -keyout "$WORK/turn.key" -out "$WORK/turn.csr" >/dev/null 2>&1
printf 'subjectAltName=IP:%s\n' "$H" >"$WORK/san.ext"
openssl x509 -req -in "$WORK/turn.csr" -CA "$WORK/ca.crt" -CAkey "$WORK/ca.key" -CAcreateserial \
  -days 2 -extfile "$WORK/san.ext" -out "$WORK/turn.crt" >/dev/null 2>&1 \
  || { echo "REFUSED: could not mint the TURN certificate"; exit 2; }
chmod 644 "$WORK/turn.key"

# -------------------------------------------------------------------- coturn
TSEC="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
cat >"$WORK/turnserver.conf" <<EOF
listening-ip=$H
relay-ip=$H
listening-port=3478
tls-listening-port=443
cert=$WORK/turn.crt
pkey=$WORK/turn.key
use-auth-secret
static-auth-secret=$TSEC
realm=carrier.test
fingerprint
no-cli
no-multicast-peers
min-port=49400
max-port=49600
pidfile=$WORK/turn.pid
log-file=$WORK/turn.log
simple-log
EOF
run_root turnserver -c "$WORK/turnserver.conf" >/dev/null 2>&1 &
ROOT_PIDS+=($!)

# --------------------------------------------------------------------- squid
mkdir -p "$WORK/squid"; chmod 777 "$WORK/squid"
PUSER=gate; PPASS="p$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s:%s\n' "$PUSER" "$(openssl passwd -apr1 "$PPASS")" >"$WORK/squid/passwd"
chmod 644 "$WORK/squid/passwd"
cat >"$WORK/squid/squid.conf" <<EOF
http_port $H:$PPORT
visible_hostname carrier-gate
pid_filename $WORK/squid/squid.pid
cache_log $WORK/squid/cache.log
access_log stdio:$WORK/squid/access.log squid
cache deny all
cache_mem 8 MB
coredump_dir $WORK/squid
shutdown_lifetime 1 seconds
auth_param basic program $NCSA $WORK/squid/passwd
auth_param basic realm carrier-gate
acl authed proxy_auth REQUIRED
acl SSL_ports port 443 $PORT
acl CONNECT method CONNECT
http_access deny CONNECT !SSL_ports
http_access allow authed
http_access deny all
EOF
run_root squid -N -f "$WORK/squid/squid.conf" >"$WORK/squid/stdout.log" 2>&1 &
ROOT_PIDS+=($!)

# ------------------------------------------------------------------- backend
SERVER="http://$H:$PORT"
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    FIL_TURN_HOST="turn:$H:3478,turn:$H:3478?transport=tcp,turns:$H:443?transport=tcp" \
    FIL_TURN_SECRET="$TSEC" "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
PIDS+=($!)
for _ in $(seq 1 40); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "REFUSED: no backend at $SERVER"; tail -20 "$WORK/backend.log"; exit 2; }
for _ in $(seq 1 20); do ss -ltn | grep -q "$H:443 " && ss -ltn | grep -q "$H:$PPORT " && break; sleep 0.5; done
ss -ltn | grep -q "$H:443 " || { echo "REFUSED: coturn is not listening on $H:443"; tail -20 "$WORK/turn.log"; exit 2; }
ss -ltn | grep -q "$H:$PPORT " || { echo "REFUSED: squid is not listening on $H:$PPORT"; tail -20 "$WORK/squid/cache.log"; exit 2; }
note "signaling $SERVER, coturn $H (3478 udp/tcp, 443 tls), squid $H:$PPORT"

# ------------------------------------------------------------- the two ends
A="$WORK/home-A"; B="$WORK/home-B"; mkdir -p "$A" "$B" "$WORK/A-drop"; chmod 755 "$B"
AENV=(env HOME="$A" TUNLION_CONFIG_DIR="$A" TUNLION_NONINTERACTIVE=1 SSL_CERT_FILE="$WORK/ca.crt")
PROXY_URL="http://$PUSER:$PPASS@$H:$PPORT"
# B: inside the namespace, as this user, with only the proxy to talk to.
b_run() {  # $1 = seconds, $2 = proxy url, rest = tunlion args
  local secs="$1" purl="$2"; shift 2
  nsx timeout -k 5 "$secs" sudo -n -u "$ME" env HOME="$B" TUNLION_CONFIG_DIR="$B" TUNLION_NONINTERACTIVE=1 \
    SSL_CERT_FILE="$WORK/ca.crt" HTTPS_PROXY="$purl" HTTP_PROXY="$purl" \
    "$BIN" --server "$SERVER" "$@"
}

timeout 60 "${AENV[@]}" "$BIN" --server "$SERVER" init --name alpha --recovery-file "$A/rec.txt" --yes >"$WORK/A-init.log" 2>&1 \
  || { echo "REFUSED: init failed"; tail "$WORK/A-init.log"; exit 2; }
"${AENV[@]}" TUNLION_L2=1 "$BIN" --server "$SERVER" up --dir "$WORK/A-drop" >"$WORK/A-up.log" 2>&1 &
PIDS+=($!)
sleep 4
timeout 45 "${AENV[@]}" "$BIN" --server "$SERVER" add --for carrier-b --allow shell,transfer --out "$WORK/inv.txt" --yes \
  >"$WORK/add.log" 2>&1 || { echo "REFUSED: add failed"; tail "$WORK/add.log"; exit 2; }

say "P1: join through the proxy"
b_run 90 "$PROXY_URL" join --invite-file "$WORK/inv.txt" --name carrier-b --no-interactive -v \
  >"$EVID/P1-join.out" 2>"$EVID/P1-join.err"
rc=$?
if [ "$rc" -eq 0 ] && "${AENV[@]}" "$BIN" devices 2>/dev/null | grep -q carrier-b; then
  ok "P1: carrier-b joined alpha with only the proxy reachable"
else
  bad "P1: join failed (rc=$rc)" P1; tail -15 "$EVID/P1-join.err"
fi
"${AENV[@]}" "$BIN" grant carrier-b shell -y >"$WORK/grant.log" 2>&1 || note "grant: $(tail -1 "$WORK/grant.log")"

say "P2: send to alpha through the proxy"
PAY="$WORK/payload.bin"; head -c $((3 * 1024 * 1024 + 13)) /dev/urandom >"$PAY"; chmod 644 "$PAY"
PAYHASH="$(sha256sum "$PAY" | cut -d' ' -f1)"
b_run 150 "$PROXY_URL" send "$PAY" --to alpha --timeout 120 -vv \
  >"$EVID/P2-send.out" 2>"$EVID/P2-send.err"
rc=$?
got="$(find "$WORK/A-drop" -type f -name 'payload.bin*' | head -1)"
gothash=""; [ -n "$got" ] && gothash="$(sha256sum "$got" | cut -d' ' -f1)"
route="$(grep -hoE 'route: [^[:cntrl:]]*' "$EVID/P2-send.err" | sed -E 's/\x1b\[[0-9;]*m//g' | head -1)"
note "send rc=$rc $route"
if [ "$rc" -eq 0 ] && [ "$gothash" = "$PAYHASH" ]; then ok "P2: delivered byte for byte (sha256 $PAYHASH)"
else bad "P2: transfer failed (rc=$rc hash=${gothash:-none})" P2; tail -15 "$EVID/P2-send.err"; fi
if printf '%s' "$route" | grep -q 'relay (TURN over tls via proxy)'; then ok "P2: route is shown as '$route'"
else bad "P2: route '$route' does not say 'relay (TURN over tls via proxy)'" P2; fi

say "P3: exec on alpha through the proxy"
out="$(b_run 120 "$PROXY_URL" exec alpha -- /bin/echo "carrier gate" 2>"$EVID/P3-exec.err" </dev/null)"
rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "carrier gate" ]; then ok "P3: exec ran and returned its exact stdout"
else bad "P3: exec failed (rc=$rc out='$out')" P3; tail -15 "$EVID/P3-exec.err"; fi

say "P4/P5: the namespace firewall"
nsx iptables -L OUTPUT -v -n -x >"$EVID/counters.txt"
u=$(counter udpdrop); t=$(counter tcpdrop); p=$(counter proxy)
note "udpdrop=$u tcpdrop=$t proxy=$p"
if [ "$u" -gt 0 ]; then ok "P4: UDP was attempted and dropped ($u packets): the block was real"
else bad "P4: no UDP was dropped; the block was not exercised" P4; fi
if [ "$t" -eq 0 ] && [ "$p" -gt 0 ]; then ok "P5: every TCP connection went to the proxy ($p), none direct"
else bad "P5: $t direct TCP packet(s) beside the proxy (proxy=$p)" P5; fi

say "P6: what squid carried"
# squid writes its log as its own user.
run_root cat "$WORK/squid/access.log" >"$EVID/squid-access.log" 2>/dev/null
SQLOG="$EVID/squid-access.log"
if grep -E "TCP_TUNNEL/200 .*CONNECT $H:443 " "$SQLOG" >/dev/null; then ok "P6: squid tunnelled TLS to the relay on 443"
else bad "P6: no CONNECT tunnel to $H:443 in squid's log" P6; fi
if grep -E "TCP_TUNNEL/200 .*CONNECT $H:$PORT " "$SQLOG" >/dev/null; then ok "P6: signaling went through a CONNECT tunnel"
else bad "P6: no CONNECT tunnel to the signaling port" P6; fi
if grep -E "/403 .*CONNECT $H:3478 " "$SQLOG" >/dev/null; then ok "P6: TURN TCP 3478 was tried and refused by policy (TLS then went at once)"
else note "P6: no refused CONNECT to 3478 (TCP TURN not tried through the proxy)"; fi

say "P7: no credentials"
b_run 60 "http://$H:$PPORT" send "$PAY" --to alpha --timeout 30 \
  >"$EVID/P7.out" 2>"$EVID/P7.err"
rc=$?
line="$(sed -E 's/\x1b\[[0-9;]*m//g' "$EVID/P7.err" | grep -m1 "tunlion server")"
note "rc=$rc: $line"
if [ "$rc" -eq 7 ] && printf '%s' "$line" | grep -q "the proxy at $H:$PPORT" && printf '%s' "$line" | grep -q 407 \
   && printf '%s' "$line" | grep -q "put credentials in the proxy URL" && ! printf '%s' "$line" | grep -q DNS; then
  ok "P7: exit 7 and one line naming the proxy, the 407 and what to do"
else bad "P7: expected exit 7 and the proxy line, got rc=$rc" P7; tail -5 "$EVID/P7.err"; fi

say "P8: doctor --json in the namespace"
b_run 60 "$PROXY_URL" doctor --json \
  >"$EVID/P8-doctor.json" 2>"$EVID/P8-doctor.err"
if python3 - "$EVID/P8-doctor.json" "$H" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); h = sys.argv[2]
c = d["carriers"]
assert c["signaling"]["carrier"].startswith("proxy "), c["signaling"]
assert c["signaling"]["result"]["ok"], c["signaling"]
tls = [r for r in c["relays"] if r["transport"] == "tls" and r["target"] == f"{h}:443"]
assert tls and tls[0]["carrier"].startswith("proxy ") and tls[0]["result"]["ok"], c["relays"]
udp = [r for r in c["relays"] if r["transport"] == "udp"]
assert udp and not udp[0]["result"]["ok"], c["relays"]
PY
then ok "P8: doctor shows signaling and TLS relay ok via the proxy, UDP blocked"
else bad "P8: doctor carrier table is wrong" P8; head -c 2000 "$EVID/P8-doctor.json"; fi

echo | tee -a "$EVID/summary.txt"
if [ "$FAIL" -eq 0 ]; then echo "RESULT carrier-proxy PASS $PASS checks" | tee -a "$EVID/summary.txt"; exit 0; fi
echo "RESULT carrier-proxy FAIL $FAIL check(s):$FAILED" | tee -a "$EVID/summary.txt"; exit 1
