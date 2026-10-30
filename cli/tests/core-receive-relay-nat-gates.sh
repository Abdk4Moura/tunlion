#!/usr/bin/env bash
# E2E relay/NAT acceptance: a real CLI `send --code` in one NATed Linux network
# namespace delivers a file to `Core::receive_code` in another, over a real
# coturn TURN allocation provisioned by the fixture backend. Nothing here fakes
# a relay: the receiver is the same `tunlion-core` helper the direct E2E gate
# uses, the sender is the product CLI, and the signaling/ICE servers are the
# real Flask backend plus a pinned coturn container.
#
# Topology (all private to this gate):
#
#   sender ns 10.203.78.2 --.
#                            +-- router ns (MASQUERADE) -- 10.203.77.0/24 -- host
#   receiver ns 10.203.79.2 --'                                      (backend + coturn)
#
# The router FORWARD policy is DROP: only the explicit sender<->WAN and
# receiver<->WAN pairs are accepted, so the two private /24s cannot reach each
# other directly. That is asserted with a UDP sentinel probe and the DROP-rule
# counter, not assumed. The sender passes the product `--relay` flag and the
# receiver config sets `relay = always`, so the only selected pair is the
# coturn relay pair. The gate asserts the sender reported a relay route,
# coturn logged a successful ALLOCATE, tcpdump observed relay-port UDP packets,
# the NAT counters moved, and the receiver's summary/bytes/sha256 match.
#
# Requires passwordless sudo, iproute2, iptables, docker, python3, curl and both
# binaries. Refuses (exit 2) when a precondition is absent; it never silently
# skips. Honors TUNLION_BIN, TUNLION_CORE_BIN, TUNLION_TEST_VENV and
# TUNLION_CORE_RELAY_PORT.

set -uo pipefail
# The shared worker serializes jobs with `flock build.lock` on fd 3. Close that
# inherited descriptor here so no backend/coturn child can keep the lock wedged
# if this script or its wrapper dies before cleanup. The helper's parent flock
# still owns the lock; only this process tree drops its copy.
exec 3>&- 2>/dev/null || true
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
# shellcheck source=cli/tests/lib/backend.sh
source "$HERE/lib/backend.sh"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CORE_BIN="${TUNLION_CORE_BIN:-$(dirname "$BIN")/receive-code}"
PYV="${TUNLION_TEST_VENV:-python3}"
PORT="${TUNLION_CORE_RELAY_PORT:-8199}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/core-relay-nat.XXXXXX")"

say() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED $1"; }

PASS=0
FAIL=0
FAILED=""
PIDS=()
CT=""
SUFFIX="$(printf '%04x' $((BASHPID % 65536)))"
R_NS="cr${SUFFIX}r"
S_NS="cr${SUFFIX}s"
C_NS="cr${SUFFIX}c"
H_IF="ch${SUFFIX}"
R_UP="ru${SUFFIX}"
S_IF="cs${SUFFIX}"
R_S="rs${SUFFIX}"
C_IF="cc${SUFFIX}"
R_C="rc${SUFFIX}"

run_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi
}
run_ns() {
  local ns="$1"; shift
  run_root ip netns exec "$ns" "$@"
}
docker_bin() {
  if docker info >/dev/null 2>&1; then docker "$@"; else sudo -n docker "$@"; fi
}
docker_timeout() {
  local secs="$1"; shift
  if docker info >/dev/null 2>&1; then timeout "$secs" docker "$@"; else timeout "$secs" sudo -n docker "$@"; fi
}
wait_bounded() {
  local pid="$1" secs="$2" i
  for i in $(seq 1 $((secs * 2))); do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid"
      return $?
    fi
    sleep 0.5
  done
  kill "$pid" 2>/dev/null || true
  sleep 1
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 124
}
cleanup() {
  backend_stop "${BACKEND_PID:-}"
  local p
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  if [ -n "$CT" ]; then docker_bin stop "$CT" >/dev/null 2>&1 || true; fi
  for ns in "$C_NS" "$S_NS" "$R_NS"; do run_root ip netns del "$ns" 2>/dev/null || true; done
  run_root ip link del "$H_IF" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------ preflight
for cmd in ip iptables docker curl sha256sum tcpdump; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "REFUSED: $cmd is required"; exit 2; }
done
[ -x "$BIN" ] || { echo "REFUSED: no tunlion binary at $BIN (build: cargo build --release -p tunlion)"; exit 2; }
[ -x "$CORE_BIN" ] || {
  echo "REFUSED: no Core receive helper at $CORE_BIN"
  echo "  build: cargo build --release -p tunlion-core --bin receive-code"
  exit 2
}
if [ "$(id -u)" -ne 0 ]; then
  sudo -n true >/dev/null 2>&1 || { echo "REFUSED: passwordless sudo is required for network namespaces"; exit 2; }
fi
docker_bin info >/dev/null 2>&1 || { echo "REFUSED: docker is not usable"; exit 2; }
"$PYV" -c 'import sys; sys.exit(0)' >/dev/null 2>&1 || { echo "REFUSED: python interpreter $PYV is not usable"; exit 2; }

# ------------------------------------------------------------------- topology
HOST_IP=10.203.77.1
ROUTER_IP=10.203.77.2
S_ROUTER=10.203.78.1
S_IP=10.203.78.2
C_ROUTER=10.203.79.1
C_IP=10.203.79.2
SERVER="http://$HOST_IP:$PORT"

run_root ip netns add "$R_NS"
run_root ip netns add "$S_NS"
run_root ip netns add "$C_NS"
for ns in "$R_NS" "$S_NS" "$C_NS"; do run_root ip -n "$ns" link set lo up; done

run_root ip link add "$H_IF" type veth peer name "$R_UP"
run_root ip link set "$R_UP" netns "$R_NS"
run_root ip addr add "$HOST_IP/24" dev "$H_IF"
run_root ip link set "$H_IF" up
run_root ip -n "$R_NS" addr add "$ROUTER_IP/24" dev "$R_UP"
run_root ip -n "$R_NS" link set "$R_UP" up

run_root ip link add "$S_IF" type veth peer name "$R_S"
run_root ip link set "$S_IF" netns "$S_NS"
run_root ip link set "$R_S" netns "$R_NS"
run_root ip -n "$S_NS" addr add "$S_IP/24" dev "$S_IF"
run_root ip -n "$R_NS" addr add "$S_ROUTER/24" dev "$R_S"
run_root ip -n "$S_NS" link set "$S_IF" up
run_root ip -n "$R_NS" link set "$R_S" up

run_root ip link add "$C_IF" type veth peer name "$R_C"
run_root ip link set "$C_IF" netns "$C_NS"
run_root ip link set "$R_C" netns "$R_NS"
run_root ip -n "$C_NS" addr add "$C_IP/24" dev "$C_IF"
run_root ip -n "$R_NS" addr add "$C_ROUTER/24" dev "$R_C"
run_root ip -n "$C_NS" link set "$C_IF" up
run_root ip -n "$R_NS" link set "$R_C" up

run_ns "$S_NS" ip route add default via "$S_ROUTER"
run_ns "$C_NS" ip route add default via "$C_ROUTER"
# The host needs an explicit path to both private /24s for the WAN->receiver
# control probe; coturn/backend themselves only speak to the NAT public IP.
run_root ip route add 10.203.78.0/24 via "$ROUTER_IP"
run_root ip route add 10.203.79.0/24 via "$ROUTER_IP"
run_ns "$R_NS" sysctl -q -w net.ipv4.ip_forward=1
run_ns "$R_NS" iptables -t nat -A POSTROUTING -s 10.203.78.0/24 -o "$R_UP" -j MASQUERADE
run_ns "$R_NS" iptables -t nat -A POSTROUTING -s 10.203.79.0/24 -o "$R_UP" -j MASQUERADE
# Default-deny the router, then permit ONLY the two WAN legs. Without this
# policy the router's connected /24 routes let S and C reach each other
# directly and the "both peers behind NAT" claim would be false.
run_ns "$R_NS" iptables -P FORWARD DROP
for pair in "$R_S:$R_UP" "$R_UP:$R_S" "$R_C:$R_UP" "$R_UP:$R_C"; do
  run_ns "$R_NS" iptables -A FORWARD -i "${pair%%:*}" -o "${pair##*:}" -j ACCEPT
done
run_ns "$R_NS" iptables -A FORWARD -s 10.203.78.0/24 -d 10.203.79.0/24 -j DROP
run_ns "$R_NS" iptables -A FORWARD -s 10.203.79.0/24 -d 10.203.78.0/24 -j DROP

# ------------------------------------------------------ backend + real coturn
TURN_USER="tlrelay"
TURN_PASS="$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')"
ICE_JSON="[{\"urls\":\"stun:$HOST_IP:3478\"},{\"urls\":\"turn:$HOST_IP:3478?transport=udp\",\"username\":\"$TURN_USER\",\"credential\":\"$TURN_PASS\"}]"
CT="cr-coturn-$SUFFIX"
docker_timeout 180 run -d --rm --name "$CT" --network host coturn/coturn:4.6.2 -n -v \
  --listening-ip="$HOST_IP" --relay-ip="$HOST_IP" --listening-port=3478 \
  --min-port=49200 --max-port=49300 --realm=tunlion.test --lt-cred-mech --no-tls --no-dtls \
  --allow-loopback-peers --user="$TURN_USER:$TURN_PASS" --cli-password=x >/dev/null
for _ in $(seq 1 40); do
  [ "$(docker_bin inspect -f '{{.State.Running}}' "$CT" 2>/dev/null)" = "true" ] && break
  sleep 0.25
done
if [ "$(docker_bin inspect -f '{{.State.Running}}' "$CT" 2>/dev/null)" != "true" ]; then
  docker_bin logs "$CT" >"$WORK/coturn.log" 2>&1 || true
  echo "REFUSED: coturn did not start; its log is at $WORK/coturn.log"
  cat "$WORK/coturn.log" | tail -20
  exit 2
fi

backend_start "$CLI_DIR/../backend" "$PYV" "$WORK/backend.log" \
  PORT="$PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
  FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
  FIL_ICE_SERVERS="$ICE_JSON"
PIDS+=("$BACKEND_PID")
for _ in $(seq 1 60); do curl --max-time 3 --connect-timeout 2 -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
if ! curl --max-time 3 --connect-timeout 2 -fsS "$SERVER/api/health" >/dev/null 2>&1; then
  echo "REFUSED: backend did not become healthy at $SERVER"
  tail -30 "$WORK/backend.log" 2>/dev/null
  exit 2
fi

# ------------------------------------------------------------------- configs
S="$WORK/sender"; R="$WORK/receiver"; INBOX="$WORK/inbox"
mkdir -p "$S" "$R" "$INBOX"
bounded_init() {
  local dir="$1" name="$2" rc
  timeout -k 5 30 env TUNLION_CONFIG_DIR="$dir" "$BIN" init --name "$name" \
    --recovery-file "$dir/rec.txt" --yes >"$WORK/init-$name.log" 2>&1
  rc=$?
  if [ "$rc" -eq 124 ]; then
    echo "REFUSED: $name init WEDGED after 30s"; tail -20 "$WORK/init-$name.log"; exit 2
  elif [ "$rc" -ne 0 ]; then
    echo "REFUSED: $name init failed (rc=$rc)"; tail -20 "$WORK/init-$name.log"; exit 2
  fi
}
bounded_init "$S" relay-sender
bounded_init "$R" relay-receiver
printf 'server %s\n' "$SERVER" >>"$R/config"
timeout -k 5 15 env TUNLION_CONFIG_DIR="$R" "$BIN" set relay always >/dev/null 2>&1 || true
if ! grep -Eq '^relay[[:space:]]+always$' "$R/config"; then printf 'relay always\n' >>"$R/config"; fi
grep -Eq '^relay[[:space:]]+always$' "$R/config" || { echo "REFUSED: could not force receiver relay=always"; exit 2; }

PAY="$WORK/relay-payload.bin"
"$PYV" - "$PAY" <<'PY'
import sys
size = 16 * 1024 * 1024 + 137
block = bytes(range(256)) * 4096
with open(sys.argv[1], "wb") as f:
    left = size
    while left:
        n = min(left, len(block))
        f.write(block[:n])
        left -= n
PY
PAYNAME="$(basename "$PAY")"
PAYHASH="$(sha256sum "$PAY" | cut -d' ' -f1)"
PAYSIZE="$(stat -c %s "$PAY")"

SENT="$WORK/sentinel.py"
cat >"$SENT" <<'PY'
import socket, sys
port, ready, hit = int(sys.argv[1]), sys.argv[2], sys.argv[3]
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", port))
s.settimeout(4)
open(ready, "w").close()
try:
    s.recvfrom(128)
    open(hit, "w").close()
except socket.timeout:
    pass
PY

LISTEN_PID=""
start_listener() {
  local port="$1" ready="$2" hit="$3" i
  rm -f "$ready" "$hit"
  run_ns "$C_NS" "$PYV" "$SENT" "$port" "$ready" "$hit" >"$WORK/sentinel-$port.log" 2>&1 &
  LISTEN_PID=$!
  PIDS+=("$LISTEN_PID")
  for i in $(seq 1 40); do
    [ -f "$ready" ] && return 0
    kill -0 "$LISTEN_PID" 2>/dev/null || break
    sleep 0.1
  done
  return 1
}
send_udp_host() {
  "$PYV" -c 'import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.sendto(b"control",(sys.argv[1],int(sys.argv[2])))' "$C_IP" "$1"
}
send_udp_sender() {
  run_ns "$S_NS" "$PYV" -c 'import socket,sys
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
for _ in range(5): s.sendto(b"cross",(sys.argv[1],int(sys.argv[2])))' "$C_IP" "$1"
}
wait_file() {
  local file="$1" secs="$2" i
  for i in $(seq 1 $((secs * 10))); do [ -f "$file" ] && return 0; sleep 0.1; done
  return 1
}

code_of() {
  "$PYV" - "$1" 2>/dev/null <<'PY'
import json, sys
try:
    lines = open(sys.argv[1], errors="replace")
except OSError:
    raise SystemExit(0)
for line in lines:
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get("event") == "code" and d.get("code"):
        print(d["code"])
        break
PY
}

# ------------------------------------------- cross-subnet direct-path probe
say "prove the router cannot carry a direct sender->receiver UDP path"
CONTROL_PORT=40101
BLOCKED_PORT=40102
CONTROL_HIT="$WORK/control.hit"
BLOCKED_HIT="$WORK/blocked.hit"
CONTROL_OK=0
BLOCKED_OK=0
DROP_HITS=0
if start_listener "$CONTROL_PORT" "$WORK/control.ready" "$CONTROL_HIT"; then
  send_udp_host "$CONTROL_PORT" || true
  wait_file "$CONTROL_HIT" 4 && CONTROL_OK=1
fi
if [ -n "$LISTEN_PID" ]; then wait_bounded "$LISTEN_PID" 6 >/dev/null 2>&1 || true; fi
if start_listener "$BLOCKED_PORT" "$WORK/blocked.ready" "$BLOCKED_HIT"; then
  send_udp_sender "$BLOCKED_PORT" || true
  sleep 2
  [ ! -f "$BLOCKED_HIT" ] && BLOCKED_OK=1
fi
if [ -n "$LISTEN_PID" ]; then wait_bounded "$LISTEN_PID" 6 >/dev/null 2>&1 || true; fi
DROP_HITS="$(run_ns "$R_NS" iptables -L FORWARD -v -n | awk '/DROP/ && /10\.203\.78\.0\/24/ && /10\.203\.79\.0\/24/ {print $1; exit}')"
if [ "$CONTROL_OK" -eq 1 ] && [ "$BLOCKED_OK" -eq 1 ] && [ "${DROP_HITS:-0}" -gt 0 ]; then
  ok "R6: WAN->receiver control arrived, sender->receiver was blocked (DROP hits=$DROP_HITS)"
else
  bad "R6: cross-subnet block not proven (control=$CONTROL_OK blocked=$BLOCKED_OK drop=${DROP_HITS:-0})"
fi

# ------------------------------------------------------------ sender + Core
run_root tcpdump -i any -n -U -w "$WORK/turn.pcap" 'udp portrange 49200-49300' \
  >"$WORK/tcpdump.log" 2>&1 &
TCPID=$!
PIDS+=("$TCPID")
sleep 1
kill -0 "$TCPID" 2>/dev/null || { echo "REFUSED: tcpdump could not start"; cat "$WORK/tcpdump.log"; exit 2; }
say "start the CLI sender inside the sender NAT namespace (--relay)"
run_ns "$S_NS" env TUNLION_CONFIG_DIR="$S" TUNLION_NONINTERACTIVE=1 \
  "$BIN" --server "$SERVER" send "$PAY" --code --word gigantic-element --relay --json -v \
  </dev/null >"$WORK/send.json" 2>"$WORK/send.err" &
SPID=$!
PIDS+=("$SPID")
CODE=""
for _ in $(seq 1 600); do
  CODE="$(code_of "$WORK/send.json")"
  [ -n "$CODE" ] && break
  kill -0 "$SPID" 2>/dev/null || break
  sleep 0.1
done
if [ -z "$CODE" ]; then
  bad "R0: sender minted no code"
  echo "--- send.json"; tail -20 "$WORK/send.json" 2>/dev/null
  echo "--- send.err"; tail -30 "$WORK/send.err" 2>/dev/null
  echo; echo "RESULT core-relay-nat FAIL $FAIL gate(s)"; exit 1
fi

say "run Core::receive_code inside the receiver NAT namespace (relay=always)"
run_ns "$C_NS" env -u TUNLION_CONFIG_DIR "$CORE_BIN" \
  --config-dir "$R" --dir "$INBOX" --code "$CODE" --yes --timeout 90 \
  >"$WORK/receiver.json" 2>"$WORK/receiver.err" &
RPID=$!
PIDS+=("$RPID")

wait_bounded "$SPID" 150; SRC=$?
wait_bounded "$RPID" 150; RRC=$?
kill -INT "$TCPID" 2>/dev/null || true
wait_bounded "$TCPID" 5 >/dev/null 2>&1 || true
TURN_PKTS="$(run_root tcpdump -nn -r "$WORK/turn.pcap" 2>/dev/null | grep -c 'UDP' || true)"
echo "## sender rc=$SRC receiver rc=$RRC relay_udp_packets=${TURN_PKTS:-0}"
echo "--- receiver.json"; cat "$WORK/receiver.json"
echo "--- receiver.err"; tail -20 "$WORK/receiver.err"

# R1: sender delivered and acknowledged the sha256.
if [ "$SRC" -eq 0 ] && "$PYV" - "$WORK/send.json" "$PAY" <<'PY'
import hashlib, json, sys
docs = []
for line in open(sys.argv[1], errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        docs.append(json.loads(line))
    except Exception:
        pass
res = next((d for d in reversed(docs) if d.get("verb") == "send" and "ok" in d), None)
assert res is not None, docs
assert res["ok"] is True, res
assert res["files"] and all(f["delivered"] for f in res["files"]), res
want = hashlib.sha256(open(sys.argv[2], "rb").read()).hexdigest()
assert res["files"][0]["sha256"] == want, (res["files"][0]["sha256"], want)
PY
then ok "R1: sender exited 0 with every file delivered and its sha256 acknowledged"
else
  bad "R1: sender did not report a verified delivery (rc=$SRC)"
  tail -20 "$WORK/send.err" 2>/dev/null
fi

# R2: bytes landed in the Core receiver inbox.
if [ -f "$INBOX/$PAYNAME" ] && cmp -s "$PAY" "$INBOX/$PAYNAME"; then
  ok "R2: $PAYNAME landed in the receiver inbox byte for byte ($PAYSIZE bytes)"
else
  bad "R2: $PAYNAME is missing or differs in the receiver inbox"
fi

# R3: Core's summary carries stored/bytes/sha256.
SUMMARY="$("$PYV" - "$WORK/receiver.json" "$PAY" <<'PY' 2>"$WORK/summary.err"
import hashlib, json, os, sys
lines = [line for line in open(sys.argv[1], errors="replace") if line.strip()]
assert lines, "receiver printed no summary"
s = json.loads(lines[-1])
want = os.path.basename(sys.argv[2])
data = open(sys.argv[2], "rb").read()
assert s.get("bytes") == len(data), s
assert s.get("refused") == [], s
stored = s.get("stored")
assert stored and len(stored) == 1, s
f = stored[0]
assert f["name"] == want, f
assert f["stored_name"] == want, f
assert f["bytes"] == len(data), f
assert f["sha256"] == hashlib.sha256(data).hexdigest(), f
print("stored=%s bytes=%d sha256=%s" % (f["stored_name"], f["bytes"], f["sha256"]))
PY
)"
if [ "$RRC" -eq 0 ] && [ -n "$SUMMARY" ]; then
  ok "R3: Core::receive_code returned the stored summary and sha256 ($SUMMARY)"
else
  bad "R3: Core::receive_code did not return the expected summary (rc=$RRC)"
  cat "$WORK/summary.err" 2>/dev/null
fi

# R4: the CLI actually selected the relay path and said so.
if grep -hEqi 'route: relay|"route"[[:space:]]*:[[:space:]]*"relay"|on relay, via a TURN server' \
    "$WORK/send.json" "$WORK/send.err"; then
  ok "R4: sender reported the relay route and TURN banner"
else
  bad "R4: sender did not report a relay route"
  grep -hiE 'route|relay|turn' "$WORK/send.json" "$WORK/send.err" | tail -10
fi

# R5: successful ALLOCATE plus relay-port data packets, not just startup text.
docker_bin logs "$CT" >"$WORK/coturn.log" 2>&1 || true
ALLOC_OK=0
if grep -Eqi 'ALLOCATE.*success' "$WORK/coturn.log"; then ALLOC_OK=1; fi
if [ "$ALLOC_OK" -eq 1 ] && [ "${TURN_PKTS:-0}" -gt 0 ]; then
  ok "R5: coturn logged ALLOCATE success and tcpdump saw ${TURN_PKTS} relay-port UDP packet(s)"
else
  bad "R5: TURN data path not proven (allocate=$ALLOC_OK relay_packets=${TURN_PKTS:-0})"
  tail -30 "$WORK/coturn.log"
  tail -10 "$WORK/tcpdump.log" 2>/dev/null
fi

# R7: both NAT rules carried packets, proving the namespaces were the path.
NAT_S="$(run_ns "$R_NS" iptables -t nat -L POSTROUTING -v -n | awk '/MASQUERADE/ && /10\.203\.78\.0\/24/ {print $1; exit}')"
NAT_C="$(run_ns "$R_NS" iptables -t nat -L POSTROUTING -v -n | awk '/MASQUERADE/ && /10\.203\.79\.0\/24/ {print $1; exit}')"
if [ "${NAT_S:-0}" -gt 0 ] && [ "${NAT_C:-0}" -gt 0 ]; then
  ok "R7: both NAT rules carried traffic (sender=$NAT_S receiver=$NAT_C packets)"
else
  bad "R7: NAT counters did not move (sender=${NAT_S:-0} receiver=${NAT_C:-0})"
fi

# R8: a successful one-shot does not leak the code and exits 0.
if [ "$RRC" -eq 0 ] && ! grep -Fq -- "$CODE" "$WORK/receiver.json" "$WORK/receiver.err" 2>/dev/null; then
  ok "R8: receiver exited 0 and did not log the claim code"
else
  bad "R8: receiver exit/code-leak check failed (rc=$RRC)"
fi

echo
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT core-relay-nat PASS $PAYNAME bytes=$PAYSIZE sha256=$PAYHASH"
  exit 0
fi
echo "RESULT core-relay-nat FAIL $FAIL gate(s):$FAILED"
exit 1
