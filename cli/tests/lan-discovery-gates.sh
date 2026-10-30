#!/usr/bin/env bash
# Local discovery with the signaling server blocked (docs/protocol/local-discovery.md).
#
# Two paired daemons in their own network namespaces on one machine, three
# topologies, each run the same way:
#
#   learn    with the server up the daemons link and exchange the lan hello;
#            each side has the other's presence key and addresses on disk
#   reach    the server is then BLOCKED (iptables DROP: connects time out, the
#            harder case than a refusal), both daemons restart, and
#            `reach boxb` from A answers over a link whose route is `lan`
#   send     a one-shot `send --to boxb` from A delivers the file, byte exact,
#            with the server still blocked
#   denied   with network.transports=direct,relay on both sides (lan off),
#            the same reach and send FAIL; nothing reaches B
#
# Topologies:
#   lan      one switch (a bridge in its own namespace); the only path between
#            A and B. Before the blocked phase B's address on it is CHANGED,
#            so the remembered address is stale and only a multicast or
#            broadcast beacon can find B. A stranger M on the same switch
#            captures every beacon and must learn nothing identifying
#            (stranger-blind).
#   wg       a WireGuard tunnel (POINTOPOINT, no multicast, no ARP) is the only
#            path; the underlay carries UDP 51820 only. B's tunnel address is
#            changed before the blocked phase, so only the bounded unicast
#            sweep of the tunnel prefix can find B. doctor must class the
#            tunnel p2p (p2p-class). Falls back to an ipip tunnel (also
#            point-to-point, no multicast) when WireGuard is unavailable, and
#            says so.
#   routed   A and B on different subnets behind a router, the analog of two
#            hosts with different public IPs: no shared link, no multicast,
#            only the addresses remembered from the hello.
#
# Needs root (sudo) for namespaces; daemons run as the invoking user, so the
# L3 overlay is the userspace one and nothing outside $WORK is touched.
#   TUNLION_BIN=/path/to/tunlion ./lan-discovery-gates.sh [lan|wg|routed ...]
# Exit: 0 all pass, 1 a gate failed, 3 refused (a precondition is missing).

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT="${LAN_GATE_PORT:-8140}"
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${LAN_GATE_TMP:-${TMPDIR:-/tmp}}/wt-lan.XXXXXX")"
DA="$WORK/A"; DB="$WORK/B"
U="$(id -un)"
SCENARIOS=("$@"); [ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(lan wg routed)

source "$HERE/lib/fixture.sh"

refuse() { echo "REFUSED: $*"; exit 3; }
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo -n"
$SUDO true 2>/dev/null || refuse "needs passwordless sudo for network namespaces"
command -v ip >/dev/null || refuse "needs iproute2"
command -v iptables >/dev/null || refuse "needs iptables"
[ -x "$BIN" ] || refuse "no binary at $BIN"

NSS=(lanA lanB lanS lanM)
cleanup() {
  for p in "${PIDS[@]:-}"; do $SUDO kill "$p" 2>/dev/null; done
  $SUDO pkill -f "$WORK/" 2>/dev/null
  for n in "${NSS[@]}"; do $SUDO ip netns del "$n" 2>/dev/null; done
  $SUDO ip link del va0 2>/dev/null; $SUDO ip link del vb0 2>/dev/null
  $SUDO iptables -D FORWARD -j LANGATE 2>/dev/null; $SUDO iptables -F LANGATE 2>/dev/null; $SUDO iptables -X LANGATE 2>/dev/null
  fixture_cleanup
}
trap cleanup EXIT
PIDS=()

nsx() { local n="$1"; shift; $SUDO ip netns exec "$n" "$@"; }
# Run as the invoking user inside a namespace, with that side's config.
asA() { nsx lanA $SUDO -u "$U" env HOME="$WORK/hA" TUNLION_CONFIG_DIR="$DA" "$@"; }
asB() { nsx lanB $SUDO -u "$U" env HOME="$WORK/hB" TUNLION_CONFIG_DIR="$DB" "$@"; }

# ---------------------------------------------------------------- base net --
# Each side reaches the root namespace (and the server there) over its own
# veth. Root forwards between the two subnets only as LANGATE allows.
base_net() {
  for n in "${NSS[@]}"; do $SUDO ip netns del "$n" 2>/dev/null; $SUDO ip netns add "$n"; nsx "$n" ip link set lo up; done
  $SUDO ip link add va0 type veth peer name va1; $SUDO ip link set va1 netns lanA
  $SUDO ip link add vb0 type veth peer name vb1; $SUDO ip link set vb1 netns lanB
  $SUDO ip addr add 10.88.1.254/24 dev va0; $SUDO ip link set va0 up
  $SUDO ip addr add 10.88.2.254/24 dev vb0; $SUDO ip link set vb0 up
  nsx lanA ip addr add 10.88.1.1/24 dev va1; nsx lanA ip link set va1 up; nsx lanA ip route add default via 10.88.1.254
  nsx lanB ip addr add 10.88.2.1/24 dev vb1; nsx lanB ip link set vb1 up; nsx lanB ip route add default via 10.88.2.254
  $SUDO sysctl -qw net.ipv4.ip_forward=1
  $SUDO iptables -N LANGATE 2>/dev/null; $SUDO iptables -F LANGATE
  $SUDO iptables -C FORWARD -j LANGATE 2>/dev/null || $SUDO iptables -I FORWARD 1 -j LANGATE
}
forward_none()   { $SUDO iptables -F LANGATE; $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -j DROP; }
forward_all()    { $SUDO iptables -F LANGATE; $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -j ACCEPT; }
forward_udp()    { $SUDO iptables -F LANGATE
                   $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -p udp --dport "$1" -j ACCEPT
                   $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -p udp --sport "$1" -j ACCEPT
                   $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -p "${2:-udp}" -j ACCEPT 2>/dev/null
                   $SUDO iptables -A LANGATE -s 10.88.0.0/16 -d 10.88.0.0/16 -j DROP; }
block_server()   { nsx lanA iptables -A OUTPUT -p tcp --dport "$PORT" -j DROP; nsx lanB iptables -A OUTPUT -p tcp --dport "$PORT" -j DROP; }
unblock_server() { nsx lanA iptables -F OUTPUT; nsx lanB iptables -F OUTPUT; }

topo_lan() {
  forward_none
  nsx lanS ip link add br0 type bridge; nsx lanS ip link set br0 up
  for s in A B M; do
    nsx lanS ip link add "s$s" type veth peer name "l$s"
    nsx lanS ip link set "l$s" netns "lan$s"
    nsx lanS ip link set "s$s" master br0; nsx lanS ip link set "s$s" up
  done
  nsx lanA ip addr add 10.77.0.1/24 dev lA; nsx lanA ip link set lA up
  nsx lanB ip addr add 10.77.0.2/24 dev lB; nsx lanB ip link set lB up
  nsx lanM ip addr add 10.77.0.3/24 dev lM; nsx lanM ip link set lM up
}
move_lan() { nsx lanB ip addr del 10.77.0.2/24 dev lB; nsx lanB ip addr add 10.77.0.9/24 dev lB; }

TUNNEL=""
topo_wg() {
  if nsx lanA ip link add wg0 type wireguard 2>/dev/null && command -v wg >/dev/null; then
    TUNNEL=wireguard
    nsx lanB ip link add wg0 type wireguard
    local ka kb; ka=$(wg genkey); kb=$(wg genkey)
    nsx lanA wg set wg0 listen-port 51820 private-key <(echo "$ka") peer "$(echo "$kb" | wg pubkey)" endpoint 10.88.2.1:51820 allowed-ips 10.99.0.0/24 persistent-keepalive 5
    nsx lanB wg set wg0 listen-port 51820 private-key <(echo "$kb") peer "$(echo "$ka" | wg pubkey)" endpoint 10.88.1.1:51820 allowed-ips 10.99.0.0/24 persistent-keepalive 5
    forward_udp 51820
  else
    nsx lanA ip link del wg0 2>/dev/null
    TUNNEL=ipip
    nsx lanA ip tunnel add wg0 mode ipip local 10.88.1.1 remote 10.88.2.1
    nsx lanB ip tunnel add wg0 mode ipip local 10.88.2.1 remote 10.88.1.1
    forward_udp 51820 4
  fi
  nsx lanA ip addr add 10.99.0.1/24 dev wg0; nsx lanA ip link set wg0 up
  nsx lanB ip addr add 10.99.0.2/24 dev wg0; nsx lanB ip link set wg0 up
  echo "tunnel: $TUNNEL"
}
move_wg() { nsx lanB ip addr del 10.99.0.2/24 dev wg0; nsx lanB ip addr add 10.99.0.7/24 dev wg0; }

topo_routed() { forward_all; }
move_routed() { :; }

# ---------------------------------------------------------------- daemons --
DPIDS=()
start_daemons() { # $@ = extra env, e.g. TUNLION_TRANSPORTS=direct,relay
  asA env "$@" TUNLION_LOG=debug TUNLION_NAME=boxa "$BIN" --server "http://10.88.1.254:$PORT" up --dir "$WORK/Adrop" >>"$WORK/upA.log" 2>&1 &
  DPIDS+=($!)
  asB env "$@" TUNLION_LOG=debug TUNLION_NAME=boxb "$BIN" --server "http://10.88.2.254:$PORT" up --dir "$WORK/Bdrop" >>"$WORK/upB.log" 2>&1 &
  DPIDS+=($!)
}
stop_daemons() {
  for p in "${DPIDS[@]:-}"; do $SUDO kill "$p" 2>/dev/null; done
  $SUDO pkill -f "TUNLION_CONFIG_DIR=$WORK" 2>/dev/null
  $SUDO pkill -u "$U" -f "$BIN .*up --dir $WORK" 2>/dev/null
  sleep 2; DPIDS=()
}

# Poll until `reach boxb` from A prints a pong whose route is lan.
reach_lan() {
  local deadline=$(( $(date +%s) + ${1:-75} )) out
  while [ "$(date +%s)" -lt "$deadline" ]; do
    out=$(timeout 15 asA "$BIN" reach boxb --timeout 5 2>&1)
    if printf '%s\n' "$out" | grep -q "pong via .*(lan"; then echo "$out" | grep "pong via"; return 0; fi
    sleep 3
  done
  echo "last reach output: $out"; return 1
}

learned() { # both sides hold the other's record with a key and addresses
  local deadline=$(( $(date +%s) + 60 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if grep -q '"boxb"' "$DA/lan-peers.json" 2>/dev/null && grep -q '"boxa"' "$DB/lan-peers.json" 2>/dev/null \
       && grep -q '"pk": "[0-9a-f]\{64\}"' "$DA/lan-peers.json" && grep -q '"pk": "[0-9a-f]\{64\}"' "$DB/lan-peers.json"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

capture_start() { # stranger M records every datagram to the discovery port
  nsx lanM "$PYV" -I -c '
import socket, struct, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 47820))
s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, struct.pack("4s4s", socket.inet_aton("239.255.84.76"), socket.inet_aton("10.77.0.3")))
s.settimeout(1.0)
out = open(sys.argv[1], "w")
end = time.time() + float(sys.argv[2])
while time.time() < end:
    try:
        d, a = s.recvfrom(4096)
    except socket.timeout:
        continue
    out.write("%s %s\n" % (a[0], d.hex())); out.flush()
' "$WORK/captured.txt" "${1:-90}" &
  PIDS+=($!)
}

stranger_blind() {
  "$PYV" -I - "$WORK/captured.txt" "$DA/lan.key" "$DB/lan.key" "$SECRET" <<'PY'
import sys
lines = [l.split() for l in open(sys.argv[1]) if l.strip()]
beacons = [bytes.fromhex(h) for _, h in lines]
secrets = [bytes.fromhex(open(sys.argv[2]).read().strip()), bytes.fromhex(open(sys.argv[3]).read().strip()), bytes.fromhex(sys.argv[4])]
names = [b"boxa", b"boxb"]
presence = [b for b in beacons if len(b) == 34 and b[3] == 1]
if len(presence) < 2:
    print("too few presence beacons captured: %d" % len(presence)); sys.exit(1)
for b in beacons:
    for n in names:
        if n in b:
            print("a beacon carries a device name"); sys.exit(1)
    for k in secrets:
        for i in range(0, 29):
            if k[i:i + 4] in b:
                print("a beacon carries 4 bytes of a key or secret"); sys.exit(1)
seen = {}
for b in presence:
    for off in range(4, 32, 4):
        w = (off, b[off:off + 4])
        if w in seen:
            print("two beacons share bytes %d..%d" % (off, off + 4)); sys.exit(1)
        seen[w] = 1
print("ok: %d datagrams, %d presence beacons, nothing identifying, nothing repeated" % (len(beacons), len(presence)))
PY
}

# --------------------------------------------------------------- scenario --
run_scenario() {
  local name="$1"
  say "$name: setup"
  stop_daemons
  base_net
  "topo_$name"
  rm -rf "$DA" "$DB" "$WORK/Adrop" "$WORK/Bdrop" "$WORK/hA" "$WORK/hB"
  mkdir -p "$DA" "$DB" "$WORK/Adrop" "$WORK/Bdrop" "$WORK/hA" "$WORK/hB"
  SECRET=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf '[{"name":"boxb","secret":"%s"}]\n' "$SECRET" > "$DA/devices.json"
  printf '[{"name":"boxa","secret":"%s"}]\n' "$SECRET" > "$DB/devices.json"
  : > "$WORK/upA.log"; : > "$WORK/upB.log"

  say "$name: learn (server up)"
  unblock_server
  start_daemons
  if learned; then ok "$name/learn: both sides remembered the other (key + addresses)"; else bad "$name/learn: no lan hello was exchanged"; fi
  stop_daemons

  say "$name: server blocked"
  "move_$name"
  block_server
  [ "$name" = lan ] && capture_start 100
  start_daemons
  if line=$(reach_lan 90); then ok "$name/reach-lan: $line"; else bad "$name/reach-lan: no lan link with the server blocked ($line)"; fi
  head -c 300000 /dev/urandom > "$WORK/payload-$name.bin"
  chmod a+r "$WORK/payload-$name.bin"
  out=$(timeout 90 asA "$BIN" --server "http://10.88.1.254:$PORT" send "$WORK/payload-$name.bin" --to boxb --timeout 60 2>&1); rc=$?
  got="$WORK/Bdrop/payload-$name.bin"
  if [ -f "$got" ] && cmp -s "$got" "$WORK/payload-$name.bin"; then ok "$name/send-lan: file delivered byte exact, server blocked"
  else bad "$name/send-lan: rc=$rc, not delivered: $(printf '%s' "$out" | tail -3 | tr '\n' ' ')"; fi
  if [ "$name" = wg ]; then
    cls=$(asA "$BIN" doctor --json 2>/dev/null | "$PYV" -I -c 'import json,sys; v=json.load(sys.stdin); print([i["class"] for i in v["lan"]["interfaces"] if i["name"]=="wg0"])' 2>&1)
    if [ "$cls" = "['p2p']" ]; then ok "wg/p2p-class: doctor classes the $TUNNEL tunnel p2p by its flags"; else bad "wg/p2p-class: doctor said $cls"; fi
  fi
  if [ "$name" = lan ]; then
    sleep 5
    if r=$(stranger_blind); then ok "lan/stranger-blind: $r"; else bad "lan/stranger-blind: $r"; fi
  fi
  stop_daemons

  say "$name: denied arm (network.transports=direct,relay)"
  rm -f "$WORK/Bdrop/"*
  start_daemons TUNLION_TRANSPORTS=direct,relay
  sleep 25
  out=$(timeout 20 asA "$BIN" reach boxb --timeout 5 2>&1)
  denied_reach=1; printf '%s\n' "$out" | grep -q "pong via" && denied_reach=0
  timeout 40 asA env TUNLION_TRANSPORTS=direct,relay "$BIN" --server "http://10.88.1.254:$PORT" send "$WORK/payload-$name.bin" --to boxb --timeout 15 >/dev/null 2>&1; rc=$?
  if [ "$denied_reach" = 1 ] && [ "$rc" != 0 ] && [ ! -f "$WORK/Bdrop/payload-$name.bin" ]; then
    ok "$name/denied: with lan off nothing reached boxb (send rc=$rc)"
  else
    bad "$name/denied: lan off but reach answered ($denied_reach=0 means it did) or send delivered (rc=$rc)"
  fi
  if grep -q "beacon\|lan: linked" "$WORK/upA.log" 2>/dev/null; then :; fi
  stop_daemons
  unblock_server
  cp "$WORK/upA.log" "$WORK/$name-upA.log"; cp "$WORK/upB.log" "$WORK/$name-upB.log"
}

start_backend
for s in "${SCENARIOS[@]}"; do run_scenario "$s"; done

echo
echo "logs: $WORK"
echo "lan-discovery gates: $PASS passed, $FAIL failed${FAILED:+ ($FAILED)}"
[ "$FAIL" = 0 ]
