#!/usr/bin/env bash
# Slice B: two Filament peers behind independently configured cone NATs.
# Proves the NAT class first, then asserts hole-punched, byte-exact transfer.
# To verify only the netns lab and prober, run: FILAMENT_BIN=/bin/true bash "$0"
# IMPORTANT: this gate is not currently a product signal. Its failure is
# located in the emulation at the receiving router inbound path. See
# docs/testing-nat-cone-gate.md. Do not wire it into CI until that is fixed.
# Prediction for COTURN=1 before the controlled rerun: srflx candidates should
# appear on both peers, followed by candidate pairs and a new pass/failure stage.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/filament}"
PROBE="$HERE/natprobe.py"
STUN="$HERE/stun-server.py"
PREFIX="filcone-${BASHPID}"
WAN="${PREFIX}-wan"; RA="${PREFIX}-ra"; RB="${PREFIX}-rb"; CA="${PREFIX}-ca"; CB="${PREFIX}-cb"
WORK="$(mktemp -d)"; PIDS=()
BACKEND_PORT=8189; STUN_PORT=3478; REF_PORT=49000
SERVER_IP=10.220.100.1
REF_A_IP=10.220.100.2
REF_B_IP=10.220.100.3

die() { printf 'nat-cone-gate: FAIL: %s\n' "$*" >&2; exit 1; }
unclassified() { printf 'nat-cone-gate: UNCLASSIFIED: %s\n' "$*" >&2; exit 3; }
cleanup() {
  for ns in "$CA" "$CB" "$RA" "$RB" "$WAN"; do
    for pid in $(ip netns pids "$ns" 2>/dev/null || true); do kill "$pid" 2>/dev/null || true; done
  done
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for ns in "$CA" "$CB" "$RA" "$RB" "$WAN"; do ip netns del "$ns" 2>/dev/null || true; done
  if [[ -n "${KEEP_WORK:-}" ]]; then
    printf 'nat-cone-gate: logs kept in %s\n' "$WORK" >&2
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT INT TERM

[[ "$(id -u)" -eq 0 ]] || unclassified "stage=setup: run as root"
[[ -x "$BIN" ]] || unclassified "stage=setup: build first: $BIN"
command -v ip >/dev/null || unclassified "stage=setup: iproute2 is required"
command -v iptables >/dev/null || unclassified "stage=setup: iptables is required"
python3 -c 'import flask' 2>/dev/null || unclassified "stage=service: python3 Flask dependency is required"

new_ns() { ip netns add "$1" || return 1; ip -n "$1" link set lo up || return 1; }
link_ns() {
  local left="$1" right="$2" lip="$3" rip="$4" li="$5" ri="$6"
  ip link add "$li" type veth peer name "$ri" || return 1
  ip link set "$li" netns "$left" || return 1; ip link set "$ri" netns "$right" || return 1
  ip -n "$left" addr add "$lip" dev "$li" || return 1; ip -n "$right" addr add "$rip" dev "$ri" || return 1
  ip -n "$left" link set "$li" up || return 1; ip -n "$right" link set "$ri" up || return 1
}
route_default() { ip netns exec "$1" ip route add default via "$2"; }

setup_topology() {
  new_ns "$WAN" || return 1; new_ns "$RA" || return 1; new_ns "$RB" || return 1; new_ns "$CA" || return 1; new_ns "$CB" || return 1
  link_ns "$WAN" "$RA" 10.220.1.1/30 10.220.1.2/30 wa ra-wan || return 1
  link_ns "$WAN" "$RB" 10.220.2.1/30 10.220.2.2/30 wb rb-wan || return 1
  link_ns "$RA" "$CA" 10.221.1.1/24 10.221.1.2/24 ra-lan ca-lan || return 1
  link_ns "$RB" "$CB" 10.221.2.1/24 10.221.2.2/24 rb-lan cb-lan || return 1
  ip -n "$WAN" addr add "$SERVER_IP/32" dev lo || return 1
  ip -n "$WAN" addr add "$REF_A_IP/32" dev lo || return 1
  ip -n "$WAN" addr add "$REF_B_IP/32" dev lo || return 1
  ip netns exec "$WAN" sysctl -q -w net.ipv4.ip_forward=1 || return 1
  ip netns exec "$RA" sysctl -q -w net.ipv4.ip_forward=1 || return 1
  ip netns exec "$RB" sysctl -q -w net.ipv4.ip_forward=1 || return 1
  route_default "$CA" 10.221.1.1 || return 1; route_default "$CB" 10.221.2.1 || return 1
  route_default "$RA" 10.220.1.1 || return 1; route_default "$RB" 10.220.2.1 || return 1
  ip -n "$WAN" route add 10.220.1.2/32 dev wa || return 1; ip -n "$WAN" route add 10.220.2.2/32 dev wb || return 1
  if [[ -n "${NO_NAT:-}" ]]; then
    ip -n "$WAN" route add 10.221.1.0/24 via 10.220.1.2 || return 1
    ip -n "$WAN" route add 10.221.2.0/24 via 10.220.2.2 || return 1
  fi
  for r in "$RA" "$RB"; do
    ip netns exec "$r" iptables -A FORWARD -j ACCEPT || return 1
    if [[ -z "${NO_NAT:-}" ]]; then
      ip netns exec "$r" iptables -t nat -A POSTROUTING -o "${r##*-}-wan" -j MASQUERADE || return 1
    fi
  done
}

start_service() {
  if [[ -n "${CAPTURE:-}" ]] && command -v tcpdump >/dev/null; then
    ip netns exec "$WAN" tcpdump -ni any -w "$WORK/wan.pcap" udp >/dev/null 2>&1 & PIDS+=("$!")
    ip netns exec "$CA" tcpdump -ni ca-lan -w "$WORK/client-ca.pcap" udp >/dev/null 2>&1 & PIDS+=("$!")
    ip netns exec "$CB" tcpdump -ni cb-lan -w "$WORK/client-cb.pcap" udp >/dev/null 2>&1 & PIDS+=("$!")
    for ns in "$WAN" "$RA" "$RB" "$CA" "$CB"; do
      ip netns exec "$ns" ip route >"$WORK/route-$ns.txt"
    done
    for router in "$RA" "$RB"; do
      ip netns exec "$router" iptables -S >"$WORK/iptables-$router.txt"
      ip netns exec "$router" iptables -t nat -S >"$WORK/iptables-nat-$router.txt"
      ip netns exec "$router" sysctl -a 2>/dev/null | grep -E '(^|\.)rp_filter|ip_forward' >"$WORK/sysctl-$router.txt"
      if command -v conntrack >/dev/null; then
        (while sleep 1; do ip netns exec "$router" conntrack -L -p udp 2>/dev/null; done) >"$WORK/conntrack-$router.log" 2>&1 & PIDS+=("$!")
      fi
    done
    ip netns exec "$WAN" sysctl -a 2>/dev/null | grep -E '(^|\.)rp_filter|ip_forward' >"$WORK/sysctl-$WAN.txt"
    ip netns exec "$WAN" iptables -S >"$WORK/iptables-$WAN.txt"
    ip netns exec "$WAN" iptables -t nat -S >"$WORK/iptables-nat-$WAN.txt"
  fi
  ip netns exec "$WAN" env PORT="$BACKEND_PORT" FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_ICE_SERVERS="[{\"urls\":[\"stun:$SERVER_IP:$STUN_PORT\"]}]" python3 "$CLI_DIR/../backend/app.py" \
    >"$WORK/backend.log" 2>&1 & PIDS+=("$!")
  if [[ -n "${COTURN:-}" ]] && command -v turnserver >/dev/null; then
    ip netns exec "$WAN" turnserver -n --log-file "$WORK/coturn.log" --listening-ip "$SERVER_IP" \
      --listening-port "$STUN_PORT" --no-cli --no-tls --no-dtls --realm=nat-gate >"$WORK/stun.log" 2>&1 & PIDS+=("$!")
  else
    ip netns exec "$WAN" python3 "$STUN" 0.0.0.0 "$STUN_PORT" >"$WORK/stun.log" 2>&1 & PIDS+=("$!")
  fi
  for _ in $(seq 1 40); do ip netns exec "$WAN" curl --noproxy '*' -fsS "http://$SERVER_IP:$BACKEND_PORT/api/health" >/dev/null 2>&1 && break; sleep .25; done
  ip netns exec "$WAN" curl --noproxy '*' -fsS "http://$SERVER_IP:$BACKEND_PORT/api/health" >/dev/null || return 1
  if [[ -z "${COTURN:-}" ]]; then grep -q READY "$WORK/stun.log" || return 1; fi
  if [[ -n "${CAPTURE:-}" ]]; then
    for client in "$CA" "$CB"; do
      ip netns exec "$client" curl --noproxy '*' -fsS "http://$SERVER_IP:$BACKEND_PORT/api/config" >"$WORK/config-$client.json" || return 1
      if command -v turnutils_stunclient >/dev/null; then
        timeout 5 ip netns exec "$client" turnutils_stunclient -p "$STUN_PORT" "$SERVER_IP" >"$WORK/stock-stun-$client.log" 2>&1 || true
      fi
    done
  fi
}

prove_cone() {
  for client in "$CA" "$CB"; do
    local ref_pids=()
    ip netns exec "$WAN" python3 "$PROBE" server --bind "$REF_A_IP" --port "$REF_PORT" --label A >"$WORK/ref-$client.log" 2>&1 & ref_pids+=("$!")
    ip netns exec "$WAN" python3 "$PROBE" server --bind "$REF_B_IP" --port "$((REF_PORT+1))" --label B >>"$WORK/ref-$client.log" 2>&1 & ref_pids+=("$!")
    sleep .2
    local result
    result=$(ip netns exec "$client" python3 "$PROBE" probe --bind 0.0.0.0 --port 40000 \
      --target A="$REF_A_IP:$REF_PORT" --target B="$REF_B_IP:$((REF_PORT+1))") \
      || { printf 'nat-cone-gate: UNCLASSIFIED: stage=prober: no verdict for %s\n' "$client" >&2; return 3; }
    printf '%s cone probe: %s\n' "$client" "$result"
    if ! python3 - "$result" <<'PY'
import json, sys
if json.loads(sys.argv[1])["mapping"] != "endpoint-independent":
    raise SystemExit("UNCLASSIFIED: NAT is not endpoint-independent")
PY
    then
      printf 'nat-cone-gate: UNCLASSIFIED: stage=non-cone: %s is not a cone NAT\n' "$client" >&2
      return 3
    fi
    for pid in "${ref_pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  done
}

pair_and_transfer() {
  local server="http://$SERVER_IP:$BACKEND_PORT" word="gigantic element" code=""
  local cfg_a="$WORK/cfg-a" cfg_b="$WORK/cfg-b" out="$WORK/out" payload="$WORK/payload.bin"
  mkdir -p "$cfg_a" "$cfg_b" "$out"; head -c 262144 /dev/urandom >"$payload"
  # Pair over WebRTC through the two NATs, then exercise the already-known
  # device path with hole-punching. Pairing itself is not the route assertion.
  ip netns exec "$CA" env FILAMENT_CONFIG_DIR="$cfg_a" FILAMENT_DIRECT=0 FILAMENT_STUN="$SERVER_IP:$STUN_PORT" \
    "$BIN" --no-relay -vv send "$payload" --word "gigantic-element" --remember boxB --server "$server" >"$WORK/pair-a.log" 2>&1 &
  local pair_pid=$!
  for _ in $(seq 1 60); do code=$(grep -oiE "gigantic-element-[0-9]{3,5}" "$WORK/pair-a.log" | head -1 || true); [ -n "$code" ] && break; sleep .25; done
  [ -n "$code" ] || unclassified "stage=pairing: pair code was not produced"
  ip netns exec "$CB" env FILAMENT_CONFIG_DIR="$cfg_b" FILAMENT_DIRECT=0 FILAMENT_STUN="$SERVER_IP:$STUN_PORT" timeout 90 \
    "$BIN" --no-relay -vv recv "$code" -y --remember boxA --dir "$out" --server "$server" >"$WORK/pair-b.log" 2>&1 || die "pairing failed"
  for _ in $(seq 1 40); do
    grep -q 'mutually remembered' "$WORK/pair-a.log" "$WORK/pair-b.log" && break
    sleep .25
  done
  kill "$pair_pid" 2>/dev/null || true; wait "$pair_pid" 2>/dev/null || true
  if [[ -n "${NO_NAT:-}" ]]; then
    local control_out
    control_out=$(find "$out" -type f -name payload.bin | head -1)
    [ -n "$control_out" ] && cmp -s "$payload" "$control_out" || die "positive control payload was not byte-exact"
    printf 'nat-cone-gate: PASS: no-NAT positive control, direct route, byte-exact payload\n'
    return 0
  fi
  [ -s "$cfg_a/devices.json" ] || die "pairing produced no sender device store"
  [ -s "$cfg_b/devices.json" ] || die "pairing produced no receiver device store"
  rm -f "$WORK/pair-a.log" "$WORK/pair-b.log"
  ip netns exec "$CB" env FILAMENT_CONFIG_DIR="$cfg_b" FILAMENT_DIRECT_NO_PUBLIC=1 \
    FILAMENT_HOLEPUNCH=1 FILAMENT_STUN="$SERVER_IP:$STUN_PORT" timeout 90 \
    "$BIN" -v up --dir "$out" --server "$server" >"$WORK/recv.log" 2>&1 &
  local up=$!; PIDS+=("$up"); sleep 4
  ip netns exec "$CA" env FILAMENT_CONFIG_DIR="$cfg_a" FILAMENT_DIRECT_NO_PUBLIC=1 \
    FILAMENT_HOLEPUNCH=1 FILAMENT_STUN="$SERVER_IP:$STUN_PORT" timeout 90 \
    "$BIN" -v send "$payload" --to boxB --server "$server" >"$WORK/send.log" 2>&1 || true
  sleep 1; kill "$up" 2>/dev/null || true; wait "$up" 2>/dev/null || true
  local got; got=$(find "$out" -type f -name payload.bin | head -1)
  [ -n "$got" ] && cmp -s "$payload" "$got" || die "payload was not byte-exact"
  grep -hEq 'DIRECT-CONNECT ok \(route: holepunched\)|route: holepunched' "$WORK/send.log" "$WORK/recv.log" || die "hole-punch route was not observed"
  ! grep -hEq 'route: relayed|route: direct-quic' "$WORK/send.log" "$WORK/recv.log" || die "transfer used a non-holepunched route"
  printf 'nat-cone-gate: PASS: cone proven, holepunched route, byte-exact payload\n'
}

if ! setup_topology; then unclassified "stage=setup: topology setup failed"; fi
if ! start_service; then unclassified "stage=service: signaling or STUN service did not start"; fi
if ! prove_cone; then unclassified "stage=prober: NAT topology was not proven"; fi
pair_and_transfer
