#!/usr/bin/env bash
# Construct two Linux NAT topologies and prove natprobe classifies both.
# Requires root, iproute2, iptables, and Python 3 stdlib only.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PROBE="$HERE/natprobe.py"
PREFIX="filnat-${BASHPID}"
ROUTER="${PREFIX}-r"
CLIENT="${PREFIX}-c"
REF_A="${PREFIX}-a"
REF_B="${PREFIX}-b"
PIDS=()

die() { printf 'natprobe-test: FAIL: %s\n' "$*" >&2; exit 1; }
cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for ns in "$CLIENT" "$REF_A" "$REF_B" "$ROUTER"; do
    ip netns del "$ns" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

[[ "$(id -u)" -eq 0 ]] || die "run as root"
command -v ip >/dev/null || die "iproute2 is required"
command -v iptables >/dev/null || die "iptables is required"
python3 -c 'import socket' || die "python3 is required"

new_ns() { ip netns add "$1"; ip -n "$1" link set lo up; }
link_ns() {
  local left="$1" right="$2" left_ip="$3" right_ip="$4" left_if="$5" right_if="$6"
  ip link add "$left_if" type veth peer name "$right_if"
  ip link set "$left_if" netns "$left"
  ip link set "$right_if" netns "$right"
  ip -n "$left" addr add "$left_ip" dev "$left_if"
  ip -n "$right" addr add "$right_ip" dev "$right_if"
  ip -n "$left" link set "$left_if" up
  ip -n "$right" link set "$right_if" up
}

setup() {
  local random_mode="$1"
  new_ns "$ROUTER"; new_ns "$CLIENT"; new_ns "$REF_A"; new_ns "$REF_B"
  link_ns "$CLIENT" "$ROUTER" 10.201.1.2/24 10.201.1.1/24 c0 r-c
  link_ns "$ROUTER" "$REF_A" 10.201.2.1/24 10.201.2.2/24 r-a a0
  link_ns "$ROUTER" "$REF_B" 10.201.3.1/24 10.201.3.2/24 r-b b0
  ip netns exec "$ROUTER" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$CLIENT" ip route add default via 10.201.1.1
  ip netns exec "$REF_A" ip route add default via 10.201.2.1
  ip netns exec "$REF_B" ip route add default via 10.201.3.1
  ip netns exec "$ROUTER" iptables -t nat -A POSTROUTING -s 10.201.1.0/24 -o r-a -j MASQUERADE $random_mode
  ip netns exec "$ROUTER" iptables -t nat -A POSTROUTING -s 10.201.1.0/24 -o r-b -j MASQUERADE $random_mode
  ip netns exec "$ROUTER" iptables -A FORWARD -i r-c -j ACCEPT
  ip netns exec "$ROUTER" iptables -A FORWARD -o r-c -j ACCEPT
  ip netns exec "$ROUTER" iptables -A FORWARD -i r-a -j ACCEPT
  ip netns exec "$ROUTER" iptables -A FORWARD -o r-a -j ACCEPT
  ip netns exec "$ROUTER" iptables -A FORWARD -i r-b -j ACCEPT
  ip netns exec "$ROUTER" iptables -A FORWARD -o r-b -j ACCEPT
  for label_ip in A:10.201.2.2 B:10.201.3.2; do
    IFS=: read -r label address <<<"$label_ip"
    local ns="$REF_A"; [[ "$label" = B ]] && ns="$REF_B"
    ip netns exec "$ns" python3 "$PROBE" server --bind "$address" --port 49000 --label "$label" >"$WORK/$label.log" 2>&1 &
    PIDS+=("$!")
    for _ in $(seq 1 20); do grep -q '^READY ' "$WORK/$label.log" && break; sleep 0.05; done
    grep -q '^READY ' "$WORK/$label.log" || die "reflector $label did not start"
  done
}

run_case() {
  local expected="$1" random_mode="$2"
  WORK="$(mktemp -d)"
  setup "$random_mode"
  local output
  output=$(ip netns exec "$CLIENT" python3 "$PROBE" probe --bind 0.0.0.0 --port 40000 \
    --target A=10.201.2.2:49000 --target B=10.201.3.2:49000) || die "$expected topology was not proven"
  printf '%s\n' "$output"
  python3 - "$expected" "$output" <<'PY'
import json, sys
expected, output = sys.argv[1:]
result = json.loads(output)
actual = result["mapping"]
if actual != expected:
    raise SystemExit(f"expected {expected}, got {actual}: {result}")
if len(result["observations"]) != 2:
    raise SystemExit("expected two reflector observations")
PY
  cleanup
  rm -rf "$WORK"
  PIDS=()
}

WORK="$(mktemp -d)"
run_case endpoint-independent ""
run_case endpoint-dependent --random-fully
printf 'natprobe-test: PASS: endpoint-independent and endpoint-dependent mappings proven\n'
