#!/usr/bin/env bash
# Plain code pairing over the LAN, with the signaling server blocked.
#
# Two paired-by-code peers on one switch, each in its own network namespace:
# the server address is unreachable (an iptables DROP), `pair --nearby` shows a
# code and a label, `join <code> --nearby` completes the ceremony, then `up`
# and `send` prove the pair secret is the same one the signaling path stores.
#
# Also covered: a wrong code stores nothing and fails, and network.transports
# without lan refuses before minting a code. Replay, cancellation and frame
# bounds are unit-level in this PR; the netns gate keeps the end-to-end shape.
#
# Needs passwordless sudo for namespaces. Nothing outside $WORK is touched.
#   TUNLION_BIN=/path/to/tunlion ./lan-pairing-gates.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
WORK="$(mktemp -d "${LAN_PAIR_TMP:-${TMPDIR:-/tmp}}/wt-lanpair.XXXXXX")"
U="$(id -un)"
SUDO=""
[ "$(id -u)" = 0 ] || SUDO="sudo -n"
PASS=0
FAIL=0
FAILED=""

ok() { PASS=$((PASS + 1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL + 1)); FAILED="$FAILED $*"; echo "FAIL: $*"; }
say() { echo "== $* =="; }
refuse() { echo "REFUSED: $*"; exit 3; }

$SUDO true 2>/dev/null || refuse "needs passwordless sudo for network namespaces"
command -v ip >/dev/null || refuse "needs iproute2"
[ -x "$BIN" ] || refuse "no binary at $BIN"

NS=(lpA lpB)
cleanup() {
  $SUDO pkill -f "$WORK/" 2>/dev/null
  for n in "${NS[@]}"; do $SUDO ip netns del "$n" 2>/dev/null; done
  $SUDO ip link del lpa0 2>/dev/null; $SUDO ip link del lpb0 2>/dev/null
  if [ "${LAN_PAIR_KEEP:-0}" = "1" ]; then
    echo "kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

nsx() { local n="$1"; shift; $SUDO ip netns exec "$n" "$@"; }
asA() { nsx lpA $SUDO -u "$U" env HOME="$WORK/hA" TUNLION_CONFIG_DIR="$DA" "$@"; }
asB() { nsx lpB $SUDO -u "$U" env HOME="$WORK/hB" TUNLION_CONFIG_DIR="$DB" "$@"; }

base_net() {
  for n in "${NS[@]}"; do $SUDO ip netns del "$n" 2>/dev/null; $SUDO ip netns add "$n"; nsx "$n" ip link set lo up; done
  $SUDO ip link add lpa0 type veth peer name lpa1
  $SUDO ip link add lpb0 type veth peer name lpb1
  $SUDO ip link set lpa1 netns lpA
  $SUDO ip link set lpb1 netns lpB
  $SUDO ip link add br-lp type bridge 2>/dev/null || true
  $SUDO ip link set lpa0 master br-lp
  $SUDO ip link set lpb0 master br-lp
  $SUDO ip link set br-lp up; $SUDO ip link set lpa0 up; $SUDO ip link set lpb0 up
  nsx lpA ip addr add 10.77.0.1/24 dev lpa1; nsx lpA ip link set lpa1 up
  nsx lpB ip addr add 10.77.0.2/24 dev lpb1; nsx lpB ip link set lpb1 up
  nsx lpA ip route add default via 10.77.0.254 2>/dev/null || true
  nsx lpB ip route add default via 10.77.0.254 2>/dev/null || true
  # The server address used by the commands is deliberately unreachable: a
  # blackhole route needs no host firewall rule and is scoped to these namespaces.
  nsx lpA ip route add blackhole 203.0.113.1/32
  nsx lpB ip route add blackhole 203.0.113.1/32
}
SERVER=http://203.0.113.1:9
DA="$WORK/A"; DB="$WORK/B"
init_pair() {
  rm -rf "$DA" "$DB"; mkdir -p "$DA" "$DB" "$WORK/hA" "$WORK/hB"
  asA "$BIN" init --name boxa --recovery-file "$DA/rec.txt" --yes >/dev/null 2>&1 || { bad "init A"; return 1; }
  asB "$BIN" init --name boxb --recovery-file "$DB/rec.txt" --yes >/dev/null 2>&1 || { bad "init B"; return 1; }
}
code_of() { grep -aoE '[A-Za-z]+(-[A-Za-z]+)+-[0-9]{4,5}' "$1" | head -1 | tr 'A-Z' 'a-z'; }

start_host() {
  local log="$1"; shift
  asA env TUNLION_TRANSPORTS=lan TUNLION_LOG=debug "$BIN" --server "$SERVER" add --nearby --word "brave otter" >"$log" 2>&1 &
  echo $! > "$WORK/host.pid"
  for _ in $(seq 1 60); do grep -aq -- "-[0-9]" "$log" && return 0; sleep 0.25; done
  return 1
}

stop_host() { [ -f "$WORK/host.pid" ] && kill "$(cat "$WORK/host.pid")" 2>/dev/null; }

happy() {
  say "lan pairing: happy path (server blocked)"
  init_pair || return
  start_host "$WORK/host.log" || { bad "host never showed a code"; return; }
  local code; code=$(code_of "$WORK/host.log")
  [ -n "$code" ] || { bad "no code in host output"; return; }
  if asB env TUNLION_TRANSPORTS=lan TUNLION_LOG=debug "$BIN" --server "$SERVER" join "$code" --nearby >"$WORK/join.log" 2>&1; then
    ok "join completed with the server blocked"
  else
    bad "join failed: $(tail -3 "$WORK/join.log" | tr '\n' ' ')"
    return
  fi
  stop_host
  if grep -aq '"secret"' "$DA/devices.json" && grep -aq '"secret"' "$DB/devices.json"; then ok "both sides stored a pair secret"; else bad "pair secret missing"; fi
  # The same pair secret is what `up` and `send` consume.
  asA env TUNLION_TRANSPORTS=lan TUNLION_LOG=debug TUNLION_NAME=boxa "$BIN" --server "$SERVER" up --dir "$WORK/Adrop" >"$WORK/upA.log" 2>&1 &
  echo $! > "$WORK/upA.pid"
  asB env TUNLION_TRANSPORTS=lan TUNLION_LOG=debug TUNLION_NAME=boxb "$BIN" --server "$SERVER" up --dir "$WORK/Bdrop" >"$WORK/upB.log" 2>&1 &
  echo $! > "$WORK/upB.pid"
  local line=""
  for _ in $(seq 1 60); do
    line=$(asA timeout 5 "$BIN" reach boxb --timeout 2 2>&1 | grep 'pong via' || true)
    [ -n "$line" ] && break
    sleep 0.5
  done
  if printf '%s' "$line" | grep -q "lan"; then ok "reach: $line"; else bad "reach did not use lan: ${line:-no pong}"; fi
  head -c 65536 /dev/urandom > "$WORK/payload.bin"
  if asA timeout 60 "$BIN" --server "$SERVER" send "$WORK/payload.bin" --to boxb --timeout 30 >/dev/null 2>&1 \
      && cmp -s "$WORK/Bdrop/payload.bin" "$WORK/payload.bin"; then
    ok "send delivered byte exact with the server blocked"
  else
    bad "send over the paired secret failed"
  fi
  for p in "$WORK/upA.pid" "$WORK/upB.pid"; do kill "$(cat "$p")" 2>/dev/null; done
}

wrong_code() {
  say "lan pairing: wrong code stores nothing"
  init_pair || return
  start_host "$WORK/host2.log" || { bad "host never showed a code"; return; }
  local wrong="wrong-code-9999"
  if asB env TUNLION_TRANSPORTS=lan "$BIN" --server "$SERVER" join "$wrong" --nearby >"$WORK/join2.log" 2>&1; then
    bad "a wrong code was accepted"
  else
    ok "wrong code refused"
  fi
  if grep -aq 'boxa' "$DB/devices.json" 2>/dev/null || grep -aq 'boxb' "$DA/devices.json" 2>/dev/null; then
    bad "a wrong code stored a device"
  else
    ok "nothing stored on either side"
  fi
  stop_host
}

denied() {
  say "lan pairing: network.transports without lan"
  init_pair || return
  if asA env TUNLION_TRANSPORTS=direct,relay "$BIN" --server "$SERVER" add --nearby --word "brave otter" >"$WORK/deny.log" 2>&1; then
    bad "pair --nearby succeeded with lan off"
  else
    ok "pair --nearby refused with lan off"
  fi
  if grep -aq "\[" "$DA/devices.json" 2>/dev/null && grep -aq '"secret"' "$DA/devices.json" 2>/dev/null; then
    bad "lan-off pairing wrote a secret"
  else
    ok "lan-off wrote no pairing"
  fi
}

base_net
happy
wrong_code
denied
echo
if [ "$FAIL" -ne 0 ]; then
  for f in "$WORK"/*.log; do [ -f "$f" ] && { echo "--- $f"; tail -40 "$f"; }; done
fi
echo "lan-pairing gates: $PASS passed, $FAIL failed${FAILED:+ ($FAILED)}"
[ "$FAIL" = 0 ]
