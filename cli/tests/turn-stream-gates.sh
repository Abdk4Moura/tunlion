#!/usr/bin/env bash
# E2E: the CLI relays over TURN-over-TCP and TURN-over-TLS(443) when UDP is
# blocked, and still uses UDP when UDP works.
#
# A real CLI runs inside a network namespace whose OUTPUT chain drops every UDP
# packet (and, in the strict cell, every TCP packet not to port 443). Its peer
# is a CLI or a real headless Chromium on the unblocked host. Both talk to the
# real signaling server and the TURN servers it hands out (`/api/config`
# mints short-lived TURN credentials per fetch; nothing long-lived is used or
# copied here).
#
#   ns 10.214.<n>.2 --veth-- host 10.214.<n>.1 --MASQUERADE--> internet
#
# Every claim is read off an instrument, not inferred from success:
#   - the ns firewall's per-endpoint counters (new TCP connections to each TURN
#     TCP/TLS endpoint, UDP packets dropped, UDP packets to each TURN UDP port);
#   - the sender's own route line ("route: relay (TURN over tcp|tls|udp)");
#   - the bytes: sha256 of what landed equals sha256 of what was sent.
#
# Cells:
#   C1 tcp      CLI->CLI      UDP dropped              relay over TCP, no TLS dialled
#   C2 tcp      CLI->browser  UDP dropped              relay over TCP
#   C3 tls443   CLI->CLI      UDP dropped, TCP!=443    relay over TLS 443
#   C4 tls443   CLI->browser  UDP dropped, TCP!=443    relay over TLS 443
#   C5 open     CLI->CLI      nothing blocked          direct; no TURN stream dialled
#   C6 open     CLI->CLI      nothing blocked, --relay relay over UDP; no TURN stream dialled
#   C7 timing   open --relay, bridge on vs TUNLION_TURN_STREAM=0, K runs each
#
# Requires: passwordless sudo, ip, iptables, python3, getent, node with
# playwright + chromium (cli/tests: npm ci && npx playwright install chromium).
# Refuses (exit 2) when one is missing; never skips a cell silently.
# Honors TUNLION_BIN, TUNLION_SERVER, TUNLION_APP, TURN_GATE_EVIDENCE, TURN_GATE_K,
# TURN_GATE_CELLS (space-separated subset, e.g. "C1 C3").

set -uo pipefail
exec 3>&- 2>/dev/null || true
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${TUNLION_BIN:?set TUNLION_BIN to the tunlion binary under test}"
SERVER="${TUNLION_SERVER:-https://api.tunlion.autumated.com}"
APP="${TUNLION_APP:-https://tunlion.autumated.com}"
K="${TURN_GATE_K:-3}"
CELLS="${TURN_GATE_CELLS:-C1 C2 C3 C4 C5 C6 C7}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/turn-stream.XXXXXX")"
EVID="${TURN_GATE_EVIDENCE:-$WORK/evidence}"
mkdir -p "$EVID"
ME="$(id -un)"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n== %s ==\n' "$*" | tee -a "$EVID/summary.txt"; }
ok()  { echo "PASS: $1" | tee -a "$EVID/summary.txt"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1" | tee -a "$EVID/summary.txt"; FAIL=$((FAIL+1)); FAILED="$FAILED $2"; }
note() { echo "  $1" | tee -a "$EVID/summary.txt"; }

run_root() { if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo -n "$@"; fi; }

SUF="$(printf '%02x' $((BASHPID % 200 + 20)))"
NET="10.214.$((BASHPID % 200 + 20))"
NS="tsg${SUF}"
H_IF="tsh${SUF}"
N_IF="tsn${SUF}"
PIDS=()
cleanup() {
  local p
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  run_root iptables -D FORWARD -i "$H_IF" -j ACCEPT 2>/dev/null || true
  run_root iptables -D FORWARD -o "$H_IF" -j ACCEPT 2>/dev/null || true
  run_root iptables -t nat -D POSTROUTING -s "$NET.0/30" ! -o "$H_IF" -j MASQUERADE 2>/dev/null || true
  run_root ip netns del "$NS" 2>/dev/null || true
  run_root ip link del "$H_IF" 2>/dev/null || true
  run_root rm -rf "/etc/netns/$NS"
  rm -rf "$WORK/home-"* 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# ----------------------------------------------------------------- preflight
for cmd in ip iptables python3 getent sha256sum node; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "REFUSED: $cmd is required"; exit 2; }
done
[ -x "$BIN" ] || { echo "REFUSED: no tunlion binary at $BIN"; exit 2; }
if [ "$(id -u)" -ne 0 ]; then sudo -n true 2>/dev/null || { echo "REFUSED: passwordless sudo is required"; exit 2; }; fi
( cd "$HERE" && node -e 'require("playwright")' ) 2>/dev/null \
  || { echo "REFUSED: playwright missing (cd cli/tests && npm ci && npx playwright install chromium)"; exit 2; }

CFG_JSON="$(curl -fsS --max-time 10 "$SERVER/api/config")" || { echo "REFUSED: $SERVER/api/config unreachable"; exit 2; }
# Only the URL list is kept; the minted credentials are not written anywhere.
printf '%s' "$CFG_JSON" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for s in d["iceServers"]:
    u=s["urls"]; u=[u] if isinstance(u,str) else u
    for x in u: print(x)' >"$EVID/ice-urls.txt"
note "ICE URLs handed out by $SERVER/api/config:"; sed 's/^/    /' "$EVID/ice-urls.txt" | tee -a "$EVID/summary.txt"

ip4() { getent ahostsv4 "$1" | awk 'NR==1{print $1}'; }
SRV_HOST="$(printf '%s' "$SERVER" | sed -E 's#^[a-z]+://([^/:]+).*#\1#')"
CF_HOST=turn.cloudflare.com
CO_TLS_HOST=turn.filament.autumated.com
SRV_IP="$(ip4 "$SRV_HOST")"; CF_IP="$(ip4 "$CF_HOST")"; CO_TLS_IP="$(ip4 "$CO_TLS_HOST")"
STUN_IP="$(ip4 stun.l.google.com)"
CO_UDP_IP="$(grep -oE '^turn:[0-9.]+:3478$' "$EVID/ice-urls.txt" | head -1 | sed -E 's/^turn:([0-9.]+):.*/\1/')"
for v in SRV_IP CF_IP CO_TLS_IP STUN_IP CO_UDP_IP; do
  [ -n "${!v}" ] || { echo "REFUSED: could not resolve $v"; exit 2; }
done
note "pinned: $SRV_HOST=$SRV_IP $CF_HOST=$CF_IP $CO_TLS_HOST=$CO_TLS_IP coturn-udp=$CO_UDP_IP"

# ------------------------------------------------------------------ topology
run_root ip netns add "$NS"
run_root ip -n "$NS" link set lo up
run_root ip link add "$H_IF" type veth peer name "$N_IF"
run_root ip link set "$N_IF" netns "$NS"
run_root ip addr add "$NET.1/30" dev "$H_IF"
run_root ip link set "$H_IF" up
run_root ip -n "$NS" addr add "$NET.2/30" dev "$N_IF"
run_root ip -n "$NS" link set "$N_IF" up
run_root ip -n "$NS" route add default via "$NET.1"
# IPv4 only, so the v4 rules below are the whole firewall: no link-local v6
# path to the host can carry the UDP this namespace is denied.
run_root ip netns exec "$NS" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1
run_root sysctl -q -w net.ipv4.ip_forward=1
run_root iptables -I FORWARD 1 -i "$H_IF" -j ACCEPT
run_root iptables -I FORWARD 1 -o "$H_IF" -j ACCEPT
run_root iptables -t nat -I POSTROUTING 1 -s "$NET.0/30" ! -o "$H_IF" -j MASQUERADE
# Names resolve from a pinned hosts file: DNS is UDP, and this namespace has
# none. The resolver points at a closed loopback port so any other lookup fails
# at once instead of hiding a UDP path.
run_root mkdir -p "/etc/netns/$NS"
printf '127.0.0.1 localhost\n%s %s\n%s %s\n%s %s\n%s stun.l.google.com\n' \
  "$SRV_IP" "$SRV_HOST" "$CF_IP" "$CF_HOST" "$CO_TLS_IP" "$CO_TLS_HOST" "$STUN_IP" \
  | run_root tee "/etc/netns/$NS/hosts" >/dev/null
printf 'nameserver 127.0.0.1\n' | run_root tee "/etc/netns/$NS/resolv.conf" >/dev/null
nsx() { run_root ip netns exec "$NS" "$@"; }

# TURN stream endpoints by class. Counted as NEW connections.
TCP_EPS="$CF_IP:3478 $CF_IP:80"
TLS_EPS="$CF_IP:5349 $CF_IP:443 $CO_TLS_IP:443"
UDP_EPS="$CO_UDP_IP:3478 $CF_IP:3478 $CF_IP:443"

firewall() { # mode: tcp | tls443 | open
  local mode="$1" ep
  nsx iptables -F OUTPUT
  nsx iptables -Z OUTPUT
  nsx iptables -A OUTPUT -o lo -j ACCEPT
  for ep in $TCP_EPS; do
    local verdict=ACCEPT; [ "$mode" = tls443 ] && verdict=DROP
    nsx iptables -A OUTPUT -p tcp -d "${ep%:*}" --dport "${ep#*:}" -m conntrack --ctstate NEW \
      -m comment --comment "tcp:$ep" -j "$verdict"
  done
  for ep in $TLS_EPS; do
    local verdict=ACCEPT; [ "$mode" = tls443 ] && [ "${ep#*:}" != 443 ] && verdict=DROP
    nsx iptables -A OUTPUT -p tcp -d "${ep%:*}" --dport "${ep#*:}" -m conntrack --ctstate NEW \
      -m comment --comment "tls:$ep" -j "$verdict"
  done
  # Count-only (no target): UDP reaching a TURN UDP port, before any drop.
  for ep in $UDP_EPS; do
    nsx iptables -A OUTPUT -p udp -d "${ep%:*}" --dport "${ep#*:}" -m comment --comment "udpturn:$ep"
  done
  case "$mode" in
    tcp)    nsx iptables -A OUTPUT -p udp -m comment --comment udpdrop -j DROP ;;
    tls443) nsx iptables -A OUTPUT -p udp -m comment --comment udpdrop -j DROP
            nsx iptables -A OUTPUT -p tcp ! --dport 443 -m comment --comment tcpdrop -j DROP ;;
    open)   : ;;
  esac
}
# Sum of packet counters for rules whose comment starts with $1.
counter() {
  nsx iptables -L OUTPUT -v -n -x | grep -F "/* $1" | awk '{s+=$1} END {print s+0}'
}
counters_dump() { nsx iptables -L OUTPUT -v -n -x >"$1"; }

# ----------------------------------------------------------------- identities
mkid() {
  local dir="$1" name="$2"
  mkdir -p "$dir"
  timeout -k 5 60 env HOME="$dir" TUNLION_CONFIG_DIR="$dir" "$BIN" --server "$SERVER" init --name "$name" \
    --recovery-file "$dir/rec.txt" --yes >"$WORK/init-$name.log" 2>&1 \
    || { echo "REFUSED: init $name failed"; tail -20 "$WORK/init-$name.log"; exit 2; }
}
S="$WORK/home-sender"; R="$WORK/home-receiver"
mkid "$S" turn-gate-sender
mkid "$R" turn-gate-receiver

PAY="$WORK/payload.bin"
head -c $((4 * 1024 * 1024 + 77)) /dev/urandom >"$PAY"
PAYHASH="$(sha256sum "$PAY" | cut -d' ' -f1)"

wait_bounded() {
  local pid="$1" secs="$2" i
  for i in $(seq 1 $((secs * 4))); do
    kill -0 "$pid" 2>/dev/null || { wait "$pid"; return $?; }
    sleep 0.25
  done
  kill "$pid" 2>/dev/null; sleep 1; kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124
}

# send_in_ns LOGPREFIX ROOM [extra env/args...]: run the sender inside the ns
# as this user (never root: HOME and config are the scratch identity).
send_in_ns() {
  local log="$1" room="$2"; shift 2
  local envs=() args=()
  while [ $# -gt 0 ]; do case "$1" in *=*) envs+=("$1") ;; *) args+=("$1") ;; esac; shift; done
  nsx sudo -n -u "$ME" env HOME="$S" TUNLION_CONFIG_DIR="$S" TUNLION_NONINTERACTIVE=1 "${envs[@]}" \
    "$BIN" --server "$SERVER" send "$PAY" --room "$room" --timeout 90 -vv "${args[@]}" \
    </dev/null >"$log.out" 2>"$log.err"
}

# cli_transfer NAME [sender args/env...]: sets T_SRC T_RRC T_HASH LAST_SEND_MS.
LAST_SEND_MS=0; T_SRC=1; T_RRC=1; T_HASH=""
cli_transfer() {
  local name="$1"; shift
  local room="tsg-$name-$RANDOM$RANDOM" inbox="$WORK/inbox-$name"
  rm -rf "$inbox"; mkdir -p "$inbox"
  env HOME="$R" TUNLION_CONFIG_DIR="$R" TUNLION_NONINTERACTIVE=1 "$BIN" --server "$SERVER" receive \
    --room "$room" --yes --dir "$inbox" --timeout 150 -v </dev/null >"$EVID/$name-recv.out" 2>"$EVID/$name-recv.err" &
  local rpid=$!; PIDS+=("$rpid")
  sleep 3
  local t0 t1; t0=$(date +%s%3N)
  send_in_ns "$EVID/$name-send" "$room" "$@" &
  local spid=$!; PIDS+=("$spid")
  wait_bounded "$spid" 150; local src=$?
  t1=$(date +%s%3N); LAST_SEND_MS=$((t1 - t0))
  wait_bounded "$rpid" 30; local rrc=$?
  local got; got="$(find "$inbox" -type f -name 'payload.bin*' | head -1)"
  T_HASH=""; [ -n "$got" ] && T_HASH="$(sha256sum "$got" | cut -d' ' -f1)"
  T_SRC=$src; T_RRC=$rrc
}

route_of() { grep -hoE 'route: [^[:cntrl:]]*' "$1" 2>/dev/null | sed -E 's/\x1b\[[0-9;]*m//g' | head -1; }

cli_cell() {
  local cell="$1" mode="$2" want="$3"; shift 3
  say "$cell: CLI (ns, $mode) -> CLI (host)"
  firewall "$mode"
  cli_transfer "$cell" "$@"
  local src=$T_SRC rrc=$T_RRC gothash=$T_HASH
  counters_dump "$EVID/$cell-counters.txt"
  local route; route="$(route_of "$EVID/$cell-send.err")"
  note "sender rc=$src receiver rc=$rrc wall=${LAST_SEND_MS}ms $route"
  note "counters: udpdrop=$(counter udpdrop) tcp=$(counter tcp:) tls=$(counter tls:) udpturn=$(counter udpturn:) tcpdrop=$(counter tcpdrop)"
  grep -hE 'TURN over|relay candidate' "$EVID/$cell-send.err" | sed 's/^/    /' | head -20 | tee -a "$EVID/summary.txt"
  if [ "$src" -eq 0 ] && [ "$gothash" = "$PAYHASH" ]; then
    ok "$cell: transfer delivered byte for byte (sha256 $PAYHASH)"
  else bad "$cell: transfer failed (send rc=$src recv rc=$rrc hash=${gothash:-none})" "$cell"; fi
  if printf '%s' "$route" | grep -Eq "$want"; then ok "$cell: sender route matches /$want/ ($route)"
  else bad "$cell: sender route '$route' does not match /$want/" "$cell"; fi
}

browser_cell() {
  local cell="$1" mode="$2" want="$3"; shift 3
  say "$cell: CLI (ns, $mode) -> Chromium (host)"
  firewall "$mode"
  local room="tsg-$cell-$RANDOM$RANDOM"
  ( cd "$HERE" && node turn-stream-browser.cjs "$APP/rooms/$room" "$WORK/dl-$cell" ) \
    >"$EVID/$cell-browser.log" 2>&1 &
  local bpid=$!; PIDS+=("$bpid")
  sleep 8
  send_in_ns "$EVID/$cell-send" "$room" &
  local spid=$!; PIDS+=("$spid")
  wait_bounded "$spid" 150; local src=$?
  wait_bounded "$bpid" 60; local brc=$?
  counters_dump "$EVID/$cell-counters.txt"
  local route; route="$(route_of "$EVID/$cell-send.err")"
  local res; res="$(grep -h '^RESULT ' "$EVID/$cell-browser.log" | tail -1)"
  note "sender rc=$src browser rc=$brc $route"
  note "browser: ${res:-none}"
  note "counters: udpdrop=$(counter udpdrop) tcp=$(counter tcp:) tls=$(counter tls:) tcpdrop=$(counter tcpdrop)"
  if [ "$src" -eq 0 ] && [ "$brc" -eq 0 ] && printf '%s' "$res" | grep -q "sha256=$PAYHASH"; then
    ok "$cell: browser received byte for byte (sha256 $PAYHASH)"
  else bad "$cell: CLI->browser failed (send rc=$src browser rc=$brc)" "$cell"; tail -5 "$EVID/$cell-browser.log"; fi
  if printf '%s' "$res" | grep -q 'relay_badge=true'; then ok "$cell: browser shows the RELAY route badge"
  else bad "$cell: browser did not show the relay badge" "$cell"; fi
  if printf '%s' "$route" | grep -Eq "$want"; then ok "$cell: sender route matches /$want/ ($route)"
  else bad "$cell: sender route '$route' does not match /$want/" "$cell"; fi
}

want_cell() { case " $CELLS " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

assert_blocked_udp_tcp() { # cell: UDP was tried and dropped; TCP TURN carried it; TLS never dialled
  local c="$1"
  local d t s; d=$(counter udpdrop); t=$(counter tcp:); s=$(counter tls:)
  if [ "$d" -gt 0 ]; then ok "$c: UDP egress was attempted and dropped ($d packets): the block was real"
  else bad "$c: no UDP was dropped; the block was not exercised" "$c"; fi
  if [ "$t" -gt 0 ]; then ok "$c: $t new TCP connection(s) to TURN TCP endpoints"
  else bad "$c: no TCP connection to a TURN TCP endpoint" "$c"; fi
  if [ "$s" -eq 0 ]; then ok "$c: TLS was never dialled (TCP came first and sufficed)"
  else bad "$c: TLS was dialled ($s) although TCP worked" "$c"; fi
}
assert_blocked_tls() {
  local c="$1"
  local d t tl; d=$(counter udpdrop); t=$(counter tcp:)
  tl=$(nsx iptables -L OUTPUT -v -n -x | grep -F '/* tls:' | grep -F ':443 */' | grep -w ACCEPT | awk '{s+=$1} END {print s+0}')
  if [ "$d" -gt 0 ]; then ok "$c: UDP egress was attempted and dropped ($d packets)"
  else bad "$c: no UDP was dropped" "$c"; fi
  if [ "$t" -gt 0 ]; then ok "$c: TCP TURN was tried first and dropped ($t SYNs)"
  else bad "$c: TCP TURN was never tried before TLS" "$c"; fi
  if [ "$tl" -gt 0 ]; then ok "$c: $tl new TLS connection(s) to TURN on 443"
  else bad "$c: no TLS connection to TURN on 443" "$c"; fi
}
assert_no_stream() {
  local c="$1"
  local t s; t=$(counter tcp:); s=$(counter tls:)
  if [ "$t" -eq 0 ] && [ "$s" -eq 0 ]; then ok "$c: no TURN TCP/TLS connection was opened (tcp=$t tls=$s)"
  else bad "$c: UDP worked but TURN streams were dialled (tcp=$t tls=$s)" "$c"; fi
}

if want_cell C1; then cli_cell C1 tcp 'relay \(TURN over tcp\)'; assert_blocked_udp_tcp C1; fi
if want_cell C2; then browser_cell C2 tcp 'relay \(TURN over tcp\)'; assert_blocked_udp_tcp C2; fi
if want_cell C3; then cli_cell C3 tls443 'relay \(TURN over tls\)'; assert_blocked_tls C3; fi
if want_cell C4; then browser_cell C4 tls443 'relay \(TURN over tls\)'; assert_blocked_tls C4; fi
if want_cell C5; then cli_cell C5 open '^route: direct'; assert_no_stream C5; fi
if want_cell C6; then
  cli_cell C6 open 'relay \(TURN over udp\)' --relay
  assert_no_stream C6
  u=$(counter udpturn:)
  if [ "$u" -gt 0 ]; then ok "C6: $u UDP packets to TURN UDP endpoints: the relay rode UDP"
  else bad "C6: no UDP reached a TURN UDP endpoint" C6; fi
fi

if want_cell C7; then
  say "C7: time to deliver over a UDP relay, bridge on vs off (K=$K each, alternating)"
  firewall open
  ON=(); OFF=()
  for i in $(seq 1 "$K"); do
    cli_transfer "C7-on-$i" --relay
    if [ "$T_SRC" -eq 0 ] && [ "$T_HASH" = "$PAYHASH" ]; then ON+=("$LAST_SEND_MS"); else bad "C7: run on-$i failed" C7; fi
    cli_transfer "C7-off-$i" --relay TUNLION_TURN_STREAM=0
    if [ "$T_SRC" -eq 0 ] && [ "$T_HASH" = "$PAYHASH" ]; then OFF+=("$LAST_SEND_MS"); else bad "C7: run off-$i failed" C7; fi
  done
  med() { printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END {if (NR==0) print -1; else print a[int((NR+1)/2)]}'; }
  MON=$(med "${ON[@]:-}"); MOFF=$(med "${OFF[@]:-}")
  note "bridge on:  ${ON[*]:-} ms (median $MON)"
  note "bridge off: ${OFF[*]:-} ms (median $MOFF)"
  if [ "${#ON[@]}" -eq "$K" ] && [ "${#OFF[@]}" -eq "$K" ] && [ "$MON" -le $((MOFF + 1000)) ]; then
    ok "C7: no time-to-deliver regression with UDP available (median on=${MON}ms off=${MOFF}ms, bound off+1000ms)"
  else bad "C7: bridge-on median ${MON}ms exceeds off ${MOFF}ms + 1000ms (or runs failed)" C7; fi
fi

echo | tee -a "$EVID/summary.txt"
if [ "$FAIL" -eq 0 ]; then
  echo "RESULT turn-stream PASS $PASS checks" | tee -a "$EVID/summary.txt"; exit 0
fi
echo "RESULT turn-stream FAIL $FAIL check(s):$FAILED" | tee -a "$EVID/summary.txt"; exit 1
