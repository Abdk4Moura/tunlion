#!/usr/bin/env bash
# EXIT NODE between two REAL machines, over the real internet.
#
# What this proves that no unit test can: a node accepts a DEFAULT route from a
# peer and its traffic actually leaves the internet from the peer's address,
# WITHOUT cutting the link that carries the route. The measurement is the public
# IP the receiver presents to the world: if it becomes the router's, every packet
# really is going through the mesh.
#
# WHY THIS IS SAFE TO RUN HERE. A default route can disconnect the machine that
# installs it, so the receiver runs inside a network namespace while the control
# channel to the remote machine runs in the ROOT namespace. If the exit route is
# wrong, the namespace loses connectivity and the harness still has both hands
# free. Testing this any other way risks locking yourself out of the box.
#
#   do-vm  [ns srr] RECEIVER  ==internet==  interserver [ns srp] ROUTER
#          owner, issues the grant                      joined device
#          pings 10.66.0.5                              advertises 10.66.0.0/24
#                                                       [ns srlan] 10.66.0.5
#
# WHY THE OWNER IS THE RECEIVER. Enforcement runs on the receiver and asks "does
# the ADVERTISER hold route:<cidr>?". The answer is an owner-SIGNED CapOp, and a
# joined device cannot mint one: if a fleet member could sign its own route
# authorization, any member could authorize any prefix for itself and the
# capability would gate nothing. So the grant must be issued by the owner, and
# putting the owner on the receiving end is what lets this run end to end. It is
# also the realistic shape: a remote box fronts a remote network, the owner's
# machine consumes it.
#
# WHY NAMESPACES. l3::ifname() is a hardcoded const ("filament0"), so a second
# daemon on a host that already runs one cannot get a kernel TUN. It silently
# degrades to the USERSPACE overlay, which installs no kernel routes, and subnet
# routing then fails for a reason unrelated to subnet routing. A netns gives each
# test daemon its own filament0 and leaves both machines' real daemons untouched.
#
# NEGATIVE CONTROL FIRST, always: the receiver must FAIL to reach the LAN before
# the grant exists and succeed after. A run that only checks success cannot tell
# working authorization from absent authorization, which is the failure this
# whole feature is built to avoid.
set -uo pipefail
# PINNED OUT OF THE SHARED CARGO_TARGET_DIR: a concurrent build in another
# checkout has silently replaced a rig binary mid-run before, which makes every
# number after it a measurement of something else.
BIN=${FILAMENT_BIN:-/tmp/sr-bin/filament}
WANT_SHA=${WANT_SHA:-}
PEER=${PEER:-interserver-0x0}
LOCAL_BIN=${LOCAL_BIN:-$HOME/.local/bin/filament}   # drives the remote PTY
W=/tmp/xn-e2e; PREFIX=0.0.0.0/0; MYNAME=xn-owner
RBIN=/tmp/sr-peer-bin/filament; RDIR=/tmp/xn-peer
FAIL=0

say()  { printf '\n=== %s\n' "$*"; }
ok()   { printf '  PASS  %s\n' "$*"; }
bad()  { printf '  FAIL  %s\n' "$*"; FAIL=1; }

# Remote execution over filament's native PTY.
# SENTINEL-DELIMITED, not tail -1: a PTY echoes the command and the prompt, so
# positional extraction reads the prompt as the answer.
# CR STRIPPED: a PTY sends CRLF, so "UNREACHABLE\r" != "UNREACHABLE" and every
# string test silently inverts. Both of these actually happened here.
rsh() {
  local out
  out=$(printf 'echo __B__; %s; echo __E__\nexit\n' "$1" \
        | timeout "${2:-90}" "$LOCAL_BIN" shell "$PEER" 2>&1 \
        | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b\]3008;[^\\]*\\//g; s/\r//g')
  printf '%s\n' "$out" | awk '/__B__/{f=1;next} /__E__/{f=0} f' | grep -vE '^\s*$'
}
# NEVER `export` FILAMENT_CONFIG_DIR: rsh drives the REAL local filament, the
# only thing that can reach the peer at all. Pointing it at the throwaway config
# breaks every remote step in a way that looks like a network fault.
own() { ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" "$BIN" "$@"; }

# Kill test daemons BY EXECUTABLE. FILAMENT_CONFIG_DIR is an env var and never
# appears in /proc/<pid>/cmdline, so matching on the config dir killed nothing
# and every aborted run leaked a live daemon; three had piled up before a
# "Text file busy" on rebuild gave it away. Matching the exe path also cannot
# hit either machine's real daemon, which runs a different binary.
kill_local()  { for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
                  [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$BIN" ] && kill "$p" 2>/dev/null
                done; return 0; }
KILL_REMOTE="for p in \$(ls /proc 2>/dev/null | grep -E '^[0-9]+\$'); do [ \"\$(readlink /proc/\$p/exe 2>/dev/null)\" = \"$RBIN\" ] && kill \$p 2>/dev/null; done"

cleanup() {
  say "cleanup"
  kill_local
  ip netns del srr 2>/dev/null; ip link del srr-h 2>/dev/null
  iptables -t nat -D POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE 2>/dev/null
  iptables -D FORWARD -i srr-h -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o srr-h -j ACCEPT 2>/dev/null
  rm -rf /etc/netns/srr
  rsh "$KILL_REMOTE
       ip netns del srp 2>/dev/null; ip netns del srlan 2>/dev/null
       ip link del srp-h 2>/dev/null
       iptables -t nat -D POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE 2>/dev/null
       iptables -D FORWARD -i srp-h -j ACCEPT 2>/dev/null
       iptables -D FORWARD -o srp-h -j ACCEPT 2>/dev/null
       rm -rf $RDIR /etc/netns/srp; echo remote-clean" 120 >/dev/null 2>&1
  echo "  local and remote state removed"
}
[ "${KEEP:-0}" = "1" ] || trap cleanup EXIT

[ -x "$BIN" ] || { echo "SETUP: no binary at $BIN"; exit 2; }
GOT_SHA=$(sha256sum "$BIN" | cut -d' ' -f1)
if [ -n "$WANT_SHA" ] && [ "$GOT_SHA" != "$WANT_SHA" ]; then
  echo "SETUP: binary hash $GOT_SHA != expected $WANT_SHA"; exit 2
fi
cleanup >/dev/null 2>&1
rm -rf "$W"; mkdir -p "$W/rtr"
say "binary: $("$BIN" --version)  sha ${GOT_SHA:0:16}"


say "1. receiver namespace (owner side, its own filament0)"
sysctl -qw net.ipv4.ip_forward=1
ip netns add srr
ip link add srr-h type veth peer name srr-n && ip link set srr-n netns srr
ip addr add 10.77.0.1/24 dev srr-h && ip link set srr-h up
ip netns exec srr ip addr add 10.77.0.2/24 dev srr-n
ip netns exec srr ip link set srr-n up && ip netns exec srr ip link set lo up
ip netns exec srr ip route add default via 10.77.0.1
mkdir -p /etc/netns/srr && echo "nameserver 1.1.1.1" > /etc/netns/srr/resolv.conf
iptables -t nat -A POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE
iptables -I FORWARD 1 -i srr-h -j ACCEPT
iptables -I FORWARD 1 -o srr-h -j ACCEPT
ip netns exec srr getent hosts api.filament.autumated.com >/dev/null 2>&1 \
  && ok "receiver namespace has internet" || { echo "SETUP: no internet in receiver ns"; exit 2; }

say "2. router namespace on the remote machine"
rsh "sysctl -qw net.ipv4.ip_forward=1
     ip netns add srp
     ip link add srp-h type veth peer name srp-n && ip link set srp-n netns srp
     ip addr add 10.88.0.1/24 dev srp-h && ip link set srp-h up
     ip netns exec srp ip addr add 10.88.0.2/24 dev srp-n
     ip netns exec srp ip link set srp-n up && ip netns exec srp ip link set lo up
     ip netns exec srp ip route add default via 10.88.0.1
     mkdir -p /etc/netns/srp && echo 'nameserver 1.1.1.1' > /etc/netns/srp/resolv.conf
     iptables -t nat -A POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE
     iptables -I FORWARD 1 -i srp-h -j ACCEPT
     iptables -I FORWARD 1 -o srp-h -j ACCEPT
     mkdir -p $RDIR" 180 >/dev/null
RNET=$(rsh "ip netns exec srp getent hosts api.filament.autumated.com >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$RNET" = "OK" ] && ok "router namespace has internet" || { echo "SETUP: no internet in router ns"; exit 2; }

# The address each side presents to the world. This is the whole measurement.
# Two providers: a single one going down would look exactly like "the exit route
# broke my connectivity", which is the failure this test is trying to detect.
pubip_local() {
  local v
  v=$(ip netns exec srr curl -s -4 --max-time 20 https://api.ipify.org 2>>"$W/curl.err")
  [ -n "$v" ] || v=$(ip netns exec srr curl -s -4 --max-time 20 https://icanhazip.com 2>>"$W/curl.err")
  printf '%s' "$v" | tr -d '[:space:]'
}
pubip_remote() {
  # Extract by PATTERN, not position. A PTY interleaves prompts and echoes, so
  # "the last line" is whatever the terminal happened to emit last; grepping for
  # a dotted quad says what we actually mean. `-4` is mandatory: the namespace
  # has no IPv6 route, and without it curl tries AAAA first and returns nothing
  # inside the timeout, which is indistinguishable from "the exit route broke
  # my connectivity" and is exactly what this test must not confuse.
  rsh "ip netns exec srp curl -s -4 --max-time 20 https://api.ipify.org 2>/dev/null; echo; ip netns exec srp curl -s -4 --max-time 20 https://icanhazip.com 2>/dev/null" 120 \
    | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

say "3. BASELINE: whose address does each side present?"
BEFORE=$(pubip_local); ROUTER_IP=$(pubip_remote)
echo "  receiver exits as: ${BEFORE:-<none>}"
echo "  router   exits as: ${ROUTER_IP:-<none>}"
if [ -z "$BEFORE" ] || [ -z "$ROUTER_IP" ]; then
  echo "SETUP: could not read public IPs"
  echo "  curl stderr:"; tail -5 "$W/curl.err" 2>/dev/null | sed 's/^/    /'
  exit 2
fi
[ "$BEFORE" != "$ROUTER_IP" ] \
  || { echo "ABORT: both machines already exit from the same address; the test would prove nothing"; exit 2; }
ok "the two machines exit from different addresses, so a change is visible"
[ "${STOP_AFTER_BASELINE:-0}" = "1" ] && { echo "  (stopping after baseline as requested)"; exit 0; }

say "4. owner identity + receiver daemon"
own init --yes --name "$MYNAME" --recovery-file "$W/rec.txt" 2>&1 | tail -1
own id >/dev/null 2>&1 || { echo "SETUP: no owner identity"; exit 2; }
own set accept-routes true 2>&1 | tail -1
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
grep -q "userspace" "$W/rtr.log" 2>/dev/null && { echo "SETUP: userspace overlay installs no kernel routes"; exit 2; }
ok "receiver up with a kernel filament0"

say "5. invite the exit node, with route in the ceiling"
rm -f "$W/inv.txt"
own add --for "$PEER" --allow transfer,mount,route --out "$W/inv.txt" --yes 2>&1 | tail -1
[ -s "$W/inv.txt" ] || { echo "SETUP: no invitation"; exit 2; }
INV=$(cat "$W/inv.txt")
rsh "umask 077; printf '%s' '$INV' > $RDIR/inv.txt; chmod 600 $RDIR/inv.txt" 90 >/dev/null
rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN join $RDIR/inv.txt --yes' >$RDIR/join.log 2>&1 & echo started" 90 >/dev/null
J=0
for i in $(seq 1 25); do
  J=$(rsh "grep -c 'joined as' $RDIR/join.log 2>/dev/null || echo 0" 60 | tail -1)
  [ "${J:-0}" != "0" ] && break; sleep 8
done
[ "${J:-0}" != "0" ] && ok "exit node joined the fleet" || { bad "never joined"; exit 1; }

say "6. the exit node advertises a default route"
rsh "ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set advertise-routes '$PREFIX' 2>&1 | tail -1" 90
rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN up' >$RDIR/up.log 2>&1 & echo up" 90 >/dev/null
sleep 30
kill_local; sleep 3; : > "$W/rtr.log"
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
sleep 50

say "7. did the traffic actually move?"
echo "  receiver policy rules:"
ip netns exec srr ip rule show 2>/dev/null | grep -E "5182|lookup" | head -4 | sed 's/^/    /'
echo "  exit table contents (first lines):"
ip netns exec srr ip route show table 51820 2>/dev/null | head -4 | sed 's/^/    /'
grep -E "exit route|not accepting|routes via" "$W/rtr.log" | tail -3 | sed 's/^/    /'

AFTER=$(pubip_local)
echo "  receiver exits as: ${AFTER:-<unreachable>}   (was $BEFORE, router is $ROUTER_IP)"
if [ "$AFTER" = "$ROUTER_IP" ]; then
  ok "traffic now leaves from the exit node's address"
elif [ -z "$AFTER" ]; then
  bad "the receiver lost connectivity: the exit route captured its own underlay"
else
  bad "traffic still leaves from $AFTER; the exit route did not take effect"
fi

# The link that carries the route must survive the route. If signaling or the
# peer endpoint were captured, this is where it shows up.
if ip netns exec srr ip route show table 51820 2>/dev/null | grep -q .; then
  ok "the exit table is populated, and the link carrying it is still up"
else
  bad "the exit table is empty"
fi

say "8. withdrawing it must restore the ordinary path"
rsh "ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set advertise-routes '' 2>&1 | tail -1" 90
rsh "$KILL_REMOTE; sleep 2; setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN up' >>$RDIR/up.log 2>&1 & echo up" 90 >/dev/null
sleep 60
RESTORED=$(pubip_local)
echo "  receiver exits as: ${RESTORED:-<unreachable>}"
if [ "$RESTORED" = "$BEFORE" ]; then
  ok "ordinary path restored after withdrawal"
else
  bad "after withdrawal the receiver exits as ${RESTORED:-<unreachable>}, expected $BEFORE"
fi

say "RESULT"
if [ "$FAIL" = "0" ]; then
  echo "  ALL CHECKS PASSED"
  echo "  before: $BEFORE   with exit node: $AFTER   after withdrawal: $RESTORED"
  echo "  The router's own address is $ROUTER_IP."
else
  echo "  SOME CHECKS FAILED"
  echo "  --- receiver log:"; tail -20 "$W/rtr.log" | sed 's/^/  /'
fi
exit "$FAIL"
