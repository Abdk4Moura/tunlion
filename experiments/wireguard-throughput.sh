#!/usr/bin/env bash
# THROUGHPUT: the WireGuard data plane against the QUIC-datagram plane.
#
# ONE LINK, TWO PLANES, MEASURED BACK TO BACK. The same pair of daemons, the same
# internet path, the same payload: first over the QUIC-datagram plane, then with
# `wireguard on` and nothing else changed. Measuring the two on separate runs
# would compare two different network moments, and this path has been seen to
# vary between 5 and 20 MB/s within a single session, which is far wider than any
# difference worth reporting.
#
# The payload rides the OVERLAY (a TCP stream to the peer's mesh address), not
# filament's file-transfer path, because the file transfer has its own framing
# and would measure that instead of the data plane.
set -uo pipefail
# PINNED OUT OF THE SHARED CARGO_TARGET_DIR: a concurrent build in another
# checkout has silently replaced a rig binary mid-run before, which makes every
# number after it a measurement of something else.
BIN=${FILAMENT_BIN:-/tmp/sr-bin/filament}
WANT_SHA=${WANT_SHA:-}
PEER=${PEER:-interserver-0x0}
LOCAL_BIN=${LOCAL_BIN:-$HOME/.local/bin/filament}   # drives the remote PTY
W=/tmp/wgperf; MYNAME=wgperf-owner
RBIN=/tmp/sr-peer-bin/filament; RDIR=/tmp/wgperf-peer
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

say "1. namespaces on both machines"
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
  && ok "local namespace has internet" || { echo "SETUP: no internet locally"; exit 2; }
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
     mkdir -p $RDIR" 200 >/dev/null
R=$(rsh "ip netns exec srp getent hosts api.filament.autumated.com >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$R" = "OK" ] && ok "remote namespace has internet" || { echo "SETUP: no internet remotely"; exit 2; }
RW=$(rsh "command -v wg >/dev/null && echo OK || echo FAIL" 90 | tail -1)
[ "$RW" = "OK" ] && ok "remote has wireguard-tools" || { echo "SETUP: remote lacks wireguard-tools"; exit 2; }

say "2. owner up, with the WireGuard plane on"
own init --yes --name "$MYNAME" --recovery-file "$W/rec" 2>&1 | tail -1
own set wireguard "${WG_FIRST:-off}" 2>&1 | tail -1
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
grep -q userspace "$W/rtr.log" && { echo "SETUP: userspace overlay, no kernel TUN"; exit 2; }
ok "owner up with a kernel filament0"

say "3. peer joins, with the WireGuard plane on"
rm -f "$W/inv.txt"
own add --for "$PEER" --allow transfer,mount --out "$W/inv.txt" --yes 2>&1 | tail -1
[ -s "$W/inv.txt" ] || { echo "SETUP: no invitation"; exit 2; }
INV=$(cat "$W/inv.txt")
rsh "umask 077; printf '%s' '$INV' > $RDIR/inv.txt; chmod 600 $RDIR/inv.txt" 90 >/dev/null
rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN join $RDIR/inv.txt --yes; ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set wireguard ${WG_FIRST:-off}; ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=debug $RBIN up' >$RDIR/up.log 2>&1 & echo started" 90 >/dev/null
J=0
for i in $(seq 1 25); do
  J=$(rsh "grep -c 'joined as' $RDIR/up.log 2>/dev/null || echo 0" 60 | tail -1)
  [ "${J:-0}" != "0" ] && break; sleep 8
done
[ "${J:-0}" != "0" ] && ok "peer joined" || { bad "peer never joined"; rsh "tail -6 $RDIR/up.log" 90; exit 1; }


MB=${MB:-40}
RUNS=${RUNS:-3}

# The peer's overlay address, which is what the payload is sent to.
# From the OWNER's own device list, not from `id --json` on the peer: that
# command has no "overlay" key, so parsing it silently yields nothing and every
# measurement then reports a failure that looks like a network problem.
peer_overlay() {
  own devices 2>/dev/null | grep -oE 'fdf1:[0-9a-f:]+' | head -1
}

# A TCP sink on the peer that reads until EOF. Started fresh per measurement so a
# previous run's socket cannot be mistaken for this one's.
start_sink() {
  # INSIDE the namespace: the overlay lives there, and a sink bound in the root
  # namespace is simply unreachable, which looks like every measurement failing.
  rsh "pkill -f wgperf-sink 2>/dev/null; setsid nohup ip netns exec srp python3 -c \"
import socket,sys
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(('::',9099)); s.listen(4)
while True:
    c,_=s.accept()
    n=0
    while True:
        b=c.recv(1<<20)
        if not b: break
        n+=len(b)
    c.close()
\" --wgperf-sink >/dev/null 2>&1 & echo sink-up" 90 >/dev/null
}

# Push MB megabytes to the sink and report MB/s, measured on the sender.
measure_once() { # $1 = peer overlay
  ip netns exec srr python3 -c "
import socket,time,sys
addr='$1'; mb=$MB
buf=b'x'*(1<<20)
s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
s.settimeout(60)
try:
    s.connect((addr,9099))
except Exception as e:
    print('ERR'); sys.exit(0)
t0=time.time()
try:
    for _ in range(mb): s.sendall(buf)
    s.shutdown(socket.SHUT_WR)
    s.close()
except Exception:
    print('ERR'); sys.exit(0)
d=time.time()-t0
print(f'{mb/d:.2f}')
" 2>/dev/null
}

median() { sort -n | awk '{v[NR]=$1} END {print (NR%2)?v[(NR+1)/2]:(v[NR/2]+v[NR/2+1])/2}'; }

bench() { # $1 = label
  local addr; addr=$(peer_overlay)
  if [ -z "$addr" ]; then bad "no peer overlay address for $1" >&2; return 1; fi
  start_sink; sleep 3
  local vals=""
  for i in $(seq 1 "$RUNS"); do
    local v; v=$(measure_once "$addr")
    [ "$v" = "ERR" ] || [ -z "$v" ] && v=""
    # Progress to STDERR: this function's stdout IS the median, and printing
    # progress there made the caller capture the whole transcript as a number.
    [ -n "$v" ] && vals="$vals$v\n" && printf '    run %s: %s MB/s\n' "$i" "$v" >&2
    sleep 2
  done
  [ -n "$vals" ] || { bad "no successful runs for $1" >&2; return 1; }
  printf '%b' "$vals" | grep -v '^$' | median
}

say "4. first plane (wireguard=${WG_FIRST:-off})"
for i in $(seq 1 20); do
  ip netns exec srr ip -6 route show 2>/dev/null | grep -q filament0 && break; sleep 3
done
sleep 15
# Say which plane this number belongs to, rather than trusting the label: if
# wireguard is meant to be on and no tunnel is live, the number is a QUIC
# measurement wearing the wrong name.
if ip netns exec srr wg show filament-wg latest-handshakes 2>/dev/null | awk '$2>0' | grep -q .; then
  echo "  (a WireGuard tunnel IS live for this measurement)"
else
  echo "  (no WireGuard tunnel: this is the QUIC-datagram plane)"
fi
QUIC=$(bench "first")
echo "  median: ${QUIC:-?} MB/s"

if [ "${SKIP_SWITCH:-0}" = "1" ]; then
  say "RESULT (single plane)"
  echo "  measured: ${QUIC:-?} MB/s"
  exit "$FAIL"
fi

say "5. switch this same pair to WireGuard"
own set wireguard on 2>&1 | tail -1
rsh "ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set wireguard on 2>&1 | tail -1" 90 >/dev/null
# `set` takes effect on the next `up`, so both daemons restart. Same pair, same
# path, one setting different.
kill_local; sleep 3; : > "$W/rtr.log"
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
rsh "$KILL_REMOTE; sleep 2; setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=debug $RBIN up' >>$RDIR/up.log 2>&1 & echo up" 90 >/dev/null
echo "  waiting for the link to go direct again and the 10s reconcile to fire"
for i in $(seq 1 40); do
  ip netns exec srr wg show filament-wg latest-handshakes 2>/dev/null | awk '$2>0' | grep -q . && break
  sleep 8
done
if ip netns exec srr wg show filament-wg latest-handshakes 2>/dev/null | awk '$2>0' | grep -q .; then
  ok "WireGuard tunnel is live"
  ip netns exec srr wg show filament-wg 2>/dev/null | grep -E "endpoint|handshake" | sed 's/^/    /'
else
  bad "WireGuard never handshook; the second number would not be a WireGuard measurement"
fi

say "6. WireGuard plane (same pair, same path)"
WG=$(bench "WireGuard")
echo "  median: ${WG:-?} MB/s"

say "RESULT"
echo "  QUIC datagrams : ${QUIC:-?} MB/s"
echo "  WireGuard      : ${WG:-?} MB/s"
if [ -n "$QUIC" ] && [ -n "$WG" ]; then
  python3 - "$QUIC" "$WG" <<'PY'
import sys
q,w=float(sys.argv[1]),float(sys.argv[2])
d=(w-q)/q*100 if q else 0
print(f"  difference     : {d:+.1f}% for WireGuard")
print("  NOTE: this internet path has been seen to vary 5-20 MB/s within one")
print("  session. Treat anything under about 20% as inside that variance and")
print("  re-run before drawing a conclusion from it.")
PY
fi
exit "$FAIL"
