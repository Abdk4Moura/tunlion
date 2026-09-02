#!/usr/bin/env bash
# End-to-end subnet routing between two REAL machines, over the real internet.
#
# What this proves that no unit test can: a prefix advertised by one node,
# authorized by an owner-signed capability the receiver checks locally, crosses
# the internet, installs in a real kernel routing table, and carries real
# traffic into a LAN the receiver has no other path to.
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
W=/tmp/sr-e2e; PREFIX=10.66.0.0/24; LANHOST=10.66.0.5; MYNAME=sr-owner
RBIN=/tmp/sr-peer-bin/filament; RDIR=/tmp/sr-peer
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

say "1. receiver namespace here (owner side, own filament0)"
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
  && ok "receiver namespace has DNS + internet" || { echo "SETUP: receiver ns has no internet"; exit 2; }

say "2. router namespace on the remote machine, with a LAN behind it"
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
     ip netns add srlan
     ip netns exec srp ip link add srl-r type veth peer name srl-l
     ip netns exec srp ip link set srl-l netns srlan
     ip netns exec srp ip addr add 10.66.0.1/24 dev srl-r
     ip netns exec srp ip link set srl-r up
     ip netns exec srlan ip addr add $LANHOST/24 dev srl-l
     ip netns exec srlan ip link set srl-l up && ip netns exec srlan ip link set lo up
     ip netns exec srlan ip route add default via 10.66.0.1" 180
RLAN=$(rsh "ip netns exec srp ping -c1 -W2 $LANHOST >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$RLAN" = "OK" ] && ok "router reaches $LANHOST on its own LAN" \
                   || { echo "SETUP: router cannot reach its LAN"; exit 2; }
RNET=$(rsh "ip netns exec srp getent hosts api.filament.autumated.com >/dev/null 2>&1 && echo OK || echo FAIL" 90 | tail -1)
[ "$RNET" = "OK" ] && ok "router namespace has internet" || { echo "SETUP: router ns has no internet"; exit 2; }

say "3. NEGATIVE CONTROL: can the receiver reach that LAN today?"
BEFORE=$(ip netns exec srr ping -c1 -W2 "$LANHOST" >/dev/null 2>&1 && echo REACHABLE || echo UNREACHABLE)
echo "  receiver -> $LANHOST : $BEFORE"
[ "$BEFORE" = "UNREACHABLE" ] \
  || { echo "ABORT: receiver already reaches the LAN; the experiment would prove nothing"; exit 2; }
ok "negative control holds"

say "4. owner identity + receiver daemon"
# Non-interactive init REQUIRES --name and --recovery-file; without them it exits
# 1. Output is NOT swallowed: an earlier version sent init to /dev/null and the
# run failed four steps later with "no identity", pointing at the wrong place.
own init --yes --name "$MYNAME" --recovery-file "$W/recovery.txt" 2>&1 | tail -1
own id 2>&1 | head -3 | sed 's/^/  /'
own id >/dev/null 2>&1 || { echo "SETUP: owner identity was not created"; exit 2; }
# accept-routes BEFORE `up`: `set` prints "takes effect on next filament up" and
# means it. Setting it on a running daemon and then testing for routes measures
# nothing.
own set accept-routes true 2>&1 | tail -1
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
grep -q "userspace" "$W/rtr.log" 2>/dev/null && {
  echo "SETUP: receiver fell back to the userspace overlay, which installs no kernel routes"
  grep -E "TUNSETIFF|userspace" "$W/rtr.log" | head -2; exit 2; }
ip netns exec srr ip link show filament0 >/dev/null 2>&1 \
  && ok "receiver has kernel filament0 in its namespace" || { echo "SETUP: no kernel TUN"; exit 2; }

# ---------------------------------------------------------------------------
# One phase: invite the router with a given CEILING, join, advertise, and see
# whether the prefix installs and carries traffic.
#
# The ceiling is the INDEPENDENT VARIABLE. Running only the permitted case would
# show that routes can install, but not that authorization is what permits them;
# an unconditional `return true` in the enforcement path would pass that test
# just as well. Running both, with nothing else changed, is what separates
# "authorization works" from "authorization is absent".
#
# For a FLEET MEMBER the ceiling IS the grant. No CapOp can bind to one: a CapOp
# targets the owner user key that every member presents, so it cannot name a
# single device, and `grant` refuses outright rather than report a success
# enforcement would not honour. Authorization therefore has to come from the
# owner-signed invitation, which is also where transfer and mount come from.
run_phase() {
  local ceiling="$1" expect="$2" label="$3"
  say "PHASE: $label   (ceiling: $ceiling, expecting route to $expect)"

  # Fresh identity on the router each phase, so the ceiling under test is the
  # only thing that differs. A re-enrollment is a new signed claim whose bounds
  # win over the old record, but reusing a joined identity would leave the
  # previous ceiling in play on the remote side.
  rsh "$KILL_REMOTE; sleep 2; rm -rf $RDIR; mkdir -p $RDIR; echo cleared" 90 >/dev/null

  rm -f "$W/inv.txt"
  own add --for "$PEER" --allow "$ceiling" --out "$W/inv.txt" --yes 2>&1 | tail -1
  [ -s "$W/inv.txt" ] || { bad "no invitation produced for ceiling '$ceiling'"; return 1; }
  local INV; INV=$(cat "$W/inv.txt")
  # 600 on the remote side too: filament refuses to read a world-readable secret.
  rsh "umask 077; printf '%s' '$INV' > $RDIR/inv.txt; chmod 600 $RDIR/inv.txt; wc -c < $RDIR/inv.txt" 90 >/dev/null
  # Detached: a join outlives the PTY session that starts it.
  rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN join $RDIR/inv.txt --yes' >$RDIR/join.log 2>&1 & echo started" 90 >/dev/null
  local J=0 i
  for i in $(seq 1 25); do
    J=$(rsh "grep -c 'joined as' $RDIR/join.log 2>/dev/null || echo 0" 60 | tail -1)
    [ "${J:-0}" != "0" ] && break; sleep 8
  done
  [ "${J:-0}" != "0" ] || { bad "router never joined in phase '$label'"; return 1; }
  echo "  ceiling as the owner recorded it:"
  own devices 2>&1 | grep -E '●.*vps' | sed 's/^/    /'

  rsh "ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN set advertise-routes '$PREFIX' 2>&1 | tail -1" 90
  rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=${FLOG:-info} $RBIN up' >$RDIR/up.log 2>&1 & echo up" 90 >/dev/null
  sleep 25

  # Restart the receiver so it re-reads settings and takes a fresh announcement.
  kill_local; sleep 3; : > "$W/rtr.log"
  ip netns exec srr env FILAMENT_CONFIG_DIR="$W/rtr" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/rtr.log" 2>&1 &
  for i in $(seq 1 45); do grep -q "L3 overlay" "$W/rtr.log" 2>/dev/null && break; sleep 2; done
  sleep 45

  echo "  router says it is carrying:"
  rsh "grep -E 'carrying|advertis' $RDIR/up.log | tail -2" 90 | sed 's/^/    /'
  echo "  receiver routing table (10.66.x):"
  ip netns exec srr ip route show | grep -E '10\.66\.' | sed 's/^/    /' || echo "    (none)"
  local installed=no reach
  ip netns exec srr ip route show | grep -qE '10\.66\.0\.0/24' && installed=yes
  reach=$(ip netns exec srr ping -c3 -W3 "$LANHOST" >/dev/null 2>&1 && echo REACHABLE || echo UNREACHABLE)
  echo "  route installed: $installed    receiver -> $LANHOST : $reach"
  grep -E "not installed|routes via" "$W/rtr.log" | tail -2 | sed 's/^/    /'

  if [ "$expect" = "install" ]; then
    [ "$installed" = "yes" ] && ok "prefix installed under an authorizing ceiling" \
                             || bad "prefix did NOT install under an authorizing ceiling"
    [ "$reach" = "REACHABLE" ] && ok "traffic crossed the internet into the remote LAN" \
                              || bad "LAN unreachable despite authorization"
    AFTER="$reach"
  else
    [ "$installed" = "no" ] && ok "prefix correctly REFUSED without route in the ceiling" \
                            || bad "prefix installed WITHOUT authorization"
    [ "$reach" = "UNREACHABLE" ] && ok "LAN correctly still unreachable" \
                                || bad "LAN reachable without authorization"
  fi
}

case "${PHASES:-both}" in
  auth)   run_phase "transfer,mount,route" "install" "AUTHORIZED (route present in ceiling)" ;;
  unauth) run_phase "transfer,mount"       "refuse"  "UNAUTHORIZED (route absent from ceiling)" ;;
  *)      run_phase "transfer,mount"       "refuse"  "UNAUTHORIZED (route absent from ceiling)"
          run_phase "transfer,mount,route" "install" "AUTHORIZED (route present in ceiling)" ;;
esac

say "RESULT"
if [ "$FAIL" = "0" ]; then
  echo "  ALL CHECKS PASSED"
  echo "  before any authorization: $BEFORE"
  echo "  ceiling without route:    refused, LAN unreachable"
  echo "  ceiling with route:       installed, LAN ${AFTER:-?}"
  echo "  Two real machines, same prefix, same code; only the owner-signed"
  echo "  ceiling differs between the two phases."
else
  echo "  SOME CHECKS FAILED"
  echo "  --- receiver log tail:"; tail -18 "$W/rtr.log" 2>/dev/null | sed 's/^/  /'
  echo "  --- router log tail:";   rsh "tail -12 $RDIR/up.log 2>/dev/null" 90 | sed 's/^/  /'
fi
exit "$FAIL"
