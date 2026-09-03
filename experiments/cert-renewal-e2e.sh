#!/usr/bin/env bash
# Certificate renewal between two REAL machines.
#
# WHAT THIS PROVES, and why a unit test cannot. Renewal is a conversation: the
# joined device asks, a device holding the owner signing key decides, and the
# answer has to survive a real link. `docs/design-pairing-ux.md` rule 2 makes
# that conversation load-bearing twice over, because expiry is the only bound
# this system has:
#
#   POSITIVE  a device in good standing must keep working past its expiry.
#             Without this every device silently falls off the mesh on a timer.
#   NEGATIVE  a REVOKED device must stop renewing and be allowed to expire.
#             "Removal is stop renewing" is the entire eviction mechanism, so if
#             renewal ignores revocation there is no way to remove a device at
#             all, and the positive arm alone would still look perfect.
#
# Running only the positive arm would pass with an unconditional "yes". The two
# arms differ in nothing but the owner's decision.
#
#   do-vm [ns srr] OWNER (holds the signing key)  ==internet==  [ns srp] JOINED
#
# Short certs by design: the invitation sets a 300s lifetime, so the device is
# due for renewal (last third of life) about 200s in and the daemon's 30s
# renewal tick fires well inside the remaining 100s window. The whole cycle is
# observable in one run instead of 90 days.
#
# EACH ARM GETS A FRESH JOIN. An earlier version revoked the same device after
# it had already renewed, and the negative arm then "passed" for the wrong
# reason: nothing renewed in either arm, so a completely broken mechanism scored
# a pass. A negative arm that cannot fail is not a control.
#
# The positive arm renews over a LIVE link with no restart, because that is the
# case that actually matters: a device connected for its whole certificate
# lifetime must not quietly expire while online.
set -uo pipefail
BIN=${FILAMENT_BIN:-/tmp/sr-bin/filament}
PEER=${PEER:-interserver-0x0}
LOCAL_BIN=${LOCAL_BIN:-$HOME/.local/bin/filament}
W=/tmp/cr-e2e; RDIR=/tmp/cr-peer; RBIN=/tmp/sr-peer-bin/filament
TTL=300; MYNAME=cr-owner
FAIL=0

say() { printf '\n=== %s\n' "$*"; }
ok()  { printf '  PASS  %s\n' "$*"; }
bad() { printf '  FAIL  %s\n' "$*"; FAIL=1; }

# Sentinel-delimited and CR-stripped: a PTY echoes the prompt and sends CRLF, so
# positional extraction reads the prompt as the answer and every string compare
# silently inverts. Both have bitten this rig before.
rsh() {
  local out
  out=$(printf 'echo __B__; %s; echo __E__\nexit\n' "$1" \
        | timeout "${2:-90}" "$LOCAL_BIN" shell "$PEER" 2>&1 \
        | sed 's/\x1b\[[0-9;?]*[a-zA-Z]//g; s/\x1b\]3008;[^\\]*\\//g; s/\r//g')
  printf '%s\n' "$out" | awk '/__B__/{f=1;next} /__E__/{f=0} f' | grep -vE '^\s*$'
}
own() { ip netns exec srr env FILAMENT_CONFIG_DIR="$W/o" "$BIN" "$@"; }

# By EXECUTABLE, not config dir: FILAMENT_CONFIG_DIR is an env var and never
# appears in /proc/<pid>/cmdline, so matching on it kills nothing and leaks
# daemons across runs.
kill_local() { for p in $(ls /proc 2>/dev/null | grep -E '^[0-9]+$'); do
                 [ "$(readlink /proc/$p/exe 2>/dev/null)" = "$BIN" ] && kill "$p" 2>/dev/null
               done; return 0; }
KILL_REMOTE="for p in \$(ls /proc 2>/dev/null | grep -E '^[0-9]+\$'); do [ \"\$(readlink /proc/\$p/exe 2>/dev/null)\" = \"$RBIN\" ] && kill \$p 2>/dev/null; done"

# The device's own certificate expiry, read from disk on the remote. This is the
# fact under test; everything else is narration.
peer_expiry() { rsh "python3 -c \"import json;print(json.load(open('$RDIR/identity/device-cert.json'))['cert']['expires'])\" 2>/dev/null || echo 0" 90 | tail -1; }

restart_peer() {
  rsh "$KILL_REMOTE; sleep 2
       setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR $RBIN up' >>$RDIR/up.log 2>&1 &
       echo restarted" 90 >/dev/null
}

cleanup() {
  say "cleanup"
  kill_local
  ip netns del srr 2>/dev/null; ip link del srr-h 2>/dev/null
  iptables -t nat -D POSTROUTING -s 10.77.0.0/24 ! -o srr-h -j MASQUERADE 2>/dev/null
  iptables -D FORWARD -i srr-h -j ACCEPT 2>/dev/null
  iptables -D FORWARD -o srr-h -j ACCEPT 2>/dev/null
  rm -rf /etc/netns/srr
  rsh "$KILL_REMOTE
       ip netns del srp 2>/dev/null; ip link del srp-h 2>/dev/null
       iptables -t nat -D POSTROUTING -s 10.88.0.0/24 ! -o srp-h -j MASQUERADE 2>/dev/null
       iptables -D FORWARD -i srp-h -j ACCEPT 2>/dev/null
       iptables -D FORWARD -o srp-h -j ACCEPT 2>/dev/null
       rm -rf $RDIR /etc/netns/srp; echo clean" 120 >/dev/null 2>&1
  echo "  local and remote state removed"
}
[ "${KEEP:-0}" = "1" ] || trap cleanup EXIT

[ -x "$BIN" ] || { echo "SETUP: no binary at $BIN"; exit 2; }
cleanup >/dev/null 2>&1
rm -rf "$W"; mkdir -p "$W/o"
say "binary: $("$BIN" --version)  sha $(sha256sum "$BIN" | cut -c1-16)"

say "1. namespaces (each daemon needs its own filament0)"
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
  && ok "owner namespace has internet" || { echo "SETUP: no internet in owner ns"; exit 2; }
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
[ "$RNET" = "OK" ] && ok "joined-device namespace has internet" || { echo "SETUP: no internet in peer ns"; exit 2; }

say "2. owner identity and daemon"
own init --yes --name "$MYNAME" --recovery-file "$W/rec.txt" 2>&1 | tail -1
own id >/dev/null 2>&1 || { echo "SETUP: no owner identity"; exit 2; }
ip netns exec srr env FILAMENT_CONFIG_DIR="$W/o" FILAMENT_LOG="${FLOG:-info}" setsid nohup "$BIN" up --name-as "$MYNAME" >"$W/o.log" 2>&1 &
for i in $(seq 1 45); do grep -q "L3 overlay" "$W/o.log" 2>/dev/null && break; sleep 2; done
ok "owner up"


# One arm: join fresh, optionally revoke, wait past the renewal point, and see
# whether the certificate expiry moved.
run_arm() {
  local revoke="$1" expect="$2" label="$3"
  say "PHASE: $label"

  rsh "$KILL_REMOTE; sleep 2; rm -rf $RDIR; mkdir -p $RDIR; echo cleared" 90 >/dev/null
  rm -f "$W/inv.txt"
  own add --for "$PEER" --expires "${TTL}s" --out "$W/inv.txt" --yes 2>&1 | tail -1
  [ -s "$W/inv.txt" ] || { bad "no invitation"; return 1; }
  local INV; INV=$(cat "$W/inv.txt")
  rsh "umask 077; printf '%s' '$INV' > $RDIR/inv.txt; chmod 600 $RDIR/inv.txt" 90 >/dev/null
  rsh "setsid nohup bash -c 'ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=debug $RBIN join $RDIR/inv.txt --yes; ip netns exec srp env FILAMENT_CONFIG_DIR=$RDIR FILAMENT_LOG=debug $RBIN up' >$RDIR/up.log 2>&1 & echo started" 90 >/dev/null
  local J=0 i
  for i in $(seq 1 25); do
    J=$(rsh "grep -c 'joined as' $RDIR/up.log 2>/dev/null || echo 0" 60 | tail -1)
    [ "${J:-0}" != "0" ] && break; sleep 6
  done
  [ "${J:-0}" != "0" ] || { bad "device never joined in '$label'"; return 1; }

  local before; before=$(peer_expiry)
  local dev; dev=$(own devices 2>&1 | grep -oE '[A-Za-z0-9][A-Za-z0-9._-]*\.trouble-free\.net' | head -1)
  echo "  joined as ${dev:-<none>}, certificate expires at $before"

  if [ "$revoke" = "yes" ]; then
    own revoke "$dev" --certificate --yes 2>&1 | tail -1
    echo "  certificate revoked on the owner"
  fi

  # Past the two-thirds point, plus room for the 30s renewal tick. No restart:
  # the link stays up the whole time, which is the case under test.
  local wait_s=$(( TTL * 2 / 3 + 70 ))
  echo "  holding the link for ${wait_s}s, past the renewal point"
  sleep "$wait_s"
  local after; after=$(peer_expiry)
  echo "  expiry before: $before   after: $after"

  if [ "$expect" = "renew" ]; then
    if [ "${after:-0}" -gt "${before:-0}" ] 2>/dev/null; then
      ok "renewed on a live link, extended by $(( after - before ))s"
      RENEWED_FROM=$before; RENEWED_TO=$after
    else
      bad "did NOT renew; a connected device is still on a timer to fall out"
    fi
    local life
    life=$(rsh "python3 -c \"import json;c=json.load(open('$RDIR/identity/device-cert.json'))['cert'];print(c['expires']-c['issued'])\" 2>/dev/null || echo 0" 90 | tail -1)
    if [ "${life:-0}" -le "$(( TTL + 5 ))" ] && [ "${life:-0}" -gt 0 ] 2>/dev/null; then
      ok "kept the granted ${TTL}s lifetime (got ${life}s) instead of widening to the default"
    else
      bad "lifetime became ${life}s; a short-lived guest just became a member"
    fi
  else
    if [ "${after:-0}" -eq "${before:-0}" ] 2>/dev/null; then
      ok "revoked device was refused; it will expire, which is how removal works"
    else
      bad "a REVOKED device renewed anyway; nothing can evict a device"
    fi
  fi
  echo "  owner-side decisions:"
  grep -E "cert renewal refused|renewed certificate" "$W/o.log" | tail -2 | sed 's/^/    /' || true
}

case "${ARMS:-both}" in
  good)   run_arm no  renew  "GOOD STANDING (expect renewal)" ;;
  revoked) run_arm yes refuse "REVOKED (expect refusal)" ;;
  *)      run_arm no  renew  "GOOD STANDING (expect renewal)"
          run_arm yes refuse "REVOKED (expect refusal)" ;;
esac

say "RESULT"
if [ "$FAIL" = "0" ]; then
  echo "  ALL CHECKS PASSED"
  echo "  in good standing: ${RENEWED_FROM:-?} -> ${RENEWED_TO:-?}, renewed on a live link"
  echo "  after revoke:     unchanged, left to expire"
  echo "  Two real machines, same code; only the owner's decision differs."
else
  echo "  SOME CHECKS FAILED"
  echo "  --- owner log:"; tail -15 "$W/o.log" | sed 's/^/  /'
  echo "  --- device log:"; rsh "grep -E 'renew|cert' $RDIR/up.log | tail -12" 90 | sed 's/^/  /'
fi
exit "$FAIL"
