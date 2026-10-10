#!/usr/bin/env bash
# The mesh name responder (fdf1:1af7:c30d::53), end to end with real daemons.
# Standalone, hermetic, fixture port 8131 ONLY. Needs passwordless sudo for ONE
# step: granting CAP_NET_ADMIN to a private copy of the binary, which is the
# product's own unprivileged-kernel-TUN path (`tunlion init` asks for the same
# grant). FILAMENT_BIN=/path/to/tunlion ./mesh-dns-gates.sh
#
# Topology: alpha (owner) on the userspace netstack, bravo (a joined device) on
# the KERNEL TUN, both on this host, linked through the fixture backend.
#
#   A  a real resolver asking over a real packet: `dig @fdf1:1af7:c30d::53
#      <alpha>.mesh AAAA` on bravo's host returns alpha's overlay address. The
#      query leaves dig, is routed by the kernel into filament0, and is answered
#      from bravo's TUN loop with no socket and no port-53 privilege.
#   B  `tunlion dns query` against bravo's daemon gives the same answer.
#   C  the USERSPACE daemon (no packet can reach a responder there) answers
#      `tunlion dns query <bravo> --type AAAA` with bravo's overlay address.
#   D  an unknown name under the suffix is NXDOMAIN, with the zone SOA.
#   E  a name outside the mesh zones is REFUSED: never recursed, never forwarded.
#   F  the reverse zone: `dig -x <alpha v6>` names alpha.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8131
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-meshdns.XXXXXX")"
DA="$WORK/A"
DB="$WORK/bravo"
RESP="fdf1:1af7:c30d::53"

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

command -v dig >/dev/null || { echo "dig is missing: install dnsutils"; exit 2; }

start_backend
init_owner "$DA"
# alpha stays on the userspace netstack whatever this host allows, so exactly
# one daemon here owns the kernel device.
FILAMENT_L3_USERSPACE=1 start_acceptor "$DA"
enroll_delegate bravo

# A private copy, so the capability never leaks into another gate's daemons.
# Beside the build output rather than under /tmp, which may be mounted nosuid
# (file capabilities are ignored there).
KBIN="$(dirname "$BIN")/tunlion-meshdns-gate"
cp "$BIN" "$KBIN" || fixture_die "setup: could not copy the binary to $KBIN"
trap 'fixture_cleanup; rm -f "$KBIN"' EXIT
sudo -n setcap cap_net_admin+ep "$KBIN" \
  || fixture_die "setup: 'sudo setcap cap_net_admin+ep' failed; this gate needs passwordless sudo"

env FILAMENT_CONFIG_DIR="$DB" "$KBIN" --server "$SERVER" up --dir "$WORK/bravo-drop" \
  >"$WORK/up-bravo.log" 2>&1 &
FIX_PIDS+=($!)

# bravo must really be on the kernel TUN, or gate A would measure nothing.
for _ in $(seq 1 30); do
  grep -q "on filament0" "$WORK/up-bravo.log" 2>/dev/null && break
  grep -q "no kernel TUN" "$WORK/up-bravo.log" 2>/dev/null && break
  sleep 1
done
if ! grep -q "on filament0" "$WORK/up-bravo.log"; then
  echo "-- bravo up log --"; cat "$WORK/up-bravo.log"
  fixture_die "setup: bravo did not come up on the kernel TUN (filament0)"
fi
grep "resolves as" "$WORK/up-bravo.log" || true

A6=$(env FILAMENT_CONFIG_DIR="$DA" "$BIN" --json addr | python3 -c 'import json,sys;print(json.load(sys.stdin)["overlayV6"])')
B6=$(env FILAMENT_CONFIG_DIR="$DB" "$BIN" --json addr | python3 -c 'import json,sys;print(json.load(sys.stdin)["overlayV6"])')
echo "## alpha=$A6 bravo=$B6"
[ -n "$A6" ] && [ -n "$B6" ] || fixture_die "setup: could not read the overlay addresses"

# The name each daemon holds for the OTHER device, read from that daemon's own
# table (status --json -> mesh.names) by address, so the gate asserts the
# responder and not a naming convention. Waits for the L3 announce exchange.
name_for() {  # $1 = config dir, $2 = v6 address
  env FILAMENT_CONFIG_DIR="$1" "$BIN" --json status 2>/dev/null | python3 -c '
import json,sys
want=sys.argv[1]
try:
    d=json.load(sys.stdin)
except Exception:
    sys.exit(1)
for n in ((d.get("mesh") or {}).get("names") or []):
    if n.get("v6")==want and n.get("served_as"):
        print(n["served_as"]); sys.exit(0)
sys.exit(1)
' "$2"
}
A_AT_B=""; B_AT_A=""
for _ in $(seq 1 90); do
  [ -z "$A_AT_B" ] && A_AT_B=$(name_for "$DB" "$A6")
  [ -z "$B_AT_A" ] && B_AT_A=$(name_for "$DA" "$B6")
  [ -n "$A_AT_B" ] && [ -n "$B_AT_A" ] && break
  sleep 1
done
echo "## bravo serves alpha as '$A_AT_B'; alpha serves bravo as '$B_AT_A'"
if [ -z "$A_AT_B" ] || [ -z "$B_AT_A" ]; then
  echo "-- bravo status --"; env FILAMENT_CONFIG_DIR="$DB" "$BIN" --json status 2>&1 | tail -40
  echo "-- alpha status --"; env FILAMENT_CONFIG_DIR="$DA" "$BIN" --json status 2>&1 | tail -40
  echo "-- bravo up log --"; tail -40 "$WORK/up-bravo.log"
  fixture_die "setup: the two daemons never learned each other's overlay names"
fi

DIG=(dig "@$RESP" +time=2 +tries=2)

say "A: dig over a real packet to the responder"
got=$("${DIG[@]}" +short "$A_AT_B" AAAA 2>&1)
if [ "$got" = "$A6" ]; then
  ok "gateA: dig @$RESP $A_AT_B AAAA = alpha's overlay address ($A6)"
else
  "${DIG[@]}" "$A_AT_B" AAAA 2>&1 | tail -20
  bad "gateA: dig answered '$got', want '$A6'"
fi

say "B: tunlion dns query matches the wire"
fs_cli 20 env FILAMENT_CONFIG_DIR="$DB" "$BIN" dns query "$A_AT_B" --type AAAA
q=$(fs_out | grep -E '^[0-9a-f:]+$' | head -1)
if [ "$q" = "$A6" ] && [ "$q" = "$got" ]; then
  ok "gateB: tunlion dns query = dig = $A6"
else
  fs_out
  bad "gateB: tunlion dns query said '$q', dig said '$got', want '$A6'"
fi

say "C: the userspace daemon answers over the control socket"
fs_cli 20 env FILAMENT_CONFIG_DIR="$DA" "$BIN" dns query "$B_AT_A" --type AAAA
q=$(fs_out | grep -E '^[0-9a-f:]+$' | head -1)
if [ "$q" = "$B6" ]; then
  ok "gateC: userspace responder resolves $B_AT_A to bravo ($B6)"
else
  fs_out
  bad "gateC: userspace responder said '$q', want '$B6'"
fi

say "D: unknown name is NXDOMAIN with the zone SOA"
out=$("${DIG[@]}" nobody-here.mesh AAAA 2>&1)
if echo "$out" | grep -q "status: NXDOMAIN" && echo "$out" | grep -qE "^mesh\.[[:space:]].*SOA"; then
  ok "gateD: nobody-here.mesh -> NXDOMAIN + SOA"
else
  echo "$out"
  bad "gateD: unknown name was not NXDOMAIN with an SOA"
fi

say "E: outside the mesh zones is REFUSED, never forwarded"
out=$("${DIG[@]}" example.com A 2>&1)
if echo "$out" | grep -q "status: REFUSED" && ! echo "$out" | grep -q "ANSWER: [1-9]"; then
  ok "gateE: example.com -> REFUSED with no answer"
else
  echo "$out"
  bad "gateE: a name outside the zone was not REFUSED"
fi

say "F: reverse lookup in the overlay ip6.arpa zone"
ptr=$("${DIG[@]}" +short -x "$A6" 2>&1)
if [ "$ptr" = "$A_AT_B." ]; then
  ok "gateF: dig -x $A6 -> $ptr"
else
  "${DIG[@]}" -x "$A6" 2>&1 | tail -20
  bad "gateF: PTR answered '$ptr', want '$A_AT_B.'"
fi

echo
echo "mesh-dns gates: $PASS passed, $FAIL failed${FAILED:+ ($FAILED)}"
[ "$FAIL" -eq 0 ]
