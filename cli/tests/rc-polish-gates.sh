#!/usr/bin/env bash
# RC polish gates: what the final lab verification of the release candidate
# (build 3189897) met driving the real CLI. Each gate drives the real binary
# against a local signaling server and asserts the user-visible property.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/rc-polish-gates.sh
#
# Gates:
#   U  argument-shape errors exit 2, not 1: `forward w2-a`, a bare `reach`,
#      `forward w2-a:notaport` (item 4).
#   N  `up` and `up --detach` on a device with no identity and nothing paired
#      exit 9 and name `tunlion init`, starting nothing; a device with only a
#      code-paired device still runs the receive-only daemon (item 5).
#   A  `add z` on a device with no identity exits 9, names `tunlion init`, and
#      writes no identity (it used to mint one with no recovery phrase) (item 6).
#   M  `send --remember x` to a receiver that does not remember prints one
#      outcome: never "remembered this device as" next to "declined", and no
#      "identity challenge NOT answered" from a sender with no identity (item 7).
#   R  `receive <code>` from an unrelated sender while one of the receiver's
#      known devices is online names only the sender: no "known device ...
#      appeared", no raw signaling id, one roster line (item 3).
#   S  the default signaling server is api.tunlion.autumated.com (item 10).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8174
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-rcpolish.XXXXXX")"
export TUNLION_NONINTERACTIVE=1

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

start_backend

# $1 = config dir, rest = args
t() { local d="$1"; shift; env TUNLION_CONFIG_DIR="$d" "$BIN" --server "$SERVER" "$@"; }
# A session-id-shaped token: 20 base64url characters mixing cases.
sid_like() { grep -oE '\b[A-Za-z0-9_-]{20}\b' "$1" | grep '[A-Z]' | grep '[a-z]' | grep -E '[A-Z].*[A-Z].*[A-Z]' | head -1; }

# ---------------------------------------------------------------------- U --
say "U: argument-shape errors exit 2"
DU="$WORK/u"; mkdir -p "$DU"
t "$DU" forward w2-a >"$WORK/u1.log" 2>&1; r1=$?
t "$DU" reach >"$WORK/u2.log" 2>&1; r2=$?
t "$DU" forward w2-a:notaport >"$WORK/u3.log" 2>&1; r3=$?
echo "## forward w2-a rc=$r1, reach rc=$r2, forward w2-a:notaport rc=$r3"
if [ "$r1" = 2 ] && [ "$r2" = 2 ] && [ "$r3" = 2 ] \
   && grep -q "forward needs <device>:<port>" "$WORK/u1.log" && grep -q "reach needs a device" "$WORK/u2.log"; then
  ok "U: forward without a port, a bare reach and a non-numeric port exit 2 with the usage line"
else
  bad "U usage exits (rc $r1/$r2/$r3)"; cat "$WORK/u1.log" "$WORK/u2.log" "$WORK/u3.log"
fi

# ---------------------------------------------------------------------- N --
say "N: up with no identity and nothing paired exits 9; a code-paired device still serves"
DN="$WORK/n"; mkdir -p "$DN"
timeout 30 env TUNLION_CONFIG_DIR="$DN" "$BIN" --server "$SERVER" up --detach --dir "$WORK/n-drop" >"$WORK/n1.log" 2>&1; rn1=$?
timeout 30 env TUNLION_CONFIG_DIR="$DN" "$BIN" --server "$SERVER" up --dir "$WORK/n-drop" </dev/null >"$WORK/n2.log" 2>&1; rn2=$?
# Control: only a code-paired device, no identity. This is the receive-only
# daemon every pair-secret gate runs, and it must still start.
DP="$WORK/np"; mkdir -p "$DP"
printf '[{"name":"peer","secret":"%s"}]\n' "$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$DP/devices.json"
timeout 40 env TUNLION_CONFIG_DIR="$DP" "$BIN" --server "$SERVER" up --detach --dir "$WORK/np-drop" >"$WORK/n3.log" 2>&1; rn3=$?
PPID3=$(cat "$DP/up.pid" 2>/dev/null)
env TUNLION_CONFIG_DIR="$DP" "$BIN" down -y >/dev/null 2>&1
[ -n "$PPID3" ] && kill "$PPID3" 2>/dev/null
echo "## up --detach rc=$rn1, up rc=$rn2, control (paired, no identity) rc=$rn3 pid=${PPID3:-none}"
if [ "$rn1" = 9 ] && [ "$rn2" = 9 ] && grep -q "tunlion init" "$WORK/n1.log" && grep -q "tunlion init" "$WORK/n2.log" \
   && [ ! -e "$DN/up.pid" ] && [ "$rn3" = 0 ] && [ -n "$PPID3" ]; then
  ok "N: up and up --detach with no identity and nothing paired exit 9 naming init; a code-paired device's up --detach still runs"
else
  bad "N up without identity (rc $rn1/$rn2, control $rn3)"; cat "$WORK/n1.log" "$WORK/n2.log"; tail -n 5 "$WORK/n3.log"
fi

# ---------------------------------------------------------------------- A --
say "A: add on a device with no identity exits 9 and mints nothing"
DA_="$WORK/a"; mkdir -p "$DA_"
t "$DA_" add z >"$WORK/a1.log" 2>&1; ra=$?
t "$DA_" add z --out "$WORK/z-inv.txt" --yes >"$WORK/a2.log" 2>&1; ra2=$?
echo "## add z rc=$ra, add z --out rc=$ra2"; cat "$WORK/a1.log"
if [ "$ra" = 9 ] && [ "$ra2" = 9 ] && grep -q "tunlion init" "$WORK/a1.log" \
   && ! grep -q "created your identity" "$WORK/a1.log" "$WORK/a2.log" \
   && [ ! -e "$DA_/identity.ed25519" ] && [ ! -e "$WORK/z-inv.txt" ]; then
  ok "A: add with no identity exits 9, names tunlion init, and writes no identity or invitation"
else
  bad "A add without identity (rc $ra/$ra2)"; ls -la "$DA_"; cat "$WORK/a2.log"
fi

# ---------------------------------------------------------------------- M --
say "M: send --remember to a receiver that does not remember says one outcome"
DMS="$WORK/ms"; DMR="$WORK/mr"; mkdir -p "$DMS" "$DMR" "$WORK/mr-drop"
echo "remember me $$" >"$WORK/m.txt"
timeout 90 env TUNLION_CONFIG_DIR="$DMS" "$BIN" --server "$SERVER" send "$WORK/m.txt" --word gigantic-element --remember x \
  </dev/null >"$WORK/m-send.log" 2>&1 &
MP=$!; FIX_PIDS+=($MP)
MC=""
for _ in $(seq 1 60); do MC=$(grep -oiE 'gigantic-element-[0-9]{3,5}' "$WORK/m-send.log" | head -1); [ -n "$MC" ] && break; sleep 0.3; done
if [ -n "$MC" ]; then
  timeout 60 env TUNLION_CONFIG_DIR="$DMR" "$BIN" --server "$SERVER" receive "$MC" -y --dir "$WORK/mr-drop" </dev/null >"$WORK/m-recv.log" 2>&1
fi
wait $MP; rm_=$?
echo "## send rc=$rm_ code=$MC"; cat "$WORK/m-send.log"
if [ "$rm_" = 0 ] && [ -f "$WORK/mr-drop/m.txt" ] \
   && ! grep -q "remembered this device as" "$WORK/m-send.log" \
   && grep -qE "declined to be remembered|nothing was remembered" "$WORK/m-send.log" \
   && ! grep -q "identity challenge NOT answered" "$WORK/m-send.log" "$WORK/m-recv.log"; then
  ok "M: a declined --remember prints only that nothing was stored, and no identity-challenge noise from a device with no identity"
else
  bad "M remember outcome (rc $rm_)"; cat "$WORK/m-recv.log"
fi

# ---------------------------------------------------------------------- R --
say "R: a code receive names only its sender while a known device is online"
DR="$WORK/r"; DK="$WORK/k"; DS="$WORK/s"; mkdir -p "$DR" "$DK" "$DS" "$WORK/r-drop" "$WORK/k-drop"
# R and K pair by code (no identity on either: an ordinary pairing).
timeout 90 env TUNLION_CONFIG_DIR="$DR" "$BIN" --server "$SERVER" add --name kdev --word quiet-harbor >"$WORK/r-add.log" 2>&1 &
RA=$!; FIX_PIDS+=($RA)
RC_=""
for _ in $(seq 1 60); do RC_=$(grep -oiE 'quiet-harbor-[0-9]{3,5}' "$WORK/r-add.log" | head -1); [ -n "$RC_" ] && break; sleep 0.3; done
[ -n "$RC_" ] && timeout 90 env TUNLION_CONFIG_DIR="$DK" "$BIN" --server "$SERVER" join "$RC_" --name rdev >"$WORK/k-join.log" 2>&1
wait $RA; rpair=$?
# K's daemon online, so a receiver subscribed to its known devices would see it.
env TUNLION_CONFIG_DIR="$DK" "$BIN" --server "$SERVER" up --dir "$WORK/k-drop" </dev/null >"$WORK/k-up.log" 2>&1 &
KP=$!; FIX_PIDS+=($KP)
sleep 4
echo "from an unrelated sender $$" >"$WORK/r.txt"
timeout 90 env TUNLION_CONFIG_DIR="$DS" "$BIN" --server "$SERVER" send "$WORK/r.txt" --word brave-otter \
  </dev/null >"$WORK/r-send.log" 2>&1 &
SP=$!; FIX_PIDS+=($SP)
SC=""
for _ in $(seq 1 60); do SC=$(grep -oiE 'brave-otter-[0-9]{3,5}' "$WORK/r-send.log" | head -1); [ -n "$SC" ] && break; sleep 0.3; done
[ -n "$SC" ] && timeout 60 env TUNLION_CONFIG_DIR="$DR" "$BIN" --server "$SERVER" receive "$SC" -y --dir "$WORK/r-drop" \
  </dev/null >"$WORK/r-recv.log" 2>&1
rr=$?
wait $SP 2>/dev/null
kill $KP 2>/dev/null
SID=$(sid_like "$WORK/r-recv.log")
echo "## pairing rc=$rpair, receive rc=$rr, sid-like token: '${SID}'"; cat "$WORK/r-recv.log"
if [ "$rpair" = 0 ] && [ "$rr" = 0 ] && [ -f "$WORK/r-drop/r.txt" ] \
   && ! grep -q "known device" "$WORK/r-recv.log" && ! grep -q "kdev" "$WORK/r-recv.log" && [ -z "$SID" ]; then
  ok "R: the code receive dialed no known device, named no one but its sender, and printed no raw id"
else
  bad "R code receive with a known device online (pair $rpair, rc $rr)"; tail -n 5 "$WORK/r-add.log" "$WORK/k-join.log"
fi

# ---------------------------------------------------------------------- S --
say "S: the default signaling server"
env -u TUNLION_SERVER "$BIN" --help >"$WORK/help.txt" 2>&1
if grep -q "api.tunlion.autumated.com" "$WORK/help.txt" && ! grep -q "api.filament.autumated.com" "$WORK/help.txt"; then
  ok "S: --help names https://api.tunlion.autumated.com as the default server"
else
  bad "S default server"; grep -n "server" "$WORK/help.txt" | head
fi

echo
echo "== rc-polish gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
