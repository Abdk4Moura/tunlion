#!/usr/bin/env bash
# Identity and re-link gates: an enrolled device keeps its identity, and the
# way back after a reset is a chain of commands that all succeed.
# Standalone, hermetic, fixture port 8141 ONLY.
#
#   FILAMENT_BIN=/path/to/tunlion bash cli/tests/identity-relink-gates.sh
#
# Gates:
#   I1a  a joined device with its daemon running, HOME unset: a scripted
#        `init --name bogus --recovery-file f --no-background -y` refuses, writes
#        no recovery file, and the device's identity and role are unchanged. It
#        used to print "identity created ... Setup complete", exit 0, and turn
#        the joined device into the owner of a new identity.
#   I1b  the same with the daemon stopped: still refused (an identity, not the
#        daemon, is the reason).
#   I2   the reset device re-joins under its old name and is stored as
#        `<name>-2`; a send to the old name prints the re-link chain; every
#        command in that chain, run exactly as printed, exits 0; afterwards the
#        old name is the new device (the name is reusable) and a send to it
#        lands. Before: `devices forget` refused for 30 days and `rename` said
#        the name already existed, so the printed chain was a dead end.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${FILAMENT_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8141
SERVER="http://127.0.0.1:$PORT"
PYV="${FILAMENT_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-relink.XXXXXX")"

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== identity-relink gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=()
cleanup() {
  for d in "$WORK"/A "$WORK"/p9b; do
    [ -d "$d" ] && FILAMENT_CONFIG_DIR="$d" timeout 10 "$BIN" down -y >/dev/null 2>&1
  done
  for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }
for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS "$SERVER/api/health" >/dev/null || { echo "no backend at $SERVER"; cat "$WORK/backend.log"; exit 2; }

A() { env FILAMENT_CONFIG_DIR="$WORK/A" timeout 60 "$BIN" --server "$SERVER" "$@" </dev/null; }
B() { env FILAMENT_CONFIG_DIR="$WORK/p9b" timeout 60 "$BIN" --server "$SERVER" "$@" </dev/null; }
# `id --json` reduced to "<identity> <role>", the two fields init must not change.
who() { "$PYV" -c 'import sys,json; d=json.load(sys.stdin); print(d.get("identity"), d.get("role"))' 2>/dev/null; }
# `devices --json` reduced to its sorted names (an array, or an envelope around one).
names() { "$PYV" -c '
import sys,json
d=json.load(sys.stdin)
if isinstance(d, dict):
    d = d.get("devices") or (d.get("data") or {}).get("devices") or []
print(" ".join(sorted(x["name"] for x in d)))' 2>/dev/null; }

mkdir -p "$WORK/A" "$WORK/p9b"
A init --name alpha --recovery-file "$WORK/A/rec.txt" --yes >/dev/null 2>&1 || { echo "init failed"; exit 2; }
A up --detach --dir "$WORK/Adrop" >"$WORK/upA.log" 2>&1 || { echo "owner daemon did not start"; cat "$WORK/upA.log"; exit 2; }
A add --for p9b --out "$WORK/inv1.txt" --yes >"$WORK/add1.log" 2>&1 || { echo "add failed"; cat "$WORK/add1.log"; exit 2; }
B join --invite-file "$WORK/inv1.txt" --name p9b --no-interactive >"$WORK/join1.log" 2>&1 \
  || { echo "join failed"; cat "$WORK/join1.log"; exit 2; }
B up --detach --dir "$WORK/Bdrop" >"$WORK/upB.log" 2>&1 || { echo "spoke daemon did not start"; cat "$WORK/upB.log"; exit 2; }
sleep 2

# ==================================================================== GATE I1 ==
say "I1a: init -y on a joined device with its daemon running refuses"
before=$(B id --json 2>/dev/null | who)
outI1=$(env -u HOME FILAMENT_CONFIG_DIR="$WORK/p9b" timeout 60 "$BIN" --server "$SERVER" \
  init --name bogus --recovery-file "$WORK/rec2" --no-background -y </dev/null 2>&1); rcI1=$?
after=$(B id --json 2>/dev/null | who)
echo "## rc=$rcI1 before=[$before] after=[$after] rec2 written: $([ -e "$WORK/rec2" ] && echo yes || echo no)"
echo "$outI1" | sed 's/^/    /'
case "$before" in *" joined-device") joined=yes ;; *) joined=no ;; esac
if [ "$rcI1" -ne 0 ] && [ "$joined" = yes ] && [ "$before" = "$after" ] && [ ! -e "$WORK/rec2" ] \
   && echo "$outI1" | grep -q "already joined" && echo "$outI1" | grep -q "tunlion reset" \
   && ! echo "$outI1" | grep -q "identity created"; then
  ok "gateI1a: init -y on a joined device (daemon up, HOME unset) refused, identity unchanged ($after)"
else
  bad "gateI1a: init -y on a joined device (rc=$rcI1, before=[$before], after=[$after])"
fi

say "I1b: the same with the daemon stopped still refuses"
B down -y >/dev/null 2>&1
outI1b=$(B init --name bogus --recovery-file "$WORK/rec3" --no-background -y 2>&1); rcI1b=$?
afterb=$(B id --json 2>/dev/null | who)
echo "## rc=$rcI1b after=[$afterb]"; echo "$outI1b" | head -2 | sed 's/^/    /'
if [ "$rcI1b" -ne 0 ] && [ "$afterb" = "$before" ] && [ ! -e "$WORK/rec3" ] && echo "$outI1b" | grep -q "already joined"; then
  ok "gateI1b: init -y on a joined device with no daemon refused, identity unchanged"
else
  bad "gateI1b: init -y on a joined device, daemon down (rc=$rcI1b, after=[$afterb])"
fi

# ==================================================================== GATE I2 ==
say "I2: after a reset, the printed re-link chain runs and the name is reusable"
B reset -y >"$WORK/reset.log" 2>&1 || { bad "gateI2: reset failed"; cat "$WORK/reset.log"; }
A add --for p9b --out "$WORK/inv2.txt" --yes >"$WORK/add2.log" 2>&1
B join --invite-file "$WORK/inv2.txt" --name p9b --no-interactive >"$WORK/join2.log" 2>&1
B up --detach --dir "$WORK/Bdrop" >"$WORK/upB2.log" 2>&1
sleep 3
names2=$(A devices --json 2>/dev/null | names)
echo "## owner's devices after the re-join: [$names2]"
echo "payload one" >"$WORK/one.txt"
outS=$(A send --to p9b "$WORK/one.txt" 2>&1); rcS=$?
echo "## send to the stale name: rc=$rcS"; echo "$outS" | tail -3 | sed 's/^/    /'
# The chain is every backticked `tunlion ...` command in the hint, in order.
mapfile -t chain < <(printf '%s\n' "$outS" | "$PYV" -c '
import sys
text = sys.stdin.read()
parts = text.split("`")[1::2]
for p in parts:
    if p.startswith("tunlion "):
        print(p)
')
chain_ok=yes; ran=0
for cmd in "${chain[@]}"; do
  read -r -a argv <<<"$cmd"
  out=$(A "${argv[@]:1}" 2>&1); rc=$?
  ran=$((ran+1))
  echo "## chain step $ran: $cmd -> rc=$rc"; echo "$out" | head -3 | sed 's/^/    /'
  [ "$rc" -eq 0 ] || chain_ok=no
done
sleep 2
names3=$(A devices --json 2>/dev/null | names)
echo "payload two" >"$WORK/two.txt"
outS2=$(A send --to p9b "$WORK/two.txt" 2>&1); rcS2=$?
sleep 1
landed=no; [ -f "$WORK/Bdrop/two.txt" ] && landed=yes
echo "## after the chain: devices=[$names3] send to p9b rc=$rcS2 landed=$landed"
echo "$outS2" | tail -2 | sed 's/^/    /'
if [ "$names2" = "p9b p9b-2" ] && [ "$rcS" -eq 6 ] && [ "$ran" -ge 2 ] && [ "$chain_ok" = yes ] \
   && printf '%s\n' "${chain[@]}" | grep -qx "tunlion devices rename p9b-2 p9b" \
   && [ "$names3" = "p9b" ] && [ "$rcS2" -eq 0 ] && [ "$landed" = yes ]; then
  ok "gateI2: the re-link chain ($ran commands) ran clean and p9b is the re-joined device again"
else
  bad "gateI2: re-link chain (devices before=[$names2] after=[$names3], send rc=$rcS, chain ok=$chain_ok/$ran, resend rc=$rcS2 landed=$landed)"
fi

# ========================================================================= sum =
echo
echo "==========================================="
echo "identity-relink gates: $PASS passed, $FAIL failed${FAILED:+ - failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
