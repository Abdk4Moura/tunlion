#!/usr/bin/env bash
# State-change UX gates: what a blind evaluator met driving the real CLI on
# three lab containers (build f0043f7). Each gate drives the real binary and
# asserts the user-visible property, against a local signaling server.
#
#   TUNLION_BIN=/path/to/tunlion bash cli/tests/state-ux-gates.sh
#
# Gates:
#   R1 `send --remember x` with no code is refused (exit 2) and names the
#      command that pairs for good, instead of being silently ignored.
#   R2 `receive --remember x` with no code and no terminal is refused (exit 2).
#   K  runner keys have ONE claim verb: `ephemeral enroll` is gone and --help
#      names `tunlion join <file>` on the runner row.
#   F1 forget, then a fresh `add` + `join` of the same device: the owner says
#      the add re-admits it, and the forget's key block is lifted (it used to
#      print "joined your fleet" while every send was declined "device revoked").
#   P  `add --for person --name <one of my devices>` is refused with the reason
#      before any code is minted (it silently re-enrolled it as fleet).
#   F2 `devices restore` of a FORGOTTEN device lifts the key block and says to
#      re-add it; restore of a name nobody had exits 3.
#   X  a `--for person` pairing between two identities prints no "filed as
#      EXTERNAL ... reset" warning on either side: EXTERNAL is what was asked.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
PORT=8171
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-stateux.XXXXXX")"
export TUNLION_NONINTERACTIVE=1

PASS=0; FAIL=0; FAILED=""
say() { printf '\n\033[1m== state-ux gate %s ==\033[0m\n' "$*"; }
ok()  { echo "PASS: $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL+1)); FAILED="$FAILED|$1"; }

pids=()
cleanup() { for p in "${pids[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null; done; true; }
trap cleanup EXIT

[ -x "$BIN" ] || { echo "build first: (cd $CLI_DIR && cargo build --release)"; exit 2; }

for pid in $(ss -tlnp 2>/dev/null | grep ":$PORT " | grep -oP 'pid=\K[0-9]+' | sort -u); do kill "$pid" 2>/dev/null; done
sleep 1
( cd "$CLI_DIR/../backend" && PORT=$PORT FIL_ASYNC_MODE=eventlet FIL_SELF_MONKEYPATCH=1 \
    FIL_CLAIM_LIMIT=1000000 FIL_PING_TIMEOUT=120 FIL_PING_INTERVAL=25 \
    "$PYV" app.py >"$WORK/backend.log" 2>&1 ) &
pids+=($!)
for _ in $(seq 1 30); do curl -fsS "$SERVER/api/health" >/dev/null 2>&1 && break; sleep 0.5; done

# $1 = config dir, rest = args
t() { local d="$1"; shift; env TUNLION_CONFIG_DIR="$d" "$BIN" --server "$SERVER" "$@"; }

# Pair by code: $1 = offering dir, $2 = accepting dir, $3 = log tag, $4 = name
# the accepting side files the offerer under; the rest are `add` arguments.
# Leaves the two logs in $WORK/<tag>-add.log and $WORK/<tag>-join.log.
pair() {
  local a="$1" b="$2" tag="$3" asname="$4"; shift 4
  timeout 120 env TUNLION_CONFIG_DIR="$a" "$BIN" --server "$SERVER" add "$@" --word "gigantic-element" >"$WORK/$tag-add.log" 2>&1 &
  local ap=$!; pids+=($ap)
  local code="" i
  for i in $(seq 1 60); do
    code=$(grep -oiE 'gigantic-element-[0-9]{3,5}' "$WORK/$tag-add.log" | head -1)
    [ -n "$code" ] && break
    sleep 0.3
  done
  [ -n "$code" ] || { echo "  no code minted:"; tail -n 5 "$WORK/$tag-add.log"; kill $ap 2>/dev/null; return 1; }
  timeout 90 env TUNLION_CONFIG_DIR="$b" "$BIN" --server "$SERVER" join "$code" --name "$asname" \
    >"$WORK/$tag-join.log" 2>&1
  local jr=$?
  wait $ap; local ar=$?
  PAIR_RC="$ar/$jr"
  [ $ar -eq 0 ] && [ $jr -eq 0 ]
}

# Entries in a config dir's revoked-keys.json recorded under name $2.
revoked_named() {
  python3 - "$1/revoked-keys.json" "$2" <<'EOF'
import json, sys
try:
    entries = json.load(open(sys.argv[1]))
except FileNotFoundError:
    entries = []
print(sum(1 for e in entries if (e.get("name") or "").lower() == sys.argv[2].lower()))
EOF
}

OWN="$WORK/owner"; DEV="$WORK/dev"; PER="$WORK/person"; mkdir -p "$OWN" "$DEV" "$PER"

# ------------------------------------------------------------------ R1/R2 --
say "R1/R2: --remember is refused where it cannot apply, never ignored"
echo hello >"$WORK/f.txt"
t "$WORK/r" send "$WORK/f.txt" --remember laptop </dev/null >"$WORK/r1.log" 2>&1; R1=$?
if [ $R1 -eq 2 ] && grep -q -- "--remember laptop" "$WORK/r1.log" && grep -q "tunlion add laptop" "$WORK/r1.log"; then
  ok "R1: send --remember with no code is refused (exit 2) and names tunlion add"
else bad "R1 send --remember without a code (rc=$R1)"; tail -n 5 "$WORK/r1.log"; fi
t "$WORK/r" receive --remember laptop --dir "$WORK/r" </dev/null >"$WORK/r2.log" 2>&1; R2=$?
if [ $R2 -eq 2 ] && grep -q "receive <code> --remember laptop" "$WORK/r2.log"; then
  ok "R2: receive --remember with no code and no terminal is refused (exit 2)"
else bad "R2 receive --remember without a code (rc=$R2)"; tail -n 5 "$WORK/r2.log"; fi

# ---------------------------------------------------------------------- K --
say "K: runner keys have one claim verb"
"$BIN" ephemeral enroll --auth-key-file "$WORK/none" >"$WORK/k1.log" 2>&1; K1=$?
"$BIN" --help >"$WORK/k2.log" 2>&1
if [ $K1 -eq 2 ] && grep -q "add --for runner.*tunlion join <file>" "$WORK/k2.log" \
   && ! grep -q "ephemeral enroll" "$WORK/k2.log"; then
  ok "K: help names tunlion join <file> for runner keys; ephemeral enroll is not a verb"
else bad "K runner claim verb (rc=$K1)"; grep -n "runner\|ephemeral" "$WORK/k2.log"; fi

# --------------------------------------------------------------------- F1 --
say "F1: a forgotten device added again is re-admitted, and told so"
t "$OWN" init --name own --recovery-file "$OWN/rec.txt" --no-background --yes >"$WORK/init-own.log" 2>&1
if pair "$OWN" "$DEV" f1a own d1; then
  t "$OWN" devices forget d1 -y >"$WORK/f1-forget.log" 2>&1
  BEFORE=$(revoked_named "$OWN" d1)
  if pair "$OWN" "$DEV" f1b own d1; then
    AFTER=$(revoked_named "$OWN" d1)
    t "$OWN" devices --caps d1 >"$WORK/f1-caps.log" 2>&1
    if [ "$BEFORE" -ge 1 ] && [ "$AFTER" -eq 0 ] \
       && grep -q "was forgotten on" "$WORK/f1b-add.log" && grep -q "re-admits it" "$WORK/f1b-add.log" \
       && ! grep -q "device revoked" "$WORK/f1-caps.log"; then
      ok "F1: re-adding a forgotten device lifts its key block (blocks $BEFORE -> $AFTER) and says it re-admits it"
    else
      bad "F1 re-add after forget (blocks $BEFORE -> $AFTER)"
      tail -n 8 "$WORK/f1b-add.log"; cat "$WORK/f1-caps.log"
    fi
  else bad "F1 re-add pairing ($PAIR_RC)"; tail -n 5 "$WORK/f1b-add.log" "$WORK/f1b-join.log"; fi
else bad "F1 first pairing ($PAIR_RC)"; tail -n 5 "$WORK/f1a-add.log" "$WORK/f1a-join.log"; fi

# ---------------------------------------------------------------------- P --
say "P: --for person cannot name one of your own devices"
t "$OWN" add --for person --name d1 --word "gigantic-element" </dev/null >"$WORK/p.log" 2>&1; PR=$?
if [ $PR -eq 2 ] && grep -q "already one of your devices" "$WORK/p.log" \
   && ! grep -qiE 'gigantic-element-[0-9]{3,5}' "$WORK/p.log"; then
  ok "P: add --for person naming an own device is refused with the reason, no code minted"
else bad "P person names own device (rc=$PR)"; tail -n 5 "$WORK/p.log"; fi

# --------------------------------------------------------------------- F2 --
say "F2: devices restore lifts a forget's key block"
t "$OWN" devices forget d1 -y >"$WORK/f2-forget.log" 2>&1
B2=$(revoked_named "$OWN" d1)
t "$OWN" devices restore d1 >"$WORK/f2-restore.log" 2>&1; F2R=$?
A2=$(revoked_named "$OWN" d1)
t "$OWN" devices restore nobody-here >"$WORK/f2-none.log" 2>&1; F2N=$?
if [ "$B2" -ge 1 ] && [ "$A2" -eq 0 ] && [ $F2R -eq 0 ] \
   && grep -q "tunlion add d1" "$WORK/f2-restore.log" && [ $F2N -eq 3 ]; then
  ok "F2: restore of a forgotten device lifted its block ($B2 -> $A2) and named the re-add; an unknown name exits 3"
else bad "F2 restore after forget (blocks $B2 -> $A2, rc=$F2R, unknown rc=$F2N)"; cat "$WORK/f2-restore.log" "$WORK/f2-none.log"; fi

# ---------------------------------------------------------------------- X --
say "X: a person pairing between two identities warns neither side"
t "$PER" init --name per --recovery-file "$PER/rec.txt" --no-background --yes >"$WORK/init-per.log" 2>&1
if pair "$OWN" "$PER" x own --for person --name per; then
  if ! grep -q "filed as EXTERNAL" "$WORK/x-add.log" "$WORK/x-join.log"; then
    ok "X: --for person pairing prints no EXTERNAL warning on either side"
  else bad "X person pairing warned EXTERNAL"; grep -n "EXTERNAL" "$WORK/x-add.log" "$WORK/x-join.log"; fi
else bad "X person pairing ($PAIR_RC)"; tail -n 5 "$WORK/x-add.log" "$WORK/x-join.log"; fi

echo
echo "state-ux gates: $PASS passed, $FAIL failed${FAILED:+ ($FAILED)}"
[ "$FAIL" -eq 0 ]
