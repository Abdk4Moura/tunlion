#!/usr/bin/env bash
# A code pairing delivers each side's device certificate (identity-expose), or
# fails on both sides. Standalone, hermetic, fixture port 8197 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion [TUNLION_OLD_BIN=/path/to/0.9.1/tunlion] ./identity-expose-gates.sh
#
# Two machines that each ran `init` pair with a code, so both hold a device
# certificate and both send it. The binary must be built with
# `--features test-hooks`: TUNLION_TEST_DROP_IDENTITY_EXPOSE drops a side's
# first N identity-expose frames (or `all`), on a real relay.
#
# Gates:
#   E1  plain: each side holds the other's certificate
#   E2  the claimer's first 3 frames are lost: the certificate still lands
#   E3  every frame from the claimer is lost: BOTH sides fail, nothing stored,
#       and each says why (never "connected" without the certificate)
#   M1  new creator, 0.9.1 claimer: pairs exactly as before, both certificates
#   M2  0.9.1 creator, new claimer: the same
#   (M1/M2 need TUNLION_OLD_BIN, the cli-v0.9.1 release binary, sha256-checked
#   by the caller; skipped, and said so, without it.)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/debug/tunlion}"
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
OLD="${TUNLION_OLD_BIN:-}"
PORT=8197
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-iexp.XXXXXX")"
export TUNLION_NONINTERACTIVE=1

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
start_backend

# $1 dir, $2 name, $3 binary
mkid() {
  mkdir -p "$1"
  env TUNLION_CONFIG_DIR="$1" "$3" init --name "$2" --recovery-file "$1/rec.txt" --yes >/dev/null 2>&1 \
    || { echo "init $2 failed"; exit 2; }
}

# certExpires the device in config dir $1 holds for device $2 ("absent" when
# there is no record, "None" when the record has no certificate).
cert_of() {
  env TUNLION_CONFIG_DIR="$1" "$BIN" devices --json 2>/dev/null | python3 -c '
import json, sys
try:
    devs = json.load(sys.stdin)["data"]["devices"]
except Exception:
    print("absent"); sys.exit()
print(next((str(d.get("certExpires")) for d in devs if d["name"] == sys.argv[1]), "absent"))' "$2"
}

# One pairing. $1 tag, $2 creator dir, $3 creator bin, $4 claimer dir,
# $5 claimer bin, $6 claimer's extra env (or "-"), $7 grace secs.
# Sets RC_A, RC_B; logs in $WORK/$1-{a,b}.log.
pairing() {
  local tag=$1 da=$2 ba=$3 db=$4 bb=$5 envb=$6 grace=$7
  local words="violet-harbor-quantum"
  [ "$envb" = - ] && envb=""
  env TUNLION_CONFIG_DIR="$da" TUNLION_LOG=debug TUNLION_PAIR_GRACE_SECS="$grace" \
    timeout 120 "$ba" --server "$SERVER" add --for person --name "peer-$tag" --word "$words" \
    </dev/null >"$WORK/$tag-a.log" 2>&1 &
  local apid=$!
  local code=""
  for _ in $(seq 1 60); do
    code=$(grep -oE "using your words: [a-z0-9-]+" "$WORK/$tag-a.log" 2>/dev/null | head -1 | awk '{print $4}' | tr -d '\033' | sed 's/\[[0-9;]*m//g')
    [ -n "$code" ] && grep -qiE "keep this window open|enter this code" "$WORK/$tag-a.log" && break
    sleep 0.5
  done
  if [ -z "$code" ]; then echo "## $tag: no code"; tail -5 "$WORK/$tag-a.log"; RC_A=99; RC_B=99; kill $apid 2>/dev/null; return; fi
  local t0; t0=$(date +%s.%N)
  env TUNLION_CONFIG_DIR="$db" TUNLION_LOG=debug TUNLION_PAIR_GRACE_SECS="$grace" $envb \
    timeout 120 "$bb" --server "$SERVER" join "$code" --name "peer-$tag" </dev/null >"$WORK/$tag-b.log" 2>&1
  RC_B=$?
  local tb; tb=$(date +%s.%N)
  wait $apid; RC_A=$?
  local ta; ta=$(date +%s.%N)
  echo "## $tag: code $code, creator rc=$RC_A, claimer rc=$RC_B, claimer took $(awk "BEGIN{printf \"%.1f\", $tb - $t0}")s, creator done $(awk "BEGIN{printf \"%.1f\", $ta - $t0}")s after the join started"
}

show() { echo "--- $1 creator"; grep -vE "^\s*$" "$WORK/$1-a.log" | grep -viE "ice|candidate" | tail -n 8; echo "--- $1 claimer"; grep -vE "^\s*$" "$WORK/$1-b.log" | grep -viE "ice|candidate" | tail -n 8; }

# ------------------------------------------------------------------ E1 --
say "E1: two certified devices pair by code and each holds the other's certificate"
mkid "$WORK/a1" ana "$BIN"; mkid "$WORK/b1" ben "$BIN"
pairing e1 "$WORK/a1" "$BIN" "$WORK/b1" "$BIN" - 60
ca=$(cert_of "$WORK/a1" peer-e1); cb=$(cert_of "$WORK/b1" peer-e1)
acks=$(grep -c "identity-expose acknowledged" "$WORK/e1-a.log" "$WORK/e1-b.log" | awk -F: '{s+=$2} END{print s}')
echo "## creator holds $ca, claimer holds $cb, acknowledgements seen: $acks"
if [ "$RC_A" = 0 ] && [ "$RC_B" = 0 ] && [ "$ca" != absent ] && [ "$ca" != None ] && [ "$cb" != absent ] && [ "$cb" != None ] && [ "$acks" -ge 2 ]; then
  ok "E1: both certificates delivered and acknowledged"
else
  bad "E1 plain pairing"; show e1
fi

# ------------------------------------------------------------------ E2 --
say "E2: the claimer's first 3 identity-expose frames are lost; its certificate still lands"
mkid "$WORK/a2" ana "$BIN"; mkid "$WORK/b2" ben "$BIN"
pairing e2 "$WORK/a2" "$BIN" "$WORK/b2" "$BIN" "TUNLION_TEST_DROP_IDENTITY_EXPOSE=3" 60
ca=$(cert_of "$WORK/a2" peer-e2); cb=$(cert_of "$WORK/b2" peer-e2)
dropped=$(grep -c "dropped by the test hook" "$WORK/e2-b.log")
echo "## creator holds $ca, claimer holds $cb, frames dropped: $dropped"
if [ "$RC_A" = 0 ] && [ "$RC_B" = 0 ] && [ "$ca" != absent ] && [ "$ca" != None ] && [ "$cb" != None ] && [ "$dropped" = 3 ]; then
  ok "E2: 3 frames lost, the certificate landed on the 4th copy"
else
  bad "E2 lost first frames"; show e2
  [ "$dropped" = 0 ] && echo "## no frame was dropped: $BIN was built without --features test-hooks" 
fi

# ------------------------------------------------------------------ E3 --
say "E3: every identity-expose frame from the claimer is lost; both sides fail"
mkid "$WORK/a3" ana "$BIN"; mkid "$WORK/b3" ben "$BIN"
pairing e3 "$WORK/a3" "$BIN" "$WORK/b3" "$BIN" "TUNLION_TEST_DROP_IDENTITY_EXPOSE=all" 15
ca=$(cert_of "$WORK/a3" peer-e3); cb=$(cert_of "$WORK/b3" peer-e3)
said_a=$(grep -c "said it would send its device certificate, and it never arrived" "$WORK/e3-a.log")
said_b=$(grep -c "never confirmed it received this device's certificate" "$WORK/e3-b.log")
connected=$(grep -ciE "connected .{0,12}(remembered|your devices)" "$WORK/e3-a.log" "$WORK/e3-b.log" | awk -F: '{s+=$2} END{print s}')
echo "## creator rc=$RC_A holds '$ca', claimer rc=$RC_B holds '$cb', reasons: $said_a/$said_b, success lines: $connected"
if [ "$RC_A" != 0 ] && [ "$RC_B" != 0 ] && [ "$ca" = absent ] && [ "$cb" = absent ] && [ "$said_a" -ge 1 ] && [ "$said_b" -ge 1 ] && [ "$connected" = 0 ]; then
  ok "E3: both sides failed, said why, and stored nothing"
else
  bad "E3 total loss"; show e3
fi

# ------------------------------------------------------------- M1 / M2 --
if [ -z "$OLD" ] || [ ! -x "$OLD" ]; then
  echo "SKIP: M1/M2 need TUNLION_OLD_BIN (the cli-v0.9.1 release binary)"
else
  say "M1: new creator, 0.9.1 claimer ($("$OLD" --version 2>&1 | head -1))"
  mkid "$WORK/a4" ana "$BIN"; mkid "$WORK/b4" ben "$OLD"
  pairing m1 "$WORK/a4" "$BIN" "$WORK/b4" "$OLD" - 60
  ca=$(cert_of "$WORK/a4" peer-m1); cb=$(env TUNLION_CONFIG_DIR="$WORK/b4" "$OLD" devices --json 2>/dev/null | python3 -c 'import json,sys; print(next((str(d.get("certExpires")) for d in json.load(sys.stdin)["data"]["devices"] if d["name"]=="peer-m1"), "absent"))')
  noack=$(grep -c "peer does not acknowledge" "$WORK/m1-a.log")
  echo "## creator holds $ca, 0.9.1 claimer holds $cb, sent the old way: $noack"
  if [ "$RC_A" = 0 ] && [ "$RC_B" = 0 ] && [ "$ca" != absent ] && [ "$ca" != None ] && [ "$cb" != absent ] && [ "$cb" != None ] && [ "$noack" = 1 ]; then
    ok "M1: a 0.9.1 claimer pairs as before, both certificates held"
  else
    bad "M1 mixed new/0.9.1"; show m1
  fi

  say "M2: 0.9.1 creator, new claimer"
  mkid "$WORK/a5" ana "$OLD"; mkid "$WORK/b5" ben "$BIN"
  pairing m2 "$WORK/a5" "$OLD" "$WORK/b5" "$BIN" - 60
  ca=$(env TUNLION_CONFIG_DIR="$WORK/a5" "$OLD" devices --json 2>/dev/null | python3 -c 'import json,sys; print(next((str(d.get("certExpires")) for d in json.load(sys.stdin)["data"]["devices"] if d["name"]=="peer-m2"), "absent"))')
  cb=$(cert_of "$WORK/b5" peer-m2)
  noack=$(grep -c "peer does not acknowledge" "$WORK/m2-b.log")
  echo "## 0.9.1 creator holds $ca, claimer holds $cb, sent the old way: $noack"
  if [ "$RC_A" = 0 ] && [ "$RC_B" = 0 ] && [ "$ca" != absent ] && [ "$ca" != None ] && [ "$cb" != absent ] && [ "$cb" != None ] && [ "$noack" = 1 ]; then
    ok "M2: a 0.9.1 creator pairs as before, both certificates held"
  else
    bad "M2 mixed 0.9.1/new"; show m2
  fi
fi

echo
echo "== identity-expose gates: $PASS passed, $FAIL failed =="
[ "$FAIL" = "0" ]
