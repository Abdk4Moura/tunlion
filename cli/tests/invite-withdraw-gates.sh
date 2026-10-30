#!/usr/bin/env bash
# An outstanding invitation can be SEEN and WITHDRAWN, and a withdrawn one is
# refused at claim time by the owner, durably.
# Standalone, hermetic, fixture port 8221 ONLY.
#
#   TUNLION_BIN=/path/to/tunlion ./invite-withdraw-gates.sh
#   TUNLION_V091_BIN=/path/to/tunlion-0.9.1   (optional; fetched otherwise)
#
# WHY THIS EXISTS. `tunlion add --for device --reuse 20 --expires 30d --out k`
# minted an invitation that stayed claimable until it expired or ran out of
# uses, with no way to list it and no way to take it back, even after the file
# leaked. The owner: "we need to see all our invites". Hiding it from a list
# is not withdrawing it, so these gates claim with the withdrawn key against
# the RUNNING owner daemon (no restart: the withdrawal must apply at once), then
# again after a restart (it must be durable), then with a 0.9.1 joiner (the
# released version must be refused cleanly too).
#
# Gates:
#   W0  POSITIVE: the reusable invitation enrols a first device
#   W1  `devices` lists the invitation by name with its uses left (19 of 20)
#   W2  `devices --json` lists it under data.invitations with usesLeft 19
#   W3  `add --withdraw` says it withdrew it, names the device already joined
#       as NOT affected, and points to `demote ... --to cut`
#   W4  the invitation is gone from `devices` and from `devices --json`
#   W5  a second claim with the SAME file, against the SAME running daemon
#       (no restart), is refused, saying the owner withdrew it; nothing enrols
#   W6  the device that joined before the withdrawal is still on record and
#       not revoked (withdrawal is not cut off)
#   W7  after an owner restart the withdrawn key is still refused
#   W8  a 0.9.1 joiner is refused too, with the reason in its words, and
#       nothing enrols
#   W9  CONTROL: a fresh invitation still enrols on the same daemon, so the
#       refusals above are the withdrawal and not a broken join path
#   W10 an unknown name is refused with a usage-class exit and names what IS
#       outstanding; a script with no name is told to give one
#
# PLATFORM: unix-only in practice (the fixture backend, ss), like every other
# *-gates.sh here. The property is platform-independent.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8221
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/wt-invwd.XXXXXX")"
DA="$WORK/owner"
NAME=ci

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

KNOWN_RED_ALLOW=()
O_ENV=(env TUNLION_CONFIG_DIR="$DA")

# The released joiner, for W8. A gate that cannot get it must not pass W8
# vacuously, so a missing binary is a FAIL with its name, not a skip.
V091="${TUNLION_V091_BIN:-}"
if [ -z "$V091" ]; then
  mkdir -p "$WORK/v091"
  base=https://github.com/Abdk4Moura/tunlion/releases/download/cli-v0.9.1
  asset=tunlion-x86_64-unknown-linux-musl.tar.gz
  if curl -fsSL --max-time 60 -o "$WORK/v091/$asset" "$base/$asset" \
     && curl -fsSL --max-time 30 -o "$WORK/v091/SHA256SUMS" "$base/SHA256SUMS" \
     && ( cd "$WORK/v091" && grep " $asset\$" SHA256SUMS | sha256sum -c - >/dev/null ) \
     && tar -xzf "$WORK/v091/$asset" -C "$WORK/v091"; then
    V091="$(find "$WORK/v091" -type f -name tunlion -perm -u+x | head -1)"
  fi
fi

start_backend
init_owner "$DA"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"
sleep 2

records() { grep -c "\"name\": *\"$1" "$DA/devices.json" 2>/dev/null || true; }

# =================================================================== GATE W0 ==
say "W0: a reusable invitation enrols a first device"
fs_cli 45 "${O_ENV[@]}" "$BIN" --server "$SERVER" add --for "$NAME" --allow transfer \
  --reuse 20 --expires 1h --out "$WORK/$NAME-inv.txt" --yes
rcMint=$?
fs_out >"$WORK/mint.out"
mkdir -p "$WORK/first"
fs_cli 60 env TUNLION_CONFIG_DIR="$WORK/first" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/$NAME-inv.txt" --name first --no-interactive
rcW0=$?
fs_out >"$WORK/W0.out"
sleep 2
if [ "$rcMint" = "0" ] && [ "$rcW0" = "0" ] && [ "$(records "$NAME")" -ge 1 ]; then
  ok "gateW0: the reusable invitation enrolled a first device"
else
  echo "-- mint --"; cat "$WORK/mint.out"; echo "-- W0 --"; cat "$WORK/W0.out"
  bad "gateW0: the reusable invitation did not enrol (mint rc=$rcMint join rc=$rcW0)"
fi
if grep -q "tunlion add --withdraw $NAME" "$WORK/mint.out"; then
  echo "   (the mint names the way to take it back)"
fi

# =================================================================== GATE W1 ==
say "W1: devices lists the invitation with its uses left"
"${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" devices >"$WORK/W1.out" 2>&1
if grep -q "INVITATIONS" "$WORK/W1.out" \
   && grep -E "^ +[^ ]+ +$NAME +your device .*19 of 20 left.*expires in" "$WORK/W1.out" >/dev/null; then
  ok "gateW1: devices lists the '$NAME' invitation, 19 of 20 left, with its expiry"
else
  cat "$WORK/W1.out"
  bad "gateW1: devices does not list the outstanding '$NAME' invitation with its uses left"
fi

# =================================================================== GATE W2 ==
say "W2: devices --json lists it under data.invitations"
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices --json >"$WORK/W2.json" 2>"$WORK/W2.err"
W2=$(python3 - "$WORK/W2.json" "$NAME" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
inv = [i for i in d["data"]["invitations"] if i.get("name") == sys.argv[2]]
ok = len(inv) == 1 and inv[0]["usesLeft"] == 19 and inv[0]["maxUses"] == 20 \
     and inv[0]["uses"] == 1 and inv[0]["kind"] == "device" and inv[0]["allow"] == ["transfer"] \
     and inv[0]["expires"] > 0 and len(inv[0]["id"]) == 12
print("ok" if ok else "bad " + json.dumps(d["data"].get("invitations")))
PY
)
if [ "$W2" = "ok" ]; then
  ok "gateW2: devices --json lists it (uses 1, usesLeft 19 of maxUses 20, kind, allow, id)"
else
  echo "$W2"; cat "$WORK/W2.err"
  bad "gateW2: devices --json does not list the invitation correctly"
fi

# =================================================================== GATE W3 ==
say "W3: add --withdraw withdraws it and says who is NOT affected"
fs_cli 30 "${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" add --withdraw "$NAME" --yes
rcW3=$?
fs_out >"$WORK/W3.out"
if [ "$rcW3" = "0" ] \
   && grep -q "withdrew the invitation for $NAME" "$WORK/W3.out" \
   && grep -q "running receiver" "$WORK/W3.out" \
   && grep -q "NOT affected: $NAME" "$WORK/W3.out" \
   && grep -q "tunlion demote $NAME --to cut" "$WORK/W3.out"; then
  ok "gateW3: the withdrawal says what it did, names '$NAME' as not affected, and gives the cut off"
else
  cat "$WORK/W3.out"
  bad "gateW3: add --withdraw did not report the withdrawal as required (rc=$rcW3)"
fi

# =================================================================== GATE W4 ==
say "W4: the invitation is gone from devices and devices --json"
"${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" devices >"$WORK/W4.out" 2>&1
"${O_ENV[@]}" "$BIN" --server "$SERVER" devices --json >"$WORK/W4.json" 2>/dev/null
W4J=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["data"]["invitations"]))' "$WORK/W4.json" 2>&1)
if ! grep -q "INVITATIONS" "$WORK/W4.out" && [ "$W4J" = "0" ]; then
  ok "gateW4: the withdrawn invitation is listed nowhere"
else
  cat "$WORK/W4.out"; echo "json invitations: $W4J"
  bad "gateW4: the withdrawn invitation is still listed"
fi

# =================================================================== GATE W5 ==
say "W5: a second claim against the SAME running daemon is refused"
before=$(records "$NAME")
mkdir -p "$WORK/second"
fs_bounded 60 env TUNLION_CONFIG_DIR="$WORK/second" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/$NAME-inv.txt" --name second --no-interactive >"$WORK/W5.out" 2>&1
stW5=$(fs_state); rcW5=$(fs_rc)
sleep 1
after=$(records "$NAME")
alive=no; kill -0 "$OWNER_PID" 2>/dev/null && alive=yes
echo "## state=$stW5 rc=$rcW5 records $before -> $after owner-alive=$alive"
if [ "$stW5" = "err" ] && grep -q "the owner withdrew this invitation" "$WORK/W5.out" \
   && [ "$after" = "$before" ] && [ "$alive" = "yes" ]; then
  ok "gateW5: the running daemon refused the withdrawn key ('the owner withdrew this invitation'), nothing enrolled"
else
  cat "$WORK/W5.out"
  bad "gateW5: a claim with the withdrawn key was not refused by the running daemon (state=$stW5 rc=$rcW5 records $before -> $after)"
fi

# =================================================================== GATE W6 ==
say "W6: the device that joined before is unaffected"
W6=$(python3 - "$DA/devices.json" "$NAME" <<'PY'
import json, sys
recs = [d for d in json.load(open(sys.argv[1])) if d.get("name") == sys.argv[2]]
r = recs[0] if recs else {}
bad = (not recs) or r.get("certRevoked") is True or r.get("principalState") == "revoked"
print("bad " + json.dumps(r)[:300] if bad else "ok")
PY
)
if [ "$W6" = "ok" ]; then
  ok "gateW6: '$NAME', joined before the withdrawal, is still on record and not revoked"
else
  echo "$W6"
  bad "gateW6: withdrawing the invitation changed the device that had joined with it"
fi

# =================================================================== GATE W7 ==
say "W7: after an owner restart the withdrawn key is still refused"
kill "$OWNER_PID" 2>/dev/null
sleep 2
cp "$WORK/up.log" "$WORK/up-before-restart.log"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"
sleep 4
mkdir -p "$WORK/third"
fs_bounded 60 env TUNLION_CONFIG_DIR="$WORK/third" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/$NAME-inv.txt" --name third --no-interactive >"$WORK/W7.out" 2>&1
stW7=$(fs_state); rcW7=$(fs_rc)
after7=$(records "$NAME")
if [ "$stW7" = "err" ] && grep -q "the owner withdrew this invitation" "$WORK/W7.out" && [ "$after7" = "$before" ]; then
  ok "gateW7: the withdrawal survived the restart"
else
  cat "$WORK/W7.out"
  bad "gateW7: after a restart the withdrawn key was not refused (state=$stW7 rc=$rcW7 records $after7)"
fi

# =================================================================== GATE W8 ==
say "W8: a 0.9.1 joiner is refused cleanly"
if [ -n "$V091" ] && [ -x "$V091" ]; then
  echo "## 0.9.1 joiner: $("$V091" --version 2>&1 | head -1)"
  mkdir -p "$WORK/old"
  fs_bounded 60 env TUNLION_CONFIG_DIR="$WORK/old" "$V091" --server "$SERVER" \
    join --invite-file "$WORK/$NAME-inv.txt" --name old --no-interactive >"$WORK/W8.out" 2>&1
  stW8=$(fs_state); rcW8=$(fs_rc)
  after8=$(records "$NAME")
  if [ "$stW8" = "err" ] && grep -q "enrollment denied: the owner withdrew this invitation" "$WORK/W8.out" \
     && [ "$after8" = "$before" ]; then
    ok "gateW8: the 0.9.1 joiner was refused ('enrollment denied: the owner withdrew this invitation'), nothing enrolled"
  else
    cat "$WORK/W8.out"
    bad "gateW8: the 0.9.1 joiner was not refused cleanly (state=$stW8 rc=$rcW8 records $after8)"
  fi
else
  bad "gateW8: no 0.9.1 binary (set TUNLION_V091_BIN, or allow the release download); the mixed-version gate did not run"
fi

# =================================================================== GATE W9 ==
say "W9: CONTROL: a fresh invitation still enrols on the same daemon"
fs_cli 45 "${O_ENV[@]}" "$BIN" --server "$SERVER" add --for fresh --allow transfer \
  --expires 1h --out "$WORK/fresh-inv.txt" --yes
mkdir -p "$WORK/fresh"
fs_cli 60 env TUNLION_CONFIG_DIR="$WORK/fresh" "$BIN" --server "$SERVER" \
  join --invite-file "$WORK/fresh-inv.txt" --name fresh --no-interactive
rcW9=$?
sleep 1
if [ "$rcW9" = "0" ] && [ "$(records fresh)" -ge 1 ]; then
  ok "gateW9: a fresh invitation enrolled, so W5, W7 and W8 were the withdrawal"
else
  fs_out
  bad "gateW9: a fresh invitation did not enrol, so the refusals above prove nothing"
fi

# ================================================================== GATE W10 ==
say "W10: unknown names and missing names are refused with a reason"
"${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" add --for spare --expires 1h \
  --out "$WORK/spare-inv.txt" --yes >/dev/null 2>&1
"${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" --no-interactive add --withdraw nobody --yes >"$WORK/W10a.out" 2>&1
rcA=$?
"${O_ENV[@]}" NO_COLOR=1 "$BIN" --server "$SERVER" --no-interactive add --withdraw --yes >"$WORK/W10b.out" 2>&1 </dev/null
rcB=$?
if [ "$rcA" = "3" ] && grep -q "no outstanding invitation named 'nobody'" "$WORK/W10a.out" \
   && grep -q "outstanding: spare" "$WORK/W10a.out" \
   && [ "$rcB" = "2" ] && grep -q "tunlion add --withdraw <name>" "$WORK/W10b.out"; then
  ok "gateW10: an unknown name exits 3 naming what is outstanding; no name from a script exits 2 with the usage"
else
  echo "-- unknown (rc=$rcA) --"; cat "$WORK/W10a.out"; echo "-- missing (rc=$rcB) --"; cat "$WORK/W10b.out"
  bad "gateW10: add --withdraw did not refuse an unknown or missing name as required"
fi

declare_known_red_summary
KNOWN_RED_N=${#KNOWN_RED_HIT[@]}

echo
echo "==========================================="
echo "invite-withdraw gates: $PASS passed, $FAIL failed, $KNOWN_RED_N known-red${FAILED:+ -- failed:$FAILED}"
echo "work: $WORK"
[ "$FAIL" = "0" ]
