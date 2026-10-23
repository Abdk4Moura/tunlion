#!/usr/bin/env bash
# Join commit gates: an accepted enrollment is success, exactly once.
#
# The Windows report this fixes (artifact 03d93407) had a device the owner had
# ALREADY certified, while the joining side printed
#   Error: this invitation has already been used
# and exited nonzero. The local store showed the other half of the damage:
# `identity/device-cert.json` existed, `devices.json` did not, and a
# `devices.json.bak` was left behind. This gate holds the observable contract:
#
#   J1  a real join succeeds and commits certificate + devices.json
#   J2  re-running the SAME invitation after losing the local commit exits 0
#       with a reissued receipt, and does NOT consume/relabel the enrollment
#   J3  a local commit failure leaves NO certificate (certificate is last) and
#       keeps a journal
#   J3b `addr --json` refuses an accepted journal whose certificate is not written
#   J4  the next join finishes that journal without a second enrollment request
#   J5  an overlay key that does not match the certificate is refused by `up`
#       with a named repair path (not a transport-looking error)
#   J6  `addr --json` refuses the same mismatch instead of printing an address
#       the fleet never certified
#   J7  `reset -y` removes the backup/journal a half-join leaves behind
#   J8  `addr --json` exposes displayName and meshName distinctly; --name-as is
#       display-only and does not rename the mesh
#   J9  the human `addr` readout says --name-as is display-only
#   J10 a corrupt certificate is refused by `addr`, not treated as "no identity"
#   J11a a bounded multi-use retry is a receipt: one use, same identity
#   J11b a forever-use retry is a receipt: one use, same secret
#   J11c a different device key on the same invitation consumes a new use
#   J11d a new invitation (new enrollment key) consumes a new use; same-key
#        changed signed bounds are unit-tested in receipt validation
#   J12 a joined store must hold its owner record, not just any JSON array
#
# Hermetic localhost fixture. TUNLION_BIN points at the built binary.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
PORT=8187
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tunlion-join-state.XXXXXX")"
DA="$WORK/owner"
DG="$WORK/joined"
DMM="$WORK/mismatch"
NAME=joined

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT
KNOWN_RED_ALLOW=()
O_ENV=(env TUNLION_CONFIG_DIR="$DA")
G_ENV=(env TUNLION_CONFIG_DIR="$DG")

start_backend
init_owner "$DA"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"

say "setup: mint an invitation for '$NAME'"
if ! "${O_ENV[@]}" "$BIN" --server "$SERVER" add --for "$NAME" --out "$WORK/inv.txt" --yes >"$WORK/add.log" 2>&1; then
  cat "$WORK/add.log"
  fixture_die "setup: the owner could not mint the invitation"
fi
mkdir -p "$DG"

say "J1: a real join commits the certificate and devices.json"
timeout 90 "${G_ENV[@]}" "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" \
  --name "$NAME" --no-interactive >"$WORK/j1.out" 2>&1
RC1=$?
if [ "$RC1" = 0 ] && [ -f "$DG/identity/device-cert.json" ] && [ -f "$DG/devices.json" ]; then
  ok "J1: join exits 0 and commits both identity files"
else
  cat "$WORK/j1.out"
  bad "J1: join did not commit cleanly (rc=$RC1)"
fi
OVERLAY_BEFORE=$(timeout 10 "${G_ENV[@]}" "$BIN" addr --json 2>/dev/null \
  | "$PYV" -c 'import json,sys; print(json.load(sys.stdin)["overlayV6"])' 2>/dev/null)
CERT_BEFORE=$(sha256sum "$DG/identity/device-cert.json" 2>/dev/null | cut -d' ' -f1)

say "J2: an already-used invitation after the owner accepted is a RECEIPT, exit 0"
# RESTART the owner first, so its in-memory single-use burn counter is empty and
# the retry reaches the DURABLE used-invitations refusal. That is the path that
# used to deny without reissuing (the gate used to keep one owner process alive
# and only proved the live-burn path).
PID_BEFORE=$(cat "$DA/up.pid" 2>/dev/null || true)
"${O_ENV[@]}" "$BIN" down -y >"$WORK/owner-down.log" 2>&1
sleep 2
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"
sleep 2
PID_AFTER=$(cat "$DA/up.pid" 2>/dev/null || true)
if [ -z "$PID_BEFORE" ] || [ -z "$PID_AFTER" ] || [ "$PID_BEFORE" = "$PID_AFTER" ]; then
  cat "$WORK/owner-down.log"
  fixture_die "J2 setup: the owner did not restart (before='$PID_BEFORE' after='$PID_AFTER'), so the durable-restart path would be untested"
fi
# Lose the local half of the commit, keep the overlay key: this is the state the
# Windows report reached (owner certified; local store write failed).
rm -f "$DG/identity/device-cert.json" "$DG/devices.json"
timeout 90 "${G_ENV[@]}" "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" \
  --name "$NAME" --no-interactive --json >"$WORK/j2.out" 2>"$WORK/j2.err"
RC2=$?
J2_JSON=$(cat "$WORK/j2.out" 2>/dev/null)
if [ "$RC2" = 0 ] && [ -f "$DG/identity/device-cert.json" ] && [ -f "$DG/devices.json" ] \
   && printf '%s' "$J2_JSON" | grep -q '"alreadyEnrolled": true' \
   && printf '%s' "$J2_JSON" | grep -q '"receipt": "reissued"'; then
  ok "J2: the owner re-sent the receipt, exit 0, local identity restored"
else
  echo "rc=$RC2"; cat "$WORK/j2.out" "$WORK/j2.err"
  bad "J2: an accepted enrollment was reported as failure (rc=$RC2)"
fi
OVERLAY_AFTER=$(timeout 10 "${G_ENV[@]}" "$BIN" addr --json 2>/dev/null \
  | "$PYV" -c 'import json,sys; print(json.load(sys.stdin)["overlayV6"])' 2>/dev/null)
CERT_AFTER=$(sha256sum "$DG/identity/device-cert.json" 2>/dev/null | cut -d' ' -f1)
if [ -n "$OVERLAY_BEFORE" ] && [ "$OVERLAY_BEFORE" = "$OVERLAY_AFTER" ] && [ "$CERT_BEFORE" = "$CERT_AFTER" ]; then
  ok "J2b: the receipt names the SAME overlay key and certificate the owner certified"
else
  bad "J2b: the receipt changed the identity (before=$OVERLAY_BEFORE/$CERT_BEFORE after=$OVERLAY_AFTER/$CERT_AFTER)"
fi

say "J3: a local commit failure leaves no certificate, only a journal"
rm -f "$DG/identity/device-cert.json" "$DG/devices.json"
# A valid, parseable empty store passes the read-only preflight. Its LOCK
# sidecar is a directory, so the locked commit fails AFTER the acknowledgement
# is journaled -- exactly the crash/IO window this journal exists for.
printf '[]' >"$DG/devices.json"
rm -f "$DG/devices.json.lock"
mkdir "$DG/devices.json.lock"
timeout 90 "${G_ENV[@]}" "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" \
  --name "$NAME" --no-interactive >"$WORK/j3.out" 2>&1
RC3=$?
if [ "$RC3" != 0 ] && [ ! -f "$DG/identity/device-cert.json" ] \
   && [ -f "$DG/join.pending.json" ]; then
  ok "J3: the failed commit exited nonzero, wrote NO certificate, and kept the journal"
else
  cat "$WORK/j3.out"
  bad "J3: a failed commit left a half identity (rc=$RC3 cert=$(test -f "$DG/identity/device-cert.json" && echo yes || echo no) journal=$(test -f "$DG/join.pending.json" && echo yes || echo no))"
fi

say "J3b: addr refuses an accepted journal before its certificate is written"
timeout 15 "${G_ENV[@]}" "$BIN" addr --json >"$WORK/j3b.out" 2>"$WORK/j3b.err"
RC3B=$?
if [ "$RC3B" != 0 ] && grep -q "still pending locally" "$WORK/j3b.err" "$WORK/j3b.out"; then
  ok "J3b: addr refuses the accepted-but-uncommitted journal"
else
  cat "$WORK/j3b.out" "$WORK/j3b.err"
  bad "J3b: addr printed an address for an uncommitted accepted join (rc=$RC3B)"
fi

say "J4: the next join finishes the accepted journal"
rmdir "$DG/devices.json.lock"
timeout 30 "${G_ENV[@]}" "$BIN" --server "$SERVER" join --invite-file "$WORK/inv.txt" \
  --name "$NAME" --no-interactive >"$WORK/j4.out" 2>&1
RC4=$?
if [ "$RC4" = 0 ] && [ -f "$DG/identity/device-cert.json" ] && [ -f "$DG/devices.json" ] \
   && [ ! -f "$DG/join.pending.json" ] \
   && grep -q "already accepted" "$WORK/j4.out"; then
  ok "J4: the journal completed the join without a second enrollment request"
else
  cat "$WORK/j4.out"
  bad "J4: the accepted journal was not resumed (rc=$RC4)"
fi
# Allow the owner's 2s store scan to settle before copying the state below.
sleep 1

say "J5: a certificate/key mismatch is refused by up, with a repair path"
cp -a "$DG" "$DMM"
# A fresh overlay key from a throwaway init: valid PKCS8, NOT the certified key.
DKEY="$WORK/keygen"; mkdir -p "$DKEY"
env TUNLION_CONFIG_DIR="$DKEY" "$BIN" init --name keygen --recovery-file "$DKEY/rec.txt" --yes >/dev/null 2>&1
cp "$DKEY/overlay.ed25519" "$DMM/overlay.ed25519"
timeout 20 env TUNLION_CONFIG_DIR="$DMM" "$BIN" --server "$SERVER" up --dir "$WORK/mm-drop" \
  >"$WORK/j5.out" 2>&1
RC5=$?
if [ "$RC5" != 0 ] && grep -q "overlay key" "$WORK/j5.out" && grep -q "tunlion reset" "$WORK/j5.out" \
   && ! grep -qi "unreachable\|timed out" "$WORK/j5.out"; then
  ok "J5: up refuses the mismatched identity and names the repair (no transport-looking error)"
else
  cat "$WORK/j5.out"
  bad "J5: up did not fail closed on the key mismatch (rc=$RC5)"
fi

say "J6: addr refuses the same mismatch instead of printing a false address"
timeout 15 env TUNLION_CONFIG_DIR="$DMM" "$BIN" addr --json >"$WORK/j6.out" 2>"$WORK/j6.err"
RC6=$?
if [ "$RC6" != 0 ] && grep -q "overlay key" "$WORK/j6.err" "$WORK/j6.out"; then
  ok "J6: addr --json refuses a certificate/key mismatch"
else
  cat "$WORK/j6.out" "$WORK/j6.err"
  bad "J6: addr printed an address for the mismatched identity (rc=$RC6)"
fi

say "J10: a corrupt certificate is refused, not read as absent"
DBAD="$WORK/corrupt-cert"
cp -a "$DG" "$DBAD"
printf '{"name":"joined","cert":{}}\n' >"$DBAD/identity/device-cert.json"
timeout 15 env TUNLION_CONFIG_DIR="$DBAD" "$BIN" addr --json >"$WORK/j10.out" 2>"$WORK/j10.err"
RC10=$?
if [ "$RC10" != 0 ] && grep -q "certificate record" "$WORK/j10.err" "$WORK/j10.out" \
   && grep -q "tunlion reset" "$WORK/j10.err" "$WORK/j10.out"; then
  ok "J10: addr refuses a corrupt certificate with the repair path"
else
  cat "$WORK/j10.out" "$WORK/j10.err"
  bad "J10: a corrupt certificate was treated as no identity (rc=$RC10)"
fi

say "J11: use accounting on retries and on genuinely different claims"
# Strict per-invitation accounting. Missing/unparseable evidence is a setup
# failure, never a pass: -1 used to be compared to -1.
used_keys() {
  "$PYV" - "$DA/used-invitations.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for e in d: print(e["keyId"])
PY
}
uses_for() {
  "$PYV" - "$DA/used-invitations.json" "$1" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
for e in d:
    if e.get("keyId")==sys.argv[2]:
        print(int(e.get("uses",-1))); raise SystemExit(0)
raise SystemExit(3)
PY
}
join_once() {  # invite dir name outfile
  timeout 90 env TUNLION_CONFIG_DIR="$2" "$BIN" --server "$SERVER" join \
    --invite-file "$1" --name "$3" --no-interactive --json >"$4" 2>"$4.err"
}
new_key_since() {  # before-file
  used_keys | grep -vxF -f "$1" | head -1
}
key_before() {
  : >"$WORK/keys.before"
  if [ -e "$DA/used-invitations.json" ]; then
    used_keys >"$WORK/keys.before" \
      || fixture_die "J11: used-invitations.json exists but cannot be read/parsed"
  fi
}

DM="$WORK/multi"; mkdir -p "$DM"
"${O_ENV[@]}" "$BIN" --server "$SERVER" add --for mreuse --reuse 5 --out "$WORK/multi-inv.txt" --yes \
  >"$WORK/j11-add.log" 2>&1 || { cat "$WORK/j11-add.log"; fixture_die "J11 setup: could not mint a multi-use invitation"; }

say "J11a: a bounded multi-use retry re-sends the receipt, one use"
key_before
join_once "$WORK/multi-inv.txt" "$DM" mreuse "$WORK/j11a.out"; RC11A=$?
KEY_A=$(new_key_since "$WORK/keys.before") || fixture_die "J11a: the first join recorded no invitation use"
USES_A1=$(uses_for "$KEY_A") || fixture_die "J11a: the invitation use entry is missing"
SECRET1=$("$PYV" - "$DM/devices.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(next((r.get("secret","") for r in d if r.get("secret")), ""))
PY
)
CERT1=$(sha256sum "$DM/identity/device-cert.json" | cut -d' ' -f1)
rm -f "$DM/identity/device-cert.json" "$DM/devices.json"
join_once "$WORK/multi-inv.txt" "$DM" mreuse "$WORK/j11b.out"; RC11B=$?
USES_A2=$(uses_for "$KEY_A") || fixture_die "J11a: the invitation use entry disappeared"
SECRET2=$("$PYV" - "$DM/devices.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(next((r.get("secret","") for r in d if r.get("secret")), ""))
PY
)
CERT2=$(sha256sum "$DM/identity/device-cert.json" | cut -d' ' -f1)
if [ "$RC11A" = 0 ] && [ "$RC11B" = 0 ] && [ "$USES_A1" = 1 ] && [ "$USES_A2" = 1 ] \
   && [ -n "$SECRET1" ] && [ "$SECRET1" = "$SECRET2" ] && [ "$CERT1" = "$CERT2" ] \
   && grep -q '"alreadyEnrolled": true' "$WORK/j11b.out"; then
  ok "J11a: one use recorded; retry kept the same certificate and secret"
else
  echo "rc=$RC11A/$RC11B uses=$USES_A1->$USES_A2 secret=$([ "$SECRET1" = "$SECRET2" ] && echo same || echo changed)"
  cat "$WORK/j11b.out" "$WORK/j11b.err"
  bad "J11a: a bounded multi-use retry did not prove one use and a stable identity"
fi

say "J11b: a forever-use retry re-sends the receipt, one use"
DMF="$WORK/multi-forever"; mkdir -p "$DMF"
"${O_ENV[@]}" "$BIN" --server "$SERVER" add --for mforever --reuse forever \
  --out "$WORK/forever-inv.txt" --yes >"$WORK/j11f-add.log" 2>&1 \
  || { cat "$WORK/j11f-add.log"; fixture_die "J11b setup: could not mint a forever invitation"; }
key_before
join_once "$WORK/forever-inv.txt" "$DMF" mforever "$WORK/j11f1.out"; RC11F1=$?
KEY_F=$(new_key_since "$WORK/keys.before") || fixture_die "J11b: the forever join recorded no use"
USES_F1=$(uses_for "$KEY_F") || fixture_die "J11b: the forever use entry is missing"
SECRET_F1=$("$PYV" - "$DMF/devices.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(next((r.get("secret","") for r in d if r.get("secret")), ""))
PY
)
rm -f "$DMF/identity/device-cert.json" "$DMF/devices.json"
join_once "$WORK/forever-inv.txt" "$DMF" mforever "$WORK/j11f2.out"; RC11F2=$?
USES_F2=$(uses_for "$KEY_F") || fixture_die "J11b: the forever use entry disappeared"
SECRET_F2=$("$PYV" - "$DMF/devices.json" <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
print(next((r.get("secret","") for r in d if r.get("secret")), ""))
PY
)
if [ "$RC11F1" = 0 ] && [ "$RC11F2" = 0 ] && [ "$USES_F1" = 1 ] && [ "$USES_F2" = 1 ] \
   && [ -n "$SECRET_F1" ] && [ "$SECRET_F1" = "$SECRET_F2" ] \
   && grep -q '"alreadyEnrolled": true' "$WORK/j11f2.out"; then
  ok "J11b: forever retry kept one use and the same secret"
else
  echo "rc=$RC11F1/$RC11F2 uses=$USES_F1->$USES_F2 secret=$([ "$SECRET_F1" = "$SECRET_F2" ] && echo same || echo changed)"
  cat "$WORK/j11f2.out" "$WORK/j11f2.err"
  bad "J11b: a forever-use retry did not prove one use and a stable secret"
fi

say "J11c: a DIFFERENT device key on the same invitation consumes a new use"
DM2="$WORK/multi-second"; mkdir -p "$DM2"
join_once "$WORK/multi-inv.txt" "$DM2" mreuse-second "$WORK/j11c.out"; RC11C=$?
USES_C=$(uses_for "$KEY_A") || fixture_die "J11c: the bounded invitation use entry is missing"
if [ "$RC11C" = 0 ] && [ "$USES_C" = 2 ] \
   && ! grep -q '"alreadyEnrolled": true' "$WORK/j11c.out"; then
  ok "J11c: a different device consumed exactly one additional use and was not treated as a retry"
else
  echo "rc=$RC11C uses=$USES_C"; cat "$WORK/j11c.out" "$WORK/j11c.err"
  bad "J11c: a different device key was treated as a retry or did not consume a use"
fi

say "J11d: a DIFFERENT invitation (new enrollment key) for the same device takes the ordinary claim path"
"${O_ENV[@]}" "$BIN" --server "$SERVER" add --for mreuse --reuse 5 --allow transfer \
  --out "$WORK/bounds-inv.txt" --yes >"$WORK/j11d-add.log" 2>&1 \
  || { cat "$WORK/j11d-add.log"; fixture_die "J11d setup: could not mint the second invitation"; }
key_before
rm -f "$DM/identity/device-cert.json" "$DM/devices.json"
join_once "$WORK/bounds-inv.txt" "$DM" mreuse "$WORK/j11d.out"; RC11D=$?
KEY_D=$(new_key_since "$WORK/keys.before") || fixture_die "J11d: the second-invitation join recorded no use"
USES_D=$(uses_for "$KEY_D") || fixture_die "J11d: the second-invitation use entry is missing"
if [ "$RC11D" = 0 ] && [ "$USES_D" = 1 ] \
   && ! grep -q '"alreadyEnrolled": true' "$WORK/j11d.out"; then
  ok "J11d: a new enrollment key consumed a new use instead of reusing the old receipt (same-key bounds are unit-tested)"
else
  echo "rc=$RC11D uses=$USES_D"; cat "$WORK/j11d.out" "$WORK/j11d.err"
  bad "J11d: a new enrollment key was treated as the same enrollment"
fi

say "J12: a joined store needs its owner record, not merely parseable JSON"
DSHAPE="$WORK/store-shape"; cp -a "$DG" "$DSHAPE"
J12_BAD=0
for shape in '[]|no owner record' '[1]|non-object record' '[{}]|without a name'              '[{"name":"x"}]|no usable credential'              '[{"name":"x","secret":123}]|non-string pair secret'              '{garbage|cannot be parsed'; do
  body=${shape%%|*}; needle=${shape#*|}
  printf '%s' "$body" >"$DSHAPE/devices.json"
  timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12.out" 2>"$WORK/j12.err"
  rc=$?
  if [ "$rc" = 0 ] || ! grep -q "$needle" "$WORK/j12.out" "$WORK/j12.err"; then
    echo "shape=$body rc=$rc expected='$needle'"; cat "$WORK/j12.out" "$WORK/j12.err"
    J12_BAD=1
  fi
done

# A structurally valid certificate with a bad signature is not a credential.
cp "$DG/devices.json" "$DSHAPE/devices.json"
"$PYV" - "$DSHAPE/devices.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p))
sig=d[0]["deviceCert"]["sig"]; d[0]["deviceCert"]["sig"]=("00" if not sig.startswith("00") else "01")+sig[2:]
json.dump(d, open(p,"w"))
PY
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12b.out" 2>"$WORK/j12b.err"
if [ $? = 0 ] || ! grep -q "invalid or expired device certificate" "$WORK/j12b.out" "$WORK/j12b.err"; then
  echo "bad-signature store cert was accepted"; cat "$WORK/j12b.out" "$WORK/j12b.err"; J12_BAD=1
fi

# Symlinks are refused rather than followed, for each file the readout opens.
cp "$DG/devices.json" "$DSHAPE/real-store.json"
rm -f "$DSHAPE/devices.json"
ln -s real-store.json "$DSHAPE/devices.json"
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12s.out" 2>"$WORK/j12s.err"
if [ $? = 0 ] || ! grep -q "symlink" "$WORK/j12s.out" "$WORK/j12s.err"; then
  echo "devices.json symlink was followed"; cat "$WORK/j12s.out" "$WORK/j12s.err"; J12_BAD=1
fi
rm -f "$DSHAPE/devices.json"; cp "$DG/devices.json" "$DSHAPE/devices.json"

mv "$DSHAPE/identity/device-cert.json" "$DSHAPE/real-cert.json"
ln -s ../real-cert.json "$DSHAPE/identity/device-cert.json"
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12s.out" 2>"$WORK/j12s.err"
if [ $? = 0 ] || ! grep -q "symlink" "$WORK/j12s.out" "$WORK/j12s.err"; then
  echo "device-cert.json symlink was followed"; cat "$WORK/j12s.out" "$WORK/j12s.err"; J12_BAD=1
fi
rm -f "$DSHAPE/identity/device-cert.json"; mv "$DSHAPE/real-cert.json" "$DSHAPE/identity/device-cert.json"

ln -s /dev/null "$DSHAPE/join.pending.json"
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12s.out" 2>"$WORK/j12s.err"
if [ $? = 0 ] || ! grep -q "symlink" "$WORK/j12s.out" "$WORK/j12s.err"; then
  echo "join.pending.json symlink was followed"; cat "$WORK/j12s.out" "$WORK/j12s.err"; J12_BAD=1
fi
rm -f "$DSHAPE/join.pending.json"

# A symlinked owner key must not make a joined certificate look like an owner
# and skip the owner-record check.
printf '[]' >"$DSHAPE/devices.json"
rm -f "$DSHAPE/identity.ed25519"
ln -s no-such-owner-key "$DSHAPE/identity.ed25519"
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12o.out" 2>"$WORK/j12o.err"
if [ $? = 0 ] || ! grep -q "symlink" "$WORK/j12o.out" "$WORK/j12o.err"; then
  echo "identity.ed25519 symlink made a joined device look like an owner"
  cat "$WORK/j12o.out" "$WORK/j12o.err"; J12_BAD=1
fi
rm -f "$DSHAPE/identity.ed25519"

# The overlay key is opened through the same no-follow handle.
mv "$DSHAPE/overlay.ed25519" "$DSHAPE/real-overlay.ed25519"
ln -s real-overlay.ed25519 "$DSHAPE/overlay.ed25519"
timeout 15 env TUNLION_CONFIG_DIR="$DSHAPE" "$BIN" addr --json >"$WORK/j12o.out" 2>"$WORK/j12o.err"
if [ $? = 0 ] || ! grep -q "symlink" "$WORK/j12o.out" "$WORK/j12o.err"; then
  echo "overlay.ed25519 symlink was followed"
  cat "$WORK/j12o.out" "$WORK/j12o.err"; J12_BAD=1
fi
rm -f "$DSHAPE/overlay.ed25519"

if [ "$J12_BAD" = 0 ]; then
  ok "J12: malformed records, bad certs and symlinked store/cert/journal/keys are refused"
else
  bad "J12: a malformed or symlinked join state was accepted"
fi

say "J7: reset removes the half-join journal and backup"
: >"$DG/devices.json.bak"
: >"$DG/join.pending.json"
"${G_ENV[@]}" "$BIN" reset -y >"$WORK/j7.out" 2>&1
RC7=$?
if [ "$RC7" = 0 ] && [ ! -f "$DG/devices.json.bak" ] && [ ! -f "$DG/join.pending.json" ] \
   && [ ! -f "$DG/devices.json" ] && [ ! -f "$DG/identity/device-cert.json" ]; then
  ok "J7: reset leaves no store backup or join journal behind"
else
  cat "$WORK/j7.out"
  bad "J7: reset called itself a clean slate while a half-join survived (rc=$RC7)"
fi

say "J8: --name-as is display-only; addr --json names mesh and display separately"
timeout 15 "${O_ENV[@]}" "$BIN" addr --json --name-as dgmfa-repro >"$WORK/j8.out" 2>"$WORK/j8.err"
RC8=$?
J8=$(cat "$WORK/j8.out" 2>/dev/null)
J8_OK=$("$PYV" - "$J8" <<'PY'
import json,sys
try: d=json.loads(sys.argv[1])
except Exception: print("bad-json"); raise SystemExit
print("ok" if d.get("displayName")=="dgmfa-repro" and d.get("meshName")=="alpha" and d.get("mesh")=="alpha.mesh" and d.get("name")=="alpha" else "bad")
PY
)
if [ "$RC8" = 0 ] && [ "$J8_OK" = ok ]; then
  ok "J8: displayName=dgmfa-repro, meshName=alpha, mesh unchanged"
else
  echo "rc=$RC8 parsed=$J8_OK"; cat "$WORK/j8.out" "$WORK/j8.err"
  bad "J8: addr --json conflated display and mesh identity"
fi

say "J9: the human readout says --name-as is display-only"
timeout 15 "${O_ENV[@]}" "$BIN" addr --name-as dgmfa-repro >"$WORK/j9.out" 2>"$WORK/j9.err"
if grep -q "display only" "$WORK/j9.err" && grep -q "tunlion set name" "$WORK/j9.err"; then
  ok "J9: addr names the display-only flag and how to persist the mesh name"
else
  cat "$WORK/j9.out" "$WORK/j9.err"
  bad "J9: --name-as semantics are still unexplained in the readout"
fi

echo
if [ "${FAIL:-0}" != 0 ]; then
  echo "FAILED:$FAILED"
fi
declare_known_red_summary
exit "$([ "$FAIL" = 0 ] && echo 0 || echo 1)"
