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
#   J4  the next join finishes that journal without a second enrollment request
#   J5  an overlay key that does not match the certificate is refused by `up`
#       with a named repair path (not a transport-looking error)
#   J6  `addr --json` refuses the same mismatch instead of printing an address
#       the fleet never certified
#   J7  `reset -y` removes the backup/journal a half-join leaves behind
#   J8  `addr --json` exposes displayName and meshName distinctly; --name-as is
#       display-only and does not rename the mesh
#   J9  the human `addr` readout says --name-as is display-only
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
mkdir "$DG/devices.json"   # the store cannot be written over a directory
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

say "J4: the next join finishes the accepted journal"
rmdir "$DG/devices.json"
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
