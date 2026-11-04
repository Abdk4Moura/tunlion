#!/usr/bin/env bash
# Real invite-file join through the shared Core API.
#
# The owner is the normal CLI (`tunlion add --for guest --out FILE` and
# `tunlion up`). The joiner is `Core::join_invitation` in the join-invitation
# helper binary, from a blank config directory. This proves the library join
# driver, the shared acknowledgement persistence and the default ceiling, not
# only a token parse.
#
# Requires a built CLI and core helper in the same target directory:
#   cargo build --release -p tunlion --bin tunlion
#   cargo build --release -p tunlion-core --bin join-invitation
#
# Honors: TUNLION_BIN, TUNLION_CORE_JOIN_BIN, TUNLION_TEST_VENV.
# Refuses (exit 2) when either binary or the backend is unavailable.

set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CLI_DIR="$(dirname "$HERE")"
BIN="${TUNLION_BIN:-$CLI_DIR/target/release/tunlion}"
CORE_BIN="${TUNLION_CORE_JOIN_BIN:-$(dirname "$BIN")/join-invitation}"
PORT="${TUNLION_CORE_JOIN_PORT:-8189}"
SERVER="http://127.0.0.1:$PORT"
PYV="${TUNLION_TEST_VENV:-python3}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/core-invite-join.XXXXXX")"
DA="$WORK/owner"
DG="$WORK/guest"
export TUNLION_NONINTERACTIVE=1
export TUNLION_SHUTDOWN_GRACE_MS=1500

source "$HERE/lib/fixture.sh"
trap fixture_cleanup EXIT

[ -x "$BIN" ] || { echo "no tunlion binary at $BIN (build: cargo build --release -p tunlion)"; exit 2; }
[ -x "$CORE_BIN" ] || {
  echo "no Core join helper at $CORE_BIN"
  echo "  build: cargo build --release -p tunlion-core --bin join-invitation"
  exit 2
}

start_backend
init_owner "$DA"
start_acceptor "$DA"
OWNER_PID="${FIX_PIDS[-1]}"

INV="$WORK/guest-invite.txt"
OUT=$(timeout 45 env TUNLION_CONFIG_DIR="$DA" "$BIN" --server "$SERVER" \
  add --for guest --out "$INV" --yes 2>&1)
if [ $? -ne 0 ] || [ ! -s "$INV" ]; then
  echo "## invitation mint failed: $OUT"
  exit 1
fi
echo "## minted invitation file (contents not printed)"

# ------------------------------------------------------------------- P1 preview
PREVIEW=$(timeout 30 "$CORE_BIN" --config-dir "$DG" --invite-file "$INV" --preview 2>"$WORK/preview.err")
rcP=$?
echo "## preview rc=$rcP $PREVIEW"
if [ "$rcP" = 0 ] && PREVIEW="$PREVIEW" "$PYV" - <<'PY'
import json, os, sys
doc = json.loads(os.environ["PREVIEW"])
caps = doc["requested_capabilities"]
assert caps == ["transfer"], caps
assert "mount" not in caps and "shell" not in caps, caps
assert doc["relationship"] == "OwnDevice", doc
assert doc["expired"] is False, doc
assert "filament-invite:" not in os.environ["PREVIEW"], "preview leaked the token"
PY
then
  ok "P1: Core preview reports the signed default (transfer only, fleet device)"
else
  cat "$WORK/preview.err"
  bad "P1: Core preview did not report the expected signed default"
fi

# ---------------------------------------------------------------------- J1 join
JOINED=$(timeout 90 "$CORE_BIN" --config-dir "$DG" --invite-file "$INV" --name guest --timeout 60 2>"$WORK/join.err")
rcJ=$?
echo "## join rc=$rcJ $JOINED"
if [ "$rcJ" = 0 ] && JOINED="$JOINED" "$PYV" - <<'PY'
import json, os
doc = json.loads(os.environ["JOINED"])
assert doc["name"] == "guest", doc
assert doc["owner_name"] == "alpha", doc
assert doc["ceiling"] == ["transfer"], doc
assert doc["ephemeral"] is False, doc
assert len(doc["device_pub"]) == 64, doc
assert "filament-invite:" not in os.environ["JOINED"], "join leaked the token"
PY
then
  ok "J1: Core join completed with the stored transfer ceiling"
else
  cat "$WORK/join.err"
  bad "J1: Core join did not complete"
fi

# ---------------------------------------------------------------- J2 local state
if [ -f "$DG/identity/device-cert.json" ] \
   && grep -qx 'name guest' "$DG/config" 2>/dev/null \
   && [ ! -f "$DG/identity.ed25519" ]; then
  ok "J2: joiner wrote the local certificate and name, and minted no owner key"
else
  echo "## guest files:"; find "$DG" -maxdepth 2 -type f -printf '%P\n' 2>/dev/null | sort
  cat "$DG/config" 2>/dev/null
  bad "J2: joiner local state is wrong"
fi

# --------------------------------------------------------------- J3 owner record
if JSON=$(timeout 30 env TUNLION_CONFIG_DIR="$DA" "$BIN" devices --json 2>/dev/null) \
   && JSON="$JSON" "$PYV" - <<'PY'
import json, os
doc = json.loads(os.environ["JSON"])
rows = {d["name"]: d for d in doc["data"]["devices"]}
guest = rows.get("guest")
assert guest is not None, rows.keys()
assert guest.get("caps") == ["transfer"], guest
assert guest.get("devicePub") or guest.get("deviceKey"), guest
PY
then
  ok "J3: the owner lists guest with the same transfer-only ceiling"
else
  bad "J3: the owner did not record the joined device"
fi

exit 0
