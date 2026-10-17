#!/usr/bin/env bash
# Drive one ci-dogfood run from this machine.
#
#   scripts/ci-dogfood.sh [--runner NAME] [--host NAME] [--ref BRANCH] [--keep-secret]
#
# What it does, in order:
#   1. mints a bounded, expiring invitation for one CI box
#   2. puts it in the repo secret TUNLION_INVITE (never on a command line)
#   3. dispatches .github/workflows/ci-dogfood.yml on `--ref`
#   4. waits until the box is online, then sends the payload over tunlion
#   5. waits for the bundle in the inbox, verifies its sha256, prints the result
#   6. forgets the device and removes the secret
#
# Requires: tunlion (this machine's daemon up), gh (authenticated), tar, sha256sum.
set -euo pipefail

RUNNER="ci-$(date +%Y%m%d-%H%M%S)"
# This machine's tunlion petname, not its hostname: the box sends the bundle to
# a tunlion device name. Override with --host.
HOST_NAME="dovm"
REF="$(git rev-parse --abbrev-ref HEAD)"
KEEP_SECRET=0
INV_DIR=""
INV=""
PAYLOAD_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --runner) RUNNER="$2"; shift 2 ;;
    --host) HOST_NAME="$2"; shift 2 ;;
    --ref) REF="$2"; shift 2 ;;
    --keep-secret) KEEP_SECRET=1; shift ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

cleanup() {
  [ -n "$INV_DIR" ] && rm -rf "$INV_DIR"
  [ -n "$PAYLOAD_DIR" ] && rm -rf "$PAYLOAD_DIR"
  if [ "$KEEP_SECRET" = "0" ]; then
    gh secret delete TUNLION_INVITE -R "$(repo)" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

repo() { gh repo view --json nameWithOwner -q .nameWithOwner; }

say() { printf '\n== %s\n' "$*"; }

# `--out` writes a NEW file and refuses to clobber, so hand it a name that does
# not exist yet rather than mktemp's pre-created file.
INV_DIR="$(mktemp -d)"
INV="$INV_DIR/invitation"
# A DEVICE invitation, not a runner one: the owner has to ADDRESS this box to
# push the payload, and an ephemeral runner is deliberately not persisted, so it
# cannot be resolved by name. The box still expires and is still forgotten at
# the end. This is the first UX finding in docs/ci-ux.md.
say "minting an invitation for $RUNNER (transfer only, 45m)"
tunlion add --for device --name "$RUNNER" --allow transfer --expires 45m \
  --out "$INV" -y --no-interactive >/dev/null

say "setting TUNLION_INVITE on $(repo)"
gh secret set TUNLION_INVITE -R "$(repo)" < "$INV"

say "building the payload"
PAYLOAD_DIR="$(mktemp -d)"
mkdir -p "$PAYLOAD_DIR/src"
cat > "$PAYLOAD_DIR/job.json" <<JSON
{
  "id": "$RUNNER",
  "cmd": ["sh", "build.sh"],
  "outputs": ["out.tar"],
  "timeout_s": 600
}
JSON
cat > "$PAYLOAD_DIR/build.sh" <<'SH'
set -eu
rustc --version > build-info.txt
uname -a >> build-info.txt
tar -cf out.tar build-info.txt
echo "built out.tar"
SH
tar -cf "$PAYLOAD_DIR/payload-$RUNNER.tar" -C "$PAYLOAD_DIR" job.json build.sh

say "dispatching ci-dogfood.yml on $REF"
gh workflow run ci-dogfood.yml -R "$(repo)" --ref "$REF" \
  -f runner_name="$RUNNER" -f host_name="$HOST_NAME"

online() {
  tunlion devices --json 2>/dev/null | python3 -c '
import json, sys
name = sys.argv[1].lower()
try:
    devices = json.load(sys.stdin).get("data", {}).get("devices", [])
except Exception:
    sys.exit(1)
sys.exit(0 if any(d.get("name", "").lower() == name and d.get("online") for d in devices) else 1)
' "$RUNNER"
}

say "waiting for $RUNNER to come online (up to 15 min)"
deadline=$(( $(date +%s) + 900 ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  if online; then
    say "$RUNNER is online"
    break
  fi
  sleep 5
done
if [ "$(date +%s)" -ge "$deadline" ]; then
  echo "the box never came online; check the workflow run" >&2
  exit 6
fi

say "sending the payload"
tunlion send "$PAYLOAD_DIR/payload-$RUNNER.tar" --to "$RUNNER" --timeout 300 --json >/dev/null

say "waiting for the bundle in the inbox"
INBOX="${TUNLION_INBOX:-$HOME/Tunlion}"
deadline=$(( $(date +%s) + 900 ))
BUNDLE=""
while [ "$(date +%s)" -lt "$deadline" ]; do
  BUNDLE=$(find "$INBOX" -maxdepth 2 -type f -name 'bundle*.tar' -newermt '-20 minutes' -print -quit 2>/dev/null || true)
  [ -n "$BUNDLE" ] && break
  sleep 5
done
if [ -z "$BUNDLE" ]; then
  echo "no bundle arrived in $INBOX; check the workflow run" >&2
  exit 6
fi

say "verifying $BUNDLE"
OUT="$(mktemp -d)"
tar -xf "$BUNDLE" -C "$OUT"
( cd "$OUT" && sha256sum -c out.sha256 )
echo
cat "$OUT/build-info.txt"
say "verified: $BUNDLE"

say "cleaning up"
tunlion devices forget "$RUNNER" -y >/dev/null 2>&1 || true
echo "done: $RUNNER"
