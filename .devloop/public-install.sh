#!/usr/bin/env bash
# Public crates.io install check for tunlion 0.9.3, then version, help and a
# safe isolated status with no existing configuration.
set -euo pipefail

WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
exec 9>"$WORK/build.lock"
flock -w 1800 9

export CARGO_TERM_COLOR=never
umask 077

say() { printf '\n== %s\n' "$*"; }

say "lease head (expected release commit 160c3948201813cfe584e9fec40e244d6a2be36a)"
git rev-parse HEAD
git log --oneline -2

say "published tunlion 0.9.3 visible in the sparse index"
ok=0
for i in $(seq 1 24); do
  if curl -fsS -A "tunlion-lease" https://index.crates.io/tu/nl/tunlion | grep -q '"vers":"0.9.3"'; then ok=1; break; fi
  sleep 5
done
[ "$ok" = "1" ] || { echo "tunlion 0.9.3 not visible"; exit 1; }
echo "tunlion 0.9.3 visible"

say "public cargo install --locked --version 0.9.3 tunlion"
ROOT="$WORK/public-install-root"
rm -rf "$ROOT"
cargo install --locked --version 0.9.3 tunlion --root "$ROOT" --force

BIN="$ROOT/bin/tunlion"
test -x "$BIN" || { echo "missing installed binary"; exit 1; }

say "version"
"$BIN" --version | tee "$WORK/version.txt"
grep -q '^tunlion 0\.9\.3' "$WORK/version.txt"

say "help"
"$BIN" --help > "$WORK/help.txt" 2>&1
head -3 "$WORK/help.txt"
grep -qi 'usage' "$WORK/help.txt"

say "isolated status with no existing configuration"
ISO="$WORK/isolated"
rm -rf "$ISO"
mkdir -p "$ISO/home" "$ISO/config"
set +e
HOME="$ISO/home" TUNLION_CONFIG_DIR="$ISO/config" "$BIN" status --json > "$WORK/status.json" 2> "$WORK/status.err"
rc=$?
set -e
echo "status exit=$rc"
cat "$WORK/status.json"
if [ -s "$WORK/status.err" ]; then echo "stderr:"; head -5 "$WORK/status.err"; fi
python3 - <<'PY'
import json
with open("/home/runner/work/_temp/tunlion-work/status.json") as f:
    d = json.load(f)
print("status json keys", sorted(d.keys())[:6])
assert isinstance(d, dict) and d, "empty status document"
PY
if pgrep -f "$ROOT/bin/tunlion" >/dev/null 2>&1; then
  echo "unexpected background process from status"; exit 1
fi
echo "no background process left by status"

say "SUMMARY"
echo "OK public cargo install 0.9.3 from crates.io, version and help, isolated status with no existing config, no background process"
