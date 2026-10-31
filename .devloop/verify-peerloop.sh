#!/usr/bin/env bash
# Lease verification for tunlion-peerloop 0.1.1 against the REAL published
# tunlion-lan 0.1.0 and tunlion-transport 0.1.1 from crates.io.
set -euo pipefail

WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
exec 9>"$WORK/build.lock"
flock -w 1800 9

export CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$WORK/target"
umask 077

say() { printf '\n== %s\n' "$*"; }

say "lease head (expected release commit 302945120357577ce0931f457a52b241a2c5a73f)"
git rev-parse HEAD
git log --oneline -2

say "published dependencies visible in the sparse index"
curl -fsS -A "tunlion-lease" https://index.crates.io/tu/nl/tunlion-lan | grep -o '"vers":"0.1.0"' | head -1
curl -fsS -A "tunlion-lease" https://index.crates.io/tu/nl/tunlion-transport | grep -o '"vers":"0.1.1"' | head -1

say "peerloop manifest requires the registry versions"
python3 - <<'PY'
import tomllib
t = tomllib.load(open("crates/filament-peerloop/Cargo.toml", "rb"))
tr = t["dependencies"]["filament-transport"]
lan = t["dependencies"]["tunlion-lan"]
print("peerloop", t["package"]["version"], "transport", tr, "lan", lan)
assert t["package"]["version"] == "0.1.1", t["package"]["version"]
assert tr.get("version") == "0.1.1", tr
assert lan.get("version") == "0.1.0", lan
print("OK manifest requirements")
PY

say "registry verification: cargo publish --dry-run"
( cd crates/filament-peerloop && cargo publish --dry-run --allow-dirty )

say "packaged manifest after dry run (must have no path)"
python3 - <<'PY'
import tomllib
p = "/home/runner/work/_temp/tunlion-work/target/package/tunlion-peerloop-0.1.1/Cargo.toml"
t = tomllib.load(open(p, "rb"))
tr = t["dependencies"]["filament-transport"]
lan = t["dependencies"]["tunlion-lan"]
print("packaged transport dep", tr)
print("packaged lan dep", lan)
assert "path" not in tr and tr.get("version") == "0.1.1", tr
assert "path" not in lan and lan.get("version") == "0.1.0", lan
print("OK packaged manifest uses the registry requirements")
PY

say "SUMMARY"
echo "OK peerloop 0.1.1 verified against published transport 0.1.1 and lan 0.1.0, no path dependency, dry run aborted before upload"
