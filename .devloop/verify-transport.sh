#!/usr/bin/env bash
# Lease verification for tunlion-transport 0.1.1 against the REAL published
# tunlion-lan 0.1.0 from crates.io. Runs on a disposable Ubuntu runner.
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

say "published tunlion-lan 0.1.0 visible in the sparse index"
curl -fsS -A "tunlion-lease" https://index.crates.io/tu/nl/tunlion-lan | grep -o '"vers":"0.1.0"' | head -1

say "transport manifest requires the registry version"
python3 - <<'PY'
import tomllib
t = tomllib.load(open("crates/filament-transport/Cargo.toml", "rb"))
d = t["dependencies"]["tunlion-lan"]
print("transport", t["package"]["version"], "lan dep", d)
assert t["package"]["version"] == "0.1.1", t["package"]["version"]
assert d.get("version") == "0.1.0", d
print("OK manifest requirement")
PY

say "registry verification: cargo publish --dry-run"
( cd crates/filament-transport && cargo publish --dry-run --allow-dirty )

say "packaged manifest after dry run (must have no path)"
python3 - <<'PY'
import tomllib
p = "/home/runner/work/_temp/tunlion-work/target/package/tunlion-transport-0.1.1/Cargo.toml"
t = tomllib.load(open(p, "rb"))
d = t["dependencies"]["tunlion-lan"]
print("packaged lan dep", d)
assert "path" not in d, d
assert d.get("version") == "0.1.0", d
print("OK packaged manifest uses the registry requirement")
PY

say "SUMMARY"
echo "OK transport 0.1.1 verified against published tunlion-lan 0.1.0, no path dependency, dry run aborted before upload"
