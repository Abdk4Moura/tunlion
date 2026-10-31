#!/usr/bin/env bash
# Lease verification for tunlion-signal 0.1.1 before publication.
set -euo pipefail

WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
exec 9>"$WORK/build.lock"
flock -w 1800 9

export CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$WORK/target"
umask 077

say() { printf '\n== %s\n' "$*"; }

say "lease head (expected PR head 7fbe273fb24c24edf6814912e35aca2ebbdbaee5)"
git rev-parse HEAD
git log --oneline -2

say "manifest and lock invariants"
python3 - <<'PY'
import tomllib

def load(p):
    with open(p, "rb") as f:
        return tomllib.load(f)

sig = load("crates/filament-signal/Cargo.toml")
cli = load("cli/Cargo.toml")
pl = load("crates/filament-peerloop/Cargo.toml")
lock = {p.get("name"): p.get("version") for p in load("Cargo.lock")["package"]}

tokio = sig["dependencies"]["tokio"]
print("signal", sig["package"]["version"], "tokio", tokio)
print("cli signal", cli["dependencies"]["filament-signal"].get("version"))
print("peerloop signal", pl["dependencies"]["filament-signal"].get("version"))
print("lock signal", lock.get("tunlion-signal"))
assert sig["package"]["version"] == "0.1.1", sig["package"]["version"]
assert "io-util" in tokio.get("features", []), tokio
assert cli["dependencies"]["filament-signal"].get("version") == "0.1.1"
assert pl["dependencies"]["filament-signal"].get("version") == "0.1.1"
assert lock.get("tunlion-signal") == "0.1.1"
print("OK manifest and lock invariants")
PY

say "registry verification: cargo publish --dry-run"
( cd crates/filament-signal && cargo publish --dry-run --allow-dirty )

say "packaged manifest and lock"
python3 - <<'PY'
import tomllib

root = "/home/runner/work/_temp/tunlion-work/target/package/tunlion-signal-0.1.1"
t = tomllib.load(open(root + "/Cargo.toml", "rb"))
tokio = t["dependencies"]["tokio"]
print("packaged signal", t["package"]["version"], "tokio", tokio)
assert t["package"]["version"] == "0.1.1"
assert "io-util" in tokio.get("features", []), tokio
for name, dep in t.get("dependencies", {}).items():
    assert "path" not in dep, (name, dep)
lock = {p.get("name"): p.get("version") for p in
        tomllib.load(open(root + "/Cargo.lock", "rb"))["package"]}
print("packaged lock signal", lock.get("tunlion-signal"))
assert lock.get("tunlion-signal") == "0.1.1"
print("OK packaged manifest and lock")
PY

say "packaged source carries the offline client"
grep -n 'pub async fn offline' /home/runner/work/_temp/tunlion-work/target/package/tunlion-signal-0.1.1/src/lib.rs

say "SUMMARY"
echo "OK signal 0.1.1 packaged, offline present, io-util declared, no path deps, dry run aborted before upload"
