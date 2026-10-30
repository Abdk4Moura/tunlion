#!/usr/bin/env bash
# Lease checks for the 0.9.3 crates dependency fix (PR 650).
# Runs on a disposable Ubuntu runner, never on the VPS.
set -euo pipefail

BASE=d658c3ba49d02f46f9dcdd73181031ec3bf319fd
WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
# One heavy cargo job per box, shared with any other tunlion lease.
exec 9>"$WORK/build.lock"
flock -w 1800 9

export CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$WORK/target"
umask 077
PKG="$WORK/pkg"
rm -rf "$PKG"
mkdir -p "$PKG"

say() { printf '\n== %s\n' "$*"; }

say "lease head (expected base $BASE)"
git rev-parse HEAD
git log --oneline -3

say "manifest and lock invariants"
python3 - <<'PY'
import sys, tomllib

def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)

fail = []
cli = load("cli/Cargo.toml")
pl = load("crates/filament-peerloop/Cargo.toml")
tr = load("crates/filament-transport/Cargo.toml")
lock = load("Cargo.lock")

if cli["package"]["version"] != "0.9.3":
    fail.append("cli version " + cli["package"]["version"])
if tr["package"]["version"] != "0.1.1":
    fail.append("transport version " + tr["package"]["version"])
if pl["package"]["version"] != "0.1.1":
    fail.append("peerloop version " + pl["package"]["version"])

dep = pl["dependencies"]["filament-transport"]
if dep.get("version") != "0.1.1":
    fail.append("peerloop transport requirement " + repr(dep.get("version")))
for name in ("filament-peerloop", "filament-transport"):
    got = cli["dependencies"][name].get("version")
    if got != "0.1.1":
        fail.append("cli " + name + " requirement " + repr(got))
    if "path" not in cli["dependencies"][name]:
        fail.append("cli " + name + " lost its path for the workspace build")

versions = {p.get("name"): p.get("version") for p in lock["package"]}
for name in ("tunlion-peerloop", "tunlion-transport"):
    if versions.get(name) != "0.1.1":
        fail.append("lock " + name + "=" + str(versions.get(name)))

print("cli", cli["package"]["version"],
      "transport", tr["package"]["version"],
      "peerloop", pl["package"]["version"])
print("lock", {n: versions.get(n) for n in ("tunlion-peerloop", "tunlion-transport")})
if fail:
    print("FAIL", fail)
    sys.exit(1)
print("OK manifest and lock invariants")
PY

say "cargo metadata --locked resolves the intended versions"
cargo metadata --locked --format-version 1 > "$WORK/metadata.json"
python3 - <<'PY'
import json
with open("/home/runner/work/_temp/tunlion-work/metadata.json") as f:
    meta = json.load(f)
got = {p["name"]: p["version"] for p in meta["packages"]}
want = {"tunlion": "0.9.3", "tunlion-peerloop": "0.1.1", "tunlion-transport": "0.1.1"}
for name, version in want.items():
    print(name, got.get(name))
    assert got.get(name) == version, (name, got.get(name), version)
print("OK metadata resolve")
PY

say "tests for the two changed crates"
cargo test --locked -p tunlion-transport -p tunlion-peerloop

say "package the three shipping crates without registry verification"
cargo package --locked --no-verify -p tunlion-transport -p tunlion-peerloop -p tunlion
for crate in tunlion-transport-0.1.1 tunlion-peerloop-0.1.1 tunlion-0.9.3; do
  test -f "$CARGO_TARGET_DIR/package/$crate.crate" || { echo "missing $crate.crate"; exit 1; }
  tar -xzf "$CARGO_TARGET_DIR/package/$crate.crate" -C "$PKG"
done
ls -l "$CARGO_TARGET_DIR/package"/*.crate

say "packaged manifests and lock"
python3 - <<'PY'
import sys, tomllib

root = "/home/runner/work/_temp/tunlion-work/pkg"
fail = []

def load(path):
    with open(path, "rb") as f:
        return tomllib.load(f)

cli = load(root + "/tunlion-0.9.3/Cargo.toml")
pl = load(root + "/tunlion-peerloop-0.1.1/Cargo.toml")
tr = load(root + "/tunlion-transport-0.1.1/Cargo.toml")
lock = load(root + "/tunlion-0.9.3/Cargo.lock")

if cli["package"]["name"] != "tunlion":
    fail.append("packaged cli name " + cli["package"]["name"])
if tr["package"]["version"] != "0.1.1":
    fail.append("packaged transport version")
if pl["package"]["version"] != "0.1.1":
    fail.append("packaged peerloop version")

for crate, table in (("cli", cli), ("peerloop", pl)):
    for name, dep in table.get("dependencies", {}).items():
        if "path" in dep:
            fail.append(crate + " " + name + " still has a path")
for name in ("filament-peerloop", "filament-transport"):
    got = cli["dependencies"][name].get("version")
    print("packaged cli", name, got)
    if got != "0.1.1":
        fail.append("packaged cli " + name + " " + repr(got))
got = pl["dependencies"]["filament-transport"].get("version")
print("packaged peerloop filament-transport", got)
if got != "0.1.1":
    fail.append("packaged peerloop transport " + repr(got))

versions = {p.get("name"): p.get("version") for p in lock["package"]}
print("packaged cli lock", {n: versions.get(n) for n in ("tunlion-peerloop", "tunlion-transport")})
for name in ("tunlion-peerloop", "tunlion-transport"):
    if versions.get(name) != "0.1.1":
        fail.append("packaged lock " + name + "=" + str(versions.get(name)))

if fail:
    print("FAIL", fail)
    sys.exit(1)
print("OK packaged manifests and lock")
PY

say "cargo publish dry run for transport 0.1.1"
# The other two cannot dry run until 0.1.1 exists on crates.io, by design.
( cd crates/filament-transport && cargo publish --dry-run --allow-dirty )

say "install dry run from the path with the locked graph"
cargo install --path cli --locked --root "$WORK/prefix" --debug --force
"$WORK/prefix/bin/tunlion" --version

say "npm tarball shape (manifest name is reported, not changed here)"
( cd packaging/npm && npm pack --dry-run --json > "$WORK/npm-pack.json" )
python3 - <<'PY'
import json
with open("/home/runner/work/_temp/tunlion-work/npm-pack.json") as f:
    d = json.load(f)[0]
print("npm name", d.get("name"), "version", d.get("version"), "files", len(d.get("files", [])))
PY

say "SUMMARY"
echo "OK lock 0.1.1, metadata 0.1.1, packaged manifests 0.1.1, no path deps, transport dry run, install dry run"
