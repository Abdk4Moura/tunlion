#!/usr/bin/env bash
# Lease checks for the 0.9.3 LAN-inclusive release tree (PR 650).
# Runs on a disposable Ubuntu runner, never on the VPS.
set -euo pipefail

BASE=b19183f96d46969f956b9c7a4c949cec3446dd56
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
lan = load("crates/tunlion-lan/Cargo.toml")
lock = load("Cargo.lock")

if cli["package"]["version"] != "0.9.3":
    fail.append("cli version " + cli["package"]["version"])
if tr["package"]["version"] != "0.1.1":
    fail.append("transport version " + tr["package"]["version"])
if pl["package"]["version"] != "0.1.1":
    fail.append("peerloop version " + pl["package"]["version"])
if lan["package"]["version"] != "0.1.0":
    fail.append("lan version " + lan["package"]["version"])

dep = pl["dependencies"]["filament-transport"]
if dep.get("version") != "0.1.1":
    fail.append("peerloop transport requirement " + repr(dep.get("version")))
for table, crate in ((cli, "cli"), (pl, "peerloop"), (tr, "transport")):
    got = table["dependencies"]["tunlion-lan"].get("version")
    if got != "0.1.0":
        fail.append(crate + " lan requirement " + repr(got))
for name in ("filament-peerloop", "filament-transport"):
    got = cli["dependencies"][name].get("version")
    if got != "0.1.1":
        fail.append("cli " + name + " requirement " + repr(got))
    if "path" not in cli["dependencies"][name]:
        fail.append("cli " + name + " lost its path for the workspace build")

versions = {p.get("name"): p.get("version") for p in lock["package"]}
want = {"tunlion-peerloop": "0.1.1", "tunlion-transport": "0.1.1", "tunlion-lan": "0.1.0"}
for name, version in want.items():
    if versions.get(name) != version:
        fail.append("lock " + name + "=" + str(versions.get(name)))

print("cli", cli["package"]["version"],
      "transport", tr["package"]["version"],
      "peerloop", pl["package"]["version"],
      "lan", lan["package"]["version"])
print("lock", {n: versions.get(n) for n in want})
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
want = {
    "tunlion": "0.9.3",
    "tunlion-peerloop": "0.1.1",
    "tunlion-transport": "0.1.1",
    "tunlion-lan": "0.1.0",
}
for name, version in want.items():
    print(name, got.get(name))
    assert got.get(name) == version, (name, got.get(name), version)
print("OK metadata resolve")
PY

say "tests for the changed and new crates"
cargo test --locked -p tunlion-transport -p tunlion-peerloop -p tunlion-lan

say "package the four shipping crates without registry verification"
cargo package --locked --no-verify -p tunlion-lan -p tunlion-transport -p tunlion-peerloop -p tunlion
for crate in tunlion-lan-0.1.0 tunlion-transport-0.1.1 tunlion-peerloop-0.1.1 tunlion-0.9.3; do
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
lan = load(root + "/tunlion-lan-0.1.0/Cargo.toml")
lock = load(root + "/tunlion-0.9.3/Cargo.lock")

if cli["package"]["name"] != "tunlion":
    fail.append("packaged cli name " + cli["package"]["name"])
if tr["package"]["version"] != "0.1.1":
    fail.append("packaged transport version")
if pl["package"]["version"] != "0.1.1":
    fail.append("packaged peerloop version")
if lan["package"]["version"] != "0.1.0":
    fail.append("packaged lan version")

for crate, table in (("cli", cli), ("peerloop", pl), ("transport", tr), ("lan", lan)):
    for name, dep in table.get("dependencies", {}).items():
        if "path" in dep:
            fail.append(crate + " " + name + " still has a path")

for crate, table in (("cli", cli), ("peerloop", pl), ("transport", tr)):
    got = table["dependencies"]["tunlion-lan"].get("version")
    print("packaged", crate, "tunlion-lan", got)
    if got != "0.1.0":
        fail.append("packaged " + crate + " lan " + repr(got))
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
print("packaged cli lock", {n: versions.get(n) for n in
                            ("tunlion-peerloop", "tunlion-transport", "tunlion-lan")})
for name, version in (("tunlion-peerloop", "0.1.1"),
                      ("tunlion-transport", "0.1.1"),
                      ("tunlion-lan", "0.1.0")):
    if versions.get(name) != version:
        fail.append("packaged lock " + name + "=" + str(versions.get(name)))

if fail:
    print("FAIL", fail)
    sys.exit(1)
print("OK packaged manifests and lock")
PY

say "cargo publish dry run for tunlion-lan 0.1.0"
# transport, peerloop and cli depend on lan 0.1.0, which is not on crates.io
# yet, so their registry verification follows the lan publish, not this lease.
( cd crates/tunlion-lan && cargo publish --dry-run --allow-dirty )

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
echo "OK lock 0.1.1/0.1.0, metadata, packaged manifests (lan included, no path deps), lan dry run, install dry run"
