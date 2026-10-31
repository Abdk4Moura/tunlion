#!/usr/bin/env bash
# Registry verification after tunlion-signal 0.1.1:
#   1. a real crates.io consumer of published transport 0.1.1 resolves
#      signal 0.1.1 and compiles it, with no path source
#   2. the packaged peerloop 0.1.1 verifies against published signal 0.1.1,
#      transport 0.1.1 and lan 0.1.0, with no path masking
set -euo pipefail

WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
exec 9>"$WORK/build.lock"
flock -w 1800 9

export CARGO_TERM_COLOR=never
export CARGO_TARGET_DIR="$WORK/target"
umask 077

say() { printf '\n== %s\n' "$*"; }

say "lease head (expected release commit 160c3948201813cfe584e9fec40e244d6a2be36a)"
git rev-parse HEAD
git log --oneline -2

say "published versions visible in the sparse index"
for crate in tunlion-signal tunlion-transport tunlion-lan; do
  case "$crate" in
    tunlion-signal) want=0.1.1 ;;
    tunlion-transport) want=0.1.1 ;;
    tunlion-lan) want=0.1.0 ;;
  esac
  ok=0
  for i in $(seq 1 24); do
    if curl -fsS -A "tunlion-lease" "https://index.crates.io/tu/nl/$crate" | grep -q "\"vers\":\"$want\""; then ok=1; break; fi
    sleep 5
  done
  [ "$ok" = "1" ] || { echo "missing $crate $want"; exit 1; }
  echo "$crate $want visible"
done
if curl -fsS -A "tunlion-lease" https://index.crates.io/tu/nl/tunlion-peerloop | grep -q '"vers":"0.1.1"'; then
  echo "peerloop 0.1.1 already present"; exit 1
fi
echo "peerloop 0.1.1 absent as expected"

say "registry consumer: published transport 0.1.1 against signal 0.1.1"
CONSUMER="$WORK/consumer"
rm -rf "$CONSUMER"
mkdir -p "$CONSUMER/src"
cat > "$CONSUMER/Cargo.toml" <<'TOML'
[package]
name = "tunlion-registry-consumer"
version = "0.0.0"
edition = "2021"

[dependencies]
tunlion-transport = "=0.1.1"
tunlion-lan = "=0.1.0"

[workspace]
TOML
printf 'fn main() {}\n' > "$CONSUMER/src/main.rs"
( cd "$CONSUMER" && cargo generate-lockfile )
( cd "$CONSUMER" && cargo metadata --format-version 1 > "$WORK/consumer-meta.json" )
python3 - <<'PY'
import json
meta = json.load(open("/home/runner/work/_temp/tunlion-work/consumer-meta.json"))
got = {p["name"]: p for p in meta["packages"]}
for name, version in (("tunlion-transport", "0.1.1"),
                      ("tunlion-signal", "0.1.1"),
                      ("tunlion-lan", "0.1.0")):
    p = got.get(name)
    print(name, p and p.get("version"), "source", p and p.get("source"))
    assert p, name
    assert p["version"] == version, (name, p["version"])
    assert p.get("source"), name + " resolved without a registry source"
    assert p["source"].startswith("registry+"), (name, p["source"])
print("OK consumer resolves published registry packages, no path sources")
PY
( cd "$CONSUMER" && cargo build )
echo "OK published transport 0.1.1 compiled against registry signal 0.1.1"

say "packaged peerloop verification against registry dependencies"
( cd crates/filament-peerloop && cargo publish --dry-run --allow-dirty 2>&1 | tee "$WORK/peerloop-dryrun.log" )

say "packaged manifest and lock"
python3 - <<'PY'
import tomllib

root = "/home/runner/work/_temp/tunlion-work/target/package/tunlion-peerloop-0.1.1"
t = tomllib.load(open(root + "/Cargo.toml", "rb"))
print("packaged peerloop", t["package"]["version"])
assert t["package"]["version"] == "0.1.1"
for name in ("filament-signal", "filament-transport", "tunlion-lan"):
    d = t["dependencies"][name]
    print("packaged dep", name, d)
    assert "path" not in d, (name, d)
assert t["dependencies"]["filament-signal"].get("version") == "0.1.1"
assert t["dependencies"]["filament-transport"].get("version") == "0.1.1"
assert t["dependencies"]["tunlion-lan"].get("version") == "0.1.0"
lock = {p.get("name"): p.get("version") for p in
        tomllib.load(open(root + "/Cargo.lock", "rb"))["package"]}
print("packaged lock", {n: lock.get(n) for n in
                        ("tunlion-signal", "tunlion-transport", "tunlion-lan")})
assert lock.get("tunlion-signal") == "0.1.1"
assert lock.get("tunlion-transport") == "0.1.1"
assert lock.get("tunlion-lan") == "0.1.0"
print("OK packaged manifest and lock use registry requirements")
PY

say "no path-source compiles in the dry run"
if grep -qE 'Compiling tunlion-(signal|transport|lan) v[0-9.]+ \(' "$WORK/peerloop-dryrun.log"; then
  echo "FAIL path source in dry run"
  grep -E 'Compiling tunlion-(signal|transport|lan)' "$WORK/peerloop-dryrun.log"
  exit 1
fi
grep -E 'Compiling tunlion-(signal|transport|lan) ' "$WORK/peerloop-dryrun.log" | head -3
echo "OK registry sources only"

say "SUMMARY"
echo "OK consumer transport 0.1.1 + signal 0.1.1 + lan 0.1.0 from registry, peerloop 0.1.1 packaged lock and manifest use registry versions, dry run aborted before upload"
