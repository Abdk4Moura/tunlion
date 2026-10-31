#!/usr/bin/env bash
# Verify the actual packaged tunlion 0.9.3 crate against published registry
# dependencies, including its shipped lockfile, then build it in an isolated
# install root. No workspace path resolution, no local patches.
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

say "published dependency versions visible in the sparse index"
for crate in tunlion-signal tunlion-transport tunlion-peerloop tunlion-lan; do
  case "$crate" in
    tunlion-signal) want=0.1.1 ;;
    tunlion-transport) want=0.1.1 ;;
    tunlion-peerloop) want=0.1.1 ;;
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

say "packaged CLI: cargo publish --dry-run"
( cd cli && cargo publish --dry-run --allow-dirty 2>&1 | tee "$WORK/cli-dryrun.log" )

say "packaged manifest and lock use registry versions"
python3 - <<'PY'
import tomllib

root = "/home/runner/work/_temp/tunlion-work/target/package/tunlion-0.9.3"
t = tomllib.load(open(root + "/Cargo.toml", "rb"))
print("packaged cli", t["package"]["name"], t["package"]["version"])
assert t["package"]["name"] == "tunlion"
assert t["package"]["version"] == "0.9.3"
want = {
    "filament-signal": ("tunlion-signal", "0.1.1"),
    "filament-transport": ("tunlion-transport", "0.1.1"),
    "filament-peerloop": ("tunlion-peerloop", "0.1.1"),
    "tunlion-lan": ("tunlion-lan", "0.1.0"),
}
for key, (name, version) in want.items():
    dep = t["dependencies"][key]
    print("packaged dep", key, dep)
    assert "path" not in dep, (key, dep)
    assert dep.get("version") == version, (key, dep.get("version"))
    if "package" in dep:
        assert dep["package"] == name, (key, dep["package"])

lock = tomllib.load(open(root + "/Cargo.lock", "rb"))
by_name = {}
for p in lock["package"]:
    if p.get("name") in ("tunlion-signal", "tunlion-transport",
                         "tunlion-peerloop", "tunlion-lan"):
        by_name[p["name"]] = p
for name, version in (("tunlion-signal", "0.1.1"),
                      ("tunlion-transport", "0.1.1"),
                      ("tunlion-peerloop", "0.1.1"),
                      ("tunlion-lan", "0.1.0")):
    p = by_name.get(name)
    print("packaged lock", name, p and p.get("version"), "source", p and p.get("source"),
          "checksum", (p and p.get("checksum", ""))[:12])
    assert p, name
    assert p["version"] == version, (name, p["version"])
    assert p.get("source") == "registry+https://github.com/rust-lang/crates.io-index", (name, p.get("source"))
    assert p.get("checksum"), name + " has no checksum"
print("OK packaged manifest and lock resolve from the registry")
PY

say "no path-source compiles in the CLI dry run"
if grep -qE 'Compiling (tunlion|filament)-(signal|transport|peerloop|lan) v[0-9.]+ \(' "$WORK/cli-dryrun.log"; then
  echo "FAIL path source in CLI dry run"
  grep -E 'Compiling (tunlion|filament)-(signal|transport|peerloop|lan)' "$WORK/cli-dryrun.log"
  exit 1
fi
grep -E 'Compiling (tunlion|filament)-(signal|transport|peerloop|lan) ' "$WORK/cli-dryrun.log" | head -4
echo "OK registry sources only"

say "isolated install root from the packaged crate"
PKG="$WORK/cli-pkg"
rm -rf "$PKG" "$WORK/cli-prefix"
mkdir -p "$PKG"
tar -xzf "$CARGO_TARGET_DIR/package/tunlion-0.9.3.crate" -C "$PKG"
cargo install --path "$PKG/tunlion-0.9.3" --locked --root "$WORK/cli-prefix" --debug --force
VERSION_OUT="$("$WORK/cli-prefix/bin/tunlion" --version)"
echo "installed version: $VERSION_OUT"
case "$VERSION_OUT" in
  "tunlion 0.9.3"*) ;;
  *) echo "unexpected version output"; exit 1 ;;
esac

say "SUMMARY"
echo "OK packaged tunlion 0.9.3: registry manifest and lock (signal/transport/peerloop 0.1.1, lan 0.1.0), dry-run compile, isolated install printed $VERSION_OUT"
