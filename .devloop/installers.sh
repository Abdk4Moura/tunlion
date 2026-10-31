#!/usr/bin/env bash
# Clean-HOME install checks for npm tunlion 0.9.3 and the curl installer.
# No service is started and no existing identity or config is used.
set -euo pipefail

WORK=/home/runner/work/_temp/tunlion-work
mkdir -p "$WORK"
exec 9>"$WORK/build.lock"
flock -w 1800 9

umask 077
say() { printf '\n== %s\n' "$*"; }

say "lease head (expected release commit 160c3948201813cfe584e9fec40e244d6a2be36a)"
git rev-parse HEAD
git log --oneline -2

say "npm registry version 0.9.3"
for i in $(seq 1 24); do
  if curl -fsS -A "tunlion-lease" https://registry.npmjs.org/tunlion/0.9.3 > "$WORK/npm-meta.json"; then break; fi
  sleep 5
done
python3 - <<'PY'
import json
d=json.load(open("/home/runner/work/_temp/tunlion-work/npm-meta.json"))
print("npm", d["name"], d["version"], "shasum", d["dist"]["shasum"])
assert d["name"]=="tunlion" and d["version"]=="0.9.3"
PY

say "default npm global prefix writability (documentation only, no sudo)"
PREFIX=$(npm config get prefix)
GROOT=$(npm root -g)
echo "default prefix: $PREFIX"
echo "default global root: $GROOT"
if [ -w "$GROOT" ]; then
  echo "default global root is writable for this user; no EACCES case here"
else
  echo "default global root is not writable; a system-wide npm install would fail EACCES. User prefix is the supported path; sudo is not suggested."
fi

say "clean HOME npm global install into an unprivileged user prefix"
ISO="$WORK/npm-iso"
rm -rf "$ISO"
mkdir -p "$ISO/home" "$ISO/prefix" "$ISO/config"
export HOME="$ISO/home"
export npm_config_prefix="$ISO/prefix"
( cd "$ISO" && npm install -g --foreground-scripts tunlion@0.9.3 2>&1 | tee "$WORK/npm-install.log" )
if grep -q 'cli-v0.9.3' "$WORK/npm-install.log"; then
  echo "postinstall reported cli-v0.9.3"
else
  echo "postinstall output not shown by npm; verifying installed files instead"
fi
node -p "require('$ISO/prefix/lib/node_modules/tunlion/package.json').version" | tee "$WORK/npm-pkg-version.txt"
grep -qx '0.9.3' "$WORK/npm-pkg-version.txt"
test -x "$ISO/prefix/lib/node_modules/tunlion/vendor/tunlion" || { echo "vendor binary missing"; ls -l "$ISO/prefix/lib/node_modules/tunlion" ; exit 1; }
if npm list -g --depth=0 2>/dev/null | grep -qE 'tunlion@0\.9\.3'; then
  echo "npm list shows tunlion@0.9.3"
else
  echo "installed npm version mismatch"; npm list -g --depth=0 2>&1 | head -5; exit 1
fi

say "npm binary version, tl shortcut, help"
"$ISO/prefix/bin/tunlion" --version | tee "$WORK/npm-version.txt"
grep -q '^tunlion 0\.9\.3' "$WORK/npm-version.txt"
"$ISO/prefix/bin/tl" --version | tee "$WORK/npm-tl-version.txt"
grep -q '^tunlion 0\.9\.3' "$WORK/npm-tl-version.txt"
"$ISO/prefix/bin/tunlion" --help > "$WORK/npm-help.txt" 2>&1
grep -qi 'usage' "$WORK/npm-help.txt"

say "npm isolated status with no existing configuration"
set +e
TUNLION_CONFIG_DIR="$ISO/config" "$ISO/prefix/bin/tunlion" status --json > "$WORK/npm-status.json" 2> "$WORK/npm-status.err"
npm_status_rc=$?
set -e
echo "status exit=$npm_status_rc"
python3 - <<'PY'
import json
d=json.load(open("/home/runner/work/_temp/tunlion-work/npm-status.json"))
print("status ok", d.get("ok"), "verb", d.get("verb"), "error", (d.get("error") or {}).get("code"))
assert isinstance(d, dict) and d.get("verb")=="status"
PY
if pgrep -f "$ISO/prefix/bin/tunlion" >/dev/null 2>&1; then
  echo "unexpected background process from npm binary"; exit 1
fi

say "clean HOME curl installer"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
echo "tl already on PATH: $(command -v tl || echo none)"
ISO2="$WORK/curl-iso"
rm -rf "$ISO2"
mkdir -p "$ISO2/home" "$ISO2/config"
( cd "$ISO2" && HOME="$ISO2/home" sh -c 'curl -fsSL https://tunlion.autumated.com/install | sh' 2>&1 | tee "$WORK/curl-install.log" )
BIN2="$ISO2/home/.local/bin/tunlion"
test -x "$BIN2" || { echo "installer did not install tunlion"; exit 1; }
"$BIN2" --version | tee "$WORK/curl-version.txt"
grep -q '^tunlion 0\.9\.3' "$WORK/curl-version.txt"
"$ISO2/home/.local/bin/tl" --version | tee "$WORK/curl-tl-version.txt"
grep -q '^tunlion 0\.9\.3' "$WORK/curl-tl-version.txt"
"$ISO2/home/.local/bin/tl" --help > "$WORK/curl-help.txt" 2>&1
grep -qi 'usage' "$WORK/curl-help.txt"

say "curl isolated status with no existing configuration"
set +e
HOME="$ISO2/home" TUNLION_CONFIG_DIR="$ISO2/config" "$BIN2" status --json > "$WORK/curl-status.json" 2> "$WORK/curl-status.err"
curl_status_rc=$?
set -e
echo "status exit=$curl_status_rc"
python3 - <<'PY'
import json
d=json.load(open("/home/runner/work/_temp/tunlion-work/curl-status.json"))
print("status ok", d.get("ok"), "verb", d.get("verb"), "error", (d.get("error") or {}).get("code"))
assert isinstance(d, dict) and d.get("verb")=="status"
PY
if pgrep -f "$ISO2/home/.local/bin/tunlion" >/dev/null 2>&1; then
  echo "unexpected background process from installer binary"; exit 1
fi

say "no tunlion daemon was started"
if pgrep -af 'tunlion (up|serve|daemon)' >/dev/null 2>&1; then
  echo "unexpected tunlion daemon"; pgrep -af 'tunlion (up|serve|daemon)'; exit 1
fi
echo "no tunlion daemon process"

say "SUMMARY"
echo "OK npm tunlion 0.9.3 user-prefix install, tl shortcut, help, isolated status (exit $npm_status_rc); curl installer 0.9.3, tl shortcut, help, isolated status (exit $curl_status_rc); no service started"
