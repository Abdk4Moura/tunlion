#!/usr/bin/env bash
# Launch matrix orchestrator. Runs on a workstation; the CLI machines live on a
# lab host with docker (a GitHub Codespace by default), the browsers run here.
#
#   LAB_HOST="gh codespace ssh -c <codespace> --" lab/matrix/run.sh <tunlion-binary> <outdir> [cli|browser|all] [cell-regex]
#
# The binary must be a static Linux build (rbuild output). Results land in
# <outdir>/matrix.json and <outdir>/matrix.md, evidence under <outdir>/ev.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
BIN="${1:?binary}"; OUT="${2:?outdir}"; WHAT="${3:-all}"; FILTER="${4:-.}"
: "${LAB_HOST:?set LAB_HOST to the command that runs a shell command on the lab host}"
: "${CODESPACE:=}"
mkdir -p "$OUT"
sha=$(sha256sum "$BIN" | cut -c1-12)
echo "binary sha256 $sha" | tee "$OUT/binary.txt"
"$BIN" --version | tee -a "$OUT/binary.txt" || true

lab() { $LAB_HOST "$*"; }
push() { # <local> <remote-path-under-home>
  if [ -n "$CODESPACE" ]; then gh codespace cp -e -c "$CODESPACE" "$1" "remote:$2"; else
    $LAB_HOST "cat > $2" < "$1"; fi
}
lab "rm -rf ~/matrix && mkdir -p ~/matrix/ctx ~/matrix/out"
for f in box.sh cli-cells.sh ctx/Dockerfile; do push "$here/$f" "/home/codespace/matrix/$f"; done
push "$BIN" /home/codespace/matrix/tunlion.bin
lab "chmod +x ~/matrix/*.sh && ~/matrix/box.sh build ~/matrix/tunlion.bin"
if [ "$WHAT" = cli ] || [ "$WHAT" = all ]; then
  lab "~/matrix/cli-cells.sh ~/matrix/out '$FILTER'" | tee "$OUT/cli-console.txt" || true
  lab "cd ~/matrix/out && tar czf - ." | tar xzf - -C "$OUT"
fi
if [ "$WHAT" = browser ] || [ "$WHAT" = all ]; then
  node "$here/browser/cells.cjs" "$OUT" "$FILTER" | tee "$OUT/browser-console.txt" || true
  node "$here/browser/dashboard-cells.cjs" "$OUT" "$FILTER" | tee "$OUT/dashboard-console.txt" || true
fi
python3 "$here/render.py" "$OUT" "$sha"
