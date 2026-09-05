#!/usr/bin/env bash
# Where does `filament` spend its startup?
#
# WHY AN INSTRUMENT AND NOT A GUESS. Startup cost is dominated by whichever of
# these your machine is worst at, and they differ by an order of magnitude
# between boxes: faulting a ~30MB binary in from cold storage, the dynamic
# loader relocating it, an antivirus or notarisation check on first exec
# (macOS Gatekeeper and Windows Defender both scan a large unsigned binary and
# both cache the result, which is exactly why the FIRST run is slow and the
# rest are not), building the tokio runtime, and only then the command's own
# work. A number from someone else's laptop tells you nothing about yours.
#
# COLD vs WARM is the whole measurement. Warm runs read the binary from page
# cache and will look instant even on a machine where the first run takes
# seconds. This script evicts the binary from the page cache before each cold
# sample (posix_fadvise DONTNEED, so it does not disturb the rest of the
# system the way dropping all caches would).
#
# Usage:  experiments/startup-bench.sh [path-to-filament] [samples]
set -uo pipefail
BIN=${1:-$(command -v filament || echo "$HOME/.local/bin/filament")}
N=${2:-10}
[ -x "$BIN" ] || { echo "no filament binary at $BIN"; exit 2; }

EVICT=$(mktemp /tmp/evict-XXXX.py)
cat > "$EVICT" <<'PY'
import os, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY)
    os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    os.close(fd)
except Exception:
    # Not fatal: on a platform without fadvise the cold column simply reads warm,
    # and the script says so rather than reporting a cold number it did not take.
    sys.exit(3)
PY
trap 'rm -f "$EVICT"' EXIT

python3 "$EVICT" "$BIN" 2>/dev/null
COLD_OK=$?
[ "$COLD_OK" = "0" ] || echo "  note: cannot evict page cache here; 'cold' figures below are NOT cold"

size=$(wc -c < "$BIN")
printf 'binary: %s  (%.1f MB)\n' "$BIN" "$(echo "$size/1048576" | bc -l)"
printf 'samples: %s\n\n' "$N"

# Median, not mean: one scheduler hiccup should not move the headline number.
median() { sort -n | awk '{v[NR]=$1} END {print (NR%2) ? v[(NR+1)/2] : (v[NR/2]+v[NR/2+1])/2}'; }

run_one() { # $1=cold|warm  $2...=args
  local mode="$1"; shift
  local t0 t1
  [ "$mode" = "cold" ] && python3 "$EVICT" "$BIN" 2>/dev/null
  t0=$(date +%s%N)
  "$BIN" "$@" >/dev/null 2>&1
  t1=$(date +%s%N)
  echo "scale=1; ($t1 - $t0)/1000000" | bc
}

printf '%-22s %10s %10s\n' "command" "cold(ms)" "warm(ms)"
printf '%-22s %10s %10s\n' "----------------------" "--------" "--------"
for cmd in "--version" "--help" "" "devices" "id" "status"; do
  cold=$(for _ in $(seq 1 "$N"); do run_one cold $cmd; done | median)
  warm=$(for _ in $(seq 1 "$N"); do run_one warm $cmd; done | median)
  printf '%-22s %10s %10s\n' "${cmd:-<bare>}" "$cold" "$warm"
done

echo
echo "Reading this:"
echo "  cold >> warm            the cost is getting the BINARY in (size, disk, or a scanner)."
echo "  cold ~= warm, both high the cost is what the process DOES at startup."
echo "  both low here but slow  something outside this script: a scanner on first exec,"
echo "                          a slow \$HOME (network mount), or a shell/PATH lookup."
