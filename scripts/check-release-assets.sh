#!/usr/bin/env bash
# Release asset hygiene check (issue #151).
#
# The GitHub release must carry EXACTLY the four platform artifacts, each
# under its tunlion name AND its pre-rename filament alias, plus SHA256SUMS.
# The filament-* aliases are a frozen protocol literal: released 0.8.x
# `filament update` downloads exactly those names (see cli-release.yml).
# Nothing more, nothing less. A repo-root file named tunlion-* or filament-*
# (a dated session doc, a decoy, anything) must not ride along into a release,
# and a missing artifact must abort the tag.
#
# Why a strict set: the release job globs `tunlion-*`, which is correct only
# when the assembled directory contains nothing else. When the repo tree is in
# the same working directory (actions/checkout for changelog-driven notes), the
# glob silently widens. The check pins the set so a future directory rename or
# a new root-level `tunlion-*` file cannot widen it again invisibly.
#
# Usage: check-release-assets.sh [DIR]
#   DIR defaults to dist/. Exits 1 on any unexpected file or any missing file.
set -euo pipefail

DIR="${1:-dist}"
EXPECTED=(
  tunlion-aarch64-apple-darwin.tar.gz
  tunlion-x86_64-apple-darwin.tar.gz
  tunlion-x86_64-unknown-linux-musl.tar.gz
  tunlion-x86_64-pc-windows-msvc.zip
  filament-aarch64-apple-darwin.tar.gz
  filament-x86_64-apple-darwin.tar.gz
  filament-x86_64-unknown-linux-musl.tar.gz
  filament-x86_64-pc-windows-msvc.zip
)

missing=0
for f in "${EXPECTED[@]}"; do
  if [[ ! -f "$DIR/$f" ]]; then
    echo "check-release-assets: FAIL: missing $f" >&2
    missing=1
  fi
done
if [[ ! -f "$DIR/SHA256SUMS" ]]; then
  echo "check-release-assets: FAIL: missing SHA256SUMS" >&2
  missing=1
fi
if [[ "$missing" = 1 ]]; then
  exit 1
fi

extra=0
for path in "$DIR"/*; do
  [[ -f "$path" ]] || continue
  base="${path##*/}"
  if [[ "$base" == "SHA256SUMS" ]]; then
    continue
  fi
  ok=0
  for e in "${EXPECTED[@]}"; do
    [[ "$base" == "$e" ]] && ok=1
  done
  if [[ "$ok" != 1 ]]; then
    echo "check-release-assets: FAIL: unexpected asset $base" >&2
    extra=1
  fi
done
if [[ "$extra" = 1 ]]; then
  exit 1
fi

echo "check-release-assets: PASS: exactly the 4 platform artifacts (tunlion + filament alias) plus SHA256SUMS"
