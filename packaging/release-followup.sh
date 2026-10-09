#!/usr/bin/env bash
# Post-release follow-up: after the cli-release workflow finishes for a tag,
# regenerate the Homebrew formula and winget manifests with the REAL release
# hashes. Usage:
#
#   packaging/release-followup.sh cli-v0.1.0
#
# Prints the rendered files into packaging/out/ and, if `gh` is authenticated:
#   - pushes the formula to Abdk4Moura/homebrew-tap
#   - prepares (and with --pr, opens) the winget-pkgs PR branch
set -euo pipefail
TAG="${1:?usage: release-followup.sh cli-vX.Y.Z [--pr]}"
OPEN_PR="${2:-}"
VERSION="${TAG#cli-v}"
# Release date for the winget manifest (the validation bot flags it missing
# otherwise, inconsistent with the published version). Overridable for replays.
RELEASE_DATE="${RELEASE_DATE:-$(date -u +%Y-%m-%d)}"
REPO="Abdk4Moura/tunlion"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"
mkdir -p "$OUT"

echo "fetching SHA256SUMS for $TAG ..."
SUMS=$(curl -fsSL "https://github.com/$REPO/releases/download/$TAG/SHA256SUMS")
# Exact-name match: SHA256SUMS lists every asset twice (tunlion-* and the
# pre-rename filament-* alias), so a suffix grep would return two hashes. The
# brew formula and winget manifest point at the tunlion-* assets.
sum_for() { echo "$SUMS" | awk -v f="tunlion-$1" '$2 == f || $2 == "*" f { print $1 }'; }
SHA_LINUX=$(sum_for x86_64-unknown-linux-musl.tar.gz)
SHA_MAC_ARM=$(sum_for aarch64-apple-darwin.tar.gz)
SHA_MAC_X64=$(sum_for x86_64-apple-darwin.tar.gz)
SHA_WINDOWS=$(sum_for x86_64-pc-windows-msvc.zip)
for v in SHA_LINUX SHA_MAC_ARM SHA_MAC_X64 SHA_WINDOWS; do
  [ -n "${!v}" ] || { echo "missing checksum: $v"; exit 1; }
done

render() { sed -e "s/@VERSION@/$VERSION/g" -e "s/@SHA_LINUX@/$SHA_LINUX/g" \
               -e "s/@SHA_MAC_ARM@/$SHA_MAC_ARM/g" -e "s/@SHA_MAC_X64@/$SHA_MAC_X64/g" \
               -e "s/@SHA_WINDOWS@/$SHA_WINDOWS/g" -e "s/@RELEASE_DATE@/$RELEASE_DATE/g" "$1"; }

# ------------------------------------------------------------------ homebrew
# The tap lives INSIDE this repo (Formula/) — no extra repo needed:
#   brew tap abdk4moura/tunlion https://github.com/Abdk4Moura/tunlion
#   brew install abdk4moura/tunlion/tunlion
# (If a dedicated Abdk4Moura/homebrew-tap repo exists, it is updated too.)
render "$HERE/brew/tunlion.rb.tmpl" > "$OUT/tunlion.rb"
ROOT="$(cd "$HERE/.." && pwd)"
mkdir -p "$ROOT/Formula"
cp "$OUT/tunlion.rb" "$ROOT/Formula/tunlion.rb"
echo "rendered Formula/tunlion.rb"
if gh auth status >/dev/null 2>&1; then
  # Commit the refreshed in-repo formula back to the default branch so the
  # secondary tap path (brew tap abdk4moura/tunlion <this repo>) doesn't lag.
  # This script runs in CI on a DETACHED, shallow tag checkout, so the local git
  # state can't push to the branch; use the Contents API. Idempotent: skip when
  # the branch already has this exact content. [skip ci] keeps the formula-only
  # commit from spinning up the full test matrix.
  DEFAULT_BRANCH=$(gh api "repos/$REPO" --jq .default_branch 2>/dev/null || echo main)
  local_b64=$(base64 "$OUT/tunlion.rb" | tr -d '\n')
  remote_b64=$(gh api "repos/$REPO/contents/Formula/tunlion.rb?ref=$DEFAULT_BRANCH" --jq .content 2>/dev/null | tr -d '\n' || true)
  cur_sha=$(gh api "repos/$REPO/contents/Formula/tunlion.rb?ref=$DEFAULT_BRANCH" --jq .sha 2>/dev/null || true)
  if [ "$local_b64" = "$remote_b64" ]; then
    echo "in-repo Formula/tunlion.rb already at $VERSION on $DEFAULT_BRANCH"
  elif gh api -X PUT "repos/$REPO/contents/Formula/tunlion.rb" \
         -f message="chore: sync in-repo Homebrew formula to $VERSION [skip ci]" \
         -f content="$local_b64" \
         -f branch="$DEFAULT_BRANCH" \
         ${cur_sha:+-f sha="$cur_sha"} >/dev/null; then
    echo "in-repo Formula/tunlion.rb synced to $VERSION on $DEFAULT_BRANCH"
  else
    echo "::warning::could not sync in-repo Formula/tunlion.rb to $DEFAULT_BRANCH (token may lack contents:write)"
  fi

  TAPDIR=$(mktemp -d)
  if gh repo clone Abdk4Moura/homebrew-tap "$TAPDIR" -- -q 2>/dev/null; then
    mkdir -p "$TAPDIR/Formula"
    cp "$OUT/tunlion.rb" "$TAPDIR/Formula/tunlion.rb"
    git -C "$TAPDIR" add Formula/tunlion.rb
    if ! git -C "$TAPDIR" diff --cached --quiet; then
      git -C "$TAPDIR" commit -q -m "tunlion $VERSION"
      git -C "$TAPDIR" push -q
      echo "homebrew-tap updated -> brew install abdk4moura/tap/tunlion"
    fi
  fi
  rm -rf "$TAPDIR"
fi

# -------------------------------------------------------------------- winget
WD="$OUT/winget/manifests/a/Abdk4Moura/Tunlion/$VERSION"
mkdir -p "$WD"
render "$HERE/winget/Abdk4Moura.Tunlion.yaml.tmpl" > "$WD/Abdk4Moura.Tunlion.yaml"
render "$HERE/winget/Abdk4Moura.Tunlion.installer.yaml.tmpl" > "$WD/Abdk4Moura.Tunlion.installer.yaml"
render "$HERE/winget/Abdk4Moura.Tunlion.locale.en-US.yaml.tmpl" > "$WD/Abdk4Moura.Tunlion.locale.en-US.yaml"
echo "rendered winget manifests under $WD"

if [ "$OPEN_PR" = "--pr" ] && gh auth status >/dev/null 2>&1; then
  WPDIR=$(mktemp -d)
  echo "forking + cloning microsoft/winget-pkgs (shallow) ..."
  gh repo fork microsoft/winget-pkgs --clone=false >/dev/null 2>&1 || true
  ME=$(gh api user --jq .login)
  git clone -q --depth 1 "https://github.com/$ME/winget-pkgs" "$WPDIR"
  BR="tunlion-$VERSION"
  git -C "$WPDIR" checkout -q -b "$BR"
  DEST="$WPDIR/manifests/a/Abdk4Moura/Tunlion/$VERSION"
  mkdir -p "$DEST"
  cp "$WD"/*.yaml "$DEST/"
  git -C "$WPDIR" add manifests
  git -C "$WPDIR" commit -q -m "New package: Abdk4Moura.Tunlion version $VERSION"
  git -C "$WPDIR" push -q -u origin "$BR"
  gh pr create --repo microsoft/winget-pkgs --head "$ME:$BR" \
    --title "New package: Abdk4Moura.Tunlion version $VERSION" \
    --body "Adds Abdk4Moura.Tunlion $VERSION (portable zip, x64). P2P file transfer CLI; binaries built and attested by GitHub Actions in https://github.com/$REPO. Validated against manifest schema 1.28.0."
  rm -rf "$WPDIR"
fi
echo "done."
