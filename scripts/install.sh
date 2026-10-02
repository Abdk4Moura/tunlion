#!/bin/sh
# tunlion installer — https://tunlion.autumated.com/install
#
#   curl -fsSL https://tunlion.autumated.com/install | sh
#
# Detects your platform, downloads the latest release binary from GitHub,
# verifies its SHA-256 against the release's SHA256SUMS, and installs to
# ~/.local/bin (override with FILAMENT_INSTALL_DIR). No sudo, no telemetry,
# fully static binary on Linux. Source: scripts/install.sh in
# https://github.com/Abdk4Moura/tunlion
set -eu

REPO="Abdk4Moura/tunlion"
INSTALL_DIR="${FILAMENT_INSTALL_DIR:-$HOME/.local/bin}"

say() { printf '\033[1mtunlion:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31mtunlion:\033[0m %s\n' "$*" >&2; exit 1; }

# ----------------------------------------------------------- platform detect
OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
  Linux)  case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-musl" ;;
            *) die "no prebuilt binary for Linux/$ARCH yet — build from source: cargo install filament-cli" ;;
          esac ;;
  Darwin) case "$ARCH" in
            arm64)  TARGET="aarch64-apple-darwin" ;;
            x86_64) TARGET="x86_64-apple-darwin" ;;
            *) die "no prebuilt binary for macOS/$ARCH" ;;
          esac ;;
  MINGW*|MSYS*|CYGWIN*) die "on Windows use:  winget install Abdk4Moura.Tunlion" ;;
  *) die "unsupported OS: $OS" ;;
esac
# Releases cut before the rename ship `filament-<target>`; everything from the
# first post-rename release ships `tunlion-<target>`. Try the new name and fall
# back, so this installer works against BOTH and never has a window where the
# documented one-liner is broken.
ASSET="tunlion-$TARGET.tar.gz"
LEGACY_ASSET="filament-$TARGET.tar.gz"

# ------------------------------------------------------------------ download
command -v curl >/dev/null || die "curl is required"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# /releases/latest redirects to the newest release; CLI releases are tagged
# cli-vX.Y.Z, so resolve the newest cli-v* tag via the API (no auth needed).
# Stable tags are digits-and-dots only; prereleases (cli-v0.2.1-beta.1) are
# skipped unless the caller opts in with FILAMENT_CHANNEL=beta. Fetch once.
RELEASES=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=20") \
  || die "could not reach the GitHub releases API"
# Highest version, NOT first listed — the API's order is not newest-tag-first
# (observed live). sort -V orders 0.2.0 < 0.2.1-beta.1 < 0.2.1 correctly.
pick_tag() { printf '%s\n' "$RELEASES" | grep -o "$1" | cut -d'"' -f4 | sort -V | tail -n 1; }

if [ "${FILAMENT_CHANNEL:-stable}" = "beta" ]; then
  TAG=$(pick_tag '"tag_name": *"cli-v[^"]*"')
else
  TAG=$(pick_tag '"tag_name": *"cli-v[0-9.]*"')
  # No stable release yet (beta period): fall back to the newest prerelease so
  # the default installer still works, with a clear notice. Once a stable exists
  # it is preferred automatically.
  if [ -z "$TAG" ]; then
    TAG=$(pick_tag '"tag_name": *"cli-v[^"]*"')
    [ -n "$TAG" ] && say "no stable release yet; installing prerelease $TAG (FILAMENT_CHANNEL=beta to silence)"
  fi
fi
[ -n "$TAG" ] || die "could not find a CLI release"
BASE="https://github.com/$REPO/releases/download/$TAG"

say "downloading tunlion $TAG for $TARGET ..."
if ! curl -fsSL "$BASE/$ASSET" -o "$TMP/$ASSET" 2>/dev/null; then
  curl -fsSL "$BASE/$LEGACY_ASSET" -o "$TMP/$LEGACY_ASSET" \
    || die "no asset $ASSET or $LEGACY_ASSET in $TAG"
  ASSET="$LEGACY_ASSET"
  say "using the pre-rename asset name for $TAG"
fi
curl -fsSL "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"

# -------------------------------------------------------------------- verify
if command -v sha256sum >/dev/null; then
  GOT=$(sha256sum "$TMP/$ASSET" | cut -d' ' -f1)
elif command -v shasum >/dev/null; then
  GOT=$(shasum -a 256 "$TMP/$ASSET" | cut -d' ' -f1)
else
  die "need sha256sum or shasum to verify the download"
fi
WANT=$(grep "$ASSET" "$TMP/SHA256SUMS" | cut -d' ' -f1)
[ "$GOT" = "$WANT" ] || die "checksum mismatch (got $GOT, want $WANT) — aborting"
say "checksum verified"

# ------------------------------------------------------------------- install
mkdir -p "$INSTALL_DIR"
tar -xzf "$TMP/$ASSET" -C "$TMP"
# The archive holds `tunlion` after the rename and `filament` before it.
if [ -f "$TMP/tunlion" ]; then SRC="$TMP/tunlion"; else SRC="$TMP/filament"; fi
[ -f "$SRC" ] || die "archive $ASSET contained neither tunlion nor filament"
install -m 755 "$SRC" "$INSTALL_DIR/tunlion"
# Keep the old command name working. Anyone who installed before the rename has
# scripts, aliases and a systemd unit calling `filament`; the rename should cost
# them nothing.
ln -sf tunlion "$INSTALL_DIR/filament"
say "installed $INSTALL_DIR/tunlion ($("$INSTALL_DIR/tunlion" --version 2>/dev/null || echo "$TAG"))"
say 'filament still works; it is a symlink to tunlion'

# man page (best effort, never fatal)
if command -v man >/dev/null 2>&1; then
  MANDIR="${XDG_DATA_HOME:-$HOME/.local/share}/man/man1"
  mkdir -p "$MANDIR" 2>/dev/null && \
    "$INSTALL_DIR/tunlion" man > "$MANDIR/tunlion.1" 2>/dev/null && \
    say "installed man page to $MANDIR/tunlion.1 (try \`man tunlion\`)" || true
  # Refresh man index (best effort)
  mandb -q 2>/dev/null || makewhatis 2>/dev/null || true
fi

# shell completions (best effort, never fatal)
if [ -n "${BASH_VERSION:-}" ] || [ -f "$HOME/.bashrc" ]; then
  mkdir -p "$HOME/.local/share/bash-completion/completions" 2>/dev/null && \
    "$INSTALL_DIR/tunlion" completions bash > "$HOME/.local/share/bash-completion/completions/tunlion" 2>/dev/null || true
fi
if command -v zsh >/dev/null; then
  mkdir -p "$HOME/.zfunc" 2>/dev/null && \
    "$INSTALL_DIR/tunlion" completions zsh > "$HOME/.zfunc/_tunlion" 2>/dev/null || true
fi
if [ -d "$HOME/.config/fish" ]; then
  mkdir -p "$HOME/.config/fish/completions" 2>/dev/null && \
    "$INSTALL_DIR/tunlion" completions fish > "$HOME/.config/fish/completions/tunlion.fish" 2>/dev/null || true
fi

# PATH hint
case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say "note: $INSTALL_DIR is not on your PATH — add:  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac

say ""
say "try it:   tunlion send <file> --code"
say "          (the other end can be a terminal — or any browser at https://tunlion.autumated.com)"
