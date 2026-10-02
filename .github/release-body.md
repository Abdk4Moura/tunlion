## Install

**Linux / macOS** (verifies checksums, installs to `~/.local/bin`, no sudo):
```
curl -fsSL https://tunlion.autumated.com/install | sh
```

**Windows:**
```
winget install Abdk4Moura.Tunlion
```

**Homebrew:** `brew install abdk4moura/tap/tunlion` · **Cargo:** `cargo install filament-cli`

Already installed? `tunlion update`

## Quick start
```
tunlion send video.mp4 --code      # speak the code aloud
tunlion receive clever-lynx-63     # …or open tunlion.autumated.com in any browser
```

All binaries are checksummed (SHA256SUMS) and carry GitHub build
provenance attestations. The Linux binary is fully static (musl).
