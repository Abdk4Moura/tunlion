## Install

**Linux / macOS** (verifies checksums, installs to `~/.local/bin`, no sudo):
```
curl -fsSL https://filament.autumated.com/install | sh
```

**Windows:**
```
winget install Abdk4Moura.Filament
```

**Homebrew:** `brew install abdk4moura/tap/filament` · **Cargo:** `cargo install filament-cli`

Already installed? `filament update`

## Quick start
```
filament send video.mp4 --code      # speak the code aloud
filament receive clever-lynx-63     # …or open filament.autumated.com in any browser
```

All binaries are checksummed (SHA256SUMS) and carry GitHub build
provenance attestations. The Linux binary is fully static (musl).
