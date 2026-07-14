# @abdk4moura/filament-cli

Send files and reach your devices, peer to peer. No upload, no account.

```sh
npm i -g @abdk4moura/filament-cli
filament send video.mp4 --code
```

The other end can be a terminal **or any browser** at
[filament.autumated.com](https://filament.autumated.com) — nothing to install on
the receiving device. Pair your machines once and you can also `filament <device>`
(shell in), `filament expose <port>`, or `filament mount` across the internet.

This package downloads the prebuilt, checksum-verified binary for your platform
(Linux x64, macOS arm64/x64, Windows x64) from the matching GitHub release on
install. Prefer another route? `cargo install filament-cli`, `brew install
abdk4moura/tap/filament`, `winget install Abdk4Moura.Filament`, or
`curl -fsSL https://filament.autumated.com/install | sh`.

Source & docs: <https://github.com/Abdk4Moura/filament>
