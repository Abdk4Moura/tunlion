# Tunlion

> **Tunlion is now Tunlion.** Same project, same people, new name. The old name
> collided with [Tunlion](https://tunlionphp.com) the Laravel admin panel, which
> owns the search results, so this one is ours alone.
>
> `tunlion.autumated.com` redirects here and old GitHub links redirect to this repo,
> so nothing you have bookmarked breaks. The published `filament-cli` crate and the
> `cli-v0.8.5` release assets keep working unchanged; new releases ship under the new
> name. **`api.filament.autumated.com` is deliberately unchanged** and stays up: every
> binary already installed points at it.

**Live: [tunlion.autumated.com](https://tunlion.autumated.com)** — send files and reach your devices, peer to peer. No upload, no size cap, no account.

Tunlion started as the file transfer nothing else does: the **receiving end needs nothing installed** — it can be any browser, on any phone or laptop. That still holds. But the same crypto-addressed link that carries a file also lets you **shell into your machines, forward a port, or mount a folder** across the internet. One tool, one identity, your devices meshed.

Files and streams travel **peer to peer** (WebRTC data channel in the browser, direct QUIC between terminals). The server only helps the two ends find each other — it never sees a byte.

![tunlion demo: send with a speakable code + QR, receive in another terminal, remembered devices](docs/launch/demo.gif)

## Install

Runs on **Linux, macOS, and Windows** (all first-class), or use it with **nothing installed** in a browser.

```sh
# Linux / macOS — curl | sh
curl -fsSL https://tunlion.autumated.com/install | sh

# Windows — PowerShell one-liner
irm https://tunlion.autumated.com/install.ps1 | iex
```

Or a package manager:

| Manager | Command |
|---|---|
| **winget** (Windows) | `winget install Abdk4Moura.Tunlion` |
| **Homebrew** (macOS/Linux) | `brew install abdk4moura/tap/tunlion` |
| **Cargo** (Rust) | `cargo install filament-cli` |
| **npm** (Node) | `npm i -g @abdk4moura/filament-cli` |

Every prebuilt binary is checksummed against the release `SHA256SUMS` and carries a GitHub build-provenance attestation. `tunlion update` self-updates a direct install and defers to your package manager when it manages the binary. Or skip all of it and open **[tunlion.autumated.com](https://tunlion.autumated.com)** on both devices.

## Send a file

```sh
tunlion send video.mp4 --code       # speak the code aloud
tunlion receive clever-lynx-63      # …or open the website on the other device

tunlion add --name phone            # remember a device (no file needed)
tunlion up --install                # receive in the background (always-on service)
```

- **The other end can be a browser** — your wife's phone with nothing installed opens a URL and taps accept.
- **Speakable one-time codes** burn on first use — an overheard code is worthless.
- **Resumable**: transfers survive process restarts and verify by content hash.
- **Route transparency**: every transfer shows whether bytes went `direct over wl1`, `direct over tailscale0`, or `relay` — you can see what your data did.

## Reach your devices

Once two machines are paired, they share a crypto-addressed overlay — each device's public key *is* its address. On top of that:

```sh
tunlion shell dovm                  # open a shell on a paired device (or just: tunlion dovm)
tunlion reach dovm                  # is it reachable, and over which route?
tunlion reach dovm --until-direct   # wait for the link to leave the relay
tunlion expose 5432                 # publish a local port on the mesh
tunlion forward dovm:5432           # forward a remote port to the same local port
tunlion mount dovm /srv/data ./data # mount a remote folder over the mesh
```

No inbound ports, no VPN config, no accounts — reachability rides the same authenticated link as file transfer, so a headless box in another network is one command away.

## Why Tunlion over the alternatives

- **vs croc / magic-wormhole**: superb tools, but both ends must install them. Tunlion's other end can be a browser with nothing installed. The CLI also resumes across restarts (croc parity), and a browser can be either side.
- **vs Snapdrop / PairDrop**: same-network discovery is the *starting* point here. Tunlion adds speakable one-time codes, resumable + content-verified transfers, a native CLI for servers and scripts, and the device mesh (shell/forward/mount).
- **vs Tailscale / ngrok** (for the mesh): no account, no coordination server holding your keys — identity is client-side crypto, and the data plane is pure P2P. It's lighter-weight and self-hostable end to end.
- **vs WeTransfer / Drive / email**: nothing is uploaded, ever. No size limit, no account, no link on someone's server. Bytes go device to device, encrypted.
- **Self-hostable end to end**: Flask signaling + Redis + coturn in one `docker compose up`. Point the apps at your instance with one env var.

## How it works

```
              one origin
   browser ── REST /api/* ─────────► Flask ── serves React build (dist/)
      │       Socket.IO /socket.io ► signaling relay (a dumb pipe; never sees files)
      └────── WebRTC DataChannel ──► other browser / CLI      (files go here)

   CLI ─────► direct QUIC ─────────► other CLI                (files + shell + ports)
              └ crypto-addressed L3 overlay for reach (shell / expose / mount)
```

The signaling relay only introduces peers; all data is peer-to-peer and end-to-end encrypted. Reliability is documented failure-by-failure: [docs/resilience.md](docs/resilience.md) (the browser's fixes) and [docs/cli-resilience.md](docs/cli-resilience.md) (the CLI's ledger, every entry gated by a test in `cli/tests/gates.sh`). Routing is explained in [the routing reference](cli/docs/tunlion-routing.md).

## Layout

```
backend/        Flask app (routes + SPA serving + Socket.IO signaling)
frontend/       React app (Vite); src/lib/ is the networking layer
cli/            Rust CLI — same wire protocol; direct-QUIC transport + L3 overlay
pake/           shared SPAKE2 pairing core (native rlib + wasm for the browser)
deploy/         docker compose: api + redis + coturn + cloudflared
scripts/        install.sh (curl|sh) + install.ps1 (Windows)
CONTRACT.md     the shape everything agrees on (REST + events + hook)
```

## Run it yourself

**Dev (hot reload):**
```bash
cd backend && pip install -r requirements.txt && python app.py    # :5000
cd frontend && npm install && npm run dev                         # :5173
```

**Production-style (one process):**
```bash
cd frontend && npm install && npm run build
cd ../backend && pip install -r requirements.txt && python app.py
```

Everything is driven by `/api/config` (no rebuild to reconfigure): `FIL_SIGNALING`, `FIL_ICE_SERVERS` / `FIL_TURN_HOST` + `FIL_TURN_SECRET`, `FIL_SECRET`, `FIL_CHUNK_SIZE`, `FIL_REDIS_URL` (horizontal scaling), `PORT`.

## A note on the "framework"

An earlier version shipped a hand-rolled, Flutter-flavored reactive UI engine. That experiment now lives on its own as **[statelet](https://github.com/Abdk4Moura/statelet)**. This repo uses real React.
