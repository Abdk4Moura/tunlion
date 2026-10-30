# Tunlion launch pack (0.9.2, paste-ready)

Everything in the paste blocks is final and contains no em dashes. Facts below
were checked against the live 0.9.2 release on 2026-10-30 (curl installer in a
clean HOME, `npm i -g tunlion`, the Homebrew formula, API health, the blog URL,
and a code pairing between two browsers on tunlion.autumated.com):

- CLI `cli-v0.9.2` on GitHub Releases (Linux, macOS Intel and Apple Silicon,
  Windows; SHA256SUMS plus build-provenance attestations).
- Installers: `curl -fsSL https://tunlion.autumated.com/install | sh` and
  `irm https://tunlion.autumated.com/install.ps1 | iex`.
- `npm i -g tunlion` and `brew install abdk4moura/tap/tunlion` are live at 0.9.2.
- winget: `Abdk4Moura.Tunlion` is in review (microsoft/winget-pkgs#466106 for
  0.9.2, #462262 for 0.9.1).
  Do not lead with winget until that PR merges.
- crates.io is not published; Cargo installs from git.
- Web app: https://tunlion.autumated.com. Source: https://github.com/Abdk4Moura/tunlion (MIT).
- Prod signaling was load-tested at 4,000 concurrent devices on 1 CPU and
  512 MB (54% CPU) and about 60 new pairings per second.

---

## 1. Show HN

**Title (paste this exact line):**

```
Show HN: Tunlion - send files to any browser, and shell into your own machines, P2P
```

**URL field:**

```
https://tunlion.autumated.com
```

**Text field (paste as-is):**

```
Tunlion sends files between devices peer to peer, and the other end can be any
browser with nothing installed. Open the site on both devices, or run the CLI on
one and say the one-time code to the other ("clever-lynx-63"). The code burns on
first use, so an overheard code is worthless. Nothing is uploaded: the server
only introduces the two ends.

The same link does more once two machines are paired. Each device's public key
is its address, so from the CLI you can open a shell on a paired box in another
network, forward a port, or mount a folder, with no inbound ports, no VPN
config and no account. The browser can open that shell too, which is how I get
into my VPS from a phone. Your own devices form a mesh: add each one once and
any two of them can reach each other, without pairing every pair.

Things I think HN might find interesting:

- Every device shows the route its link actually took: LAN, direct over the
  internet, or RELAY. Relay is the only route with a middleman, so it is the
  loud one. It turned out to be the best trust and debugging feature.
- Permissions are per device and time-boxed. Pairing gives file transfer; a
  shell is a separate grant you can make expire, and revoking a device cuts its
  open sessions at once, on all your other devices too. Invitations you sent
  are listed and can be withdrawn. `tunlion dashboard` shows all of it on a
  local page.
- Transfers resume after a drop and are verified by content hash. Shells
  reattach after a dropped connection and replay only what you missed.
- Pairing is SPAKE2, shared by the CLI and the browser (Rust compiled to wasm),
  so the relay never learns the code.
- Every command takes --json and has documented exit codes, and
  `tunlion skill install` gives a coding agent the exact commands.

Stack: React on Cloudflare, a Flask-SocketIO signaling relay behind a
Cloudflare Tunnel, coturn plus Cloudflare TURN as relay fallback, WebRTC in the
browser and direct QUIC between terminals. The whole backend self-hosts with
one docker compose. I load-tested the relay at 4,000 concurrent devices on a
single CPU, mostly to find out where it falls over (it was an O(n) scan per
sync, now fixed).

Honest limits: both devices must be online, since nothing is stored. Browser
resume needs the sending tab to stay open. iOS Safari in the background is
still the hardest environment.

Install: curl -fsSL https://tunlion.autumated.com/install | sh, npm i -g
tunlion, or brew install abdk4moura/tap/tunlion. Code (MIT):
https://github.com/Abdk4Moura/tunlion
```

**First comment (post right after submitting):**

```
If you want the details, I wrote up the WebRTC failure modes I hit and the fix
for each: signaling glare, ICE candidates arriving before the remote
description, presence that goes zombie after a server restart, transfers stuck
at "transferring" forever, and TURN credentials going stale in a tab left open
overnight:
https://abdk4moura.github.io/post.html?post=webrtc-file-transfer-failures.md
```

**Posting notes (do not paste):**

- Tue to Thu, 8 to 10am US Eastern. Stay 2 to 3 hours to answer comments.
- Likely questions and short answers:
  - "vs Snapdrop / PairDrop?" Cross-network one-time codes, resume, visible
    route, a CLI for servers, and the device shell / forward / mount.
  - "vs croc / magic-wormhole?" The other end can be a browser with nothing
    installed. Both use a PAKE, so the relay cannot learn the code.
  - "vs Tailscale?" No account and no coordination server holding keys;
    identity is client-side. Tailscale is a full network; Tunlion is per-device
    grants on one link.
  - "What does the server see?" Who paired with whom and when, never content.
    Data is end-to-end encrypted (DTLS in the browser, QUIC between CLIs).
  - "Relay bandwidth cost?" Most pairs connect direct; relay is coturn plus
    Cloudflare TURN.

---

## 2. r/selfhosted

**Title (paste this exact line):**

```
Tunlion: self-hostable P2P file drop to any browser, plus shell/forward/mount to your own devices, no inbound ports
```

**Flair:** Release

**Body (paste as-is):**

```
I have been building this for a while and use it daily, and the whole thing
self-hosts, so sharing it here.

Tunlion sends files peer to peer. The receiving side can be any browser with
nothing installed. Same-WiFi devices find each other; across networks you pair
with a one-time spoken code that burns after one use. Files are never uploaded.

Once two of your machines are paired, the same link lets you open a shell,
forward a port, or mount a folder on the other one, even when it sits behind
NAT in another network. No inbound ports, no VPN setup, no account. The browser
can open the shell too.

For r/selfhosted specifically:

- Backend is one docker compose: Flask-SocketIO signaling, coturn for the relay
  fallback, cloudflared if you want no open API port. Redis is optional (only
  for running several API replicas).
- It is light. I load-tested the signaling relay at 4,000 concurrent devices on
  1 CPU and 512 MB.
- Route transparency: every device shows whether the link is LAN, direct over
  the internet, or going through your relay.
- Access is per device and can expire. A shell is a separate grant from file
  transfer, and revoking a device ends its open sessions immediately.
- CLI for Linux, macOS and Windows, installs as an always-on service with
  `tunlion up --install`. Add each of your machines once and they all reach
  each other; the CLI falls back to TURN over TCP or TLS on 443 when UDP is
  blocked. Point it and the web app at your own instance with
  one setting.

Honest limits: both ends must be online (nothing is stored), and browser resume
needs the sending tab open.

Live instance: https://tunlion.autumated.com
Code and deploy guide (MIT): https://github.com/Abdk4Moura/tunlion
```

---

## 3. AlternativeTo

**Name:** `Tunlion`

**URL:** `https://tunlion.autumated.com`

**Category:** File Sharing

**License:** Open Source (MIT), https://github.com/Abdk4Moura/tunlion

**Platforms:** Web (any browser), Linux, macOS, Windows.

**Tagline (paste as-is):**

```
Send files directly between devices, to any browser. Peer to peer, no upload, no account, no size limit.
```

**Description (paste as-is):**

```
Tunlion transfers files straight between devices. The receiving end can be any
browser with nothing installed. Devices on the same WiFi find each other
automatically; devices on different networks pair with a one-time spoken code.
Files are never uploaded: they travel peer to peer over an encrypted link, with
an encrypted relay as fallback for strict networks, and every device shows
which route its link took (LAN, direct, or relay). Interrupted transfers resume
and are verified by content hash. A native CLI for Linux, macOS and Windows
adds an always-on receiver and, between your own paired machines, shell, port
forwarding and folder mounts without inbound ports. Open source (MIT) and
self-hostable with one docker compose.
```

**Alternative to:**

```
Snapdrop, PairDrop, AirDrop, Send Anywhere, WeTransfer, magic-wormhole, croc
```

**Features to tick:**

```
No registration, No file size limit, Peer-to-peer, Encrypted transfer, Self-hostable, Open source, Resumable transfers, Cross-platform, Web-based, Command line
```

---

## 4. Launch-day checks (do not paste)

- [ ] `https://tunlion.autumated.com` opens, two browsers see each other.
- [ ] `curl -fsSL https://tunlion.autumated.com/install | sh` in a clean HOME
      gives 0.9.2.
- [ ] `npm i -g tunlion` gives 0.9.2.
- [ ] `brew install abdk4moura/tap/tunlion` gives 0.9.2.
- [ ] Two of your devices added to the mesh but never paired reach each
      other (`tunlion reach <device>`).
- [ ] `https://api.filament.autumated.com/health` returns `{"ok":true,...}`.
- [ ] Watch api CPU during the HN window: `docker stats` on the box. At the
      tested rate there is headroom to about 4,000 concurrent devices.
- [ ] Blog post is live at the first-comment URL before posting.
- [ ] Different week for r/selfhosted than HN.

## 5. What changed from the previous pack

- 0.9.2: the fleet mesh (your devices reach each other without pairing each
  pair), fleet-wide revoke, listing and withdrawing invitations, and CLI TURN
  over TCP/TLS. The load-test number is unchanged: it is the prod Flask
  signaling, not the Cloudflare duplicate, which is not on prod routes.

Earlier:


- Rewritten for 0.9.1: the device shell, forward and mount, per-device
  time-boxed access, the dashboard, shell reattach, the npm and Homebrew
  channels, and the agent skill. The old pack described CLI 0.2.0 and file
  transfer only.
- Stack facts corrected: the frontend is on Cloudflare (Workers), Redis is
  optional, and relay fallback is coturn plus Cloudflare TURN.
- Added the load-test number as a concrete, checkable detail.
- winget is mentioned only as in review; crates.io is not mentioned.
