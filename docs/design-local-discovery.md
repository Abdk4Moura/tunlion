# Local discovery: find and pair nearby peers with no server

Status: design, for owner review. Written against `main` at bd3928a8. A peer of
`docs/carriers.md` (branch `work/carriers`, PRs #623, #624), not a parallel
system: it is the "LAN, Bluetooth, mesh discovery" row of that doc's
censorship table (section 8), built now.

## 1. Goal and the gap

Owner principle: tunlion connects any two peers whenever some path exists
between them, resilient to impedance and censorship; zero config, quiet, UX
first. Devices on one Wi-Fi, one Ethernet or one tailnet are the easiest pair
there is, and today they depend on our server to meet:

- "People near you" is the public IP the server sees: `/api/room`
  (`backend/app.py`, `api_room`, grouping by full IPv4 or IPv6 /64), used by
  the CLI via `fetch_auto_room` (`crates/filament-transport/src/net.rs`).
  Peers behind a VPN, dual WAN, or one on v4 and one on v6 land in different
  rooms and miss each other.
- Once two peers have met, the CLI already offers host candidates on every
  interface including `tailscale0` (`direct.rs` `gather_candidates`, the
  `tailscale` 100.64.0.0/10 class) and dials them in `race_connect` from
  `conn.rs` `on_transport_offer`. But the candidates travel over signaling. No
  server, no meeting, no connection, even with the peer one metre away.

Goal: paired and fleet peers on a shared local link or tailnet find each other
and connect with no server; two strangers in one room can pair with a code
with no server; nothing identifying is broadcast; no new trust.

## 2. Where it fits with carriers

Carriers move bytes to a rendezvous (signaling, TURN) through whatever egress
exists. Local discovery adds rendezvous that need no carrier. Both feed the
same thing: candidates and a channel for the ceremony.

| Rendezvous | Yields | Reached through |
|---|---|---|
| signaling server | room presence, offers, candidates | a carrier (direct, proxy, later PT) |
| **lan** beacon (this doc) | address + port of a recognized peer | the local link itself |
| **lan** tailnet list (this doc) | 100.x addresses to probe | the Tailscale local API |
| nearby native peer (this doc) | a local signaling endpoint for browsers | HTTP on the LAN, or BLE |
| QR / paste (carriers "serverless signaling") | an offer or an address | a camera or a clipboard |

What happens after discovery is unchanged: direct QUIC with the exporter MAC
over the pair secret (`direct.rs` module header), or WebRTC with the C20
fingerprint proof; make-before-break promotion (`CONTRACT.md`, "Post-PAKE
promotion is make-before-break") adopts a LAN path that appears later, and the
stall ladder (`conn.rs` `enum Rung`) still escalates to relay. When the server
is reachable, discovered addresses are merged into the candidate set, so the
different-public-IP case is fixed even online. Discovery never replaces the
server; it removes the dependency on it.

## 3. Wire design (one format, several carriers of it)

**Presence key.** Each device holds a random 32-byte presence key `P`. It is
given to each paired peer inside the already authenticated session at pairing
(and on the next connection for existing pairs), and to fleet siblings via a
key derived from the fleet rendezvous secret (`fleet_rv.rs` `rv`), so a new
sibling recognizes the whole fleet without per-pair exchange. Unpair or fleet
removal rotates `P` and redelivers it to the rest.

**Beacon** (about 34 bytes): `ver | kind | nonce(12) | tag(16) | port(2)`,
`tag = HMAC(P, "tlb1" | epoch | nonce | port)`, epoch = 10 minutes, ±1
accepted. `kind` is `presence` or `pairing`. No name, no key, no fingerprint,
no device id. A listener tries every `P` it knows (one HMAC per known device,
microseconds); a match yields "device D is at src:port". A stranger sees a
random-looking tunlion beacon from an address it can already see.

**Query.** A device that wants a peer now (`tunlion ssh laptop` with no
server) sends `ver | query | nonce`; devices answer with a unicast presence
beacon, rate limited, never larger than the query by more than a few bytes (no
amplification).

**A tag is a hint, never trust.** A replayed or forged beacon only makes us
dial an address; the exporter MAC or PAKE confirmation fails and we drop it.
The dialer opens with a 16-byte blinded hint
(`HMAC(P_peer, exporter)` truncated) so the acceptor picks the right pair
secret without a cleartext id.

**Carriers of the beacon**, all sent, all listened on, per interface:

- DNS-SD `_tunlion._udp` with a random instance and host label per epoch and
  the beacon in TXT. Uses the OS responder where one exists (Bonjour,
  Windows DNS Client, Avahi, Android `NsdManager`), else our own on 5353 with
  address reuse.
- Raw UDP multicast (239.255.0.0/16 and `ff02::` link scope, TTL 1) and IPv4
  subnet broadcast on a fixed port, for networks where mDNS is filtered.
- Tailnet: the tailnet carries unicast only, so instead of beacons we read the
  peer list (`/localapi/v0/status` on `tailscaled`'s socket, or
  `tailscale status --json`) and send a query to each online peer's 100.x
  address. A peer that also runs tunlion answers. Nothing is sent to non-peers
  off the tailnet.

Same-link correlation is honestly bounded: rotation stops a stranger learning
who you are or linking you across networks, not noticing that the same MAC
address keeps sending beacons on this network.

## 4. Pairing nearby

Opt-in "visible nearby for pairing" is exactly the time a code is on screen:
`tunlion pair` (and the app's Add device screen) emits `pairing` beacons until
the code is used or expires; nothing else ever does. The beacon carries no
code-derived value (a low-entropy code must not be testable offline) and a
random two-word label shown beside the code. The joiner types the code (or
scans the QR, which also carries the LAN address); `join` finds pairing
beacons, opens a local QUIC stream to each (in practice one) and runs the same
SPAKE2 ceremony there instead of over signaling. A wrong target costs one
online guess, counted by the existing attempt limit. In the UI the joiner sees
"Nearby: otter-maple" matching the label on the other screen. Fleet admission
over LAN is the existing certificate handshake (`filament-fleet`
`verify_hello`) on the discovered link. No new trust anywhere.

## 5. Per client

**Linux.** Own multicast/broadcast sockets on every up, broadcast-capable
interface; coexist with Avahi via `SO_REUSEPORT`. Firewalld/ufw may drop 5353
or our port inbound: `doctor` names the rule. Containers, WSL2 NAT mode and
AP client isolation (guest Wi-Fi) carry no local multicast: these are the
environments that forbid it, and we fall back to the server silently.

**macOS** (15+). Local network privacy gates outgoing TCP, UDP unicast to the
local net, all multicast and broadcast, and Bonjour; it automatically allows
launchd daemons, anything running as root, and command-line tools run from
Terminal or SSH, but **not launchd agents** ([TN3179](https://developer.apple.com/documentation/technotes/tn3179-understanding-local-network-privacy)).
`tunlion up --install` writes a LaunchAgent for user installs
(`cli/src/platform/mod.rs`), so that path gets one OS prompt; it needs
`AssociatedBundleIdentifiers` and a Developer ID signature for the decision to
stick (TN3179, build-time considerations). Root installs (`/Library/LaunchDaemons`)
never prompt. The multicast entitlement is iOS only.

**Windows.** Defender Firewall prompts on the first inbound listener; the
installer adds rules for the **Private** profile only, and on a Public-profile
network `lan` stays off unless the user turns it on (cafe Wi-Fi is not home).
Prefer the system mDNS (DNS Client service, `DnsServiceRegister` /
`DnsServiceBrowse`) and add raw multicast beside it.

**Android app** (wraps the binary, `docs/android-app-spec.md`). Android 17
enforces local network protection for apps targeting SDK 37: raw mDNS/SSDP
sockets and `NsdManager` need the `ACCESS_LOCAL_NETWORK` runtime permission,
except through the system NSD picker (`FLAG_SHOW_PICKER`), which needs none
([Android docs](https://developer.android.com/privacy-and-security/local-network-permission)).
So: Add device uses the picker (no prompt, one device, fits pairing); the
background "my devices nearby" uses the permission, asked once with a one-line
reason when the user first turns the foreground service on. Denied means
`lan` off, everything else works. Multicast reception needs a
`WifiManager.MulticastLock`, held only while the service is on. Bluetooth LE:
Android is both peripheral and central (`BLUETOOTH_ADVERTISE`/`SCAN`/`CONNECT`),
so the app is the BLE bridge for browsers and for offline phone-to-laptop
signaling. Wi-Fi Aware / Wi-Fi Direct (`NEARBY_WIFI_DEVICES`) give phone-to-phone
links with no access point; last phase.

**Browser** (the hard one; section 6).

## 6. What the browser can and cannot do

**Impossible in every browser, tab or installed PWA:** send or receive
multicast, broadcast or mDNS; open a UDP or TCP socket; advertise over
Bluetooth; find anything nearby on its own. The installed PWA has no extra
network powers. The one exception is Direct Sockets, including
`direct-sockets-multicast` for mDNS, which exists only for Isolated Web Apps
([Chrome docs](https://developer.chrome.com/docs/iwa/direct-sockets)), a
separately packaged, signed install, not our PWA; noted, not planned.

**Works everywhere once signaled:** WebRTC gathers host candidates, hidden
behind random `.local` mDNS names that only same-LAN peers can resolve
([draft-ietf-mmusic-mdns-ice-candidates](https://datatracker.ietf.org/doc/html/draft-ietf-rtcweb-mdns-ice-candidates-03));
the connection goes LAN-direct and `peer.route` already says `local`
(`CONTRACT.md`, Part A). So the browser problem is only signaling without the
server, and the answer is a nearby native peer (CLI/daemon or Android app)
acting as a local rendezvous: it serves a small HTTP signaling endpoint on its
LAN address (offer/answer and the PAKE frames), then the browser does WebRTC
with it, or through it to another browser on the LAN.

How the browser reaches that endpoint, per browser:

| Browser | Private-address fetch from the https app | Prompt |
|---|---|---|
| Chrome, Edge 142+ (desktop, Android) | allowed after the Local Network Access prompt; private IP literals and `.local` names skip mixed-content blocking, as does `fetch(..., {targetAddressSpace: "local"})` ([Chrome](https://developer.chrome.com/blog/local-network-access), [spec](https://wicg.github.io/local-network-access/)) | yes, per site, `local-network` (and `loopback-network` for 127.0.0.1) |
| Firefox 151+ | its own Local Network Access prompt, rolling out from 151 (earlier under ETP Strict) ([Mozilla](https://support.mozilla.org/en-US/kb/control-personal-device-local-network-permissions-firefox)) | yes |
| Safari macOS, iOS Safari | no LNA (WebKit: no signal, [standards-positions #520](https://github.com/WebKit/standards-positions/issues/520)); an http fetch from our https page is mixed content | n/a: use the served page below |

Rules that follow. Use `fetch` (long-poll), not WebSocket: Chrome gates local
WebSockets too (moved to M147) and has no `targetAddressSpace` for them, so
`ws://` to a LAN address gets no mixed-content exemption
([intent to ship](https://groups.google.com/a/chromium.org/g/blink-dev/c/O6GMKt44Ups)).
Chrome has prototyped gating WebRTC to local addresses behind the same
permission ([intent](https://groups.google.com/a/chromium.org/g/blink-dev/c/CDy8LAs-DoA));
once the user granted it for signaling, that is the same prompt. LNA is a
unicast permission: it grants requests to an address we already have, never
discovery. Only a secure context can ask.

**Safari and iOS:** the daemon serves the web app itself at
`http://<lan-ip>:<port>`, reached by scanning its QR or typing the short
address `tunlion` prints. Top-level navigation to a LAN address is allowed,
and Safari's traffic is exempt from iOS local network privacy (TN3179). It is
an insecure context: the SPAKE2 pairing is WASM and works, but the known-device
path uses `crypto.subtle` and goes dormant there (`frontend/src/lib/useTunlion.js`,
"crypto.subtle unavailable"), so that path moves to the same WASM. This also
works in every other browser and is the universal fallback.

**Where the browser gets the address:** (1) last-known LAN addresses of paired
devices, cached in IndexedDB whenever the server was reachable; (2) QR or
typed address; (3) loopback when a daemon runs on the same machine (the
existing `127.0.0.1:53317` helper probe in `useTunlion.js`, which this design
turns into the daemon itself; the spike in `experiments/localsend-discovery`
announces names in cleartext and is replaced, not shipped).

**Web Bluetooth:** Chrome, Edge, Opera, Samsung Internet on desktop and
Android; not Firefox (negative position) or Safari/iOS
([web-features](https://web-platform-dx.github.io/web-features-explorer/features/web-bluetooth)).
Central only: it can connect to a GATT peripheral the user picks in a chooser
(a prompt every time), never advertise. Use: offline signaling to a nearby
Android app or laptop daemon that advertises a tunlion GATT service (about 1 KB
of offer/answer). Two browsers cannot find each other over BLE.

**Browser to browser with no server and no native peer:** only by QR
offer/answer (two scans; the carriers doc's serverless signaling), and then
mDNS host candidates connect them if the LAN passes multicast.

## 7. UX

- Zero config: `lan` is on by default everywhere it is allowed; no new commands.
- One route word: `lan`. `tunlion ping laptop` prints `laptop: lan (direct over
  wlan0) 2.1 ms`; `devices` shows `lan` where it shows `relay`/`direct` today;
  the web app badge maps today's `local` to `lan`. As in carriers section 7,
  only the shown form changes in the first phase; `route()` stays (it is
  compared in code), and the vocabulary unification is the carriers follow-up.
- `doctor` gains one block: per interface, beacons sent and recognized, mDNS
  owner, tailnet seen, and the one blocking cause ("multicast filtered on
  eth0", "macOS Local Network denied for tunlion: System Settings > Privacy").
- Off: `network.transports` (carriers section 9) lists `lan` as a member;
  `auto` includes it; pin a list without `lan` to turn it off. Admins disable
  it the same way.
- Prompts are asked in context only: the Android permission when the service
  is first switched on, Chrome/Firefox LNA when the user picks a nearby device,
  BLE when the user taps "Bluetooth".

## 8. Security, collected

1. Beacons carry no name, key or stable id; tags rotate every epoch with a
   fresh nonce; only holders of `P` recognize them.
2. Pairing beacons exist only while a code is on screen, and leak nothing that
   tests the code offline.
3. Every connection is still authenticated by SPAKE2, the pair secret
   (exporter MAC / C20), or fleet certificates. A tag never admits anything.
4. Unpair and fleet removal rotate `P`; an ex-peer can at most notice you
   nearby until its next miss.
5. No amplification (query-sized replies, rate limits); listeners bound to
   local interfaces only; Windows Public profile off by default.
6. Proof: extend `proofs/establishment_model.py` with discovered addresses as a
   rendezvous and add a mutant that admits on a matching tag; it must be caught.

## 9. Phases and rough effort

| Phase | Contents | Effort |
|---|---|---|
| 1 | CLI/daemon: presence key, beacon over multicast/broadcast + DNS-SD, tailnet query, server-free direct dial for paired and fleet peers, candidate merge when online, `lan` in shown route, doctor block, `network.transports` member, two-namespace CI rig with no server (and the denied arm: `lan` off must not connect) | 2 to 3 weeks |
| 2 | Pairing nearby: pairing beacons, SPAKE2 over local QUIC, label in UI, QR with LAN address | 1 to 2 weeks |
| 3 | Android: NSD picker for Add device, `ACCESS_LOCAL_NETWORK` flow, MulticastLock, service integration | 1 to 2 weeks |
| 4 | Browser: daemon HTTP signaling endpoint, LNA flow (Chrome, Edge, Firefox), served-page path (Safari, iOS) with WASM known-device crypto, cached addresses, QR offer/answer | 2 to 3 weeks |
| 5 | BLE: Android peripheral, desktop central, Web Bluetooth signaling; then Wi-Fi Aware/Direct | 3 to 4 weeks |

Each phase is verified on real devices on one Wi-Fi with the server blocked,
and with differing public IPs (one peer on a VPN), before it ships.
