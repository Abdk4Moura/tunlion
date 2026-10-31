# Local discovery: find and pair nearby peers with no server

Status: revised after owner review (2026-10-30), for approval. Written against
`main` at bd3928a8. A peer of `docs/carriers.md` (branch `work/carriers`, PRs
#623, #624): it is the "LAN, Bluetooth, mesh discovery" row of that doc's
censorship table (section 8), built now.

**Protocol first.** The wire format is specified language-neutrally in
`docs/protocol/local-discovery.md`, with test vectors produced by an
independent Python implementation (`crates/tunlion-lan/vectors/`). The Rust
core (`crates/tunlion-lan`) is sans-IO: pure encode, decode, derive and verify
functions plus an engine that turns time and datagrams into actions, with no
sockets, no async runtime and no peerloop types, so the same core serves the
CLI daemon, Android (through the FFI) and the browser (wasm). The daemon
integration is a thin adapter on top. Any other client conforms by
reproducing the vectors.

**Interfaces by capability, never by name.** Discovery treats every up
interface with a unicast address the same way, from its flags: Ethernet,
Wi-Fi, USB tethering, a Hyper-V or WSL switch, WireGuard, ZeroTier, Tailscale,
Nebula and tunlion's own overlay (`tunlion0`) are not special cases, and no
code keeps a list of names. There is no dependency on any VPN's API.

## 1. Goal and the gap

Owner principle: tunlion connects any two peers whenever some path exists
between them, resilient to impedance and censorship; zero config, quiet, UX
first. Devices on one Wi-Fi, one Ethernet, one VPN or overlay are the easiest
pair there is, and today they depend on our server to meet:

- "People near you" is the public IP the server sees: `/api/room`
  (`backend/app.py`, `api_room`, grouping by full IPv4 or IPv6 /64), used by
  the CLI via `fetch_auto_room` (`crates/filament-transport/src/net.rs`).
  Peers behind a VPN, dual WAN, or one on v4 and one on v6 land in different
  rooms and miss each other.
- Once two peers have met, the CLI offers host candidates and dials them in
  `race_connect` from `conn.rs` `on_transport_offer`. **Correction:** the
  first draft said those candidates cover every interface. They do not:
  `direct.rs` `local_ips` returns only the default-route source addresses, so
  a peer reachable only over a second interface (a tunnel, a second NIC) was
  never dialed there. And the candidates travel over signaling: no server, no
  meeting, no connection, even with the peer one metre away.

Goal: paired peers on any shared or private network find each other and
connect with no server; two strangers in one room can pair with a code with
no server; nothing identifying is broadcast; no new trust.

## 2. Where it fits with carriers

Carriers move bytes to a rendezvous (signaling, TURN) through whatever egress
exists. Local discovery adds rendezvous that need no carrier. Both feed the
same thing: candidates and a channel for the ceremony.

| Rendezvous | Yields | Reached through |
|---|---|---|
| signaling server | room presence, offers, candidates | a carrier (direct, proxy, later PT) |
| **lan** beacon | address + port of a recognized peer | multicast, broadcast, mDNS on shared interfaces |
| **lan** probe | the same, by unicast query | point-to-point interfaces (bounded sweep, neighbor hints) |
| **lan** remembered address | every address the peer had when last linked | any interface, any network |
| nearby native peer | a local signaling endpoint for browsers | HTTP on the LAN, or BLE |
| QR / paste (carriers "serverless signaling") | an offer or an address | a camera or a clipboard |

What happens after discovery is unchanged: direct QUIC with the exporter MAC
over the pair secret (`direct.rs` module header), or WebRTC with the C20
fingerprint proof; make-before-break promotion (`CONTRACT.md`, "Post-PAKE
promotion is make-before-break") adopts a LAN path that appears later, and the
stall ladder (`conn.rs` `enum Rung`) still escalates to relay. When the server
is reachable, every interface's addresses are merged into the signaled
candidate set, so the second-interface case is fixed even online. Discovery
never replaces the server; it removes the dependency on it.

## 3. Mechanisms, per interface by capability

The spec (`docs/protocol/local-discovery.md`) is normative; this is the why.

| Interface class (from flags) | Mechanisms |
|---|---|
| shared: not point-to-point, multicast or broadcast | presence beacons to a link-scope group and the subnet broadcast; the same beacon in a DNS-SD TXT record; queries answered by unicast |
| p2p: point-to-point, or neither multicast nor broadcast (most VPN tunnels) | a bounded unicast sweep of small on-link prefixes and on-link routes (at most a /22 worth of hosts, 200 probes/s in total); the OS neighbor table as hints |
| every class | remembered addresses (below) |

**Remembered addresses are the generic mechanism.** Every time two paired
peers link, by any route, each sends a `lan-hello` over the authenticated
link: its presence key, its listener port, and every unicast address on every
interface with its class. Each side keeps the other's addresses (per peer,
with class and last-success time) and, whenever the server is unreachable,
dials them directly with the existing authenticated direct-QUIC handshake.
Beside a working server the daemon gives signaling an 8 s grace at start and
then dials only the devices signaling has not linked; a one-shot command uses
local discovery only when the server is unreachable. (Dialing both at once
was measured: the warm-hold gate saw duplicate links and a peer dialing a
one-shot's session that never answered.) This makes any overlay or private network work without knowing
what it is.

**Presence key.** Each device holds a random 32-byte presence key `P`, sent
only inside the hello. **Beacon** (34 bytes, every kind): `"TL" | v1 | kind |
nonce(12) | field(16) | port(2)`, presence field
`HMAC(P, "tunlion-lan-v1/presence" | epoch | nonce | port)[0..16]`, epoch = 10
minutes, ±1 accepted. A listener tries every key it holds; a match yields
"device D is probably at src:port". A query is padded to the same 34 bytes so
no reply is larger than what caused it.

**A tag is a hint, never trust.** A replayed or forged beacon only makes us
dial an address; the exporter MAC fails and the connection is dropped.
**Correction:** the first draft had the dialer send a blinded 16-byte hint so
the listener could pick the secret. Not needed: the listener reads the
dialer's 32-byte MAC and tries each secret it holds (one HMAC each), so
nothing new goes on the wire.

**The circular-route guard.** The one guard on candidates: never dial peer X
at an address whose route is carried by our own link to X (X's address on
tunlion's overlay exists only while that link is up). Decided by route
ownership (the device store's recorded overlay addresses for X and the live
overlay table), never by interface name: an overlay address carried by a link
to a third device, a second tunlion instance or a nested setup is a real path
and is dialed.

Same-link correlation is honestly bounded: rotation stops a stranger learning
who you are or linking you across networks, not noticing that the same MAC
address keeps sending beacons on this network. A device that could not bind
the default listener port sends its own port in every beacon, which links its
beacons on that link.

## 4. Pairing nearby

Opt-in "visible nearby for pairing" is exactly the time a code is on screen:
`tunlion pair` (and the app's Add device screen) emits `pairing` beacons until
the code is used or expires; nothing else ever does. The beacon carries no
code-derived value (a low-entropy code must not be testable offline), only a
random pairing id; both screens show a 4-digit label derived from the id
beside the code. The joiner types the code (or scans the QR, which also
carries the LAN address); `join` finds pairing beacons, opens a local QUIC
stream to each (in practice one) and runs the same SPAKE2 ceremony there
instead of over signaling. A wrong target costs one online guess, counted by
the existing attempt limit. Fleet admission over LAN is the existing
certificate handshake (`filament-fleet` `verify_hello`) on the discovered
link. No new trust anywhere.

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

**Windows.** Phase 1 dials remembered addresses only (no interface
enumeration yet, so no beacon or probe is ever sent). Then: Defender Firewall prompts on the first inbound listener; the
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
- One route word: `lan`. `tunlion reach laptop` prints
  `pong via 192.168.1.20:47821 (lan, direct) 2 ms`; `devices` shows
  `online lan` for such a link; `--json` carries `"route": "lan"`. As in
  carriers section 7, only shown forms change; the internal route labels stay
  as they are, and the vocabulary unification is the carriers follow-up.
- `doctor` gains one row: on/off, the listener, beacons sent and recognized,
  devices remembered, every interface with what it does there ("eth0
  multicast+broadcast", "wg0 probe 253 hosts", "off" when opted out), and the
  one blocking cause when there is one.
- Off: `network.transports` (carriers section 9) lists `lan` as a member;
  `auto` includes it; `tunlion set network.transports direct,relay` turns it
  off (no datagram sent, no listener, no remembered dial). Per interface:
  `tunlion set network.lan-skip eth1,10.20.0.0/16`.
- Prompts are asked in context only: the Android permission when the service
  is first switched on, Chrome/Firefox LNA when the user picks a nearby device,
  BLE when the user taps "Bluetooth".

## 8. Security, collected

1. Beacons carry no name, key or stable id; tags rotate with a fresh nonce
   per datagram and are bound to an epoch; only holders of `P` recognize them.
2. Pairing beacons exist only while a code is on screen, and leak nothing that
   tests the code offline.
3. Every connection is still authenticated by SPAKE2, the pair secret
   (exporter MAC / C20), or fleet certificates. A tag never admits anything.
4. A hello is accepted only from a link whose identity is proven by its pair
   secret; unpair forgets the record and rotates `P`.
5. No amplification (query-sized replies, per-source and global rate limits);
   nothing sent or answered on an opted-out interface or a Windows Public
   network.
6. Proof: `proofs/lan_discovery_model.py` checks ADMIT, REACH, GUARD, OFF,
   QUIET, BLIND and HELLO over every environment and catches ten mutants
   (among them: admit on a matching tag, dial the circular overlay address,
   drop a third device's overlay path by name).

## 9. Implementation plan

Ordered work units. Each lists what it touches, its interface to the next,
and the test or gate that closes it. Units 1 to 7 are phase 1; 8 is phase 2.

| # | Unit | Touches | Interface out | Closed by |
|---|---|---|---|---|
| 1 | Spec and vectors | `docs/protocol/local-discovery.md`, `crates/tunlion-lan/vectors/gen_vectors.py`, `v1.json` | the bytes | an independent Python implementation produces the vectors |
| 2 | Sans-IO core | `crates/tunlion-lan` (`wire`, `mdns`, `iface`, `record`, `engine`) | `Engine::tick`/`on_datagram` returning `Action`s; `Hello`, `Record`, `RouteOwner`, `not_circular` | `tests/conformance.rs` (vectors) and `tests/properties.rs` (blind beacons across epochs, name-agnostic plans, sweep cap, opt-out/public silence, bounded replies, the circular guard) |
| 3 | Adapter | `crates/filament-transport/src/lan.rs`: getifaddrs by flags, on-link routes, neighbors, discovery and mDNS sockets, the QUIC listener with trial-MAC, dial, `LanStore` (`lan.key`, `lan-peers.json`); `Ev::Lan` | `LanService::{start, dial, learn, hello_json, write_state}`; `LanEvent::{Linked, Found, PairingNearby}` | unit tests: a listener holding several secrets admits only a held one; the store round-trips, ranks and forgets |
| 4 | Candidate merge | `direct.rs` `gather_candidates` | every interface's addresses in the signaled offer when lan is on | existing transport gates; the `lan`/`wg` learn phases below ride it |
| 5 | Loops | `filament-peerloop` `lan_glue.rs` (`seed_lan`, `lan_dial`, `on_linked`, `Ownership`), `recv/dispatch.rs` (start without the server, non-blocking re-dial, periodic remembered dial, `lan-hello` send and learn), `cli/src/send_cmd.rs` + `lan_send.rs` (one-shot send dials remembered addresses beside signaling) | a LAN link is an ordinary `Ev::DirectReady` with route `lan` | `cli/tests/lan-discovery-gates.sh` |
| 6 | Settings and surfaces | `cli/src/settings.rs` (`network.transports`, `network.lan-skip`), `ping.rs`, `devices`, `doctor.rs` + `lan_doctor.rs` | route word `lan`; doctor `lan` row and `--json` `lan` | unit tests for the validator and the doctor row |
| 7 | Model | `proofs/lan_discovery_model.py` | | `--self-test`: every mutant caught |
| 8a | Pairing nearby, plain pair (phase 2) | `tunlion-lan` pairing beacon (in the core already), `filament-transport` pairing ALPN and exporter binding, `cli/src/lan_pair.rs`, `pair_cmd.rs`/`join` | `LanEvent::PairingNearby` -> join dials it; one-winner code state | `cli/tests/lan-pairing-gates.sh`: two namespaces, server blocked, `pair --nearby` and `join <code> --nearby` complete and then `send` works; wrong code, lan-off and cancellation negatives |
| 8b | Pairing nearby, owner grant (phase 2, separate review) | the same carrier plus `enrol-offer`/`enrol-grant` and the owner decision | an owner-signed certificate over LAN, with the existing ceiling/TTL rules | extends 8a: owner grant happy path, non-interactive refusal, forged offer, runner refusal and revocation |

Gates (`cli/tests/lan-discovery-gates.sh`, namespaces on one lease, server
blocked by an iptables DROP so connects time out): **lan**, one switch, B's
address changed after learning so only a beacon can find it, plus a stranger
on the switch who must learn nothing identifying from the captured beacons;
**wg**, a WireGuard tunnel (no multicast) as the only path, B's tunnel address
changed so only the sweep can find it; **routed**, different subnets behind a
router (the different-public-IP case), remembered addresses only. Each must
`reach` with route `lan` and deliver a `send`; the denied arm
(`network.transports=direct,relay`) must fail in each.

Phase 2 is split: 8a is a plain pair only and issues no certificate; 8b is the owner-grant half and is reviewed separately. Later phases, in order: Android (NSD picker for Add device,
`ACCESS_LOCAL_NETWORK`, MulticastLock, the core through the FFI); browser
(daemon HTTP signaling endpoint, LNA flow, served page for Safari/iOS, the
core as wasm for cached addresses); Windows interface enumeration with the
Public-profile check (until then Windows dials remembered addresses only and
never sends a beacon or probe); fleet siblings over LAN (the hello waits for
the certificate); BLE, then Wi-Fi Aware/Direct.
