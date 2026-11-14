# Carriers: reach the other peer over whatever the network allows

Status: design approved by the owner (2026-10-29), written against `main` at
2757d2de. Target: 0.9.3 for the core, later phases after. Sections marked
**Correction** are places where the code disagreed with the approved design and
the design was changed to match it.

## 1. Goal

Connect any two peers whenever some chain of byte channels exists between them,
including on networks that impede tunlion on purpose (corporate proxies, agent
sandboxes, censors).

The reduction that keeps this tractable:

- one side reachable: dial it (direct QUIC, `crates/filament-transport/src/direct.rs`);
- both sides outbound-only: both reach a rendezvous, and the rendezvous relays
  (signaling for control, TURN for data).

So the work is: for every egress shape a network can have, one **carrier** that
reaches our infrastructure through it, and a relay that speaks it.

## 2. What a carrier is, and the trust boundary

A carrier moves bytes between this process and a rendezvous. It never
authenticates a peer and never holds a key. Everything that makes tunlion safe
stays above it and unchanged: the SPAKE2 code ceremony (`CONTRACT.md`, "Code
ceremony frames"), device keys and certificates, the DTLS fingerprint binding
(C20), the direct-QUIC exporter MAC (`direct.rs`, module header), and
capabilities. Every carrier, and every proxy or relay a carrier passes through,
is untrusted.

**Correction (signaling metadata under TLS inspection).** The design said a
carrier never sees plaintext. That holds for the data plane: a TURN relay or
proxy only ever sees DTLS or QUIC ciphertext. It does not hold for signaling
behind a TLS-inspecting proxy. Signaling is ordinary HTTPS/WSS to our server;
a proxy whose CA the OS trusts (exactly the case PR #621 makes work) terminates
that TLS and reads the Socket.IO frames: room and channel ids, SDP including ICE
candidates and DTLS fingerprints, and SPAKE2 elements. What that proxy still
cannot do: learn or brute-force a code offline (SPAKE2), or splice itself into
the data path (the fingerprints are confirmed by the PAKE MAC or the pair
secret, so a rewritten SDP fails confirmation). So the honest statement is: a
carrier learns "an encrypted connection to tunlion infrastructure"; a
TLS-inspecting proxy additionally learns signaling metadata. Hiding that needs
an inner encryption layer on signaling, which is out of scope here and listed in
section 10.

## 3. What exists today

| Egress shape | What tunlion does on `main` | Where |
|---|---|---|
| Any UDP | direct QUIC race, ICE host/srflx, hole punch | `direct.rs` `race_connect`, `gather_candidates`; `cli/src/holepunch.rs` |
| Some UDP ports | TURN over UDP (3478, and whatever `/api/config` lists) | webrtc-ice, URLs from `net.rs` `fetch_config` |
| TCP only / TCP 443 only | TURN over TCP, then TLS 443, through a loopback bridge | `crates/filament-transport/src/turn_bridge.rs` (#601) |
| TCP 443 for signaling | WSS, websocket only, dialled directly | `crates/filament-signal/src/lib.rs` `connect_inner` |
| HTTPS proxy (`HTTPS_PROXY`) | **REST calls only** (`/api/config`, `/api/room`) honour it via reqwest `system-proxy`; signaling and the TURN bridge ignore it, so pairing never starts | `crates/filament-transport/src/http.rs`, `net.rs` `http_get_json` |
| TLS-inspecting proxy | REST trusts the OS store (rustls-platform-verifier); signaling trusts only compiled-in webpki roots, so it fails | `http.rs` `trusted_tls_config`; fix in PR #621 |
| HTTP only, no websockets | browser falls back to Engine.IO polling; CLI has no polling | `frontend/src/lib/signalTransport.js`; `filament-signal` is websocket-only by design |
| Inbound-only peer | a CLI with a reachable address is dialled by the other CLI's direct-QUIC race (UDP). No TCP listener exists; a browser can never listen | `direct.rs` `race_connect`, `serve_tun_listen` |

Path changes are already make-before-break: after a code ceremony the WebRTC
link keeps serving while direct QUIC races beside it, and the move is one round
trip at a frame boundary (`CONTRACT.md`, "Post-PAKE promotion is
make-before-break"; #598; modelled in `proofs/transport_upgrade_model.py`).
The stall ladder (`crates/filament-peerloop/src/conn.rs`, `enum Rung`:
Resume, Repaired, Relayed, Exhausted) is how a failing path escalates to relay.
A better carrier appearing later therefore needs no new mechanism: it is
another standby that the existing promotion adopts.

## 4. The interface

**Correction (what the stack actually consumes).** The design said every carrier
presents a local datagram port to "the existing QUIC/WebRTC stack". In the code
only WebRTC consumes relays: webrtc-ice is handed `turn:` URLs, and quinn
(direct QUIC) binds its own UDP socket and dials peer candidates; it never rides
a relay (`direct.rs` `bind_endpoint`). And #601's bridge does not
length-prefix: TURN over a stream is the same protocol as over UDP because STUN
and ChannelData are self-delimiting (RFC 8656 section 6.2; `turn_bridge.rs`
`read_frame`/`write_frame`). So the layering in the code is:

```
signaling (Engine.IO/WSS)  ┐
                           ├── StreamCarrier: dial(host, port) -> byte stream
TURN over TCP / TLS        ┘        direct TCP | HTTP CONNECT via proxy | (later) WebSocket, PT
        │
turn_bridge: TURN frames over that stream  ->  loopback UDP port  ->  webrtc-ice as turn:127.0.0.1:P
```

The primitive is a **stream** carrier. The datagram form is `turn_bridge` applied
on top of a stream carrier, and it already exists. Shape:

```rust
#[async_trait]
pub trait StreamCarrier: Send + Sync {
    /// Short label shown in routes and doctor: "direct", "proxy".
    fn name(&self) -> &'static str;
    /// A byte stream to host:port. TLS, if any, is the caller's (end to end).
    async fn dial(&self, host: &str, port: u16) -> io::Result<TcpStream>;
}
```

`TcpStream` rather than a boxed stream is deliberate for 0.9.3: an HTTP CONNECT
tunnel through an `http://` proxy is a plain TCP socket after the `200`, so the
signaling client's existing types (`MaybeTlsStream<TcpStream>`) and the bridge's
socket tuning (`STREAM_SNDBUF`) are unchanged. A carrier that is not a TCP socket
(a WebSocket relay, a pluggable transport) widens this to a boxed
`AsyncRead + AsyncWrite` when it lands. Raw QUIC datagrams over a stream carrier
would need a length prefix; nothing does that yet.

Known cost: on a stream carrier, SCTP (inside DTLS) recovers loss on top of TCP
recovering it. #601 already measured the symptom and bounds it: the bridge
drops instead of queueing past `STREAM_SNDBUF` and `SESSION_QUEUE`, so SCTP
congestion control sees loss rather than seconds of bufferbloat. This is
acceptable for a fallback; make-before-break promotes away from it.

## 5. Selection

TURN carriers are already raced by cost, gated on what has actually been
gathered, never on a probe (`turn_bridge.rs` `gate`): UDP first; TCP after
`TCP_AFTER` (1.5 s) with no UDP relay; TLS after `TLS_AFTER_TCP` (1.5 s more) or
at once when every TCP server failed. 0.9.3 keeps those values. Through a proxy
a TURN TCP port is normally refused by the proxy within one round trip (squid's
default allows CONNECT only to 443), which counts as a TCP failure, so TLS 443
goes without waiting.

**Correction (proxy versus direct is not raced).** The design raced every tier.
For a destination the proxy configuration covers, 0.9.3 uses the proxy only,
the same rule reqwest (and curl) apply, for two reasons: REST and signaling
must agree, or `/api/config` succeeds while pairing fails (today's bug in a new
form); and in agent sandboxes and corporate networks a direct connection
attempt beside a configured proxy is what egress monitoring flags. Racing
direct against proxy becomes possible with the `network.transports` setting,
where the person running tunlion opts in.

Later phases add the ~250 ms stagger across further tiers and a per-network
memory (coarse fingerprint: default gateway, proxy setting, signaling RTT
bucket) that is forgotten on the first failure.

## 6. Proxy discovery: identical to the REST client by construction

reqwest's `system-proxy` feature is `hyper_util::client::proxy::matcher::Matcher::from_system()`
(hyper-util 0.1.20). The carrier uses that same matcher, so a proxy that works
for `/api/config` works for signaling and TURN, and `NO_PROXY` means the same
thing everywhere. What it reads:

- `ALL_PROXY`, `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`, each also lowercase,
  uppercase first; ignored entirely when `REQUEST_METHOD` is set (CGI guard);
- macOS: the SCDynamicStore HTTP and HTTPS proxy settings;
- Windows: `ProxyEnable`, `ProxyServer`, `ProxyOverride` under the user's
  Internet Settings.

wss:// is matched as https://, ws:// as http://, and a TURN TCP or TLS URL as
https:// (the tunnel is a CONNECT either way). Credentials come from the proxy
URL's userinfo and are sent as `Proxy-Authorization: Basic`.

**Correction (PAC, auth schemes, proxy schemes).** The design listed PAC. reqwest
does not evaluate PAC or WPAD, and neither will 0.9.3; on Linux, desktop proxy
settings (GNOME, KDE) are not read either. NTLM, Kerberos and Negotiate proxy
auth are not supported. An `https://` proxy (TLS to the proxy itself) and
`socks5://` proxies are refused with a sentence naming the scheme; reqwest
supports both for REST, so this is a known mismatch for later.

## 7. The route word

**Correction (there is no single vocabulary yet).** The design assumed one route
word (LAN / DIRECT / RELAY). The code has three: the browser contract
(`CONTRACT.md`, "`peer.route`": `local`, `direct`, `relayed`); the CLI's
`Peer::route` (`net.rs`: `relay`, `direct over <iface>`, with `ROUTE_RELAY`
compared by `ping.rs`); and `direct-quic` from the direct path. `route()` is
compared against in code, so changing its words is a protocol-adjacent change
(see `never-relax-a-failing-assertion`).

0.9.3 therefore changes only the shown form, `Peer::route_shown`, which already
appends the relay's transport (`relay (TURN over tls)`): it now also appends the
carrier when it is not plain, `relay (TURN over tls via proxy)`. `route()` is
untouched. Unifying the three vocabularies into one word across status, devices,
the browser and `--json` is its own change, after 0.9.3.

## 8. Censorship

The principle: many cheap carriers behind one interface, raced; no single
blocklist entry, fingerprint or probe takes all of them out.

| Censor capability | Answer | Phase |
|---|---|---|
| IP or domain blocklist | many cheap, rotatable rendezvous: Cloudflare Workers on several domains (`docs/cf-signaling.md` already runs the backend on Workers), user-run relays, fleet devices relaying for each other | later |
| Signaling blocked entirely | serverless signaling: the offer exchanged out of band (QR, paste), safe with short codes because of SPAKE2; LAN, Bluetooth, mesh discovery | later |
| DPI fingerprinting | look like ordinary HTTPS to a CDN (WebSocket relay on the API domain), or like random bytes (pluggable transports) | later |
| Active probing | relay silent until the client proves a secret | later |
| SNI blocking | ECH | later |
| DNS only | dnstt-style tunnel; slow, signaling-class traffic only | later |
| Whitelist | Snowflake-style volunteer browsers as relays; tunlion already runs in browsers | later |

External circumvention transports (obfs4, WebTunnel, Snowflake) run through the
Tor pluggable-transport interface (PT spec v1: managed subprocess, SOCKS
handoff), so tunlion does not maintain those protocols. A PT is a
`StreamCarrier` whose `dial` goes through the PT's local SOCKS listener.

Who decides: the person running tunlion. Circumvention is tried automatically
when plain paths fail, and it is always shown. Admins can turn it off. Relays
carry only paired-peer traffic (TURN credentials are minted per `/api/config`
fetch; signaling relays only between peers in a room), and are never an open
proxy.

## 9. UX

- Zero configuration by default: the proxy environment and OS settings (section
  6), the OS CA store and `SSL_CERT_FILE`/`SSL_CERT_DIR` (PR #621).
- Route: `via proxy` (and later `via https`, `via bridge`) appears only for a
  non-plain carrier, in the shown route and in `doctor --json`.
- Failure: one sentence with one action, for example "the proxy at
  proxy.corp:3128 refused to tunnel to api.tunlion.autumated.com:443 (407 Proxy
  Authentication Required): put credentials in HTTPS_PROXY". The full tried and
  blocked table is only in `tunlion doctor`.
- Three settings, later: `network.transports` (auto | pinned list),
  `network.circumvention` (auto | off), `network.bridge` (a bridge line).
  Invitation files and QR codes may carry a bridge; the spoken code cannot.
- No new commands.

Usage this has to serve: an agent sandbox or CI box (`npm i -g tunlion`,
`tunlion join <code>`, route `relay (TURN over tls via proxy)`); a corporate
laptop (OS CA and proxy picked up); a censored user (a bridge from a setting or
a friend's invitation); an admin (circumvention off).

The browser needs no work for proxies: it already uses the system proxy and the
OS trust store, and already falls back from websocket to polling
(`signalTransport.js`). Parity work starts with the WebSocket relay and PTs.

## 10. Proof and tests

`proofs/carrier_model.py` discharges the assumption the establishment model
states as A4 ("a path exists", `proofs/README.md`): it explores every
combination of per-peer carrier availability and a censor that blocks carrier
classes at rendezvous, runs the selector, and checks:

- **reach**: if both peers have at least one unblocked carrier class to a
  reachable signaling rendezvous, and to a reachable relay (or one side is
  directly reachable), establishment succeeds within a bound fixed by the
  tier gates;
- **no leak by selection**: a carrier is only ever handed bytes that are
  already encrypted end to end, or signaling TLS (the metadata caveat in
  section 2 is modelled as an explicit observer, not assumed away).

It runs with `--self-test`, which re-runs it against mutants (a selector that
stops at the first failed tier; signaling that ignores the proxy; a TLS gate
keyed on a TCP attempt starting rather than a TCP relay existing) and requires
each to be caught.

CI network profiles (each must pair, transfer and exec, against a local
signaling server and coturn, never production):

| Profile | Network | 0.9.3 |
|---|---|---|
| proxy-only | network namespace, UDP and direct TCP dropped, only squid reachable | yes |
| inspecting proxy | squid ssl-bump with a custom CA, `SSL_CERT_FILE` | after #621 is on main |
| no websockets | proxy strips `Upgrade` | with long-polling |
| DNS only, IP blocklist, inbound-only | as named | later |

## 11. Install path

npm per-platform packages in `optionalDependencies`, so the binary comes from
the npm registry and a sandbox that blocks GitHub downloads still installs
(GitHub download stays as the fallback). crates.io publish of all internal
crates after that.

## 12. Phases

**0.9.3**: `StreamCarrier` with direct and HTTP CONNECT carriers; signaling
through the proxy (NO_PROXY, Basic auth from the URL, same matcher as REST);
TURN TCP/TLS through the proxy via `turn_bridge`; `via proxy` in the shown
route; the carrier rows in `doctor`; the proxy-only CI profile; the carrier
model with its mutants; npm platform packages.

**Later**: long-polling signaling for the CLI; WebSocket relay on the API
domain; PT interface; fleet devices as relays; serverless signaling; the three
settings; per-network memory and the 250 ms stagger; one route vocabulary;
inspecting-proxy profile; inner encryption for signaling metadata; PAC,
NTLM/Negotiate, `https://` and SOCKS proxies for signaling.

## 13. Corrections, collected

1. The stack consumes relays only through webrtc-ice; direct QUIC never rides a
   carrier. The interface is a stream carrier; the datagram form is the existing
   TURN bridge, and TURN framing needs no length prefix.
2. A configured proxy is used, not raced against direct, matching reqwest/curl.
3. Proxy discovery is reqwest's matcher, which has no PAC/WPAD and no Linux
   desktop settings; Basic auth only; `http://` proxies only for signaling and TURN.
4. There is no single route word; 0.9.3 extends the shown route only.
5. Behind a TLS-inspecting proxy, signaling metadata is visible to the proxy;
   code secrecy and data-path integrity still hold.
6. "Inbound-only peer to a listening peer" exists for CLIs over UDP only.
