# Design: detect and survive UDP-hostile networks

Status: DESIGN (pre-implementation). Owner: filament core. Reviewers: claude-advisor
(security), then a coding agent implements per the phasing below with a live rig gate.

## 1. Problem and the current reality

filament connects peers with two transports: a WebRTC DataChannel (DTLS/SCTP over
ICE, via webrtc-rs) and a direct-QUIC transport (quinn, UDP-only), plus a TURN relay
(coturn) as fallback. On networks that block or throttle UDP — corporate firewalls,
hotel/airport wifi, mobile carriers, DPI that only passes TCP/443 — a P2P tool quietly
dies. We want it to keep working there, and to be honest about how.

The reconnaissance turned up something worse than "needs a fallback." The one path an
earlier analysis believed survived a full UDP block — TURN over TCP on 3478 — **does not
actually work from the Rust client.** In `webrtc-ice` 0.17.1, `gather_candidates_relay`
(`agent_gather.rs:776-805`) implements exactly one case, `ProtoType::Udp && SchemeType::Turn`
(plain TURN over UDP). The TURNS (TLS) and TCP-TURN cases are a literal commented-out
`/*TODO*/` ported from the Go source and never written; neither `turn` nor `webrtc-ice`
even depends on a TLS library. So:

- **The `turns:443` advertisement is a typo AND unusable by the CLI.** coturn listens TLS
  on 443, the config advertises plain `turn:` there, and even a corrected `turns:` URL
  cannot be dialed by webrtc-ice.
- **Today, on a full UDP block, the Rust CLI has no surviving peer data path at all** —
  every relay candidate it can form requires UDP. It fails clean after ~5s (direct-QUIC
  budget) + up to ~45s (WebRTC establish grace), silently, with no indication that UDP
  was the cause.
- Signaling itself always survives (WSS/TCP/443 behind Cloudflare), so peers still
  discover and negotiate — they just cannot open a data path.

Because the WebRTC stack cannot do TCP or TLS relay, **the entire TCP/443 survival story
must be filament-native, outside webrtc-rs.** That constraint is what shapes this design.

## 2. Goals and non-goals

**Goals**
- A peer data path that survives a full UDP block (and the stricter case where tcp/3478
  is also blocked), over TCP/TLS on 443.
- A *direct* (non-relayed) path where one is reachable without hole-punching (same-LAN,
  or a peer with a public/forwarded port), even when UDP is blocked.
- Fast, non-silent failover: no 50-second stall before a working path is tried.
- Traffic that looks like ordinary web traffic to the networks in question, without an
  arms-race obfuscation layer.

**Non-goals (explicitly not building)**
- **Obfuscation / active DPI evasion** (fingerprint mimicry, byte-transforms, padding).
  When "looks like HTTPS/WebRTC" fails on a corporate net, the cause is almost always
  *destination policy* (WebRTC allowed to Zoom/Teams, denied to an unknown relay), which
  obfuscation cannot fix. It is also an endless arms race, gets the tool quarantined by
  endpoint security, and on a managed device is the *user's* acceptable-use risk. If ever
  wanted, it ships opt-in and labeled, never a silent default. Design the transport so a
  byte-transform *could* slot in later; do not build one now.
- **A UDP-block detector.** A probe is a second code path that can disagree with reality
  and taxes every connect. We race instead; parallel attempts self-detect (§7).
- **TCP hole-punching (simultaneous-open).** Materially less reliable than UDP punching
  (firewalls connection-track TCP and drop out-of-state SYNs); Tailscale, the reference
  for this problem, does not attempt it. Its failure mode is a slow timeout before
  fallback, i.e. it makes the bad networks *worse*. Direct TCP is no-punch only.
- **Forking webrtc-ice** to implement its TCP/TLS-TURN TODO. That is TURN framing + rustls
  + ICE plumbing inside a dependency we would then maintain against upstream, to obtain a
  relay we can write ourselves with no ICE semantics. Held as a fallback only.

## 3. Architecture

One new **filament-native TLS-over-TCP transport** implementing the existing `Transport`
trait (`cli/src/net.rs:280`), with **two dialers** — because, per the advisor, DERP relay
and no-punch direct TCP are the *same transport* with different ways of reaching the peer,
not two phases:

```
                         ┌─────────────────────────────────────────┐
                         │  TlsTcpTransport  (impl Transport)       │
                         │  end-to-end TLS (rustls) between A and B │
                         └───────────────┬─────────────┬───────────┘
                    direct dialer        │             │   relay dialer
          ┌──────────────────────────────┘             └──────────────────────────┐
          │ TCP connect to peer's                        │ WSS/443 to DERP relay at │
          │ advertised addr (no punch):                  │ the signaling origin;    │
          │ same-LAN, public/forwarded port              │ relay pairs A<->B and    │
          │                                              │ forwards opaque bytes    │
          └──────────────────────────────────────────────┴──────────────────────────┘
```

Key property: **the TLS session is end-to-end between the two peers in both dialers.** In
the relay case that end-to-end TLS runs *inside* the relay-forwarded WSS tunnel, so the
relay (and any DPI middlebox terminating the outer 443 TLS) sees only ciphertext. This is
the same trust shape as the existing DTLS/DataChannel path, where peer traffic is DTLS
end-to-end and the middlebox sees only TURN framing.

Existing transports are unchanged and stay as the preferred, faster legs where they work:
direct-QUIC (UDP), WebRTC DataChannel (UDP/ICE), and coturn/UDP-TURN as the relay tier
*above* the new one. The new transport is the tier that survives when all UDP is gone.

## 4. The transport (`TlsTcpTransport`)

- **Wire:** a single TLS 1.3 session (rustls) over a byte stream. The byte stream is a
  raw TCP connection (direct dialer) or the relay-forwarded stream (relay dialer). The
  transport does not know or care which; it is handed an `AsyncRead + AsyncWrite`.
- **Identity of the session:** an ephemeral self-signed certificate per connection, exactly
  as the WebRTC path uses an ephemeral DTLS cert. The certificate fingerprints are folded
  into pairing/confirmation (§6), so a substituted cert breaks confirmation.
- **Framing:** length-prefixed frames matching the `Transport` trait's expectations
  (control + data channels), reusing the existing message framing so `send_control` /
  stream I/O behave identically to the QUIC and DataChannel transports.
- **Candidate advertisement:** reuse the existing `transport-offer` exchange in
  `cli/src/l2.rs` that direct-QUIC already uses to advertise direct addresses; add (a) the
  peer's TCP listen address(es) for the direct dialer and (b) a relay ticket (§5) for the
  relay dialer. No new signaling message type is required beyond extending the offer.

## 5. The relay (DERP-style WSS/443 byte-forwarder)

A minimal service co-located with the signaling origin (same hostname / Cloudflare front,
so it inherits a destination reputation corporate policy already permits — this is why
signaling survives everywhere, and why we do NOT try to push TURN through the CDN, which
cannot carry it).

- **Protocol:** WebSocket over TLS/443 (HTTP-upgrade, which the CDN proxies — unlike TURN).
  Each client sends an `attach` frame with its relay ticket (§5.1), then the service
  forwards opaque binary frames between the two clients of a pair. It never inspects,
  decrypts, or stores payload — it sees only ciphertext plus the pair id.
- **Pairing:** the service keys a table by `pair_id`. The first client to attach for a
  `pair_id` waits; the second completes the pair; thereafter every frame from one side is
  written to the other. On either disconnect or an idle timeout, the pair is torn down.
- **Limits:** max frame size, idle timeout, and a per-pair (and per-identity) bandwidth
  cap, logged when hit. These bound cost and abuse even for authenticated pairs.
- **Statelessness:** no payload persistence; the only state is the live in-memory pair map.

### 5.1 Relay authentication (load-bearing — decided before the first line)

An open byte-forwarder on our infrastructure is an abuse magnet and an unbounded bandwidth
bill, and unlike TURN it has no credentials of its own. We bind relay access to the
signaling session, which already knows who is talking to whom (Tailscale authenticates
DERP by node key; we authenticate by the pairing signaling already performed):

- When signaling matches two peers A and B (they are already exchanging offers), the
  signaling server issues each a short-lived **relay ticket**:
  `ticket = { pair_id, side, exp, nonce, mac }` where
  - Two subkeys are derived from the shared key `k` with **domain separation** so no value
    can be reinterpreted across uses: `k_id = HKDF(k, "filament/relay/pair-id")` and
    `k_mac = HKDF(k, "filament/relay/ticket-mac")`. (Without this, `pair_id` and `mac` use
    one key for two purposes and a `pair_id` handed to a peer could coincide with a valid
    `mac` — the same key-reuse class as the cold key signing both device certs and cap ops,
    and the overlay key's multiple duties. Domain separation makes the question disappear.)
  - `pair_id = HMAC_{k_id}( sort(A_session_id, B_session_id) || round_nonce )` — unique to
    this specific A↔B pairing and this attempt; identical value derivable for both sides,
    opaque to the relay beyond equality. `round_nonce` is fresh per pairing attempt.
  - `side` ∈ {0,1} so the relay pairs one of each and never joins two A's.
  - `exp` — a short expiry (target ~30s; must exceed expected attach latency, not more).
    **Clock dependency:** signaling issues and the relay checks `exp`; if they are separate
    hosts they MUST share a clock source (NTP) or the relay MUST apply an explicit skew
    allowance, because a 30s window is small enough that a minute of drift makes every
    ticket dead-on-arrival or valid far too long.
  - `mac = HMAC_{k_mac}( pair_id || side || exp )` under the shared key `k` (verified by the
    relay offline; NOT a signaling callback — see §12). `round_nonce` is already committed
    inside `pair_id`, so the ticket carries no separate nonce.
- Each peer presents its ticket in the `attach`. The relay verifies `mac`, checks `exp`,
  and pairs the two `attach`es that carry the same `pair_id` and opposite `side`. No valid
  ticket → no forwarding. Rate-limit ticket issuance per identity at the signaling server.
- The ticket authorizes *forwarding between these two peers for this attempt only*. It is
  not a bearer credential for arbitrary relaying: it is pair-scoped, side-scoped, and
  short-lived. A leaked ticket buys ciphertext forwarding, not access (payload is
  end-to-end encrypted, §6). **The residual risk is DoS, not compromise:** an attacker who
  presents a leaked ticket first *occupies* that side of the pair, so the legitimate peer's
  later attach finds the pair complete and is rejected and loses its relay path for that
  attempt (the inner handshake then fails, so there is no MITM). Short `exp` + per-identity
  issuance rate limits exist to bound this DoS window, not only to bound confidentiality.

This is deliberately *not* the app-layer capability system — the relay makes no
authorization decision about what the peers may *do*; that stays entirely in the existing
capability gates, which run over the end-to-end channel after the transport is up. The
ticket only answers "may these two bytes-streams be spliced," which is an infrastructure
question, not a trust question.

## 6. Channel binding (load-bearing — the DPI-MITM defense)

The networks this feature exists for are precisely the ones that intercept TLS on 443. If
identity binding were derived from the *outer* transport TLS (peer↔relay WSS, or a
proxied direct TLS), a corporate middlebox that terminates 443 would hold a perfectly
valid binding and become an undetected MITM — the feature would be least trustworthy
exactly where it is most used. So:

- **The binding comes from the INNER end-to-end TLS session between the two peers, never
  the outer 443 TLS.** In the relay case that inner session runs inside the forwarded WSS
  tunnel; the relay/middlebox cannot terminate it. In the direct case the transport TLS is
  already end-to-end, and the same inner-session binding is used, so there is one binding
  mechanism for both dialers.
- **The bound value is the inner TLS session's EXPORTER** (RFC 5705 / 9266;
  `rustls::ConnectionCommon::export_keying_material` with a filament label). The exporter is
  session-unique by construction, which collapses invariant 3 into the primitive instead of
  leaving "add a session-unique input" as a rule to remember: two sessions between the same
  peers produce *different* exporters, whereas cert fingerprints identify the keys and would
  repeat. Cert fingerprints MAY be folded in as well for defense-in-depth, but the exporter
  is the value that carries the property.
- **The binding has a different HOME per flow — bind in all of them, not just pairing.**
  "Fold it into `confirm_mac`" specifies only the pairing ceremony; a reconnecting or
  enrolling peer binds elsewhere, and getting it in pairing but not reconnect is the same
  shape as the ceiling being right in `evaluate` while `cap_authorize` passed `None`. In
  EVERY case the bound value is the inner-session exporter; only the carrier differs:

  | Flow | Binding carrier |
  |------|-----------------|
  | Pairing (PAKE) | `confirm_mac` (folded alongside the sorted fingerprints) |
  | Reconnect — PAKE path | `possession_msg` `binding_value` (currently `cmv`) |
  | Reconnect — introduce path | `possession_msg` `binding_value` (currently receiver nonce) |
  | Auth-key enrollment | the daemon-held challenge nonce |

Four invariants, each of which we have been bitten by in a different form:

1. **Never optional / never fallback-able.** A `TlsTcpTransport` that cannot produce an
   inner-session exporter is *refused for identity-expose* — meaning the peer never reaches
   Proven and therefore falls to grant-only (the coherent degraded state that matches the
   rest of the system), NOT that the connection is dropped. The transport stays usable for
   non-identity traffic; it simply cannot be the basis of a Proven binding. (Dropping the
   connection instead would break the fallback; refusing only the *identity* elevation is
   the correct degrade.) A binding you can *skip* is the optional-`device_cert` side door.
2. **Never transmit the binding value.** Both ends compute it independently from the
   established inner session. A binding sent on the wire is a binding an in-path attacker
   supplies to both sides.
3. **Contribute a session-unique input.** `confirm_mac` binds *sorted* fingerprints, which
   erases direction; the TLS-TCP transport must contribute a per-session-unique value
   (e.g. the TLS exporter, or a fresh nonce mixed like `K` on the PAKE path) so the
   direction-erasure that is harmless today cannot be exploited on the new path.
4. **The relay is not in the trust path.** It forwards ciphertext and authenticates only
   the splice (§5.1). It never sees identity *claims*, capabilities, or plaintext, and
   holding a valid ticket grants no capability — those are decided end-to-end after the
   transport is up. It DOES see metadata: the pair relationship, both session ids, and per-
   connection timing and volume. That metadata exposure is the honest cost of any relay and
   is stated so "not in the trust path" is not read as "sees nothing."

## 7. Failover: happy-eyeballs, no detector

Today the ladder is sequential: ~5s direct-QUIC, then up to ~45s WebRTC establish grace,
then relay escalation — up to ~50s of silent "establishing" before a surviving path is
even attempted. Replace with a staggered parallel race:

- t=0: start direct-QUIC (UDP), WebRTC (UDP/ICE), and the direct TLS-TCP dialer together.
- t≈1s: start the DERP relay dialer (the only UDP-independent leg). The 1s stagger avoids
  relaying connections that would have gone direct, which is the sole cost of the relay leg.
- **First transport to establish AND verify its channel binding wins;** the others are torn
  down. Prefer a direct/UDP transport over the relay when both arrive within a small window,
  since the relay is slower and costs bandwidth.
- No UDP-block detector: the race self-detects. If direct-QUIC still *hangs* rather than
  failing fast under a UDP block, fix the hang with a bounded attempt (it already has a 5s
  budget), do not add a probe to route around it.
- **Optional, low priority:** a per-network *hint* (keyed on gateway/SSID) that only
  *reorders* the race to try the winning leg first next time — never a cached verdict that
  *skips* a path (networks change; a cached "UDP blocked" would strand a user on relay
  after they leave the hotel). Note the small privacy cost of writing a network fingerprint
  to disk given the no-account posture; make it opt-in or off by default.

## 8. Cheap wins folded in

- **`turns:443` config fix — keep it, for browsers.** Dead for the Rust CLI (webrtc-ice
  cannot dial `turns:`), but the frontend feeds the server's `iceServers` straight into
  `new RTCPeerConnection({ iceServers })` (`frontend/src/lib/webrtc.js:422`), and browsers
  *do* implement `turns:`. So advertising `turns:IP:443` (TLS) helps the web-shell/browser
  clients traverse strict networks. One-line change in the TURN advertisement; verify the
  browser path end-to-end.
- **ALPN / cleartext-fingerprint hygiene.** On our own TLS-TCP transport we control the
  ClientHello. Present browser-like ALPN (`h2`/`http/1.1` for the WSS relay so it looks
  like the web traffic it rides among; ordinary extension ordering; no custom protocol
  name that fingerprints as "filament"). Audit the direct-QUIC and DataChannel handshakes
  for any product-identifying cleartext string (ALPN is the likeliest offender), and any
  product string in the signaling handshake. Skip padding/timing (obfuscation territory).

## 9. Security analysis (summary)

- **DPI TLS interception on 443:** defeated for the *relay* path by the inner end-to-end
  TLS (relay/middlebox sees ciphertext + TURN-like framing only), and for the *direct*
  path by binding to the end-to-end transport TLS, never a proxied outer TLS (§6).
- **Relay abuse / cost:** bounded by signaling-scoped, side-scoped, short-lived tickets
  plus per-pair/identity rate and bandwidth limits (§5.1). No ticket, no forwarding.
- **Relay as trust boundary:** it is not one. It authenticates a splice, forwards
  ciphertext, and grants no capability. All authorization stays in the existing gates,
  end-to-end.
- **Downgrade / side-door:** the new transport is refused for identity-expose unless it
  produces a valid inner-session binding (§6 invariant 1), so it cannot become a
  weaker-authenticated path than QUIC/DTLS.

## 10. Phasing (order of work)

1. **turns:443 one-liner + browser verification** (independent, tiny, helps browsers now).
2. **`TlsTcpTransport` + the relay dialer + the DERP relay service + relay auth + inner
   channel binding** — the survival mechanism. The bulk. Ship behind the happy-eyeballs
   race as the UDP-independent leg.
3. **Happy-eyeballs failover rework** (can land with or just after 2; turns the 50s stall
   into ~1s and is what makes 2 actually get used promptly).
4. **Direct dialer** on the same transport (no-punch: LAN + public/forwarded port). Small
   addition once the transport exists — "a dialer, not a phase."
5. **ALPN / fingerprint hygiene audit** (cheap, do alongside).

Held as a fallback only, not planned: forking webrtc-ice for in-WebRTC TCP/TLS candidates.

## 11. Verification (the rig gate — nothing ships on "it compiles")

On the do-vm ↔ other-do cross-machine rig:

- **Baseline:** a transfer + a shell open succeed normally (UDP available), unchanged.
- **UDP blocked:** `iptables`-DROP all UDP on the test box; assert a transfer and a shell
  still succeed, over the DERP relay on 443, and that the connect completes in ~seconds
  (happy-eyeballs), not ~50s.
- **UDP + tcp/3478 blocked** (the strict-corporate case): same assertion — must still work
  over 443.
- **Direct dialer:** on a two-host LAN with UDP blocked, assert the *direct* TLS-TCP path
  is selected (not the relay) and a transfer succeeds.
- **Relay auth:** a connection to the relay with a missing/expired/wrong-pair ticket is
  refused; a valid pair is forwarded. Prove the relay forwards only ciphertext (capture
  shows no plaintext).
- **Channel binding / MITM:** simulate an on-path terminator of the outer 443 TLS and
  assert identity-expose still fails to bind to the middlebox (the inner session's
  fingerprints do not match) — i.e. the middlebox cannot become an authenticated MITM.
- **No regression:** the existing UDP-available paths (direct-QUIC, DataChannel) still win
  the race when UDP works; the relay leg is torn down when a direct leg wins.

## 12. Decisions (was open questions; resolved in review)

- **Ticket auth: shared HMAC key, NOT a signaling callback.** A callback couples relay
  availability to signaling availability and adds a synchronous hot-path dependency; a
  shared key (with domain separation per §5.1 and a rotation story) lets the relay verify
  offline.
- **Relay hosting: a sibling service, NOT in the signaling process.** Bulk byte forwarding
  inside the Flask-SocketIO signaling process would compete with signaling for the event
  loop, and signaling is the one thing that already survives everywhere. Keep them separate,
  same origin/hostname so the destination reputation still applies, so a relay bandwidth
  spike cannot starve signaling.
- **Inner binding value: the TLS exporter** (§6, hole 5). Cert fingerprints optional
  defense-in-depth.

Still open (non-blocking):
- Whether the direct TLS-TCP dialer should also advertise on the LAN via mDNS for the
  same-LAN case, or rely solely on signaling-exchanged host candidates.
