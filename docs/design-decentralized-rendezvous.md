# Decentralized rendezvous: any node can be a meeting point

> Status: design. Formalizes one line from `docs/design-mesh-network.md`
> ("make the signaling server self-hostable; let a stable peer double as the
> rendezvous"). The claim: **any filament node can be a rendezvous; the global
> server is demoted to a cold-start default**, not a dependency. This is a UX /
> plumbing note, not a crypto change. Three of the four hard parts already exist.

## Current role of the global rendezvous

`DEFAULT_SERVER = "https://api.filament.autumated.com"`
(`cli/src/main.rs:94`) does exactly three things, all control-plane:

- **Blind signaling.** Socket.IO exchange of SDP / ICE candidates so two peers
  can holepunch. It never sees content and never decides who may talk to whom
  (`docs/design-mesh-network.md:186`, "signaling never decides who may talk to
  whom").
- **Presence / discovery.** Per-channel "who is here" for a channel id that is
  itself `sha256("filament-pair:" + secret)` (`cli/src/main.rs:1765`,
  `channel_of`). The server sees meeting points, never secrets.
- **Serves `/api/config`.** Clients fetch the STUN/TURN list before every
  connect (`cli/src/net.rs:867`, `fetch_config` -> `{server}/api/config`).

**TURN is a separate tier, not part of "be a rendezvous."**
`turn.filament.autumated.com` (`deploy/README.md:11`) is a bulk relay, obtained
dynamically via `/api/config`, kept regional and metered per
`docs/design-edge-signaling.md:92`. Being a rendezvous is signaling + presence +
config, none of which touch peer bytes.

**Trust does not flow through the server.** Pairing is SPAKE2 PAKE over the
spoken words (`cli/src/pake_ceremony.rs:134`); re-auth is an HMAC pair-proof
bound to the DTLS session (`cli/src/main.rs:1799` `proof_for`, on-wire at
`cli/src/l2.rs:1419`). The introducer already brokers first-contact trust
peer-natively and blind: identity exchange rides A<->B's own direct DTLS
DataChannel, and the introducer is not a DTLS endpoint
(`cli/src/main.rs:2593`, "direct DTLS keeps introducer BLIND"). The server URL
is fully swappable (`--server` / `FILAMENT_SERVER` / config `server`, falling
back to `DEFAULT_SERVER`: `cli/src/main.rs:421`, `cli/src/settings.rs:94`).

**The gap:** trust is already peer-native and blind, but the introducer still
reaches A and B *through* the global signaling server. There is no
peer-as-rendezvous for NAT-traversal signaling today.

## The painless build shape

Three of the four hard parts already exist:

- **Self-detecting rendezvous capability is free.** A public-address node learns
  its own reflexive `ip:port` from STUN (`cli/src/holepunch.rs:57`
  `stun_srflx`), and cone-vs-symmetric is already reasoned about in the same
  file (`holepunch.rs:103`, "on a cone NAT every server returns the same
  value"). `is_private_addr` (`cli/src/net.rs:1699`) already tells a node
  whether its address is routable. A node can decide "I can be a rendezvous"
  with code that already ships.
- **The always-on box already exists.** `filament up --install` (systemd) is the
  standing public-address daemon a rendezvous needs.
- **The `--server` swap point already exists** (above), and rendezvous vs relay
  are deliberately distinct commands (`docs/design-mesh-network.md:207`, "keep
  rendezvous and relay distinct in the protocol").

The **two genuinely-new pieces are both UX / plumbing, not crypto:**

1. **Address distribution over the existing blind introducer channel.** A
   rendezvous address is a non-authorizing *hint*. Ride it on the same
   fingerprint-bound, pair-proof'd DataChannel `introduce` already uses. No URL
   pasting, and a hostile box cannot inject itself: the address arrives inside
   an already-authorized channel, and it grants no authority anyway (it is just
   "meet me here"; the pairing / pair-proof still gates who talks).
2. **Server as a raced list, not a single value.** Replace the one `server`
   string with an ordered list (hosted default + any self-hosted), tried the way
   the transport ladder already races paths. A self-hosted rendezvous being down
   then never strands anyone: it is an optimization, never a dependency.

**Sharp edge, with a clean answer.** A self-hosted rendezvous must also serve
`/api/config` (clients fetch it before connect). But a public-IP node *is* a STUN
reflector, so `filament up --rendezvous` can auto-serve its own config (its own
`ip:port` as a STUN entry, TURN list optional / inherited) with zero operator
env vars.

**Net UX:** `filament up --rendezvous` + address-over-introducer +
server-as-raced-list.

## Multi-rendezvous mechanics and scale

**Capacity is a non-issue.** A rendezvous is control-plane only: bytes never
touch it (the data plane is P2P). Load is bursty (first-contact, plus
reconnect-after-address-change), known peers skip signaling entirely via
cache-and-dial (`docs/design-edge-signaling.md:70`), and LAN / known-address
peers never signal at all. Its one bit of state, per-channel presence keyed by
`channel_of(secret)`, shards perfectly (`docs/design-edge-signaling.md:53`, "it
already shards").

**The real ceiling is selection**: two peers must independently pick the *same*
rendezvous, with no chatter.

For **already-paired peers this is solved by rendezvous hashing (HRW).** Both
sides share the pair secret and the server list. Each computes
`score(server_i) = H(pair_secret, server_i)`, ranks, and picks the top live one.
Identical inputs give an identical pick, so they meet in channel
`H(pair_secret)` with no negotiation.

- N = 10 or 100 rendezvous is irrelevant: each pair picks *one*, not all N.
- Server down falls to the next-ranked, and both sides agree on the fallback
  because both rank the same list.
- Load self-shards by pair (different secrets -> different top picks).
- The **hosted default sits in everyone's list as a guaranteed shared floor** if
  custom lists diverge. Optionally subscribe the top K=2 for skew tolerance.

**Honest caveat.** HRW needs both sides to agree which ranked server is *live*.
A flapping server (up for one peer, down for the other) can briefly split them
onto different picks. The shared floor catches this: if the top picks disagree,
both still hold the hosted default in common.

## The honest boundary

HRW works because paired peers **share a secret to hash on.** Cold **stranger
first-contact has no such secret**, so it genuinely needs one of: the hosted
floor, explicit federation (someone names the rendezvous out of band), or open
discovery (a DHT). Open discovery is the unsolved Sybil / eclipse frontier. This
note does **not** claim it is solved.

So the design is deliberately two-tier:

- **Many rendezvous for shared-context connects**: teams, and introducer-linked
  trust webs, where a pair secret (or an authorized introducer channel) already
  exists to HRW on or to carry the address hint.
- **Hosted default as the meet-anyone floor**, for the strangers and the
  list-divergence corner.

This decentralizes the ~90% of connects that already share context, without
reintroducing the central coordinator the project rejects
(`docs/design-mesh-network.md:142`).

## Open / to build

1. **Address-over-introducer.** Carry a rendezvous address as a non-authorizing
   hint on the existing blind, pair-proof'd introducer DataChannel. No new trust
   surface; a hostile box cannot inject itself.
2. **Server-as-a-raced-list.** Turn the single `server` value into an ordered
   list (hosted default + self-hosted), raced like the transport ladder, with
   HRW selection over the list for paired peers.
3. **`filament up --rendezvous` self-serving `/api/config`.** A public-IP node
   auto-serves its own STUN config (it is already a reflector), so standing up a
   self-hosted rendezvous needs zero operator env vars.

## Out of scope

Global, Sybil-resistant stranger discovery (open DHT rendezvous). That is the
unsolved frontier; the hosted floor covers the no-shared-context case until it
is solved elsewhere.

See also: `docs/design-mesh-network.md` (why filament stays pairwise; the
signaling-is-not-the-coordinator section this note builds on),
`docs/design-edge-signaling.md` (per-channel sharding and cache-and-dial).
