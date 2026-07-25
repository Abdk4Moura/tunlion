# Mesh networking: why filament stays pairwise

> Status: decided (2026-07-16). This note records a design question that was
> taken seriously, explored exhaustively, and deliberately answered "no." It
> exists so the next person (or agent) who proposes a mesh control plane can see
> the reasoning already done, rather than re-run it. The near-term build list at
> the bottom is the actionable part.

## Summary / decision

filament will **not** build a mesh: no hub federation, no gossip control plane,
no transitive trust, no kernel-L3 mesh, no third-party store-and-forward. These
were steelmanned and rejected on the merits.

What filament builds instead, to serve both small trusted teams and larger
agent/team meshes with the *same* primitives:

- **Transport hardening** (highest-utility move): happy-eyeballs path racing,
  QUIC lossy-link tuning, connection migration, faster dead-link detection,
  warm-hold (done).
- **Self-hosted relay flag**: let a user supply their own relay, solving the
  relay-privacy concern with zero group state.
- **Single-hop peer-relay among authorized peers** (static/manual first): a
  stable peer can relay for its authorized peers.
- **Introducer-TOFU onboarding**: reduce pairing friction. The introducer is a
  key-exchange helper, not an authorization delegate; the user always confirms.

Anything that genuinely needs multi-hop segmented routing is **out of scope**.
For that need, a mesh product (Tailscale, WireGuard, Yggdrasil) is the right tool
*instead of* filament, not under it: if two nodes already share a tailnet, that
mesh has already connected them and filament adds nothing between them. This is
the same boundary filament already draws by having no subnet routers and no exit
nodes, and it comes with the coordinator / account / admin-controlled-membership
tradeoff filament exists to avoid. filament does not compose *onto* a mesh to
gain reach; it declines the use case. (Distinct and legitimate: filament may
select an existing `tailscale0` interface as one candidate path for its own
pairwise connection, per `docs/filament-routing.md`. That is transport-interface
selection, not a mesh-reach strategy, and it is redundant if raw connectivity is
all you want.)

## The question

Warm-hold turns the daemon from a set of on-demand tunnels into a standing graph
of connected peers. That standing graph is the substrate a mesh control plane
would need, so the natural question was: should filament grow one? Propagate
presence, rosters, and capabilities by gossip; route to peers through on-path
peers ("reach C through B"); hold mail for offline peers. And could a single
design serve both small trusted teams and an agent/team mesh at scale?

## The design space

Every strategy is a choice on a handful of mostly-orthogonal axes:

- **Membership / trust**: none · static roster · introducer-TOFU · gossip (SWIM) ·
  central coordinator · global DHT
- **Relay / reachability**: direct+holepunch only · public relay · self-hosted
  relay · manual peer-hub · auto-selected peer-relay · full source-routing
- **Who you can reach**: directly-paired only · paired-but-relayed ·
  transitively-trusted · open
- **Path selection**: fixed serial ladder · happy-eyeballs race ·
  measured-adaptive · multi-path bonding
- **Layer**: app-L7 · userspace-L4 · kernel-L3
- **Async delivery**: none · your-own-node queues your outbound · third-party
  store-and-forward · delegate to email/Matrix
- **Naming**: petnames · static-roster names · MagicDNS

Coherent end-to-end paths through those axes: (0) status quo, (1) transport-only
hardening, (2) static minimal mesh, (3) discovered Tier-A mesh, (4)
transitive-trust Tier-B mesh, (5) centralized coordinator (become Tailscale), (6)
full decentralized overlay (libp2p/Yggdrasil), (7) compose over an existing mesh,
(8) async-without-storage (own-node queue), (9) introducer-TOFU pairing.

## The frontier

Two independent analyses converged on the same live frontier: **1, 2, 7, 8, 9**,
with transport hardening (1) as the top move. Rejected as dominated or
against filament's ethos: (4) transitive trust kills the pairwise identity, (5)
loses to Tailscale on its own turf, (6) is the wrong scale and a research-grade
routing protocol, kernel-L3 mesh loses to WireGuard/Tailscale/Yggdrasil. Third-
party store-and-forward is a distributed untrusted encrypted storage system
(quotas, GC, replication-needs-consensus, and a real CSAM-hosting liability),
not a networking feature; the useful part is covered by an own-node send queue
(8).

The one hard disagreement was Path 3/4 (the mesh proper). Resolving it produced
the core argument below.

## The core argument: reachability vs authorization

filament's word "pairwise" quietly conflates two different things:

- **Reachability**: who can route bytes to me (a network property).
- **Authorization**: who I will open a secure channel with (a trust property).

The tempting synthesis was "federate hubs, not individuals": keep every trust
link an explicit pairing, but let hubs relay so reach scales. Under scrutiny this
splits by what the hub is allowed to authorize, and every branch fails:

1. **If a hub relays ciphertext only (no authorization power):** then two peers
   can talk only if they *already* authorized each other (direct pairing or an
   introducer the user confirmed). In that case they already have each other's
   keys and addressing, and filament already connects them via
   direct/holepunch/relay. Federation adds value *only* in the corner case where
   direct fails, single-hop relay fails, but a multi-hop hub path works, which
   requires two authorized peers each reachable to different hubs but to no
   common relay. Rare in filament's topologies.

2. **If a hub authorizes on peers' behalf:** that is transitive trust (Path 4).
   A reaches B because an admin paired the hubs, not because A decided about B.
   That breaks filament's actual user contract ("I only talk to devices I
   authorized") and is exactly the identity-killer the project rejects.

There is no third option. And two further observations close it:

- **The gossip has nothing to carry.** With authorization strictly
  device-level, rosters and capabilities are per-pair, and reachability gossip is
  redundant with the addressing you already needed in order to authorize. The
  only hub-gossip-worthy payload is transitive membership, which is Path 4. So
  the control plane has no job.
- **The internet analogy leaks.** On the internet the reachability layer is
  *open* (any host may send to any host; TLS then authorizes). In filament the
  reachability layer is *already* the private graph of authorized pairs, so there
  is no general substrate for federation to optimize. It is "pairwise tunnels
  plus optional multi-hop stitching," and the stitching only pays in the corner
  case above.

Conclusion: separating reachability from authorization does not *save*
federation, it *dissolves* it. What survives is "a stable peer can relay for its
authorized peers" (single-hop peer-relay), which is a deployment pattern, not a
new architecture.

Federation's value genuinely reappears in one place: segmented / enterprise
networks where no single relay crosses a boundary but local nodes can bridge
segments. That is precisely the subnet-router / exit-node space filament chose
not to enter. So this whole analysis re-derives filament's founding scope
decision from first principles: no federation, for the same reason there are no
subnet routers. That segmented use case belongs to a mesh product used *instead
of* filament (with its coordinator/trust-model tradeoff), not to filament stacked
on top of one.

## Decision

**Build.** Transport hardening (in flight); self-hosted relay flag; single-hop
peer-relay among authorized peers (static/manual first, no auto-discovery until
proven necessary); introducer-TOFU onboarding.

**Do not build.** Hub federation; hub-tier gossip; transitive trust (Path 4);
third-party store-and-forward; centralized coordinator / become Tailscale (Path
5); kernel-L3 mesh; full decentralized overlay (Path 6).

**Out of scope.** Multi-hop segmented routing. If a user needs it, a mesh product
(Tailscale/WireGuard/Yggdrasil) is the right tool *instead of* filament for that
need, with its coordinator/trust tradeoff; filament does not stack on top of a
mesh to gain reach.

## Guardrails

1. **Pairwise authorization is absolute.** A talks securely to B only if A made
   an explicit A-to-B trust decision. No relay, hub, or admin ever authorizes on
   a peer's behalf.
2. **The introducer reduces friction, not trust.** It is a key-exchange helper;
   the user (A) always confirms. It must not become an authorization delegate or
   a de facto coordinator.
3. **No `hub` concept in the protocol.** A relay-peer is "filament on a stable
   node with a public address," an ordinary peer that happens to be reachable.
   The protocol treats it as a peer. Adding a `hub` type to the protocol starts
   selling a different product.
4. **"Agent-mesh-at-scale" means many pairwise-authorized endpoints mediated by
   a stable relay.** It never means a large group where agents reach each other
   transitively without individual authorization. The xats bridge is a valid
   model only because each agent-to-agent channel is separately authorized; the
   bridge does not authorize on agents' behalf.
5. **Confidentiality is stated honestly per path.** Authorized flows are
   end-to-end encrypted and a relay-peer only ever moves ciphertext. There is no
   silent plaintext-at-relay tier.

## The signaling server is not the coordinator we rejected

Rejecting a central coordinator (Path 5) raises an obvious question: filament
already has a hosted signaling server, so isn't that a central dependency? No,
and the distinction matters. The signaling server is a **rendezvous /
NAT-traversal helper** (STUN-like), not a coordinator of trust or policy:

- It does not authorize anyone. Pairing establishes E2E trust; signaling never
  decides who may talk to whom.
- It does not route traffic. It helps two peers exchange candidates so they can
  holepunch, then steps out once the direct link is up.
- It holds no rosters, capabilities, or policy. It is a meeting point, not a
  source of truth.

So it lives in the reachability layer we keep and harden, not the authorization
or control layer we constrain. The decisions above give it a clear trajectory,
by the same logic as the self-hosted relay flag:

1. **Make it self-hostable** (a team runs its own rendezvous, no hosted infra).
2. **Let the stable relay-peer double as the rendezvous**, so a self-hosted setup
   needs one public-address node for both relay and signaling and depends on zero
   hosted filament infrastructure. Consistent with "a relay-peer is an ordinary
   peer," no new protocol concept.
3. **Keep it minimal**: rendezvous only (addresses/candidates, ephemeral). It
   becomes a coordinator in disguise the moment it gains any of: persistent
   roster/membership storage, a capability directory ("B exposes sshd:22"),
   name resolution (MagicDNS), admission/rate policy, or social-graph analytics
   logging. A pure rendezvous has none of these. Its only powers are
   denial-of-service and metadata observation, not authorization or policy,
   which is why the STUN-vs-coordinator line holds.
4. **Keep rendezvous and relay distinct in the protocol**, even when one
   self-hosted node hosts both (`filament rendezvous <addr>` and
   `filament relay <addr>` are separate services). Co-locating them is a
   deployment choice; the protocol must not assume "signaling = relay," or that
   monoculture becomes a hidden single point.

Honest caveat: the signaling server is filament's one genuinely centralized
dependency and a metadata vantage point (it sees who wants to connect to whom,
never content). The principled trajectory is to minimize dependence on it, not
grow it: LAN peers via mDNS need no signaling, known-address peers need no
signaling, and everything else can use a self-hosted rendezvous. The hosted
server is then a convenience default for zero-config first-connect, not a
requirement, which keeps filament honestly self-hostable end to end.

## Relationship to the roadmap

None of this blocks or changes the near-term work: transport hardening,
self-hosted relay, and introducer-TOFU are the shared primitives regardless of
how far any mesh idea might have gone. This note simply records that the mesh
destination was explored to its end and the road stops at the pairwise core.

See also: `docs/filament-routing.md` (the pairwise route model), `ROADMAP.md`
(the Exploration entries this note supersedes), `/root/xats/BRIDGE-M0-SPEC.md`
(the app-level federation prototype that motivated the question).
