# Subnet routes: reaching a network, not just a machine

> Status: **partly built (2026-09-01).** The routing table and the policy surface
> are in (`l3::RouteTable`, `advertise-routes` / `accept-routes`). Wire
> advertisement and forwarding are not, and the authorization model is an open
> decision. This records what was built, what was deliberately not, and why.

## What the overlay gives you today, and what it does not

Every node has an overlay address, and packets sent to it arrive wherever that
machine is. That reaches **machines you control**.

The things people actually want to reach are usually not nodes: the NAS, the
printer, a Postgres box on `10.0.0.5` nobody will install anything on, an office
LAN. Those will never run filament, and some cannot run anything.

A **subnet router** closes that gap: one node on the LAN announces "I can reach
`10.0.0.0/24`", peers route that prefix to it, and it forwards. One install
onboards a whole network.

## The four pieces

1. **A routing table that understands prefixes.** DONE (`d7a8105a`).
2. **A policy surface** for who offers what and who believes it. DONE (`8457d587`).
3. **Forwarding on the router node.** NOT DONE.
4. **Authorization of advertisement.** OPEN DECISION.

## 1. Route table (built)

Routing was `HashMap<IpAddr, Transport>`, exact match. It is now `RouteTable`:
host routes in their own map with the exact-match fast path **unchanged**, and
prefixes consulted ONLY on a host miss. Precedence is most-specific-wins; keeping
hosts separate is a blast-radius and performance choice, not a semantic one,
because a host route is just a /32 or /128.

`set_subnets` treats an advertisement as a **full restatement, not a delta**. A
peer that stops advertising a prefix has it withdrawn. Diffing deltas is how a
retracted route survives its own retraction.

`prefix_contains` is pure and tested on the cases that catch a wrong
implementation: `/0` (where the naive `<< (32 - len)` is undefined behaviour),
full-length prefixes, over-long lengths refused rather than wrapping, and
**families never mixing**, so a v4 destination cannot match a v6 prefix even
where the bits line up.

## 2. Policy surface (built)

Two settings, not one, because advertising and accepting are different trust
decisions made by different people:

- `advertise-routes` (global, list of CIDRs): what this machine offers to carry.
- `accept-routes` (bool, per-peer via `--peer`, **default off**): whether to
  install what a peer offers.

## 3. Forwarding (not built)

On the router: enable IP forwarding, and NAT the LAN side, because the LAN host
replies to an overlay address it has never heard of and needs either a masquerade
or a route back. Platform-specific (`sysctl` + `iptables` on Linux, `pf` on
macOS, different again on Windows) and it needs elevated privileges, which the
existing `ensure_net_admin_for_l3` machinery already handles for the TUN.

**Deliberately not written yet, for one reason: it cannot be verified here.** It
needs a real second network. Writing it and asserting it works would be the
failure mode this tree has been repeatedly bitten by, most recently the
fault-injection hook that was dead for ~620 commits while its gate reported
green.

## 4. Authorization (the open decision)

The announce already proves a lot: signature, channel binding, possession, and a
sequence number that stops replay and address rollback. But note the asymmetry it
rests on.

**An overlay address is self-certifying.** It DERIVES from the peer's public key
(Yggdrasil-style), so "my address is X" is provable from the key alone, and no
approval is needed or meaningful.

**A prefix derives from nothing.** "I can reach `10.0.0.0/24`" is an unbacked
claim no signature can make true. Signing proves WHO said it, never that they may.
This is why production meshes make an operator approve advertised routes, and it
is why `accept-routes` defaults to off.

Three ways to close it:

- **Operator approval per route**, like the existing `requests` flow. Conservative
  and familiar, but adds a second approval concept beside capabilities.
- **A capability**: `grant <device> route:10.0.0.0/24`. RECOMMENDED. It reuses the
  signed capability machinery, makes advertisement the same shape as every other
  permission, and needs no new concept. It also answers the same question the
  #161 gate asks (see WORK-STATE 1v), because both are "a claim that must be
  authorized before it is trusted".
- **Owner-signed route grants** distributed like cap ops. Strongest, most work,
  and the natural end state if fleets ever advertise routes to each other.

`accept-routes` defaulting to off is correct under ALL THREE, which is why it
could ship before the decision.

## Wire format, when advertisement is built

Prefixes must live INSIDE the signed announce payload or they are forgeable in
transit. `Announce` lives in the `filament-overlay` crate, so this is a published
wire-format change and needs forward compatibility: an older peer must ignore an
unknown field rather than reject the announce. There is precedent in the same
message (`dg_relay`, which older peers discard silently).

## What the two-machine experiment changed (2026-09-01)

The design above was complete and every unit test passed while the feature did
not work at all. Running it between two real machines (do-vm and a KVM VPS,
`experiments/subnet-route-e2e.sh`) found six defects, five of which no unit test
could have caught because each lived in the seam between two components that
were individually correct.

1. **The advertisement was never sent.** Both announce paths called
   `announce()`, which hardcodes `routes: Vec::new()`. The router configured its
   own forwarding and printed "carrying 10.66.0.0/24 for peers"; the receiver
   called `verify_routes`, got an empty set, and installed nothing. Neither end
   was wrong on its own, so neither logged an error.

2. **No kernel route was installed.** An accepted prefix updated only the
   in-process `RouteTable`, which decides which transport a packet rides *after*
   it reaches us. It cannot make the kernel deliver the packet in the first
   place. `filament` printed "routes via <peer>" while `ip route` showed nothing.

3. **`route` was missing from the invitation bitmask**, and the encoder ended in
   `.unwrap_or(0)`, so an unencodable capability silently collapsed the WHOLE
   ceiling to empty. `add --allow transfer,mount,route` minted a valid, signed
   invitation conferring nothing. Now rejected at mint, with a round-trip test
   over `CANONICAL_CAPABILITIES` so a future capability cannot repeat it.

4. **`mint_capability` was a second hardcoded capability list** that never
   learned about `route`, so `add --allow route` was refused outright. The CLI
   printed "re-invite with route in the invitation" as the remedy for a ceiling
   error and then rejected that exact command. Now derived from
   `CANONICAL_CAPABILITIES`.

5. **Enforcement read the owner key the wrong way.** `UserKey::load` returns
   `None` on a joined device, so deriving the resource id from it made every
   fleet member refuse every route: precisely the population subnet routes exist
   for. Verification needs only the owner's PUBLIC key, which a joined device
   carries in its own certificate.

6. **The ceiling was read from the link's principal.** A peer reconnecting
   through fleet-hello is admitted by `admit_fleet` as `FleetDevice`, which
   carries no caps; only a fresh enrollment yields `Delegated { caps }`. Matching
   on `Delegated` worked exactly once per join and silently stopped after the
   first reconnect. The persisted record is now the single source, the same one
   `devices` renders and `grant` consults.

### Authorization model, as it actually resolved

For a FLEET MEMBER the invitation ceiling IS the grant. No CapOp can bind to
one: a CapOp targets the owner user key that every member presents, so it cannot
name a single device, and `grant` refuses outright rather than report a success
enforcement would not honour. Authorization therefore comes from the
owner-signed invitation, the same place `transfer` and `mount` come from.

**Known coarseness, recorded rather than hidden.** A ceiling carries an ACTION
and no resource, so `route` in a ceiling authorizes ANY prefix that member
advertises, including `0.0.0.0/0`. Two things bound it: `accept-routes` is off by
default and is settable per peer, so nothing installs without the receiver opting
in. Narrowing it to a per-prefix ceiling needs a v3 invitation token, because v2
encodes capabilities as an 8-bit mask with nowhere to put a CIDR. Until then the
prefix-bound `route:<cidr>` resource is the model for owner-to-owner grants,
and the ceiling is the model for fleet members.

### The result

Two real machines, one prefix, one code path; the only difference between the
two phases is the owner-signed ceiling.

    ceiling without route:  refused, LAN unreachable
    ceiling with route:     10.66.0.0/24 dev filament0, LAN REACHABLE
