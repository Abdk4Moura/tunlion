# Fleet auto-mesh: same-owner devices connect without pairwise pairing

> Status: decided (2026-08-25). Amends `docs/design-mesh-network.md`, which
> rejected a mesh control plane. This note records the one narrow exception the
> owner accepted, why it does not reopen what that note closed, and the exact
> mechanism.

## Problem

Install plus pair does not give a mesh. A pairing mints one shared secret and
the signaling channel is `sha256("filament-pair:" || secret)`
(`cli/src/main.rs:2755`). The daemon subscribes only to channels read from
`devices.json`. If A pairs B and B pairs C, A never learns C exists. Fully
connecting N devices costs N(N-1)/2 pairings, so a user's own laptop, phone and
server behave as a star around whichever device did the pairing.

## What changes, and what does not

`design-mesh-network.md` guardrail 1 read "pairwise authorization is absolute: A
talks securely to B only if A made an explicit A-to-B trust decision." That
guardrail is narrowed to **cross-user** authorization. Within a single owner
key, the owner's signature on a `DeviceCert` IS the explicit trust decision. It
is made once and it covers every device it certifies. Between different owners
nothing changes at all.

**Why this is not Path 4 (transitive trust).** Under Path 4, A trusts C because
B says so, and the trust flows along the graph. Here A trusts C because C
presents a `DeviceCert` signed by the owner key A already holds. B's assertion
is not an input to A's decision. Delete B from the network entirely and A still
accepts C on the same evidence. No peer ever authorizes on another peer's
behalf, which is the property that carried the original argument, and it
survives intact.

The distinction the original note never drew is that it reasoned about A, B and
C as different people. "Your own devices" is a different case: there is one
human and one key, so there is nothing to delegate.

## Mechanism

### 1. The fleet rendezvous secret

`fleet_rv` is 32 random bytes created once by the owner device and stored as a
secret file at `<config>/fleet.rv`. It is delivered to each device at
enrollment inside the existing `identity-auth-key-enroll-ack` control message
(`cli/src/main.rs:6034`), which is already an authenticated end-to-end message
on the pairing transport and already carries the pair secret, the device cert
and the owner cert. This adds one field. It is consumed at the single existing
client-side persistence point, `persist_join_ack`.

`fleet_rv` is deliberately NOT derived from `owner_pub`. The owner public key is
disclosed to EXTERNAL peers during ordinary pairing, so deriving the meeting
point from it would let any device you ever paired with, including one you no
longer trust, compute your fleet channel and watch your devices come and go.

### 2. The fleet channel

`fleet_channel = channel_of(fleet_rv)`, which is the same
`sha256("filament-pair:" || secret)` construction and therefore the same 64-hex
shape the server already validates (`CHAN_RE`, `backend/signaling.py:543`).
Every fleet device subscribes to it alongside its pairwise channels.

This needs **zero signaling-server changes**. `registry.subscribe` already holds
a set of members per channel and returns every other live member
(`backend/signaling.py:111`), and `MAX_CHANNELS` is 64. The server still never
sees a secret and gains no new power: it sees one more opaque meeting point. It
does learn that some set of sids form a group, which is a real metadata
increase over per-pair channels and is stated honestly here rather than hidden.

### 3. Discovery reuses the presence machinery, so there is no CRDT

The `known-peer` push plus the `peers` roster returned in the subscribe ACK
already deliver the live member list deterministically
(`backend/signaling.py:546`, `roster_from_ack` in `cli/src/net.rs:1133`), and
the daemon already reconciles against that roster (`Session::on_synced`,
`cli/src/session.rs:145`). A fleet member therefore appears through exactly the
same code path a paired device appears through today. The roster CRDT that step
3 of the L3 plan called for is not needed: the durable set is `devices.json`,
and the live set is the channel roster.

### 4. Admission is by certificate, never by channel

Presence on the fleet channel authorizes nothing. A accepts C only when all of
the following hold:

1. C presents a `DeviceCert` whose `user_pub` equals A's known `owner_pub` and
   which is unexpired (`verify_chain`, `crates/filament-id/src/lib.rs:220`).
2. C proves possession of `cert.device_pub`, bound to the live link's channel
   binding, which is the pattern `l3-announce` already uses (`cli/src/l3.rs:11`).
3. C's `device_pub` is not revoked in A's local record.

So anyone who learns the channel id gets presence metadata and nothing more.
This is the property that keeps the fleet channel a rendezvous rather than an
authorization surface, and it is what makes the metadata cost in (2) acceptable.

### 4b. Auto-mesh grants reachability, not capability

A newly met sibling has no local record, so there is no capability ceiling to
apply to it, and `capability.rs` fails closed in that case ("a same-owner
certificate with no matching record fails closed as a delegated principal with an
empty ceiling and expiry zero"). Rather than paper over that, v1 adopts it as the
rule: a device admitted by auto-mesh is admitted as a Delegated principal with an
EMPTY ceiling.

Concretely: the link forms, warm-hold keeps it, `filament ping` works, L3 routes
to it and `<peer>.mesh` resolves. Transfer, shell and mount still require their
own explicit grant, exactly as before.

This is the reachability/authorization split the original mesh note drew, applied
in our favour. It also bounds the blast radius of this whole feature: a bug in
the certificate path cannot escalate privilege, it can only connect something it
should not have connected. Capability flow across a fleet needs an owner-signed
fleet ceiling, which is deliberately deferred.

One consequence worth stating plainly: fleet membership is exactly "holds a
DeviceCert signed by my owner key", and a device enrolled through `filament mint`
holds one even if you think of it as somebody else's machine. Such a device joins
the mesh at reachability level. Its capabilities remain bounded by the ceiling
the mint issued, so this is not an escalation, but the presence is real and the
`devices` UX should eventually distinguish it.

### 4c. A proven key is not a proven name

The certificate proves a device KEY. It does not prove the display name that
arrives alongside it. So `Link::verified_name`, which is the capability-store
key, is resolved by looking the proven key up in the local device records
(`device_name_for_pub`), never from the name on the wire.

This one is worth stating because the first implementation got it wrong: it set
`verified_name` from the peer's self-asserted name, which would have let a fleet
device name itself after a device that holds grants and key into them. The
verification was sound and the decision resting on it was not, which is the
failure shape to watch for here. A sibling we hold no record for keeps
`verified_name = None`: reachable, keyed into no grants, its claimed name used
for display only.

### 5. Revocation rotates the rendezvous

Revoking a device must remove both its authorization and its view.

- **Authorization** is already handled: existing revocation denies at 4(c), and
  that alone is sufficient for security.
- **View** is not. A revoked device still knows `fleet_rv` and would keep seeing
  presence. So revocation rotates it: the owner device generates a new
  `fleet_rv` and pushes it to each still-trusted device over that device's
  pairwise channel, which is unchanged and remains the durable backbone. A
  device that is offline at rotation receives it on its next pairwise contact,
  and until then sits on the stale channel and simply does not see the new one.
  That is a liveness delay, never an authorization error, because (4) is what
  gates admission.
- Rotation is tied to the existing `epoch` in `caps.json` so a device can tell
  which generation it holds and ask for the current one.

## Precedent already in the tree

`cli/src/ephemeral.rs` already has `enroll_channel(owner_pub)`: a channel derived
from the owner public key, on which devices meet with NO shared pair secret and
are dialed via `maybe_adopt` rather than `start_direct(pid, name, secret)`
(`cli/src/main.rs:16386`). The fleet channel is the same shape, so the
"presence without a pair secret" path is not new machinery.

Noted honestly: that existing channel has exactly the metadata property this
design rejects for `fleet_rv`, since it is derived from `owner_pub`, which
external peers learn during pairing. It is tolerable there because enrollment is
short-lived and operator-initiated (`filament mint`), while fleet presence is
permanent and continuous. A v1 that wanted to ship sooner could reuse
`enroll_channel` and skip `fleet_rv` entirely, at the cost of letting any device
you ever paired with watch your fleet come and go. That shortcut is available and
is deliberately not taken.

## Alternative considered: owner-minted pairwise channels

Instead of one shared channel, the owner device could mint a fresh pair secret
for every (new device, existing device) combination and deliver both halves.
Every link would stay a private per-pair channel, revocation would need no
rotation, and the owner would be acting as the introducer the original note
already sanctions.

Rejected for v1 on cost: it is O(N) deliveries per enrollment and O(N^2) stored
secrets, it needs the owner device online to add any device, and delivery to an
offline peer defers exactly as rotation does, so it does not even remove the
liveness caveat it would be buying. The fleet channel is one subscription and no
new state. Because admission is cert-gated either way, the two are equivalent in
authorization terms and differ only in metadata exposure, which is the tradeoff
recorded in (2). Revisit if fleet-grouping metadata at the rendezvous becomes a
stated user concern.

## What the live three-node test found

The design above was implemented, type-checked, unit-tested and model-checked
green, and still did not work. Three daemons under one owner key (separate
`FILAMENT_CONFIG_DIR`s, B and C never exchanging a code) drove out four bugs that
none of those gates could see. Recording them because each is a trap for the next
change, not just a bug that got fixed.

1. **The daemon never subscribed to the fleet channel.** It rebuilds its channel
   list from scratch and overwrites `sess.channels` (`main.rs:14976`), discarding
   anything pushed earlier. The feature was inert on the wire while every test
   passed.
2. **Fleet links were reaped seconds after forming.** The room reconciler exempts
   channel-introduced links by testing `expected_secret.is_none()`. That is a
   PROXY for "channel-introduced", sound only while every channel link carried a
   pair secret. A fleet link is channel-introduced and secretless, so it read as
   room-sourced, was absent from the room roster, and was dropped after two
   digest ticks.
3. **`verified_name` was set from the peer's claimed name.** See 4c.
4. **Nobody dialed.** `maybe_adopt` prepares to ACCEPT; the dial normally comes
   from `start_direct` with a pair secret. Two daemons on a secretless channel
   both sat waiting. The WebRTC fallback did connect, but `net.rs`
   `channel_binding()` returns `None`, so `fleet-hello` could never bind to it.

### Why fleet dials are their own intent

Fixing (4) means dialing direct-QUIC keyed by `fleet_rv`. But `adopt_direct`
births a direct link `trusted: true`, `verified_name` from the dial, and
`PrincipalKind::OwnerDevice`, on the reasoning that a direct dial always carried
a PAIR secret which already proved identity. `fleet_rv` is shared by the whole
fleet: it proves MEMBERSHIP, not identity, and certainly not owner-equivalence.
Reusing that path as-is would have handed owner-equivalent status to any holder
of a group secret, before any certificate check.

So fleet dials use `DirectIntent::Fleet` and are born untrusted, unnamed, with an
empty delegated ceiling. Only a verified `fleet-hello` names them.

The pattern in (2) and in this one is the same, and it is worth naming: a check
that was sound under an assumption, reused where the assumption no longer holds.
"Has a pair secret" meant "is identity-bound" and "came from a channel" at once,
and secretless fleet links break that conflation. Other sites keying on
`expected_secret` should be swept for the same reason.

## What this does not build

No multi-hop routing. No reaching C through B. No `hub` concept in the protocol.
No roster, membership or capability storage on the signaling server. No name
resolution server-side (MagicDNS stays local to each node). No transitive trust
across owners. A fleet device that cannot reach another fleet device directly or
by relay stays unreachable, which is the same boundary as today.

## Properties to model-check before implementing

1. **Convergence.** Any two devices enrolled under the same owner key, both
   online, reach mutual presence for every enrollment order and every
   interleaving of the subscribe ACK and the `known-peer` push.
2. **Revocation safety.** A revoked device is denied by every non-revoked
   device, no matter what it presents, in bounded time.
3. **Rotation liveness.** Rotation never partitions the fleet permanently: every
   still-trusted device reaches the current epoch's channel after one pairwise
   contact.
4. **No admission without a cert.** No device ever accepts a peer lacking a
   valid owner-signed cert, under any interleaving of presence, rotation and
   reconnect.

Checked, and the checker was validated by mutation: removing the certificate
check has to make the Intruder tier fail, or the tier is not testing anything.
See `proofs/README.md`. The implementation carries the same property one level
down: an unverified fleet link is refused an L3 route AND its `l3-announce` is
not cached for replay, so presence alone never buys reachability either.

See also: `docs/design-mesh-network.md` (the decision this amends),
`/root/filament-l3-plan.md` (steps 1 to 3), `docs/design-scoped-mesh.md`
(projecting capabilities onto the L3 dataplane).

## Fleet peers are indexed, not addressable

A verified sibling is now written to `devices.json` so `filament devices` can
show the fleet, and it renders under FLEET with an empty capability list. The
record deliberately carries **no pair secret**, which is what keeps it an index
entry rather than an authorization: `devices_load` filter-maps on `secret`, so
the record can never become a channel subscription or a dial target.

Two things had to be corrected to make that honest:

- **The listing itself.** `device_entries` iterated `devices_load()`, so a
  secretless record was invisible in the exact surface that exists to show it.
  It now iterates the raw records.
- **The FLEET tier on a joined device.** The tier test asked
  `load_owner_key()`, "do I hold the owner's PRIVATE key", which is only ever
  true on the owner device. Every joined device therefore rendered its own
  siblings as EXTERNAL. The question is which owner key we CHAIN TO, which a
  joined device knows from its own certificate.

And one consequence had to be handled rather than left: a fleet peer is now
listed but still cannot be a `send --to` target, so the old error ("no known
device by that name; run `filament devices`") pointed the user at a list
containing the very name it claimed not to know. `send --to` now distinguishes
the two cases and names the real limitation.

## The negative test, run and PASSED (2026-08-26)

The empty-ceiling claim in 4b is now verified live. Setup: three daemons, `phone`
a fleet sibling of `laptop` with zero grants, and `laptop`'s shell acceptor ARMED
by granting shell to a DIFFERENT device (otherwise the request is ignored above
the gate and proves nothing). Then `phone` attempts a shell on `laptop`:

    reach laptop  ->  warm direct link, pong          (reachability: GRANTED)
    shell laptop  ->  l2: pty refused: phone: not in auth key caps   (capability: DENIED)

That refusal line is the gate itself, denying on an empty ceiling. Reachability
and capability are demonstrably separate, which is the whole design claim.

Getting there required fixing three things that each stopped the request BEFORE
the gate, and each looked like "peer unreachable":

1. **The warm path is skipped for non-tty stdio.** Every redirected test run
   silently never asked the daemon at all. The test has to drive a real terminal.
2. **Fleet dial GLARE.** Both ends see each other on the fleet channel and both
   dialed, colliding and superseding each other forever: measured at 1 verify and
   10 drops, never settling. Downstream that reads as "unreachable" while a link
   is visibly present. Fixed with a deterministic tiebreak (`conn.my_id < pid`),
   so exactly one side dials. After: 1 verify, 0 drops.
3. **`warm_link_for` gated on `l.trusted`**, the legacy blanket-trust flag a
   fleet link deliberately never sets, so every sibling was ineligible for the
   warm path. It now accepts a Proven identity binding. That decides ROUTING, not
   permission; what the peer may do is still the receiving side's gate, which is
   exactly what then denied the shell.

### Refusal latency: FIXED. Refusal copy: still wrong.

`l2-open` and `l2-close` shared one guard, `l2_enabled`, which answers "will I
ACCEPT inbound stream opens". That is right for an open and wrong for a close: a
close is the peer answering a stream WE opened, and a node that accepts no
inbound opens still opens outbound ones. So the refusal was discarded by the very
client that asked for it, which then waited out its 2500ms verify window,
declared the link a zombie, and fell through to a 45s cold establish.

Split, so a close is always processed. Measured: the refusal now returns in
**22-55ms instead of 45s**.

What is still wrong is the MESSAGE. The warm attempt fails with the refusal, then
`pty_cmd` falls through to the cold path, which fails immediately at name
resolution ("no known device named 'laptop'", because a fleet peer carries no
pair secret) and THAT error is what reaches the user. So the caller is told
"can't reach 'laptop' ... in 45s - it may be offline", which is false on both
counts: the peer is reachable and nothing waited 45s.

Three of the four layers are now fixed and the plumbing is in place:

- the daemon no longer treats a peer-close as a zombie (it stopped tearing down a
  healthy link on every refusal),
- `ctl::try_pty_reason` surfaces WHY the daemon said no instead of a bare `None`,
- the client treats a `refused:` reason as DEFINITIVE and does not fall through
  to a cold retry.

**FIXED.** Measured end to end, from a real terminal:

    before:  45s   ->  "can't reach 'laptop' ... it may be offline"
    after:   28ms  ->  "the peer closed the shell request (capability not granted?)"

The last piece was the guard split: once `l2-close` stopped being gated on
`l2_enabled`, the close reached `Mux::on_close`, which drops the stream, which
ends `verify_first_frame` with "closed before any frame" instead of a timeout,
which is what lets the client tell a REFUSAL from a dead link.

Worth noting the same defect had already been found and fixed once, for mount:
`on_close` carries a comment (#206) explaining that the acceptor sends
`l2-close{err}` on a ceiling refusal and that "before this, the reason was
dropped here and the initiator read a generic channel-closed". The pty path had
the identical hole, one layer up, and nobody had walked it.

None of this is an authorization problem. The gate is correct and proven, and
`ping`/`devices` report the peer accurately; it is the failure COPY that lies.

### Earlier framing of this defect

The refusal is not surfaced to the caller. `phone` sees "can't reach 'laptop'"
after a 45s cold retry, when the truth is "refused: not in auth key caps" and was
known in milliseconds. The peer refuses silently, so the client reads the silence
as a zombie link ("warm link unresponsive after 2500ms") and falls through to a
pointless cold establish. A refusal should be a reply, not a timeout.

## What the earlier negative test showed (superseded)

The claim in 4b is that auto-mesh grants reachability and not capability. Driven
live, from a fleet peer C against a sibling B that has granted it nothing:

    filament shell laptop   ->  can't reach 'laptop' (no link established in 45s)
    filament send --to laptop -> no known device by that name

Both denied, and both denied EARLIER than the capability gate. `send --to`
fails in name resolution and `shell` fails at link establishment, because fleet
peers are deliberately not written to `devices.json` (see "What this does not
build"), so the L2 verbs cannot address them at all.

So the honest status of the empty ceiling: it is correct by construction and
covered by unit tests, and it is currently a SECOND line of defence sitting
behind an addressability barrier that stops the request earlier. It has not been
exercised live, because from the CLI there is presently no way to drive an L2
operation at a fleet peer and reach the gate.

That matters for the next step, not this one. Whenever fleet peers become
addressable (persisting them, or teaching the verbs to resolve `.mesh` names),
the gate stops being belt-and-braces and becomes the operative barrier, and it
must be re-tested at that point. A change that makes fleet peers addressable
without re-running this test would be silently promoting an untested check into
the load-bearing position.

## A privilege escalation this feature introduced, and how it was caught

Building `send --to` for siblings surfaced a real escalation IN THIS FEATURE,
default-on, not confined to the opt-in send path. Recording it in full because
the mechanism is the same one that keeps recurring here.

`DirectIntent::Fleet` births a fleet link untrusted and unnamed. But
`adopt_direct` read that intent off the local `DirectPending`:

    let fleet = pend.as_ref().map(|p| p.fleet).unwrap_or(false);

Only the DIALER holds a pending. The ACCEPTOR has none, so `unwrap_or(false)`
made every accepted fleet link `trusted: true` with `PrincipalKind::OwnerDevice`,
which is precisely what the Fleet intent exists to prevent, reachable by anyone
holding the fleet secret.

It was caught by a live test, not by review: a device whose `transfer` grant had
been REVOKED still delivered a file, verified sha256 and all. The grant was gone
from the record and the transfer happened anyway, because the acceptor had handed
the peer owner-equivalence at link birth, before capabilities were ever consulted.

The fix fails safe when there is no pending. The acceptor cannot see which secret
authenticated the MAC, so it infers: a peer we hold a PAIR secret for is that
device (only it could produce that MAC); anything else, while a fleet secret
exists at all, is a fleet link and stays untrusted until `fleet-hello` names it.
Verified after the fix: the mesh still forms across all three nodes, and the
revoked peer's file no longer lands.

Two things worth carrying forward. First, the escalation existed because a NEW
kind of link (authenticated by a secret that proves membership, not identity)
was routed down a path whose every reader assumed "direct-QUIC implies pair
secret implies identity proven". Same shape as the other twelve. Second, no
amount of reading found it: it took sending a real file from a device whose
permission had been taken away.

### What the fix then revealed

With the escalation closed, a fleet sibling does not receive a file. Measured in
both gate modes: nothing lands.

**Correction to a diagnosis written earlier in this document.** I first recorded
this as "blocked on the trust floor". That is WRONG, and the code says so:
`cap_trust_floor` passes when `binding == BindingStrength::Proven`, which is
exactly what a verified `fleet-hello` sets via `admit_delegated`. The floor is
not the obstacle.

What is actually true:

- In DEFAULT (shadow) mode the effective decision falls back to `legacy_ok`,
  which in daemon mode is just `link_trusted`. A fleet link is untrusted by
  design, so it is declined. That is the real default-mode blocker, and it is
  section 4b working as written: reachability, not capability.
- Under `FILAMENT_CAP_AUTHORITATIVE=1` the capability layer already has a FLEET
  path for transfer: `cap_fleet_inputs` plus `scoped_in_bounds` allow a
  same-owner Proven device to land a file inside the receiver's own drop dir.
  So the mechanism that would authorize this already exists and was built for
  precisely this case.

Instrumenting the receiver's transfer gate settled it: with the receiver
authoritative and a `transfer` grant in place, the `transfer-gate:` line never
fires. **The offer never reaches the capability layer.** So caps, floors and
grants are all innocent, and the blocker is upstream: the sender does not emit
the offer, or the link does not carry it. The sender printing nothing under `-vv`
before its timeout points at the sender.

That is worth contrasting with where this started. The first framing was "blocked
on the trust floor", which was wrong and would have sent someone to redesign a
trust model that needed no redesign. One debug line moved it to a measured fact
about which layer is even involved.

### Where the transfer investigation ends

Chased to its end, `send --to` for a sibling terminates at a deferral the
codebase already declares. The sequence, each step measured rather than argued:

1. Offer never emitted (fixed: re-emit ChannelReady after identity is proven,
   mirroring what the PAKE path documents for itself).
2. Offer now reaches the receiver's gate, which denies with `own_user=false`.
3. `own_user` comes from a `cap_header` in the capability store, and a joined
   device has none. Confirmed on disk: owner has `caps.json` with a header, the
   joined device has no `caps.json` at all.
4. It cannot make one. `ensure_self_genesis_header` signs the header with the
   owner's `UserKey`. A fleet device can only RECEIVE owner-signed policy.

That is same-owner fleet-trust, which `cap_authoritative`'s own doc comment names
as the pending work gating the authoritative flip. So the remaining step is the
owner-signed fleet ceiling, not anything in the transfer path. Everything
upstream of the policy store is done and verified.

### A misdelivery bug, found and fixed (2026-08-26)

`send --to <sibling>` delivered to the WRONG fleet device: asked for `laptop`,
the file landed in `owner`'s inbox, 2/2 reproducible.

**Root cause: `fleet_proven` was a single `bool`.** It meant "some peer proved
itself" while every read of it meant "THIS peer proved itself". Several siblings
are present on the fleet channel, so once any one verified, the offer guard
passed for all of them and the file went to whichever peer the loop reached next.
The trace is unambiguous:

    fleet-send verify:  pid=8gNe...  proven=Some("laptop")   <- verified THIS peer
    fleet-send: OFFERING to pid=yNDj...                      <- offered to ANOTHER
    inbox-owner: [file]     inbox-laptop: []

Fixed by making it a per-peer set. After:

    verify:   pid=SDax...  proven=Some("laptop")
    OFFERING: pid=SDax...                        <- same peer
    declined                                     <- and nothing lands anywhere

**Why it took three attempts to see.** The first report blamed the identity
check ("it does not stop it"), which was wrong: the check always worked. The
second blamed a re-offer after a hard decline, which was closer but still wrong.
Only instrumenting BOTH the verified pid and the offered pid made it visible,
because the bug is precisely that those two are different. Before that, every
observation was consistent with several wrong stories.

It is also the same shape as everything else in this document: a value whose
scope is narrower than the decision resting on it. `fleet_proven` had no peer in
it at all.

### One value for many siblings: the recurring defect on this channel

The fleet channel carries EVERY sibling. Any state describing "the peer" must
therefore be keyed by peer, and four separate bugs have now come from state that
was not:

  `fleet_proven`        one bool  "some peer proved" read as "THIS peer proved"
  `fleet_bind_ours`     one nonce the last connector overwrote the binding
  `fleet_rechallenged`  one bool  one sibling spent the retry another needed
  wrong-peer skip       no memory the dropped peer was re-adopted as the target

A pair channel has exactly one peer on it, so this class of code was correct
before auto-mesh and is wrong after it. When touching anything on the fleet
channel, the first question is: is this per-link state stored per link?

### Grant distribution: DONE

A grant is a `CapOp` with `resource: "self"`, and the self-resource id is derived
from the OWNER's key rather than the machine's. So an owner-signed op means the
same thing on every device in the fleet, which is what makes distributing it
coherent instead of a category error: it is one policy, replicated, not a policy
about one machine being applied to another.

Two paths, because each covers what the other misses:
  - the enrollment ack carries the owner's signed ops, seeding a device at join
  - a verified `fleet-hello` re-pushes them, so grants made LATER still arrive

**A peer can relay policy but never author it.** `merge_owner_cap_ops` keeps only
ops whose `grantor` equals the owner key the receiving device already holds AND
whose signature verifies against it. Anything else is dropped silently.

Measured with three daemons:

    owner grants `mount` to laptop AFTER enrollment -> owner has 1 op
    mesh forms                                      -> laptop 1 op, phone 1 op
    stored op is byte-identical to the owner's
    full mesh restart, repeated pushes              -> still 1 op each (idempotent)

### Ungranted fleet-scope transfer: DONE (PrincipalKind::FleetDevice)

A sibling with NO grant now lands a file in the receiver's own drop dir, while
the deliberate tier stays grant-only. Measured:

    transfer (scoped default, in drop dir), no grant -> allowed, delivered to the NAMED device
        gate: allowed=true legacy_ok=false trusted=false binding=Proven
              own_user=true has_grant=false in_bounds=true
    shell (deliberate tier), no grant               -> refused, "capability not granted"

**What was actually wrong.** An earlier note in this document said this needed a
principal kind that "does not exist" and called it a security-model change. The
kind was needed, but the reasoning behind calling it a model change was WRONG: it
assumed a ceiling-less kind would inherit the owner shortcut and become
owner-equivalent. `cap_gate_effective` already DISCARDS the owner shortcut for a
same-owner peer and recomputes from fleet policy (the finding-#24 note in that
function says so explicitly). The policy was already written and reviewed; it
simply could never be reached.

`PrincipalKind::FleetDevice` carries no ceiling and is neither `Delegated` nor
`OwnerDevice`:
  - not `Delegated`, whose auth-key ceiling is unconditional and purely
    restrictive, so the empty ceiling a sibling starts with denied everything
    before the fleet policy ran. `Delegated` ALSO means "ephemeral, drop on
    disconnect", which a persistent sibling is not, so it was wrong twice.
  - not `OwnerDevice`, so nothing reads a sibling as the local primary.

This is 4b revised, not abandoned: reachability is still the default, the
deliberate tier is still grant-only, and what a sibling gains without a grant is
exactly the scoped default the capability layer already defined.

### Sibling transfer works, with a grant

    filament grant <sibling> transfer      (on the receiver)
    gate: allowed=true legacy_ok=false trusted=false binding=Proven
          own_user=true has_grant=false in_bounds=true
    inboxes: owner[]  laptop[gr.txt]

`legacy_ok=false` and `trusted=false` are the important columns: the link is not
trusted, so the capability layer alone authorized this, and the file reached the
NAMED device rather than the owner.

The long run of denials before this were all correct. `cap_gate_effective`'s
delegated-principal ceiling (check 2 of 2) is unconditional in both modes and
purely restrictive; a fleet link carries `device_caps(name)` as its ceiling,
which is `Some([])` without a grant, so it denies before the fleet-scope branch
is reached. Every earlier measurement was taken without a grant. That is 4b
working: reachability by default, capability only when granted.

Worth noting how it was settled: by READING the gate, after four rounds of
measuring its inputs. The inputs had all been measured correctly and none of them
was the answer.

### Confirmed across roles

Re-run with per-node inboxes after the per-peer fix:

    joined -> joined (C -> laptop): verify pid == OFFERING pid, declined, nothing landed
    joined -> owner  (C -> owner):  delivered to the owner only (correct: they are paired)

The fix holds across sender/target roles, and the ordinary paired send is
untouched by any of this.

The path is now CORRECT but not yet USEFUL, which is why it stays behind the
flag: a transfer to a sibling still cannot succeed until a joined device has
owner-signed capability state to authorize it. Correct-and-refusing is the right
place to stop; correct-and-delivering needs the fleet ceiling.

### Residual: RESOLVED

This section used to say an untrusted sibling's offer left the SENDER with no
feedback until its timeout. Re-measured: the sender is told `declined` after
about 17s, nearly all of which is link establishment, and well inside its
timeout. Not a hang.

Almost certainly resolved by the `l2-close` guard split earlier in this document
(the client had been discarding the peer's close because that arm was gated on
`l2_enabled`). Recorded rather than deleted, because "we fixed X and it silently
also fixed Y" is worth knowing when Y reappears.

## Verb-by-verb status for a fleet sibling

Measured against a sibling the caller never paired with:

| verb | result |
|---|---|
| `devices` | listed under FLEET, capabilities `(none)` |
| `reach` / `ping` | works, warm link |
| `shell` | reaches the peer, refused by the gate in ~2s with the reason |
| `addr` | shows the overlay address (channel blank: there is no pair channel) |
| `devices revoke` / `restore` | works, and now READS as revoked |
| `send --to` | not a target; says so accurately rather than "unknown device" |

Getting that table consistent turned up three more instances of one check
standing in for another, all of them reading `devices_load()` (which filter-maps
on `secret`, so it silently means "devices I can DIAL") as if it meant "devices I
know":

- **`addr`** refused with "no device named X, see `filament devices`" while
  `devices` listed X on the next line. It only needed the secret to print a
  channel id.
- **`devices revoke` / `restore` / `forget`** did the same, which for revoke is
  worse than confusing: a device you can SEE but cannot revoke.
- **`delegated_device_state`** returned early unless `principalKind ==
  "delegated"`, so once revoke DID work, the revocation wrote correctly, denied
  the device on reconnect, and then listed it as perfectly healthy. Revocation is
  a decision about a device, not about a principal kind, so it is now checked
  first. A revocation you cannot see is one you cannot trust.

`send --to` remains the one genuine gap: routing a transfer over the daemon's
warm link needs a warm-send request kind that does not exist yet.

## The `expected_secret` sweep

Fleet links are the first links that can exist WITHOUT a pair secret, so every
site keying on `expected_secret` was audited for what the field was actually
standing in for. 44 sites; most are writes, and the reads split three ways.

**Safe as written.** The `channel_of(secret)` comparisons (pair-channel digest
reconcilers) compute the FLEET channel for a fleet link, which never matches the
pair channels they test against, so a fleet link is correctly not reaped by a
pair-channel digest. The `pair-proof` MAC sites are all guarded by `l.direct`
or fall through an `if let`, so a fleet link either skips them or sends nothing.

**Two that were wrong**, both because "has no pair secret" had quietly meant
something narrower than it says:

1. **The in-session pairing ceremony** (`fresh_link`). It means "a peer we have
   never met", which is what makes a link a candidate to receive `pair-keep`.
   A fleet sibling whose direct dial fell back to WebRTC also has no pair
   secret, so it qualified, and it would have consumed the code the human just
   typed: the ceremony secret goes to a device we already know, and the intended
   device is left unpaired. A fleet peer is now never a pairing candidate.
2. **`digest_says_alone`.** "No room-independent link remains" was tested as
   "no link has a pair secret". A fleet link is room-independent in exactly the
   same way, so a daemon holding only fleet links read as alone and could take
   the quiet-exit path with peers connected.

Both are latent rather than dramatic today, because `start_direct_fleet` makes
fleet links direct-QUIC (and therefore secret-bearing) in the normal case; they
bite on the WebRTC fallback.

The general rule this leaves: when adding a code path that lacks something every
existing path had, the field that is now absent is not the question. The question
is what each reader was using its presence to CONCLUDE.
