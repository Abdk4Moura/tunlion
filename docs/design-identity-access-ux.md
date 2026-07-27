# Identity and access UX

> Status: design (2026-07-25). Builds on `docs/design-mesh-network.md` (filament
> stays pairwise) and `docs/design-introduce-user-identity.md` (user-key over
> device-certs). Every load-bearing decision here was stress-tested adversarially
> before it landed. This note freezes the product-layer identity and access design
> so implementation has a spec; it is not yet built.

## Governing principles

1. **Hide the crypto.** Users see people, devices, connect, grant, recover. They
   never see "Ed25519," "sign a certificate," or "public key." Fingerprints appear
   only behind a "compare" affordance for the security-curious.
2. **The safe path is the easy path.** In-person QR is one tap and the highest
   trust. The recovery backup is one tap at onboarding.
3. **Progressive disclosure.** Identity works in the first minute. Cold-key storage,
   recovery contacts, revocation witnesses, and capability grants are depth you grow
   into, never walls you hit.
4. **The human confirms every cross-boundary action.** The same confirm dialog
   gates introduce (accept a peer), grant (accept an access change), recovery
   (threshold + out-of-band), and the GPU consent screen. That one recurring gate is
   where filament's pairwise-authorization guarantee lives in the product.

## 1. Onboarding

The device key is generated silently and never shown; the user never manages it.
The user key (the person) lives encrypted-at-rest on the first device and signs
device certs there (the delegated-online-signer default); truly cold storage is a
power-user upgrade.

```
   FIRST RUN
   ( ) This is my first device       ( ) I'm adding to an identity I already have
         |                                     |
   generate device key + user key        QR / 6-word link from an existing device;
   (user key encrypted on device)        that device's user key signs a cert for
         |                                this new device key (Signal/Tailscale-style)
         v
   "Protect your identity" (nudged, not blocking, re-surfaced until done):
     [ Save a recovery file ]  [ Choose recovery contacts (later ok) ]
```

Recovery is nudged in consequence terms ("lose this device, lose your identity"),
skippable once, re-surfaced until done. Backup is pushed hardest here because a
brand-new user has no recovery contacts yet.

## 2. Contact book

A contact is a **local petname + their user key**. The name is yours (no global
naming authority); the key is the truth. Show *people*; expose devices only as
shared, and never imply you can see someone's full device set.

```
   Bob      [verified in person]   online     <- you scanned their QR face to face
   Carol    [introduced by Dave]   offline    <- TOFU through a mutual contact
   You can reach Bob on: laptop (online)       <- only the devices Bob shared
   Fingerprint 7f3a 9c21 ... [compare]         <- anti-spoof: petname is a label,
                                                  the key is identity
```

Trust state is shown in plain words (verified in person vs introduced by X), which
is the anti-spoofing affordance: two contacts can be named "Bob," only one has the
fingerprint you verified.

## 3. Introduce

Introduction is a per-device capability grant bound to the user key (see the
introduce-user-identity note), surfaced as three tiers, highest trust easiest:

```
   A. IN PERSON  (push this): Bob shows a QR, Alice scans. One tap, "verified in person."
   B. ONE-TIME WORD: Bob shares "brave-otter-42" out-of-band; Alice types it.
      Scope: (o) Reach me   ( ) A specific device      <- bound, non-downgradable
   C. VIA A MUTUAL CONTACT: Dave brokers a token; BOTH Alice and Bob still confirm
      ("Alice wants to connect, introduced by Dave. [Accept] [Decline]").
```

The confirm prompt names *who* (petname or "introduced by X" + fingerprint); it is
the trust gate and reduces friction not trust. Bob's side exposes exactly one
device; Alice never learns his other devices. Scope defaults to person-level;
device-scoped is the deliberate advanced choice (a GPU host exposing one box).

## 4. Recovery

Two orthogonal opt-in dials, surfaced as honest presets so nobody hand-composes a
bad quadrant:

- **Dial A, recovery method**: backup-only, or backup + social recovery.
- **Dial B, revocation witness**: none (pure gossip, accept the compromise race), or
  a blind timestamping oracle (federated, user-chosen, never one hardcoded party).

```
                       NO WITNESS                    BLIND WITNESS
   BACKUP ONLY    |  Anonymous purist            |  High-availability            |
                  |  zero infra, max privacy,    |  no social graph, wins the    |
                  |  accepts lose-key + the race |  compromise race              |
   BACKUP +       |  Trusted-circle              |  Consumer default             |
   SOCIAL         |  recoverable, race-exposed   |  recoverable + race handled   |
   RECOVERY       |  (explicit warning)          |  [recommended]                |
```

Mechanisms:
- **Backup is the primary path**; social recovery is a deliberately slow, multi-day
  safety net with notifications and a waiting period, never one-click.
- **Blind timestamping witness** signs only `H(old_key, new_key, ts)`; earliest
  timestamp wins a revocation race; it never sees identities and is federated
  (k-of-n), so it is a blind clock, not a coordinator.
- **7-day pending activation with old-key freeze** (Argent/Ethereum guardians
  model, minus the chain): a recovered/rotated key is pending, during which the old
  key can freeze or counter, the compromise-race mitigation.
- **Out-of-band confirmation is unskippable and multi-channel** (video / pre-agreed
  codeword; the "It's really Bob" button is grayed until the call happened, with a
  contact-specific challenge). Necessary, explicitly not a fortress.
- **Duress PIN** silently aborts or delays (coercion of the user, which threshold
  cannot help).
- **Recovery contacts are private**: the mapping is local, requests are encrypted
  per-contact, notifications ride an untrusted relay that learns timing and rough
  size but never the social graph.
- **Threshold defaults**: 3-of-5 (tolerates 2 offline); 2-of-3 power; 4-of-7 paranoid.

Hard-blocked or strongly discouraged (the genuinely dangerous combinations):
`M=1` recovery, a skippable-by-design out-of-band confirm, a single hardcoded
witness, and no backup at all. UI north star: **the unsafe thing is false
confidence, not the combination.**

## 5. Access control: capabilities, not an ACL file

filament does **not** use a Tailscale-style central ACL file (that is the pain and
the coordinator we reject). Access is an **object-capability** model.

- **Edge-local, owner-signed.** Each device/service carries its own signed grant
  list, a capability CRDT: the latest owner-signed version wins, revocation is a new
  version with the entry removed or expired. No central server; a version
  counter/timestamp plus the owner's signature suffice.
- **One-way, per-action, semantic.** A grant points from resource to grantee and the
  reverse does not exist unless separately granted (directionality is inherent).
  Actions are named semantically (`ssh`, `deploy`, `run-gpu-job`), not ports.
- **Deny-by-default; same-identity own-devices default to full trust** (zero config
  for the 90% case). Restrictions are opt-in per grant. The GPU consent gate
  ("borrower may run this exact command") is already this primitive.

### The apply surface is a narrow typed signed op (this is the "knob")

Not JSON Patch (too general), not embedded code (a sandbox nightmare). A
capability-specific op vocabulary, owner-signed, batched in a signed transaction:

```
   { "op": "grant" | "revoke" | "modify",
     "target": "<peer user-key or device>",
     "permissions": ["deploy"],
     "expires": "2026-10-25T00:00:00Z",
     "version": 17,
     "signature": "<owner>" }
```

The apply engine accepts only this schema, rejects anything outside the capability
namespace, and only the owner may sign. That constrained grammar is what makes it
both **LLM-legible and foot-gun-resistant**.

### AI is external; safety lives in the apply path

filament embeds no AI. Users bring their own (ChatGPT/Claude) to draft the typed
ops from natural-language intent. filament never trusts the author. Its safety is a
single apply path, identical no matter who or what wrote the grant:

- **Preview the effective bidirectional access, and show the negative space** (what
  is denied), because a security policy is verified by what it forbids:
  ```
   After this change:
     Pixel     -> DO-server : ssh      (new)
     GCloud    -> DO-server : deploy    (new)
     GCloud    -> DO-server : shell     DENIED
     DO-server -> GCloud    : anything  DENIED
   [ Apply ]  [ Adjust ]
  ```
- **Render it as a directed graph** of your named resources so asymmetry is obvious
  at a glance.
- **Guard self-lockout**: never cut off your own admin path without an explicit
  acknowledgement and an undo.

### Lost global view is an honest, fundamental cost

You cannot have edge-local capabilities and a perfect global view without
centralizing. The split:
- **Source of truth**: the edge-local capability lists (authoritative).
- **Convenience index**: the owner's local, signed, encrypted, backed-up **grant
  ledger** ("I granted X to Y"). Lost ledger = lost *view*, not lost *access*;
  rebuildable best-effort by fanning out across your own reachable resources.

The UX must say this plainly: the capability list is authoritative; the "shared
with" view is an index that can be incomplete.

### Sharp edges

- **Groups** are separate capability objects (a signed member list a grant can
  reference); grouping stays edge-local, at the cost of a resolution hop.
- **Grant at the service/device level with inheritance**, not per-tiny-action; keeps
  the view problem manageable.
- **Multi-owner**: each owner can revoke only their own grants; the union applies.
- **Revocation propagation**: the owner pushes new metadata; an offline peer's stale
  capability is valid only until expiry. Expiry bounds the window (the same
  no-global-revocation bound as recovery).

## The seams, named honestly

None is a central authority; each is a bounded helper.
- **Rendezvous / introducer**: a blind meeting point (STUN-like), never authorizes.
- **Revocation witness**: a blind, federated timestamping oracle, opt-in.
- **Grant ledger**: a local convenience index, never a source of truth.

## The one recurring pattern

The same human-confirm gate appears four times, introduce, grant, recovery, GPU
consent, each showing *who/what* and requiring an explicit yes. One pattern reused
is the product's trust model made tangible, and it is the thing to build first and
reuse everywhere.

### Two delivery modes for that gate (the CLI serves only one)

The gate is one concept but reaches the human two ways, and a CLI is natively good
at only the first:

- **Deliberate grant (pull).** The owner decides and issues the grant themselves,
  ahead of the access: `filament grant <peer> shell --for 1h`. No interruption, no
  surface needed, because the owner is already the party acting. This is the
  CLI-native mode and the correct default. Helping a friend lands entirely here: the
  friend is already at his keyboard, so *he* runs the grant; it is directional and
  expiring, so it cannot leak back to your machine and needs no `off` cleanup. It is
  also safer than a prompt, no connection blocked on a human, no approve-reflex
  trained by a modal, every grant logged and time-bounded.
- **Live approval (push).** Someone asks while the owner is not looking and wants a
  yes in the moment. This REQUIRES a persistent notification surface, which a CLI
  structurally is not. Degrade honestly: the daemon holds a **pending-requests
  queue** surfaced in-band on next CLI use (`filament requests`, plus a line in
  `filament devices`), and optional owner-configured **notify hooks** (notify-send /
  webhook / email). The instant tap-allow experience is the first-class job of the
  daemon + tray/companion app (see `docs/design-product-interface.md`), not
  something to fake in the terminal.

Do not collapse the two: **grant** is deliberate and CLI-native; **approve** is live
and is the concrete reason the companion surface exists.

## Postures, and the enterprise envelope

All of the above is one substrate (pairwise channels, user-key over device-certs,
edge-local capabilities) with **how much coordination you opt into** as the only
thing that changes across a spectrum of postures:

```
   ANON PURIST ---- CONSUMER / SMALL TEAM ---- PROSUMER/TEAM ---- ENTERPRISE
   no infra,        no-account, dead-easy       compute pooling    SSO + audit +
   max privacy      UX = the wedge              among trusted       device approval
                    (Tailscale can't match)     devices             = the ENVELOPE
   <---------------  ONE substrate, ONE codebase, sliding postures  --------------->
```

The **enterprise posture** is an opt-in, per-org, self-hosted **org authority**
(Headscale-shaped) that provides what the pairwise posture deliberately lacks:
SSO-bound identity (the org authority is just another CA binding user keys to IdP
identities; deprovision = revoke the org cert), admin-authorized membership +
device approval (delegated trust *within the org boundary*, which enterprises want
and consumers reject), central policy authored once and pushed to devices as the
typed signed ops, and the audit log + global policy view. It squares with "filament
stays pairwise" the same way the GPU discovery layer and the recovery witness do:
it is a **product-layer coordinator** that orchestrates pairwise primitives for an
org that opts in, never a mandatory global one. Cross-org stays pairwise;
anonymity is traded for control *inside* the org, which is the desired trade there.

### The positioning this implies (stress-tested)

- **The fabric is the foundation we must OWN, standalone, not merely "table
  stakes."** filament must remain a standalone mesh; Tailscale is a
  migration/compatibility bridge only, never the primary fabric. If we build on
  someone else's network we become a feature on their platform.
- **But fabric parity does not WIN enterprise.** You do not dislodge Tailscale with
  a newer VPN. Fabric is necessary, not sufficient.
- **The wedge is the compute platform: governing USE, not reachability.** Per-action
  capabilities (`run-gpu-job`, `deploy`, `read-logs`), sandbox + consent, content-
  addressed model distribution (`mount <cid>`), inference routing. Tailscale governs
  reachability and stops at the network edge.

```
   +===========================================================+
   |  COMPUTE PLATFORM      <- THE WEDGE (govern USE)          |
   |  lend/borrow GPU, sandbox+consent, mount<cid>, routing,    |
   |  per-ACTION capabilities.  Tailscale is NOT in this layer. |
   +===========================================================+
   |  ORG AUTHORITY         <- COMPLIANCE ENVELOPE (build LAST) |
   |  SSO, audit, device approval, central policy = Headscale   |
   +===========================================================+
   |  SECURE FABRIC / VPN   <- FOUNDATION (must own, standalone)|
   |  pairwise WireGuard, identity, capabilities                |
   +===========================================================+
```

- **Defensibility is temporary and execution-based**, not structural: first-mover,
  consumer distribution, and *depth* of the runtime primitives. If "govern use" is
  just "ACLs for GPU jobs," Tailscale copies it in a quarter. The moat is depth plus
  being first to the use case nobody has taken: **trusted small-group compute over a
  no-account mesh.**
- **Enterprise is not a trap, but enterprise-FIRST is.** The org authority is a
  **demand-pulled envelope built LAST**, not a wedge. Sequence: consumer no-account
  mesh -> prosumer/small-team compute pooling (validate primitives, no SOC2) ->
  team compute with light policy (org authority starts being asked for) ->
  enterprise envelope. Compute enterprise GTM (SOC2, SLAs, verifiable isolation,
  legal review of employee-owned GPUs, competing Modal/RunPod/CoreWeave) is a
  bigger, longer fight than a VPN GTM; earn it, do not lead with it.
- **The pitch is "secure compute pooling among trusted devices," never "a no-account
  Tailscale."** If we catch ourselves pitching the latter, we have lost the thread.

## Deferred / open

- Per-preset default for the witness-vs-pure-gossip dial.
- Detailed group-resolution and directory-inheritance semantics.
- Grant-ledger sync and best-effort rebuild details.
- Naming beyond local petnames (kept minimal on purpose; a global naming authority
  would reintroduce the coordinator we reject).
