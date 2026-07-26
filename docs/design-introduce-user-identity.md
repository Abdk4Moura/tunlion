# Introduce, user identity, and reaching one device (not a person's mesh)

> Status: design (2026-07-25). Extends the introduce model in
> `docs/design-mesh-network.md` (which keeps filament strictly pairwise). Reviewed
> adversarially (internal skeptic pass). Not yet built.

## The gap

filament is device-level: a device is an Ed25519 key = an overlay address, and
`introduce` wires two *devices* together (pairwise, rendezvous-brokered, the user
confirms). But humans reach *people*, and a person is a set of devices. That
mismatch leaves three things unaddressed:

1. **Addressing**: there is no "Bob," only bob-laptop / bob-phone / bob-desktop.
2. **Granularity**: you want a channel to *one* of Bob's devices, not to join his set.
3. **Privacy**: reaching Bob must not reveal that Bob has five devices, or which.

## Decision: a thin user-key-over-device-certs layer (SSH-CA shaped)

Add one layer, no more. It is deliberately **SSH certificate-authority shaped**,
which is the framing to steal:

| filament | SSH-CA analogue |
|---|---|
| **User key** (long-term, cold, rarely used) | the CA key |
| **Device key** (never leaves the device) | a host key |
| **Device certificate** ("this device is user U's", signed by the user key) | a signed host certificate |
| verify cert chains to U, then pairwise PAKE with the device | verify the cert, then connect to the host |

This is a strict simplification of Matrix cross-signing (master + self-signing +
user-signing keys), and that is correct: Matrix's extra machinery exists to do
federated cross-user trust without an authoritative server, which filament does
not need. One user key signing device certs is sufficient. (Keybase sigchains,
Signal's server-mediated device linkage, DIDs/verifiable-credentials,
WebAuthn/passkeys, age/minisign: understood and deliberately not adopted, wrong
scale or wrong abstraction.)

## Introduction becomes a per-device capability grant

Redefine introduction as: *Bob grants you an authorized channel to one specific
device, and proves that device is his.* It is **not** mesh membership and **not** a
roster. When you are introduced to Bob:

1. Bob's side exposes **exactly one device**: it sends that device's key +
   candidates + its device cert, **inside the PAKE-encrypted channel** (see privacy
   below).
2. You complete the normal pairwise PAKE / channel-binding with *that device* and
   verify the cert chains to Bob's user key.
3. You now hold: a pairwise-authorized link to bob-laptop, and the fact that its
   user is Bob. You learn nothing about his other devices. The set is never
   enumerated.

Authorization stays exactly where filament requires it: device-to-device, pairwise
(your device to bob-laptop). Only the *addressing and consent* are user-mediated.

### Scope is a knob on the out-of-band token, and it is not downgradable

The out-of-band token Bob shares (a one-time PAKE word / user-key fingerprint)
carries the scope, and the scope must be **bound and non-downgradable** (else a
confused-deputy problem):

- **User-scoped** ("reach me"): Bob's side chooses which device to expose (a
  designated front-door device, or an online one).
- **Device-scoped** ("reach my laptop specifically"): that one device is the target.

A user-scoped token must not be silently convertible to device-scoped or vice
versa without an explicit action by Bob.

## Privacy properties (and the honest caveats)

The property we want (never expose the device set) holds only if the protocol is
built carefully:

- **The rendezvous/introducer must see only the token and ciphertext.** The device
  key + cert exchange happens *inside* the PAKE-encrypted channel, so the
  introducer never learns Bob's device set.
- **Keep user-key identifiers out of plaintext signaling.** The PAKE token is the
  only rendezvous handle. If user keys appear in the clear during rendezvous, the
  introducer can correlate which two users connected.
- **Cert linkability is a real, accepted leak.** If Alice is introduced to Bob's
  device1 and later device2, both certs chain to Bob's user key, so Alice learns
  both are Bob's. That is the price of continuity. A user who wants context
  separation (work-Bob unlinkable from personal-Bob) uses **separate per-context
  user keys**, giving up continuity between them. This tradeoff is by design.
- **There is no global revocation** (see below); that is a privacy feature and a
  security liability at once.

## Continuity falls out (this is why we solve it first)

Because the introduction binds to the **user key**, not just a device key, Bob can
later expose a *different* device with a cert to the *same* user key; the peer
verifies "still Bob" and gets a fresh device link **with no new trust decision**.
This is the substrate identity-continuity and social recovery both need, which is
why this note comes before the recovery design: recovery = re-establishing the
user key's authority over a new device, vouched through peers who already hold a
link bound to that user key.

## Consistency with filament's pairwise core

- **Within Bob**: his devices are pairwise-paired with each other (a small private
  mesh) and share the user key, so they can coordinate which device fronts an
  introduction. This is entirely inside Bob's own trust domain and invisible to
  Alice. It does **not** create transitive trust.
- **Across users**: a single device-to-device pairwise link, separately authorized.
  No mesh membership, no roster, no transitive trust.
- **No coordinator sneaks in** as long as: device certs travel **with
  introductions** (never a central cert host), revocation is **pairwise** (never a
  central revocation server), and the introducer stays **stateless and
  token-based** (never stores user keys or device lists).

## Phase-1 recommendations

- **User key** generated on the most-trusted device or a hardware token (YubiKey),
  kept cold/offline; encrypted backup (paper / encrypted file / HSM). Its only job
  is signing device certs.
- **Device certs are short-lived** (e.g. 90 days) to bound the no-global-revocation
  window, refreshed before expiry.
- **Delegated online signer**: because a truly cold user key makes refresh a manual
  chore, authorize *one* online device (once, via the user key) with limited
  authority to refresh device certs. Avoids waking the cold key routinely.
- **Revocation of a lost device** is a signed statement from the user key,
  propagated **pairwise** only to peers who held a link to that device. Bounded
  blast radius, acceptable.
- **Do not** build a Matrix-style rotating master for phase 1: complexity without a
  concrete problem we have today. The cold-key-plus-short-certs posture upgrades to
  threshold or hardware-backed later without changing the architecture.

## Open problems (do not hand-wave these)

1. **Availability vs privacy on user-scoped tokens.** If Bob's front-door device is
   offline, the introduction fails. Need an explicit policy: try another device,
   expose all online devices, or wait. Pick one and state it; it is a real tension.
2. **Cold-key refresh friction** vs the delegated-online-signer mitigation above.
3. **Contact book is a real product surface.** Continuity assumes the peer stores
   Bob's user key as "Bob." That naming/contact abstraction must be designed, not
   assumed. (Keep it petname-scoped, not a global naming authority, per the mesh
   note.)
4. **Confused-deputy on scope.** The PAKE token must be cryptographically bound to
   its intended scope (user vs device).
5. **Initial user-key distribution is out-of-band and unsolved by the cert model.**
   Alice learns Bob's user key via QR code, a trusted introducer, or a first
   introduction. This is the irreducible bootstrap seam; do not pretend the cert
   model solves it.

## Summary

Add a thin **user-key-over-device-certs** layer (SSH-CA shaped), and redefine
introduction as a **per-device capability grant bound to the user key**. This lets
you address a person, land on exactly one device, keep the device set private, and
get identity continuity for free, all without breaking filament's pairwise
authorization or introducing a coordinator. Do not adopt Matrix cross-signing; this
model is simpler and sufficient. The residual risks are cert linkability (accepted
tradeoff), user-key compromise (mitigated by cold storage + short-lived certs), and
the standing temptation to add a central cert or revocation server (resist).
