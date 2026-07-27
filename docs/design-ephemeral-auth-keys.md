# Ephemeral devices and auth keys

Status: designed + adversarially reviewed (claude-advisor), pending implementation.
Sits after the capability layer, before the compute product. This is the
automation-facing face of identity + capabilities: a pre-authorized, scoped,
expiring delegation to self-enroll, plus a lifecycle where a device exists only
while it is present.

## Motivation

Automation and short-lived environments have no human to do the interactive
spoken-code pairing, and should not leave persistent identity behind: CI runners,
autoscaled workers, GPU borrowers (lend-gpu), and browsers. They need to
authenticate repeatedly, self-register, and be forgotten when they vanish.

## Two enrollment doors, one trust root

- **Interactive pairing** (spoken code / PAKE): people and persistent devices,
  live human authorization.
- **Auth key**: programmatic and ephemeral, pre-authorized delegation.

Both root in the same user key. The auth key is the user key pre-authorizing the
second door with a scope and a clock on it.

## The auth key (owner-signed)

```
AuthKey {
  issuer:    owner_pub,
  enroll_pub:[u8;32],        // a PUBLIC key. NOT a bearer secret (see Block 1).
  caps:      [semantic actions],  // a CEILING, not a floor (see delegated principal).
  audience:  [peer_pub ...] | Any, // which peer(s) may enroll (makes single-use enforceable).
  expires:   u64,            // MANDATORY, capped low by construction.
  reuse:     Once | N(u32) | Reusable,
  ephemeral: bool,
  tag:       String,         // "ci", "gpu-borrower"
  sig:       <owner user key>,
}
```

No bearer secret is ever transmitted.

## Enrollment (coordinator-free, self-verifying)

The machine generates its own device keypair and presents
`{auth_key, device_pub, possession_sig}`, where `possession_sig` is over the
session-bound possession message (the same confirmation-transcript binding the
identity layer uses) signed by **enroll_priv** (proving it holds the auth key's
private half) and by **device_priv** (proving it holds the device it claims).

The verifying peer, in order:
1. Validate `auth_key.sig` under `issuer`, where `issuer` MUST equal a `user_pub`
   the peer ALREADY trusts (its own trust anchor). Never accept a valid signature
   from an unknown owner: that is an attacker enrolling as their own owner (the
   genesis-forgery rule from the capability layer).
2. Reject if `expires` has passed.
3. Reject if `caps` contains `mesh`, structurally, regardless of a valid owner
   signature (see Mesh below). Enforced at the verifier, never only at issuance.
4. Reject if `audience` names peers and this peer is not among them.
5. Verify `possession_sig` under `enroll_pub` (holder possesses the auth key) and
   the device possession under `device_pub`.
6. Burn / rate-limit checks keyed by `enroll_pub` (the auth-key identity), NEVER
   by `device_pub` (attacker-chosen, and new on every ephemeral life).
7. Admit as a DELEGATED principal with a ceiling of `auth_key.caps`.

## Block 1: no bearer secret

A bearer `secret` cannot be validated without being disclosed. Coordinator-free,
the verifier is any peer, and peers are not equally trusted, so every peer the
machine enrolls at would learn the secret and could re-enroll itself as the
owner's device at any other peer. Tailscale avoids this only because the secret
goes to a single trusted coordinator. We have none. So the auth key carries an
enroll PUBLIC key and the holder proves possession of `enroll_priv`; the verifier
learns only a public key, nothing replayable. A leak (for example a forked-PR CI
log) is then confined to whoever reads it, not extended to every peer contacted.

## Block 2: caps are a ceiling, via a delegated principal class

An auth-key-enrolled machine is `principal_kind = Delegated`, NOT a device of the
owner. Two mechanisms would otherwise make `auth_key.caps` decorative: the
same-user full-trust default (an owner device inherits everything), and
`user_pub`-targeted grants (which apply to any device of that user). Both are
closed by the principal class. In `evaluate()`:

- `effective(delegated) = (what the user principal would be authorized for) INTERSECT auth_key.caps`.
- The same-user full-trust default does NOT apply to delegated principals.
- `user_pub`-targeted grants do NOT widen a delegated principal.

Invariant: for a delegated principal, `auth_key.caps` is an upper bound that no
grant path can widen. This is the entire value of the headline cases (constrained
borrower, browser, CI), so it is safe by construction, not by every future grant
author remembering.

## Single-use, honestly

Burn-once is not globally enforceable coordinator-free: burn state is per-peer, so
a single-use key claimed at peer A is claimable again at a fresh peer B that never
saw the burn (the first-seen problem from capability finding 1, but with no
resource to anchor a floor on). So:

- With an `audience` naming the target peer(s): "single-use at this named peer" IS
  locally enforceable, because that peer is the only party that matters and can
  track the burn for keys addressed to it. CI runners and borrowers know their
  target at issue time, so this costs the issuer nothing.
- Without a pinned audience: `reuse` count is best-effort HYGIENE, labeled as such
  in docs AND UI. No security argument anywhere rests on it. Best-effort burn
  gossip among the owner's own devices narrows the window but is never a bound.

Enforceable coordinator-free controls: expiry, caps (ceiling), audience, and
possession of `enroll_priv`. Reuse count is not one of them unless audience-pinned.

## Ephemeral lifecycle

- Not persisted: present while connected, removed on disconnect, re-register
  (re-claim + re-prove) on return. Presence is existence; no time-ago tail.
- NO continuity anchor and NO takeover guard: transient, and a new `device_pub`
  each life is normal and expected.
- Namespace separation: a delegated / ephemeral principal must NOT shadow or
  assume a persistent named device's identity or grants. The tiers never cross.
- **Liveness is a security boundary.** Once presence equals authorization,
  removal-on-disconnect is what ends authorization, so disconnect DETECTION is a
  security control, and a zombie or half-open session stays authorized until
  noticed. Bound ephemeral authorization by BOTH liveness AND a short absolute
  deadline, and re-prove the session periodically (not only at enrollment), so a
  zombie cannot coast to expiry.

## Revocation

No global revocation (the same accepted bound as capabilities), and WORSE for
reusable keys, because a reusable key names no holder and cannot be enumerated.
Mandatory short expiry, capped low by construction rather than left to the issuer,
is the real control. Best-effort gossip narrows the window.

## Use cases

- **CI runner**: single-use-per-job, audience-pinned to the target peer,
  `[transfer]` or `[gpu-run]` caps, short expiry, ephemeral.
- **Autoscaled worker**: reusable, audience-pinned, narrow caps, short expiry.
- **lend-gpu GPU borrower**: ephemeral, `[gpu-run]` only, audience = the lender's
  node. The delegated ceiling keeps it off everything else, including the mesh.
  This is the constrained-borrower-off-the-mesh model the WG limit required.
- **Browser**: an ephemeral, narrow-caps delegated device. Sidesteps the
  user-key-in-browser problem: the browser holds `enroll_priv` plus a
  non-extractable device key, and never the user key.

## Mesh in auth keys

Disallowed. A mesh cap hands a runner or borrower L3 reach that subsumes the
gates (the accepted WG limit), the largest possible grant on the least
trustworthy principal. Refuse it at the verifying peer, structurally, regardless
of a valid owner signature. This refusal only holds because Block 2 closes the
`user_pub`-targeted-grant inheritance path; otherwise the delegate would inherit
mesh anyway and the ban would buy nothing.

## Security summary

- No bearer secret (enroll keypair); leak confined, not fanned out to every peer.
- Caps as a hard ceiling via the delegated principal class.
- Mesh disallowed, verifier-enforced.
- Owner validated against the verifier's own trust anchor.
- Session-bound possession (no cross-session replay).
- Liveness + short absolute deadline + periodic re-proof (no zombie authorization).
- Rate-limit and burn keyed by `enroll_pub`, never the per-life `device_pub`.
- Single-use enforceable only with an audience; otherwise best-effort, labeled.
- Short mandatory expiry, capped by construction: the primary control given no
  global revocation.

## Schema-shaping (locked before implementation)

`enroll_pub` (not a secret), `principal_kind` (owner_device | delegated), and
`audience`. Enforcement-side and following: the liveness + absolute-deadline +
re-proof cycle, the verifier-side mesh refusal, and keying guards by `enroll_pub`.

## Open / phase-2

- Fleet-wide view of ephemeral devices is the rebuildable convenience-index
  problem; the per-peer view is the honest default.
- Best-effort burn gossip among the owner's own devices.
