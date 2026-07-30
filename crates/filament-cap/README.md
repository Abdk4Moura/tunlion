# filament-cap

Edge-local capability tokens: signed grants, delegation ceilings, and fully
offline authorization — no server, no CA, no callback.

A capability is an owner-signed statement that a principal may perform an action
on a resource. Verification is a pure function of the token, the resource header,
and the current time; it never phones home. Delegated principals are bounded by a
ceiling (the intersection of what they were granted and what the delegator holds),
so a delegate can never exceed its delegator.

This is the authorization core of [filament](https://github.com/Abdk4Moura/filament),
extracted so it can be audited and reused on its own.

## What's inside

- **Signed capability objects** — `CapHeader` (per-resource genesis/succession/ratchet)
  and `CapOp` (typed `Grant` / `Revoke`), with injective canonical encodings so a
  signature commits to exactly what verification reads.
- **Pure evaluation** — `evaluate(...)` and `evaluate_grants_only(...)` (the latter
  never applies the owner shortcut, for gate sites that must treat a same-owner peer
  as an ordinary principal). Both share one grant-scan, so they cannot diverge.
- **Delegation ceiling** — a delegated principal's action must fall within its auth
  key's stated caps, enforced independently of the grant scan.
- **Fleet trust** — `fleet_auto_trust(same_owner, binding, scoped_in_bounds)`, a
  Proven-gated scoped-default decision for a device that chains to your own user key.
- **Ephemeral auth keys** — the `ephemeral` module: owner-signed, single-use
  pre-authorization for device self-enrollment.

## Status

Pre-1.0. The API tracks filament's internal needs and may change between minor
versions. Security-reviewed but not independently audited.

## License

MIT
