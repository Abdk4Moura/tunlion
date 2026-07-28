# Reviewing signed structures: the field-coverage check

A standing, mechanical review step for any owner/device-signed structure
(capability ops, device certs, auth keys, headers). It exists because a single
class of bug kept recurring across the capability + identity + ephemeral work:

> **The signature commits to less than the semantics read.**

A field is used to make a security decision, but that field is *not* inside the
bytes the signature covers (or the encoding isn't injective, so two different
logical values share one signature). The signature then verifies while the
attacker changes the meaning.

## The check (do this for every signed struct, on the first pass)

1. **Enumerate every field the code reads for a security decision** — anywhere a
   value gates allow/deny, a ceiling, a ban, an expiry, a reuse limit, an
   audience, an owner/issuer identity.
2. **Prove each of those fields is inside the signed (canonical) bytes.** Read
   the canonicalization function and tick every field off against the struct.
   A field that's read but not signed is a forgery primitive.
3. **Prove the encoding is INJECTIVE** — distinct logical values must map to
   distinct bytes:
   - every variable-length section carries a **count** prefix (u32, not u8 — no
     truncation) *before* its items;
   - every variable-length item carries a **length** prefix;
   - no section is terminator-delimited or boundary-free (an unmarked boundary
     between two adjacent variable sections lets bytes move across it);
   - enum discriminants AND their payloads are committed (a bare discriminant
     lets `N(1)` masquerade as `N(999999)`).
4. **Confirm a single producer.** The canonical-bytes function must be called by
   exactly the sign path and the verify path — a second encoder is how an
   injective encoding stops being the one actually used.
5. **Normalize where you check.** If the signature commits to a normalized form
   (lowercased/sorted/deduped), every security check must read the *normalized*
   field, not the raw one — or assert `field == normalize(field)` at the point
   of use so the invariant is local, not established two functions away.
6. **Verify recomputes from received bytes.** Bounds/rejections that only run at
   *mint* don't protect a key received off the wire (which skips mint). Enforce
   at verify too.
7. **Nonces are the verifier's, not the payload's.** A challenge nonce echoed
   inside the signed payload is decorative — it reintroduces replay in full. The
   verifier must build the signed message from a nonce IT generated (CSPRNG),
   holds per-session, and consumes (single-use, erased after one attempt whether
   it passed or failed). Prefer consume-from-store so single-use is structural.

## Companion rule: no optional security inputs

A security check that reads an `Option` input runs only when the input is
`Some`. If the input arrives from the peer/attacker, the attacker supplies
`None` and the check is skipped — the guard "constrains only those who
volunteer to be checked."

> **A security input that can be absent will be absent when it's the attacker
> supplying it. Make it non-optional at the type level.**

- Don't gate a verification on `if let Some(x) = attacker_supplied { ...check... }`.
  Use `let Some(x) = attacker_supplied else { return Deny/None }` — absence is a
  refusal, not a skip.
- Better, drop the `Option` from the parameter/field type so "no value" is
  unrepresentable and a caller cannot express the unsafe state (same spirit as
  `PrincipalKind { OwnerDevice, Delegated { caps } }` making a delegated
  principal without caps impossible).
- This bit the ephemeral auth-key feature three separate times: a dead
  `auth_key_caps: Option` argument (ceiling inert), a challenge nonce that could
  be a self-chosen value, and a `device_cert: Option` on the enroller so a
  malicious daemon omits it and skips mutual auth. Each was one line; each
  defeated the exact property the code around it was written to guarantee.

## Why it's here (six instances, one feature)

The ephemeral auth-key work (#9) alone produced six findings of this exact shape:
the bearer secret, caps read as a floor, a case-sensitive mesh ban over
case-normalized signed bytes, truncated `as u8` length prefixes, a count-less
caps/audience boundary, and an uncommitted `Reuse::N(n)` count. Each is a
one-line encoding fix; together they'd have let a holder forge caps, bypass the
mesh ban, and defeat the single-use limit. The mechanical check above catches
all six before code review, let alone before shipping.
