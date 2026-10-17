# Auth keys: as easy as Tailscale's, without becoming a bearer secret

Status: direction, 2026-10-17. The first slice (environment / file / stdin, and
`up` joining on the way up) is implemented. This file records the model and what
is deliberately left.

## What Tailscale gets right

One key from a console, then one command:

```
tailscale up --authkey=tskey-auth-xxxx     # or TS_AUTHKEY in a container
```

The key carries the policy: reusable or one-off, ephemeral, pre-approved, tags,
an expiry. The box needs nothing else. Nobody hand-delivers a file per machine,
and nobody mints per boot when the same key can enrol a fleet.

## Why ours drifted

The invitation is signed material, and we deliberately refuse to accept it in
argv, because argv is visible in `ps` and lands in shell history. That left a
file as the only transport, which means one file per box and a delivery step
before the box can do anything. The security rule is right; the delivery was too
narrow.

## The model we want

The invitation already is an auth key. It has a ceiling, an expiry, a reuse
count, and an ephemeral flag. What was missing is a way to present it that is not
"copy this file to the machine first":

- `--authkey-file <path>`, where `-` means stdin.
- `TUNLION_AUTHKEY` in the environment (and `TUNLION_INVITE`, which CI already
  uses).
- `tunlion up` joins when it has no identity and a key is present, then serves.
  That is the one-command shape:

  ```
  TUNLION_AUTHKEY=filament-invite:v2:... tunlion up --detach
  ```

- `tunlion join` with no argument reads the same environment, for callers that
  want the join and the serve as separate steps.

Precedence is explicit file, then `TUNLION_AUTHKEY`, then `TUNLION_INVITE`. The
value is trimmed and held in `Zeroizing`. It is never logged, never printed back,
and never accepted as an argument.

Naming caveat: `up`'s automatic join has no device name to use, so the box takes
the platform hostname. A caller that needs a deterministic name (CI does, to
send to it) should keep the explicit `tunlion join --name <name>` and then `up`.

## Why this is still not a bearer secret

A bare bearer key is only a password: whoever holds it is in, until it expires.
The invitation is a signed delegation with a ceiling and a per-machine identity:

- the joiner mints its own device key at join; the enrolment key authorises, it
  does not become the device,
- the ceiling is signed, so the joining box cannot widen its own permissions,
- certificates stay short and renew while the record stands, so removal is
  "stop renewing", and a revoked record is terminal,
- `--reuse N` bounds how many boxes one file can enrol, and the count is durable
  (`used-invitations.json`), not process memory.

So we can be as easy to use and still refuse the "one string is root forever"
failure mode.

## What is still missing for parity

1. **Key management.** `tunlion keys` to list outstanding invitations and revoke
   them. Today the only record is `armed.json`, which is a listener, not a
   listing.
2. **Cohort revoke.** A device record carries no provenance, so retiring a key
   cannot stop the renewals of the boxes it admitted. That needs an
   `admittedBy` field first.
3. **Tags.** The model has them; the invitation mint does not take `--tag`.
4. **No expiry, with renewal.** The certificate must stay short, or "stop
   renewing" stops being a revocation mechanism. The right shape is an unbounded
   principal with short, renewed certificates. See `docs/ci-ux.md`.
5. **Per-claim approval.** For a reusable key that outlives one job, require an
   owner approval per claim (the Asks flow already exists).

## What must not regress

- Never argv. Env or file only.
- Never a world-readable key file; `--out` writes `0600` and refuses to clobber.
- Never log the key or echo it into a workflow log.
- Never widen the ceiling on renewal; renewal moves the clock only.
