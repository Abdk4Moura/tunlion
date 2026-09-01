# `add` must be able to put a device on the mesh

> Status: RESOLVED 2026-08-28. Diagnosed and reproduced 2026-08-27, implemented
> in `66357a0` (enrolment over the pairing code) and `13dcc0a` (one spelling per
> axis, and verbs that mean offer/accept).
>
> The surface that came out of it:
>
>     filament add                             offer a code, ordinary pair
>     filament add --for device                ...and enrol into your mesh
>     filament add --for person                ...explicitly external
>     filament add --for device --out f.json   ...delivered as a file
>     filament join <code>                     accept a code
>     filament join --invite-file f.json       accept a file
>
> `--internal`, added in the first pass, was deleted in the second: `--for`
> already asked that question on the invitation path, so the code path did not
> need a second spelling of it. Net one FEWER flag than before this work began.
>
> The report below is kept as written, because the reproduction is the useful
> part and it is what a future reader should compare against.

## The report

`filament add` and `filament add <code>` do not join a device to the mesh. They
behave as though pairing were for external people only, and mesh membership
comes solely from the invitation path.

## Reproduced, not inferred

Fresh owner, fresh device, nothing else:

    owner:   filament init --yes --name owner
    owner:   filament add --word "gigantic element" --name laptop
    device:  filament add GIGANTIC-ELEMENT-9982 --name owner

Both sides report success ("mutually remembered, verified end-to-end"). Then:

    device D:  fleet.rv            NO
               owner-signed cert   NO
               caps.json           NO
    device D lists its own owner under:
               EXTERNAL / "other people, time-boxed, deny-by-default"
    owner recorded:  laptop  caps=['transfer']  cert=false

So the device classifies its OWNER as an outsider, and the owner grants its own
laptop the baseline `transfer` capability and nothing else. That is not a
cosmetic mislabel: EXTERNAL is a real tier with deny-by-default semantics, and
without `fleet.rv` the device can never take part in auto-mesh at all.

## Why it happens

Two ceremonies that look interchangeable are not:

| | `add` / `add <code>` | `add --for` + `join` |
|---|---|---|
| exchanges | PAKE, then a pair secret | bounded invitation |
| issues an owner-signed `DeviceCert` | **no** | yes |
| delivers `fleet_rv` | **no** | yes (when persistent) |
| delivers `cap_header` / `cap_ops` | **no** | yes |
| result | pairwise peer, EXTERNAL tier | fleet member |

`pair_cmd` has a `same_person` check, but it only asks whether the peer ALREADY
holds a certificate issued by our owner key, i.e. whether it is already a mesh
member. A brand-new device has no certificate, so `same_person` is false and it
falls to the external branch. The check recognises membership; it never confers
it.

## What it should do

`add` and the invitation path should BOTH be able to admit an internal device or
an external person. The ceremony is a transport for the decision, not the
decision itself. Which one you use should be a matter of convenience (a code you
read out, versus a file you hand over), not a hidden change in what the peer
becomes.

## Posture is per-invocation, not a global default

Some devices should not get `shell` automatically even when they are mine.
Shell-by-default for same-person is the right convenience, and it must stay
overridable AT THE POINT OF ADDING, because that is when the operator knows what
the device is for.

`--allow` already exists on `add --for`. The pairing path has no posture control
at all: externals are hardcoded to baseline `transfer`. It needs the same flag,
applied to internal enrolment too.

## Implementation shape

1. **Extract the enrolment response.** The owner-signed ack (device cert, owner
   cert, `fleet_rv`, `cap_header`, `cap_ops`) is built INLINE in the daemon's
   `identity-auth-key-enroll-request` handler. Lift it into one function so the
   pairing path can produce the same artifact. Two hand-written copies of a
   certificate ceremony is exactly the shape that produced four per-peer bugs in
   the fleet handshake this month.
2. **Carry the peer device key on the pairing path.** The possession exchange
   already proves a device key when the peer HAS a cert. Enrolment needs that key
   when it does not.
3. **Issue on the minting side** when the operator says this is an internal
   device and we hold the UserKey.
4. **Persist on the claiming side** through the same code `join` uses, so a
   device enrolled by code is byte-identically a device enrolled by invitation.
5. **Posture flag** on both paths, defaulting to the same-person convenience.

## Do not rush step 3

It issues owner-signed certificates from inside the PAKE ceremony. Four attempts
to patch the fleet handshake this month each measured WORSE and were reverted;
every one was a small change to a ceremony that looked safe. This one wants the
negative tests written first: an EXTERNAL peer must never obtain a certificate,
`fleet_rv`, or anything above its stated posture through this path.
