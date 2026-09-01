# Mesh membership: what the user sees

> Status: proposed (2026-08-15), second draft. The first failed adversarial
> review; the findings are folded in and the blocking decision is made. The
> model is `docs/design-mesh-network.md`, and the decision this draft rests on is
> its "enrolment and primacy are two rights" section:
>
> **Changing the set of primaries always needs the root. Changing the set of
> devices never does.**
>
> Still not buildable: it assumes certificate renewal, which does not exist
> (#236 records that the UI already claims otherwise). Nothing here ships before
> that.

The promise, in one line: **you add a device once, from whatever machine is in
your hand, and every other device knows it.**

## The honesty rule this document is mostly about

Membership is distributed, so a device shows what it last heard. A stale view is
wrong in **both** directions: it can miss a device that was added, and it can
still list a device that was removed.

The first draft stated that rule and then broke it in six screens, including on
the fresh path and on the screen it held up as its own honesty exemplar. The
rule is easy to write and hard to keep, so each screen below records what the
program can actually establish.

Three specific traps, all of which caught the first draft:

- **Do not print a verdict when you can only establish an observation.** "roster
  current" is a verdict. "fetched 30s ago" is an observation. A withholding
  relay reproduces the first exactly.
- **Do not forecast.** "will learn about it when it next connects" requires
  reconnection, delivery, and nothing withholding. None are established.
- **Do not state a quantity no single device can compute.** With two primaries,
  no one device knows the longest certificate another has issued.

## `filament devices`

Fresh:

```
  ● MESH  /  your devices
     ● phone        online   primary   inbox mount shell
     ● desktop      idle     primary   inbox mount
     ● laptop       idle               inbox mount

     roster epoch 41, fetched 30s ago
```

Epoch and fetch time, both facts. No claim that this is the newest epoch that
exists, because the device cannot know that.

Stale:

```
  ● MESH  /  your devices
     ● phone        ?        primary   inbox mount shell
     ● desktop      ?        primary   inbox mount

     roster epoch 39, last fetched 3 days ago; could not reach the mesh
     devices added since are missing, and devices removed since are still listed
     shell and write access are paused until this refreshes
```

Liveness becomes `?` rather than `idle`, because it is not established. Both
failure directions are named, because naming one is the more dangerous
half-truth. And the last line is the substantive change from the first draft: a
banner is not a security boundary, so past a threshold the deliberate tier is
**denied**, not annotated.

## Adding a device

`filament add` on one machine, `filament join <code>` on the other, from any
device holding an enrolment delegation, which is the point of the split.

The verbs split by ROLE, not transport: `add` offers, `join` accepts, and
whether the offer travelled as a spoken code or an invitation file is an
argument. Add `--for device` to enrol the other side into the mesh rather than
merely pair with it; `--for person` is the explicit external case. (`add <code>`
still accepts a code, but `join <code>` is the spelling everything prints.)

```
  ✓ laptop joined your mesh
    4 devices: phone, desktop, tablet, laptop

    phone, desktop     told
    tablet             not told (offline)
```

"Not told (offline)" is the fact. The first draft said "will learn about laptop
when it next connects", which is a forecast, one line after the document told
itself not to forecast.

On the joining device, replacing today's `EXTERNAL / other people,
time-boxed, deny-by-default`, which is wrong for your own laptop:

```
  ● MESH  /  abdul's devices
     ● phone        online
     ● desktop      idle

  you are 'laptop' here, with inbox + mount
  this is a local index; each device's own capability list is authoritative
```

The last line is kept from today's product (`ux-copy-final.md` 3a). Dropping it
while making the list look mesh-wide would move the surface in exactly the
direction that produced #226 and #228.

## Removing a device

```
$ filament revoke laptop
  ✓ laptop removed from your mesh

    phone       told
    desktop     not told (offline)

  Any device that has not been told still honours laptop's certificate.
  Each stops within 10 minutes of hearing, or when its own roster expires.
    filament revoke laptop --now    contacts every device this device knows
                                    about, and fails loudly if any is unreachable
```

Three corrections from the first draft. It no longer prints "expires in 27
days", a quantity no single device can compute once two primaries can issue
certificates, and which is not a bound at all if a primary is compromised. It
states the bound the system can actually deliver, which is bounded staleness
rather than immediacy. And `--now` says "every device this device knows about",
because "every device" cannot include a connected mesh's devices and cannot
distinguish "unreachable" from "never knew about".

## Promoting and demoting

Both need the root. That is the decision, and it removes the first draft's worst
defect: two adjacent screens stating opposite rules for the most
security-relevant verb in the model.

```
$ filament devices promote desktop
  Promoting needs your recovery phrase, because a primary that could promote
  could also promote a device you never approved, and removing the primary
  afterwards would not remove that device.

  desktop will be able to change who is a primary. It does not need this to
  add ordinary devices; any device with an enrolment delegation can already
  do that.

  recovery phrase:
```

```
$ filament devices demote desktop
  Demoting needs your recovery phrase, because nothing a primary could sign
  is enough to remove a primary.

  Devices desktop enrolled stay enrolled. Their certificates lapse on their
  own unless another primary renews them.

  recovery phrase:
```

The last paragraph of the demote screen is the one that must not be dropped. The
first draft implied the recovery phrase was sufficient to end a compromise, and
it is not: demotion does not retract what the demoted primary already signed.
Saying what a security operation does **not** do is the part users need.

This also closes #191, which advertises `devices promote` and does not implement
it. The verb now has a precise meaning: grant the right to change the primary
set.

## Expiry, and why it is not removal

Expired means "cannot currently prove standing". Tombstoned means "the owner
removed me". Conflating them is what makes a short window sound like
annihilation.

A grace **window**, not a grace state:

- full ceiling until **T1**
- **transfer only** until **T2**, and say so
- nothing after **T2**

T2 stays a hard bound. A degraded tier with no expiry would convert today's
bounded exposure into an unbounded one, deleting the only fail-closed mechanism
the product currently has, so the residual tier must terminate. Transfer is a
defensible residual because it is push, not read (`fleet_ui/requests.rs` renders
it "send you files"), so it is not an exfiltration path, but an indefinite write
channel into a machine whose owner believes the device is gone is a
content-planting vector. Bounded, it is reasonable.

```
  ! no primary reachable. full access until 14:20, then send and receive only.
    this device drops out entirely at 03:00 tomorrow unless a primary renews it.
```

Both times are stated, because the second is the one that costs the user their
device.

## The one conflict a user can see

```
  ! laptop was added here, and removed by desktop 2 minutes ago.
    A removal always wins, whichever happened first.
    To re-admit it, add it again from the laptop itself. It will need a new
    device key, because a removed key stays removed.
```

Both surprising rules stated where they bite. Kept verbatim from the first
draft, which the review confirmed is correct.

## Vocabulary

Keep `filament devices`. The mesh model lives in the heading. #198 shipped
because a surface removal was audited for the new thing working rather than the
old thing still existing, and a second verb for a list that already has one
invites the same mistake.

## Open

- Connecting two meshes. A device shared into another mesh appears in both
  rosters, keyed `(issuing root, device, ceiling)` and never compared across
  meshes. A primary is never shared into another mesh. Screens not designed.
- Merging two meshes. Not designed, deliberately not smuggled in.
- Coercion. The recovery phrase is a single point whose capture is total and
  permanent, and k-of-n is not being built. At minimum, root rotation signed by
  the outgoing root, so an owner who recovers from coercion has a path.
