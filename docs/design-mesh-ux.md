# Mesh membership: what the user sees

> Status: proposed (2026-08-15). The model is in `docs/design-mesh-network.md`
> (reconciliation section). This note is only the surface: what a person types,
> what they read, and which sentences we are allowed to print.

The promise, in one line: **you add a device once and every other device knows
it.** Everything below exists to make that true and to be honest on the
occasions when it is not yet true.

## The honesty problem, first

Membership is distributed, so a device shows what it last heard. A stale view is
wrong in **both** directions: it can miss a device that was added, and it can
still list a device that was removed. Under `docs/ui/OUTPUT.md` that means a
device list is not allowed to be printed as bare fact. It has to carry its own
freshness.

This is the whole design constraint. Get it wrong and `filament devices` joins
the list of surfaces that confidently state something the program has not
established, next to #226 and #228.

## `filament devices`

Fresh:

```
  ● MESH  /  your devices
     ● phone        online   primary   inbox mount shell
     ● desktop      idle     primary   inbox mount
     ● laptop       idle               inbox mount        added 4m ago

     roster current, checked 30s ago
```

Stale, which is the screen that matters:

```
  ● MESH  /  your devices
     ● phone        ?        primary   inbox mount shell
     ● desktop      ?        primary   inbox mount

     roster last updated 3 days ago; could not reach the mesh to refresh
     devices added since then are missing, and devices removed since then
     are still listed
```

Two rules in that second screen. Liveness becomes `?`, not `idle`, because we
cannot establish it. And the caveat states both failure directions, because
naming only one of them is the more dangerous half-truth.

## Adding a device

The flow does not change. `filament add` on one device, `filament add <code>` on
the other. What changes is the sentence at the end, on the issuing side:

```
  ✓ laptop joined your mesh
    4 devices: phone, desktop, tablet, laptop

    phone, desktop     told
    tablet             offline, will learn about laptop when it next connects
```

Do not print "they will all see it in a few minutes". We can establish who was
told. We cannot establish when an offline device comes back.

And on the joining device, replacing today's `EXTERNAL / other people,
time-boxed, deny-by-default`, which is simply wrong for your own laptop:

```
  ● MESH  /  abdul's devices
     ● phone        online   
     ● desktop      idle

  you are 'laptop' here, with inbox + mount
```

## Removing a device

This is where propagation is load-bearing, so it gets the most honest screen in
the product:

```
$ filament revoke laptop
  ✓ laptop removed from your mesh

    phone       told
    desktop     offline, will be told when it next connects

  Until desktop hears, it still honours laptop's certificate, which expires
  in 27 days. To cut that short:
    filament revoke laptop --now     contacts every device, fails loudly if
                                     any cannot be reached
```

The certificate expiry is the real backstop and the screen says so out loud. A
removal you cannot deliver is a removal that has not fully happened, and the
user is the one who needs to know that, not us.

**Certificate lifetime is therefore the security tuning knob**, not the roster
refresh interval. Shorter certificates mean a removal you could not deliver
stops mattering sooner. That is a real tradeoff to expose in `filament set`
rather than bury.

## Promoting a primary

Closes #191, which advertises `devices promote` and does not implement it. Under
this model the verb has a precise meaning: give this device the authority to add
and remove devices.

```
$ filament devices promote desktop
  This lets desktop add and remove devices in your mesh, acting as you.
  You can undo it from any primary. Removing a primary later needs your
  recovery phrase.
  Promote desktop? [y/N]

  ✓ desktop is a primary
    primaries: phone, desktop
```

Demotion is the case that needs the root, and the prompt should explain why
rather than just demand the phrase:

```
$ filament revoke desktop --primary
  desktop is a primary, so removing it needs your recovery phrase. A primary
  holds the authority to add devices, including itself, so nothing a primary
  could sign is enough to remove a primary.

  recovery phrase:
```

That is the moment the recovery phrase earns its keep, and the explanation is
what turns it from an obstacle into a reason.

## The one conflict a user can see

Merge is union of monotone sets with removal dominating, so concurrent edits do
not conflict. The single visible case is an add that loses to a removal:

```
  ! laptop was added here, and removed by desktop 2 minutes ago.
    A removal always wins, whichever happened first.
    To re-admit it, add it again from the laptop itself. It will need a new
    device key, because a removed key stays removed.
```

Both surprising rules are stated where they bite, which is the only place a user
will read them.

## Vocabulary

Keep `filament devices`. The mesh model shows up in the **heading** (`MESH /
your devices`) rather than in a new verb. #198 shipped because a surface removal
was audited for the new thing working rather than the old thing still existing,
and adding a second verb for a list that already has one invites the same class
of mistake.

`filament mesh` is worth considering later, when connecting two meshes needs a
home. Not before.

## Open

- Connecting two meshes: a device shared into another mesh appears in both
  rosters. The screens for that are not designed here.
- Merging two meshes: not designed, and deliberately not smuggled in.
- Quorum primaries (k-of-n): the model supports it, the UX does not exist, and
  it should stay optional because changing membership would otherwise need k
  devices awake.
