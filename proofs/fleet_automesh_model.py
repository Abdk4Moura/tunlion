#!/usr/bin/env python3
"""Exhaustive model check for fleet auto-mesh (docs/design-fleet-automesh.md).

Same discipline as establishment_model.py: enumerate the ENTIRE reachable state
space of a faithful model, then assert the properties over every state, not over
a trace we happened to hit.

WHAT IS MODELLED
----------------
A fleet of N devices under one owner key. Device 0 is the owner (holds the
UserKey, always enrolled, never revoked, always online).

Per device:
  enrolled   holds a DeviceCert chaining to the owner key
  revoked    global truth: the owner has revoked it
  rv         which fleet_rv generation it HOLDS            (-1 = none)
  sub        which fleet channel it is SUBSCRIBED to       (-1 = none)
  online     reachable right now
  known      peers it has admitted (its live mesh view)
  rev_known  peers it LOCALLY knows are revoked

Global: `epoch`, the current fleet_rv generation.

STATE <-> CODE MAPPING
----------------------
  enroll             identity-auth-key-enroll-ack carrying fleet_rv  (main.rs:6034)
  subscribe          sess.emit("subscribe", channel_of(fleet_rv))    (main.rs:15915)
  discover           known-peer push + subscribe-ACK roster          (signaling.py:546)
  admit gate         verify_chain + local revocation record          (filament-id:220)
  revoke             owner revokes; epoch bumps, fleet_rv rotates    (caps.json epoch)
  propagate_revoke   revocation reaches a peer over its PAIRWISE channel
  rotate             new fleet_rv delivered over the PAIRWISE channel

The `discover` action deliberately collapses the async known-peer push and the
synchronous subscribe-ACK roster into one action: both have the identical,
idempotent effect (a admits b), so no interleaving of the two can differ. That
is the same reason net.rs handles them on one code path.

WHAT IS PROVEN
--------------
Safety, checked in every reachable state:
  S1  no admission without a cert: b in known[a] implies enrolled[b]
  S2  no retention of a locally-known revoked peer: b in known[a] implies
      b not in rev_known[a]
  S3  a device holds a fleet_rv only if it is enrolled
  S4  the owner never admits a device it has revoked

Tier 2 adds an INTRUDER: a device with no owner-signed cert that parks on every
fleet channel id it could possibly learn. Without it, S1 is VACUOUS, because
only an enrolled device can ever subscribe, so nothing uncertified is ever on a
channel to be wrongly admitted. Removing the cert check from `discover` was
caught by no tier until this one existed. That is the whole reason it is here:
the check must be able to fail before a pass means anything.

Liveness, by backward reachability from the goal: EVERY reachable state can
still reach full convergence, where every live (enrolled, non-revoked) device
  - mutually knows every other live device,
  - holds and is subscribed to the CURRENT epoch's channel,
  - has learned every revocation and dropped those peers.
This is the strong form: not "the goal is reachable from the start" but "no
reachable state is a trap", which is what catches a protocol that can wedge.

THE RESIDUAL THIS MAKES EXPLICIT
--------------------------------
S2 is conditioned on rev_known, not on the global revoked flag, because a real
device gates admission on its LOCAL record. So between `revoke` and
`propagate_revoke` reaching a peer, that peer will still admit the revoked
device. The model asserts that window closes (liveness) but does not pretend it
does not exist. That window is revocation-propagation latency, which filament
already has; the fleet channel neither widens nor narrows it.
"""

import sys
from itertools import product

OWNER = 0


class Dev:
    __slots__ = ("enrolled", "revoked", "rv", "sub", "online", "known", "rev_known")

    def __init__(self, enrolled, revoked, rv, sub, online, known, rev_known):
        self.enrolled, self.revoked = enrolled, revoked
        self.rv, self.sub, self.online = rv, sub, online
        self.known, self.rev_known = known, rev_known


def pack(devs, epoch):
    return (epoch, tuple((d.enrolled, d.revoked, d.rv, d.sub, d.online,
                          d.known, d.rev_known) for d in devs))


def unpack(state):
    epoch, ds = state
    return [Dev(*d) for d in ds], epoch


def initial(n, with_intruder=False):
    devs = []
    for i in range(n):
        if i == OWNER:
            devs.append(Dev(True, False, 0, -1, True, frozenset(), frozenset()))
        else:
            devs.append(Dev(False, False, -1, -1, True, frozenset(), frozenset()))
    if with_intruder:
        # INTRUDER (index n): knows the fleet channel id but holds NO cert from
        # the owner key. Models the worst case for the "the channel is only a
        # meeting point" claim: channel-id leakage via a stale fleet_rv, a
        # compromised backup, or a signaling-server observer.
        devs.append(Dev(False, False, -1, -1, True, frozenset(), frozenset()))
    return pack(devs, 0)


def successors(state, n, max_epoch, allow_offline, total=None):
    """Every enabled action. Returns a list of (label, next_state)."""
    devs, epoch = unpack(state)
    total = total if total is not None else n
    out = []

    def emit(label):
        out.append((label, pack(devs, epoch)))

    # The intruder can park on ANY epoch's channel at will: assume total leakage
    # of every channel id, so the cert gate is the only thing left standing.
    for i in range(n, total):
        d = devs[i]
        for e in range(max_epoch + 1):
            if d.sub != e:
                old = d.sub
                d.sub = e
                emit(f"squat({i},{e})")
                d.sub = old

    for i in range(n):
        d = devs[i]

        # enroll: the owner certifies i and hands it the current fleet_rv.
        if not d.enrolled and d.online and devs[OWNER].online:
            d.enrolled, d.rv = True, epoch
            emit(f"enroll({i})")
            d.enrolled, d.rv = False, -1

        # subscribe: join the channel for the fleet_rv this device holds.
        if d.enrolled and d.online and d.sub != d.rv:
            old = d.sub
            d.sub = d.rv
            emit(f"subscribe({i})")
            d.sub = old

        # rotate: current fleet_rv delivered over i's pairwise channel.
        if d.enrolled and not d.revoked and d.online and devs[OWNER].online and d.rv != epoch:
            old = d.rv
            d.rv = epoch
            emit(f"rotate({i})")
            d.rv = old

        # revoke: owner revokes i, which bumps the epoch and rotates fleet_rv.
        if i != OWNER and d.enrolled and not d.revoked and epoch < max_epoch:
            o = devs[OWNER]
            sav = (d.revoked, epoch, o.rv, o.known, o.rev_known)
            d.revoked = True
            epoch += 1
            o.rv = epoch
            o.known = o.known - {i}
            o.rev_known = o.rev_known | {i}
            emit(f"revoke({i})")
            d.revoked, epoch, o.rv, o.known, o.rev_known = sav

        # propagate_revoke: i learns of a revocation over its pairwise channel
        # and drops that peer.
        if d.enrolled and not d.revoked and d.online and devs[OWNER].online:
            for r in devs[OWNER].rev_known - d.rev_known:
                sav = (d.rev_known, d.known)
                d.rev_known = d.rev_known | {r}
                d.known = d.known - {r}
                emit(f"propagate_revoke({i},{r})")
                d.rev_known, d.known = sav

        # offline / online churn (degraded tier only; the owner stays up).
        if allow_offline and i != OWNER:
            d.online = not d.online
            emit(f"{'offline' if d.online is False else 'online'}({i})")
            d.online = not d.online

    # discover: a admits b. Requires a shared live meeting point AND a valid
    # owner-signed cert AND no local revocation record. Presence alone is not
    # sufficient, which is the property that keeps the channel a rendezvous.
    for a, b in product(range(total), repeat=2):
        if a == b:
            continue
        da, db = devs[a], devs[b]
        if not (da.online and db.online):
            continue
        if da.sub == -1 or da.sub != db.sub:
            continue          # not on the same fleet channel
        if not db.enrolled:
            continue          # no cert chaining to the owner key
        if b in da.rev_known:
            continue          # locally revoked
        if b in da.known:
            continue          # idempotent
        old = da.known
        da.known = da.known | {b}
        emit(f"discover({a},{b})")
        da.known = old

    return out


def check_safety(state, n, total=None):
    devs, epoch = unpack(state)
    total = total if total is not None else n
    for i in range(total):
        d = devs[i]
        for b in d.known:
            if not devs[b].enrolled:
                return f"S1 violated: {i} admitted uncertified {b}"
            if b in d.rev_known:
                return f"S2 violated: {i} retains locally-revoked {b}"
        if d.rv != -1 and not d.enrolled:
            return f"S3 violated: unenrolled {i} holds fleet_rv"
        if i == OWNER:
            for b in d.known:
                if devs[b].revoked:
                    return f"S4 violated: owner admitted revoked {b}"
    return None


def is_goal(state, n):
    devs, epoch = unpack(state)
    devs = devs[:n]          # the intruder is never part of convergence
    live = [i for i in range(n) if devs[i].enrolled and not devs[i].revoked]
    if len(live) + sum(1 for d in devs if d.revoked) != n:
        return False                      # every device enrolled or revoked
    for i in live:
        d = devs[i]
        if not d.online or d.rv != epoch or d.sub != epoch:
            return False
        for j in live:
            if i != j and j not in d.known:
                return False              # full mutual mesh among live devices
        for r in range(n):
            if devs[r].revoked and (r not in d.rev_known or r in d.known):
                return False              # revocations learned and applied
    return True


def explore(n, max_epoch, allow_offline, with_intruder=False, cap=4_000_000):
    total = n + (1 if with_intruder else 0)
    start = initial(n, with_intruder)
    seen = {start}
    stack = [start]
    edges = {}
    while stack:
        s = stack.pop()
        v = check_safety(s, n, total)
        if v:
            return None, None, f"{v}\n  in state {s}"
        succ = successors(s, n, max_epoch, allow_offline, total)
        edges[s] = [t for _, t in succ]
        for _, t in succ:
            if t not in seen:
                if len(seen) >= cap:
                    return None, None, f"state cap {cap} exceeded"
                seen.add(t)
                stack.append(t)
    return seen, edges, None


def backward_can_reach_goal(seen, edges, n):
    """States from which the goal is still reachable (least fixpoint)."""
    rev = {s: [] for s in seen}
    for s, ts in edges.items():
        for t in ts:
            rev[t].append(s)
    good = {s for s in seen if is_goal(s, n)}
    if not good:
        return good
    work = list(good)
    while work:
        s = work.pop()
        for p in rev[s]:
            if p not in good:
                good.add(p)
                work.append(p)
    return good


def run(label, n, max_epoch, allow_offline, with_intruder=False):
    seen, edges, err = explore(n, max_epoch, allow_offline, with_intruder)
    if err:
        print(f"  {label:<28} FAILED: {err}")
        return False
    good = backward_can_reach_goal(seen, edges, n)
    traps = seen - good
    if not good:
        print(f"  {label:<28} FAILED: goal unreachable in {len(seen)} states")
        return False
    if traps:
        t = next(iter(traps))
        print(f"  {label:<28} FAILED: {len(traps)} trap state(s), e.g. {t}")
        return False
    print(f"  {label:<28} PROVEN  ({len(seen)} states, 0 unsafe, 0 traps)")
    return True


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    print("Fleet auto-mesh model check (docs/design-fleet-automesh.md)")
    ok = True

    if only in (None, "0"):
        print("\nTier 0 GoodNet: all devices online, no revocation.")
        print("  proves: convergence to a full mesh for EVERY enrollment /")
        print("  subscribe / discover interleaving, and no admission without a cert.")
        for n in (2, 3, 4):
            ok &= run(f"GoodNet N={n}", n, max_epoch=0, allow_offline=False)

    if only in (None, "2"):
        print("\nTier 2 Intruder: an uncertified device parks on every fleet")
        print("  channel it can learn. proves: presence authorizes NOTHING, and")
        print("  the fleet still converges with a squatter sitting on the channel.")
        for n in (2, 3):
            ok &= run(f"Intruder N={n}", n, max_epoch=0,
                      allow_offline=False, with_intruder=True)
        ok &= run("Intruder N=2 K=1", 2, max_epoch=1,
                  allow_offline=True, with_intruder=True)

    if only in (None, "1"):
        print("\nTier 1 Degraded: GoodNet plus revocation (epoch rotation),")
        print("  revocation propagation lag, and offline/online churn.")
        print("  proves: no reachable state is a trap, rotation never partitions")
        print("  the fleet permanently, and a learned revocation is never undone.")
        for n in (2, 3):
            ok &= run(f"Degraded N={n} K=1", n, max_epoch=1, allow_offline=True)

    print("\n" + ("ALL PROVEN" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
