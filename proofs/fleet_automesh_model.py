#!/usr/bin/env python3
"""Exhaustive model check for fleet auto-mesh (docs/design-fleet-automesh.md).

Same discipline as establishment_model.py: enumerate the ENTIRE reachable state
space of a faithful model, then assert the properties over every state, not over
a trace we happened to hit.

WHAT IS MODELLED
----------------
A fleet of N devices under one owner key. Device 0 is the owner (holds the
UserKey, always enrolled, never revoked, always online). Every joined device is
PAIRED with the owner (enrolment pairs them); joined devices are never paired
with each other. That sibling relation is the one auto-mesh adds.

Per device:
  enrolled   holds a DeviceCert chaining to the owner key
  revoked    global truth: the owner has revoked it
  sub        subscribed to the fleet channel (it holds fleet_rv)
  online     reachable right now
  ros        which owner roster generation it HOLDS (-1 = none yet)
  known      peers it has admitted as SIBLINGS (its live mesh view)

Global: `rosters`, the owner-signed roster generations minted so far. The owner
mints a new generation on every membership change (an enrolment or a
revocation); each generation lists the enrolled, non-revoked devices.

STATE <-> CODE MAPPING
----------------------
  enroll          identity-auth-key-enroll-ack carrying fleet_rv   (recv/enrollment.rs)
  subscribe       the daemon subscribes channel_of(fleet_rv)        (recv/dispatch.rs)
  mint            owner roster on a membership change               (recv/roster.rs mint_roster)
  push_roster     roster pushed over the owner<->device PAIR link,  (conn.rs roster_maintenance)
                  accepted (monotonic), then the revocation sweep
                  closes every sibling link the new roster drops     (dispatch.rs roster arm +
                                                                     revocation::sibling_link_must_close)
  discover        fleet-hello verified: cert chains to the owner
                  key (verify_hello), not revoked, AND listed in the
                  roster held (DeviceStore::sibling_admissible)
  revoke          `demote --to cut` on the owner

The owner's own admissions are decided by its local records (it is paired with
every device), so the roster rule applies to joined devices only, exactly as
`sibling_admissible` returns true on the owner.

The fleet_rv is never rotated. An earlier version of this model proved a design
that rotated it on revocation; the implementation never did, and rotation only
ever concerned VIEW (a revoked device watching presence), never admission. This
model checks what the code does.

WHAT IS PROVEN
--------------
Safety, in every reachable state:
  S1  no admission without a cert: b in known[a] implies enrolled[b]
  S2  roster-bound: for a joined device a, b in known[a] implies a holds a
      roster and that roster lists b. With S5 this is the revocation rule: once
      a holds any roster minted after b's revocation, b is not in known[a].
  S3  fail closed: a joined device holding no roster has admitted no one
  S4  the owner never admits a device it has revoked

Tier 2 adds an INTRUDER: a device with no owner-signed cert parked on the fleet
channel. Without it S1 is vacuous (only enrolled devices ever subscribe).

Liveness, by backward reachability from the goal: EVERY reachable state can
still reach full convergence, where every live (enrolled, non-revoked) device is
online, holds the newest roster, mutually knows every other live device, and
knows no revoked one. "No reachable state is a trap."

MUTATION CONTROLS
-----------------
A checker that cannot fail proves nothing, so `main` also runs each mutant below
and REQUIRES it to fail:
  no-cert      discover skips the certificate check     -> S1 (intruder tier)
  no-roster    discover skips the roster listing         -> S2
  no-sweep     a new roster is stored but links are kept  -> S2
  open-no-ros  a device with no roster admits anyone     -> S3

THE RESIDUAL THIS MAKES EXPLICIT
--------------------------------
Between `revoke` and `push_roster` reaching a device, that device still holds
the revoked sibling. That is propagation latency (one roster push, every 5 s on
a live owner link), and the model proves it closes; it does not pretend the
window is zero. A device the owner cannot reach keeps its stale roster until it
can, which is the same boundary every pushed revocation has.
"""

import sys
from itertools import product

OWNER = 0


def pack(devs, rosters):
    return (rosters, tuple(devs))


def unpack(state):
    rosters, devs = state
    return [list(d) for d in devs], rosters


# device tuple: (enrolled, revoked, sub, online, ros, known)
E, R, SUB, ON, ROS, K = range(6)


def live_set(devs, n):
    return frozenset(i for i in range(n) if devs[i][E] and not devs[i][R])


def initial(n, with_intruder=False):
    devs = [[True, False, False, True, -1, frozenset()]]
    for _ in range(1, n):
        devs.append([False, False, False, True, -1, frozenset()])
    if with_intruder:
        devs.append([False, False, True, True, -1, frozenset()])
    # Generation 0: the owner alone.
    return pack([tuple(d) for d in devs], (frozenset({OWNER}),))


def successors(state, n, max_rev, allow_offline, total, mutant=None):
    devs, rosters = unpack(state)
    out = []

    def emit(label, d2, r2):
        out.append((label, pack([tuple(x) for x in d2], r2)))

    def copy():
        return [list(x) for x in devs]

    revoked_count = sum(1 for i in range(n) if devs[i][R])

    if devs[OWNER][ON] and not devs[OWNER][SUB]:
        d2 = copy()
        d2[OWNER][SUB] = True
        emit("subscribe(0)", d2, rosters)

    for i in range(1, n):
        d = devs[i]
        # enroll: owner certifies i (pair link + fleet_rv) and mints a roster.
        if not d[E] and d[ON]:
            d2 = copy()
            d2[i][E] = True
            emit(f"enroll({i})", d2, rosters + (live_set(d2, n),))
        # subscribe to the fleet channel.
        if d[E] and d[ON] and not d[SUB]:
            d2 = copy()
            d2[i][SUB] = True
            emit(f"subscribe({i})", d2, rosters)
        # push_roster over the pair link with the owner; then the sweep.
        latest = len(rosters) - 1
        if d[E] and not d[R] and d[ON] and d[ROS] < latest:
            d2 = copy()
            d2[i][ROS] = latest
            if mutant != "no-sweep":
                d2[i][K] = frozenset(b for b in d[K] if b in rosters[latest])
            emit(f"push_roster({i})", d2, rosters)
        # revoke on the owner: owner drops it, new roster generation.
        if d[E] and not d[R] and revoked_count < max_rev:
            d2 = copy()
            d2[i][R] = True
            d2[OWNER][K] = d2[OWNER][K] - {i}
            emit(f"revoke({i})", d2, rosters + (live_set(d2, n),))
        if allow_offline:
            d2 = copy()
            d2[i][ON] = not d[ON]
            emit(f"{'offline' if d[ON] else 'online'}({i})", d2, rosters)

    # discover: a admits b over the fleet channel (fleet-hello verified).
    for a, b in product(range(total), repeat=2):
        if a == b:
            continue
        da, db = devs[a], devs[b]
        if not (da[ON] and db[ON] and da[SUB] and db[SUB]):
            continue
        if b in da[K]:
            continue
        if mutant != "no-cert" and not db[E]:
            continue                      # no cert chaining to the owner key
        if a >= n:
            continue                      # the intruder's own view is irrelevant
        if a == OWNER:
            if db[R] or (mutant != "no-cert" and not db[E]):
                continue                  # owner: its local records decide
        else:
            if da[R] or not da[E]:
                continue                  # a revoked device's view is not modelled
            if da[ROS] == -1:
                if mutant != "open-no-ros":
                    continue              # fail closed: no roster, no sibling
            elif mutant != "no-roster" and b not in rosters[da[ROS]]:
                continue                  # the owner's roster must list b
        d2 = copy()
        d2[a][K] = da[K] | {b}
        emit(f"discover({a},{b})", d2, rosters)
    return out


def check_safety(state, n, total):
    devs, rosters = unpack(state)
    for a in range(n):
        d = devs[a]
        for b in d[K]:
            if not devs[b][E]:
                return f"S1 violated: {a} admitted uncertified {b}"
        if a == OWNER:
            for b in d[K]:
                if devs[b][R]:
                    return f"S4 violated: owner admitted revoked {b}"
            continue
        if d[R]:
            continue
        if d[ROS] == -1 and d[K]:
            return f"S3 violated: {a} admitted {set(d[K])} holding no roster"
        if d[ROS] != -1:
            for b in d[K]:
                if b not in rosters[d[ROS]]:
                    return f"S2 violated: {a} keeps {b}, which its roster no longer lists"
    return None


def is_goal(state, n):
    devs, rosters = unpack(state)
    latest = len(rosters) - 1
    if any(not devs[i][E] for i in range(n)):
        return False                      # every device has been enrolled
    live = [i for i in range(n) if devs[i][E] and not devs[i][R]]
    for i in live:
        d = devs[i]
        if not d[ON] or not d[SUB]:
            return False
        if i != OWNER and d[ROS] != latest:
            return False
        for j in live:
            if i != j and j not in d[K]:
                return False
        for j in d[K]:
            if devs[j][R]:
                return False
    return True


def explore(n, max_rev, allow_offline, with_intruder=False, mutant=None, cap=4_000_000):
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
        succ = successors(s, n, max_rev, allow_offline, total, mutant)
        edges[s] = [t for _, t in succ]
        for _, t in succ:
            if t not in seen:
                if len(seen) >= cap:
                    return None, None, f"state cap {cap} exceeded"
                seen.add(t)
                stack.append(t)
    return seen, edges, None


def backward_can_reach_goal(seen, edges, n):
    rev = {s: [] for s in seen}
    for s, ts in edges.items():
        for t in ts:
            rev[t].append(s)
    good = {s for s in seen if is_goal(s, n)}
    work = list(good)
    while work:
        s = work.pop()
        for p in rev[s]:
            if p not in good:
                good.add(p)
                work.append(p)
    return good


def run(label, n, max_rev, allow_offline, with_intruder=False, mutant=None, quiet=False):
    seen, edges, err = explore(n, max_rev, allow_offline, with_intruder, mutant)
    if err:
        if not quiet:
            print(f"  {label:<30} FAILED: {err}")
        return False, err
    good = backward_can_reach_goal(seen, edges, n)
    traps = seen - good
    if not good or traps:
        msg = "goal unreachable" if not good else f"{len(traps)} trap state(s)"
        if not quiet:
            print(f"  {label:<30} FAILED: {msg}")
        return False, msg
    if not quiet:
        print(f"  {label:<30} PROVEN  ({len(seen)} states, 0 unsafe, 0 traps)")
    return True, None


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    print("Fleet auto-mesh model check (docs/design-fleet-automesh.md)")
    ok = True

    if only in (None, "0"):
        print("\nTier 0 GoodNet: all devices online, no revocation.")
        for n in (2, 3, 4):
            ok &= run(f"GoodNet N={n}", n, 0, False)[0]

    if only in (None, "2"):
        print("\nTier 2 Intruder: an uncertified device parks on the fleet channel.")
        for n in (2, 3):
            ok &= run(f"Intruder N={n}", n, 0, False, with_intruder=True)[0]
        ok &= run("Intruder N=3 K=1 churn", 3, 1, True, with_intruder=True)[0]

    if only in (None, "1"):
        print("\nTier 1 Degraded: revocation on the owner, roster-push lag,")
        print("  offline/online churn.")
        ok &= run("Degraded N=2 K=1", 2, 1, True)[0]
        ok &= run("Degraded N=3 K=1", 3, 1, True)[0]
        ok &= run("Degraded N=3 K=2", 3, 2, True)[0]

    if only in (None, "m"):
        print("\nMutation controls: each mutant MUST fail, or the tier proves nothing.")
        cases = [
            ("no-cert", dict(n=2, max_rev=0, allow_offline=False, with_intruder=True), "S1"),
            ("no-roster", dict(n=3, max_rev=1, allow_offline=True), "S2"),
            ("no-sweep", dict(n=3, max_rev=1, allow_offline=True), "S2"),
            ("open-no-ros", dict(n=3, max_rev=0, allow_offline=False), "S3"),
        ]
        for mutant, kw, expect in cases:
            passed, err = run(f"mutant {mutant}", mutant=mutant, quiet=True, **kw)
            caught = (not passed) and err is not None and expect in err
            print(f"  mutant {mutant:<22} {'CAUGHT' if caught else 'NOT CAUGHT'} (expects {expect})")
            ok &= caught

    print("\n" + ("ALL PROVEN" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
