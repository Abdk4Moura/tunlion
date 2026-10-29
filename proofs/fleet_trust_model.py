#!/usr/bin/env python3
"""Exhaustive model check for fleet trust: owner-signed grant sets.

Mechanism: docs/design-fleet-automesh.md ("0.9.2 fleet trust"). Code:
filament-id FleetGrantSet (signature), filament_cap::fleet_grants
(judge_grant_set, grant_set_allows, fleet_sibling_inputs), DeviceStore
mint_fleet_grant_set / verify_and_store_fleet_grants / fleet_grant_held.

WHAT IS MODELLED
----------------
One owner O, one target device T, one subject sibling S, one capability.
A discrete clock `now` (0..MAX_T). A set minted at time t is valid until
t + TTL.

Owner actions (only while online, except `revoke_subject` and toggles, which
are local edits the owner can always make):
  grant / ungrant      change the authored grant; the next mint bumps the epoch
  revoke_subject       S is revoked on the owner; the next mint omits S, and
                       the roster stops listing S (PR #609)
  mint_push            sign the current set (fresh valid_until) and put it on
                       the network; the network keeps EVERY set ever minted
  offline / online

The network is hostile. At any time it may deliver to T:
  - any set ever minted (replay, reordering, delay)
  - a FORGED set (claims the owner key, signature does not verify)
  - an honestly signed set from a compromised sibling's OWN key
  - a genuine owner set about ANOTHER target
T judges each with judge_grant_set and, on Accept, replaces what it holds.

T also learns of S's revocation through the roster while the owner is
online (`roster_push`), and its operator may set or clear a local deny.

The gate on T allows S iff: no local deny, S not known-revoked, the held set
(re-checked at use) lists the grant and is still within valid_until, and T's
local `fleet.owner_grants` knob (off | files | all, read at USE) lets an owner
grant of that capability apply. The modelled capability is a parameter: CAP is
"file" (transfer or mount) or "shell"; every check runs for both.

The knob is T's local state. Only T's own operator changes it (`set_knob`, to
any value at any time, including narrowing while a set is held). The hostile
network additionally tries to set it: a ("knob", v) message for every v, which
T must ignore. Under `off`, T refuses every set and keeps nothing.

WHAT IS PROVEN (every reachable state)
--------------------------------------
  P1  T never holds a forged, foreign-owner or other-target set
  P2  T never accepts a set already expired, and never allows on an expired one
  P3  the held epoch never decreases (checked on every transition)
  P4  a local deny always refuses
  P5  once T knows S is revoked, S is refused
  P6  every allow is backed by a genuine owner set that granted it, and once T
      holds a set minted after the owner withdrew the grant, no replay of an
      older set can bring the allow back

  P7  the knob changes only by T's local action, whatever the network sends
  P8  an allow happens only when the knob CURRENTLY lets an owner grant of CAP
      apply: shell is never allowed unless the knob is `all`, nothing at all
      under `off` (so narrowing applies at once to a set already held)
  P9  under `off`, T accepts no set

Liveness: no reachable state is a trap: from every state, with the owner
online, T can come to hold the owner's current set (bounded by MAX_T).

MUTATION CONTROLS (each MUST fail):
  no-sig       accept a set whose signature does not verify      -> P1
  no-target    accept a set about another device                  -> P1
  no-monotone  accept an older epoch                              -> P6
  no-expiry    accept an expired set                              -> P2
  stale-use    allow on a held set past its valid_until           -> P2
  deny-last    let a grant outrank a local deny                   -> P4
  net-knob     apply a knob value received over the network       -> P7
  files-shell  let `files` apply an owner shell grant (CAP=shell)  -> P8
  accept-only  filter by the knob at accept time only, not at use  -> P8
  off-keeps    keep (accept) a set while the knob is `off`         -> P9
"""

import sys

CAP = "shell"  # set per run by main(): "file" or "shell"
KNOBS = ("off", "files", "all")

TTL = 2
MAX_T = 4
MAX_EPOCH = 3

# A minted set: (epoch, valid_until, grants_S: bool)
# Delivered kinds: ("real", set) | ("forged",) | ("foreign",) | ("other_target",)


def initial():
    # owner: online, authored grant, S revoked, current epoch, last content
    owner = (True, False, False, 0, None)
    # T: held set (or None), knows S revoked, local deny, fleet.owner_grants
    t = (None, False, False, "files")
    return (0, owner, frozenset(), t)


def applies(knob, mutant):
    """OwnerGrantPolicy::applies for the modelled CAP."""
    if knob == "off":
        return False
    if knob == "files":
        return CAP == "file" or mutant == "files-shell"
    return True


def accept(held, kind, s, now, mutant, knob="files"):
    """judge_grant_set_under; returns the new held value or the old one."""
    if knob == "off" and mutant != "off-keeps":
        return held
    if mutant == "accept-only" and s is not None and s[2] and not applies(knob, mutant):
        # The mutant filters only here: a set carrying CAP is refused when the
        # knob does not allow it, and nothing is checked at use.
        return held
    if kind == "forged" and mutant != "no-sig":
        return held
    if kind == "foreign":
        return held
    if kind == "other_target" and mutant != "no-target":
        return held
    if kind in ("forged", "other_target"):
        return ("BAD", 0, MAX_T + TTL, True)
    epoch, until, grants = s
    if until <= now and mutant != "no-expiry":
        return held
    if held is not None and held[0] != "BAD" and mutant != "no-monotone":
        he, hu = held[0], held[1]
        if not (epoch > he or (epoch == he and until > hu)):
            return held
    return s


def allows(t, now, mutant):
    held, knows_rev, deny, knob = t
    if mutant != "accept-only" and not applies(knob, mutant):
        return False
    if deny and mutant != "deny-last":
        return False
    if knows_rev:
        return False
    if held is None:
        return False
    if held[0] == "BAD":
        return held[3]
    _, until, grants = held
    if until <= now and mutant != "stale-use":
        return False
    return grants


def successors(state, mutant):
    now, owner, net, t = state
    online, authored, revoked, epoch, last = owner
    held, knows_rev, deny, knob = t
    out = []
    if now < MAX_T:
        out.append(("tick", (now + 1, owner, net, t)))
    out.append(("toggle_online", (now, (not online, authored, revoked, epoch, last), net, t)))
    if not revoked:
        out.append(("grant" if not authored else "ungrant",
                    (now, (online, not authored, revoked, epoch, last), net, t)))
        out.append(("revoke_subject", (now, (online, authored, True, epoch, last), net, t)))
    if online:
        content = authored and not revoked
        new_epoch = epoch if (last == content and epoch > 0) else epoch + 1
        if new_epoch <= MAX_EPOCH:
            s = (new_epoch, now + TTL, content)
            out.append(("mint_push", (now, (online, authored, revoked, new_epoch, content), net | {s}, t)))
        if revoked and not knows_rev:
            out.append(("roster_push", (now, owner, net, (held, True, deny, knob))))
    out.append(("toggle_deny", (now, owner, net, (held, knows_rev, not deny, knob))))
    # T's own operator: `tunlion set fleet.owner_grants <v>`, any time.
    for k in KNOBS:
        if k != knob:
            out.append(("set_knob", (now, owner, net, (held, knows_rev, deny, k))))
    for s in net:
        nh = accept(held, "real", s, now, mutant, knob)
        if nh != held:
            out.append((f"deliver{s}", (now, owner, net, (nh, knows_rev, deny, knob))))
    for kind in ("forged", "foreign", "other_target"):
        nh = accept(held, kind, None, now, mutant, knob)
        if nh != held:
            out.append((f"deliver_{kind}", (now, owner, net, (nh, knows_rev, deny, knob))))
    # The hostile network tries to set the knob. T ignores it; the mutant obeys.
    for k in KNOBS:
        if k != knob and mutant == "net-knob":
            out.append(("deliver_knob", (now, owner, net, (held, knows_rev, deny, k))))
    return out


def check(state, prev, mutant, label=None):
    now, owner, net, t = state
    online, authored, revoked, epoch, last = owner
    held, knows_rev, deny, knob = t
    if prev is not None and knob != prev[3][3] and label != "set_knob":
        return "P7 violated: the knob changed by something other than a local action"
    if held is not None and held[0] == "BAD":
        return "P1 violated: T holds a forged or misdirected set"
    if held is not None and held not in net:
        return "P1 violated: T holds a set the owner never minted"
    if allows(t, now, mutant):
        if held is None or held[1] <= now:
            return "P2 violated: allowed on an expired set"
        if deny:
            return "P4 violated: allowed despite a local deny"
        if knows_rev:
            return "P5 violated: allowed a known-revoked subject"
        if not held[2]:
            return "P6 violated: allowed without a granting set"
        # No set T could hold that is newer withdraws it.
        withdrawn_after = any(s[0] > held[0] and not s[2] for s in net if s[1] > now)
        if withdrawn_after and prev is not None and prev[3][0] is not None and prev[3][0] != "BAD" \
                and prev[3][0][0] > held[0]:
            return "P6 violated: an older set displaced a newer withdrawal"
    if prev is not None and held is not None and held != prev[3][0] and held[0] != "BAD" \
            and held[1] <= now:
        return "P2 violated: accepted a set already past its valid_until"
    if prev is not None:
        ph = prev[3][0]
        if ph is not None and ph != "BAD" and held is not None and held[0] != "BAD" and held[0] < ph[0]:
            return "P6 violated: the held epoch went backwards (replay won)"
    if allows(t, now, mutant):
        if knob == "off":
            return "P8 violated: allowed an owner grant under off"
        if CAP == "shell" and knob != "all":
            return "P8 violated: allowed an owner shell grant while the knob is not all"
    if prev is not None and prev[3][3] == "off" and knob == "off" and held != prev[3][0]:
        return "P9 violated: accepted a set while the knob is off"
    return None


def explore(mutant=None, cap=4_000_000):
    """DFS over every reachable state. States are numbered and edges kept as
    index lists (not state tuples), so the knob's extra dimension fits in
    modest memory."""
    start = initial()
    index = {start: 0}
    states = [start]
    edges = []
    stack = [0]
    while stack:
        i = stack.pop()
        s = states[i]
        succ = successors(s, mutant)
        out = []
        for label, t in succ:
            v = check(t, s, mutant, label)
            if v:
                return None, None, v
            j = index.get(t)
            if j is None:
                if len(states) >= cap:
                    return None, None, "state cap exceeded"
                j = len(states)
                index[t] = j
                states.append(t)
                stack.append(j)
            out.append(j)
        while len(edges) <= i:
            edges.append(None)
        edges[i] = out
    return states, edges, None


def is_goal(state):
    now, owner, net, t = state
    online, authored, revoked, epoch, last = owner
    if epoch == 0:
        return False
    current = max((s for s in net if s[0] == epoch), key=lambda s: s[1], default=None)
    return online and current is not None and t[0] == current


def no_traps(states, edges):
    n = len(states)
    rev = [[] for _ in range(n)]
    for i, ts in enumerate(edges):
        for j in ts or ():
            rev[j].append(i)
    good = bytearray(n)
    work = [i for i in range(n) if is_goal(states[i])]
    for i in work:
        good[i] = 1
    while work:
        i = work.pop()
        for p in rev[i]:
            if not good[p]:
                good[p] = 1
                work.append(p)
    # A state at the clock bound with the owner's current set already expired
    # cannot mint again (time is bounded), so only states with time left count.
    return [states[i] for i in range(n)
            if not good[i] and states[i][0] < MAX_T and states[i][1][3] < MAX_EPOCH]


def main():
    global CAP
    print("Fleet trust model check (owner-signed grant sets, fleet.owner_grants)")
    ok = True
    for cap in ("file", "shell"):
        CAP = cap
        seen, edges, err = explore()
        if err:
            print(f"  baseline CAP={cap} FAILED: {err}")
            ok = False
            continue
        traps = no_traps(seen, edges)
        if traps:
            print(f"  baseline CAP={cap} FAILED: {len(traps)} trap state(s), e.g. {traps[0]}")
            ok = False
        else:
            print(f"  baseline CAP={cap} PROVEN ({len(seen)} states, P1-P9 hold, 0 traps)")
    print("\nMutation controls: each mutant MUST fail.")
    for m, expect, cap in [("no-sig", "P1", "shell"), ("no-target", "P1", "shell"),
                           ("no-monotone", "P6", "shell"), ("no-expiry", "P2", "shell"),
                           ("stale-use", "P2", "shell"), ("deny-last", "P4", "shell"),
                           ("net-knob", "P7", "shell"), ("files-shell", "P8", "shell"),
                           ("accept-only", "P8", "shell"), ("accept-only", "P8", "file"),
                           ("off-keeps", "P9", "file")]:
        CAP = cap
        _, _, err = explore(m)
        caught = err is not None and err.startswith(expect)
        print(f"  mutant {m:<12} CAP={cap:<5} {'CAUGHT' if caught else 'NOT CAUGHT'} (expects {expect}; got {err})")
        ok &= caught
    print("\n" + ("ALL PROVEN" if ok else "FAILURES ABOVE"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
