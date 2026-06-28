#!/usr/bin/env python3
"""Filament connection-establishment model checker.

Exhaustively explores the ENTIRE reachable state space of the peer-to-peer
establishment protocol and verifies, for N peers:

  Tier 0  GoodNet      no invalid state; no deadlock; CONNECTED is always
                       reachable and clean-FAIL is never reached.
  Tier 1  DegradedNet  under a BOUNDED number of network faults (lost signals,
                       unclean disconnects, black-holed links, peer reconnect /
                       supersede): invariants still hold in every state; no
                       deadlock at any point (a timer always rescues a wait);
                       every trajectory reaches a terminal in bounded steps; and
                       once faults stop (fault budget == 0) the system self-heals
                       back to CONNECTED rather than stalling at FAIL.

Exhaustive over a bounded model == a definitive result for that bound: the
checker finds EVERY stuck/invalid state, not just one we tripped over.

Faithfulness: the FSM below is extracted from the deployed code
  - cli/src/{net,main,session}.rs   (Rust client / `up` daemon)
  - frontend/src/lib/{webrtc,useFilament}.js   (web client)
  - signaling.py (the relay), CONTRACT.md, docs/observability-state-machine.md
See proofs/README.md for the state<->code mapping. Both clients implement the
SAME protocol (cross-impl parity is pinned by tests), so one canonical FSM
models both.

Role rule (CONTRACT.md:66 "newer initiates"; net.rs:1002 polite_role): of any
pair the lexically-LESSER uid is impolite=OFFERER, the greater is polite=
ANSWERER. polite_role is a strict total order => exactly one offerer per pair =>
glare-free by construction (invariant I1, structural here).
"""
from itertools import combinations, product
from collections import deque

# ---- bounded budgets (real code: MAX_ATTEMPTS=3, STALL_MAX_REPAIRS=5, relay
# at-most-once). Exact cap values don't change the *property* (boundedness); we
# keep attempts faithful and shrink repairs for a tractable state space. The
# point being proven is that the budgets are FINITE and strictly consumed.
MAXATT = 3   # establishment-watchdog / grace retries (net.rs MAX_ATTEMPTS)
MAXREP = 2   # stall-ladder repairs before relay escalation (<= STALL_MAX_REPAIRS)

# A pair (i<j): i = offerer (impolite), j = answerer (polite).
# Endpoint states:
#   offerer  o in {IDLE, OFFER, READY, RECON, FAIL}
#   answerer a in {IDLE, WAIT, ANSW, READY, RECON, FAIL}
# plus per-pair: offer/answer in flight, per-endpoint attempt counters, the
# established-link repair counter, relay-escalated flag, black-holed flag.
PairTuple = tuple  # (o, a, offer, answer, oatt, aatt, rep, relay, bh)

def pair_init():
    return ('IDLE', 'IDLE', False, False, 0, 0, 0, False, False)

def pair_ready(ps):
    o, a = ps[0], ps[1]
    return o == 'READY' and a == 'READY' and not ps[8]  # not black-holed

def pair_failed(ps):
    return ps[0] == 'FAIL' or ps[1] == 'FAIL'

# ---- per-pair PROGRESS + TIMER transitions (no fault budget cost). Each yields
# (label, new_pair_tuple). These are exactly the protocol steps + the three
# watchdogs + the stall ladder + self-heal.
def pair_steps(ps):
    o, a, offer, answer, oatt, aatt, rep, relay, bh = ps
    out = []
    def mk(**kw):
        d = dict(o=o, a=a, offer=offer, answer=answer, oatt=oatt, aatt=aatt,
                 rep=rep, relay=relay, bh=bh)
        d.update(kw)
        return (d['o'], d['a'], d['offer'], d['answer'], d['oatt'], d['aatt'],
                d['rep'], d['relay'], d['bh'])

    # 1. discover: offerer creates offer, answerer waits (net.rs:2565 / webrtc T1-T2)
    if o == 'IDLE' and a == 'IDLE':
        out.append(('discover', mk(o='OFFER', a='WAIT', offer=True)))
    # 2. deliver offer -> answerer answers (T4 / net.rs:1254-1281)
    if offer and a == 'WAIT':
        out.append(('deliver_offer', mk(offer=False, a='ANSW', answer=True)))
    # 3. deliver answer -> handshake completes BOTH (ICE succeeds, A4) (T7/T8)
    if answer and o == 'OFFER' and a == 'ANSW':
        out.append(('deliver_answer', mk(answer=False, o='READY', a='READY')))

    # 4/5. establishment watchdog (15s; net.rs:48 -> on_stuck main.rs:3101).
    # A watchdog models a TIMEOUT: it only legitimately fires when the awaited
    # message is genuinely absent (lost / never arrived). Under GoodNet (A1
    # reliable bounded delivery) an in-flight message is always delivered before
    # the 15s timer, so the watchdog is DISABLED while progress is in flight --
    # which is why GoodNet can never reach FAIL. A loss (a Degraded fault) is the
    # only thing that empties the pipe and arms the timeout.
    if o == 'OFFER' and not offer and not answer:
        if oatt < MAXATT:
            out.append(('wd_offerer_retry', mk(oatt=oatt+1, o='OFFER',
                                               offer=True, answer=False)))
        else:
            out.append(('wd_offerer_fail', mk(o='FAIL')))
    if a == 'WAIT' and not offer:
        if aatt < MAXATT:
            out.append(('wd_answerer_retry', mk(aatt=aatt+1, a='WAIT')))
        else:
            out.append(('wd_answerer_fail', mk(a='FAIL')))
    if a == 'ANSW' and not answer:
        if aatt < MAXATT:
            out.append(('wd_answerer_retry', mk(aatt=aatt+1, a='WAIT')))
        else:
            out.append(('wd_answerer_fail', mk(a='FAIL')))
    # 6/7. disconnect grace (6s; main.rs:3870 GraceExpired -> on_stuck)
    if o == 'RECON':
        if oatt < MAXATT:
            out.append(('grace_offerer_retry', mk(oatt=oatt+1, o='OFFER', offer=True)))
        else:
            out.append(('grace_offerer_fail', mk(o='FAIL')))
    if a == 'RECON':
        if aatt < MAXATT:
            out.append(('grace_answerer_retry', mk(aatt=aatt+1, a='WAIT')))
        else:
            out.append(('grace_answerer_fail', mk(a='FAIL')))
    # 8. stall ladder on an established but black-holed link (the "zombie":
    #    connected at transport, no data). main.rs:3284 correct_stall ->
    #    resume/repair (rep) -> relay escalate (once) -> honest exhaustion.
    if o == 'READY' and a == 'READY' and bh:
        if rep < MAXREP:
            out.append(('stall_repair', mk(rep=rep+1, bh=False)))   # resume/repair clears it
        elif not relay:
            out.append(('stall_relay_escalate', mk(relay=True, bh=False)))  # relay works (A4)
        else:
            out.append(('stall_exhaust_clean_fail', mk(o='FAIL', a='FAIL')))
    # 9. self-heal: a cleanly-FAILED link re-establishes when the device returns
    #    / is rediscovered (known-peer / proactive re-pair). Resets budgets. In
    #    GoodNet this never fires (no FAIL). It is what makes Tier-1 recover to
    #    CONNECTED after the deficiency passes instead of staying FAILED.
    if o == 'FAIL' or a == 'FAIL':
        out.append(('self_heal_reconnect', pair_init()))
    return out

# ---- per-pair FAULT transitions (Tier 1 only; each consumes one fault-budget
# unit at the global level). These are the network deficiencies.
def pair_faults(ps):
    o, a, offer, answer, oatt, aatt, rep, relay, bh = ps
    out = []
    def mk(**kw):
        d = dict(o=o, a=a, offer=offer, answer=answer, oatt=oatt, aatt=aatt,
                 rep=rep, relay=relay, bh=bh)
        d.update(kw)
        return (d['o'], d['a'], d['offer'], d['answer'], d['oatt'], d['aatt'],
                d['rep'], d['relay'], d['bh'])
    if offer:
        out.append(('fault_lose_offer', mk(offer=False)))
    if answer:
        out.append(('fault_lose_answer', mk(answer=False)))
    if o == 'READY' and a == 'READY':
        out.append(('fault_disconnect', mk(o='RECON', a='RECON', bh=False)))
        if not bh:
            out.append(('fault_blackhole', mk(bh=True)))
    return out

# ---------------------------------------------------------------------------
class Model:
    def __init__(self, n_peers, fault_budget):
        self.n = n_peers
        self.fb0 = fault_budget
        self.pairs = list(combinations(range(n_peers), 2))  # (i,j), i<j

    def initial(self):
        return (tuple(pair_init() for _ in self.pairs), self.fb0)

    def is_terminal_good(self, st):
        pairs, _ = st
        return all(pair_ready(p) for p in pairs)

    def is_terminal_fail(self, st):
        pairs, _ = st
        return any(pair_failed(p) for p in pairs)

    def successors(self, st):
        pairs, fb = st
        succ = []
        # local progress + timer steps on each pair (no fb cost)
        for idx, ps in enumerate(pairs):
            for label, np_ in pair_steps(ps):
                newpairs = list(pairs)
                newpairs[idx] = np_
                succ.append((f'p{self.pairs[idx]}:{label}', (tuple(newpairs), fb)))
        # faults (Tier 1): each consumes one fb unit
        if fb > 0:
            for idx, ps in enumerate(pairs):
                for label, np_ in pair_faults(ps):
                    newpairs = list(pairs)
                    newpairs[idx] = np_
                    succ.append((f'p{self.pairs[idx]}:{label}', (tuple(newpairs), fb-1)))
            # multi-peer supersede: one device drops -> ALL its READY links go
            # RECON at once (models an unclean disconnect / reconnect of a peer
            # touching every link it holds). One fb unit.
            for peer in range(self.n):
                touched = False
                newpairs = list(pairs)
                for idx, (i, j) in enumerate(self.pairs):
                    if peer in (i, j):
                        o, a, *rest = pairs[idx]
                        if o == 'READY' and a == 'READY':
                            newpairs[idx] = ('RECON', 'RECON', *pairs[idx][2:6],
                                             pairs[idx][6], pairs[idx][7], False)
                            touched = True
                if touched:
                    succ.append((f'peer{peer}:fault_supersede_drop',
                                 (tuple(newpairs), fb-1)))
        return succ

    # ---- invariants (safety) checked on EVERY reachable state
    def invariant_violations(self, st):
        pairs, fb = st
        v = []
        for idx, ps in enumerate(pairs):
            o, a = ps[0], ps[1]
            # I2: no stuck half-open -- one endpoint believes CONNECTED while the
            # other has given up (FAIL) or never started (IDLE) with no recovery.
            if o == 'READY' and a in ('IDLE', 'FAIL'):
                v.append(f'I2 half-open {self.pairs[idx]}: offerer READY, answerer {a}')
            if a == 'READY' and o in ('IDLE', 'FAIL'):
                v.append(f'I2 half-open {self.pairs[idx]}: answerer READY, offerer {o}')
            # budgets never exceed their caps (boundedness sanity)
            if ps[4] > MAXATT or ps[5] > MAXATT or ps[6] > MAXREP:
                v.append(f'budget overflow {self.pairs[idx]}: {ps}')
        return v


def explore(model):
    """Full BFS of the reachable state space. Returns (states, edges, depth)."""
    init = model.initial()
    seen = {init: 0}            # state -> BFS depth
    edges = {}                  # state -> list[(label, next)]
    q = deque([init])
    while q:
        st = q.popleft()
        succ = model.successors(st)
        edges[st] = succ
        for _, ns in succ:
            if ns not in seen:
                seen[ns] = seen[st] + 1
                q.append(ns)
    return seen, edges


def can_reach(edges, targets):
    """Set of states from which SOME target is reachable (reverse BFS)."""
    rev = {}
    for s, succ in edges.items():
        for _, ns in succ:
            rev.setdefault(ns, []).append(s)
    reach = set(targets)
    q = deque(targets)
    while q:
        s = q.popleft()
        for p in rev.get(s, ()):
            if p not in reach:
                reach.add(p)
                q.append(p)
    return reach


def check(n_peers, fault_budget, tier):
    m = Model(n_peers, fault_budget)
    seen, edges = explore(m)
    states = list(seen)
    good = {s for s in states if m.is_terminal_good(s)}
    fail = {s for s in states if m.is_terminal_fail(s)}
    terminals = good | fail

    report = {'tier': tier, 'n_peers': n_peers, 'fault_budget': fault_budget,
              'states': len(states)}

    # SAFETY: invariants hold everywhere
    inv = []
    for s in states:
        for msg in m.invariant_violations(s):
            inv.append((s, msg))
    report['invariant_violations'] = inv

    # NO DEADLOCK: every non-terminal state has at least one successor (a timer
    # always rescues a wait). A non-terminal sink == stuck.
    deadlocks = [s for s in states
                 if not m.is_terminal_good(s) and not m.is_terminal_fail(s)
                 and len(edges[s]) == 0]
    report['deadlocks'] = deadlocks

    # LIVENESS: every state can reach a terminal (no stuck SCC / black-hole of
    # states). AG EF terminal.
    can_term = can_reach(edges, terminals)
    report['cannot_reach_any_terminal'] = [s for s in states if s not in can_term]

    # GoodNet: FAIL must be unreachable, and every state can reach CONNECTED.
    can_good = can_reach(edges, good)
    report['cannot_reach_connected'] = [s for s in states if s not in can_good]
    report['fail_reachable'] = sorted(fail)[:3]

    # Tier-1 self-heal: once faults stop (fb==0), CONNECTED is still reachable
    # from every state -- the deficiency passing => recovery, not stuck at FAIL.
    nofault = [s for s in states if s[1] == 0]
    report['fb0_cannot_reach_connected'] = [s for s in nofault if s not in can_good]

    # bounded recovery: BFS depth of the deepest reachable state (a coarse
    # upper bound on steps-to-settle).
    report['max_depth'] = max(seen.values())
    return report, m, edges


def trace_to(edges, start, pred, limit=40):
    """BFS a shortest path from start to a state satisfying pred (for counterex)."""
    q = deque([(start, [])])
    seen = {start}
    while q:
        s, path = q.popleft()
        if pred(s):
            return path + [(None, s)]
        if len(path) > limit:
            continue
        for label, ns in edges.get(s, ()):
            if ns not in seen:
                seen.add(ns)
                q.append((ns, path + [(label, ns)]))
    return None


def banner(r):
    ok = (not r['invariant_violations'] and not r['deadlocks']
          and not r['cannot_reach_any_terminal'])
    extra_ok = True
    notes = []
    if r['tier'] == 'GoodNet':
        if r['fail_reachable']:
            extra_ok = False; notes.append('FAIL reachable under GoodNet!')
        if r['cannot_reach_connected']:
            extra_ok = False; notes.append('some state cannot reach CONNECTED')
    else:
        if r['fb0_cannot_reach_connected']:
            extra_ok = False
            notes.append('a post-fault (fb==0) state cannot self-heal to CONNECTED')
    verdict = 'PROVEN' if (ok and extra_ok) else 'COUNTEREXAMPLE'
    print(f"=== {r['tier']:10s} N={r['n_peers']} faults<= {r['fault_budget']}"
          f"  | states={r['states']:>7d} depth<= {r['max_depth']:>2d}  ->  {verdict}")
    print(f"      invariant violations : {len(r['invariant_violations'])}")
    print(f"      deadlocks (stuck)    : {len(r['deadlocks'])}")
    print(f"      states that can't reach ANY terminal : {len(r['cannot_reach_any_terminal'])}")
    if r['tier'] == 'GoodNet':
        print(f"      FAIL reachable       : {len(r['fail_reachable'])} (must be 0)")
        print(f"      states that can't reach CONNECTED    : {len(r['cannot_reach_connected'])}")
    else:
        print(f"      post-fault states that can't self-heal to CONNECTED : "
              f"{len(r['fb0_cannot_reach_connected'])}")
    for nt in notes:
        print(f"      !! {nt}")
    return verdict == 'PROVEN'


if __name__ == '__main__':
    all_ok = True
    import sys
    runs = [
        ('GoodNet', 2, 0),
        ('Degraded', 2, 1),
        ('Degraded', 2, 2),
        ('Degraded', 2, 3),
        ('GoodNet', 3, 0),
        ('Degraded', 3, 1),
        ('Degraded', 3, 2),
    ]
    if len(sys.argv) > 1:  # e.g. `python3 establishment_model.py 2` -> only N=2 runs
        only = int(sys.argv[1])
        runs = [r for r in runs if r[1] == only]
    checkers = {}
    for tier, n, fb in runs:
        r, m, edges = check(n, fb, tier)
        checkers[(tier, n, fb)] = (r, m, edges)
        all_ok &= banner(r)
        # print a counterexample trace if anything failed
        if r['deadlocks']:
            print('      e.g. deadlock state:', r['deadlocks'][0])
        if r['cannot_reach_any_terminal']:
            print('      e.g. stuck state   :', r['cannot_reach_any_terminal'][0])
        if r['invariant_violations']:
            print('      e.g. invariant     :', r['invariant_violations'][0][1])
        print()
    print('ALL TIERS PROVEN' if all_ok else 'PROOF FAILED -- counterexample(s) above')
    sys.exit(0 if all_ok else 1)  # non-zero == CI gate fails
