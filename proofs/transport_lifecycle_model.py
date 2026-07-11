#!/usr/bin/env python3
"""Filament transport-LIFECYCLE model checker.

The companion to `establishment_model.py`. That model proves the *signaling*
protocol (offer -> answer -> ICE -> CONNECTED) is glare-free, deadlock-free and
self-healing. This model picks up where it leaves off: a pair is already
CONNECTED and now must carry a file over a DATA-PLANE transport, confirm whole-
file delivery, and tear the transport down -- possibly reusing it for a second
transfer to the same remembered peer.

Every bug this project hit in the multi-stream push lived in THIS layer, in a
corner that neither the establishment model nor the liveness classifier
(`resilience.rs::classify`) covered:

  BUG-CORPSE   a link entry whose transport has died persists in `conn.links`;
               the re-dial that would revive it is SUPPRESSED because
               `start_direct_inner` (main.rs:3421) gates on link EXISTENCE, not
               link LIVENESS. classify() calls a transport-less in-flight link
               `Establishing` and defers to "the establishment watchdog", but
               that watchdog can't act -> the link is a corpse that blocks its
               own resurrection. Symptom: 10GB transfer "never starts",
               transport_up=false workers=0 idle=u64::MAX, "delivery not
               confirmed".

  BUG-ACKLOSS  QUIC has no flush-on-close (RFC 9000 s10.2). The receiver writes
               the delivery-ack on the now-IDLE primary, then drops the
               connection; the ack (never flushed/acked) is discarded and the
               peer's reader sees ApplicationClosed(0,""). The canonical fix
               (quinn/iroh "Closing a QUIC Connection", croc, rsync): the
               RECEIVER of the last message must WAIT; the party that READ the
               last message (here the file sender, reading the ack) is the one
               that closes -- then wait_idle so the CONNECTION_CLOSE lands.

  BUG-ROLE     both ends took the ANSWERER role (sid_answerer() true on both
               ends of a symmetric simultaneous-open), so NOBODY dialed and a
               transport never came up. Fix: net::polite_role -- a strict total
               order on uids picks exactly one dialer.

The model encodes each fix as an independent boolean and checks ALL 2^3
combinations (the "necessity matrix"), proving each fix is not just sufficient
but NECESSARY: turning any one off re-introduces a reachable invalid/stuck state.

  Tier 0  GoodNet   perfect link (DO-vm <-> DO-vm): reliable bounded delivery,
                    no SPONTANEOUS transport death. The ONLY connection deaths
                    are the ones the code inflicts on itself (BUG-ACKLOSS). With
                    all fixes on: no invalid state, no deadlock, and the clean
                    terminal (both transfers delivered + verified + cleanly
                    closed) is reachable from every state.
  Tier 1  Degraded  GoodNet minus reliability: up to K genuine mid-transfer
                    transport deaths (real NAT rebind / drop). Proves the
                    lifecycle self-heals -- but ONLY when the liveness-aware
                    re-dial (BUG-CORPSE fix) is on; teardown-correctness alone
                    cannot recover a genuinely-dropped transport.

Exhaustive over a bounded model == definitive for that bound: the checker finds
EVERY corpse / lost-ack / stuck state, not just one we tripped over.

Faithfulness -- state <-> code:
  T (transport slot)   main.rs Link.{transport,workers}; direct.rs DirectTransport
  the re-dial guard    main.rs:3421 start_direct_inner (contains_key vs liveness)
  X (sender transfer)  main.rs outgoing OutFile.{accepted_once,sent,acked,done}; P4 window
  R (receiver)         main.rs up-loop verify_incoming -> delivery_ack_msg
  ack teardown         event-36 fix: receiver waits (conn.closed()), sender closes
                       (conn.close + Endpoint::wait_idle); RFC 9000 s10.2
  role                 net::polite_role (CONTRACT.md "newer initiates")
  aggregate liveness   detect_stall min(idle) over primary+workers (multi-stream)
"""
from collections import deque, namedtuple
from itertools import product

Cfg = namedtuple('Cfg', 'role guard teardown')  # each True == the FIX is applied

# ---- transport slot: the data-plane connection for this link ----------------
# NONE    no transport (never dialed, or fully torn down and reset for reuse)
# DIALING a fresh authenticated dial is in flight (main.rs direct_pending)
# LIVE    an authenticated transport is carrying data (aggregate over the
#         primary + K worker connections -- "alive if ANY moved a byte")
# DEAD    a transport existed and died (ApplicationClosed / ConnectionLost) and
#         has NOT yet been purged+re-dialed  <-- the corpse precursor
# CLOSING graceful teardown in progress (finish + close + wait_idle)
# CLOSED  cleanly torn down
T_NONE, T_DIALING, T_LIVE, T_DEAD, T_CLOSING, T_CLOSED = \
    'NONE', 'DIALING', 'LIVE', 'DEAD', 'CLOSING', 'CLOSED'

# ---- sender transfer state (OutFile) ----------------------------------------
X_IDLE, X_OFFERED, X_STREAM, X_AWAIT, X_DELIV = \
    'IDLE', 'OFFERED', 'STREAMING', 'AWAIT_ACK', 'DELIVERED'
IN_FLIGHT = {X_OFFERED, X_STREAM, X_AWAIT}   # a transfer needing a live transport

# ---- receiver state ---------------------------------------------------------
R_IDLE, R_RECV, R_VERIFIED, R_ACKED, R_DONE = \
    'R_IDLE', 'R_RECV', 'R_VERIFIED', 'R_ACKED', 'R_DONE'

# A state: (T, X, R, ack, ep, fb, rx_gone)
#   ack     delivery-ack bytes on the wire, not yet consumed by the sender (0/1)
#   ep      which of the two back-to-back transfers we are in (1 or 2)
#   fb      remaining fault budget (Degraded tier); 0 under GoodNet
#   rx_gone the receiver tore down its OWN link and is DONE (premature_close): it
#           will not re-accept, so the sender cannot re-establish. Distinguishes a
#           SELF-INFLICTED close (unrecoverable by re-dial) from a real FAULT
#           (receiver still present -> re-dialable). This is the faithfulness fix
#           that made the model match the live 5GB result -- see can_redial_dead.
State = namedtuple('State', 'T X R ack ep fb rx_gone')


def initial(fb):
    return State(T_NONE, X_IDLE, R_IDLE, 0, 1, fb, False)


# The FINAL good terminal: BOTH transfers delivered+verified and the link cleanly
# closed. Proving THIS is reachable from everywhere is the back-to-back property
# (the "500MB works, then 10GB to the same peer fails" scenario made impossible).
def is_good_terminal(s):
    return s.ep == 2 and s.X == X_DELIV and s.R == R_DONE and s.T == T_CLOSED


def can_dial_fresh(s, cfg):
    """A brand-new dial (no link entry yet, or a cold reset for reuse). Needs a
    dialer to exist (role fix); the existence-guard never blocks a fresh dial."""
    return cfg.role


def can_redial_dead(s, cfg):
    """Re-dial a link whose transport DIED while a transfer is in flight (corpse
    recovery). The BUGGY guard blocks it (a link entry exists -> start_direct_inner
    early-returns); the liveness-aware guard allows it.

    CRITICAL faithfulness fix (confirmed against the live 5GB run, xats event 42):
    a receiver that tore down its OWN link and is DONE (premature_close, rx_gone)
    cannot be re-dialed -- there is no peer left to answer the re-offer ("peer did
    not come back within 45s"). Only a link killed by a real FAULT (receiver still
    present, rx_gone == False) is re-dialable. So `guard` CANNOT rescue a
    self-inflicted receiver-gone close; only correct `teardown` (not closing in the
    first place) can. This is why guard-alone passes GoodNet in the OLD model but
    FAILS the live premature-close case."""
    return cfg.role and cfg.guard and not s.rx_gone


def successors(s, cfg):
    out = []

    def add(label, **kw):
        out.append((label, s._replace(**kw)))

    # ===================================================== establish / re-dial
    # Initial dial from NONE (fresh link, no entry yet -> guard irrelevant).
    if s.T == T_NONE and s.X == X_IDLE and can_dial_fresh(s, cfg):
        add('dial', T=T_DIALING)
    # Cold reuse: a cleanly-closed link starting the NEXT transfer re-dials.
    if s.T == T_CLOSED and s.X == X_IDLE and can_dial_fresh(s, cfg):
        add('redial_reuse', T=T_DIALING)
    # DIALING completes (GoodNet: connectivity exists, handshake succeeds).
    if s.T == T_DIALING:
        add('transport_up', T=T_LIVE)
    # Corpse recovery: an in-flight transfer whose transport DIED (or was
    # dropped by a premature close) re-dials -- IF the guard is liveness-aware.
    if s.T in (T_DEAD, T_CLOSED) and s.X in IN_FLIGHT and can_redial_dead(s, cfg):
        add('redial_dead', T=T_DIALING)

    # ============================================================ the transfer
    if s.T == T_LIVE and s.X == X_IDLE:
        add('offer', X=X_OFFERED)
    if s.T == T_LIVE and s.X == X_OFFERED and s.R == R_IDLE:
        add('accept', X=X_STREAM, R=R_RECV)
    if s.T == T_LIVE and s.X == X_STREAM and s.R == R_RECV:
        # GoodNet: every striped byte lands and the whole-file sha256 verifies.
        add('deliver_and_verify', X=X_AWAIT, R=R_VERIFIED)

    # ================================================= delivery-ack + teardown
    # Receiver verified -> sends the delivery-ack. Under the FIXED teardown the
    # receiver then WAITS (does not close). Under the buggy teardown it will
    # race a close (see premature_close below).
    if s.R == R_VERIFIED:
        add('send_ack', R=R_ACKED, ack=1)
    # Sender reads the ack off a LIVE transport -> transfer is truly delivered.
    if s.ack == 1 and s.T == T_LIVE and s.X == X_AWAIT:
        add('ack_read', X=X_DELIV, ack=0)
    # Resume after a lost ack: the transport is LIVE again but the sender never
    # got the ack (R_ACKED, ack==0). On resume the receiver re-sends it.
    if s.T == T_LIVE and s.X == X_AWAIT and s.R == R_ACKED and s.ack == 0:
        add('resend_ack', ack=1)

    # BUG-ACKLOSS: buggy teardown = the receiver closes right after acking,
    # racing the sender's read. QUIC drops the un-flushed ack (RFC 9000 s10.2)
    # and the sender's transport observes the close as DEAD. Modeled as a
    # NORMAL transition (no fault budget): on a PERFECT link this is entirely
    # self-inflicted by the code.
    if (not cfg.teardown) and s.R == R_ACKED and s.T == T_LIVE and s.X == X_AWAIT:
        # The receiver closes right after acking. The ack is lost (ack -> 0), the
        # shared connection dies (sender's transport -> DEAD), AND the receiver is
        # DONE: it will not re-accept, so the sender cannot re-establish (rx_gone).
        # Only NOT closing (the teardown fix) avoids this -- guard cannot recover it.
        add('premature_close', T=T_DEAD, ack=0, rx_gone=True)

    # =========================================================== clean teardown
    # The party that READ the last message closes. The last message is the
    # delivery-ack, read by the SENDER; so the sender closes once X==DELIVERED.
    if s.X == X_DELIV and s.T == T_LIVE:
        add('sender_close', T=T_CLOSING)          # conn.close(0,"done")
    if s.T == T_CLOSING:
        add('wait_idle', T=T_CLOSED)              # Endpoint::wait_idle drains it
    # The receiver was WAITING (R_ACKED); the peer's clean close releases it.
    if s.R == R_ACKED and s.T in (T_CLOSING, T_CLOSED) and s.X == X_DELIV:
        add('recv_release', R=R_DONE)

    # ============================================== next transfer (warm/cold)
    # Transfer 1 done cleanly -> start transfer 2 to the SAME remembered peer.
    # This is where a corpse left by transfer 1 would strand transfer 2.
    if s.ep == 1 and s.X == X_DELIV and s.R == R_DONE and s.T == T_CLOSED:
        add('next_transfer', T=T_CLOSED, X=X_IDLE, R=R_IDLE, ack=0, ep=2)

    return out


def faults(s, cfg):
    """Degraded tier only: a GENUINE mid-transfer transport death (NAT rebind /
    real drop), each consuming one fault-budget unit. Distinct from the
    self-inflicted premature_close: this can happen on any real network and is
    exactly what the corpse-fix must be able to recover from."""
    out = []
    if s.fb > 0 and s.T == T_LIVE and s.X in IN_FLIGHT:
        out.append(('fault_transport_dies',
                    s._replace(T=T_DEAD, ack=0, fb=s.fb - 1)))
    return out


# ============================================================== safety invariants
def invariant_violations(s, cfg):
    v = []
    # I-CORPSE: an in-flight transfer sitting on a DEAD/absent transport with no
    # way to re-dial is a corpse. (Reported explicitly; the liveness check below
    # also catches it as "cannot reach terminal", but naming it localizes blame.)
    if s.X in IN_FLIGHT and s.T in (T_NONE, T_DEAD):
        if not (can_dial_fresh(s, cfg) or can_redial_dead(s, cfg)):
            v.append(f'I-CORPSE: in-flight {s.X} on transport {s.T}, no re-dial possible')
    # I-ACKLOSS: the connection is CLOSED/DEAD, the receiver had VERIFIED the
    # whole file, yet the sender never recorded delivery and cannot recover.
    if s.T in (T_DEAD, T_CLOSED) and s.R in (R_ACKED,) and s.X == X_AWAIT:
        if not can_redial_dead(s, cfg):
            v.append('I-ACKLOSS: verified receiver, connection gone, ack lost with no recovery')
    # I-HALFOPEN: sender believes DELIVERED while the receiver never verified.
    if s.X == X_DELIV and s.R in (R_IDLE, R_RECV):
        v.append('I-HALFOPEN: sender DELIVERED but receiver never verified')
    # NOTE (I-OFFER-INTO-DEAD): "an offer may only be PLACED on a LIVE transport"
    # is enforced STRUCTURALLY -- the `offer` transition guards on T==LIVE, so no
    # reachable state has an offer placed onto a dead link (the warm-reuse bug is
    # unrepresentable). It is NOT a state predicate: a Degraded fault can kill a
    # transport AFTER a live offer (X=OFFERED, T=DEAD), which is a legitimate
    # transient that corpse-recovery re-dials + re-offers, not a violation.
    return v


# ============================================================== exhaustive BFS
def explore(cfg, fb):
    init = initial(fb)
    seen = {init: 0}
    edges = {}
    q = deque([init])
    while q:
        s = q.popleft()
        succ = successors(s, cfg) + faults(s, cfg)
        edges[s] = succ
        for _, ns in succ:
            if ns not in seen:
                seen[ns] = seen[s] + 1
                q.append(ns)
    return seen, edges


def can_reach(edges, targets):
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


def trace_to(edges, start, pred, limit=60):
    q = deque([(start, [])])
    seen = {start}
    while q:
        s, path = q.popleft()
        if pred(s):
            return path + [('(here)', s)]
        if len(path) > limit:
            continue
        for label, ns in edges.get(s, ()):
            if ns not in seen:
                seen.add(ns)
                q.append((ns, path + [(label, ns)]))
    return None


def check(cfg, fb, tier):
    seen, edges = explore(cfg, fb)
    states = list(seen)
    good = {s for s in states if is_good_terminal(s)}

    inv = [(s, m) for s in states for m in invariant_violations(s, cfg)]
    deadlocks = [s for s in states
                 if not is_good_terminal(s) and len(edges[s]) == 0]
    can_good = can_reach(edges, good)
    stuck = [s for s in states if s not in can_good]     # cannot reach clean terminal

    return {
        'tier': tier, 'cfg': cfg, 'fb': fb, 'states': len(states),
        'invariant_violations': inv, 'deadlocks': deadlocks,
        'stuck': stuck, 'good_terminals': len(good),
        'max_depth': max(seen.values()), 'edges': edges,
        'init': initial(fb),
    }, edges


def is_clean(r):
    return (not r['invariant_violations'] and not r['deadlocks']
            and not r['stuck'] and r['good_terminals'] > 0)


def fix_label(cfg):
    on = [n for n, b in (('role', cfg.role), ('guard', cfg.guard),
                         ('teardown', cfg.teardown)) if b]
    return '+'.join(on) if on else '(none)'


def banner(r):
    cfg = r['cfg']
    verdict = 'PROVEN' if is_clean(r) else 'COUNTEREXAMPLE'
    print(f"  fixes[{fix_label(cfg):22s}] {r['tier']:8s} fb<={r['fb']} | "
          f"states={r['states']:>4d} depth<={r['max_depth']:>2d} -> {verdict}")
    if verdict == 'COUNTEREXAMPLE':
        if r['invariant_violations']:
            print(f"        invariant: {r['invariant_violations'][0][1]}")
        if r['stuck']:
            s = r['stuck'][0]
            print(f"        stuck (cannot reach clean terminal): {tuple(s)}")
        if r['deadlocks']:
            print(f"        deadlock: {tuple(r['deadlocks'][0])}")
    return is_clean(r)


def print_trace(r, pred, title):
    tr = trace_to(r['edges'], r['init'], pred)
    if not tr:
        return
    print(f"\n  counterexample trace -- {title}:")
    for label, s in tr:
        print(f"      {label:20s} -> T={s.T:8s} X={s.X:10s} R={s.R:10s} "
              f"ack={s.ack} ep={s.ep}")


ALLFIX = Cfg(True, True, True)


if __name__ == '__main__':
    import sys
    print("=" * 78)
    print("TRANSPORT-LIFECYCLE PROOF  (data-plane transport + delivery-ack + teardown)")
    print("=" * 78)

    ok = True

    # ---- Tier 0: GoodNet necessity matrix -- ALL 2^3 fix combinations --------
    # THEOREM (GoodNet): the lifecycle is correct  IFF  role AND teardown.
    #   role      -- someone must dial, or no transport ever comes up (BUG-ROLE).
    #   teardown  -- correct close = the receiver does NOT drop its own link, so no
    #                self-inflicted death and the ack always lands (BUG-ACKLOSS).
    # `guard` does NOT rescue GoodNet: on a perfect link the only death is the
    # self-inflicted premature_close, after which the RECEIVER is gone (rx_gone)
    # and cannot be re-dialed -- guard has no peer to reconnect to. (Confirmed
    # against the live 5GB run, xats event 42: "guard alone passes baseline, fails
    # premature-close".) guard earns its necessity only under Degraded (real
    # faults, receiver still present). The checker verifies this on all 8.
    print("\n[Tier 0: GoodNet -- perfect DO<->DO link, only self-inflicted deaths]")
    print("THEOREM: clean  <=>  role AND teardown.  Verifying all 8:")
    goodnet = {}
    for role, guard, teardown in product((True, False), repeat=3):
        cfg = Cfg(role, guard, teardown)
        r, _ = check(cfg, 0, 'GoodNet')
        goodnet[cfg] = r
        clean = banner(r)
        predicted = cfg.role and cfg.teardown
        if clean != predicted:
            print(f"        !! THEOREM VIOLATED: predicted clean={predicted}, got {clean}")
            ok = False
        if cfg == ALLFIX:
            ok &= clean                      # the CI gate: all-fixed MUST be clean

    # Necessity corollaries that MUST hold under GoodNet:
    print("\nnecessity under GoodNet:")
    role_off = not is_clean(goodnet[ALLFIX._replace(role=False)])
    # teardown necessary EVEN WITH guard on: guard cannot rescue a receiver-gone close.
    teardown_off = not is_clean(goodnet[ALLFIX._replace(teardown=False)])
    print(f"  role is necessary (drop role -> break)                 : {role_off}")
    print(f"  teardown necessary even WITH guard (guard can't rescue): {teardown_off}")
    ok &= role_off and teardown_off

    # ---- illustrative counterexample traces (the actual bugs) ----------------
    # guard ON, teardown OFF: guard STILL cannot recover -- the money shot matching
    # the live premature-close result (receiver gone -> no re-dial possible).
    print_trace(goodnet[Cfg(True, True, False)],
                lambda s: s.T == T_DEAD and s.X == X_AWAIT and s.rx_gone,
                "BUG-ACKLOSS: guard ON but receiver GONE -> unrecoverable (needs teardown)")
    print_trace(goodnet[Cfg(False, True, True)],
                lambda s: s.T == T_NONE and s.X == X_IDLE and len(successors(s, Cfg(False, True, True))) == 0,
                "BUG-ROLE (nobody dials; no transport ever comes up)")

    # ---- Tier 1: Degraded -- genuine mid-transfer transport deaths -----------
    # THEOREM (Degraded): with real drops, the corpse-recovery (guard) fix is now
    # INDEPENDENTLY necessary -- correct teardown cannot resurrect a transport the
    # network killed. All fixes on -> self-heals to the clean terminal.
    print("\n[Tier 1: Degraded -- up to K real transport deaths mid-transfer]")
    print("THEOREM: guard (liveness-aware re-dial) is now independently necessary.")
    for fb in (1, 2):
        r_ok, _ = check(ALLFIX, fb, 'Degraded')
        ok &= banner(r_ok)                   # all fixes -> must self-heal
        r_bad, _ = check(Cfg(True, False, True), fb, 'Degraded')  # guard OFF
        broke = not is_clean(r_bad)
        banner(r_bad)
        print(f"        -> guard fix {'NECESSARY (breaks without it)' if broke else 'NOT necessary?!'}")
        ok &= broke

    print("\n" + "=" * 78)
    print("ALL TRANSPORT-LIFECYCLE PROPERTIES PROVEN"
          if ok else "PROOF FAILED -- counterexample(s) above")
    print("=" * 78)
    sys.exit(0 if ok else 1)
