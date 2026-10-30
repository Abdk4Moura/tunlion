#!/usr/bin/env python3
"""Exhaustive model of a code pairing's identity-expose delivery.

After the SPAKE2 key confirmation, a side that holds a device certificate
sends it to the other in one sealed `identity-expose` frame. That frame went
out once, unacknowledged, and the receiver waited 5 s for it, so one lost
frame left a device paired but uncertified while BOTH sides said "connected".

The fix (cli/src/pair_cmd.rs, crates/filament-peerloop/src/expose.rs):

  - a side advertises `expose_ack: 1` (it acknowledges) and `exposes: true`
    (it will send a certificate) on its PAKE payloads;
  - facing a peer that acknowledges, the sender re-sends the SAME frame on the
    #597 backoff until acknowledged, and does not succeed until then;
  - the receiver acknowledges every copy it accepted (duplicates harmless),
    and when the peer said `exposes: true` it does not succeed without the
    certificate;
  - after succeeding, the receiver lingers answering re-sent copies until the
    sender leaves or no copy came for a quiet spell;
  - a peer that does not advertise `expose_ack` (0.9.1, the browser) gets the
    old behaviour: one send, a short window, never an acknowledgement.

The model: sender A holds a certificate, receiver B does not (a mutual pairing
is two independent instances of this, one per direction). Each side is new
(0.9.2) or old (0.9.1). The relay may lose up to F frames (copies or
acknowledgements) and delivers the rest in any order. A sends at most R copies
before its deadline. Timers follow the establishment model's rule: a deadline
or quiet timer fires only when what it waits for is genuinely absent (nothing
in flight that would satisfy it).

Properties, for every version mix, F in 0..R+1:
  P1 safety (new/new): no side ever reports success unless B holds A's
     certificate.
  P2 no deadlock: every non-terminal state has a successor, every path ends.
  P3 GoodNet (F=0): every ending is both OK, certificate at B.
  P4 Degraded (F < R): every ending has B OK with the certificate, and A OK
     unless a copy was lost while B was lingering (then A fails honestly:
     it cannot know the certificate landed).
  P5 mixed versions: the expose machinery never fails a pairing (the 0.9.1
     outcome), and no acknowledgement ever reaches a 0.9.1 side.

A checker that cannot fail proves nothing: each mutant below must be caught.
Exit status is non-zero on any counterexample or any uncaught mutant.
"""
import sys
from collections import deque
from itertools import product

R = 4  # copies A sends before its deadline (the real budget allows ~30)

RUN, LINGER, OK, FAIL = "RUN", "LINGER", "OK", "FAIL"

MUTANTS = {
    "send-once": "the sender never re-sends (the shipped 0.9.1 behaviour)",
    "no-wait": "the receiver completes without the certificate it was promised",
    "ack-once": "the receiver acknowledges only the first copy",
    "no-linger": "the receiver leaves the moment it succeeds",
    "ack-to-old": "acknowledgements are sent to a peer that never advertised them",
    "no-promise": "the sender completes before its promised frame went out (CI found it)",
}


def initial():
    # (a, copies, acked, b, cert, acked_any, ch_x, ch_ack, losses, lost_in_linger, misrouted)
    return (RUN, 0, False, RUN, False, False, 0, 0, 0, False, False)


def successors(s, a_new, b_new, F, mutant):
    a, copies, acked, b, cert, acked_any, chx, chk, losses, lil, mis = s
    out = []

    def st(**kw):
        d = dict(a=a, copies=copies, acked=acked, b=b, cert=cert, acked_any=acked_any,
                 chx=chx, chk=chk, losses=losses, lil=lil, mis=mis)
        d.update(kw)
        return (d["a"], d["copies"], d["acked"], d["b"], d["cert"], d["acked_any"],
                d["chx"], d["chk"], d["losses"], d["lil"], d["mis"])

    peer_acks = a_new and b_new          # A faces a B that acknowledges
    b_expects = a_new and b_new          # B was told a certificate is coming
    a_gone = a in (OK, FAIL)

    # ---- A, the sender -------------------------------------------------
    if a == RUN:
        if copies == 0:
            out.append(st(copies=1, chx=chx + 1))
        elif peer_acks and not acked and copies < R and mutant != "send-once":
            out.append(st(copies=copies + 1, chx=chx + 1))
        if copies > 0 and (acked or not peer_acks):
            out.append(st(a=OK))
        elif mutant == "no-promise" and copies == 0:
            out.append(st(a=OK))
        # Deadline: every copy is out and nothing in flight can still answer.
        exhausted = copies >= R or (mutant == "send-once" and copies > 0)
        if peer_acks and not acked and exhausted and chk == 0 and (chx == 0 or b in (OK, FAIL)):
            out.append(st(a=FAIL))
    if chk > 0:
        if a == RUN:
            out.append(st(chk=chk - 1, acked=True, mis=mis or not a_new))
        else:
            out.append(st(chk=chk - 1))  # A already left

    # ---- B, the receiver -----------------------------------------------
    if chx > 0:
        if b in (RUN, LINGER):
            send_ack = (a_new and b_new) or (mutant == "ack-to-old" and b_new)
            if mutant == "ack-once" and acked_any:
                send_ack = False
            out.append(st(chx=chx - 1, cert=True,
                          acked_any=acked_any or send_ack,
                          chk=chk + (1 if send_ack else 0)))
        else:
            out.append(st(chx=chx - 1))  # B already left
    if b == RUN:
        wait_for_cert = b_expects and mutant != "no-wait"
        if not wait_for_cert:
            # Old window (or no promise): completes with what it has. The
            # window's timer fires only when the frame is genuinely absent.
            if cert or (copies > 0 and chx == 0):
                out.append(st(b=OK))
        else:
            if cert:
                linger = acked_any and mutant != "no-linger"
                out.append(st(b=LINGER if linger else OK))
            elif chx == 0 and (a_gone or copies >= R or (mutant == "send-once" and copies > 0)):
                out.append(st(b=FAIL))
    if b == LINGER:
        # Leave when A left (peer-left), or after a quiet spell, which only
        # happens when a copy was lost (A re-sends inside the quiet window).
        if a_gone or (lil and chx == 0):
            out.append(st(b=OK))

    # ---- the relay loses a frame ------------------------------------------
    if losses < F:
        if chx > 0:
            out.append(st(chx=chx - 1, losses=losses + 1, lil=lil or b == LINGER))
        if chk > 0:
            out.append(st(chk=chk - 1, losses=losses + 1))
    return out


def terminal(s):
    return s[0] in (OK, FAIL) and s[3] in (OK, FAIL) and s[6] == 0 and s[7] == 0


def explore(a_new, b_new, F, mutant=None):
    seen = {initial()}
    q = deque([initial()])
    ends, errors = set(), []
    while q:
        s = q.popleft()
        a, copies, acked, b, cert = s[:5]
        mis = s[10]
        if a_new and b_new and (a == OK or b in (OK, LINGER)) and not cert:
            errors.append(("P1 success without the certificate", s))
        if mis:
            errors.append(("P5 an acknowledgement reached a 0.9.1 side", s))
        nxt = successors(s, a_new, b_new, F, mutant)
        if not nxt:
            if terminal(s):
                ends.add(s)
            elif s[0] in (OK, FAIL) and s[3] in (OK, FAIL):
                ends.add(s)  # both left; frames still in flight go nowhere
            else:
                errors.append(("P2 deadlock", s))
        for n in nxt:
            if n not in seen:
                seen.add(n)
                q.append(n)
    for e in ends:
        a, b, cert, lil = e[0], e[3], e[4], e[9]
        if F == 0 and not (a == OK and b == OK and cert):
            errors.append(("P3 GoodNet ending is not both OK with the certificate", e))
        if a_new and b_new and F < R:
            if not (b == OK and cert):
                errors.append(("P4 Degraded: the certificate did not land", e))
            elif a == FAIL and not lil:
                errors.append(("P4 Degraded: the sender failed without a loss during linger", e))
        if not (a_new and b_new) and FAIL in (a, b):
            errors.append(("P5 mixed versions: a pairing failed", e))
    return len(seen), ends, errors


def check(mutant=None, quiet=False):
    total, bad = 0, []
    for a_new, b_new, F in product((True, False), (True, False), range(0, R + 2)):
        n, ends, errors = explore(a_new, b_new, F, mutant)
        total += n
        if errors:
            bad.append(((a_new, b_new, F), errors[0]))
        if not quiet:
            mix = f"A={'new' if a_new else 'old'} B={'new' if b_new else 'old'}"
            kinds = sorted({(e[0], e[3], e[4]) for e in ends})
            print(f"  {mix} F={F}: {n:5d} states, endings {kinds}{'  VIOLATION' if errors else ''}")
    return total, bad


def main():
    print("identity-expose delivery model (R=%d copies before the deadline)" % R)
    total, bad = check()
    if bad:
        for cfg, (what, s) in bad:
            print(f"COUNTEREXAMPLE {cfg}: {what}: {s}")
        sys.exit(1)
    print(f"OK: P1-P5 hold in {total} states.")
    # Total loss (F > R) is covered above: P1 holds and both sides fail.
    _, ends, _ = explore(True, True, R + 1)
    if not any(e[0] == FAIL and e[3] == FAIL for e in ends):
        print("COUNTEREXAMPLE: total loss never fails both sides")
        sys.exit(1)
    print("OK: every copy lost ends with both sides failing, never succeeding.")
    print("\nMutation controls: each mutant MUST be caught.")
    uncaught = []
    for m, why in MUTANTS.items():
        _, mbad = check(m, quiet=True)
        caught = bool(mbad)
        first = mbad[0][1][0] if mbad else "-"
        print(f"  mutant {m:<11} {'CAUGHT' if caught else 'NOT CAUGHT'} ({why}; {first})")
        if not caught:
            uncaught.append(m)
    if uncaught:
        sys.exit(1)


if __name__ == "__main__":
    main()
