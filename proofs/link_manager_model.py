#!/usr/bin/env python3
"""Model the link manager's placement and upgrade-verify decisions.

`crates/filament-peerloop/src/link_manager.rs` decides which existing link a request rides and when
a direct standby has earned the cutover from relay. This model mirrors those
two pure functions and checks, exhaustively over a small domain, the
properties the rest of the system relies on:

Placement
  P1  never places work on a link to another device;
  P2  never places work on a link whose identity is unknown;
  P3  never places work on a dead or transportless link;
  P4  never places work on a relay link quiet past the stale window
      (a possible NAT/relay zombie), while a quiet direct link stays usable;
  P5  reuses whenever any eligible link exists (no needless cold dial);
  P6  prefers a direct link whenever an eligible one exists.

Upgrade verify (run over every tick sequence up to a bound)
  U1  never upgrades on the first look at a standby;
  U2  upgrades only after holding for the whole verify window;
  U3  any failed heartbeat or idle path after the window starts discards,
      however long the standby held before.

Structure guards (the model must describe the code that runs)
  S1  the stale window constant matches the Rust source;
  S2  the warm-reuse resolver goes through `place`, so the rule exists once.

Run this file directly; it exits non-zero on any violation.
"""
from itertools import product
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LM = os.path.join(ROOT, "crates", "filament-peerloop", "src", "link_manager.rs")
DC = os.path.join(ROOT, "cli", "src", "daemon_ctl.rs")


def source_stale_ms():
    src = open(LM, encoding="utf-8").read()
    m = re.search(r"const\s+WARM_RELAY_STALE_MS:\s*u64\s*=\s*([\d_]+)", src)
    if not m:
        raise SystemExit("S1: WARM_RELAY_STALE_MS not found in link_manager.rs; refusing to report")
    return int(m.group(1).replace("_", ""))


STALE = source_stale_ms()


def eligible(link, peer):
    return (
        link["identity_known"]
        and link["name"] is not None
        and link["name"].lower() == peer.lower()
        and link["has_transport"]
        and link["alive"]
        and (link["direct"] or link["idle"] < STALE)
    )


def place(peer, links):
    best = None
    for l in links:  # max_by_key keeps the LAST maximum
        if eligible(l, peer) and (best is None or int(l["direct"]) >= int(best["direct"])):
            best = l
    return ("reuse", best["pid"]) if best else ("establish", None)


def link_space():
    for name, known, has_t, alive, direct, idle in product(
        ["laptop", "LAPTOP", "server", None],
        [True, False],
        [True, False],
        [True, False],
        [True, False],
        [0, STALE - 1, STALE, 10 * STALE],
    ):
        yield dict(name=name, identity_known=known, has_transport=has_t,
                   alive=alive, direct=direct, idle=idle)


def check_placement():
    singles = list(link_space())
    checked = 0
    for a, b in product(singles, repeat=2):
        links = [dict(a, pid="a"), dict(b, pid="b")]
        kind, pid = place("laptop", links)
        checked += 1
        if kind == "reuse":
            chosen = next(l for l in links if l["pid"] == pid)
            assert chosen["name"] and chosen["name"].lower() == "laptop", ("P1", links)
            assert chosen["identity_known"], ("P2", links)
            assert chosen["has_transport"] and chosen["alive"], ("P3", links)
            assert chosen["direct"] or chosen["idle"] < STALE, ("P4", links)
            if any(eligible(l, "laptop") and l["direct"] for l in links):
                assert chosen["direct"], ("P6", links)
        else:
            assert not any(eligible(l, "laptop") for l in links), ("P5", links)
    # P4, the positive half: a long-quiet direct link stays usable.
    d = dict(name="laptop", identity_known=True, has_transport=True, alive=True,
             direct=True, idle=100 * STALE, pid="d")
    assert place("laptop", [d]) == ("reuse", "d"), "P4 direct"
    return checked


def decide_verify(elapsed, beat_ok, idle, verify_idle, verify):
    if elapsed is None:
        return "start"
    if not beat_ok or idle >= verify_idle:
        return "discard"
    return "upgrade" if elapsed >= verify else "wait"


def check_verify(max_ticks=6):
    VERIFY_IDLE, VERIFY, TICK = 2, 3, 1
    ticks_checked = 0
    obs = [(b, i) for b in (True, False) for i in (0, 1, VERIFY_IDLE, VERIFY_IDLE + 1)]
    for n in range(1, max_ticks + 1):
        for seq in product(obs, repeat=n):
            started = None
            outcome = None
            for k, (beat, idle) in enumerate(seq):
                elapsed = None if started is None else (k - started) * TICK
                act = decide_verify(elapsed, beat, idle, VERIFY_IDLE, VERIFY)
                if k == 0:
                    assert act == "start", ("U1", seq)
                if act == "start":
                    started = k
                elif act in ("discard", "upgrade"):
                    outcome = (act, k)
                    break
            ticks_checked += 1
            if outcome and outcome[0] == "upgrade":
                k = outcome[1]
                assert (k - started) * TICK >= VERIFY, ("U2", seq)
                held = seq[started + 1:k + 1]
                assert all(b and i < VERIFY_IDLE for b, i in held), ("U3", seq)
            for k, (beat, idle) in enumerate(seq[1:], start=1):
                if outcome and k > outcome[1]:
                    break
                if not beat or idle >= VERIFY_IDLE:
                    assert outcome == ("discard", k), ("U3 discard", seq)
                    break
    return ticks_checked


def check_structure():
    dc = open(DC, encoding="utf-8").read()
    m = re.search(r"fn warm_link_for\(.*?\n}\n", dc, re.S)
    if not m or "place(" not in m.group(0):
        raise SystemExit("S2: warm_link_for no longer goes through link_manager::place")
    if "WARM_RELAY_STALE_MS" in dc:
        raise SystemExit("S2: daemon_ctl.rs has its own stale window again; the rule must live in link_manager.rs")


def main():
    check_structure()
    p = check_placement()
    v = check_verify()
    print(f"link manager model: stale window {STALE} ms from source")
    print(f"  placement: {p} two-link configurations, P1-P6 hold")
    print(f"  upgrade verify: {v} tick sequences, U1-U3 hold")
    print("  structure: S1, S2 hold")
    return 0


if __name__ == "__main__":
    sys.exit(main())
