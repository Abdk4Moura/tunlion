#!/usr/bin/env python3
"""Local discovery model (docs/protocol/local-discovery.md).

Discovery adds a rendezvous that needs no server: beacons, unicast probes and
remembered addresses yield candidate addresses, and the existing
authenticated direct-QUIC handshake decides who is at them. The model
enumerates EVERY environment of two paired devices A and B plus a stranger M
(who holds no secret, sees every beacon, can replay or forge beacons, and can
own any address), and checks:

  ADMIT     a link is admitted as device X only if the far end proved the
            secret shared with X in the handshake. A beacon tag, a replay or a
            forged beacon never admits anything.
  REACH     with lan on, if some non-circular path between A and B exists and
            A learns an address on it (a beacon over a shared link, a sweep of
            a point-to-point prefix, or a remembered address), A links B with
            route lan, whether or not the server is reachable.
  GUARD     A never dials B at an address carried only by A's own link to B
            (tunlion's overlay address for B); an overlay address carried by a
            link to a third device is dialed.
  OFF       with lan off (network.transports without lan), nothing is sent,
            nothing is bound, nothing is dialed from remembered addresses.
  QUIET     on an opted-out interface or a public network nothing is sent or
            answered.
  BLIND     nothing a beacon carries is stable across epochs (the port aside,
            see the spec), and nothing names the device.
  HELLO     remembered addresses are learned only from a link whose identity
            is proven.

Run:  python3 proofs/lan_discovery_model.py              (prove)
      python3 proofs/lan_discovery_model.py --self-test  (every mutant must be caught)
"""
import itertools
import sys

MUTANT = None

MUTANTS = (
    "admit_on_tag",          # a recognized beacon tag admits the link
    "dial_circular",         # the overlay address carried by the link to B is dialed
    "skip_third_overlay",    # all overlay addresses dropped, by "name" (tunlion0)
    "off_still_beacons",     # lan off but beacons still go out
    "off_still_dials",       # lan off but remembered addresses are dialed
    "stable_id_in_beacon",   # the beacon carries a device id
    "hello_unproven",        # hello learned from an unproven link
    "answer_public",         # queries answered on a public network
    "sweep_shared_only",     # point-to-point interfaces are never swept
    "remembered_needs_server",  # remembered dial only while the server is up
)

# ------------------------------------------------------------ environments --

def environments():
    for (server, lan_on, link_kind, remembered, overlay_b_circular, overlay_c,
         stranger_replays, public, hello_proven) in itertools.product(
        (False, True),               # signaling server reachable
        (False, True),               # network.transports includes lan
        ("shared", "p2p", "none"),   # the direct path between A and B, if any
        (False, True),               # A remembers an address of B on that path
        (False, True),               # A's candidates include B's overlay address
        (False, True),               # a third device C carries an overlay path to B
        (False, True),               # M replays B's beacon from M's address
        (False, True),               # A's interface is on a public network
        (False, True),               # the link the hello came over was proven
    ):
        yield dict(server=server, lan_on=lan_on, link=link_kind, remembered=remembered,
                   circ=overlay_b_circular, third=overlay_c, replay=stranger_replays,
                   public=public, hello_proven=hello_proven)

# ------------------------------------------------------------- the system --

def beacon(device, epoch):
    """What a presence beacon of `device` carries in `epoch`: fresh values
    only. Modelled as a tuple of field origins."""
    fields = [("nonce", "fresh", epoch), ("tag", "fresh", epoch), ("port", "default")]
    if MUTANT == "stable_id_in_beacon":
        fields.append(("id", device))
    return fields

def run(env):
    """Returns the observable outcome of A trying to reach B."""
    out = dict(sent=[], answered=[], dialed=[], admitted=[], learned=False)
    lan = env["lan_on"]
    # Sending: beacons on a shared, non-public interface; sweep on p2p.
    sends = lan or MUTANT == "off_still_beacons"
    quiet = env["public"] and MUTANT != "answer_public"
    if sends and not quiet:
        if env["link"] == "shared":
            out["sent"].append("beacon")
        if env["link"] == "p2p" and MUTANT != "sweep_shared_only":
            out["sent"].append("probe")
    if lan and not quiet:
        out["answered"].append("query")
    # Candidates A learns for B.
    cands = []
    if lan and not env["public"]:
        if env["link"] == "shared":
            cands.append(("B", "path"))                     # B's beacon
        if env["link"] == "p2p" and MUTANT != "sweep_shared_only":
            cands.append(("B", "path"))                     # B answered the sweep
        if env["replay"]:
            cands.append(("M", "replayed"))                 # M replays B's tag from M
    dial_remembered = (lan or MUTANT == "off_still_dials") and (env["server"] or MUTANT != "remembered_needs_server")
    if dial_remembered and env["remembered"] and env["link"] != "none":
        cands.append(("B", "path"))
    if dial_remembered and env["circ"]:
        cands.append(("B", "overlay-of-B"))
    if dial_remembered and env["third"]:
        cands.append(("C", "overlay-via-C"))                # C relays to B
    # The guard: route ownership, not interface name.
    kept = []
    for who, kind in cands:
        if kind == "overlay-of-B" and MUTANT != "dial_circular":
            continue
        if kind.startswith("overlay") and MUTANT == "skip_third_overlay":
            continue
        kept.append((who, kind))
    out["dialed"] = kept
    # Handshake: only the holder of the A-B secret proves it. B holds it; C
    # forwards to B over its own link, so the far end is B; M holds nothing.
    for who, kind in kept:
        far = {"B": "B", "C": "B", "M": "M"}[who]
        if kind == "overlay-of-B":
            # Only exists while the A-B link is up; dialing it to build that
            # link can never succeed.
            continue
        if far == "B" or MUTANT == "admit_on_tag":
            out["admitted"].append(far)
    out["learned"] = env["hello_proven"] or MUTANT == "hello_unproven"
    return out

# ------------------------------------------------------------- properties --

def check(env, out):
    bad = []
    if any(x != "B" for x in out["admitted"]):
        bad.append("ADMIT: admitted a device that never proved the secret")
    path = env["link"] != "none" or env["third"]
    learnable = (env["link"] == "shared" and not env["public"]) or \
                (env["link"] == "p2p" and not env["public"]) or \
                (env["remembered"] and env["link"] != "none") or env["third"]
    if env["lan_on"] and path and learnable and "B" not in out["admitted"]:
        bad.append("REACH: a usable path existed and A did not link B")
    if ("B", "overlay-of-B") in out["dialed"]:
        bad.append("GUARD: dialed B over B's own overlay address")
    if env["lan_on"] and env["third"] and ("C", "overlay-via-C") not in out["dialed"]:
        bad.append("GUARD: dropped a real path through a third device")
    if not env["lan_on"] and (out["sent"] or out["dialed"] or out["answered"]):
        bad.append("OFF: lan is off and something was sent or dialed")
    if env["public"] and (out["sent"] or out["answered"]):
        bad.append("QUIET: sent or answered on a public network")
    b1, b2 = beacon("A", 1), beacon("A", 2)
    stable = [f for f in b1 if f in b2 and f[0] != "port"]
    if stable or any(f[0] == "id" for f in b1):
        bad.append("BLIND: a beacon carries a stable or naming value")
    if out["learned"] and not env["hello_proven"]:
        bad.append("HELLO: learned addresses from an unproven link")
    return bad

def prove():
    n = 0
    for env in environments():
        n += 1
        bad = check(env, run(env))
        if bad:
            return False, n, env, bad
    return True, n, None, None

def main():
    global MUTANT
    if "--self-test" in sys.argv:
        MUTANT = None
        ok, n, env, bad = prove()
        if not ok:
            print(f"FAIL baseline: {bad} in {env}")
            return 1
        missed = []
        for m in MUTANTS:
            MUTANT = m
            ok, _, _, bad = prove()
            print(f"  mutant {m:<24} {'caught: ' + bad[0] if not ok else 'MISSED'}")
            if ok:
                missed.append(m)
        MUTANT = None
        if missed:
            print(f"FAIL: mutants not caught: {missed}")
            return 1
        print(f"ok: {len(MUTANTS)} mutants caught; baseline holds over {n} environments")
        return 0
    ok, n, env, bad = prove()
    if not ok:
        print(f"FAIL: {bad}\n  in {env}")
        return 1
    print(f"ok: ADMIT REACH GUARD OFF QUIET BLIND HELLO hold over {n} environments")
    return 0

if __name__ == "__main__":
    sys.exit(main())
