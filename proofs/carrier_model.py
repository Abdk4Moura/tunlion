#!/usr/bin/env python3
"""Carrier selection model (docs/carriers.md, section 10).

The establishment model (establishment_model.py) assumes A4, "a path exists".
This model discharges A4 for the carriers that exist: it enumerates EVERY
combination of per-peer egress (UDP, TCP ports, a configured HTTP proxy and
what it allows, inbound reachability, whether a blocked path refuses or goes
silent) and a censor that blocks relay or signaling classes, runs the carrier
selection the code implements, and checks:

  REACH   if each peer has at least one usable carrier class to signaling and
          (a direct path exists, or each peer has a usable class to the relay),
          establishment succeeds, within BOUND ticks.
  QUIET   when a proxy is configured, no peer ever attempts a direct TCP
          connection beside it (the sandbox-polite rule; the CI profile
          measures the same thing with iptables counters).
  LEAK    nothing a carrier, proxy or relay can observe is secret: the only
          code-derived value on signaling is a SPAKE2 element; data is DTLS or
          QUIC ciphertext. A TLS-inspecting proxy additionally observes
          signaling METADATA, which is modelled, not assumed away.

The selector is deterministic given an environment, so exhaustive enumeration
of environments is exhaustive over its behaviours.

Faithfulness (one tick = 250 ms):
  - signaling: crates/filament-signal/src/lib.rs connect_inner; a configured
    proxy is used, never raced (filament-carrier select).
  - relay: crates/filament-transport/src/turn_bridge.rs gate(): UDP at once;
    TCP after TCP_AFTER (1.5 s) without a UDP relay; TLS after TLS_AFTER_TCP
    more, or at once when every TCP server failed; TCP and TLS dial through
    the proxy when one is configured. CONNECT_TIMEOUT 5 s bounds a silent dial.
  - direct QUIC: direct.rs race_connect needs UDP both ways and one side
    inbound-reachable.

Run:  python3 proofs/carrier_model.py              (prove)
      python3 proofs/carrier_model.py --self-test  (every mutant must be caught)
"""
import itertools
import sys

TCP_AFTER = 6        # 1.5 s
TLS_AFTER_TCP = 6    # 1.5 s
CONNECT_TIMEOUT = 20  # 5 s
RTT = 1              # an answered dial or allocation
BOUND = TCP_AFTER + TLS_AFTER_TCP + 2 * RTT

MUTANT = None  # set by --self-test

# ------------------------------------------------------------ environments --

PROXY_KINDS = (None, "443", "all")   # what the proxy allows CONNECT to
TCP_KINDS = ("none", "443", "all")   # direct TCP egress

def environments():
    for udp, tcp, proxy, inbound, silent, inspect in itertools.product(
        (False, True), TCP_KINDS, PROXY_KINDS, (False, True), (False, True), (False, True)
    ):
        if inspect and proxy is None:
            continue
        yield dict(udp=udp, tcp=tcp, proxy=proxy, inbound=inbound, silent=silent, inspect=inspect)

CENSOR_CLASSES = ("relay-udp", "relay-tcp", "relay-tls", "signaling")

def censors():
    for r in range(len(CENSOR_CLASSES) + 1):
        for c in itertools.combinations(CENSOR_CLASSES, r):
            yield frozenset(c)

# ------------------------------------------------------- path primitives ----

def tcp_reachable(env, port, censor, cls):
    """Can this peer open a stream to our server on `port`, over the carrier the
    selector picks? Returns (ok, used_proxy, attempted_direct)."""
    if cls in censor:
        return False, env["proxy"] is not None, env["proxy"] is None
    use_proxy = env["proxy"] is not None
    if MUTANT == "bridge-ignores-proxy" and cls != "signaling":
        use_proxy = False
    if MUTANT == "signal-ignores-proxy" and cls == "signaling":
        use_proxy = False
    if use_proxy:
        allowed = env["proxy"] == "all" or port == 443
        return allowed, True, False
    ok = env["tcp"] == "all" or (env["tcp"] == "443" and port == 443)
    return ok, False, True

def fail_time(env):
    # A refusal (RST, proxy 403) is one round trip; a silent drop is the timeout.
    return CONNECT_TIMEOUT if env["silent"] else RTT

# ------------------------------------------------------------- selection ----

def relay_alloc(env, censor, attempts):
    """When this peer's relay allocation succeeds (tick), or None."""
    udp_ok = env["udp"] and "relay-udp" not in censor
    if udp_ok:
        return RTT
    # TCP at TCP_AFTER (the config always lists UDP TURN, so it waits).
    t_tcp = TCP_AFTER
    ok, proxied, direct = tcp_reachable(env, 3478, censor, "relay-tcp")
    attempts.append(("relay-tcp", proxied, direct))
    if ok:
        return t_tcp + RTT
    tcp_failed_at = t_tcp + fail_time(env)
    if MUTANT == "no-fallback":
        return None
    if MUTANT == "tls-gate-on-attempt":
        # TLS suppressed because a TCP attempt had started (narrow view: an
        # attempt is not a relay).
        return None
    t_tls = min(TCP_AFTER + TLS_AFTER_TCP, tcp_failed_at)
    ok, proxied, direct = tcp_reachable(env, 443, censor, "relay-tls")
    attempts.append(("relay-tls", proxied, direct))
    return t_tls + RTT if ok else None

def establish(a, b, censor):
    attempts = {0: [], 1: []}
    times = []
    for i, env in enumerate((a, b)):
        ok, proxied, direct = tcp_reachable(env, 443, censor, "signaling")
        attempts[i].append(("signaling", proxied, direct))
        if not ok:
            return None, attempts
    direct_path = a["udp"] and b["udp"] and (a["inbound"] or b["inbound"])
    if direct_path:
        return RTT, attempts
    for i, env in enumerate((a, b)):
        t = relay_alloc(env, censor, attempts[i])
        if t is None:
            return None, attempts
        times.append(t)
    return max(times), attempts

# --------------------------------------------------------- the hypothesis --

def usable(env, censor):
    """What the network offers, independent of the selector. A configured proxy
    is the egress policy: when one is set, only what it allows counts."""
    def stream(port, cls):
        if cls in censor:
            return False
        if env["proxy"] is not None:
            return env["proxy"] == "all" or port == 443
        return env["tcp"] == "all" or (env["tcp"] == "443" and port == 443)
    sig = stream(443, "signaling")
    relay = (env["udp"] and "relay-udp" not in censor) or stream(3478, "relay-tcp") or stream(443, "relay-tls")
    return sig, relay

# ------------------------------------------------------------ observation --

def observed(env, mutant):
    """What any party on this peer's carriers can see."""
    seen = {"ciphertext"}
    seen.add("spake2-element" if mutant != "code-in-signaling" else "code")
    if env["inspect"]:
        seen.add("signaling-metadata")
    return seen

SAFE = {"ciphertext", "spake2-element", "signaling-metadata"}

# ----------------------------------------------------------------- check ----

def check():
    envs = list(environments())
    cs = list(censors())
    cases = reach_premise = 0
    worst = 0
    violations = []
    for a in envs:
        for b in envs:
            for censor in cs:
                cases += 1
                t, attempts = establish(a, b, censor)
                sa, ra = usable(a, censor)
                sb, rb = usable(b, censor)
                direct = a["udp"] and b["udp"] and (a["inbound"] or b["inbound"])
                if sa and sb and (direct or (ra and rb)):
                    reach_premise += 1
                    if t is None:
                        violations.append(("REACH", a, b, censor))
                    elif t > BOUND:
                        violations.append(("BOUND", a, b, censor, t))
                    else:
                        worst = max(worst, t)
                for i, env in enumerate((a, b)):
                    if env["proxy"] is not None and any(d for _, _, d in attempts[i]):
                        violations.append(("QUIET", env, censor, attempts[i]))
                    if not observed(env, MUTANT) <= SAFE:
                        violations.append(("LEAK", env))
                if len(violations) > 20:
                    return cases, reach_premise, worst, violations
    return cases, reach_premise, worst, violations

def main(quiet=False):
    """Returns (green, kind of the first violation or None)."""
    cases, premise, worst, v = check()
    if v:
        if not quiet:
            print(f"carrier model: {len(v)}+ violation(s), first: {v[0][0]}")
            for x in v[:3]:
                print("   ", x)
        return False, v[0][0]
    if not quiet:
        print(f"carrier model: {cases} environment pairs x censors, {premise} satisfy the REACH premise")
        print(f"  worst establishment time under the premise: {worst} ticks ({worst * 250} ms), bound {BOUND}")
    if premise == 0:
        print("  the REACH premise was never satisfied: the property was not tested")
        return False, "VACUOUS"
    if not quiet:
        print("  PROVEN: REACH, BOUND, QUIET, LEAK hold in every case")
    return True, None

# mutant -> (the property that must catch it, what it breaks)
MUTANTS = {
    "no-fallback": (("REACH",), "the selector stops at the first failed relay tier"),
    "signal-ignores-proxy": (("REACH", "QUIET"), "signaling dials directly beside a configured proxy (the pre-0.9.3 bug)"),
    "bridge-ignores-proxy": (("REACH", "QUIET"), "TURN TCP/TLS streams dial directly (the pre-0.9.3 bridge)"),
    "tls-gate-on-attempt": (("REACH",), "TLS is suppressed by a TCP attempt rather than a TCP relay"),
    "code-in-signaling": (("LEAK",), "the pairing code itself (not a SPAKE2 element) rides signaling"),
}

def self_test():
    global MUTANT
    ok = True
    MUTANT = None
    if not main(quiet=True)[0]:
        print("self-test: the unmutated model is not green")
        return False
    for m, (want, why) in MUTANTS.items():
        MUTANT = m
        green, kind = main(quiet=True)
        caught = not green and kind in want
        print(f"  mutant {m:<22} {'caught by ' + kind if caught else 'NOT CAUGHT (' + str(kind) + ')'}: {why}")
        ok &= caught
    MUTANT = None
    print("self-test:", "every mutant caught by the property it breaks" if ok else "a mutant survived")
    return ok

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(0 if self_test() else 1)
    sys.exit(0 if main()[0] else 1)
