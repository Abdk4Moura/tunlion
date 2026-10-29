"""Rate-limit conformance, against an instance started with SMALL budgets:

    FIL_SESSION_CLAIM_LIMIT=8 FIL_CLAIM_LIMIT=3 FIL_CLOSE_LIMIT=4

(edge/signal's `limits` environment, or the Python relay with the same env).
Every client shares one address, which is exactly the NAT case #592 is about.
Run it once per fresh minute: the budgets are 60 s sliding windows.

    CONFORMANCE_URL=... python -m unittest backend.conformance.test_limits -v
"""
import json
import random
import unittest

from backend.conformance.wire import Peer, http, uniq

CLAIM = 8
PAIR_CLAIM = 3
CLOSE = 4


class Limits(unittest.TestCase):
    # Tests run in name order; earlier ones spend IP claims the budget test counts.
    ip_claims_used = 0

    def setUp(self):
        self.peers = []

    def tearDown(self):
        for p in self.peers:
            p.close()

    def peer(self):
        p = Peer().connect()
        self.peers.append(p)
        return p

    def test_c_session_claim_budget(self):
        room = uniq()
        # Three devices behind one address join (3 IP charges).
        devs = []
        for i in range(3):
            p = self.peer()
            uid, gen = uniq("u"), uniq("g")
            p.emit("join", {"room": room, "name": f"d{i}", "uid": uid, "gen": gen})
            w = p.wait("welcome")
            devs.append((p, {"v": 1, "room": room, "name": f"d{i}", "uid": uid, "gen": gen, "token": w["token"]}))
        # #592: refresh-only syncs are charged to the socket, never the IP.
        for _ in range(4):
            for p, st in devs:
                self.assertTrue(p.call("sync", st)["ok"])
        # The socket budget still bounds one socket: 1 join + 4 syncs so far,
        # three more refreshes fit, the next one is refused.
        p0, st0 = devs[0]
        for _ in range(CLAIM - 5):
            self.assertTrue(p0.call("sync", st0)["ok"])
        refused = p0.call("sync", st0)
        self.assertEqual(refused["ok"], False)
        self.assertEqual(p0.wait("session-superseded"), {"reason": "rate-limited"})
        # The IP budget bounds NEW sessions: 3 used here (plus any spent by
        # earlier tests), the rest fit, then refusal.
        for i in range(CLAIM - 3 - Limits.ip_claims_used):
            p = self.peer()
            p.emit("join", {"room": room, "name": f"n{i}", "uid": uniq("u"), "gen": uniq("g")})
            p.wait("welcome")
        last = self.peer()
        last.emit("join", {"room": room, "name": "over", "uid": uniq("u"), "gen": uniq("g")})
        self.assertEqual(last.wait("session-superseded"), {"reason": "rate-limited"})
        last.none("welcome")
        # ...while an existing device's refresh is still admitted.
        p1, st1 = devs[1]
        self.assertTrue(p1.call("sync", st1)["ok"])

    def test_b_pair_claim_budget(self):
        p = self.peer()
        for _ in range(PAIR_CLAIM):
            p.emit("pair-claim", {"nameplate": str(random.randint(10000, 99999)), "v": 2})
            self.assertEqual(p.wait("pair-error")["error"], "invalid")
        p.emit("pair-claim", {"nameplate": "12345", "v": 2})
        self.assertEqual(p.wait("pair-error"), {"error": "slow-down"})
        # Per address, not per socket: a fresh socket is still over.
        q = self.peer()
        q.emit("pair-claim", {"nameplate": "12345", "v": 2})
        self.assertEqual(q.wait("pair-error"), {"error": "slow-down"})

    def test_a_close_budget(self):
        for _ in range(CLOSE):
            self.assertEqual(http("POST", "/api/session/close", data="{}").status_code, 204)
        # Over budget a VALID close is silently ignored (still 204).
        p = Peer().connect()
        self.peers.append(p)
        p.emit("join", {"room": uniq(), "name": "c", "uid": uniq("u"), "gen": "g-c"})
        w = p.wait("welcome")
        Limits.ip_claims_used += 1
        r = http("POST", "/api/session/close", data=json.dumps({"token": w["token"], "gen": "g-c"}))
        self.assertEqual(r.status_code, 204)
        p.none("session-superseded")


if __name__ == "__main__":
    unittest.main()
