"""The expired-session sweep must not run on every claim.

_MemRegistry._prune_sessions walks every token record. Run on every claim it
made each claim O(records), so with a few thousand devices the server's CPU
grew with the square of the device count. The sweep is now periodic
(PRUNE_INTERVAL); these tests pin that, and that expiry is still honoured.

Run:  python -m unittest backend.tests.test_session_prune
"""
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402


def _expired(reg, n):
    past = time.time() - 1
    for i in range(n):
        reg._sessions[f"old-{i}"] = {"sid": f"gone-{i}", "gen": "g", "uid": "u", "name": "n",
                                     "last_seen": past, "exp": past}
        reg._sid_token[f"gone-{i}"] = f"old-{i}"


class PeriodicPrune(unittest.TestCase):
    def test_sweep_runs_once_per_interval_not_per_claim(self):
        reg = signaling._MemRegistry()
        calls = []
        real = reg._prune_sessions
        reg._prune_sessions = lambda now: calls.append(now) or real(now)
        for i in range(200):
            reg.claim_session(None, f"g{i}", f"s{i}", "u", "n")
        self.assertEqual(len(calls), 1, "one sweep inside one interval")

    def test_expired_records_are_still_swept(self):
        reg = signaling._MemRegistry()
        reg.claim_session(None, "g0", "s0", "u", "n")  # first sweep, sets the next deadline
        _expired(reg, 500)
        reg.claim_session(None, "g1", "s1", "u", "n")
        self.assertEqual(len(reg._sessions), 502, "inside the interval nothing is swept")
        reg._next_prune = 0.0  # the interval has passed
        out = reg.claim_session(None, "g2", "s2", "u", "n")
        self.assertEqual(len(reg._sessions), 3)
        self.assertEqual(len(out["evicted"]), 500, "swept sids are still handed back for cleanup")
        self.assertFalse(any(k.startswith("gone-") for k in reg._sid_token))

    def test_claimed_token_expiry_is_checked_inline(self):
        reg = signaling._MemRegistry()
        first = reg.claim_session(None, "g0", "s0", "u", "n")
        token = first["token"]
        reg._sessions[token]["exp"] = time.time() - 1  # expires between sweeps
        again = reg.claim_session(token, "g0", "s0", "u", "n")
        self.assertEqual(again["status"], "new")
        self.assertNotEqual(again["token"], token, "an expired token is never reattached")

    def test_capacity_does_not_wait_for_the_sweep(self):
        reg = signaling._MemRegistry()
        reg.MAX_SESSIONS = 10
        reg.claim_session(None, "g0", "s0", "u", "n")
        _expired(reg, 9)
        out = reg.claim_session(None, "g1", "s1", "u", "n")
        self.assertEqual(out["status"], "new", "expired records make room at capacity")


if __name__ == "__main__":
    unittest.main()
