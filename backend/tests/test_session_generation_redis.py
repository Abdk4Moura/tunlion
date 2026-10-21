"""Redis parity for the generation/token ownership rules.

Skipped unless FIL_TEST_REDIS_URL points at a real Redis (the Lua path cannot be
exercised by a dict). Run locally with e.g.:

    redis-server --port 6399 --save '' --appendonly no &
    FIL_TEST_REDIS_URL=redis://127.0.0.1:6399/0 \
      python -m unittest backend.tests.test_session_generation_redis

Run:  python -m unittest backend.tests.test_session_generation_redis
"""
import os
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

URL = os.environ.get("FIL_TEST_REDIS_URL", "")


@unittest.skipUnless(URL, "FIL_TEST_REDIS_URL not set (real Redis required for Lua)")
class RedisGenerationParity(unittest.TestCase):
    def _cleanup(self):
        self.reg.r.delete(f"filament:owner:{self.uid}")
        self.reg.r.zrem("filament:owners", self.uid)
        for member, _score in list(self.reg.r.zscan_iter("filament:retired:gens", match=f"{self.uid}|*")):
            self.reg.r.zrem("filament:retired:gens", member)

    def setUp(self):
        self.uid = "test-" + uuid.uuid4().hex
        self.reg = signaling._RedisRegistry(URL)
        self._cleanup()

    def tearDown(self):
        self._cleanup()

    def test_mint_ignore_client_token_reclaim_and_close(self):
        first = self.reg.claim_session(self.uid, "g1", "s1", "attacker-chosen")
        self.assertEqual(first["status"], "new")
        tok = first["token"]
        self.assertNotEqual(tok, "attacker-chosen")
        self.assertEqual(self.reg.claim_session(self.uid, "g1", "s2", "attacker-chosen")["status"], "denied")
        repl = self.reg.claim_session(self.uid, "g1", "s2", tok)
        self.assertEqual((repl["status"], repl["prev"]), ("replace", "s1"))
        newer = self.reg.claim_session(self.uid, "g2", "s3", tok)
        self.assertEqual((newer["status"], newer["prev"]), ("new", "s2"))
        self.assertEqual(self.reg.claim_session(self.uid, "g1", "s4", tok)["status"], "retired")
        self.assertIsNone(self.reg.take_session(self.uid, "g2", "wrong"))
        self.assertEqual(self.reg.take_session(self.uid, "g2", tok)["sid"], "s3")

    def test_shared_ttl_live_tokenless_and_expired_paths(self):
        first = self.reg.claim_session(self.uid, "g1", "s1")
        tok = first["token"]
        # Tokenless new generation cannot take a live owner.
        self.assertEqual(self.reg.claim_session(self.uid, "g2", "s2", None)["status"], "denied")
        # A live sync refreshes the ONE hash key carrying gen/sid/token.
        self.reg.r.pexpire(f"filament:owner:{self.uid}", 100)
        self.assertEqual(self.reg.claim_session(self.uid, "g1", "s1", tok)["status"], "current")
        self.assertGreater(self.reg.r.pttl(f"filament:owner:{self.uid}"), 1000)
        # Close keeps the token (gen/sid empty) but a tokenless client cannot reuse it.
        self.assertEqual(self.reg.take_session(self.uid, "g1", tok)["sid"], "s1")
        self.assertEqual(self.reg.claim_session(self.uid, "g2", "s2", None)["status"], "denied")
        reclaim = self.reg.claim_session(self.uid, "g2", "s2", tok)
        self.assertEqual((reclaim["status"], reclaim["token"]), ("new", tok))
        # Expired ownership hash is stale; a fresh relay token is minted.
        self.reg.r.delete(f"filament:owner:{self.uid}")
        expired = self.reg.claim_session(self.uid, "g3", "s3", None)
        self.assertEqual(expired["status"], "new")
        self.assertNotEqual(expired["token"], tok)

    def test_concurrent_claims_leave_one_owner(self):
        from concurrent.futures import ThreadPoolExecutor

        tok = self.reg.claim_session(self.uid, "g0", "s0")["token"]
        gens = [f"r{i}" for i in range(24)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.reg.claim_session(self.uid, gens[i], f"rs{i}", tok), range(len(gens))))
        cur_gen, cur_sid = self.reg.r.hmget(f"filament:owner:{self.uid}", "gen", "sid")
        self.assertIn(cur_gen, gens)
        # every other generation is a tombstone; one remains current
        for i, g in enumerate(gens):
            if g != cur_gen:
                self.assertEqual(self.reg.claim_session(self.uid, g, f"rs{i}", tok)["status"], "retired")
        self.assertEqual(self.reg.claim_session(self.uid, cur_gen, cur_sid, tok)["status"], "current")


if __name__ == "__main__":
    unittest.main()
