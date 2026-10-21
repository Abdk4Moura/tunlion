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
    def setUp(self):
        self.uid = "test-" + uuid.uuid4().hex
        self.reg = signaling._RedisRegistry(URL)
        self.reg.r.delete(
            f"filament:uid:{self.uid}:gen",
            f"filament:uid:{self.uid}:sid",
            f"filament:uid:{self.uid}:retired",
            f"filament:uid:{self.uid}:token",
        )

    def tearDown(self):
        for suffix in ("gen", "sid", "retired", "token"):
            self.reg.r.delete(f"filament:uid:{self.uid}:{suffix}")

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

    def test_concurrent_claims_leave_one_owner(self):
        from concurrent.futures import ThreadPoolExecutor

        tok = self.reg.claim_session(self.uid, "g0", "s0")["token"]
        gens = [f"r{i}" for i in range(24)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.reg.claim_session(self.uid, gens[i], f"rs{i}", tok), range(len(gens))))
        cur_gen = self.reg.r.get(f"filament:uid:{self.uid}:gen")
        cur_sid = self.reg.r.get(f"filament:uid:{self.uid}:sid")
        self.assertIn(cur_gen, gens)
        # every other generation is a tombstone; one remains current
        for i, g in enumerate(gens):
            if g != cur_gen:
                self.assertEqual(self.reg.claim_session(self.uid, g, f"rs{i}", tok)["status"], "retired")
        self.assertEqual(self.reg.claim_session(self.uid, cur_gen, cur_sid, tok)["status"], "current")


if __name__ == "__main__":
    unittest.main()
