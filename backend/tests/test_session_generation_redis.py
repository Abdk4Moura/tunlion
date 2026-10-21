"""Redis parity for TOKEN-keyed sessions.

Skipped unless FIL_TEST_REDIS_URL points at a real Redis (Lua cannot be
exercised by a dict). Run locally with:

    redis-server --port 6399 --save '' --appendonly no &
    FIL_TEST_REDIS_URL=redis://127.0.0.1:6399/0 \
      python -m unittest backend.tests.test_session_generation_redis

Run:  python -m unittest backend.tests.test_session_generation_redis
"""
import os
import sys
import time
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

URL = os.environ.get("FIL_TEST_REDIS_URL", "")


@unittest.skipUnless(URL, "FIL_TEST_REDIS_URL not set (real Redis required for Lua)")
class RedisTokenParity(unittest.TestCase):
    def setUp(self):
        self.uid = "test-" + uuid.uuid4().hex
        self.reg = signaling._RedisRegistry(URL)
        self.tokens = []

    def tearDown(self):
        if not self.tokens:
            return
        keys = [self.reg._sess(t) for t in self.tokens]
        if keys:
            self.reg.r.delete(*keys)
        for t in self.tokens:
            self.reg.r.zrem(self.reg._sessions(), t)
            for member, _ in list(self.reg.r.zscan_iter(self.reg._retired_key(), match=f"{t}|*")):
                self.reg.r.zrem(self.reg._retired_key(), member)

    def claim(self, token=None, gen="g1", sid="s1", uid=None):
        out = self.reg.claim_session(token, gen, sid, uid or self.uid, "pad")
        if out.get("token"):
            self.tokens.append(out["token"])
        return out

    def test_token_keyed_lifecycle(self):
        first = self.claim()
        token = first["token"]
        self.assertEqual(first["status"], "new")
        self.assertEqual(self.claim(token, "g1", "s2")["status"], "replace")
        self.assertEqual(self.claim(token, "g2", "s3")["status"], "new")
        self.assertEqual(self.claim(token, "g1", "s4")["status"], "retired")
        self.assertIsNone(self.reg.take_session(token, "wrong-gen"))
        self.assertIsNone(self.reg.take_session("wrong", "g2"))
        self.assertEqual(self.reg.take_session(token, "g2")["sid"], "s3")

    def test_uid_alone_and_wrong_token_are_new_sessions(self):
        victim = self.claim()
        uid = self.uid
        other = self.claim()  # no token: independent session
        self.assertNotEqual(other["token"], victim["token"])
        wrong = self.claim("not-the-token")
        self.assertNotEqual(wrong["token"], victim["token"])
        # victim's hash stays exactly where it was
        rec = self.reg.r.hmget(self.reg._sess(victim["token"]), "sid", "gen")
        self.assertEqual(rec, ["s1", "g1"])

    def test_shared_ttl_live_tokenless_and_expired(self):
        first = self.claim()
        token = first["token"]
        # A tokenless new generation cannot touch the live token: it is a new session.
        tokenless = self.claim(gen="g2", sid="s2")
        self.assertNotEqual(tokenless["token"], token)
        # A live sync refreshes the one hash key carrying sid/gen/token.
        self.reg.r.pexpire(self.reg._sess(token), 100)
        self.assertEqual(self.claim(token, "g1", "s1")["status"], "current")
        self.assertGreater(self.reg.r.pttl(self.reg._sess(token)), 1000)
        # Real short TTL: after expiry the same token is a new session.
        self.reg.r.pexpire(self.reg._sess(token), 50)
        time.sleep(0.12)
        expired = self.claim(token, "g3", "s3")
        self.assertEqual(expired["status"], "new")
        self.assertNotEqual(expired["token"], token)

    def test_concurrent_same_token_one_owner_distinct_tokens(self):
        from concurrent.futures import ThreadPoolExecutor

        token = self.claim()["token"]
        gens = [f"r{i}" for i in range(24)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.claim(token, gens[i], f"rs{i}"), range(len(gens))))
        current = self.reg.r.hmget(self.reg._sess(token), "gen", "sid")
        self.assertIn(current[0], gens)
        other = self.claim()
        self.assertNotEqual(other["token"], token)
        self.assertTrue(self.reg.r.exists(self.reg._sess(other["token"])))

    def test_capacity_eviction_is_token_only(self):
        self.reg.MAX_SESSIONS = 2
        a = self.claim(sid="sa")
        b = self.claim(sid="sb")
        c = self.claim(sid="sc")
        self.assertNotEqual(a["token"], b["token"])
        self.assertNotEqual(b["token"], c["token"])
        self.assertIn("sa", c["evicted"])
        self.assertFalse(self.reg.r.exists(self.reg._sess(a["token"])))
        self.assertTrue(self.reg.r.exists(self.reg._sess(b["token"])))


if __name__ == "__main__":
    unittest.main()
