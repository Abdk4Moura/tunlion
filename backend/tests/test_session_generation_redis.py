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
        # Closed token reattaches with the SAME token; its old generation stays retired.
        reattach = self.claim(token, "g3", "s3b")
        self.assertEqual((reattach["status"], reattach["token"]), ("new", token))
        self.assertEqual(self.claim(token, "g2", "s3c")["status"], "retired")
        tokenless = self.claim(gen="g4", sid="s4")
        self.assertNotEqual(tokenless["token"], token)

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

    def test_retired_cap_is_global_and_does_not_refuse_owner(self):
        self.reg.MAX_RETIRED_TOTAL = 8
        token = self.claim(gen="g0", sid="s0")["token"]
        statuses = []
        for i in range(1, 21):
            statuses.append(self.claim(token, f"g{i}", f"s{i}")["status"])
        self.assertNotIn("capacity", statuses)
        self.assertNotIn("denied", statuses)
        self.assertLessEqual(self.reg.r.zcard(self.reg._retired_key()), 8)
        self.assertTrue(self.reg.r.zscore(self.reg._retired_key(), f"{token}|g19"))
        self.assertIsNone(self.reg.r.zscore(self.reg._retired_key(), f"{token}|g20"))

    def test_zset_ttl_and_closed_score_refresh(self):
        token = self.claim(gen="g1", sid="s1")["token"]
        self.reg.take_session(token, "g1")
        self.assertGreater(self.reg.r.ttl(self.reg._sessions()), 0)
        score = self.reg.r.zscore(self.reg._sessions(), token)
        self.assertIsNotNone(score)
        # A stale ZSET score must not prune the closed (valid) record; the
        # hash TTL, not the score, decides expiry.
        self.reg.r.zadd(self.reg._sessions(), {token: time.time() - 2 * self.reg.SESSION_TTL})
        self.claim(gen="g1", sid="s-new")
        reattach = self.claim(token, "g2", "s2")
        self.assertEqual((reattach["status"], reattach["token"]), ("new", token))

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
        self.assertEqual(c["status"], "capacity")
        self.assertIsNone(c["token"])
        self.assertTrue(self.reg.r.exists(self.reg._sess(a["token"])))
        self.assertTrue(self.reg.r.exists(self.reg._sess(b["token"])))
        # Closing a record makes room; a live record is still never evicted.
        self.reg.take_session(a["token"], "g1")
        d = self.claim(sid="sd")
        self.assertEqual(d["status"], "new")
        self.assertFalse(self.reg.r.exists(self.reg._sess(a["token"])))
        self.assertTrue(self.reg.r.exists(self.reg._sess(b["token"])))


if __name__ == "__main__":
    unittest.main()
