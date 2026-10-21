"""Concurrency guards for the rate limiters.

The relay runs Flask-SocketIO with async_mode=threading, so allow() is entered
from many request threads; with Redis it is entered from many replicas too. A
check-then-charge sequence without atomicity can let two callers both pass the
last slot. The Mem test is always run; the Redis test uses a real server when
FIL_TEST_REDIS_URL is set (CI supplies one).

Run:  python -m unittest backend.tests.test_ratelimit
"""
import os
import sys
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ratelimit  # noqa: E402

REDIS_URL = os.environ.get("FIL_TEST_REDIS_URL", "")


class MemLimiterConcurrency(unittest.TestCase):
    def test_concurrent_calls_admit_exactly_the_limit(self):
        limiter = ratelimit.MemLimiter(limit=10, window=60)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: limiter.allow(["one-key"], now=0.0), range(200)))
        self.assertEqual(sum(1 for r in results if r), 10)
        self.assertFalse(limiter.allow(["one-key"], now=0.0))

    def test_keys_are_charged_together(self):
        limiter = ratelimit.MemLimiter(limit=1, window=60)
        self.assertTrue(limiter.allow(["a", "b"], now=0.0))
        self.assertFalse(limiter.allow(["a"], now=0.0))
        self.assertFalse(limiter.allow(["b"], now=0.0))


@unittest.skipUnless(REDIS_URL, "FIL_TEST_REDIS_URL not set (real Redis required for Lua)")
class RedisLimiterConcurrency(unittest.TestCase):
    def test_concurrent_calls_admit_exactly_the_limit(self):
        import redis

        r = redis.Redis.from_url(REDIS_URL, decode_responses=True)
        name = "test-" + uuid.uuid4().hex
        limiter = ratelimit.RedisLimiter(r, name, limit=10, window=60)
        with ThreadPoolExecutor(max_workers=16) as pool:
            results = list(pool.map(lambda _: limiter.allow(["one-key"], now=0.0), range(200)))
        self.assertEqual(sum(1 for r in results if r), 10)
        self.assertFalse(limiter.allow(["one-key"], now=0.0))
        for key in r.keys(f"filament:rl:{name}:*"):
            r.delete(key)


if __name__ == "__main__":
    unittest.main()
