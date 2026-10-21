"""Concurrency guard for the in-process sliding-window limiter.

The relay runs Flask-SocketIO with async_mode=threading, so allow() is entered
from many request threads. A check-then-charge sequence without a lock can let
two threads both pass the last slot. This test hammers one key from many
threads and requires exactly `limit` admissions.

Run:  python -m unittest backend.tests.test_ratelimit
"""
import sys
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ratelimit  # noqa: E402


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


if __name__ == "__main__":
    unittest.main()
