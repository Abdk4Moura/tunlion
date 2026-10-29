"""HTTP-level tests for GET /health (readiness) and GET /api/health (liveness).

/health must be an explicit route: it never falls through to the SPA fallback,
so it answers even when frontend/dist is absent (the split deploy). It returns
503 only when a configured Redis does not answer a PING.

The live states (real Redis up, Redis unreachable) are proven against a running
server in the PR description; these tests pin the routing and the status
mapping without a network dependency.

Run:  python -m unittest backend.tests.test_health_http
"""
import importlib.util
import os
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("FIL_SECRET", "health-http-test")
os.environ.setdefault("FIL_DEV", "1")
os.environ.setdefault("FIL_CORS_ORIGINS", "*")

import config  # noqa: E402

config.SECRET = config.SECRET or "health-http-test"
config.DEV = True
config.CORS_ALLOWED_ORIGINS = config.CORS_ALLOWED_ORIGINS or "*"

_spec = importlib.util.spec_from_file_location("tunlion_health_app", BACKEND / "app.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class _UpRedis:
    def ping(self):
        return True


class _DownRedis:
    def ping(self):
        raise ConnectionError("Error 111 connecting to 10.0.0.1:6379. Connection refused.")


class HealthHTTP(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.old_redis = api._HEALTH_REDIS
        self.old_dist = api.DIST_DIR
        # Point the SPA at a directory with no build, as in the split deploy.
        api.DIST_DIR = str(BACKEND / "tests" / "no-such-dist")

    def tearDown(self):
        api._HEALTH_REDIS = self.old_redis
        api.DIST_DIR = self.old_dist

    def test_spa_fallback_still_503_without_build(self):
        # Guard for the premise: an unknown path does hit the SPA fallback.
        self.assertEqual(self.client.get("/not-a-route").status_code, 503)

    def test_health_ok_without_redis_or_build(self):
        api._HEALTH_REDIS = None
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"ok": True, "redis": "not-configured"})

    def test_health_ok_when_redis_answers(self):
        api._HEALTH_REDIS = _UpRedis()
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"ok": True, "redis": "up"})

    def test_health_503_when_redis_down_and_no_detail_leaks(self):
        api._HEALTH_REDIS = _DownRedis()
        r = self.client.get("/health")
        self.assertEqual(r.status_code, 503)
        self.assertEqual(r.get_json(), {"ok": False, "redis": "down"})
        self.assertNotIn(b"10.0.0.1", r.data)

    def test_api_health_stays_liveness_only(self):
        api._HEALTH_REDIS = _DownRedis()
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
