"""HTTP-level tests for POST /api/session/close.

Covers the close endpoint itself (not just the origin helper): default wildcard
CORS, explicit allowlist refusal, no-Origin beacons, a missing/wrong token, and
the rate-limiter gate. Uses the real Flask app with a Mem registry.

Run:  python -m unittest backend.tests.test_session_close_http
"""
import importlib.util
import os
import sys
import unittest
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("FIL_SECRET", "session-close-http-test")
os.environ.setdefault("FIL_DEV", "1")
os.environ.setdefault("FIL_CORS_ORIGINS", "*")

import config  # noqa: E402  (imported by earlier test modules in discover order)

config.SECRET = config.SECRET or "session-close-http-test"
config.DEV = True
config.CORS_ALLOWED_ORIGINS = config.CORS_ALLOWED_ORIGINS or "*"

_spec = importlib.util.spec_from_file_location("tunlion_http_app", BACKEND / "app.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class CloseEndpointHTTP(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()
        self.old_allowed = api._ALLOWED_ORIGINS
        self.old_limiter = api._close_limiter

    def tearDown(self):
        api._ALLOWED_ORIGINS = self.old_allowed
        api._close_limiter = self.old_limiter

    def _seed(self):
        uid = "http-" + uuid.uuid4().hex
        gen = "g-" + uuid.uuid4().hex
        sid = "s-" + uuid.uuid4().hex
        ack = api.REGISTRY.claim_session(uid, gen, sid)
        api.REGISTRY.add(sid, "r-http", "ipad", uid, gen)
        return uid, gen, sid, ack["token"]

    def _post(self, body, origin=None):
        headers = {"Origin": origin} if origin else {}
        return self.client.post("/api/session/close", json=body, headers=headers)

    def _owned(self, uid, gen):
        cur = api.REGISTRY.owned_uid(uid)
        return bool(cur and cur.get("gen") == gen)

    def test_missing_and_wrong_token_do_nothing(self):
        uid, gen, _sid, token = self._seed()
        self.assertEqual(self._post({"uid": uid, "gen": gen}).status_code, 204)
        self.assertEqual(self._post({"uid": uid, "gen": gen, "token": "wrong"}).status_code, 204)
        self.assertTrue(self._owned(uid, gen))
        self.assertEqual(self._post({"uid": uid, "gen": gen, "token": token}).status_code, 204)
        self.assertFalse(self._owned(uid, gen))

    def test_explicit_allowlist_refuses_evil_origin_but_allows_configured(self):
        api._ALLOWED_ORIGINS = ["https://app.example"]
        uid, gen, _sid, token = self._seed()
        self.assertEqual(self._post({"uid": uid, "gen": gen, "token": token},
                                    origin="https://evil.example").status_code, 204)
        self.assertTrue(self._owned(uid, gen))
        self.assertEqual(self._post({"uid": uid, "gen": gen, "token": token},
                                    origin="https://app.example").status_code, 204)
        self.assertFalse(self._owned(uid, gen))

    def test_default_wildcard_and_missing_origin(self):
        api._ALLOWED_ORIGINS = "*"
        uid, gen, _sid, token = self._seed()
        r = self._post({"uid": uid, "gen": gen, "token": token}, origin="https://evil.example")
        self.assertEqual(r.status_code, 204)
        self.assertEqual(r.headers.get("Access-Control-Allow-Origin"), "https://evil.example")
        self.assertFalse(self._owned(uid, gen))
        # No Origin at all (some sendBeacon paths) is accepted when the token
        # is valid; the bearer token, not the Origin, is the authority.
        uid2, gen2, _s2, token2 = self._seed()
        self.assertEqual(self._post({"uid": uid2, "gen": gen2, "token": token2}).status_code, 204)
        self.assertFalse(self._owned(uid2, gen2))

    def test_rate_limiter_gate_blocks_noop(self):
        class Closed:
            def allow(self, keys, now=None):
                return False

        api._close_limiter = Closed()
        uid, gen, _sid, token = self._seed()
        self.assertEqual(self._post({"uid": uid, "gen": gen, "token": token}).status_code, 204)
        self.assertTrue(self._owned(uid, gen))


if __name__ == "__main__":
    unittest.main()
