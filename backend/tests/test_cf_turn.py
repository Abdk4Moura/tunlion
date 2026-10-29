"""Cloudflare TURN entries in /api/config, next to coturn.

Pins the filtering (no STUN, no port 53), the shared-credential cache, and that
a failed mint leaves the config without a CF entry instead of failing it.

Run:  python -m unittest backend.tests.test_cf_turn
"""
import os
import sys
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("FIL_SECRET", "cf-turn-test")
os.environ.setdefault("FIL_DEV", "1")

import config  # noqa: E402

CF_REPLY = {"iceServers": [
    {"urls": ["stun:stun.cloudflare.com:3478", "stun:stun.cloudflare.com:53"]},
    {"urls": [
        "turn:turn.cloudflare.com:3478?transport=udp",
        "turn:turn.cloudflare.com:53?transport=udp",
        "turn:turn.cloudflare.com:3478?transport=tcp",
        "turn:turn.cloudflare.com:80?transport=tcp",
        "turns:turn.cloudflare.com:5349?transport=tcp",
        "turns:turn.cloudflare.com:443?transport=tcp",
    ], "username": "u", "credential": "c"},
]}


class CloudflareTurn(unittest.TestCase):
    def setUp(self):
        self.saved = (config.CF_TURN_KEY_ID, config.CF_TURN_API_TOKEN)
        config.CF_TURN_KEY_ID, config.CF_TURN_API_TOKEN = "kid", "tok"
        config._cf_turn_cache.update(servers=[], until=0.0)

    def tearDown(self):
        config.CF_TURN_KEY_ID, config.CF_TURN_API_TOKEN = self.saved
        config._cf_turn_cache.update(servers=[], until=0.0)

    def test_entries_keep_turn_and_drop_stun_and_port_53(self):
        out = config._cf_turn_entries(CF_REPLY["iceServers"])
        self.assertEqual(out, [{"urls": [
            "turn:turn.cloudflare.com:3478?transport=udp",
            "turn:turn.cloudflare.com:3478?transport=tcp",
            "turn:turn.cloudflare.com:80?transport=tcp",
            "turns:turn.cloudflare.com:5349?transport=tcp",
            "turns:turn.cloudflare.com:443?transport=tcp",
        ], "username": "u", "credential": "c"}])

    def test_credentials_are_reused_until_half_the_ttl(self):
        calls = []

        def fetch():
            calls.append(1)
            return config._cf_turn_entries(CF_REPLY["iceServers"])

        first = config._cf_turn_servers(now=1000.0, fetch=fetch)
        config._cf_turn_servers(now=1000.0 + config.TURN_TTL / 2 - 1, fetch=fetch)
        self.assertEqual(len(calls), 1)
        config._cf_turn_servers(now=1000.0 + config.TURN_TTL / 2, fetch=fetch)
        self.assertEqual(len(calls), 2)
        self.assertEqual(first[0]["username"], "u")

    def test_a_failed_mint_yields_no_entry_and_retries_later(self):
        def boom():
            raise OSError("cloudflare unreachable")

        self.assertEqual(config._cf_turn_servers(now=1000.0, fetch=boom), [])
        ok = lambda: config._cf_turn_entries(CF_REPLY["iceServers"])  # noqa: E731
        self.assertEqual(config._cf_turn_servers(now=1000.0 + 1, fetch=ok), [])
        self.assertEqual(
            len(config._cf_turn_servers(now=1000.0 + config.CF_TURN_RETRY, fetch=ok)), 1)

    def test_unconfigured_means_no_entry_and_no_call(self):
        config.CF_TURN_KEY_ID = None
        self.assertEqual(config._cf_turn_servers(fetch=lambda: 1 / 0), [])


class CloudflareTurnRequest(unittest.TestCase):
    def test_the_mint_request_does_not_send_urllibs_default_user_agent(self):
        import io
        import json
        import urllib.request

        seen = {}

        def fake_urlopen(req, timeout):
            seen["ua"] = req.get_header("User-agent")
            return io.BytesIO(json.dumps(CF_REPLY).encode())

        saved = urllib.request.urlopen
        urllib.request.urlopen = fake_urlopen
        try:
            out = config._cf_turn_fetch()
        finally:
            urllib.request.urlopen = saved
        self.assertTrue(seen["ua"])
        self.assertNotIn("Python-urllib", seen["ua"])
        self.assertEqual(len(out), 1)


if __name__ == "__main__":
    unittest.main()
