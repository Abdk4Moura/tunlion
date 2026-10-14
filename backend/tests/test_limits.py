"""Hardening tests: who the caller is, how often they may act, whom they may
signal, and that the server refuses to run on the public dev secret.

Run:  python -m pytest backend/tests -q
"""
import importlib
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import config  # noqa: E402
import ratelimit  # noqa: E402
import signaling  # noqa: E402


class _Env:
    """Temporarily set/unset environment variables."""

    def __init__(self, **kv):
        self.kv = kv
        self.old = {}

    def __enter__(self):
        for k, v in self.kv.items():
            self.old[k] = os.environ.get(k)
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return self

    def __exit__(self, *exc):
        for k, v in self.old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _make(**env):
    from flask import Flask
    from flask_socketio import SocketIO

    with _Env(**env):
        app = Flask(__name__)
        sio = SocketIO(app, async_mode="threading")
        reg = signaling._MemRegistry()
        signaling.register(sio, reg)
    return app, sio, reg


def _client(app, sio):
    c = sio.test_client(app)
    c.get_received()
    return c


def _names(received):
    return [ev["name"] for ev in received]


class IpBucket(unittest.TestCase):
    def test_ipv6_counts_per_64(self):
        a = ratelimit.ip_bucket("2001:db8:1:2::1")
        b = ratelimit.ip_bucket("2001:db8:1:2:ffff:ffff:ffff:ffff")
        c = ratelimit.ip_bucket("2001:db8:1:3::1")
        self.assertEqual(a, b, "one /64 is one bucket")
        self.assertNotEqual(a, c)

    def test_ipv4_counts_per_address(self):
        self.assertNotEqual(ratelimit.ip_bucket("198.51.100.1"), ratelimit.ip_bucket("198.51.100.2"))
        self.assertEqual(ratelimit.ip_bucket("::ffff:198.51.100.1"), ratelimit.ip_bucket("198.51.100.1"))


class ClientIp(unittest.TestCase):
    def _ip(self, trusted, remote, headers):
        from flask import Flask, request

        app = Flask(__name__)
        old = config.TRUSTED_PROXIES
        config.TRUSTED_PROXIES = trusted
        try:
            with app.test_request_context("/", headers=headers, environ_base={"REMOTE_ADDR": remote}):
                return ratelimit.client_ip(request)
        finally:
            config.TRUSTED_PROXIES = old

    def test_cf_header_ignored_from_untrusted_peer(self):
        ip = self._ip([], "203.0.113.9", {"CF-Connecting-IP": "198.51.100.77"})
        self.assertEqual(ip, "203.0.113.9", "a forged header must not choose the key")

    def test_cf_header_honoured_from_trusted_proxy(self):
        nets = config._trusted_proxies("172.16.0.0/12")
        ip = self._ip(nets, "172.18.0.5", {"CF-Connecting-IP": "198.51.100.77"})
        self.assertEqual(ip, "198.51.100.77")
        ip = self._ip("*", "10.0.0.1", {"CF-Connecting-IP": "198.51.100.78"})
        self.assertEqual(ip, "198.51.100.78")

    def test_peer_outside_the_trusted_cidr_is_not_trusted(self):
        nets = config._trusted_proxies("172.16.0.0/12")
        ip = self._ip(nets, "203.0.113.9", {"CF-Connecting-IP": "198.51.100.77"})
        self.assertEqual(ip, "203.0.113.9")


class MemLimiterBehaviour(unittest.TestCase):
    def test_limit_window_and_all_keys(self):
        lim = ratelimit.MemLimiter(limit=2, window=60)
        self.assertTrue(lim.allow(["sid:a", "ip:x"], now=0))
        self.assertTrue(lim.allow(["sid:b", "ip:x"], now=1))
        self.assertFalse(lim.allow(["sid:c", "ip:x"], now=2), "the shared ip key is spent")
        self.assertTrue(lim.allow(["sid:c", "ip:x"], now=62), "the window slides")

    def test_idle_keys_are_evicted_and_the_map_is_bounded(self):
        lim = ratelimit.MemLimiter(limit=5, window=10, max_keys=100)
        for i in range(1000):
            lim.allow([f"ip:{i}"], now=float(i))
        self.assertLessEqual(len(lim), 100, "rotating keys cannot grow the map without bound")
        lim._sweep(10_000.0)
        self.assertEqual(len(lim), 0, "keys idle for a full window are dropped")


class PairCreateLimit(unittest.TestCase):
    def test_pair_create_is_rate_limited(self):
        app, sio, _ = _make(FIL_PAIR_CREATE_LIMIT="3", FIL_CLAIM_LIMIT="5")
        c = _client(app, sio)
        c.emit("join", {"room": "r", "name": "a"})
        c.get_received()
        outcomes = []
        for n in range(5):
            c.emit("pair-create", {"v": 2, "nameplate": str(100 + n)})
            outcomes.append(_names(c.get_received()))
        self.assertEqual(outcomes[:3], [["pair-ok"]] * 3)
        self.assertEqual(outcomes[3:], [["pair-error"]] * 2)

    def test_default_create_limit_follows_a_lifted_claim_limit(self):
        app, sio, _ = _make(FIL_PAIR_CREATE_LIMIT=None, FIL_CLAIM_LIMIT="1000000")
        c = _client(app, sio)
        for n in range(40):
            c.emit("pair-create", {"v": 2, "nameplate": str(1000 + n)})
            self.assertEqual(_names(c.get_received()), ["pair-ok"], "fixtures lift both limits")


class SignalScope(unittest.TestCase):
    def setUp(self):
        self.app, self.sio, self.reg = _make()

    def test_signal_reaches_same_room_only(self):
        a, b, z = (_client(self.app, self.sio) for _ in range(3))
        a.emit("join", {"room": "r1", "name": "a"})
        b.emit("join", {"room": "r1", "name": "b"})
        z.emit("join", {"room": "r2", "name": "z"})
        welcome_b = [e for e in b.get_received() if e["name"] == "welcome"][0]
        welcome_z = [e for e in z.get_received() if e["name"] == "welcome"][0]
        a.get_received()
        b_sid = welcome_b["args"][0]["id"]
        z_sid = welcome_z["args"][0]["id"]

        a.emit("signal", {"to": b_sid, "data": {"sdp": "hi"}})
        self.assertIn("signal", _names(b.get_received()), "same room: delivered")

        a.emit("signal", {"to": z_sid, "data": {"sdp": "inject"}})
        self.assertNotIn("signal", _names(z.get_received()), "other room, no channel: refused")

    def test_signal_reaches_a_shared_channel_across_rooms(self):
        ch = "c" * 64
        a, z = _client(self.app, self.sio), _client(self.app, self.sio)
        a.emit("sync", {"room": "r1", "name": "a", "channels": [ch]}, callback=True)
        ack = z.emit("sync", {"room": "r2", "name": "z", "channels": [ch]}, callback=True)
        a.get_received()
        z.get_received()
        a_sid = ack["channel_peers"][0]["id"]
        z.emit("signal", {"to": a_sid, "data": {"sdp": "known peer"}})
        self.assertIn("signal", _names(a.get_received()), "paired devices signal across rooms")

    def test_signal_without_a_room_is_dropped(self):
        a, b = _client(self.app, self.sio), _client(self.app, self.sio)
        b.emit("join", {"room": "r1", "name": "b"})
        b_sid = [e for e in b.get_received() if e["name"] == "welcome"][0]["args"][0]["id"]
        a.emit("signal", {"to": b_sid, "data": {}})
        self.assertNotIn("signal", _names(b.get_received()))


class SecretRequired(unittest.TestCase):
    def _reload(self, **env):
        with _Env(**env):
            return importlib.reload(config)

    def tearDown(self):
        importlib.reload(config)

    def test_unset_secret_fails_outside_dev(self):
        cfg = self._reload(FIL_SECRET=None, FIL_DEV=None)
        with self.assertRaises(RuntimeError):
            cfg.ensure_secret(dev_entrypoint=False)

    def test_dev_flag_or_dev_server_allows_the_dev_default(self):
        cfg = self._reload(FIL_SECRET=None, FIL_DEV="1")
        self.assertEqual(cfg.ensure_secret(), cfg.DEV_SECRET)
        cfg = self._reload(FIL_SECRET=None, FIL_DEV=None)
        self.assertEqual(cfg.ensure_secret(dev_entrypoint=True), cfg.DEV_SECRET)

    def test_a_set_secret_is_used(self):
        cfg = self._reload(FIL_SECRET="s3cret-for-test", FIL_DEV=None)
        self.assertEqual(cfg.ensure_secret(), "s3cret-for-test")


if __name__ == "__main__":
    unittest.main()
