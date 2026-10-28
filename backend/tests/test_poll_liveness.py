"""Polling liveness: a long-polling client that stops polling is closed in
seconds, one that keeps polling is never closed, and websocket sockets are not
touched.

Two layers:
  * poll_check over fake sockets and a fake clock (the rule itself);
  * the real Flask app on a real HTTP server, driven by a raw engine.io v4
    long-polling client, so the WSGI middleware, the NOOP cycling and the
    disconnect path are exercised end to end with the ping timeout set far
    out of reach (120 s), as in production terms.

Run:  python -m unittest backend.tests.test_poll_liveness
"""
import http.client
import importlib.util
import json
import os
import sys
import threading
import time
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

HOLD, GRACE, TICK = 1.0, 2.0, 0.2
os.environ.setdefault("FIL_SECRET", "poll-liveness-test")
os.environ.setdefault("FIL_DEV", "1")
os.environ.setdefault("FIL_CORS_ORIGINS", "*")
os.environ["FIL_POLL_HOLD_S"] = str(HOLD)
os.environ["FIL_POLL_GRACE_S"] = str(GRACE)
os.environ["FIL_POLL_TICK_S"] = str(TICK)
os.environ["FIL_PING_TIMEOUT"] = "120"
os.environ["FIL_PING_INTERVAL"] = "25"

import signaling  # noqa: E402


class FakeClock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


class FakeSock:
    def __init__(self):
        self.closed = self.closing = self.upgraded = self.upgrading = False
        self.sent = []
        self.close_calls = []

    def send(self, pkt):
        self.sent.append(pkt.packet_type)

    def close(self, wait=True, abort=False, reason=None):
        self.close_calls.append((wait, abort))
        self.closed = True


class FakeEio:
    def __init__(self):
        self.sockets = {}


class PollRule(unittest.TestCase):
    def setUp(self):
        self.clock = FakeClock()
        self.watch = signaling.PollWatch(None, clock=self.clock)
        self.eio = FakeEio()
        self.sock = self.eio.sockets["e1"] = FakeSock()

    def check(self):
        return signaling.poll_check(self.eio, self.watch, HOLD, GRACE)

    def test_a_held_get_is_cycled_once_then_a_silent_client_is_closed(self):
        from engineio import packet

        self.watch.begin("e1")
        self.clock.t += HOLD - 0.1
        self.assertEqual(self.check(), [])
        self.assertEqual(self.sock.sent, [])
        self.clock.t += 0.2
        self.assertEqual(self.check(), [])
        self.assertEqual(self.sock.sent, [packet.NOOP])
        self.clock.t += 5
        self.check()
        self.assertEqual(self.sock.sent, [packet.NOOP], "one NOOP per held GET")
        # The NOOP ends the GET; the client never polls again.
        self.watch.end("e1")
        self.clock.t += GRACE - 0.1
        self.assertEqual(self.check(), [])
        self.clock.t += 0.2
        self.assertEqual(self.check(), ["e1"])
        self.assertEqual(self.sock.close_calls, [(False, True)])
        self.assertIsNone(self.watch.state("e1"))

    def test_a_client_that_keeps_polling_is_never_closed(self):
        for _ in range(200):
            self.watch.begin("e1")
            self.clock.t += HOLD + 0.5
            self.check()
            self.watch.end("e1")
            self.clock.t += GRACE - 0.5  # a slow round trip, inside the grace
            self.assertEqual(self.check(), [])
        self.assertEqual(self.sock.close_calls, [])

    def test_upgraded_sockets_are_forgotten_and_upgrading_ones_left_alone(self):
        self.watch.begin("e1")
        self.watch.end("e1")
        self.sock.upgrading = True
        self.clock.t += GRACE * 10
        self.assertEqual(self.check(), [])
        self.assertEqual(self.sock.close_calls, [])
        self.sock.upgrading = False
        self.sock.upgraded = True
        self.assertEqual(self.check(), [])
        self.assertIsNone(self.watch.state("e1"))
        self.assertEqual(self.sock.close_calls, [])

    def test_unknown_or_closed_sockets_are_dropped(self):
        self.watch.begin("gone")
        self.watch.end("gone")
        self.clock.t += GRACE * 10
        self.assertEqual(self.check(), [])
        self.assertIsNone(self.watch.state("gone"))

    def test_only_polling_gets_with_a_sid_are_recorded(self):
        seen = []
        w = signaling.PollWatch(lambda env, sr: seen.append(w.sids()) or [b""], clock=self.clock)
        base = {"REQUEST_METHOD": "GET", "PATH_INFO": "/socket.io/"}
        w(dict(base, QUERY_STRING="EIO=4&transport=polling"), None)  # handshake
        w(dict(base, QUERY_STRING="EIO=4&transport=websocket&sid=abc"), None)
        w(dict(base, REQUEST_METHOD="POST", QUERY_STRING="EIO=4&transport=polling&sid=abc"), None)
        w(dict(base, PATH_INFO="/api/room", QUERY_STRING="transport=polling&sid=abc"), None)
        self.assertEqual(w.sids(), [])
        w(dict(base, QUERY_STRING="EIO=4&transport=polling&t=x&sid=abc"), None)
        self.assertEqual(seen[-1], ["abc"], "in flight while the app holds it")
        inflight, _age, _c = w.state("abc")
        self.assertEqual(inflight, 0, "ended when the app returns")


# -- end to end: real app, real HTTP, raw engine.io long-polling ------------

_spec = importlib.util.spec_from_file_location("tunlion_poll_app", BACKEND / "app.py")
api = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(api)


class RawPoller:
    """A minimal engine.io v4 long-polling client (no websocket)."""

    def __init__(self, port):
        self.port = port
        body = self._req("GET", "/socket.io/?EIO=4&transport=polling")
        assert body.startswith("0"), body
        self.sid = json.loads(body[1:])["sid"]
        self._req("POST", self._q(), "40")
        self.stop = threading.Event()
        self.gets = 0
        self.packets = []

    def _q(self):
        return f"/socket.io/?EIO=4&transport=polling&sid={self.sid}"

    def _req(self, method, path, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request(method, path, body=body, headers={"Content-Type": "text/plain;charset=UTF-8"})
        r = c.getresponse()
        data = r.read().decode()
        c.close()
        if r.status != 200:
            raise OSError(f"{method} {r.status} {data[:80]}")
        return data

    def emit(self, event, payload):
        self._req("POST", self._q(), "42" + json.dumps([event, payload]))

    def run(self, delay=0.0):
        """Poll until stopped, answering pings; `delay` slows each re-poll."""
        while not self.stop.is_set():
            try:
                data = self._req("GET", self._q())
            except OSError:
                return
            self.gets += 1
            for pkt in data.split("\x1e"):
                self.packets.append(pkt[:1])
                if pkt == "2":
                    self._req("POST", self._q(), "3")
            if delay:
                time.sleep(delay)


class PollEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from werkzeug.serving import make_server

        cls.srv = make_server("127.0.0.1", 0, api.app, threaded=True)
        cls.port = cls.srv.server_port
        cls.th = threading.Thread(target=cls.srv.serve_forever, daemon=True)
        cls.th.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def alive(self, p):
        s = api.socketio.server.eio.sockets.get(p.sid)
        return s is not None and not s.closed

    def test_a_polling_client_that_goes_silent_is_closed_and_leaves_the_room(self):
        a, b = RawPoller(self.port), RawPoller(self.port)
        ta = threading.Thread(target=a.run, daemon=True)
        tb = threading.Thread(target=b.run, daemon=True)
        ta.start()
        tb.start()
        a.emit("join", {"room": "poll-e2e", "name": "a", "uid": "u-poll-a"})
        b.emit("join", {"room": "poll-e2e", "name": "b", "uid": "u-poll-b"})
        time.sleep(HOLD * 4 + GRACE)  # well past HOLD + GRACE while polling
        self.assertTrue(self.alive(a) and self.alive(b), "a polling client was closed")
        self.assertIn("6", a.packets, "a held GET was not cycled with a NOOP")
        self.assertEqual(len(api.REGISTRY.peers_in("poll-e2e")), 2)

        # b dies without a word: it just stops polling (its held GET is left
        # for the server to answer into the void).
        b.stop.set()
        t0 = time.monotonic()
        while self.alive(b) and time.monotonic() - t0 < 30:
            time.sleep(0.05)
        took = time.monotonic() - t0
        self.assertFalse(self.alive(b), "a silent polling client stayed open 30 s")
        bound = HOLD + GRACE + 2 * TICK + 1.0
        self.assertLessEqual(took, bound, f"closed after {took:.1f}s, want <= {bound:.1f}s")
        names = [p["name"] for p in api.REGISTRY.peers_in("poll-e2e")]
        self.assertEqual(names, ["a"], "the silent client is still in the room")
        self.assertTrue(self.alive(a))
        a.stop.set()

    def test_a_slow_poller_inside_the_grace_is_kept(self):
        p = RawPoller(self.port)
        th = threading.Thread(target=p.run, kwargs={"delay": GRACE * 0.6}, daemon=True)
        th.start()
        t0 = time.monotonic()
        while time.monotonic() - t0 < GRACE * 5:
            self.assertTrue(self.alive(p), "a slow but live poller was closed")
            time.sleep(0.1)
        self.assertGreater(p.gets, 3)
        p.stop.set()


if __name__ == "__main__":
    unittest.main()
