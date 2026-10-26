"""The per-IP session-claim budget (FIL_SESSION_CLAIM_LIMIT, 600/min).

What the budget protects: a claim that is not a pure refresh can mint a token
session record (bounded by MAX_SESSIONS; the capacity path evicts other
callers' non-live sessions and then refuses everyone), add a retired-generation
tombstone (MAX_RETIRED_TOTAL is a global FIFO, so a flood ages out other
tokens' tombstones), or move a session onto another socket. One address must
not be able to do those faster than the budget.

What it must NOT do: cap how many devices can sit behind one public IP. A CLI
daemon full-syncs every 30 s, so when every sync was charged, 600/min held only
about 300 devices behind an office, campus or carrier NAT, and the rest were
refused with session-superseded {reason: rate-limited}.

A fake clock drives every limiter so windows are deterministic. All test
clients share one address (asserted), exactly the NAT case.

Run:  python -m unittest backend.tests.test_session_claim_limit
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import ratelimit  # noqa: E402
import signaling  # noqa: E402


class _Clock:
    def __init__(self):
        self.t = 10_000.0


def _make(limit=None):
    """A relay whose limiters read a fake clock and record the keys charged."""
    from flask import Flask
    from flask_socketio import SocketIO

    clock = _Clock()
    seen = {"ip": set()}

    def factory(name, lim, window, redis_client=None):
        inner = ratelimit.MemLimiter(lim, window)

        class _Clocked:
            def allow(self, keys, now=None):
                for k in keys:
                    if k.startswith("ip:"):
                        seen["ip"].add(k)
                return inner.allow(keys, now=clock.t)

        return _Clocked()

    old = os.environ.get("FIL_SESSION_CLAIM_LIMIT")
    if limit is None:
        os.environ.pop("FIL_SESSION_CLAIM_LIMIT", None)
    else:
        os.environ["FIL_SESSION_CLAIM_LIMIT"] = str(limit)
    try:
        app = Flask(__name__)
        sio = SocketIO(app, async_mode="threading")
        reg = signaling._MemRegistry()
        with mock.patch.object(ratelimit, "make_limiter", factory):
            signaling.register(sio, reg)
    finally:
        if old is None:
            os.environ.pop("FIL_SESSION_CLAIM_LIMIT", None)
        else:
            os.environ["FIL_SESSION_CLAIM_LIMIT"] = old
    return app, sio, reg, clock, seen


def _client(app, sio):
    c = sio.test_client(app)
    c.get_received()
    return c


def _cli_sync(c, room, i):
    """Exactly what the Rust daemon sends (filament-peerloop session.rs
    sync_payload): no gen and no token."""
    return c.emit("sync", {"v": 1, "room": room, "name": f"dev-{i}", "uid": f"uid-{i}",
                           "channels": []}, callback=True)


def _browser_sync(c, room, i, gen, token=None):
    p = {"v": 1, "room": room, "name": f"tab-{i}", "uid": f"tab-uid-{i}", "gen": gen,
         "channels": []}
    if token:
        p["token"] = token
    return c.emit("sync", p, callback=True)


def _rate_limited(c):
    return [ev for ev in c.get_received()
            if ev["name"] == "session-superseded"
            and (ev["args"][0] or {}).get("reason") == "rate-limited"]


class _Quiet(unittest.TestCase):
    def setUp(self):
        # Thousands of TEL lines would bury the result; telemetry is not
        # what these tests check.
        patcher = mock.patch.object(signaling, "_tel", lambda *a, **k: None)
        patcher.start()
        self.addCleanup(patcher.stop)


class ManyDevicesBehindOneIp(_Quiet):
    """(a) About 1000 devices behind one IP keep syncing at the default limit."""

    N = 1000

    def test_1000_cli_daemons_keep_syncing(self):
        app, sio, reg, clock, seen = _make()  # default 600/min
        clients = []
        # Devices come up over a few minutes, never 600 brand-new sessions in
        # one minute from one address (that IS the abuse the budget refuses).
        for i in range(self.N):
            if i and i % 500 == 0:
                clock.t += 61
            c = _client(app, sio)
            ack = _cli_sync(c, f"solo-{i}", i)
            self.assertTrue(ack["ok"], f"device {i} first sync")
            clients.append(c)
        self.assertEqual(len(seen["ip"]), 1, "every client shares one address")
        self.assertEqual(len(reg._sessions), self.N)
        # Ten 30 s rounds: 1000 claims every 30 s is 2000/min against a
        # 600/min budget. Before the fix, round 1 already refused ~400.
        for rnd in range(10):
            clock.t += 30
            for i, c in enumerate(clients):
                ack = _cli_sync(c, f"solo-{i}", i)
                self.assertTrue(ack["ok"], f"round {rnd} device {i}: {ack}")
                self.assertEqual(_rate_limited(c), [], f"round {rnd} device {i}")
        # And the daemon's socket kept ONE session: a tokenless sync no longer
        # mints a fresh session record every 30 s.
        self.assertEqual(len(reg._sessions), self.N)

    def test_1000_browser_tabs_keep_syncing(self):
        app, sio, reg, clock, seen = _make()
        tabs = []
        for i in range(self.N):
            if i and i % 500 == 0:
                clock.t += 61
            c = _client(app, sio)
            ack = _browser_sync(c, f"room-{i % 50}", i, f"g-{i}")
            self.assertTrue(ack["ok"])
            tabs.append((c, ack["token"], ack["gen"]))
        self.assertEqual(len(seen["ip"]), 1)
        for rnd in range(4):
            clock.t += 5
            for i, (c, token, gen) in enumerate(tabs):
                ack = _browser_sync(c, f"room-{i % 50}", i, gen, token)
                self.assertTrue(ack["ok"], f"round {rnd} tab {i}: {ack}")
        self.assertEqual(len(reg._sessions), self.N)


class ClaimFloodsStillLimited(_Quiet):
    """(b) Anything that creates or takes over a session stays charged per IP."""

    LIMIT = 20

    def setUp(self):
        super().setUp()
        self.app, self.sio, self.reg, self.clock, self.seen = _make(self.LIMIT)

    def _fresh(self):
        return _client(self.app, self.sio)

    def test_tokenless_join_flood_is_limited(self):
        ok = limited = 0
        for i in range(self.LIMIT + 15):
            c = self._fresh()
            c.emit("join", {"room": "r", "name": f"n{i}", "uid": f"u{i}"})
            names = [ev["name"] for ev in c.get_received()]
            if "welcome" in names:
                ok += 1
            if "session-superseded" in names:
                limited += 1
        self.assertEqual((ok, limited), (self.LIMIT, 15))
        self.assertEqual(len(self.reg._sessions), self.LIMIT)

    def test_new_session_sync_flood_is_limited(self):
        # CLI-shaped and browser-shaped first syncs on fresh sockets both mint
        # a session, so both are charged to the IP.
        results = []
        for i in range(self.LIMIT + 10):
            c = self._fresh()
            ack = _cli_sync(c, "r", i) if i % 2 else _browser_sync(c, "r", i, f"g{i}")
            results.append(ack["ok"])
        self.assertEqual(results.count(True), self.LIMIT)
        self.assertEqual(len(self.reg._sessions), self.LIMIT)

    def test_generation_bump_flood_is_limited(self):
        owner = self._fresh()
        first = _browser_sync(owner, "r", 0, "g0")
        token = first["token"]
        oks = 0
        for i in range(1, self.LIMIT + 10):
            ack = _browser_sync(self._fresh(), "r", 0, f"g{i}", token)
            oks += bool(ack["ok"])
        self.assertEqual(oks, self.LIMIT - 1, "one IP budget covers the first claim too")
        self.assertLessEqual(len(self.reg._retired), self.LIMIT - 1, "tombstones bounded")

    def test_takeover_of_a_held_session_is_limited(self):
        # Same token and generation from a DIFFERENT socket is a replace
        # (it moves the session); it never qualifies as a refresh.
        owner = self._fresh()
        first = _browser_sync(owner, "r", 0, "g0")
        token, gen = first["token"], first["gen"]
        oks = 0
        for _ in range(self.LIMIT + 10):
            ack = _browser_sync(self._fresh(), "r", 0, gen, token)
            oks += bool(ack["ok"])
        self.assertEqual(oks, self.LIMIT - 1)

    def test_exhausted_ip_budget_refuses_everything_but_a_refresh(self):
        holder = self._fresh()
        first = _browser_sync(holder, "home", 0, "g0")
        token, gen = first["token"], first["gen"]
        daemon = self._fresh()
        self.assertTrue(_cli_sync(daemon, "solo", 1)["ok"])
        for i in range(self.LIMIT):  # burn the rest of the IP budget
            _cli_sync(self._fresh(), "x", 100 + i)
        # A fresh session from this address is refused now ...
        self.assertFalse(_cli_sync(self._fresh(), "x", 999)["ok"])
        # ... but sockets that already hold their session keep refreshing.
        self.assertTrue(_browser_sync(holder, "home", 0, gen, token)["ok"])
        self.assertTrue(_cli_sync(daemon, "solo", 1)["ok"])
        # A room change is a re-announce, not a refresh: charged, refused.
        self.assertFalse(_browser_sync(holder, "elsewhere", 0, gen, token)["ok"])
        # So is a generation bump by the holder itself.
        self.assertFalse(_browser_sync(holder, "home", 0, "g-next", token)["ok"])
        # And a join is never treated as a refresh.
        holder.get_received()
        holder.emit("join", {"room": "home", "name": "tab-0", "uid": "tab-uid-0",
                             "gen": gen, "token": token})
        self.assertTrue(_rate_limited(holder))
        # The next window restores the budget.
        self.clock.t += 61
        self.assertTrue(_cli_sync(self._fresh(), "x", 1000)["ok"])

    def test_refresh_is_still_bounded_per_socket(self):
        c = self._fresh()
        first = _browser_sync(c, "r", 0, "g0")
        token, gen = first["token"], first["gen"]
        oks = sum(bool(_browser_sync(c, "r", 0, gen, token)["ok"])
                  for _ in range(self.LIMIT + 5))
        self.assertEqual(oks, self.LIMIT - 1, "the sid key still charges every claim")

    def test_cli_socket_reuse_never_crosses_sockets(self):
        a = self._fresh()
        b = self._fresh()
        self.assertTrue(_cli_sync(a, "r", 1)["ok"])
        self.assertTrue(_cli_sync(b, "r", 2)["ok"])
        self.assertEqual(len(self.reg._sessions), 2, "each socket gets its own session")
        # Repeated syncs on each socket keep exactly those two sessions.
        for _ in range(3):
            self.assertTrue(_cli_sync(a, "r", 1)["ok"])
            self.assertTrue(_cli_sync(b, "r", 2)["ok"])
        self.assertEqual(len(self.reg._sessions), 2)
        a.disconnect()
        # A reconnect is a new socket, so a new session, and it is charged.
        c = self._fresh()
        self.assertTrue(_cli_sync(c, "r", 1)["ok"])
        self.assertEqual(len(self.reg._sessions), 3)


class MemHoldsSession(unittest.TestCase):
    """holds_session must agree with claim_session's "current" verdict
    (the Redis twin is in test_session_generation_redis)."""

    def test_holds_session_matches_the_current_claim(self):
        reg = signaling._MemRegistry()
        token = reg.claim_session(None, "g1", "s1", "u1", "pad")["token"]
        self.assertTrue(reg.holds_session(token, "g1", "s1"))
        self.assertEqual(reg.claim_session(token, "g1", "s1", "u1", "pad")["status"], "current")
        self.assertFalse(reg.holds_session(token, "g1", "s2"), "another sid is a takeover")
        self.assertFalse(reg.holds_session(token, "g2", "s1"), "another gen is a bump")
        self.assertFalse(reg.holds_session("not-the-token", "g1", "s1"))
        self.assertFalse(reg.holds_session(None, "g1", "s1"))
        self.assertEqual(reg.claim_session(token, "g2", "s1", "u1", "pad")["status"], "new")
        self.assertFalse(reg.holds_session(token, "g1", "s1"), "a retired gen is not held")
        reg.take_session(token, "g2")
        self.assertFalse(reg.holds_session(token, "g2", "s1"), "a closed session is not held")


if __name__ == "__main__":
    unittest.main()
