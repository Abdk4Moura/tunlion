"""A room `join` must not drop the socket's channel subscriptions.

Browsers send a legacy `join` right after their first `sync`. The join used to
run the full departure path (`_do_leave` -> `_channel_goodbye`), which
unsubscribed every known-device channel: the remembered device then went unseen
until the client's next re-sync, about 30 s later, and the other member was
told `known-peer-left`.

Run:  python -m unittest backend.tests.test_join_keeps_channels
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

C1 = "c" * 64


def _make():
    from flask import Flask
    from flask_socketio import SocketIO

    app = Flask(__name__)
    sio = SocketIO(app, async_mode="threading")
    reg = signaling._MemRegistry()
    signaling.register(sio, reg)
    return app, sio, reg


def _names(received):
    return [ev["name"] for ev in received]


class JoinKeepsChannels(unittest.TestCase):
    def test_join_after_sync_keeps_channel_and_partner(self):
        app, sio, reg = _make()
        a = sio.test_client(app)
        b = sio.test_client(app)
        a.get_received()
        b.get_received()
        # Two remembered devices in different rooms share channel C1.
        a.emit("sync", {"room": "ra", "name": "laptop", "uid": "ua", "channels": [C1]}, callback=True)
        b.emit("sync", {"room": "rb", "name": "ipad", "uid": "ub", "channels": [C1]}, callback=True)
        a_sid = next(s for s in reg._m if reg._m[s]["name"] == "laptop")
        b_sid = next(s for s in reg._m if reg._m[s]["name"] == "ipad")
        self.assertTrue(reg.share_channel(a_sid, b_sid), "precondition: both subscribed to C1")
        a.get_received()
        b.get_received()

        # The browser's legacy join, same room as its sync.
        b.emit("join", {"room": "rb", "name": "ipad", "uid": "ub"})

        self.assertTrue(reg.share_channel(a_sid, b_sid),
                        "a room join dropped the socket's known-device channel")
        self.assertNotIn("known-peer-left", _names(a.get_received()),
                         "the partner was told the joiner left its channel")

    def test_leave_still_drops_channels(self):
        app, sio, reg = _make()
        a = sio.test_client(app)
        b = sio.test_client(app)
        a.emit("sync", {"room": "ra", "name": "laptop", "uid": "ua", "channels": [C1]}, callback=True)
        b.emit("sync", {"room": "rb", "name": "ipad", "uid": "ub", "channels": [C1]}, callback=True)
        a_sid = next(s for s in reg._m if reg._m[s]["name"] == "laptop")
        b_sid = next(s for s in reg._m if reg._m[s]["name"] == "ipad")
        a.get_received()
        b.emit("leave")
        self.assertFalse(reg.share_channel(a_sid, b_sid), "an explicit leave must drop channels")
        self.assertIn("known-peer-left", _names(a.get_received()))


if __name__ == "__main__":
    unittest.main()
