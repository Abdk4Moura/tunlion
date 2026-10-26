"""A second `join` to the room a sid already holds must not churn the room.

A browser's socket-up `sync` can reach the relay before its `join`; the sync
runs the room join, and the join then ran it again: every other member got
`peer-left` and `peer-joined` for the same sid and tore down its link to it.

Run:  python -m unittest backend.tests.test_join_idempotent
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402


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


class JoinIdempotent(unittest.TestCase):
    def test_join_after_sync_does_not_churn_the_room(self):
        app, sio, reg = _make()
        a = sio.test_client(app)
        b = sio.test_client(app)
        a.emit("join", {"room": "r", "name": "laptop", "uid": "ua", "gen": "ga"})
        a.get_received()
        b.get_received()

        b.emit("sync", {"room": "r", "name": "ipad", "uid": "ub", "gen": "gb"}, callback=True)
        seen = _names(a.get_received())
        self.assertEqual(seen.count("peer-joined"), 1, seen)
        b.get_received()

        b.emit("join", {"room": "r", "name": "ipad", "uid": "ub", "gen": "gb"})
        seen = _names(a.get_received())
        self.assertNotIn("peer-left", seen, "a duplicate join told the room the device left")
        self.assertNotIn("peer-joined", seen, "a duplicate join re-announced the device")
        got = b.get_received()
        welcomes = [ev for ev in got if ev["name"] == "welcome"]
        self.assertEqual(len(welcomes), 1, "the joiner still gets its roster")
        self.assertEqual([p["name"] for p in welcomes[0]["args"][0]["peers"]], ["laptop"])

    def test_join_to_another_room_still_moves(self):
        app, sio, reg = _make()
        a = sio.test_client(app)
        b = sio.test_client(app)
        a.emit("join", {"room": "r", "name": "laptop", "uid": "ua", "gen": "ga"})
        b.emit("join", {"room": "r", "name": "ipad", "uid": "ub", "gen": "gb"})
        a.get_received()
        b.emit("join", {"room": "r2", "name": "ipad", "uid": "ub", "gen": "gb"})
        self.assertIn("peer-left", _names(a.get_received()))

    def test_rename_by_join_still_announces(self):
        app, sio, reg = _make()
        a = sio.test_client(app)
        b = sio.test_client(app)
        a.emit("join", {"room": "r", "name": "laptop", "uid": "ua", "gen": "ga"})
        b.emit("join", {"room": "r", "name": "ipad", "uid": "ub", "gen": "gb"})
        a.get_received()
        b.emit("join", {"room": "r", "name": "ipad-2", "uid": "ub", "gen": "gb"})
        self.assertIn("peer-joined", _names(a.get_received()))


if __name__ == "__main__":
    unittest.main()
