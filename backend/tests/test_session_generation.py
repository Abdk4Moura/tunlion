"""Generation-safe reload tests for the signaling relay.

A browser page load mints a fresh session generation. A reload keeps the same
device uid but has a new generation, and must take over immediately. A late
beacon/sync from the retired generation must be ignored: it cannot close or
re-claim the replacement session. A rename is a relabel of the same sid, never
a second device.

Run:  python -m unittest backend.tests.test_session_generation
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

U1 = "browser-uid-1"
U2 = "browser-uid-2"


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


def _join(c, room, name, uid, gen):
    return c.emit("sync", {"v": 1, "room": room, "name": name, "uid": uid, "gen": gen}, callback=True)


class ReloadSupersede(unittest.TestCase):
    def test_new_generation_supersedes_old_sid_immediately(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        old = sio.test_client(app)
        peer.get_received()
        old.get_received()

        _join(peer, "r1", "peer", U2, "peer-gen")
        peer.get_received()
        ack1 = _join(old, "r1", "ipad", U1, "old-gen")
        old.get_received()
        self.assertEqual(ack1["room"], "r1")
        old_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()

        new = sio.test_client(app)
        new.get_received()
        ack2 = _join(new, "r1", "ipad", U1, "new-gen")
        self.assertEqual(ack2["room"], "r1")
        new_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        self.assertNotEqual(old_sid, new_sid)

        # The old page is told immediately, and the room sees exactly one ipad:
        # peer-left for the stale sid + peer-joined for the replacement.
        self.assertIn("session-superseded", _names(old.get_received()))
        peer_events = peer.get_received()
        self.assertIn("peer-left", _names(peer_events))
        self.assertIn("peer-joined", _names(peer_events))
        self.assertNotIn(old_sid, reg._m)

        # The newcomer's welcome does not include its own stale sid.
        welcome = next(e for e in new.get_received() if e["name"] == "welcome")["args"][0]
        self.assertNotIn(old_sid, [p["id"] for p in welcome["peers"]])

    def test_late_sync_from_retired_generation_is_refused(self):
        app, sio, reg = _make()
        old = sio.test_client(app)
        old.get_received()
        _join(old, "r1", "ipad", U1, "old-gen")
        old.get_received()

        new = sio.test_client(app)
        new.get_received()
        _join(new, "r1", "ipad", U1, "new-gen")
        new_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        new.get_received()
        old.get_received()

        ack = _join(old, "r1", "ipad", U1, "old-gen")
        self.assertFalse(ack["ok"])
        self.assertTrue(ack.get("superseded"))
        self.assertIn("session-superseded", _names(old.get_received()))
        # The retired page did not evict or replace the new owner.
        self.assertEqual(reg._m[new_sid]["uid"], U1)
        self.assertEqual(reg.room_of(new_sid), "r1")

    def test_stale_close_is_ignored_current_close_works(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        old = sio.test_client(app)
        peer.get_received()
        old.get_received()
        _join(peer, "r1", "peer", U2, "peer-gen")
        peer.get_received()
        _join(old, "r1", "ipad", U1, "old-gen")
        old.get_received()

        new = sio.test_client(app)
        new.get_received()
        _join(new, "r1", "ipad", U1, "new-gen")
        new_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()
        new.get_received()

        # A pagehide beacon from the previous generation: ignored.
        self.assertFalse(signaling.close_session(sio, reg, U1, "old-gen"))
        self.assertIn(new_sid, reg._m)
        self.assertEqual(reg._m[new_sid]["uid"], U1)

        # The current generation's beacon is honored and tells the room.
        self.assertTrue(signaling.close_session(sio, reg, U1, "new-gen"))
        self.assertNotIn(new_sid, reg._m)
        events = peer.get_received()
        self.assertIn("peer-left", _names(events))
        left = next(e for e in events if e["name"] == "peer-left")["args"][0]
        self.assertEqual(left["id"], new_sid)
        # A closed generation stays closed: a stray late sync from it must not
        # re-create the session it just asked to end.
        self.assertEqual(reg.claim_session(U1, "new-gen", new_sid)["status"], "retired")


class RenameIsSameDevice(unittest.TestCase):
    def test_rename_updates_existing_sid_without_rejoin(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        me = sio.test_client(app)
        peer.get_received()
        me.get_received()
        _join(peer, "r1", "peer", U2, "peer-gen")
        peer.get_received()
        _join(me, "r1", "silken-chickadee", U1, "gen-1")
        my_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()
        me.get_received()

        _join(me, "r1", "studio-ipad", U1, "gen-1")
        events = peer.get_received()
        self.assertIn("peer-updated", _names(events))
        updated = next(e for e in events if e["name"] == "peer-updated")["args"][0]
        self.assertEqual(updated["id"], my_sid)
        self.assertEqual(updated["name"], "studio-ipad")
        # Same sid: this is a relabel, not a new peer/join.
        self.assertNotIn("peer-joined", _names(events))
        self.assertEqual(reg.meta(my_sid)["name"], "studio-ipad")


class ClaimPrimitives(unittest.TestCase):
    def test_claim_states(self):
        reg = signaling._MemRegistry()
        self.assertEqual(reg.claim_session(U1, "g1", "s1")["status"], "new")
        self.assertEqual(reg.claim_session(U1, "g1", "s1")["status"], "current")
        r = reg.claim_session(U1, "g1", "s2")
        self.assertEqual((r["status"], r["prev"]), ("replace", "s1"))
        r = reg.claim_session(U1, "g2", "s3")
        self.assertEqual((r["status"], r["prev"]), ("new", "s2"))
        self.assertEqual(reg.claim_session(U1, "g1", "s4")["status"], "retired")
        self.assertEqual(reg.claim_session(U1, "g2", "s3")["status"], "current")

    def test_legacy_client_without_generation_is_not_superseded(self):
        reg = signaling._MemRegistry()
        self.assertEqual(reg.claim_session(U1, None, "s1")["status"], "legacy")
        self.assertEqual(reg.claim_session(U1, None, "s2")["status"], "legacy")


if __name__ == "__main__":
    unittest.main()
