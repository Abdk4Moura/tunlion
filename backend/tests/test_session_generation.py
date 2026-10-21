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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

U1 = "browser-uid-1"
U2 = "browser-uid-2"
TOK1 = "owner-token-u1"
TOK2 = "owner-token-u2"


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


def _join(c, room, name, uid, gen, token=None):
    payload = {"v": 1, "room": room, "name": name, "uid": uid, "gen": gen}
    if token:
        payload["token"] = token
    return c.emit("sync", payload, callback=True)


class ReloadSupersede(unittest.TestCase):
    def test_new_generation_supersedes_old_sid_immediately(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        old = sio.test_client(app)
        peer.get_received()
        old.get_received()

        _join(peer, "r1", "peer", U2, "peer-gen", TOK2)
        peer.get_received()
        ack1 = _join(old, "r1", "ipad", U1, "old-gen", TOK1)
        tok1 = ack1["token"]
        old.get_received()
        self.assertEqual(ack1["room"], "r1")
        old_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()

        new = sio.test_client(app)
        new.get_received()
        ack2 = _join(new, "r1", "ipad", U1, "new-gen", tok1)
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
        ack1 = _join(old, "r1", "ipad", U1, "old-gen", TOK1)
        tok1 = ack1["token"]
        old.get_received()

        new = sio.test_client(app)
        new.get_received()
        _join(new, "r1", "ipad", U1, "new-gen", tok1)
        new_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        new.get_received()
        old.get_received()

        ack = _join(old, "r1", "ipad", U1, "old-gen", tok1)
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
        _join(peer, "r1", "peer", U2, "peer-gen", TOK2)
        peer.get_received()
        ack1 = _join(old, "r1", "ipad", U1, "old-gen", TOK1)
        tok1 = ack1["token"]
        old.get_received()

        new = sio.test_client(app)
        new.get_received()
        _join(new, "r1", "ipad", U1, "new-gen", tok1)
        new_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()
        new.get_received()

        # A pagehide beacon from the previous generation: ignored.
        self.assertFalse(signaling.close_session(sio, reg, U1, "old-gen", tok1))
        self.assertIn(new_sid, reg._m)
        self.assertEqual(reg._m[new_sid]["uid"], U1)

        # The current generation's beacon is honored and tells the room.
        self.assertTrue(signaling.close_session(sio, reg, U1, "new-gen", tok1))
        self.assertNotIn(new_sid, reg._m)
        events = peer.get_received()
        self.assertIn("peer-left", _names(events))
        left = next(e for e in events if e["name"] == "peer-left")["args"][0]
        self.assertEqual(left["id"], new_sid)
        # A closed generation stays closed: a stray late sync from it must not
        # re-create the session it just asked to end.
        self.assertEqual(reg.claim_session(U1, "new-gen", new_sid)["status"], "retired")


class OwnershipToken(unittest.TestCase):
    def test_first_claim_mints_token_only_to_the_joiner(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        victim = sio.test_client(app)
        peer.get_received()
        victim.get_received()
        _join(peer, "r1", "peer", U2, "peer-gen", TOK2)
        peer.get_received()
        ack = _join(victim, "r1", "ipad", U1, "victim-gen", "client-supplied-token")
        self.assertTrue(ack["ok"])
        self.assertTrue(ack.get("token"))
        self.assertNotEqual(ack["token"], "client-supplied-token")
        victim_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        victim_events = victim.get_received()
        welcome = next(e for e in victim_events if e["name"] == "welcome")["args"][0]
        self.assertEqual(welcome.get("token"), ack["token"])
        # The public roster never carries the token.
        peer_events = peer.get_received()
        joined = next(e for e in peer_events if e["name"] == "peer-joined")["args"][0]
        self.assertNotIn("token", joined)
        self.assertNotIn("token", welcome["peers"][0] if welcome["peers"] else {})
        self.assertNotIn(ack["token"], str(_names(peer_events)) + str(peer_events))
        # A client value never becomes the first owner's token.
        self.assertFalse(_join(victim, "r1", "ipad", U1, "victim-gen-2", "client-supplied-token")["ok"])
        self.assertIn(victim_sid, reg._m)

    def test_unrelated_client_cannot_take_over_or_close_victim(self):
        app, sio, reg = _make()
        victim = sio.test_client(app)
        attacker = sio.test_client(app)
        victim.get_received()
        attacker.get_received()
        ack = _join(victim, "r1", "ipad", U1, "victim-gen")
        token = ack["token"]
        victim_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        victim.get_received()
        attacker.get_received()

        # The attacker learned the uid from the room but not the token.
        evil = _join(attacker, "r1", "ipad", U1, "attacker-gen", "attacker-token")
        self.assertFalse(evil["ok"])
        self.assertTrue(evil.get("superseded"))
        self.assertIn("session-superseded", _names(attacker.get_received()))
        # The victim did not move and was not even told about a takeover.
        self.assertIn(victim_sid, reg._m)
        self.assertEqual(reg._m[victim_sid]["uid"], U1)
        self.assertNotIn("session-superseded", _names(victim.get_received()))
        self.assertFalse(signaling.close_session(sio, reg, U1, "victim-gen", "attacker-token"))
        self.assertIn(victim_sid, reg._m)
        # A no-token claim is equally refused.
        self.assertFalse(_join(attacker, "r1", "ipad", U1, "attacker-gen-2")["ok"])
        self.assertIn(victim_sid, reg._m)
        # So is a legacy no-generation attempt against an owned uid.
        self.assertFalse(_join(attacker, "r1", "ipad", U1, None)["ok"])
        self.assertIn(victim_sid, reg._m)
        # The real owner can still close.
        self.assertTrue(signaling.close_session(sio, reg, U1, "victim-gen", token))

    def test_concurrent_generations_leave_exactly_one_owner(self):
        reg = signaling._MemRegistry()
        claims = [f"g{i}" for i in range(64)]
        tok = reg.claim_session(U1, claims[0], "s0")["token"]
        with ThreadPoolExecutor(max_workers=16) as pool:
            list(pool.map(lambda i: reg.claim_session(U1, claims[i], f"s{i}", tok), range(len(claims))))
        cur = reg._uids[U1]
        self.assertIn(cur["gen"], claims)
        self.assertEqual(cur["sid"], f"s{claims.index(cur['gen'])}")
        retired = reg._retired[U1]
        self.assertEqual(set(claims) - {cur["gen"]}, retired)
        self.assertEqual(reg.claim_session(U1, cur["gen"], cur["sid"], tok)["status"], "current")
        for i, g in enumerate(claims):
            if g != cur["gen"]:
                self.assertEqual(reg.claim_session(U1, g, f"s{i}", tok)["status"], "retired")
        self.assertEqual(reg.claim_session(U1, "next", "s-next", "wrong")["status"], "denied")


class CloseOriginPolicy(unittest.TestCase):
    def test_default_wildcard_and_explicit_allowlist(self):
        self.assertTrue(signaling.origin_allowed(None, "*"))
        self.assertTrue(signaling.origin_allowed("https://any.example", "*"))
        self.assertFalse(signaling.origin_allowed("https://evil.example", ["https://app.example"]))
        self.assertTrue(signaling.origin_allowed("https://app.example", ["https://app.example"]))
        self.assertTrue(signaling.origin_allowed(None, ["https://app.example"]))


class RenameIsSameDevice(unittest.TestCase):
    def test_rename_updates_existing_sid_without_rejoin(self):
        app, sio, reg = _make()
        peer = sio.test_client(app)
        me = sio.test_client(app)
        peer.get_received()
        me.get_received()
        _join(peer, "r1", "peer", U2, "peer-gen", TOK2)
        peer.get_received()
        ack1 = _join(me, "r1", "silken-chickadee", U1, "gen-1", TOK1)
        tok1 = ack1["token"]
        my_sid = next(s for s, v in reg._m.items() if v["uid"] == U1)
        peer.get_received()
        me.get_received()

        _join(me, "r1", "studio-ipad", U1, "gen-1", tok1)
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
        first = reg.claim_session(U1, "g1", "s1", "client-token")
        self.assertEqual(first["status"], "new")
        tok = first["token"]
        self.assertNotEqual(tok, "client-token")
        self.assertEqual(reg.claim_session(U1, "g1", "s1", tok)["status"], "current")
        r = reg.claim_session(U1, "g1", "s2", tok)
        self.assertEqual((r["status"], r["prev"]), ("replace", "s1"))
        r = reg.claim_session(U1, "g2", "s3", tok)
        self.assertEqual((r["status"], r["prev"]), ("new", "s2"))
        self.assertEqual(reg.claim_session(U1, "g1", "s4", tok)["status"], "retired")
        self.assertEqual(reg.claim_session(U1, "g2", "s3", tok)["status"], "current")
        self.assertEqual(reg.claim_session(U1, "g3", "s5", "client-token")["status"], "denied")

    def test_legacy_client_without_generation_is_not_superseded(self):
        reg = signaling._MemRegistry()
        self.assertEqual(reg.claim_session(U1, None, "s1")["status"], "legacy")
        self.assertEqual(reg.claim_session(U1, None, "s2")["status"], "legacy")

    def test_token_expiry_and_length_caps(self):
        reg = signaling._MemRegistry()
        first = reg.claim_session(U1, "g1", "s1")
        tok = first["token"]
        reg._uids[U1]["token_exp"] = 0  # expired; sid is not live
        # No live sid -> expired token is stale ownership; a fresh server token
        # is minted (a client token still cannot choose it).
        rotated = reg.claim_session(U1, "g2", "s2", tok)
        self.assertEqual(rotated["status"], "new")
        self.assertNotEqual(rotated["token"], tok)
        self.assertEqual(reg.claim_session(U1, "g3", "s3", tok)["status"], "denied")
        self.assertEqual(reg.claim_session(U1, "g3", "s3", "x" * 257)["status"], "denied")
        self.assertEqual(reg.claim_session("u" * 129, "g4", "s4")["status"], "denied")

    def test_concurrent_reads_and_mutations_do_not_raise(self):
        reg = signaling._MemRegistry()
        tok = reg.claim_session(U1, "g0", "s0")["token"]
        reg.add("s0", "r1", "pad", U1, "g0")

        def worker(i):
            for j in range(150):
                sid = f"x{i}-{j}"
                reg.add(sid, "r1", f"n{i}", f"u{i}", "g")
                reg.peers_in("r1")
                reg.room_of(sid)
                reg.owned_uid(U1)
                reg.remove(sid)

        def claimer():
            for j in range(40):
                reg.claim_session(U1, f"cg{j}", f"cs{j}", tok)
                reg.claim_session(U1, f"cg{j}", f"cs{j}", tok)

        with ThreadPoolExecutor(max_workers=12) as pool:
            futs = [pool.submit(worker, i) for i in range(8)]
            futs.append(pool.submit(claimer))
            for f in futs:
                f.result()

    def test_owned_state_is_bounded(self):
        reg = signaling._MemRegistry()
        reg.MAX_OWNED_UIDS = 8
        for i in range(50):
            reg.claim_session(f"u{i}", "g", f"s{i}")
        self.assertLessEqual(len(reg._uids), 8)
        reg2 = signaling._MemRegistry()
        reg2.MAX_RETIRED_PER_UID = 8
        first = reg2.claim_session(U1, "g0", "s0")
        tok = first["token"]
        for i in range(20):
            reg2.claim_session(U1, f"g{i + 1}", f"s{i + 1}", tok)
        self.assertLessEqual(len(reg2._retired[U1]), 8)


if __name__ == "__main__":
    unittest.main()
