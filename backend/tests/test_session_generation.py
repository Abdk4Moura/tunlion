"""TOKEN-keyed session tests for the signaling relay.

A session is identified by a server-minted opaque token. uid/name are display
attributes only; a uid is never an ownership key. A client without the token
gets a new independent session and can never evict, close, or join another
session, even when it knows the victim's uid.

Run:  python -m unittest backend.tests.test_session_generation
"""
import sys
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signaling  # noqa: E402

U1 = "browser-uid-1"
U2 = "browser-uid-2"
NAME = "ipad"


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


def _sync(c, room, name, uid, gen, token=None):
    payload = {"v": 1, "room": room, "name": name, "uid": uid, "gen": gen}
    if token:
        payload["token"] = token
    return c.emit("sync", payload, callback=True)


def _join(c, room, name, uid, gen=None, token=None):
    payload = {"room": room, "name": name, "uid": uid}
    if gen is not None:
        payload["gen"] = gen
    if token:
        payload["token"] = token
    c.emit("join", payload)


def _sid_for(reg, token):
    rec = reg._sessions.get(token)
    return rec.get("sid") if rec else None


class TokenOwnership(unittest.TestCase):
    def test_uid_is_not_authority(self):
        app, sio, reg = _make()
        victim = sio.test_client(app)
        attacker = sio.test_client(app)
        victim.get_received()
        attacker.get_received()
        ack = _sync(victim, "r1", NAME, U1, "victim-gen")
        token = ack["token"]
        victim_sid = _sid_for(reg, token)
        victim.get_received()

        # Same uid, no token: an independent session, never the victim's.
        evil = _sync(attacker, "r1", NAME, U1, "attacker-gen")
        self.assertTrue(evil["ok"])
        self.assertNotEqual(evil["token"], token)
        self.assertIn(victim_sid, reg._m)
        self.assertEqual(reg._m[victim_sid]["uid"], U1)
        victim_events = victim.get_received()
        self.assertNotIn("session-superseded", _names(victim_events))
        joined = next(e for e in victim_events if e["name"] == "peer-joined")["args"][0]
        self.assertNotIn("token", joined)
        welcome = next(e for e in attacker.get_received() if e["name"] == "welcome")["args"][0]
        self.assertTrue(welcome.get("token"))
        self.assertNotIn("token", welcome["peers"][0])
        self.assertNotIn(welcome["token"], str(welcome["peers"]))

        # A wrong token is also just a new session.
        evil2 = _sync(attacker, "r1", NAME, U1, "attacker-gen-2", "attacker-token")
        self.assertNotEqual(evil2["token"], token)
        self.assertIn(victim_sid, reg._m)

        # Close with no/wrong token is refused.
        self.assertFalse(signaling.close_session(sio, reg, "attacker-token", "victim-gen"))
        self.assertFalse(signaling.close_session(sio, reg, None, "victim-gen"))
        self.assertIn(victim_sid, reg._m)
        self.assertTrue(signaling.close_session(sio, reg, token, "victim-gen"))
        self.assertNotIn(victim_sid, reg._m)

    def test_same_token_supersedes_only_its_own_sid(self):
        app, sio, reg = _make()
        old = sio.test_client(app)
        other = sio.test_client(app)
        old.get_received()
        other.get_received()
        ack = _sync(old, "r1", NAME, U1, "g1")
        token = ack["token"]
        old_sid = _sid_for(reg, token)
        other_ack = _sync(other, "r1", "laptop", U2, "g-other")
        other_token = other_ack["token"]
        other_sid = _sid_for(reg, other_token)
        old.get_received()
        other.get_received()

        new = sio.test_client(app)
        new.get_received()
        takeover = _sync(new, "r1", NAME, U1, "g2", token)
        self.assertEqual(takeover["token"], token)
        self.assertNotEqual(_sid_for(reg, token), old_sid)
        self.assertIn("session-superseded", _names(old.get_received()))
        # An unrelated token is untouched.
        self.assertEqual(_sid_for(reg, other_token), other_sid)

    def test_legacy_no_token_coexists(self):
        app, sio, reg = _make()
        victim = sio.test_client(app)
        victim.get_received()
        token = _sync(victim, "r1", NAME, U1, "g1")["token"]
        victim_sid = _sid_for(reg, token)
        victim.get_received()

        legacy = sio.test_client(app)
        legacy.get_received()
        _join(legacy, "r1", NAME, U1)  # no token, no gen
        welcome = next(e for e in legacy.get_received() if e["name"] == "welcome")["args"][0]
        self.assertTrue(welcome.get("token"))
        self.assertNotEqual(welcome["token"], token)
        self.assertIn(victim_sid, reg._m)
        self.assertNotIn("session-superseded", _names(victim.get_received()))

    def test_non_live_sessions_are_evicted(self):
        reg = signaling._MemRegistry()
        reg.MAX_SESSIONS = 2
        a = reg.claim_session(None, "g1", "s1", U1, "pad")
        b = reg.claim_session(None, "g1", "s2", U2, "laptop")
        reg.refresh(["s1", "s2"])
        reg.SESSION_LIVE_WINDOW = 0.05
        time.sleep(0.1)  # live sids but stale heartbeat/score
        c = reg.claim_session(None, "g1", "s3", "u3", "nas")
        self.assertEqual(c["status"], "new")
        self.assertIn("s1", c["evicted"])
        self.assertIn("s2", c["evicted"])
        self.assertNotIn(a["token"], reg._sessions)
        self.assertNotIn(b["token"], reg._sessions)

    def test_live_capacity_refuses_new_sessions(self):
        reg = signaling._MemRegistry()
        reg.MAX_SESSIONS = 2
        a = reg.claim_session(None, "g1", "sa", U1, "pad")
        b = reg.claim_session(None, "g1", "sb", U2, "laptop")
        reg.refresh(["sa", "sb"])
        c = reg.claim_session(None, "g1", "sc", "u3", "nas")
        self.assertEqual(c["status"], "capacity")
        self.assertIn(a["token"], reg._sessions)
        self.assertIn(b["token"], reg._sessions)

    def test_closed_slot_reused_before_live(self):
        reg = signaling._MemRegistry()
        reg.MAX_SESSIONS = 2
        a = reg.claim_session(None, "g1", "sa", U1, "pad")
        b = reg.claim_session(None, "g1", "sb", U2, "laptop")
        reg.refresh(["sb"])
        reg.take_session(a["token"], "g1")
        d = reg.claim_session(None, "g1", "sd", "u4", "phone")
        self.assertEqual(d["status"], "new")
        self.assertNotIn(a["token"], reg._sessions)
        self.assertIn(b["token"], reg._sessions)

    def test_concurrent_same_token_one_owner_distinct_tokens_coexist(self):
        reg = signaling._MemRegistry()
        first = reg.claim_session(None, "g0", "s0", U1, "pad")
        token = first["token"]
        gens = [f"g{i}" for i in range(1, 33)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: reg.claim_session(token, gens[i], f"s{i}", U1, "pad"), range(len(gens))))
        self.assertEqual(len([t for t in reg._sessions if t == token]), 1)
        self.assertIn(reg._sessions[token]["gen"], gens)
        other = reg.claim_session(None, "g1", "other", U2, "laptop")
        self.assertIn(other["token"], reg._sessions)

    def test_real_short_ttl_live_and_expired(self):
        reg = signaling._MemRegistry()
        reg.SESSION_TTL = 0.05
        first = reg.claim_session(None, "g1", "s1", U1, "pad")
        token = first["token"]
        # Live claim refreshes the one record and keeps the token.
        live = reg.claim_session(token, "g1", "s1", U1, "pad")
        self.assertEqual((live["status"], live["token"]), ("current", token))
        time.sleep(0.08)
        expired = reg.claim_session(token, "g2", "s2", U1, "pad")
        self.assertEqual(expired["status"], "new")
        self.assertNotEqual(expired["token"], token)

    def test_closed_token_reattaches_and_old_generation_stays_retired(self):
        reg = signaling._MemRegistry()
        token = reg.claim_session(None, "g1", "s1", U1, "pad")["token"]
        self.assertEqual(reg.take_session(token, "g1")["sid"], "s1")
        reattach = reg.claim_session(token, "g2", "s2", U1, "pad")
        self.assertEqual((reattach["status"], reattach["token"]), ("new", token))
        self.assertEqual(reg.claim_session(token, "g1", "s3", U1, "pad")["status"], "retired")
        independent = reg.claim_session(None, "g3", "s4", U1, "pad")
        self.assertNotEqual(independent["token"], token)

    def test_retired_per_token_is_global_bounded_not_refused(self):
        reg = signaling._MemRegistry()
        reg.MAX_RETIRED_TOTAL = 8
        token = reg.claim_session(None, "g0", "s0", U1, "pad")["token"]
        statuses = []
        for i in range(1, 21):
            statuses.append(reg.claim_session(token, f"g{i}", f"s{i}", U1, "pad")["status"])
        self.assertNotIn("capacity", statuses)
        self.assertNotIn("denied", statuses)
        self.assertLessEqual(len(reg._retired), 8)
        self.assertIn((token, "g19"), reg._retired, "the just-closed generation stays retired")
        self.assertNotIn((token, "g20"), reg._retired)

    def test_input_types_and_lengths_are_refused(self):
        app, sio, _reg = _make()
        c = sio.test_client(app)
        c.get_received()
        for bad_uid in (None, "", 123, ["u"], {"u": 1}):
            self.assertFalse(_sync(c, "r1", NAME, bad_uid, "g1")["ok"])
        for bad_gen in (123, ["g"], {"g": 1}):
            self.assertFalse(_sync(c, "r1", NAME, U1, bad_gen)["ok"])
        self.assertFalse(_sync(c, "r1", 123, U1, "g1")["ok"])
        self.assertFalse(_sync(c, "r1", "", U1, "g1")["ok"])
        self.assertFalse(_sync(c, "r1", NAME, U1, "g1", token=123)["ok"])
        self.assertFalse(sio.test_client(app).emit("sync", ["not", "a", "dict"], callback=True)["ok"])


class CloseOriginPolicy(unittest.TestCase):
    def test_default_wildcard_and_explicit_allowlist(self):
        self.assertTrue(signaling.origin_allowed(None, "*"))
        self.assertTrue(signaling.origin_allowed("https://any.example", "*"))
        self.assertFalse(signaling.origin_allowed("https://evil.example", ["https://app.example"]))
        self.assertTrue(signaling.origin_allowed("https://app.example", ["https://app.example"]))
        self.assertTrue(signaling.origin_allowed(None, ["https://app.example"]))


if __name__ == "__main__":
    unittest.main()
