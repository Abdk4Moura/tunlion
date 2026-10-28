"""One protocol, two backends: the conformance suite.

Every test here talks to a running signaling backend over the real wire and
asserts the behaviour CONTRACT.md and backend/signaling.py define. The SAME
tests run against the Python relay and against the Cloudflare Durable Object
port (edge/signal), so the two cannot drift without one of them going red.

    CONFORMANCE_URL=http://127.0.0.1:5000 CONFORMANCE_TRANSPORT=websocket \
        python -m unittest backend.conformance.test_conformance -v

CONFORMANCE_TRANSPORT is websocket | polling | upgrade. The backend must run
with a lifted pair-claim budget (FIL_CLAIM_LIMIT>=200, FIL_PAIR_CREATE_LIMIT
>=800, as the gate fixture does): every client here shares one address. The
small-budget behaviour is test_limits.py, against a separately configured
instance.
"""
import json
import os
import random
import threading
import time
import unittest

from backend.conformance.wire import QUIET, WAIT, Peer, RawWs, chan, http, uniq


class Base(unittest.TestCase):
    def setUp(self):
        self.peers = []

    def tearDown(self):
        for p in self.peers:
            p.close()

    def peer(self):
        p = Peer().connect()
        self.peers.append(p)
        return p

    def joined(self, room, name="dev", uid=None, gen=None, token=None):
        """Connect + tokenless join; returns (peer, welcome)."""
        p = self.peer()
        p.emit("join", {"room": room, "name": name, "uid": uid or uniq("u"),
                        "gen": gen or uniq("g"), "token": token})
        w = p.wait("welcome")
        return p, w


class Rest(unittest.TestCase):
    def test_config_shape(self):
        r = http("GET", "/api/config")
        self.assertEqual(r.status_code, 200)
        c = r.json()
        self.assertEqual(set(c), {"signaling", "iceServers", "firebase", "chunkSize"})
        self.assertEqual(c["signaling"], "socketio")
        self.assertIsNone(c["firebase"])
        self.assertEqual(c["chunkSize"], 60 * 1024)
        self.assertIsInstance(c["iceServers"], list)
        self.assertIn({"urls": "stun:stun.l.google.com:19302"}, c["iceServers"])
        for s in c["iceServers"][1:]:
            urls = s["urls"] if isinstance(s["urls"], list) else [s["urls"]]
            for u in urls:
                self.assertRegex(u, r"^turns?:")
                self.assertFalse(u.endswith(":53") or ":53?" in u, u)
            self.assertTrue(s.get("username") and s.get("credential"))

    def test_room_shape_and_stability(self):
        a = http("GET", "/api/room").json()
        b = http("GET", "/api/room").json()
        self.assertEqual(set(a), {"room", "network", "scope"})
        self.assertRegex(a["room"], r"^[0-9a-f]{12}$")
        self.assertIn(a["network"], ("ipv4", "ipv6", "raw"))
        self.assertEqual(a["scope"], "auto")
        self.assertEqual(a, b)

    def test_room_code_shape(self):
        c = http("GET", "/api/room/code").json()
        self.assertRegex(c["code"], r"^[ABCDEFGHJKMNPQRSTUVWXYZ23456789]{6}$")
        self.assertEqual(c["room"], "code-" + c["code"])
        self.assertEqual(c["scope"], "code")

    def test_health_endpoints(self):
        self.assertEqual(http("GET", "/api/health").json(), {"ok": True})
        r = http("GET", "/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["ok"], True)
        self.assertIn(r.json()["redis"], ("up", "not-configured"))

    def test_whoami(self):
        ip = http("GET", "/api/whoami").json()["ip"]
        self.assertIsInstance(ip, str)
        self.assertTrue(ip)

    def test_session_close_is_always_204(self):
        for body in ("", "not json", "[]", json.dumps({"token": "nope", "gen": "nope"})):
            r = http("POST", "/api/session/close", data=body)
            self.assertEqual(r.status_code, 204, body)
            self.assertEqual(r.content, b"")


class EngineIo(unittest.TestCase):
    """Transport-level facts both engine.io servers must agree on."""

    def test_polling_open_packet(self):
        r = http("GET", "/socket.io/?EIO=4&transport=polling")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.text.startswith("0"))
        o = json.loads(r.text[1:])
        self.assertEqual(o["upgrades"], ["websocket"])
        self.assertEqual(set(o) >= {"sid", "upgrades", "pingInterval", "pingTimeout", "maxPayload"}, True)

    def test_unknown_sid_is_400(self):
        r = http("GET", "/socket.io/?EIO=4&transport=polling&sid=doesnotexist")
        self.assertEqual(r.status_code, 400)

    def test_unsupported_eio_version_is_400(self):
        r = http("GET", "/socket.io/?EIO=3&transport=polling")
        self.assertEqual(r.status_code, 400)

    def test_many_packets_in_one_post(self):
        # A high-RTT browser batches its burst into one POST (FIL_MAX_DECODE_PACKETS).
        r = http("GET", "/socket.io/?EIO=4&transport=polling")
        sid = json.loads(r.text[1:])["sid"]
        q = f"/socket.io/?EIO=4&transport=polling&sid={sid}"
        self.assertEqual(http("POST", q, data="40").text, "OK")
        self.assertTrue(http("GET", q).text.startswith("40"))
        burst = "\x1e".join("42" + json.dumps(["signal", {"to": "x", "data": i}]) for i in range(40))
        self.assertEqual(http("POST", q, data=burst).status_code, 200)


class CliFraming(unittest.TestCase):
    """The Rust client's bytes (crates/filament-signal/src/lib.rs)."""

    def test_open_connect_event_ack(self):
        c = RawWs()
        try:
            self.assertTrue(c.open.startswith("0"))
            o = json.loads(c.open[1:])
            self.assertEqual(o["upgrades"], [])
            self.assertTrue(c.connect_reply.startswith('40{"sid":'))
            room = uniq()
            # CLI-style sync: no token, no gen (legacy session, #592).
            ack = c.call("sync", {"v": 1, "room": room, "name": "cli", "uid": uniq("u"), "channels": []})
            self.assertEqual(len(ack), 1)
            d = ack[0]
            self.assertTrue(d["ok"])
            self.assertEqual(d["room"], room)
            self.assertTrue(d["token"])
            # The Rust client reads the digest as a plain event.
            synced = c.wait("synced")
            self.assertEqual(synced["token"], d["token"])
            # #592: the next full sync on the SAME socket continues the session.
            again = c.call("sync", {"v": 1, "room": room, "name": "cli", "uid": d.get("uid") or "u-x", "channels": []})
            self.assertTrue(again[0]["ok"])
            self.assertEqual(again[0]["token"], d["token"])
            self.assertEqual(again[0]["gen"], d["gen"])
        finally:
            c.close()

    def test_handler_without_return_still_acks(self):
        c = RawWs()
        try:
            self.assertEqual(c.call("signal", {"to": "nobody", "data": 1}), [])
        finally:
            c.close()


class Rooms(Base):
    def test_join_welcome_and_peer_joined(self):
        room = uniq()
        a, wa = self.joined(room, "alpha", uid="ua-" + uniq())
        self.assertEqual(wa["id"], a.sid)
        self.assertEqual(wa["peers"], [])
        self.assertTrue(wa["token"])
        self.assertTrue(wa["gen"])
        b, wb = self.joined(room, "beta")
        self.assertEqual([p["id"] for p in wb["peers"]], [a.sid])
        self.assertEqual(set(wb["peers"][0]), {"id", "name", "uid"})
        self.assertEqual(wb["peers"][0]["name"], "alpha")
        pj = a.wait("peer-joined")
        self.assertEqual(pj["id"], b.sid)
        self.assertEqual(pj["name"], "beta")
        self.assertNotIn("token", pj)

    def test_tokens_are_per_socket_sessions(self):
        room = uniq()
        uid = uniq("u")
        a, wa = self.joined(room, "same", uid=uid)
        b, wb = self.joined(room, "same", uid=uid)
        # A uid alone is never authority: B is a new session, A is untouched.
        self.assertNotEqual(wa["token"], wb["token"])
        a.none("session-superseded")

    def test_duplicate_join_is_a_roster_refresh(self):
        # #594: a second identical join re-sends the roster to the joiner only.
        room = uniq()
        a, _ = self.joined(room, "a")
        uid, gen = uniq("u"), uniq("g")
        b, wb = self.joined(room, "b", uid=uid, gen=gen)
        a.wait("peer-joined")
        b.emit("join", {"room": room, "name": "b", "uid": uid, "gen": gen, "token": wb["token"]})
        again = b.wait("welcome")
        self.assertEqual([p["id"] for p in again["peers"]], [a.sid])
        self.assertEqual(again["token"], wb["token"])
        a.none("peer-left")
        a.none("peer-joined")

    def test_join_requires_name(self):
        p = self.peer()
        p.emit("join", {"room": uniq(), "name": "", "uid": uniq("u")})
        self.assertEqual(p.wait("session-superseded"), {"reason": "invalid"})

    def test_invalid_uid_is_refused(self):
        p = self.peer()
        p.emit("join", {"room": uniq(), "name": "x", "uid": "bad uid with spaces"})
        self.assertEqual(p.wait("session-superseded"), {"reason": "invalid"})
        p.none("welcome")

    def test_leave_and_disconnect_announce_peer_left(self):
        room = uniq()
        a, _ = self.joined(room, "a")
        b, _ = self.joined(room, "b")
        c, _ = self.joined(room, "c")
        a.wait("peer-joined")
        a.wait("peer-joined")
        b.emit("leave", {})
        self.assertEqual(a.wait("peer-left", lambda d: d["id"] == b.sid), {"id": b.sid})
        csid = c.sid
        c.close()
        self.assertEqual(a.wait("peer-left", lambda d: d["id"] == csid), {"id": csid})

    def test_switching_rooms_announces_both_sides(self):
        r1, r2 = uniq(), uniq()
        a, _ = self.joined(r1, "a")
        b, wb = self.joined(r1, "b")
        c, _ = self.joined(r2, "c")
        a.wait("peer-joined")
        b.emit("join", {"room": r2, "name": "b", "uid": uniq("u"), "gen": wb["gen"], "token": wb["token"]})
        w = b.wait("welcome")
        self.assertEqual([p["id"] for p in w["peers"]], [c.sid])
        a.wait("peer-left", lambda d: d["id"] == b.sid)
        c.wait("peer-joined", lambda d: d["id"] == b.sid)


class Sync(Base):
    def test_digest_shape_and_synced_event(self):
        room = uniq()
        a, wa = self.joined(room, "a")
        b, _ = self.joined(room, "b")
        d = a.call("sync", {"v": 1, "room": room, "name": "a", "uid": uniq("u"),
                            "gen": wa["gen"], "token": wa["token"], "channels": []})
        self.assertEqual(set(d), {"v", "ok", "room", "channels", "lease", "peers", "channel_peers", "gen", "token"})
        self.assertEqual((d["v"], d["ok"], d["room"], d["lease"]), (1, True, room, True))
        self.assertEqual(d["token"], wa["token"])
        self.assertEqual([p["id"] for p in d["peers"]], [b.sid])
        self.assertEqual(a.wait("synced"), d)

    def test_roster_is_sorted_by_sid(self):
        room = uniq()
        a, wa = self.joined(room, "a")
        others = [self.joined(room, f"p{i}")[0] for i in range(4)]
        d = a.call("sync", {"v": 1, "room": room, "name": "a", "uid": uniq("u"),
                            "gen": wa["gen"], "token": wa["token"]})
        ids = [p["id"] for p in d["peers"]]
        self.assertEqual(ids, sorted(o.sid for o in others))

    def test_tokenless_sync_mints_and_joins(self):
        room = uniq()
        a, _ = self.joined(room, "a")
        b = self.peer()
        d = b.call("sync", {"v": 1, "room": room, "name": "b", "uid": uniq("u"), "gen": uniq("g")})
        self.assertTrue(d["ok"])
        self.assertTrue(d["token"])
        b.wait("welcome")
        a.wait("peer-joined", lambda x: x["id"] == b.sid)

    def test_repeated_sync_is_silent(self):
        room = uniq()
        a, wa = self.joined(room, "a")
        b, _ = self.joined(room, "b")
        a.wait("peer-joined")
        st = {"v": 1, "room": room, "name": "a", "uid": uniq("u"), "gen": wa["gen"], "token": wa["token"]}
        for _ in range(3):
            self.assertTrue(a.call("sync", st)["ok"])
        b.none("peer-joined")
        b.none("peer-left")

    def test_rename_is_peer_updated(self):
        room = uniq()
        uid = uniq("u")
        a, wa = self.joined(room, "old", uid=uid)
        b, _ = self.joined(room, "b")
        a.call("sync", {"v": 1, "room": room, "name": "new", "uid": uid, "gen": wa["gen"], "token": wa["token"]})
        self.assertEqual(b.wait("peer-updated"), {"id": a.sid, "name": "new", "uid": uid})

    def test_bad_sync_shapes(self):
        p = self.peer()
        bad = {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False}
        self.assertEqual(p.call("sync", {"room": uniq(), "name": ""}), bad)
        self.assertEqual(p.call("sync", {"room": "", "name": "x"}), bad)


class Generations(Base):
    def test_new_generation_supersedes_and_retires(self):
        room = uniq()
        uid = uniq("u")
        old, w1 = self.joined(room, "tab", uid=uid, gen="g-one")
        watcher, _ = self.joined(room, "w")
        new, w2 = self.joined(room, "tab", uid=uid, gen="g-two", token=w1["token"])
        self.assertEqual(w2["token"], w1["token"])
        self.assertEqual(old.wait("session-superseded"), {"reason": "newer-generation"})
        watcher.wait("peer-left", lambda d: d["id"] == old.sid)
        # A late sync from the retired generation cannot take the session back.
        d = old.call("sync", {"v": 1, "room": room, "name": "tab", "uid": uid,
                              "gen": "g-one", "token": w1["token"]})
        self.assertEqual(d, {"v": 1, "ok": False, "superseded": True, "room": None,
                             "channels": 0, "lease": False})
        self.assertEqual(old.wait("session-superseded"), {"reason": "stale-generation"})
        new.none("session-superseded")

    def test_same_generation_on_a_new_socket_replaces(self):
        room = uniq()
        uid = uniq("u")
        first, w1 = self.joined(room, "tab", uid=uid, gen="g-same")
        second, w2 = self.joined(room, "tab", uid=uid, gen="g-same", token=w1["token"])
        self.assertEqual(w2["token"], w1["token"])
        self.assertEqual(first.wait("session-superseded"), {"reason": "newer-generation"})

    def test_unknown_token_is_a_new_session(self):
        room = uniq()
        _, w = self.joined(room, "x", token="never-issued-token")
        self.assertNotEqual(w["token"], "never-issued-token")

    def test_session_close_beacon(self):
        room = uniq()
        a, wa = self.joined(room, "closing", gen="g-close")
        b, _ = self.joined(room, "b")
        a.wait("peer-joined")
        # Wrong generation: ignored, still 204.
        r = http("POST", "/api/session/close", data=json.dumps({"token": wa["token"], "gen": "g-other"}))
        self.assertEqual(r.status_code, 204)
        a.none("session-superseded")
        r = http("POST", "/api/session/close", data=json.dumps({"token": wa["token"], "gen": "g-close"}),
                 headers={"Content-Type": "text/plain;charset=UTF-8"})
        self.assertEqual(r.status_code, 204)
        self.assertEqual(a.wait("session-superseded"), {"reason": "page-closed"})
        b.wait("peer-left", lambda d: d["id"] == a.sid)
        # The closed generation is retired.
        d = a.call("sync", {"v": 1, "room": room, "name": "closing", "uid": uniq("u"),
                            "gen": "g-close", "token": wa["token"]})
        self.assertFalse(d["ok"])


class Signal(Base):
    def test_same_room_relay(self):
        room = uniq()
        a, _ = self.joined(room, "a")
        b, _ = self.joined(room, "b")
        b.emit("signal", {"to": a.sid, "data": {"sdp": "offer", "n": [1, 2]}})
        self.assertEqual(a.wait("signal"), {"from": b.sid, "data": {"sdp": "offer", "n": [1, 2]}})

    def test_cross_room_is_refused(self):
        a, _ = self.joined(uniq(), "a")
        c, _ = self.joined(uniq(), "c")
        c.emit("signal", {"to": a.sid, "data": "inject"})
        a.none("signal")

    def test_roomless_sender_is_refused(self):
        a, _ = self.joined(uniq(), "a")
        stranger = self.peer()
        stranger.emit("signal", {"to": a.sid, "data": "x"})
        a.none("signal")

    def test_shared_channel_relays_across_rooms(self):
        ch = chan()
        a, _ = self.joined(uniq(), "a")
        c, _ = self.joined(uniq(), "c")
        a.call("subscribe", {"channels": [ch]})
        c.call("subscribe", {"channels": [ch]})
        c.emit("signal", {"to": a.sid, "data": "hello"})
        self.assertEqual(a.wait("signal"), {"from": c.sid, "data": "hello"})


class Channels(Base):
    def test_known_peer_both_sides_and_roster_ack(self):
        ch = chan()
        ua, uc = uniq("u"), uniq("u")
        a, _ = self.joined(uniq(), "a", uid=ua)
        c, _ = self.joined(uniq(), "c", uid=uc)
        ack_a = a.call("subscribe", {"channels": [ch, "not-a-channel"]})
        self.assertEqual(ack_a, {"ok": True, "n": 1, "peers": []})
        ack_c = c.call("subscribe", {"channels": [ch]})
        self.assertEqual(ack_c["n"], 1)
        self.assertEqual(ack_c["peers"], [{"id": a.sid, "name": "a", "uid": ua, "channel": ch}])
        self.assertEqual(c.wait("known-peer"), {"id": a.sid, "name": "a", "uid": ua, "channel": ch})
        self.assertEqual(a.wait("known-peer"), {"id": c.sid, "name": "c", "uid": uc, "channel": ch})

    def test_subscribe_without_valid_channels(self):
        p = self.peer()
        self.assertEqual(p.call("subscribe", {"channels": ["xyz"]}), {"ok": False, "n": 0, "peers": []})

    def test_channel_goodbye(self):
        ch = chan()
        a, _ = self.joined(uniq(), "a")
        c, _ = self.joined(uniq(), "c")
        a.call("subscribe", {"channels": [ch]})
        c.call("subscribe", {"channels": [ch]})
        self.assertEqual(c.call("channel-goodbye", {"channels": [ch]}), {"ok": True, "n": 1})
        left = a.wait("known-peer-left")
        self.assertEqual((left["id"], left["channel"]), (c.sid, ch))

    def test_disconnect_sends_known_peer_left(self):
        ch = chan()
        a, _ = self.joined(uniq(), "a")
        c, _ = self.joined(uniq(), "c")
        a.call("subscribe", {"channels": [ch]})
        c.call("subscribe", {"channels": [ch]})
        csid = c.sid
        c.close()
        self.assertEqual(a.wait("known-peer-left", lambda d: d["id"] == csid), {"id": csid, "channel": ch})

    def test_join_keeps_channels(self):
        # A legacy join right after a first sync must not drop subscriptions.
        ch = chan()
        room = uniq()
        a = self.peer()
        d = a.call("sync", {"v": 1, "room": room, "name": "a", "uid": uniq("u"), "gen": uniq("g"),
                            "channels": [ch]})
        a.emit("join", {"room": uniq(), "name": "a", "uid": uniq("u"), "gen": d["gen"], "token": d["token"]})
        a.wait("welcome")
        c, _ = self.joined(uniq(), "c")
        ack = c.call("subscribe", {"channels": [ch]})
        self.assertEqual([p["id"] for p in ack["peers"]], [a.sid])

    def test_sync_carries_channel_peers(self):
        ch = chan()
        a, _ = self.joined(uniq(), "a")
        a.call("subscribe", {"channels": [ch]})
        b = self.peer()
        d = b.call("sync", {"v": 1, "room": uniq(), "name": "b", "uid": uniq("u"), "gen": uniq("g"),
                            "channels": [ch]})
        self.assertEqual(d["channels"], 1)
        self.assertEqual([(p["id"], p["channel"]) for p in d["channel_peers"]], [(a.sid, ch)])


class Pairing(Base):
    def nameplate(self):
        return str(random.randint(10000, 99999))

    def test_create_claim_burns(self):
        room = uniq()
        a, _ = self.joined(room, "creator")
        n = self.nameplate()
        a.emit("pair-create", {"nameplate": n, "v": 2})
        self.assertEqual(a.wait("pair-ok"), {"nameplate": n, "ttl": 600, "v": 2})
        b = self.peer()
        b.emit("pair-claim", {"nameplate": n, "v": 2})
        self.assertEqual(b.wait("pair-matched"), {"room": room})
        self.assertEqual(a.wait("pair-used"), {"code": n})
        c = self.peer()
        c.emit("pair-claim", {"nameplate": n, "v": 2})
        self.assertEqual(c.wait("pair-error"), {"error": "invalid", "why": "unknown"})

    def test_taken_and_validation(self):
        a, _ = self.joined(uniq(), "a")
        n = self.nameplate()
        a.emit("pair-create", {"nameplate": n, "v": 2})
        a.wait("pair-ok")
        b, _ = self.joined(uniq(), "b")
        b.emit("pair-create", {"nameplate": n, "v": 2})
        self.assertEqual(b.wait("pair-error"), {"error": "taken"})
        b.emit("pair-create", {"nameplate": "words-123", "v": 2})
        self.assertEqual(b.wait("pair-error"), {"error": "bad-nameplate"})
        b.emit("pair-create", {"keyword": "legacy"})
        self.assertEqual(b.wait("pair-error")["error"], "update-required")
        b.emit("pair-claim", {"nameplate": "12"})
        self.assertEqual(b.wait("pair-error")["error"], "update-required")
        b.emit("pair-claim", {"nameplate": "12", "v": 2})
        self.assertEqual(b.wait("pair-error"), {"error": "invalid", "why": "bad-nameplate"})

    def test_creator_gone(self):
        a, _ = self.joined(uniq(), "a")
        n = self.nameplate()
        a.emit("pair-create", {"nameplate": n, "v": 2})
        a.wait("pair-ok")
        a.close()
        time.sleep(1.0)
        b = self.peer()
        b.emit("pair-claim", {"nameplate": n, "v": 2})
        self.assertEqual(b.wait("pair-error"), {"error": "invalid", "why": "sender-gone"})


# Polling liveness (PR #608, fix/polling-liveness; mirrored in edge/signal).
# FIL_POLL_HOLD_S=2, FIL_POLL_GRACE_S=7, FIL_POLL_TICK_S=1 on the backend.
HOLD, GRACE, TICK = 2.0, 7.0, 1.0


class RawPoller:
    """A minimal engine.io v4 long-polling client (no websocket), ported from
    backend/tests/test_poll_liveness.py to speak to any base URL."""

    def __init__(self):
        body = http("GET", "/socket.io/?EIO=4&transport=polling").text
        assert body.startswith("0"), body
        self.eid = json.loads(body[1:])["sid"]
        self.q = f"/socket.io/?EIO=4&transport=polling&sid={self.eid}"
        assert http("POST", self.q, data="40").status_code == 200
        first = http("GET", self.q).text.split("\x1e")
        self.sid = json.loads(first[0][2:])["sid"]
        self.stop = threading.Event()
        self.gets = 0
        self.packets = []

    def emit(self, event, payload):
        assert http("POST", self.q, data="42" + json.dumps([event, payload])).status_code == 200

    def run(self, delay=0.0):
        """Poll until stopped, answering pings; `delay` slows each re-poll."""
        while not self.stop.is_set():
            try:
                r = http("GET", self.q, timeout=60)
            except Exception:
                return
            if r.status_code != 200:
                return
            self.gets += 1
            for pkt in r.text.split("\x1e"):
                self.packets.append(pkt[:1])
                if pkt == "2":
                    http("POST", self.q, data="3")
            if delay:
                time.sleep(delay)


@unittest.skipUnless(os.environ.get("CONFORMANCE_POLL_LIVENESS") == "1",
                     "polling liveness (PR #608): set CONFORMANCE_POLL_LIVENESS=1 "
                     "once the backend under test carries it")
class PollLiveness(Base):
    """A long-polling client that stops polling without a word (a killed tab)
    leaves the room within seconds, not after pingInterval + pingTimeout
    (85 s in production); one that keeps polling, even slowly, stays."""

    def start(self, poller, **kw):
        th = threading.Thread(target=poller.run, kwargs=kw, daemon=True)
        th.start()
        self.addCleanup(poller.stop.set)
        return th

    def test_silent_polling_client_leaves_quickly(self):
        room = uniq()
        watcher, _ = self.joined(room, "watcher")
        a, b = RawPoller(), RawPoller()
        self.start(a)
        self.start(b)
        a.emit("join", {"room": room, "name": "a", "uid": uniq("u"), "gen": uniq("g")})
        b.emit("join", {"room": room, "name": "b", "uid": uniq("u"), "gen": uniq("g")})
        watcher.wait("peer-joined", lambda d: d["id"] == a.sid)
        watcher.wait("peer-joined", lambda d: d["id"] == b.sid)
        # Well past HOLD + GRACE while both keep polling: nobody leaves, and
        # held GETs are cycled with NOOPs.
        watcher.none("peer-left", within=HOLD * 2 + GRACE)
        self.assertIn("6", a.packets, "a held GET was not cycled with a NOOP")
        # b dies without a word: it just stops polling.
        b.stop.set()
        t0 = time.time()
        bound = HOLD + GRACE + 2 * TICK + 3.0  # + the round trips of a remote backend
        watcher.wait("peer-left", lambda d: d["id"] == b.sid, timeout=bound + 10)
        took = time.time() - t0
        self.assertLessEqual(took, bound, f"left after {took:.1f}s, want <= {bound:.1f}s")
        watcher.none("peer-left", lambda d: d["id"] == a.sid)

    def test_slow_poller_inside_the_grace_is_kept(self):
        room = uniq()
        watcher, _ = self.joined(room, "watcher")
        p = RawPoller()
        self.start(p, delay=GRACE * 0.6)
        p.emit("join", {"room": room, "name": "slow", "uid": uniq("u"), "gen": uniq("g")})
        watcher.wait("peer-joined", lambda d: d["id"] == p.sid)
        watcher.none("peer-left", within=GRACE * 4)
        self.assertGreater(p.gets, 3)

if __name__ == "__main__":
    unittest.main()
