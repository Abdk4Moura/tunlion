"""Socket.IO signaling relay.

A *dumb pipe*: it never sees file bytes. It tracks who is in which room and
forwards opaque WebRTC payloads (SDP/ICE) between peers, keyed by socket id.

Scaling: room membership lives behind a small Registry. With no Redis it's an
in-memory dict (single instance, the dev default). Set FIL_REDIS_URL and it
moves to Redis — combined with Socket.IO's Redis message queue (see app.py),
that lets you run many api replicas and scale them up/down on demand, because
every instance shares the same room state and can deliver to any peer.

Event contract (kept in sync with CONTRACT.md):
  client -> server   join {room,name,uid,gen,token} ·
                     sync {room,name,uid,gen,token,channels}
                     signal {to,data} · leave {}
  server -> client   welcome {id,peers:[{id,name,uid}],token?} ·
                     peer-joined {id,name,uid} · peer-left {id} ·
                     peer-updated {id,name,uid} · session-superseded {reason} ·
                     signal {from,data}
  HTTP               POST /api/session/close {token,gen} (pagehide beacon)

`gen` is a fresh per-page-load generation. `token` is the opaque SESSION key,
minted by the relay on a tokenless join and returned only to that socket (in
the welcome/sync ack, never in a roster). A valid token may replace its own
previous sid; a new generation for that token retires the old one. uid/name are
display attributes only: a uid alone is never authority, and a tokenless client
gets an independent session (one per socket: a client that omits both token and
gen keeps the session its socket was given).
"""
import os
import re
import secrets
import threading
import time as _time
from collections import deque

from flask import request
from flask_socketio import emit, join_room, leave_room

import ratelimit

# One-time pairing nameplate allocation. v2 ONLY: the client CSPRNG-mints the
# WORDS locally (spec S2.0), the server allocates/matches only the numeric
# nameplate (the password NEVER reaches the server). The v1 word-minting path
# has been removed (Decision #1: v2-only cutover).


# Test-only adversary (gate P): drop named SERVER->CLIENT pushes so a client's
# ability to RECOVER from a missed push can be tested directly, instead of
# waiting for a platform to drop one by accident.
#
# Every push the client can miss must be recoverable from the `sync` digest,
# which carries the full roster (C30 phase 2). This makes that property
# testable: drop `peer-joined`, and a correct client still converges on the
# next sync. A client that discards the digest roster waits out its full
# claim deadline instead, which is the macOS smoke failure.
#
# FILAMENT_TEST_DROP_PUSH="peer-joined,welcome"   (unset in production)
_DROP_PUSH = {
    e.strip() for e in os.environ.get("FILAMENT_TEST_DROP_PUSH", "").split(",") if e.strip()
}


def _push(event, payload, **kw):
    """emit(), minus any event gate P is configured to swallow."""
    if event in _DROP_PUSH:
        return
    emit(event, payload, **kw)


def _norm_code(raw):
    """Normalize a spoken keyword: lowercase, spaces→dashes, strip noise."""
    if not isinstance(raw, str):
        return ""
    return re.sub(r"[^a-z0-9-]", "", re.sub(r"\s+", "-", raw.strip().lower()))[:48]


_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _valid_id(value):
    """Session ids cross a JSON boundary. Require a short, separator-safe str
    before they become Redis key/hash/zset members or Python dict keys."""
    return isinstance(value, str) and bool(_ID_RE.match(value))


def origin_allowed(origin, allowed):
    """Whether a pagehide beacon Origin may reach the close endpoint.

    No Origin is allowed (some same-origin beacons omit it) because the bearer
    token still gates the operation. "*" is the dev/simple default; otherwise
    the configured list is enforced exactly.
    """
    if not origin:
        return True
    if allowed == "*":
        return True
    try:
        return origin in allowed
    except TypeError:
        return False


class _MemRegistry:
    """Process-local membership (single instance).

    Liveness (#10, dev parity): same lease idea as _RedisRegistry, backed by a
    dict of monotonic expiries. Without it the in-proc backend advertised
    SIGKILL'd sids (ghosts) until the engine.io ping timeout fired disconnect.
    """

    LIVE_TTL = 60  # liveness lease; refreshed by the lease loop + on activity
    SESSION_TTL = 24 * 3600  # token/session lifetime (sliding on use)
    SESSION_LIVE_WINDOW = 120  # last claim heartbeat; sync is every 5s
    RETIRED_TTL = 24 * 3600  # per-token generation tombstone lifetime
    MAX_SESSIONS = 50_000  # token records (LRU-evicted, never uid ownership)
    MAX_RETIRED_TOTAL = 200_000

    def __init__(self):
        self._m = {}  # sid -> {"room", "name", "uid", "gen"}
        self._live = {}  # sid -> lease expiry (monotonic)
        # TOKEN -> {"sid", "gen", "uid", "name", "last_seen", "exp"}.
        # uid/name are display attributes only; the token is the session key.
        # Retired generations are (token, gen) -> expiry, globally bounded.
        self._sessions = {}
        self._sid_token = {}
        self._retired = {}
        self._retired_order = deque()
        # async_mode=threading really is concurrent: claim/take must not
        # interleave or two generations can both believe they own a session.
        self._lock = threading.RLock()

    def refresh(self, sids):
        """Extend the liveness lease for connected sids."""
        exp = _time.monotonic() + self.LIVE_TTL
        with self._lock:
            for sid in sids:
                self._live[sid] = exp

    def _alive(self, sid):
        return self._live.get(sid, 0) > _time.monotonic()

    def add(self, sid, room, name, uid=None, gen=None):
        with self._lock:
            self._m[sid] = {"room": room, "name": name, "uid": uid, "gen": gen}
            self.refresh([sid])

    def room_of(self, sid):
        with self._lock:
            m = self._m.get(sid)
            return m["room"] if m else None

    def remove(self, sid):
        with self._lock:
            self._live.pop(sid, None)
            # Keep the session's recorded sid: a same-token reconnect uses it
            # as `prev` and replaces it. Clearing it here made a fresh join
            # lose its own owner before the room announcement.
            self._sid_token.pop(sid, None)
            m = self._m.pop(sid, None)
            return m["room"] if m else None

    def claim_session(self, token, gen, sid, uid, name):
        """Create or reattach a TOKEN-keyed session.

        uid/name are display attributes. The token is the only key and the only
        authority: a caller without a valid token gets a brand-new session and
        can never evict or close any other session. Returns
        {status, token, gen, prev, evicted, retired?}.
        """
        if not _valid_id(uid) or not _valid_id(gen):
            return {"status": "denied", "token": None, "gen": None, "prev": None, "evicted": []}
        if token is not None and (not isinstance(token, str) or not token or len(token) > 512):
            return {"status": "denied", "token": None, "gen": None, "prev": None, "evicted": []}
        with self._lock:
            now = _time.time()
            self._prune_retired(now)
            evicted = self._prune_sessions(now)
            rec = self._sessions.get(token) if token else None
            if rec and rec.get("exp", 0) <= now:
                self._sessions.pop(token, None)
                if rec.get("sid") and rec.get("sid") != sid:
                    evicted.append(rec["sid"])
                rec = None
            if rec is not None:
                if self._is_retired(token, gen):
                    return {"status": "retired", "token": token, "gen": rec.get("gen"),
                            "prev": rec.get("sid"), "evicted": evicted}
                rec["last_seen"] = now
                rec["exp"] = now + self.SESSION_TTL
                rec["uid"] = uid
                rec["name"] = name
                if rec.get("gen") == gen:
                    prev = rec.get("sid")
                    if prev != sid:
                        self._sid_token.pop(prev, None)
                        rec["sid"] = sid
                        self._sid_token[sid] = token
                        return {"status": "replace", "token": token, "gen": gen,
                                "prev": prev, "evicted": evicted}
                    return {"status": "current", "token": token, "gen": gen,
                            "prev": None, "evicted": evicted}
                old = rec.get("gen")
                prev = rec.get("sid")
                if old:
                    self._add_retired(token, old, now)
                if prev and prev != sid:
                    self._sid_token.pop(prev, None)
                rec["gen"] = gen
                rec["sid"] = sid
                self._sid_token[sid] = token
                return {"status": "new", "token": token, "gen": gen,
                        "prev": prev, "evicted": evicted}
            # No token, unknown token, or expired token: a fresh independent
            # session. The caller's uid/name are only labels here.
            made = self._make_room(now)
            if made is None:
                return {"status": "capacity", "token": None, "gen": None,
                        "prev": None, "evicted": evicted}
            evicted += made
            issued = secrets.token_urlsafe(24)
            self._sessions[issued] = {"sid": sid, "gen": gen, "uid": uid, "name": name,
                                      "last_seen": now, "exp": now + self.SESSION_TTL}
            self._sid_token[sid] = issued
            return {"status": "new", "token": issued, "gen": gen,
                    "prev": None, "evicted": evicted}

    def _prune_sessions(self, now):
        """Drop expired token records; return their sids for room cleanup."""
        out = []
        for token, rec in list(self._sessions.items()):
            if rec.get("exp", 0) <= now:
                self._sessions.pop(token, None)
                sid = rec.get("sid")
                if sid:
                    self._sid_token.pop(sid, None)
                    out.append(sid)
        return out

    def _session_live(self, rec, now):
        """A session is live only if its sid is connected AND its last claim is
        inside the configured heartbeat window. A stale score with a lingering
        sid is not live and may be evicted under capacity pressure."""
        sid = rec.get("sid")
        if not sid or not self._alive(sid):
            return False
        return (now - rec.get("last_seen", 0)) <= self.SESSION_LIVE_WINDOW

    def _make_room(self, now):
        """Capacity is on TOKEN records only. Prefer expired/closed/non-live
        records; never evict a live session. Returns evicted sids, or None when
        every record is live (caller returns a capacity error)."""
        if len(self._sessions) < self.MAX_SESSIONS:
            return []
        out = []
        candidates = [
            (token, rec)
            for token, rec in self._sessions.items()
            if not self._session_live(rec, now)
        ]
        if not candidates:
            return None
        # Remove every non-live record on pressure, matching Redis. This frees
        # multiple stale slots without touching a genuinely live session.
        for token, rec in candidates:
            self._sessions.pop(token, None)
            sid = rec.get("sid")
            if sid:
                self._sid_token.pop(sid, None)
                out.append(sid)
        return out

    def _prune_retired(self, now):
        """Global (token, gen) tombstones: 24h TTL + hard total cap."""
        while self._retired_order:
            token, gen, exp = self._retired_order[0]
            if exp > now and len(self._retired) < self.MAX_RETIRED_TOTAL:
                break
            self._retired_order.popleft()
            if self._retired.get((token, gen)) == exp:
                self._retired.pop((token, gen), None)
        while len(self._retired) >= self.MAX_RETIRED_TOTAL and self._retired_order:
            token, gen, exp = self._retired_order.popleft()
            if self._retired.get((token, gen)) == exp:
                self._retired.pop((token, gen), None)

    def _is_retired(self, token, gen):
        exp = self._retired.get((token, gen))
        if exp is None:
            return False
        if exp <= _time.time():
            self._retired.pop((token, gen), None)
            return False
        return True

    def _add_retired(self, token, gen, now):
        self._prune_retired(now)
        key = (token, gen)
        if key in self._retired:
            return
        exp = now + self.RETIRED_TTL
        self._retired[key] = exp
        self._retired_order.append((token, gen, exp))

    def holds_session(self, token, gen, sid):
        """True when `sid` is already the live holder of TOKEN at generation
        `gen`: a claim with these values could only be a refresh ("current"),
        never a create, a takeover or a generation bump. Read-only."""
        if not isinstance(token, str) or not token or not _valid_id(gen):
            return False
        with self._lock:
            rec = self._sessions.get(token)
            if not rec or rec.get("exp", 0) <= _time.time():
                return False
            return rec.get("gen") == gen and rec.get("sid") == sid

    def rename(self, sid, name):
        with self._lock:
            m = self._m.get(sid)
            if not m:
                return None
            m["name"] = name
            return {"id": sid, "name": name, "uid": m.get("uid")}

    def take_session(self, token, gen):
        """Close the current sid for this token+generation. Wrong/expired token
        or an old generation returns None."""
        if not isinstance(token, str) or not token or not _valid_id(gen):
            return None
        with self._lock:
            now = _time.time()
            rec = self._sessions.get(token)
            if not rec or rec.get("exp", 0) <= now or rec.get("gen") != gen:
                return None
            sid = rec.get("sid")
            if sid:
                self._sid_token.pop(sid, None)
                self._live.pop(sid, None)
            rec["sid"] = None
            rec["gen"] = None
            rec["last_seen"] = now
            rec["exp"] = now + self.SESSION_TTL
            self._add_retired(token, gen, now)
            m = self._m.pop(sid, None) if sid else None
            return {"sid": sid, "room": m.get("room") if m else None}

    def peers_in(self, room, exclude=None):
        # Snapshot under the same lock that add/remove/take use: iterating a
        # live dict while another thread mutates it raises RuntimeError.
        with self._lock:
            items = list(self._m.items())
            return [
                {"id": s, "name": v["name"], "uid": v.get("uid")}
                for s, v in items
                if v["room"] == room and s != exclude and self._alive(s)
            ]

    def meta(self, sid):
        with self._lock:
            m = self._m.get(sid)
            return {"id": sid, "name": m["name"], "uid": m.get("uid")} if m else None

    # -- persistent-pair presence channels (C12): a channel id is a hash of an
    # E2E-shared secret; two sids in the same channel are mutually-trusted
    # devices and get told about each other regardless of room.
    def subscribe(self, sid, channels):
        chans = getattr(self, "_chan", None)
        if chans is None:
            chans = self._chan = {}
        bysid = getattr(self, "_sidchan", None)
        if bysid is None:
            bysid = self._sidchan = {}
        bysid.setdefault(sid, set()).update(channels)
        out = {}
        for ch in channels:
            members = chans.setdefault(ch, set())
            # lease-filter (#10) + lazy cleanup: dead sids vanish on first look
            members -= {s for s in members if s != sid and not self._alive(s)}
            out[ch] = [s for s in members if s != sid]
            members.add(sid)
        return out  # channel -> other live sids already present

    def share_channel(self, a, b):
        """Whether sids `a` and `b` are subscribed to at least one common channel."""
        bysid = getattr(self, "_sidchan", {})
        return bool(bysid.get(a, set()) & bysid.get(b, set()))

    def unsubscribe_all(self, sid):
        affected = {}
        for ch in getattr(self, "_sidchan", {}).pop(sid, set()):
            members = getattr(self, "_chan", {}).get(ch, set())
            members.discard(sid)
            others = [s for s in members if self._alive(s)]
            if others:
                affected[ch] = others
        return affected

    def unsubscribe(self, sid, channels):
        affected = {}
        bysid = getattr(self, "_sidchan", {})
        sid_chans = bysid.get(sid, set())
        for ch in channels:
            sid_chans.discard(ch)
            members = getattr(self, "_chan", {}).get(ch, set())
            members.discard(sid)
            others = [s for s in members if self._alive(s)]
            if others:
                affected[ch] = others
        return affected  # channel -> remaining sids to notify

    # -- one-time pairing codes (#11) --
    def pair_create(self, code, sid, ttl=600):
        pairs = getattr(self, "_pairs", None)
        if pairs is None:
            pairs = self._pairs = {}
        if code in pairs:
            return False
        pairs[code] = sid
        return True

    def pair_claim(self, code):
        return getattr(self, "_pairs", {}).pop(code, None)

    def peek_pair(self, code):
        """Telemetry only: (exists, creator, creator_alive) without consuming."""
        creator = getattr(self, "_pairs", {}).get(code)
        return (creator is not None, creator, creator in self._m)


class _RedisRegistry:
    """Shared membership in Redis so api replicas see one another's peers.

    Liveness (#10): membership alone can't be trusted — an api restart kills
    sockets without running disconnect handlers, orphaning entries that then
    appear in every `welcome` as zombie peers. So every connection also holds a
    short LEASE, refreshed by its owning instance; `peers_in` only returns
    leased entries and lazily deletes the dead ones.
    """

    TTL = 86400  # room/sid bookkeeping
    SESSION_TTL = _MemRegistry.SESSION_TTL
    SESSION_LIVE_WINDOW = _MemRegistry.SESSION_LIVE_WINDOW
    RETIRED_TTL = _MemRegistry.RETIRED_TTL
    MAX_SESSIONS = _MemRegistry.MAX_SESSIONS
    MAX_RETIRED_TOTAL = _MemRegistry.MAX_RETIRED_TOTAL
    LIVE_TTL = 120  # liveness lease; refreshed every ~15s while connected

    def __init__(self, url):
        import redis  # lazy: only needed when scaling with Redis

        self.r = redis.Redis.from_url(url, decode_responses=True)

    def _rk(self, room):
        return f"filament:room:{room}"

    def _sk(self, sid):
        return f"filament:sid:{sid}"

    def _lk(self, sid):
        return f"filament:live:{sid}"

    def _sess(self, token):
        return f"filament:session:{token}"

    def _sessions(self):
        return "filament:sessions"

    def _retired_key(self):
        return "filament:retired:gens"

    def add(self, sid, room, name, uid=None, gen=None):
        import json

        p = self.r.pipeline()
        p.hset(self._rk(room), sid, json.dumps({"name": name, "uid": uid, "gen": gen}))
        p.expire(self._rk(room), self.TTL)
        p.set(self._sk(sid), room, ex=self.TTL)
        p.set(self._lk(sid), 1, ex=self.LIVE_TTL)  # liveness lease (#10)
        p.execute()

    def claim_session(self, token, gen, sid, uid, name):
        """Atomic TOKEN-keyed session claim (no uid ownership anywhere).

        Returns status/token/gen/prev/evicted. An unknown or expired token gets
        a brand-new SESSION; it can never touch an existing token record.
        """
        if not _valid_id(uid) or not _valid_id(gen):
            return {"status": "denied", "token": None, "gen": None, "prev": None, "evicted": []}
        if token is not None and (not isinstance(token, str) or not token or len(token) > 512):
            return {"status": "denied", "token": None, "gen": None, "prev": None, "evicted": []}
        candidate = secrets.token_urlsafe(24)
        now = _time.time()
        lookup = token if token else candidate
        status, out_token, out_gen, prev, evicted = self.r.eval(
            """
            local cur = redis.call('HMGET', KEYS[1], 'sid', 'gen')
            local cursid, curgen = cur[1], cur[2]
            local exists = redis.call('EXISTS', KEYS[1])
            local has_token = (ARGV[8] ~= '' and exists == 1)
            redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[5])
            if has_token then
              -- A token record exists even if it is closed (gen/sid empty).
              -- The retired check applies to closed slots too.
              if redis.call('ZSCORE', KEYS[2], ARGV[8] .. '|' .. ARGV[1]) then
                return {'retired', ARGV[8], curgen or '', cursid or '', ''}
              end
              redis.call('EXPIRE', KEYS[1], ARGV[4])
              redis.call('HSET', KEYS[1], 'uid', ARGV[9], 'name', ARGV[10], 'last_seen', ARGV[5])
              redis.call('ZADD', KEYS[3], ARGV[5], ARGV[8])
              redis.call('EXPIRE', KEYS[3], tonumber(ARGV[4]) * 2)
              if (not curgen) or curgen == '' then
                redis.call('HSET', KEYS[1], 'gen', ARGV[1], 'sid', ARGV[2])
                return {'new', ARGV[8], ARGV[1], '', ''}
              end
              if curgen == ARGV[1] then
                if cursid == ARGV[2] then return {'current', ARGV[8], curgen, '', ''} end
                redis.call('HSET', KEYS[1], 'sid', ARGV[2])
                return {'replace', ARGV[8], curgen, cursid or '', ''}
              end
              while redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[6]) do
                redis.call('ZREMRANGEBYRANK', KEYS[2], 0, 0)
              end
              redis.call('ZADD', KEYS[2], tonumber(ARGV[5]) + tonumber(ARGV[12]),
                         ARGV[8] .. '|' .. curgen)
              redis.call('EXPIRE', KEYS[2], tonumber(ARGV[12]) * 2)
              redis.call('HSET', KEYS[1], 'gen', ARGV[1], 'sid', ARGV[2])
              return {'new', ARGV[8], ARGV[1], cursid or '', ''}
            end
            -- No usable token: fresh SESSION. Capacity prefers expired/closed
            -- records; it NEVER evicts a live session. If all are live, refuse.
            local evicted = ''
            local cards = redis.call('ZCARD', KEYS[3])
            if cards >= tonumber(ARGV[11]) then
              local all = redis.call('ZRANGE', KEYS[3], 0, -1)
              for _, tok in ipairs(all) do
                local skey = 'filament:session:' .. tok
                if redis.call('EXISTS', skey) == 0 then
                  redis.call('ZREM', KEYS[3], tok)
                end
              end
              cards = redis.call('ZCARD', KEYS[3])
            end
            if cards >= tonumber(ARGV[11]) then
              local all = redis.call('ZRANGE', KEYS[3], 0, -1)
              for _, tok in ipairs(all) do
                local skey = 'filament:session:' .. tok
                local h = redis.call('HMGET', skey, 'sid', 'gen')
                local esid, egen = h[1], h[2]
                local score = redis.call('ZSCORE', KEYS[3], tok)
                local connected = esid and esid ~= '' and redis.call('EXISTS', 'filament:live:' .. esid) == 1
                local stale = (not score) or tonumber(score) < (tonumber(ARGV[5]) - tonumber(ARGV[13]))
                if (not egen) or egen == '' or (not connected) or stale then
                  if esid and esid ~= '' then evicted = evicted .. esid .. ',' end
                  redis.call('DEL', skey)
                  redis.call('ZREM', KEYS[3], tok)
                end
              end
              cards = redis.call('ZCARD', KEYS[3])
            end
            if cards >= tonumber(ARGV[11]) then
              return {'capacity', '', '', '', evicted}
            end
            local newkey = 'filament:session:' .. ARGV[7]
            redis.call('HSET', newkey, 'sid', ARGV[2], 'gen', ARGV[1],
                       'uid', ARGV[9], 'name', ARGV[10], 'last_seen', ARGV[5])
            redis.call('EXPIRE', newkey, ARGV[4])
            redis.call('ZADD', KEYS[3], ARGV[5], ARGV[7])
            redis.call('EXPIRE', KEYS[3], tonumber(ARGV[4]) * 2)
            return {'new', ARGV[7], ARGV[1], '', evicted}
            """,
            3, self._sess(lookup), self._retired_key(), self._sessions(),
            gen, sid, str(token) if token else "", self.SESSION_TTL, now,
            self.MAX_RETIRED_TOTAL, candidate,
            str(token) if token else "",  # ARGV[8] token for existing records
            uid, name, self.MAX_SESSIONS, self.RETIRED_TTL,
            self.SESSION_LIVE_WINDOW,
        )
        return {"status": status, "token": out_token or None, "gen": out_gen or None,
                "prev": prev or None,
                "evicted": [s for s in (evicted or "").split(",") if s]}

    def holds_session(self, token, gen, sid):
        """Redis twin of _MemRegistry.holds_session (read-only peek)."""
        if not isinstance(token, str) or not token or not _valid_id(gen):
            return False
        cur_sid, cur_gen = self.r.hmget(self._sess(token), "sid", "gen")
        return bool(cur_gen) and cur_gen == gen and cur_sid == sid

    def rename(self, sid, name):
        import json

        room = self.r.get(self._sk(sid))
        if not room:
            return None
        raw = self.r.hget(self._rk(room), sid)
        try:
            v = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            v = {"uid": None}
        v["name"] = name
        self.r.hset(self._rk(room), sid, json.dumps(v))
        return {"id": sid, "name": name, "uid": v.get("uid")}

    def take_session(self, token, gen):
        if not isinstance(token, str) or not token or not _valid_id(gen):
            return None
        sid, room = self.r.eval(
            """
            local cur = redis.call('HMGET', KEYS[1], 'sid', 'gen')
            if not cur[2] or cur[2] ~= ARGV[2] then return {'', ''} end
            local sid = cur[1]
            if not sid then return {'', ''} end
            local room = redis.call('GET', 'filament:sid:' .. sid)
            while redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[4]) do
              redis.call('ZREMRANGEBYRANK', KEYS[2], 0, 0)
            end
            redis.call('ZADD', KEYS[2], tonumber(ARGV[3]) + tonumber(ARGV[5]),
                       ARGV[1] .. '|' .. ARGV[2])
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[5]) * 2)
            redis.call('HSET', KEYS[1], 'gen', '', 'sid', '')
            redis.call('EXPIRE', KEYS[1], ARGV[6])
            redis.call('ZADD', KEYS[3], ARGV[3], ARGV[1])
            redis.call('EXPIRE', KEYS[3], tonumber(ARGV[6]) * 2)
            return {sid, room or ''}
            """,
            3, self._sess(token), self._retired_key(), self._sessions(),
            token, gen, _time.time(), self.MAX_RETIRED_TOTAL, self.RETIRED_TTL,
            self.SESSION_TTL,
        )
        if not sid:
            return None
        if room:
            p = self.r.pipeline()
            p.hdel(self._rk(room), sid)
            p.delete(self._sk(sid))
            p.delete(self._lk(sid))
            p.execute()
        return {"sid": sid, "room": room or None}

    def refresh(self, sids):
        """Extend the liveness lease for locally-connected sids."""
        if not sids:
            return
        p = self.r.pipeline()
        for sid in sids:
            p.set(self._lk(sid), 1, ex=self.LIVE_TTL)
        p.execute()

    def room_of(self, sid):
        return self.r.get(self._sk(sid))

    def remove(self, sid):
        room = self.r.get(self._sk(sid))
        if room:
            p = self.r.pipeline()
            p.hdel(self._rk(room), sid)
            p.delete(self._sk(sid))
            p.delete(self._lk(sid))
            p.execute()
            # The uid->generation ownership record deliberately survives:
            # a same-generation socket reconnect reclaims it, a newer
            # generation still supersedes this sid, and a stale old generation
            # can never clear the new owner. take_session() drops it on close.
        return room

    def meta(self, sid):
        import json

        room = self.r.get(self._sk(sid))
        if not room:
            return None
        raw = self.r.hget(self._rk(room), sid)
        try:
            v = json.loads(raw) if raw else {}
        except (TypeError, ValueError):
            v = {"name": raw}
        return {"id": sid, "name": v.get("name"), "uid": v.get("uid")}

    def _ck(self, channel):
        return f"filament:chan:{channel}"

    def _sck(self, sid):
        return f"filament:sidchan:{sid}"

    def subscribe(self, sid, channels):
        out = {}
        p = self.r.pipeline()
        for ch in channels:
            p.smembers(self._ck(ch))
        existing = p.execute()
        p = self.r.pipeline()
        for ch, members in zip(channels, existing):
            # lease-filter (#10): only live sids count
            live = [s for s in members if s != sid and self.r.exists(self._lk(s))]
            out[ch] = live
            p.sadd(self._ck(ch), sid)
            p.expire(self._ck(ch), self.TTL)
            p.sadd(self._sck(sid), ch)
            p.expire(self._sck(sid), self.TTL)
        p.execute()
        return out

    def unsubscribe(self, sid, channels):
        affected = {}
        p = self.r.pipeline()
        for ch in channels:
            p.srem(self._ck(ch), sid)
            p.srem(self._sck(sid), ch)
        p.execute()
        for ch in channels:
            others = [s for s in self.r.smembers(self._ck(ch)) if s != sid and self.r.exists(self._lk(s))]
            if others:
                affected[ch] = others
        return affected

    def share_channel(self, a, b):
        """Whether sids `a` and `b` are subscribed to at least one common channel."""
        return bool(self.r.sinter(self._sck(a), self._sck(b)))

    def unsubscribe_all(self, sid):
        affected = {}
        for ch in self.r.smembers(self._sck(sid)):
            self.r.srem(self._ck(ch), sid)
            others = [s for s in self.r.smembers(self._ck(ch)) if self.r.exists(self._lk(s))]
            if others:
                affected[ch] = others
        self.r.delete(self._sck(sid))
        return affected

    # -- one-time pairing codes (#11): SET NX EX to create, GETDEL to consume
    # atomically — a code can be claimed exactly once, ever.
    def pair_create(self, code, sid, ttl=600):
        return bool(self.r.set(f"filament:pair:{code}", sid, nx=True, ex=ttl))

    def peek_pair(self, code):
        """Telemetry only: (exists, creator, creator_alive) without consuming."""
        creator = self.r.get(f"filament:pair:{code}")
        return (creator is not None, creator, bool(creator and self.r.exists(self._lk(creator))))

    def pair_claim(self, code):
        creator = self.r.getdel(f"filament:pair:{code}")
        # Don't match against a creator whose connection is already dead.
        if creator and not self.r.exists(self._lk(creator)):
            return None
        return creator

    def peers_in(self, room, exclude=None):
        import json

        entries = self.r.hgetall(self._rk(room))
        sids = [s for s in entries if s != exclude]
        if not sids:
            return []
        # Liveness check (#10): only entries holding a lease are real.
        p = self.r.pipeline()
        for s in sids:
            p.exists(self._lk(s))
        alive = dict(zip(sids, p.execute()))

        out, dead = [], []
        for s in sids:
            if not alive.get(s):
                dead.append(s)
                continue
            raw = entries[s]
            try:
                v = json.loads(raw)
                out.append({"id": s, "name": v.get("name"), "uid": v.get("uid")})
            except (json.JSONDecodeError, AttributeError):
                out.append({"id": s, "name": raw, "uid": None})  # pre-uid entry
        if dead:  # lazy cleanup: zombies vanish the first time anyone looks
            p = self.r.pipeline()
            p.hdel(self._rk(room), *dead)
            for s in dead:
                p.delete(self._sk(s))
            p.execute()
        return out


def make_registry(redis_url):
    return _RedisRegistry(redis_url) if redis_url else _MemRegistry()


def close_session(socketio, registry, token, gen):
    """Best-effort pagehide close for one TOKEN+generation.

    Only the token holder with the current generation can close it. A late
    beacon from an older generation is ignored. Returns bool.
    """
    info = registry.take_session(token, gen)
    if not info:
        return False
    sid = info.get("sid")
    room = info.get("room")
    if not sid:
        return False
    # This runs OUTSIDE a Socket.IO event (an HTTP beacon), where the
    # Flask-SocketIO wrapper's include_self/skip_sid path reads flask.request.sid
    # and raises. The underlying server emit addresses sids/rooms directly and
    # works from any context (including cross-replica with the Redis queue).
    for ch, others in registry.unsubscribe_all(sid).items():
        for other in others:
            socketio.server.emit("known-peer-left", {"id": sid, "channel": ch}, to=other)
    if room:
        socketio.server.emit("peer-left", {"id": sid}, to=room)
    socketio.server.emit("session-superseded", {"reason": "page-closed"}, to=sid)
    _tel("session-close", sid=sid, gen=str(gen)[:8], tok=str(token)[:8])
    return True


def _tel(event, **kv):
    """Debugger-grade telemetry (C24): one JSON line per lifecycle event,
    prefixed TEL, to stdout -> docker logs. No file contents, no file names."""
    import json as _json
    import sys as _sys
    import time as _t

    try:
        print("TEL " + _json.dumps({"ts": round(_t.time(), 3), "ev": event, **kv}, separators=(",", ":")), flush=True)
    except Exception:
        _sys.stderr.write("TEL-fail\n")


# ALLOWS 3-5 digits (spec nameplate: 900 -- 3-digit, but 4-5 gas for widening).
_NAMEPLATE_RE = re.compile(r"^[0-9]{3,5}$")

def register(socketio, registry):
    local_sids = set()  # connections owned by THIS instance (for lease refresh)

    def _eio_alive(sid):
        """Ground truth for sids THIS instance owns: is the underlying
        engine.io socket still open? Catches a SIGKILL'd client the moment the
        transport sees FIN/RST -- long before any lease lapses or the ping
        timeout fires."""
        try:
            eio_sid = socketio.server.manager.eio_sid_from_sid(sid, "/")
            sock = socketio.server.eio.sockets.get(eio_sid)
            return sock is not None and not sock.closed
        except Exception:
            return True  # never let introspection failure hide live peers

    def _sid_alive(sid):
        """Roster/known-peer gate (#10): a locally-owned sid must have a live
        socket; a remote sid (another instance) is vouched for by the lease the
        registry already filters on."""
        return sid not in local_sids or _eio_alive(sid)

    @socketio.on("connect")
    def on_connect():
        local_sids.add(request.sid)
        registry.refresh([request.sid])  # liveness lease from the first moment
        _tel("connect", sid=request.sid)

    def _lease_loop():
        # Refresh every 15s (TTL is 60s mem / 120s Redis) but ONLY for sids
        # whose engine.io socket is still open — a dead-but-undetected socket
        # stops being refreshed, so its lease lapses and every roster filter
        # stops advertising it even before disconnect fires.
        while True:
            socketio.sleep(15)
            try:
                registry.refresh([s for s in list(local_sids) if _eio_alive(s)])
            except Exception:
                pass

    socketio.start_background_task(_lease_loop)

    _session_claim_limiter = ratelimit.make_limiter(
        "session-claim",
        int(os.environ.get("FIL_SESSION_CLAIM_LIMIT", "600")),
        60.0,
        getattr(registry, "r", None),
    )

    # What the per-IP budget protects: every claim that is not a pure refresh
    # can mint a session record (MAX_SESSIONS, whose capacity path evicts
    # other callers' non-live sessions and then refuses everyone), add a
    # retired-generation tombstone (MAX_RETIRED_TOTAL, a global FIFO, so a
    # flood would age out other tokens' tombstones), or move a session to a
    # new sid. Those stay charged to the sid AND the caller's IP.
    #
    # A periodic full `sync` from the socket that already holds the session at
    # the same generation, in the room it is already in, does none of that:
    # registry.claim_session answers "current" and only slides the TTL. It is
    # charged to the sid only. Charging it to the IP made the budget a device
    # cap: a daemon full-syncs every 30 s, so 600/min allowed about 300
    # devices behind one public IP (an office or carrier NAT), and the rest
    # were silently refused with session-superseded {reason: rate-limited}.
    #
    # sid -> (token, gen) the relay minted for a tokenless, generation-less
    # (CLI) claim on this socket. Local to this instance (a socket's events
    # always arrive at its own instance) and dropped on leave/disconnect or
    # when the sid is superseded or evicted, so it is bounded by live sockets.
    _legacy_sessions = {}

    def _session_claim_allowed(sid, refresh_only=False):
        keys = [f"sid:{sid}"]
        if not refresh_only:
            keys.append("ip:" + ratelimit.ip_bucket(ratelimit.client_ip(request)))
        return _session_claim_limiter.allow(keys)

    def _claim_session(sid, uid, gen, token, name, room=None):
        """Create/reattach a token-keyed session and return
        (ok, owner_token, effective_gen). uid/name are labels only.

        `room` is passed by `sync` only: when this sid already holds TOKEN at
        GEN and is already in ROOM, the claim is a refresh and skips the
        per-IP budget (see _session_claim_allowed). `join` never passes it."""
        if not _valid_id(uid):
            _tel("session-invalid", sid=sid)
            emit("session-superseded", {"reason": "invalid"})
            return False, None, None
        legacy = token is None and gen is None
        reuse = _legacy_sessions.get(sid) if legacy else None
        if reuse and registry.holds_session(reuse[0], reuse[1], sid):
            # A tokenless, generation-less client (the CLI daemon) on the SAME
            # socket that the relay already gave a session. It never echoes
            # the token, so without this every 30 s full sync minted a brand
            # new session record and could never be recognised as a refresh.
            # Only this sid can speak as this sid, and the relay minted that
            # session for it, so continuing it grants nothing new.
            token, gen = reuse
        elif gen is None:
            if reuse:
                _legacy_sessions.pop(sid, None)
            # Legacy/CLI clients omit a generation. It is server-assigned and
            # only orders generations for THIS token; it grants no uid rights.
            gen = secrets.token_urlsafe(8)
        elif not _valid_id(gen):
            _tel("session-invalid", sid=sid)
            emit("session-superseded", {"reason": "invalid"})
            return False, None, None
        if token is not None and (not isinstance(token, str) or len(token) > 512):
            _tel("session-invalid", sid=sid)
            emit("session-superseded", {"reason": "invalid"})
            return False, None, None
        refresh_only = (
            room is not None
            and registry.room_of(sid) == room
            and registry.holds_session(token, gen, sid)
        )
        if not _session_claim_allowed(sid, refresh_only):
            _tel("session-claim-rate-limited", sid=sid, uid=uid)
            emit("session-superseded", {"reason": "rate-limited"})
            return False, None, None
        verdict = registry.claim_session(token, gen, sid, uid, name)
        status = verdict.get("status")
        owner_token = verdict.get("token")
        effective_gen = verdict.get("gen") or gen
        if status in ("retired", "denied", "capacity"):
            reason = {"retired": "stale-generation", "denied": "invalid",
                      "capacity": "capacity"}[status]
            _tel("session-retired" if status == "retired" else "session-denied",
                 sid=sid, uid=uid, gen=str(gen)[:8], status=status)
            emit("session-superseded", {"reason": reason})
            return False, None, None
        if legacy:
            _legacy_sessions[sid] = (owner_token, effective_gen)
        for evicted_sid in verdict.get("evicted") or []:
            if not evicted_sid or evicted_sid == sid:
                continue
            _tel("session-evicted", sid=evicted_sid, uid=uid)
            socketio.emit("session-superseded", {"reason": "session-evicted"}, to=evicted_sid)
            _legacy_sessions.pop(evicted_sid, None)
            _channel_goodbye(evicted_sid)
            local_sids.discard(evicted_sid)
            _leave_room(evicted_sid)
        prev = verdict.get("prev")
        if prev and prev != sid:
            _tel("session-supersede", old=prev, new=sid, uid=uid, gen=str(effective_gen)[:8])
            socketio.emit("session-superseded", {"reason": "newer-generation"}, to=prev)
            _legacy_sessions.pop(prev, None)
            _channel_goodbye(prev)
            local_sids.discard(prev)
            _leave_room(prev)
        return True, owner_token, effective_gen

    def _do_join(sid, room, name, uid, gen=None, token=None):
        """The room-join effect: leave any prior room, join the new one, and
        announce in both directions. Factored so `sync` can reuse the EXACT
        same flow when (and only when) a sid's room actually changes."""
        # Leave any prior ROOM only. Channel subscriptions (known-device presence)
        # are independent of the room and must survive a join: a legacy `join`
        # right after a first `sync` used to drop them all, so a remembered
        # device went unseen until the client's next re-sync (~30 s).
        local_sids.discard(sid)  # unchanged from the old full leave
        _leave_room(sid)

        join_room(room)
        registry.add(sid, room, name, uid, gen)
        peers = [p for p in registry.peers_in(room, exclude=sid) if _sid_alive(p["id"])]
        _tel("join", sid=sid, uid=uid, gen=str(gen)[:8] if gen else None, room=room, peers=len(peers))

        # Tell the joiner who's already here (they initiate offers); tell the
        # room someone arrived. With the Redis message queue these reach peers
        # on every instance. `token` goes ONLY to the joining socket -- it is
        # the device ownership secret and must never ride a broadcast roster.
        welcome = {"id": sid, "peers": peers, "gen": gen}
        if token:
            welcome["token"] = token
        _push("welcome", welcome)
        _push("peer-joined", {"id": sid, "name": name, "uid": uid}, room=room, include_self=False)

    @socketio.on("join")
    def on_join(data):
        sid = request.sid
        data = data if isinstance(data, dict) else {}
        room = data.get("room")
        raw_name = data.get("name")
        if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 128:
            emit("session-superseded", {"reason": "invalid"})
            return
        name = raw_name
        # uid: a stable per-tab identity that survives reconnects (sids don't).
        # It lets peers recognize "same device, new connection" — the basis for
        # transfer resume.
        uid = (data or {}).get("uid")
        gen = (data or {}).get("gen")
        token = (data or {}).get("token")
        if not room:
            return
        ok, owner_token, effective_gen = _claim_session(sid, uid, gen, token, name)
        if not ok:
            return
        _do_join(sid, room, name, uid, effective_gen, owner_token)

    # -- one-time pairing (#11): say the code aloud; it works exactly once. --
    PAIR_TTL = 600  # unclaimed codes evaporate after 10 minutes

    # Claim rate limit: 21.8 bits of code entropy only holds if nobody can
    # sweep the space. 5 attempts/min per connection (and per client IP, so
    # reconnecting doesn't reset it) makes an exhaustive sweep of 3.7M codes
    # take years instead of the minutes the unthrottled 9,000-code space took.
    # FIL_CLAIM_LIMIT overrides it: the gate fixture sets it sky-high so the
    # suite's many rapid claims never collide (the limit is a prod security
    # control, irrelevant to a local single-tester fixture — pinning it makes
    # the claim path DETERMINISTIC instead of timing-window-dependent).
    #
    # The client IP is the TCP peer unless a configured trusted proxy vouches
    # for a header (FIL_TRUSTED_PROXIES); IPv6 counts per /64. With Redis the
    # budget is shared across replicas, else it is a bounded in-process map.
    CLAIM_LIMIT = int(os.environ.get("FIL_CLAIM_LIMIT", "5"))
    CLAIM_WINDOW = 60.0
    # pair-create had no limit at all: every call parks a nameplate for 10
    # minutes, so one client could fill the 3-5 digit nameplate space and deny
    # pairing to everyone. Default 4x the claim budget (a creator retries on
    # `taken`); FIL_PAIR_CREATE_LIMIT overrides, and a fixture that lifts the
    # claim limit lifts this one with it.
    PAIR_CREATE_LIMIT = int(os.environ.get("FIL_PAIR_CREATE_LIMIT", str(CLAIM_LIMIT * 4)))
    _redis = getattr(registry, "r", None)
    _claim_limiter = ratelimit.make_limiter("pair-claim", CLAIM_LIMIT, CLAIM_WINDOW, _redis)
    _create_limiter = ratelimit.make_limiter("pair-create", PAIR_CREATE_LIMIT, CLAIM_WINDOW, _redis)

    def _limit_keys(sid):
        return (f"sid:{sid}", "ip:" + ratelimit.ip_bucket(ratelimit.client_ip(request)))

    def _claim_allowed(sid):
        return _claim_limiter.allow(_limit_keys(sid))

    # L1-a (PAKE v2): a v:2 client mints the WORDS locally and asks the server
    # to allocate only the NAMEPLATE (the numeric routing suffix). The server
    # NEVER sees or generates the words — the entire MITM-resistance claim rests
    # on this (spec §2.0). A v2 nameplate is validated to be purely numeric so a
    # client can never smuggle words into it; the server stores ONLY that
    # nameplate and never echoes any code back (the creator displays its own
    # locally-assembled `words-nameplate`).

    @socketio.on("pair-create")
    def on_pair_create(data=None):
        sid = request.sid
        if not _create_limiter.allow(_limit_keys(sid)):
            emit("pair-error", {"error": "slow-down"})
            return
        # C24: refresh liveness lease so the nameplate is never minted by a
        # creator the claim-side lease check would call dead (zombie-tab bug).
        if hasattr(registry, "refresh"):
            registry.refresh([sid])
        data = data or {}
        # v2-only: client mints the words locally, sends ONLY the numeric
        # nameplate. Non-v2 clients receive "update-required" (Decision #1).
        # FIL_FORCE_V1 fixture hook retained for Gate #6 (downgrade-refused)
        # testing: when set, the server simulates a legacy relay that omits
        # the v:2 field, forcing the client to refuse.
        force_v1 = os.environ.get("FIL_FORCE_V1") == "1"
        if data.get("v") != 2 or force_v1:
            if force_v1:
                emit("pair-code", {"code": "legacy-downgrade-test-000", "ttl": 600})
                return
            emit("pair-error", {"error": "update-required", "why": "this server requires v2 (PAKE handshake); update your client"})
            return
        nameplate = _norm_code(data.get("nameplate"))
        if not _NAMEPLATE_RE.match(nameplate):
            # Defense-in-depth: reject anything that is not a bare number so
            # a buggy/malicious client cannot park words server-side.
            emit("pair-error", {"error": "bad-nameplate"})
            return
        if registry.pair_create(nameplate, sid, ttl=PAIR_TTL):
            # NO words echoed; the creator shows its OWN minted full code.
            _tel("pair-create", sid=sid, nameplate=nameplate, v=2,
                 in_room=bool(registry.room_of(sid)), leased=registry.meta(sid) is not None)
            emit("pair-ok", {"nameplate": nameplate, "ttl": PAIR_TTL, "v": 2})
            return
        # Collision: the client re-mints a fresh nameplate and retries.
        emit("pair-error", {"error": "taken"})

    @socketio.on("pair-claim")
    def on_pair_claim(data=None):
        if not _claim_allowed(request.sid):
            emit("pair-error", {"error": "slow-down"})
            return
        data = data or {}
        # v2-only: claimer sends ONLY the nameplate (the password NEVER reaches
        # the server, relay-blind, gate 2). Non-v2 receives "update-required".
        if data.get("v") != 2:
            emit("pair-error", {"error": "update-required", "why": "this server requires v2 (PAKE handshake); update your client"})
            return
        code = _norm_code(data.get("nameplate"))
        if not _NAMEPLATE_RE.match(code):
            emit("pair-error", {"error": "invalid", "why": "bad-nameplate"})
            return
        existed, peek_creator, creator_alive = registry.peek_pair(code) if code else (False, None, False)
        creator = registry.pair_claim(code) if code else None
        room = registry.room_of(creator) if creator else None
        if not room:
            # The smoking-gun cases, now distinguishable: code never existed /
            # expired, vs creator known but its liveness lease lapsed (zombie
            # phone tab), vs creator alive but roomless.
            _tel("pair-claim-fail", sid=request.sid, code=code, existed=existed,
                 creator=peek_creator, creator_alive=creator_alive)
            # Tell the claimer WHICH failure this was (additive field — old
            # clients ignore it): a code whose creator is gone reads very
            # differently from a typo'd/expired one.
            why = "sender-gone" if existed and peek_creator else "unknown"
            emit("pair-error", {"error": "invalid", "why": why})
            return
        _tel("pair-claim-ok", sid=request.sid, code=code, creator=creator, room=room)
        # Code BURNED (atomic claim). Pairing is ADDITIVE: the claimer joins the
        # creator's CURRENT room — the creator never moves, keeps seeing nearby
        # devices, and can mint another code to admit another person.
        emit("pair-used", {"code": code}, to=creator)  # clear the displayed code
        emit("pair-matched", {"room": room})  # claimer crosses over

    # -- persistent-pair presence (C12). The client subscribes with channel
    # ids derived from E2E-shared pair secrets (sha256, hex). The server never
    # sees a secret — only meeting points. Mutual presence is symmetric:
    # both sides get `known-peer`. Trust is NOT asserted here; clients verify
    # each other with an HMAC proof over the secret after connecting.
    CHAN_RE = re.compile(r"^[0-9a-f]{64}$")
    MAX_CHANNELS = 64

    def _do_subscribe(sid, raw_channels):
        """Validate + apply a channel subscription (union, idempotent) and emit
        the symmetric known-peer pairs. Returns the count of accepted channels.
        Factored so both `subscribe` and `sync` share one code path — no
        duplicated validation, no duplicated emission loop."""
        chans = [c for c in (raw_channels or [])[:MAX_CHANNELS]
                 if isinstance(c, str) and CHAN_RE.match(c)]
        if not chans:
            return 0, []
        me = registry.meta(sid)
        roster = []  # live existing members on these channels — returned in the
        # ack so the subscriber discovers DETERMINISTICALLY, not dependent on the
        # async known-peer push landing (which is unreliable across prod workers).
        for ch, others in registry.subscribe(sid, chans).items():
            for other in others:
                if not _sid_alive(other):  # never advertise a dead sid (#10)
                    continue
                om = registry.meta(other)
                if om:
                    emit("known-peer", {**om, "channel": ch})
                    roster.append({**om, "channel": ch})
                if me:
                    emit("known-peer", {**me, "channel": ch}, to=other)
        return len(chans), roster

    @socketio.on("subscribe")
    def on_subscribe(data=None):
        registry.refresh([request.sid])  # any inbound event proves liveness
        n, roster = _do_subscribe(request.sid, (data or {}).get("channels"))
        # C28: the return value is the socket.io ACK — subscribers VERIFY the
        # emit landed instead of assuming (a subscribe that dies in a half-open
        # socket left devices mutually invisible until a page reload). `peers`
        # carries the live channel roster so discovery is deterministic.
        return {"ok": bool(n), "n": n, "peers": roster}

    @socketio.on("channel-goodbye")
    def on_channel_goodbye(data=None):
        """Unsubscribe the caller from named channels without dropping the socket
        or affecting other subscriptions. Emits known-peer-left to remaining
        members so they stop dialing.
        Note: meta resolves through the socket's room; a room-less caller
        disarms correctly but notifies nobody (om=None skips the emit)."""
        registry.refresh([request.sid])
        chans = (data or {}).get("channels") or []
        for ch, others in registry.unsubscribe(request.sid, chans).items():
            om = registry.meta(request.sid)
            if om:
                for other in others:
                    emit("known-peer-left", {**om, "channel": ch}, to=other)
        return {"ok": True, "n": len(chans)}

    # -- C30 convergent session: ONE idempotent, full-state event that ensures
    # membership + subscriptions + lease in a single ack'd round-trip. No emit
    # is load-bearing; only convergence is. The old join/subscribe events
    # remain for compat — new clients drive session state through `sync` alone.
    @socketio.on("sync")
    def on_sync(data=None):
        sid = request.sid
        data = data if isinstance(data, dict) else {}
        room = data.get("room")
        raw_name = data.get("name")
        if not isinstance(raw_name, str) or not raw_name or len(raw_name) > 128:
            return {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False}
        name = raw_name
        uid = data.get("uid")
        gen = data.get("gen")
        token = data.get("token")
        if not room:
            return {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False}

        # Token-first: a reload's new generation replaces that token's old sid,
        # and a retired generation cannot take the session back with a late
        # sync. A uid alone creates an independent session and affects nothing.
        ok, owner_token, effective_gen = _claim_session(sid, uid, gen, token, name, room=room)
        if not ok:
            return {"v": 1, "ok": False, "superseded": True, "room": None,
                    "channels": 0, "lease": False}

        # Membership: re-announce ONLY when the room actually changes for this
        # sid (idempotent — a repeated sync to the same room is silent).
        room_changed = registry.room_of(sid) != room
        if room_changed:
            _do_join(sid, room, name, uid, effective_gen, owner_token)
        else:
            if hasattr(registry, "refresh"):
                registry.refresh([sid])  # lease refresh only (Redis); no emits
            # A rename is a relabel of the SAME device: update this sid's
            # metadata and tell the room, never create a second peer/pairing.
            me = registry.meta(sid)
            if me and me.get("name") != name:
                updated = registry.rename(sid, name)
                if updated:
                    emit("peer-updated", updated, room=room, include_self=False)
                    _tel("rename", sid=sid, uid=uid)

        # Subscriptions: union, idempotent, emits known-peer pairs as today AND
        # returns the live channel roster (deterministic discovery).
        n, chan_peers = _do_subscribe(sid, data.get("channels"))

        _tel("sync", sid=sid, room_changed=room_changed, channels=n)
        # Roster (C30 phase 2): the digest carries everyone the server holds in
        # the caller's room (welcome-shaped, self excluded). registry.peers_in
        # lease-filters; _sid_alive additionally drops locally-owned sids whose
        # socket just died (#10). Sort by sid THEN cap at 32 so an unchanged
        # room yields a byte-identical digest across repeated syncs (the
        # client's idempotency/reconciliation depends on it).
        peers = sorted((p for p in registry.peers_in(room, exclude=sid)
                        if _sid_alive(p["id"])), key=lambda p: p["id"])[:32]
        # Ack carries the server's resulting beliefs for this sid; the client
        # compares (digest) instead of assuming any single emit landed.
        digest = {"v": 1, "ok": True, "room": room, "channels": n, "lease": True,
                  "peers": peers, "channel_peers": chan_peers, "gen": effective_gen}
        if owner_token:
            # Same private token as `welcome`; this ack goes to this sid only.
            digest["token"] = owner_token
        # Also emit the digest as a plain event: the Rust client consumes
        # events through one channel (Ev enum) and skips ack plumbing.
        emit("synced", digest)
        return digest

    @socketio.on("signal")
    def on_signal(data):
        sid = request.sid
        to = (data or {}).get("to")
        payload = (data or {}).get("data")
        my_room = registry.room_of(sid)
        if not to or not isinstance(to, str) or not my_room:
            return
        # Only deliver to a peer the sender could legitimately have learned
        # about: same room (welcome/peer-joined/sync) or a shared pair channel
        # (known-peer). Forwarding to ANY sid let a client inject offers into
        # strangers' sessions by guessing or harvesting socket ids.
        if registry.room_of(to) != my_room and not registry.share_channel(sid, to):
            _tel("signal-refused", sid=sid, to=to)
            return
        emit("signal", {"from": sid, "data": payload}, to=to)  # routes cross-instance

    @socketio.on("leave")
    def on_leave(_data=None):
        _do_leave(request.sid)

    @socketio.on("disconnect")
    def on_disconnect():
        _tel("disconnect", sid=request.sid)
        _do_leave(request.sid)

    def _channel_goodbye(sid):
        for ch, others in registry.unsubscribe_all(sid).items():
            for other in others:
                emit("known-peer-left", {"id": sid, "channel": ch}, to=other)

    def _do_leave(sid):
        """Full departure (leave event, disconnect): channels and room."""
        _legacy_sessions.pop(sid, None)
        _channel_goodbye(sid)
        local_sids.discard(sid)
        _leave_room(sid)

    def _leave_room(sid):
        room = registry.remove(sid)
        if not room:
            return
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
