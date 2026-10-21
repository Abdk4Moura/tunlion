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
  HTTP               POST /api/session/close {uid,gen,token} (pagehide beacon)

`gen` is a fresh per-page-load generation. `token` is a PRIVATE ownership token
minted by the relay on the first claim and returned only to that socket (in the
welcome/sync ack, never in a roster). A new token-bearing generation for the
same uid supersedes the old sid immediately; a late, forged or retired sync or
close is ignored/refused. A uid alone is never authority.
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
    OWNER_TTL = 24 * 3600  # ownership token/record lifetime (sliding on use)
    RETIRED_TTL = 24 * 3600  # tombstone lifetime (one global set)
    MAX_OWNED_UIDS = 50_000
    MAX_RETIRED_TOTAL = 200_000

    def __init__(self):
        self._m = {}  # sid -> {"room", "name", "uid", "gen"}
        self._live = {}  # sid -> lease expiry (monotonic)
        # uid -> {"gen", "sid", "token", "token_exp", "last_seen"}.
        # A reload has the same uid but a new generation; it takes ownership
        # immediately when it presents the server-minted token. Retired
        # generations are one GLOBAL (uid, gen) -> expiry map so memory is
        # bounded by MAX_RETIRED_TOTAL, not by uid count.
        self._uids = {}
        self._retired = {}
        self._retired_order = deque()
        # async_mode=threading really is concurrent: claim/take must not
        # interleave or two generations can both believe they own a uid.
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
            m = self._m.pop(sid, None)
            # Keep the uid->generation ownership record: a socket reconnect
            # under the SAME generation must be able to reclaim it, while a
            # newer generation still supersedes this sid. Only take_session (a
            # real close) clears the live sid. Stale records are bounded by
            # _retired.
            return m["room"] if m else None

    def claim_session(self, uid, gen, sid, token=None):
        """Claim this device identity for a page-load generation.

        Returns {"status": "current"|"new"|"replace"|"retired"|"denied",
        "prev": sid, "token": issued-or-current-token}. A client-supplied uid
        alone NEVER authorizes eviction: after the first claim, the caller must
        present the private ownership token, or be the same server socket that
        made the first claim (the join/sync race on initial load).
        """
        if not uid or not gen:
            return {"status": "legacy", "prev": None}
        if not _valid_id(uid) or not _valid_id(gen) or (token is not None and not isinstance(token, str)):
            return {"status": "denied", "prev": None}
        if token and len(token) > 256:
            return {"status": "denied", "prev": None}
        with self._lock:
            now = _time.time()
            has_room = self._sweep_owners(now)
            self._prune_retired(now)
            if self._is_retired(uid, gen):
                cur = self._uids.get(uid)
                return {"status": "retired", "prev": cur.get("sid") if cur else None}
            cur = self._uids.get(uid)
            if cur is None:
                if not has_room:
                    return {"status": "capacity", "prev": None}
                # The relay mints unconditionally; a client-supplied token is
                # never allowed to become the first owner of a uid.
                issued = secrets.token_urlsafe(24)
                self._uids[uid] = {"gen": gen, "sid": sid, "token": issued,
                                   "token_exp": now + self.OWNER_TTL, "last_seen": now}
                return {"status": "new", "prev": None, "token": issued}
            # An expired token whose session is not live is stale ownership:
            # mint a new token. A live session keeps its token until it expires
            # only if it stops refreshing (sync normally refreshes every 5s).
            if cur.get("token_exp", 0) <= now:
                if self._alive(cur.get("sid")):
                    return {"status": "denied", "prev": cur.get("sid")}
                issued = secrets.token_urlsafe(24)
                self._uids[uid] = {"gen": gen, "sid": sid, "token": issued,
                                   "token_exp": now + self.OWNER_TTL, "last_seen": now}
                return {"status": "new", "prev": None, "token": issued}
            authorized = bool(token) and secrets.compare_digest(str(token), str(cur.get("token") or ""))
            # One page load emits `join` and `sync` concurrently on the SAME
            # socket. The first mints the token; the second cannot know it yet.
            # Same sid + same generation is that race, not a takeover.
            if not authorized and cur.get("sid") == sid and cur.get("gen") == gen:
                authorized = True
            if not authorized:
                return {"status": "denied", "prev": cur.get("sid")}
            cur_token = cur.get("token")
            cur["last_seen"] = now
            cur["token_exp"] = now + self.OWNER_TTL
            if cur.get("gen") == gen:
                prev = cur.get("sid")
                if prev != sid:
                    cur["sid"] = sid
                    return {"status": "replace", "prev": prev, "token": cur_token}
                return {"status": "current", "prev": None, "token": cur_token}
            old = cur.get("gen")
            prev = cur.get("sid")
            if old:
                self._add_retired(uid, old, now)
            cur.update({"gen": gen, "sid": sid})
            return {"status": "new", "prev": prev, "token": cur_token}

    def _prune_retired(self, now):
        """Drop expired tombstones and enforce the global count cap (oldest
        first). A valid owner is never refused because of this bound."""
        while self._retired_order:
            uid, gen, exp = self._retired_order[0]
            if exp > now and len(self._retired) < self.MAX_RETIRED_TOTAL:
                break
            self._retired_order.popleft()
            if self._retired.get((uid, gen)) == exp:
                self._retired.pop((uid, gen), None)
        while len(self._retired) >= self.MAX_RETIRED_TOTAL and self._retired_order:
            uid, gen, exp = self._retired_order.popleft()
            if self._retired.get((uid, gen)) == exp:
                self._retired.pop((uid, gen), None)

    def _is_retired(self, uid, gen):
        exp = self._retired.get((uid, gen))
        if exp is None:
            return False
        if exp <= _time.time():
            self._retired.pop((uid, gen), None)
            return False
        return True

    def _add_retired(self, uid, gen, now):
        self._prune_retired(now)
        exp = now + self.RETIRED_TTL
        key = (uid, gen)
        if key in self._retired:
            return
        self._retired[key] = exp
        self._retired_order.append((uid, gen, exp))

    def _sweep_owners(self, now):
        """Bound ownership memory: drop stale, non-live records oldest-first."""
        if len(self._uids) < self.MAX_OWNED_UIDS:
            return True
        stale = [
            (uid, rec.get("last_seen", 0))
            for uid, rec in self._uids.items()
            if not self._alive(rec.get("sid"))
        ]
        stale.sort(key=lambda x: x[1])
        drop = len(self._uids) - self.MAX_OWNED_UIDS + 1
        for uid, _ in stale[: max(0, drop)]:
            self._uids.pop(uid, None)
        return len(self._uids) < self.MAX_OWNED_UIDS

    def rename(self, sid, name):
        with self._lock:
            m = self._m.get(sid)
            if not m:
                return None
            m["name"] = name
            return {"id": sid, "name": name, "uid": m.get("uid")}

    def owned_uid(self, uid):
        """Whether this uid has ever been claimed (used by legacy no-gen
        clients: they may not re-use a uid that a token-owning session owns)."""
        with self._lock:
            return self._uids.get(uid)

    def claim_legacy(self, uid):
        """Atomic decision for a generation-less client: a fresh uid may join
        as non-owning; an already-owned uid is refused. No later token claim can
        be raced by a stale read between check and return."""
        with self._lock:
            return uid not in self._uids

    def take_session(self, uid, gen, token=None):
        """Close the active sid for (uid, gen) IF the caller holds its ownership
        token. A wrong/missing token, or a close for an OLD generation, returns
        None -- exactly what makes a late/forged pagehide harmless."""
        if not uid or not gen:
            return None
        with self._lock:
            now = _time.time()
            cur = self._uids.get(uid)
            if not cur or cur.get("gen") != gen:
                return None
            if cur.get("token_exp", 0) <= now:
                return None
            if not token or not secrets.compare_digest(str(token), str(cur.get("token") or "")):
                return None
            sid = cur.get("sid")
            # Keep the token record: the same device may reload later with a
            # new generation. Only the live sid/gen is cleared.
            cur["sid"] = None
            cur["gen"] = None
            cur["last_seen"] = now
            cur["token_exp"] = now + self.OWNER_TTL
            self._add_retired(uid, gen, now)
            self._live.pop(sid, None)
            m = self._m.pop(sid, None)
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
    OWNER_TTL = _MemRegistry.OWNER_TTL
    RETIRED_TTL = _MemRegistry.RETIRED_TTL
    MAX_OWNED_UIDS = _MemRegistry.MAX_OWNED_UIDS
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

    # One hash per uid holds gen/sid/token, so they share one TTL and cannot
    # expire independently (a surviving token with an expired gen was the bug).
    def _ok(self, uid):
        return f"filament:owner:{uid}"

    def _owners(self):
        return "filament:owners"

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

    def claim_session(self, uid, gen, sid, token=None):
        """Atomic generation ownership (same contract as _MemRegistry)."""
        if not uid or not gen:
            return {"status": "legacy", "prev": None}
        if not _valid_id(uid) or not _valid_id(gen) or (token is not None and not isinstance(token, str)):
            return {"status": "denied", "prev": None}
        if token and len(token) > 256:
            return {"status": "denied", "prev": None}
        # Mint unconditionally on a first claim; the client's value never
        # becomes the first owner of a uid.
        candidate = secrets.token_urlsafe(24)
        now = _time.time()
        member = f"{uid}|{gen}"
        status, prev, issued = self.r.eval(
            """
            local cur = redis.call('HMGET', KEYS[1], 'gen', 'sid', 'token')
            local curgen, cursid, curtok = cur[1], cur[2], cur[3]
            redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[6])
            -- owners idle past the shared TTL are gone with their hash
            local stale = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', tonumber(ARGV[6]) - tonumber(ARGV[5]))
            for _, ou in ipairs(stale) do
              if not redis.call('EXISTS', 'filament:owner:' .. ou) then
                redis.call('ZREM', KEYS[3], ou)
              end
            end
            if redis.call('ZSCORE', KEYS[2], ARGV[11]) then
              return {'retired', cursid or '', curtok or ''}
            end
            if (not curgen) or curgen == '' then
              -- A closed slot may still hold the real token (hash TTL keeps
              -- all fields together). Only that token may reclaim it.
              if curtok then
                if ARGV[3] == '' or ARGV[3] ~= curtok then
                  return {'denied', '', curtok}
                end
                redis.call('HSET', KEYS[1], 'gen', ARGV[1], 'sid', ARGV[2])
                redis.call('EXPIRE', KEYS[1], ARGV[5])
                redis.call('ZADD', KEYS[3], ARGV[6], ARGV[7])
                return {'new', '', curtok}
              end
              -- Brand-new uid: a tokenless caller gets the server-minted
              -- token; no existing live token can be taken this way.
              local cards = redis.call('ZCARD', KEYS[3])
              if cards >= tonumber(ARGV[8]) then
                local olds = redis.call('ZRANGE', KEYS[3], 0, cards - tonumber(ARGV[8]) + 1)
                local freed = false
                for _, ou in ipairs(olds) do
                  local osid = redis.call('HGET', 'filament:owner:' .. ou, 'sid')
                  if not osid or osid == '' or redis.call('EXISTS', 'filament:live:' .. osid) == 0 then
                    redis.call('DEL', 'filament:owner:' .. ou)
                    redis.call('ZREM', KEYS[3], ou)
                    freed = true
                    break
                  end
                end
                if not freed then return {'capacity', '', ''} end
              end
              redis.call('ZREM', KEYS[3], ARGV[7])
              redis.call('HSET', KEYS[1], 'gen', ARGV[1], 'sid', ARGV[2], 'token', ARGV[4])
              redis.call('EXPIRE', KEYS[1], ARGV[5])
              redis.call('ZADD', KEYS[3], ARGV[6], ARGV[7])
              return {'new', '', ARGV[4]}
            end
            local authorized = (ARGV[3] ~= '' and curtok and ARGV[3] == curtok)
            if not authorized and curgen == ARGV[1] and cursid == ARGV[2] then
              authorized = true
            end
            if not authorized then return {'denied', cursid or '', curtok or ''} end
            redis.call('EXPIRE', KEYS[1], ARGV[5])
            redis.call('ZADD', KEYS[3], ARGV[6], ARGV[7])
            if curgen == ARGV[1] then
              if cursid == ARGV[2] then return {'current', '', curtok} end
              redis.call('HSET', KEYS[1], 'sid', ARGV[2])
              return {'replace', cursid, curtok}
            end
            -- retire the old generation in one global ZSET; evict oldest
            -- tombstones rather than refusing the valid current owner.
            while redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[9]) do
              redis.call('ZREMRANGEBYRANK', KEYS[2], 0, 0)
            end
            redis.call('ZADD', KEYS[2], tonumber(ARGV[6]) + tonumber(ARGV[10]),
                       ARGV[7] .. '|' .. curgen)
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[10]) * 2)
            redis.call('HSET', KEYS[1], 'gen', ARGV[1], 'sid', ARGV[2])
            return {'new', cursid or '', curtok}
            """,
            3, self._ok(uid), self._retired_key(), self._owners(),
            gen, sid, str(token) if token else "", candidate, self.OWNER_TTL,
            now, uid, self.MAX_OWNED_UIDS, self.MAX_RETIRED_TOTAL,
            self.RETIRED_TTL, member,
        )
        return {"status": status, "prev": prev or None, "token": issued or None}

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

    def owned_uid(self, uid):
        h = self.r.hmget(self._ok(uid), "gen", "sid", "token")
        if not any(h):
            return None
        return {"gen": h[0] or None, "sid": h[1] or None}

    def claim_legacy(self, uid):
        # EXISTS is atomic against a concurrent token claim.
        return not self.r.exists(self._ok(uid))

    def take_session(self, uid, gen, token=None):
        if not uid or not gen or not token:
            return None
        sid, room = self.r.eval(
            """
            local cur = redis.call('HMGET', KEYS[1], 'gen', 'sid', 'token')
            if cur[1] ~= ARGV[1] or not cur[3] or cur[3] ~= ARGV[3] then
              return {'', ''}
            end
            local sid = cur[2]
            if not sid then return {'', ''} end
            local room = redis.call('GET', 'filament:sid:' .. sid)
            while redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) do
              redis.call('ZREMRANGEBYRANK', KEYS[2], 0, 0)
            end
            redis.call('ZADD', KEYS[2], tonumber(ARGV[4]) + tonumber(ARGV[6]), ARGV[7])
            redis.call('EXPIRE', KEYS[2], tonumber(ARGV[6]) * 2)
            redis.call('HSET', KEYS[1], 'gen', '', 'sid', '')
            redis.call('EXPIRE', KEYS[1], ARGV[2])
            return {sid, room or ''}
            """,
            2, self._ok(uid), self._retired_key(),
            gen, self.OWNER_TTL, str(token), _time.time(),
            self.MAX_RETIRED_TOTAL, self.RETIRED_TTL, f"{uid}|{gen}",
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


def close_session(socketio, registry, uid, gen, token=None):
    """Best-effort pagehide close, tagged with the page-load generation.

    Only the holder of the session ownership token AND the current generation
    can close it. A late beacon from the page that has just been reloaded (same
    uid, older generation) is ignored, so it can never drop the replacement
    link. Returns bool.
    """
    info = registry.take_session(uid, gen, token)
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
    _tel("session-close", sid=sid, uid=uid, gen=str(gen)[:8])
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

    def _session_claim_allowed(sid):
        return _session_claim_limiter.allow([
            f"sid:{sid}",
            "ip:" + ratelimit.ip_bucket(ratelimit.client_ip(request)),
        ])

    def _claim_session(sid, uid, gen, token=None):
        """Let a new page-load generation own `uid` immediately, evicting the
        old sid (if any), but ONLY when the caller holds the device's private
        ownership token. A uid visible in the roster is not authority. Returns
        (ok, token); on the first claim the relay mints and returns the token
        to this socket alone."""
        if not uid:
            return True, None
        if not _valid_id(uid) or (token is not None and not isinstance(token, str)):
            _tel("session-invalid", sid=sid)
            emit("session-superseded", {"reason": "invalid"})
            return False, None
        if not gen:
            # Legacy/CLI clients do not carry a generation. The check-and-join
            # is one atomic registry operation, so a concurrent token claim
            # cannot slip between "no owner" and "join".
            if not registry.claim_legacy(uid):
                _tel("session-denied", sid=sid, uid=uid, gen=None)
                emit("session-superseded", {"reason": "not-owner"})
                return False, None
            return True, None
        if not _valid_id(gen) or (token and len(token) > 256):
            _tel("session-invalid", sid=sid)
            emit("session-superseded", {"reason": "invalid"})
            return False, None
        if not _session_claim_allowed(sid):
            _tel("session-claim-rate-limited", sid=sid, uid=uid)
            emit("session-superseded", {"reason": "rate-limited"})
            return False, None
        verdict = registry.claim_session(uid, gen, sid, token)
        status = verdict.get("status")
        owner_token = verdict.get("token")
        if status in ("retired", "denied", "capacity"):
            reason = {"retired": "stale-generation", "denied": "not-owner",
                      "capacity": "capacity"}[status]
            _tel("session-retired" if status == "retired" else "session-denied",
                 sid=sid, uid=uid, gen=str(gen)[:8], status=status)
            emit("session-superseded", {"reason": reason})
            return False, None
        prev = verdict.get("prev")
        if prev and prev != sid:
            _tel("session-supersede", old=prev, new=sid, uid=uid, gen=str(gen)[:8])
            # Tell the old page first, then make the room/known-device views
            # forget it. Its own late disconnect/beacon is ignored by the uid
            # generation check.
            socketio.emit("session-superseded", {"reason": "newer-generation"}, to=prev)
            _channel_goodbye(prev)
            local_sids.discard(prev)
            _leave_room(prev)
        return True, owner_token

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
        welcome = {"id": sid, "peers": peers}
        if token:
            welcome["token"] = token
        _push("welcome", welcome)
        _push("peer-joined", {"id": sid, "name": name, "uid": uid}, room=room, include_self=False)

    @socketio.on("join")
    def on_join(data):
        sid = request.sid
        data = data if isinstance(data, dict) else {}
        room = data.get("room")
        name = data.get("name") if isinstance(data.get("name"), str) else "anonymous"
        name = name[:128] or "anonymous"
        # uid: a stable per-tab identity that survives reconnects (sids don't).
        # It lets peers recognize "same device, new connection" — the basis for
        # transfer resume.
        uid = (data or {}).get("uid")
        gen = (data or {}).get("gen")
        token = (data or {}).get("token")
        if not room:
            return
        ok, owner_token = _claim_session(sid, uid, gen, token)
        if not ok:
            return
        _do_join(sid, room, name, uid, gen, owner_token)

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
        name = data.get("name") if isinstance(data.get("name"), str) else "anonymous"
        name = name[:128] or "anonymous"
        uid = data.get("uid")
        gen = data.get("gen")
        token = data.get("token")
        if not room:
            return {"v": 1, "ok": False, "room": None, "channels": 0, "lease": False}

        # Generation ownership first: a reload's new generation takes over even
        # if the old sid is still in the room, and a retired old page cannot
        # take the session back with a late sync. A uid alone is not authority:
        # without the ownership token this is denied and the victim stays put.
        ok, owner_token = _claim_session(sid, uid, gen, token)
        if not ok:
            return {"v": 1, "ok": False, "superseded": True, "room": None,
                    "channels": 0, "lease": False}

        # Membership: re-announce ONLY when the room actually changes for this
        # sid (idempotent — a repeated sync to the same room is silent).
        room_changed = registry.room_of(sid) != room
        if room_changed:
            _do_join(sid, room, name, uid, gen, owner_token)
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
                  "peers": peers, "channel_peers": chan_peers}
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
        _channel_goodbye(sid)
        local_sids.discard(sid)
        _leave_room(sid)

    def _leave_room(sid):
        room = registry.remove(sid)
        if not room:
            return
        leave_room(room)
        emit("peer-left", {"id": sid}, room=room, include_self=False)
