"""Who is calling, and how often: client address resolution + rate limits.

Two decisions live here because they are one decision: a rate limit is only as
good as the key it counts, and the key is the caller's address.

Address: the immediate TCP peer is the only address a client cannot forge. A
proxy header (CF-Connecting-IP, X-Forwarded-For) is honoured ONLY when that
peer is a configured trusted proxy (``FIL_TRUSTED_PROXIES``); otherwise anyone
who can reach the server directly picks their own "IP" per request and walks
straight through any per-IP limit (or into another network's auto room).

Limits: IPv6 callers are counted per /64 (one host typically holds a whole
/64, so per-address counting gives it 2^64 fresh budgets). State lives in
Redis when the deployment has one, so every replica shares one budget;
otherwise in a bounded in-process map whose idle keys are evicted.
"""
import ipaddress
import time
from collections import OrderedDict, deque

import config


def ip_bucket(ip_str):
    """The unit a per-IP limit counts: full IPv4 address, IPv6 /64 prefix."""
    try:
        ip = ipaddress.ip_address((ip_str or "").strip())
    except ValueError:
        return f"raw:{ip_str}"
    if ip.version == 6 and ip.ipv4_mapped is None:
        return "v6:" + str(ipaddress.ip_network(f"{ip}/64", strict=False).network_address) + "/64"
    if ip.version == 6:
        return f"v4:{ip.ipv4_mapped}"
    return f"v4:{ip}"


def _peer_is_trusted(peer):
    trusted = config.TRUSTED_PROXIES
    if trusted == "*":
        return True
    try:
        addr = ipaddress.ip_address(peer)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


def client_ip(req):
    """The caller's address for rate limiting and network grouping.

    The raw socket peer is read from the WSGI environ (before ProxyFix, which
    trusts X-Forwarded-For unconditionally). Proxy headers count only when that
    peer is a configured trusted proxy.
    """
    env = getattr(req, "environ", {}) or {}
    orig = env.get("werkzeug.proxy_fix.orig") or {}
    peer = orig.get("REMOTE_ADDR") or env.get("REMOTE_ADDR") or getattr(req, "remote_addr", None) or ""
    if peer and _peer_is_trusted(peer):
        cf = req.headers.get("CF-Connecting-IP")
        if cf and cf.strip():
            return cf.strip()
        # ProxyFix already resolved X-Forwarded-For into remote_addr.
        return getattr(req, "remote_addr", None) or peer
    return peer or "0.0.0.0"


class MemLimiter:
    """Sliding-window limit over several keys at once, in process memory.

    ``allow(keys)`` admits an event only if EVERY key is under its limit, and
    then charges all of them. Keys idle for a full window are evicted, and the
    map is capped at ``max_keys`` (least-recently-touched dropped first), so a
    caller rotating keys cannot grow it without bound.
    """

    def __init__(self, limit, window, max_keys=100_000):
        self.limit = limit
        self.window = window
        self.max_keys = max_keys
        self._log = OrderedDict()  # key -> deque of timestamps
        self._ops = 0

    def _prune(self, key, now):
        q = self._log.get(key)
        if q is None:
            return None
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def _sweep(self, now):
        for key in list(self._log.keys()):
            q = self._prune(key, now)
            if not q:
                del self._log[key]

    def allow(self, keys, now=None):
        now = time.monotonic() if now is None else now
        self._ops += 1
        if self._ops % 1024 == 0 or len(self._log) > self.max_keys:
            self._sweep(now)
        for key in keys:
            q = self._prune(key, now)
            if q is not None and len(q) >= self.limit:
                return False
        for key in keys:
            q = self._log.get(key)
            if q is None:
                q = self._log[key] = deque()
            else:
                self._log.move_to_end(key)
            q.append(now)
        while len(self._log) > self.max_keys:
            self._log.popitem(last=False)
        return True

    def __len__(self):
        return len(self._log)


class RedisLimiter:
    """Fixed-window limit shared by every replica through Redis.

    Falls back to an in-process limiter if Redis errors, so a Redis blip
    degrades to per-replica limits rather than to no limit at all.
    """

    def __init__(self, r, name, limit, window):
        self.r = r
        self.name = name
        self.limit = limit
        self.window = window
        self._fallback = MemLimiter(limit, window)

    def _key(self, key, idx):
        return f"filament:rl:{self.name}:{key}:{idx}"

    def allow(self, keys, now=None):
        now = time.time() if now is None else now
        idx = int(now // self.window)
        try:
            p = self.r.pipeline()
            for key in keys:
                p.get(self._key(key, idx))
            counts = p.execute()
            if any(int(c or 0) >= self.limit for c in counts):
                return False
            p = self.r.pipeline()
            for key in keys:
                k = self._key(key, idx)
                p.incr(k)
                p.expire(k, int(self.window * 2) + 1)
            p.execute()
            return True
        except Exception:
            return self._fallback.allow(keys)


def make_limiter(name, limit, window, redis_client=None):
    if redis_client is not None:
        return RedisLimiter(redis_client, name, limit, window)
    return MemLimiter(limit, window)
