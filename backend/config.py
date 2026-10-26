"""Runtime configuration for the Tunlion backend.

Everything the frontend needs in order to bootstrap is exposed through
``public_config()`` and served at ``GET /api/config`` so the React app never
has to be rebuilt to switch signaling backends or ICE servers.
"""
import json
import os


def _bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, str(default)).lower() in ("1", "true", "yes", "on")


# Which signaling channel the client should use: "socketio" (default, served by
# this Flask app) or "firebase" (serverless, talks straight to Firestore).
SIGNALING = os.environ.get("FIL_SIGNALING", "socketio").lower()

# Explicit development mode. The ONLY thing it unlocks today is the built-in
# FIL_SECRET fallback below; production must never run with that value.
DEV = _bool("FIL_DEV", False)

# Secret used to derive a stable, non-reversible default room name per network.
# There is deliberately no silent default: a server that falls back to a
# public, committed secret makes every network's auto room predictable to
# anyone who reads this file. `ensure_secret()` resolves it at startup.
DEV_SECRET = "filament-dev-secret"
SECRET = os.environ.get("FIL_SECRET") or ""


def ensure_secret(dev_entrypoint: bool = False) -> str:
    """Resolve SECRET or refuse to start.

    Unset FIL_SECRET is allowed only in development: FIL_DEV=1, or the direct
    `python app.py` Werkzeug dev server (``dev_entrypoint``), which is what
    the local gate fixtures launch and which production never runs (it runs
    gunicorn, see deploy/api.Dockerfile). Anything else fails startup.
    """
    global SECRET
    if SECRET:
        return SECRET
    if DEV or dev_entrypoint:
        import sys

        sys.stderr.write("tunlion backend: FIL_SECRET unset, using the DEV secret (development only)\n")
        SECRET = DEV_SECRET
        return SECRET
    raise RuntimeError(
        "FIL_SECRET is not set. Set it to a long random string (see deploy/.env.example); "
        "FIL_DEV=1 enables the development default."
    )


def _trusted_proxies(raw):
    """FIL_TRUSTED_PROXIES: comma-separated IPs/CIDRs of the reverse proxies in
    front of this server (e.g. the cloudflared container's network), or "*"
    when the server is reachable ONLY through a proxy. Proxy headers such as
    CF-Connecting-IP are honoured only from these peers. Unset = trust none."""
    import ipaddress

    raw = (raw or "").strip()
    if raw == "*":
        return "*"
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            pass
    return nets


TRUSTED_PROXIES = _trusted_proxies(os.environ.get("FIL_TRUSTED_PROXIES"))

PORT = int(os.environ.get("PORT", 5000))

# Set to a redis:// URL to scale horizontally (shared room registry + Socket.IO
# message queue across api replicas). Unset = single in-memory instance.
REDIS_URL = os.environ.get("FIL_REDIS_URL")

# Allow the Vite dev server origin to open the websocket during development.
CORS_ALLOWED_ORIGINS = os.environ.get("FIL_CORS_ORIGINS", "*")

# ICE servers handed to the browser's RTCPeerConnection. STUN is enough for most
# networks; TURN (below) is the fallback for the ~10-15% that need a relay.
DEFAULT_ICE = [{"urls": "stun:stun.l.google.com:19302"}]

# Self-hosted coturn. We hand out *ephemeral* credentials (coturn's REST-API /
# use-auth-secret scheme): a time-limited username + an HMAC of it, so the
# browser never holds a long-lived TURN password.
#   FIL_TURN_HOST   comma-separated TURN urls, e.g.
#                   "turn:turn.tunlion.example.com:3478,turn:turn.tunlion.example.com:3478?transport=tcp"
#   FIL_TURN_SECRET must equal coturn's `static-auth-secret`
#   FIL_TURN_TTL    credential lifetime in seconds (default 1h)
TURN_HOST = os.environ.get("FIL_TURN_HOST")
TURN_SECRET = os.environ.get("FIL_TURN_SECRET")
TURN_TTL = int(os.environ.get("FIL_TURN_TTL", 3600))


def _turn_servers():
    if not (TURN_HOST and TURN_SECRET):
        return []
    import hashlib
    import hmac
    import time
    from base64 import b64encode

    username = str(int(time.time()) + TURN_TTL)  # username IS the expiry timestamp
    credential = b64encode(
        hmac.new(TURN_SECRET.encode(), username.encode(), hashlib.sha1).digest()
    ).decode()
    urls = [u.strip() for u in TURN_HOST.split(",") if u.strip()]
    return [{"urls": urls, "username": username, "credential": credential}]


# Cloudflare Realtime TURN, handed out NEXT TO coturn so a relay survives either
# one being down (ICE tries every server it is given; no failover logic here).
#   FIL_CF_TURN_KEY_ID     the TURN key id (dashboard: Realtime -> TURN)
#   FIL_CF_TURN_API_TOKEN  that key's API token (server-side only, never sent out)
# Credentials are minted for TURN_TTL and shared until half of it has passed,
# so /api/config does not call Cloudflare per request. A failed mint is retried
# after CF_TURN_RETRY seconds; until then the config simply has no CF entry.
CF_TURN_KEY_ID = os.environ.get("FIL_CF_TURN_KEY_ID")
CF_TURN_API_TOKEN = os.environ.get("FIL_CF_TURN_API_TOKEN")
CF_TURN_RETRY = 60
_cf_turn_cache = {"servers": [], "until": 0.0}


def _cf_turn_servers(now=None, fetch=None):
    if not (CF_TURN_KEY_ID and CF_TURN_API_TOKEN):
        return []
    import time

    now = time.time() if now is None else now
    if now < _cf_turn_cache["until"]:
        return _cf_turn_cache["servers"]
    try:
        servers = (fetch or _cf_turn_fetch)()
        _cf_turn_cache.update(servers=servers, until=now + TURN_TTL / 2)
    except Exception:
        _cf_turn_cache.update(servers=[], until=now + CF_TURN_RETRY)
    return _cf_turn_cache["servers"]


def _cf_turn_fetch():
    import urllib.request

    req = urllib.request.Request(
        f"https://rtc.live.cloudflare.com/v1/turn/keys/{CF_TURN_KEY_ID}"
        "/credentials/generate-ice-servers",
        data=json.dumps({"ttl": TURN_TTL}).encode(),
        headers={"Authorization": f"Bearer {CF_TURN_API_TOKEN}",
                 "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=3) as resp:
        body = json.loads(resp.read())
    return _cf_turn_entries(body.get("iceServers") or [])


def _cf_turn_entries(ice_servers):
    """Keep Cloudflare's TURN entries, minus its STUN and port-53 urls.

    Our own STUN is already in DEFAULT_ICE, and browsers refuse or stall on
    port 53, which Cloudflare lists for networks that only allow DNS out.
    """
    out = []
    for s in ice_servers:
        urls = s.get("urls") or []
        urls = [urls] if isinstance(urls, str) else urls
        urls = [u for u in urls if u.startswith(("turn:", "turns:")) and ":53?" not in u
                and not u.endswith(":53")]
        if urls and s.get("username") and s.get("credential"):
            out.append({"urls": urls, "username": s["username"],
                        "credential": s["credential"]})
    return out


def _ice_servers():
    raw = os.environ.get("FIL_ICE_SERVERS")
    if raw:
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
    # Default STUN + (when configured) ephemeral self-hosted TURN.
    return DEFAULT_ICE + _turn_servers() + _cf_turn_servers()


def _firebase_web_config():
    """The Firebase *web* config (safe to expose) used only when SIGNALING=firebase."""
    raw = os.environ.get("FIL_FIREBASE_CONFIG")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return None


def public_config() -> dict:
    """The exact JSON shape the frontend consumes at startup."""
    firebase = _firebase_web_config()
    # Fall back to socket.io if firebase was requested but not configured.
    signaling = SIGNALING if (SIGNALING != "firebase" or firebase) else "socketio"
    return {
        "signaling": signaling,
        "iceServers": _ice_servers(),
        "firebase": firebase if signaling == "firebase" else None,
        # Tuning knobs the transfer layer reads (kept server-side so they can be
        # changed without a rebuild). 60 KiB, NOT 64: chunks carry a 4-byte
        # stream-id header and SCTP's default max message size is 65535 —
        # 64 KiB + 4 overflows it. Chrome tolerates the overage between
        # browsers, but strict stacks (webrtc-rs, i.e. the CLI) reject it.
        # See docs/cli-resilience.md C1.
        "chunkSize": int(os.environ.get("FIL_CHUNK_SIZE", 60 * 1024)),
    }
