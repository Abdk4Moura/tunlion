"""Failover drill: kill the origin behind the staging router, watch clients
move to the Durable Object, bring the origin back, watch them move home.

    ROUTER=https://<router> ORIGIN_CMD_KILL='...' ORIGIN_CMD_START='...' \
        python edge/signal/test/failover_drill.py OUTDIR

Clients (all through ROUTER, all in one room):
  * three socket.io clients (python-socketio, auto-reconnect, rejoin on every
    connect), the browser's behaviour: two on websocket, one on long-polling;
  * one raw-framing client that reconnects itself, the Rust CLI's behaviour.

A client counts as "on cf" when its engine.io sid carries the hub's "cf."
prefix (the router's own stickiness key) and as "home" when it does not.
The drill passes when, after the kill, every client is on cf AND sees every
other client in its room roster, and after the restart, every client is home
and again sees every other. Every transition is timestamped into OUTDIR.
"""
import json
import os
import subprocess
import sys
import threading
import time
import uuid

import requests
import socketio
import websocket

ROUTER = os.environ["ROUTER"].rstrip("/")
KILL = os.environ["ORIGIN_CMD_KILL"]
START = os.environ["ORIGIN_CMD_START"]
OUT = sys.argv[1] if len(sys.argv) > 1 else "drill-out"
os.makedirs(OUT, exist_ok=True)
ROOM = "drill-" + uuid.uuid4().hex[:8]
T0 = time.time()
LOG = open(os.path.join(OUT, "drill.log"), "w")
EVENTS = []


def say(*a):
    line = f"{time.time() - T0:8.2f}s " + " ".join(str(x) for x in a)
    print(line, flush=True)
    LOG.write(line + "\n")
    LOG.flush()


def mark(name, **kv):
    EVENTS.append({"t": round(time.time() - T0, 2), "ev": name, **kv})
    say("MARK", name, json.dumps(kv) if kv else "")


class SioClient:
    def __init__(self, name, transports=("websocket",)):
        self.name = name
        self.transports = list(transports)
        self.uid = "u-" + uuid.uuid4().hex[:10]
        self.sio = socketio.Client(reconnection=True, reconnection_delay=0.4,
                                   reconnection_delay_max=2, randomization_factor=0.2)
        self.roster = set()
        self.sid = None
        self.eid = None
        self.lock = threading.Lock()
        self.sio.on("connect", self.on_connect)
        self.sio.on("welcome", self.on_welcome)
        self.sio.on("peer-joined", lambda d: self._add(d["id"]))
        self.sio.on("peer-left", lambda d: self._drop(d["id"]))

    def on_connect(self):
        self.sid = self.sio.get_sid()
        self.eid = self.sio.eio.sid
        with self.lock:
            self.roster = set()
        say(self.name, "connected eid", self.eid)
        # Fresh session on whichever backend: no token carried across (tokens
        # are backend-local; the browser mints anew the same way).
        self.sio.emit("join", {"room": ROOM, "name": self.name, "uid": self.uid,
                               "gen": "g-" + uuid.uuid4().hex[:8]})

    def on_welcome(self, d):
        with self.lock:
            self.roster = {p["id"] for p in d.get("peers", [])}

    def _add(self, sid):
        with self.lock:
            self.roster.add(sid)

    def _drop(self, sid):
        with self.lock:
            self.roster.discard(sid)

    def start(self):
        self.sio.connect(ROUTER, transports=self.transports, wait_timeout=10)

    def connected(self):
        return self.sio.connected

    def state(self):
        with self.lock:
            return {"eid": self.eid if self.sio.connected else None, "sid": self.sid, "roster": set(self.roster)}


class RawClient:
    """CLI-style: bare websocket, '40', tokenless sync every 3 s, own reconnect."""

    def __init__(self, name):
        self.name = name
        self.uid = "u-" + uuid.uuid4().hex[:10]
        self.eid = None
        self.sid = None
        self.roster = set()
        self.up = False
        self.lock = threading.Lock()
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        url = ROUTER.replace("https://", "wss://").replace("http://", "ws://") + "/socket.io/?EIO=4&transport=websocket"
        while True:
            try:
                ws = websocket.create_connection(url, timeout=10)
                op = ws.recv()
                assert op.startswith("0"), op
                eid = json.loads(op[1:])["sid"]
                ws.send("40")
                while True:
                    m = ws.recv()
                    if m.startswith("40"):
                        sid = json.loads(m[2:])["sid"]
                        break
                    if m == "2":
                        ws.send("3")
                with self.lock:
                    self.eid, self.sid, self.up, self.roster = eid, sid, True, set()
                say(self.name, "connected eid", eid)
                ws.settimeout(3)
                last = 0
                while True:
                    if time.time() - last >= 3:
                        ws.send("42" + json.dumps(["sync", {"v": 1, "room": ROOM, "name": self.name, "uid": self.uid, "channels": []}]))
                        last = time.time()
                    try:
                        m = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        continue
                    if not m:
                        raise ConnectionError("closed")
                    if m == "2":
                        ws.send("3")
                    elif m.startswith("42"):
                        ev, data = json.loads(m[2:])[:2]
                        if ev == "synced" and data.get("ok"):
                            with self.lock:
                                self.roster = {p["id"] for p in data.get("peers", [])}
                    elif m.startswith("1"):
                        raise ConnectionError("server close")
            except Exception as e:
                with self.lock:
                    was = self.up
                    self.up = False
                if was:
                    say(self.name, "down:", type(e).__name__, str(e)[:80])
                time.sleep(1.0)

    def connected(self):
        return self.up

    def state(self):
        with self.lock:
            return {"eid": self.eid if self.up else None, "sid": self.sid, "roster": set(self.roster)}


def status():
    try:
        return requests.get(ROUTER + "/__router/status", timeout=5).json()
    except Exception as e:
        return {"error": str(e)}


def converged(clients, want_cf):
    st = [c.state() for c in clients]
    if any(s["eid"] is None for s in st):
        return False
    if any(s["eid"].startswith("cf.") != want_cf for s in st):
        return False
    sids = {s["sid"] for s in st}
    return all(s["roster"] >= (sids - {s["sid"]}) for s in st)


def wait_converged(clients, want_cf, label, limit, since=None):
    """Wait until converged; after_s counts from `since` (the kill or the
    restart itself), not from when this wait began."""
    t = since or time.time()
    last_phase = None
    while time.time() - t < limit:
        ph = (status().get("health") or {}).get("phase")
        if ph != last_phase:
            mark("router-phase", phase=ph)
            last_phase = ph
        if converged(clients, want_cf):
            mark(label, after_s=round(time.time() - t, 2))
            return round(time.time() - t, 2)
        time.sleep(0.5)
    mark(label + "-TIMEOUT", states=str([{k: (sorted(v) if isinstance(v, set) else v) for k, v in c.state().items()} for c in clients]))
    return None


def main():
    say("router", ROUTER, "room", ROOM)
    say("status", json.dumps(status()))
    # Long-polling never upgrades here: every poll is its own request through
    # the router, so it exercises the sid stickiness rule directly.
    clients = [SioClient("sio-a"), SioClient("sio-b"), SioClient("sio-poll", ["polling"])]
    for c in clients:
        c.start()
    clients.append(RawClient("cli-c"))
    r0 = wait_converged(clients, False, "baseline-on-origin", 60)
    rest = requests.get(ROUTER + "/api/config", timeout=5)
    mark("rest-backend", backend=rest.headers.get("x-tunlion-backend"))

    t_kill = time.time()
    mark("kill-origin")
    subprocess.run(KILL, shell=True, check=False)
    mark("kill-command-returned")
    r1 = wait_converged(clients, True, "converged-on-cf", 300, since=t_kill)
    rest = requests.get(ROUTER + "/api/config", timeout=5)
    mark("rest-backend", backend=rest.headers.get("x-tunlion-backend"))
    time.sleep(5)

    t_start = time.time()
    mark("start-origin")
    subprocess.run(START, shell=True, check=False)
    mark("start-command-returned")
    r2 = wait_converged(clients, False, "converged-back-on-origin", 420, since=t_start)
    rest = requests.get(ROUTER + "/api/config", timeout=5)
    mark("rest-backend", backend=rest.headers.get("x-tunlion-backend"))

    summary = {
        "router": ROUTER,
        "baseline_s": r0,
        "failover_s_after_kill": r1,
        "failback_s_after_restart": r2,
        "router_status_end": status(),
        "events": EVENTS,
        "pass": r0 is not None and r1 is not None and r2 is not None,
    }
    with open(os.path.join(OUT, "drill-summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)
    say("SUMMARY", json.dumps({k: summary[k] for k in ("baseline_s", "failover_s_after_kill", "failback_s_after_restart", "pass")}))
    os._exit(0 if summary["pass"] else 1)


if __name__ == "__main__":
    main()
