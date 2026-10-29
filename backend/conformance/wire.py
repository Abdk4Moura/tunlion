"""Wire-level clients for the conformance suite.

Two kinds, on purpose:

* ``Peer``: a python-socketio client, the same protocol stack as the browser
  (socket.io v5 over engine.io v4), on the transport the suite was asked for:
  ``websocket``, ``polling`` or ``upgrade`` (polling first, then the engine.io
  upgrade to websocket, the browser's polling-led path).
* ``RawWs``: hand-written frames over a bare websocket, byte for byte what the
  Rust CLI sends (crates/filament-signal): ``EIO=4&transport=websocket``,
  ``40``, ``42[...]``, ``42<id>[...]``. It proves the CLI's exact framing, not
  just what a full socket.io client tolerates.
"""
import json
import os
import queue
import threading
import time
import uuid

import requests
import socketio
import websocket

BASE = os.environ.get("CONFORMANCE_URL", "http://127.0.0.1:5000").rstrip("/")
TRANSPORT = os.environ.get("CONFORMANCE_TRANSPORT", "websocket")
WAIT = float(os.environ.get("CONFORMANCE_WAIT", "8"))
QUIET = float(os.environ.get("CONFORMANCE_QUIET", "1.5"))


def uniq(prefix="r"):
    return f"{prefix}-{uuid.uuid4().hex[:12]}"


def chan():
    return uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex chars, a channel id


class Peer:
    def __init__(self, transport=None):
        self.transport = transport or TRANSPORT
        self.sio = socketio.Client(reconnection=False)
        self._q = []
        self._cv = threading.Condition()
        self.sio.on("*", self._any)
        self.sio.on("disconnect", self._gone)
        self.disconnected = threading.Event()

    def _any(self, event, *args):
        with self._cv:
            self._q.append((event, args[0] if args else None))
            self._cv.notify_all()

    def _gone(self, *_a):
        self.disconnected.set()

    def connect(self):
        transports = {
            "websocket": ["websocket"],
            "polling": ["polling"],
            "upgrade": ["polling", "websocket"],
        }[self.transport]
        self.sio.connect(BASE, transports=transports, wait_timeout=WAIT)
        if self.transport == "upgrade":
            # Give the engine.io upgrade a moment so the test runs over it.
            deadline = time.time() + WAIT
            while time.time() < deadline and self.sio.transport() != "websocket":
                time.sleep(0.05)
            assert self.sio.transport() == "websocket", "polling did not upgrade"
        return self

    @property
    def sid(self):
        return self.sio.get_sid()

    def emit(self, event, data=None):
        self.sio.emit(event, data)

    def call(self, event, data=None, timeout=None):
        return self.sio.call(event, data, timeout=timeout or WAIT)

    def wait(self, event, pred=None, timeout=None):
        """Pop the first queued `event` matching pred (waiting up to timeout)."""
        deadline = time.time() + (timeout or WAIT)
        with self._cv:
            while True:
                for i, (ev, data) in enumerate(self._q):
                    if ev == event and (pred is None or pred(data)):
                        del self._q[i]
                        return data
                left = deadline - time.time()
                if left <= 0:
                    seen = [e for e, _ in self._q]
                    raise AssertionError(f"no {event!r} within timeout; queued: {seen}")
                self._cv.wait(left)

    def none(self, event, pred=None, within=None):
        """Assert no matching `event` arrives within the quiet window."""
        try:
            got = self.wait(event, pred, timeout=within or QUIET)
        except AssertionError:
            return
        raise AssertionError(f"unexpected {event!r}: {got}")

    def drain(self):
        with self._cv:
            self._q.clear()

    def close(self):
        try:
            self.sio.disconnect()
        except Exception:
            pass


class RawWs:
    """The Rust CLI's exact framing over a bare websocket."""

    def __init__(self):
        url = BASE.replace("https://", "wss://").replace("http://", "ws://")
        self.ws = websocket.create_connection(
            f"{url}/socket.io/?EIO=4&transport=websocket", timeout=WAIT)
        self.open = self.ws.recv()
        self.events = queue.Queue()
        self.acks = {}
        self.pings = 0
        self._ack_id = 0
        self._lock = threading.Lock()
        self.ws.send("40")
        while True:
            m = self.ws.recv()
            if m.startswith("40"):
                self.connect_reply = m
                break
            if m == "2":
                self.ws.send("3")
        self.sid = json.loads(self.connect_reply[2:])["sid"]
        self._t = threading.Thread(target=self._read, daemon=True)
        self._t.start()

    def _read(self):
        while True:
            try:
                m = self.ws.recv()
            except Exception:
                self.events.put(("__closed__", None))
                return
            if not m:
                continue
            if m == "2":
                self.pings += 1
                self.ws.send("3")
            elif m.startswith("42"):
                arr = json.loads(m[m.index("["):])
                self.events.put((arr[0], arr[1] if len(arr) > 1 else None))
            elif m.startswith("43"):
                body = m[2:]
                i = body.index("[")
                with self._lock:
                    self.acks[int(body[:i])] = json.loads(body[i:])
            elif m.startswith("1"):
                self.events.put(("__closed__", None))
                return

    def emit(self, event, data):
        self.ws.send("42" + json.dumps([event, data]))

    def call(self, event, data, timeout=None):
        with self._lock:
            self._ack_id += 1
            n = self._ack_id
        self.ws.send(f"42{n}" + json.dumps([event, data]))
        deadline = time.time() + (timeout or WAIT)
        while time.time() < deadline:
            with self._lock:
                if n in self.acks:
                    return self.acks.pop(n)
            time.sleep(0.02)
        raise AssertionError(f"no ack for {event}")

    def wait(self, event, timeout=None):
        deadline = time.time() + (timeout or WAIT)
        held = []
        try:
            while True:
                left = deadline - time.time()
                if left <= 0:
                    raise AssertionError(f"no {event!r} on raw ws")
                try:
                    ev, data = self.events.get(timeout=left)
                except queue.Empty:
                    continue
                if ev == event:
                    return data
                held.append((ev, data))
        finally:
            for h in held:
                self.events.put(h)

    def close(self):
        try:
            self.ws.close()
        except Exception:
            pass


def http(method, path, **kw):
    kw.setdefault("timeout", WAIT)
    return requests.request(method, BASE + path, **kw)
