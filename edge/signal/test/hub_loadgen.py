#!/usr/bin/env python3
"""Load generator for the SignalHub Durable Object (or any tunlion signaling
backend), meant to run as a fleet: one process group per GitHub runner, all
runners on one wall-clock schedule so their shares add up to one population.

Wire: the same raw framing the Rust CLI speaks (crates/filament-signal): a
plain websocket to /socket.io/?EIO=4&transport=websocket, engine.io v4
framing, socket.io `42["event",data]` events and `42<id>[...]` / `43<id>[...]`
acks. No socket.io client library, so one runner holds thousands of devices.

Modes:

  idle   ramp this runner's share of a `tunlion up`-shaped population through
         the steps. Each device connects, joins a solo room, subscribes to
         its two pair channels (ack'd), then every CYCLE seconds sends a full
         `sync` (room + channels, answered by `synced`) and CYCLE/2 later a
         room-null heartbeat `sync` (ack'd). Server pings are answered with
         "3". With --cycle 20 and the 25 s ping a device sends
         2/20 + 1/25 = 0.14 messages per second.

  churn  pairing bursts at a fixed rate. Per pair: A connects, joins,
         pair-create; B connects, pair-claim, pair-matched, joins A's room,
         welcome; offer and answer (~3 KB each) and 4 ICE candidates each way
         relayed through `signal`, then both disconnect.

  aggregate  merge the per-runner result files into one table (raw
         latencies are carried in the rows so percentiles are exact).

Schedule: step i of idle ramps during [T0 + i*SLOT, T0 + i*SLOT + RAMP) and
measures during [T0 + i*SLOT + RAMP, T0 + (i+1)*SLOT). After the last step the
population is held for --final-hold more seconds, measured as step "final",
so a churn group can run on top of it.
"""
import argparse
import asyncio
import glob
import json
import multiprocessing as mp
import os
import random
import resource
import secrets
import ssl
import sys
import threading
import time

try:
    from websockets.asyncio.client import connect as ws_connect
except ImportError:  # websockets < 13, or absent (aggregate needs no client)
    try:
        from websockets import connect as ws_connect  # type: ignore
    except ImportError:
        ws_connect = None


def pct(xs, p):
    if not xs:
        return None
    xs = sorted(xs)
    k = min(len(xs) - 1, max(0, int(round(p / 100.0 * (len(xs) - 1)))))
    return xs[k]


def bump(d, k, n=1):
    d[k] = d.get(k, 0) + n


SSL_CTX = ssl.create_default_context()


class Conn:
    """One socket.io-over-websocket connection, EIO=4."""

    def __init__(self, url, on_event=None, stats=None):
        # stats: a callable returning the CURRENT stats window (windows rotate)
        self.url = url
        self.ws = None
        self.sid = None
        self.on_event = on_event
        self.acks = {}
        self.ack_id = 0
        self.closed = False
        self.close_reason = None
        self.reader = None
        self.stats = stats
        self.connected = asyncio.Event()
        self.waiters = {}

    async def open(self, timeout=20.0):
        kw = dict(compression=None, max_size=None, ping_interval=None, open_timeout=timeout, close_timeout=2)
        if self.url.startswith("wss://"):
            kw["ssl"] = SSL_CTX
        self.ws = await asyncio.wait_for(ws_connect(self.url, **kw), timeout)
        self.reader = asyncio.ensure_future(self._read())
        await asyncio.wait_for(self.connected.wait(), timeout)

    async def _read(self):
        try:
            async for msg in self.ws:
                if not isinstance(msg, str) or not msg:
                    continue
                t = msg[0]
                if t == "0":
                    await self.ws.send("40")
                elif t == "2":
                    await self.ws.send("3")
                    if self.stats is not None:
                        self.stats()["pings"] += 1
                elif t == "1":
                    self.close_reason = "eio-close"
                    break
                elif t == "4":
                    self._sio(msg[1:])
            if self.close_reason is None:
                rc = getattr(self.ws, "close_code", None)
                self.close_reason = f"ws-close-{rc}"
        except Exception as e:  # noqa: BLE001
            rcvd = getattr(e, "rcvd", None)
            code = getattr(rcvd, "code", None) if rcvd is not None else None
            self.close_reason = f"{type(e).__name__}-{code}" if code is not None else type(e).__name__
        finally:
            self.closed = True
            for fut in list(self.acks.values()):
                if not fut.done():
                    fut.set_exception(ConnectionError("closed"))
                    fut.exception()
            for lst in self.waiters.values():
                for fut in lst:
                    if not fut.done():
                        fut.set_exception(ConnectionError("closed"))
                        fut.exception()

    def _sio(self, s):
        if not s:
            return
        k = s[0]
        body = s[1:]
        if k == "0":
            try:
                self.sid = json.loads(body).get("sid")
            except Exception:  # noqa: BLE001
                pass
            self.connected.set()
            return
        if k in ("2", "3"):
            i = 0
            while i < len(body) and body[i].isdigit():
                i += 1
            aid = int(body[:i]) if i else None
            try:
                arr = json.loads(body[i:])
            except Exception:  # noqa: BLE001
                return
            if k == "3":
                fut = self.acks.pop(aid, None)
                if fut and not fut.done():
                    fut.set_result(arr[0] if arr else None)
                return
            name = arr[0]
            data = arr[1] if len(arr) > 1 else None
            lst = self.waiters.pop(name, None)
            if lst:
                for fut in lst:
                    if not fut.done():
                        fut.set_result(data)
            if self.on_event:
                self.on_event(self, name, data)
        elif k == "4":
            self.close_reason = "connect_error " + body[:80]

    def wait_for(self, name):
        fut = asyncio.get_event_loop().create_future()
        self.waiters.setdefault(name, []).append(fut)
        return fut

    async def emit(self, name, data):
        await self.ws.send("42" + json.dumps([name, data], separators=(",", ":")))

    async def emit_ack(self, name, data, timeout=10.0):
        self.ack_id += 1
        aid = self.ack_id
        fut = asyncio.get_event_loop().create_future()
        self.acks[aid] = fut
        await self.ws.send("42" + str(aid) + json.dumps([name, data], separators=(",", ":")))
        try:
            return await asyncio.wait_for(fut, timeout)
        finally:
            self.acks.pop(aid, None)

    async def close(self):
        try:
            await self.ws.close()
        except Exception:  # noqa: BLE001
            pass
        if self.reader:
            self.reader.cancel()


def err_key(e):
    status = getattr(getattr(e, "response", None), "status_code", None)
    if status is None:
        status = getattr(e, "status_code", None)
    return f"{type(e).__name__}-{status}" if status is not None else type(e).__name__


# ---------------------------------------------------------------- idle -----

def new_stats():
    return {"conn_ok": 0, "conn_fail": 0, "conn_lat": [], "conn_err": {}, "hb_lat": [], "sync_lat": [],
            "sub_lat": [], "ack_timeout": 0, "drops": 0, "close": {}, "superseded": 0, "pings": 0,
            "sync_bad": 0, "sent": 0}


class IdleDevice:
    def __init__(self, w, idx, channels):
        self.w = w
        self.idx = idx
        self.uid = "lt" + secrets.token_hex(8)
        self.name = f"lt-{w.tag}-{idx}"
        self.room = "up-" + secrets.token_urlsafe(12)
        self.channels = channels
        self.conn = None
        self.task = None
        self.pending_sync = None

    def on_event(self, conn, name, data):
        st = self.w.stats
        if name == "synced":
            if self.pending_sync is not None:
                st["sync_lat"].append(time.perf_counter() - self.pending_sync)
                self.pending_sync = None
            if not (isinstance(data, dict) and data.get("ok")):
                st["sync_bad"] += 1
        elif name == "session-superseded":
            st["superseded"] += 1

    async def run(self, cycle):
        t0 = time.perf_counter()
        self.conn = Conn(self.w.url, on_event=self.on_event, stats=lambda: self.w.stats)
        try:
            await self.conn.open()
        except Exception as e:  # noqa: BLE001
            self.w.stats["conn_fail"] += 1
            bump(self.w.stats["conn_err"], err_key(e))
            return
        self.w.stats["conn_ok"] += 1
        self.w.stats["conn_lat"].append(time.perf_counter() - t0)
        half = cycle / 2.0
        try:
            await self.conn.emit("join", {"room": self.room, "name": self.name, "uid": self.uid})
            t = time.perf_counter()
            await self.conn.emit_ack("subscribe", {"channels": self.channels}, timeout=15)
            self.w.stats["sub_lat"].append(time.perf_counter() - t)
            self.w.stats["sent"] += 2
            await asyncio.sleep(random.uniform(0, cycle))
            while not self.conn.closed and not self.w.stopping:
                self.pending_sync = time.perf_counter()
                await self.conn.emit("sync", {"v": 1, "room": self.room, "name": self.name,
                                              "uid": self.uid, "channels": self.channels})
                self.w.stats["sent"] += 1
                await asyncio.sleep(half)
                if self.conn.closed or self.w.stopping:
                    break
                if self.pending_sync is not None and time.perf_counter() - self.pending_sync > 10:
                    self.w.stats["ack_timeout"] += 1
                    self.pending_sync = None
                t = time.perf_counter()
                try:
                    self.w.stats["sent"] += 1
                    await self.conn.emit_ack("sync", {"v": 1, "room": None, "name": self.name,
                                                      "uid": self.uid}, timeout=10)
                    self.w.stats["hb_lat"].append(time.perf_counter() - t)
                except asyncio.TimeoutError:
                    self.w.stats["ack_timeout"] += 1
                await asyncio.sleep(half)
        except Exception:  # noqa: BLE001
            pass
        if self.conn.closed and not self.w.stopping:
            self.w.stats["drops"] += 1
            bump(self.w.stats["close"], self.conn.close_reason or "?")


class Worker:
    def __init__(self, tag, url):
        self.tag = tag
        self.url = url
        self.stats = new_stats()
        self.devices = []
        self.stopping = False

    def reset_window(self):
        old = self.stats
        self.stats = new_stats()
        return old


def channels_for(tag, idx):
    # fleets of 3 devices, pairwise channels: each device on 2 channels
    import hashlib
    fleet, pos = idx // 3, idx % 3
    out = []
    for a, b in ((0, 1), (0, 2), (1, 2)):
        if pos in (a, b):
            out.append(hashlib.sha256(f"lt-chan-{tag}-{fleet}-{a}{b}".encode()).hexdigest())
    return out


async def idle_worker_main(tag, url, pipe, cycle):
    w = Worker(tag, url)
    loop = asyncio.get_event_loop()
    while True:
        cmd = await loop.run_in_executor(None, pipe.recv)
        op = cmd[0]
        if op == "ramp":
            target, budget = cmd[1], cmd[2]
            add = max(0, target - len(w.devices))
            delay = (budget * 0.8) / add if add else 0
            t_end = time.time() + budget
            while len(w.devices) < target:
                d = IdleDevice(w, len(w.devices), channels_for(tag, len(w.devices)))
                w.devices.append(d)
                d.task = asyncio.ensure_future(d.run(cycle))
                await asyncio.sleep(delay)
            while time.time() < t_end:
                pending = [d for d in w.devices if d.conn is None or
                           (not d.conn.connected.is_set() and not d.conn.closed and not d.task.done())]
                if not pending:
                    break
                await asyncio.sleep(0.5)
            pipe.send(("ramped", len(w.devices)))
        elif op == "window":
            s = w.reset_window()
            s["alive"] = sum(1 for d in w.devices if d.conn and d.conn.connected.is_set() and not d.conn.closed)
            pipe.send(("window", s))
        elif op == "stop":
            w.stopping = True
            await asyncio.gather(*[d.conn.close() for d in w.devices if d.conn], return_exceptions=True)
            pipe.send(("stopped",))
            return


# --------------------------------------------------------------- churn -----

SDP = "v=0\r\n" + ("a=candidate:1 1 udp 2122260223 192.0.2.10 54321 typ host generation 0\r\n" * 40)


def new_churn_stats():
    return {"pairs_started": 0, "pairs_ok": 0, "pairs_fail": 0, "fail": {},
            "sig_lat": [], "setup_lat": [], "pair_total": [], "conn_lat": []}


async def one_pair(url, st, timeout=20.0):
    st["pairs_started"] += 1
    t0 = time.perf_counter()
    stage = "a-connect"
    recv_a, recv_b = asyncio.Queue(), asyncio.Queue()

    def ev_a(c, name, data):
        if name == "signal":
            recv_a.put_nowait((time.perf_counter(), data))

    def ev_b(c, name, data):
        if name == "signal":
            recv_b.put_nowait((time.perf_counter(), data))

    a = Conn(url, on_event=ev_a)
    b = Conn(url, on_event=ev_b)
    try:
        async def body():
            nonlocal stage
            tc = time.perf_counter()
            await a.open()
            st["conn_lat"].append(time.perf_counter() - tc)
            stage = "a-join"
            w = a.wait_for("welcome")
            await a.emit("join", {"room": "up-" + secrets.token_urlsafe(12), "name": "lt-a",
                                  "uid": "lt" + secrets.token_hex(8)})
            await w
            stage = "pair-create"
            for _ in range(5):
                np_ = str(random.randint(10000, 99999))
                ok = a.wait_for("pair-ok")
                er = a.wait_for("pair-error")
                await a.emit("pair-create", {"v": 2, "nameplate": np_})
                done, _ = await asyncio.wait({ok, er}, return_when=asyncio.FIRST_COMPLETED)
                if ok in done:
                    break
                err = er.result()
                if (err or {}).get("error") != "taken":
                    raise RuntimeError("pair-create " + str(err))
            else:
                raise RuntimeError("pair-create taken x5")
            stage = "b-connect"
            tc = time.perf_counter()
            await b.open()
            st["conn_lat"].append(time.perf_counter() - tc)
            stage = "pair-claim"
            m = b.wait_for("pair-matched")
            er = b.wait_for("pair-error")
            used = a.wait_for("pair-used")
            await b.emit("pair-claim", {"v": 2, "nameplate": np_})
            done, _ = await asyncio.wait({m, er}, return_when=asyncio.FIRST_COMPLETED)
            if m not in done:
                raise RuntimeError("pair-claim " + str(er.result()))
            room = m.result()["room"]
            stage = "b-join"
            wb = b.wait_for("welcome")
            pj = a.wait_for("peer-joined")
            await b.emit("join", {"room": room, "name": "lt-b", "uid": "lt" + secrets.token_hex(8)})
            welcome = await wb
            await pj
            await used
            if not any(p.get("id") == a.sid for p in welcome.get("peers", [])):
                raise RuntimeError("welcome missing creator")
            st["setup_lat"].append(time.perf_counter() - t0)
            stage = "offer"
            await b.emit("signal", {"to": a.sid, "data": {"type": "offer", "sdp": SDP, "ts": time.perf_counter()}})
            t, d = await recv_a.get()
            st["sig_lat"].append(t - d["data"]["ts"])
            stage = "answer"
            await a.emit("signal", {"to": b.sid, "data": {"type": "answer", "sdp": SDP, "ts": time.perf_counter()}})
            t, d = await recv_b.get()
            st["sig_lat"].append(t - d["data"]["ts"])
            stage = "candidates"
            for i in range(4):
                cand = {"candidate": f"candidate:{i} 1 udp 1686052607 198.51.100.{i} 6{i}000 typ srflx raddr 0.0.0.0 rport 0",
                        "sdpMid": "0", "ts": time.perf_counter()}
                await b.emit("signal", {"to": a.sid, "data": cand})
                await a.emit("signal", {"to": b.sid, "data": dict(cand, ts=time.perf_counter())})
            for q in (recv_a, recv_b):
                for _ in range(4):
                    t, d = await q.get()
                    st["sig_lat"].append(t - d["data"]["ts"])

        await asyncio.wait_for(body(), timeout)
        st["pairs_ok"] += 1
        st["pair_total"].append(time.perf_counter() - t0)
    except Exception as e:  # noqa: BLE001
        st["pairs_fail"] += 1
        bump(st["fail"], f"{stage}:{err_key(e)}")
    finally:
        await asyncio.gather(a.close(), b.close(), return_exceptions=True)


async def churn_worker_main(url, pipe):
    loop = asyncio.get_event_loop()
    while True:
        cmd = await loop.run_in_executor(None, pipe.recv)
        if cmd[0] == "stop":
            pipe.send(("stopped",))
            return
        _, rate, dur = cmd
        st = new_churn_stats()
        tasks = []
        interval = 1.0 / rate
        start = time.perf_counter()
        n = 0
        while time.perf_counter() - start < dur:
            tasks.append(asyncio.ensure_future(one_pair(url, st)))
            n += 1
            await asyncio.sleep(max(0, start + n * interval - time.perf_counter()))
        await asyncio.gather(*tasks, return_exceptions=True)
        st["elapsed"] = time.perf_counter() - start
        pipe.send(("result", st))


# ---------------------------------------------------------- controller -----

def worker_entry(kind, tag, url, pipe, cycle):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (hard, hard))
    if kind == "idle":
        asyncio.run(idle_worker_main(tag, url, pipe, cycle))
    else:
        asyncio.run(churn_worker_main(url, pipe))


def proc_cpu_seconds(pid):
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(")", 1)[1].split()
        return (int(parts[11]) + int(parts[12])) / os.sysconf("SC_CLK_TCK")
    except Exception:  # noqa: BLE001
        return 0.0


class GenSampler(threading.Thread):
    """The generator's own CPU per process, so a saturated generator shows."""

    def __init__(self, pids, every=5.0):
        super().__init__(daemon=True)
        self.pids, self.every = pids, every
        self.samples = []
        self.lock = threading.Lock()
        self.stop_ev = threading.Event()

    def run(self):
        last = {p: proc_cpu_seconds(p) for p in self.pids}
        last_t = time.time()
        while not self.stop_ev.wait(self.every):
            now = time.time()
            dt = max(1e-6, now - last_t)
            us = []
            for p in self.pids:
                c = proc_cpu_seconds(p)
                us.append((c - last[p]) / dt * 100)
                last[p] = c
            last_t = now
            with self.lock:
                self.samples.append((now, max(us) if us else 0.0))

    def max_in(self, t0, t1):
        with self.lock:
            xs = [u for t, u in self.samples if t0 <= t <= t1]
        return round(max(xs), 1) if xs else None


def merge(dicts):
    out = {}
    for d in dicts:
        for k, v in d.items():
            if isinstance(v, list):
                out.setdefault(k, []).extend(v)
            elif isinstance(v, dict):
                o = out.setdefault(k, {})
                for kk, vv in v.items():
                    o[kk] = o.get(kk, 0) + vv
            elif isinstance(v, (int, float)):
                out[k] = out.get(k, 0) + v
    return out


def msl(xs):
    return [round(x * 1000, 1) for x in xs]


def sleep_until(t):
    d = t - time.time()
    if d > 0:
        time.sleep(d)


def run_idle(a, pipes, sampler, emit):
    steps = [int(s) for s in a.steps.split(",")]
    labels = [str(s) for s in steps] + (["final"] if a.final_hold > 0 else [])
    for i, label in enumerate(labels):
        total = steps[min(i, len(steps) - 1)]
        mine = total // a.shards + (1 if a.shard < total % a.shards else 0)
        per = [mine // a.procs + (1 if j < mine % a.procs else 0) for j in range(a.procs)]
        t_ramp = a.start_at + i * a.slot if label != "final" else a.start_at + len(steps) * a.slot
        hold_end = (t_ramp + a.slot) if label != "final" else (t_ramp + a.final_hold)
        ramp_budget = a.ramp if label != "final" else 0
        sleep_until(t_ramp)
        for pp, n in zip(pipes, per):
            pp.send(("ramp", n, ramp_budget))
        for pp in pipes:
            pp.recv()
        sleep_until(t_ramp + ramp_budget)
        rs = merge([(pp.send(("window",)), pp.recv()[1])[1] for pp in pipes])
        t0 = time.time()
        sleep_until(hold_end)
        t1 = time.time()
        ws = merge([(pp.send(("window",)), pp.recv()[1])[1] for pp in pipes])
        row = {
            "mode": "idle", "shard": a.shard, "step": label, "total_target": total, "mine": mine,
            "hold_s": round(t1 - t0, 1), "conn_ok": rs["conn_ok"] + ws["conn_ok"],
            "conn_fail": rs["conn_fail"] + ws["conn_fail"], "conn_err": merge([rs["conn_err"], ws["conn_err"]]),
            "alive_end": ws["alive"], "drops": rs["drops"] + ws["drops"], "close": merge([rs["close"], ws["close"]]),
            "ack_timeouts": ws["ack_timeout"], "superseded": rs["superseded"] + ws["superseded"],
            "sync_bad": ws["sync_bad"], "pings": ws["pings"], "sent": ws["sent"],
            "gen_cpu_max_proc": sampler.max_in(t_ramp, t1),
            "conn_lat": msl(rs["conn_lat"] + ws["conn_lat"]), "sub_lat": msl(rs["sub_lat"] + ws["sub_lat"]),
            "sync_lat": msl(ws["sync_lat"]), "hb_lat": msl(ws["hb_lat"]),
        }
        emit(row)


def run_churn(a, pipes, sampler, emit):
    rates = [float(r) for r in a.rates.split(",")]
    for i, rate in enumerate(rates):
        t_start = a.start_at + i * (a.dur + a.gap)
        sleep_until(t_start)
        mine = rate / a.shards
        for pp in pipes:
            pp.send(("run", mine / a.procs, a.dur))
        res = [pp.recv()[1] for pp in pipes]
        t1 = time.time()
        s = merge(res)
        emit({
            "mode": "churn", "shard": a.shard, "step": str(rate), "rate_target": rate, "rate_mine": mine,
            "elapsed_s": round(t1 - t_start, 1), "pairs_started": s["pairs_started"], "pairs_ok": s["pairs_ok"],
            "pairs_fail": s["pairs_fail"], "fail": s.get("fail", {}), "gen_cpu_max_proc": sampler.max_in(t_start, t1),
            "sig_lat": msl(s["sig_lat"]), "setup_lat": msl(s["setup_lat"]), "conn_lat": msl(s["conn_lat"]),
            "pair_total": msl(s["pair_total"]), "dur": a.dur,
        })


def run_fleet(a):
    url = a.url.rstrip("/")
    url = url.replace("https://", "wss://").replace("http://", "ws://") + "/socket.io/?EIO=4&transport=websocket"
    os.makedirs(a.out, exist_ok=True)
    ctx = mp.get_context("fork")
    pipes, procs = [], []
    for j in range(a.procs):
        parent, child = ctx.Pipe()
        tag = f"{a.run_tag}-{a.shard}-{j}"
        p = ctx.Process(target=worker_entry, args=(a.mode, tag, url, child, a.cycle), daemon=True)
        p.start()
        pipes.append(parent)
        procs.append(p)
    sampler = GenSampler([p.pid for p in procs])
    sampler.start()
    resf = open(os.path.join(a.out, f"{a.mode}-shard{a.shard}.jsonl"), "a")

    def emit(row):
        resf.write(json.dumps(row) + "\n")
        resf.flush()
        brief = {k: v for k, v in row.items() if not isinstance(v, list)}
        for k in ("sync_lat", "hb_lat", "sig_lat", "setup_lat", "conn_lat"):
            if k in row:
                brief[k + "_p50"] = pct(row[k], 50)
                brief[k + "_p99"] = pct(row[k], 99)
        print(json.dumps(brief), flush=True)

    (run_idle if a.mode == "idle" else run_churn)(a, pipes, sampler, emit)
    for pp in pipes:
        try:
            pp.send(("stop",))
            pp.recv()
        except Exception:  # noqa: BLE001
            pass
    sampler.stop_ev.set()


# ----------------------------------------------------------- aggregate -----

def aggregate(a):
    rows = []
    for f in sorted(glob.glob(os.path.join(a.indir, "**", "*-shard*.jsonl"), recursive=True)):
        with open(f) as fh:
            rows += [json.loads(line) for line in fh if line.strip()]
    out = []
    for mode in ("idle", "churn"):
        steps = []
        for r in rows:
            if r["mode"] == mode and r["step"] not in steps:
                steps.append(r["step"])
        for step in steps:
            rs = [r for r in rows if r["mode"] == mode and r["step"] == step]
            m = merge(rs)
            agg = {"mode": mode, "step": step, "shards": len(rs),
                   "gen_cpu_max_proc": max((r.get("gen_cpu_max_proc") or 0) for r in rs)}
            for k, v in m.items():
                if isinstance(v, list):
                    agg[k + "_n"] = len(v)
                    agg[k + "_p50"] = pct(v, 50)
                    agg[k + "_p99"] = pct(v, 99)
                    agg[k + "_max"] = max(v) if v else None
                elif k not in ("shard", "rate_mine", "rate_target", "total_target", "dur", "hold_s", "elapsed_s",
                               "gen_cpu_max_proc"):
                    agg[k] = v
            if mode == "idle":
                agg["total_target"] = rs[0]["total_target"]
                hold = max(r["hold_s"] for r in rs)
                agg["hold_s"] = hold
                agg["client_msgs_per_s"] = round((m.get("sent", 0) + m.get("pings", 0)) / max(1e-6, hold), 1)
            else:
                agg["rate_target"] = rs[0]["rate_target"]
                agg["ok_pairs_per_s"] = round(m["pairs_ok"] / max(1e-6, rs[0]["dur"]), 2)
            out.append(agg)
    with open(a.outfile, "w") as fh:
        for r in out:
            fh.write(json.dumps(r) + "\n")
    for r in out:
        print(json.dumps(r))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["idle", "churn", "aggregate"])
    ap.add_argument("--url")
    ap.add_argument("--out", default="out")
    ap.add_argument("--procs", type=int, default=3)
    ap.add_argument("--shard", type=int, default=0)
    ap.add_argument("--shards", type=int, default=1)
    ap.add_argument("--run-tag", default=secrets.token_hex(3))
    ap.add_argument("--start-at", type=float, default=0, help="epoch seconds; 0 = now + 5")
    # idle
    ap.add_argument("--steps", default="500,1000,2000,4000", help="TOTAL devices across all shards")
    ap.add_argument("--slot", type=float, default=180)
    ap.add_argument("--ramp", type=float, default=60)
    ap.add_argument("--final-hold", type=float, default=0)
    ap.add_argument("--cycle", type=float, default=20)
    # churn
    ap.add_argument("--rates", default="20,40,60", help="TOTAL pairs/s across all shards")
    ap.add_argument("--dur", type=float, default=30)
    ap.add_argument("--gap", type=float, default=15)
    # aggregate
    ap.add_argument("--indir")
    ap.add_argument("--outfile", default="aggregate.jsonl")
    a = ap.parse_args()
    if a.mode == "aggregate":
        aggregate(a)
        return
    if not a.start_at:
        a.start_at = time.time() + 5
    run_fleet(a)


if __name__ == "__main__":
    sys.exit(main())
