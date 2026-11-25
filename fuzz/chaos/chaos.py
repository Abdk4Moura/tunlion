#!/usr/bin/env python3
"""Stateful chaos fuzzer for tunlion (stage 1: real binaries, real kernel).

Three real daemons (alpha = owner, bravo and charlie = delegates enrolled with
a shell grant) each live in their own network namespace, routed through the
root namespace where the signaling backend runs. A SCHEDULE says which faults
to apply when (network impairment, partitions, signaling blackhole or reset,
SIGSTOP, SIGKILL and restart, backend restart) and which user operations to run
meanwhile (exec, send, reach). After every fault heals, ORACLES judge the run.

The fuzzer is greybox, in the AFL sense but over behaviour rather than
branches: a schedule that makes the daemons log a kind of line never seen
before is kept and mutated further. Nothing here is deterministic (real
clocks, real sockets), so every failure is replayed before it is reported, and
the reproduction rate is part of the finding.

Exit codes (same convention as scripts/flake-check.sh):
  0  clean            1  at least one hard finding
  3  refused: a precondition is unmet, so no result was produced
  4  the canary was NOT detected: the instrument is broken, every other
     result of this job is meaningless
  5  the harness itself crashed: a bug in this file, not in tunlion

Subcommands:
  canary    two-arm self-check: a known-broken daemon must be flagged and the
            same schedule on a healthy daemon must pass
  replay    run checked-in schedules (the PR gate)
  explore   mutate and run schedules until the time budget runs out (nightly)
  selftest  pure unit checks of the schedule machinery; no root needed

Run as root (network namespaces, tc, iptables). Daemons and CLI commands are
run as an unprivileged user with HOME inside the work dir, never as root: a
root daemon once rewrote sshd's trusted CA on a dev box.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent

DEVICES = ["alpha", "bravo", "charlie"]          # index i -> subnet 10.89.(i+1).0/24
OWNER = "alpha"
DELEGATES = ["bravo", "charlie"]
PORT = 8155
SUBNET = "10.89.0.0/16"

# The CLI's own documented exit codes (cli/src/cli_def.rs, EXIT CODES). A code
# outside this set, a panic (101) or death by a signal we did not send is a
# finding in itself: the user got an answer the docs do not explain.
DOCUMENTED_RC = set(range(0, 14)) | {126, 127, 130, 141, 143}

# Per-operation wall-clock deadlines. The CLI gives up on a link after 45 s
# and says so; a command still running well past that is a hang, which is a
# finding even while faults are active.
OP_DEADLINE = {"exec": 75.0, "send": 90.0, "reach": 75.0, "status": 15.0, "doctor": 90.0}

SETTLE_SIGNALING = 90.0     # after heal: every daemon must report signaling connected
STORM_WINDOW = 30.0         # quiet window in which reconnects are counted
STORM_MAX_CONNECTS = 8      # per device per window; the 2026 storm made ~75
LOOP_STALL_GRACE = 150.0
STALE_LINK_AFTER = 90.0     # O10: a peer silent this long should not still look warm    # a logged stall must be followed by recovery or exit

# CHAOS: device to device (FORWARD). CHAOS_IN: device to the backend (INPUT).
# CHAOS_OUT: the backend's replies to a device (OUTPUT), needed to isolate it.
CHAINS = [("CHAOS", "FORWARD"), ("CHAOS_IN", "INPUT"), ("CHAOS_OUT", "OUTPUT")]

FAULTS = ["net.impair", "net.partition", "net.isolate", "sig.blackhole", "sig.reset",
          "proc.freeze", "proc.kill", "server.down"]
OPS = ["exec", "send", "reach", "status", "doctor"]

# Env hooks (test-hooks builds) that add INTERNAL faults with a designed
# recovery. The fuzzer may switch them on per daemon. Hooks that disable a
# recovery (NO_SIGNALING_RECONNECT, NO_DIRECT...) are not here: those are
# canaries, not faults.
RECOVERABLE_HOOKS = {
    "TUNLION_TEST_DIRECT_FLAKY": ["1"],
    "TUNLION_TEST_DIRECT_DELAY_MS": ["500", "3000"],
    "TUNLION_TEST_ESTABLISH_DELAY_MS": ["500", "4000"],
    "TUNLION_TEST_DROP_FILE_END": ["1"],
    "TUNLION_TEST_DROP_PEER_LEFT": ["1"],
    "TUNLION_TEST_CORRUPT_ONCE": ["1"],
}


# Files a daemon creates while it runs. They are state of THAT process, not of
# the enrolled device, and a socket cannot be copied at all.
RUNTIME_FILES = shutil.ignore_patterns("*.sock", "up.pid", "up.exe", "up.ready", "up.inbox", "up.lock", "*.lock")


def log(msg: str) -> None:
    print(f"[chaos {time.strftime('%H:%M:%S')}] {msg}", flush=True)


class Refused(Exception):
    """A precondition is unmet; no result may be reported (exit 3)."""


def sh(cmd: list[str], check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> rc={r.returncode}: {r.stderr.strip()[:300]}")
    return r


def dev_index(name: str) -> int:
    return DEVICES.index(name) + 1


def dev_ip(name: str) -> str:
    return f"10.89.{dev_index(name)}.1"


def gw_ip(name: str) -> str:
    return f"10.89.{dev_index(name)}.254"


def ns(name: str) -> str:
    return f"chz_{name}"


# ----------------------------------------------------------------- schedule --
#
# A schedule is plain JSON so a finding can be checked in and replayed:
#   {"version": 1, "seed": 7, "hooks": {"bravo": {"ENV": "v"}},
#    "steps": [{"at": 4.0, "fault": "proc.freeze", "target": "bravo", "dur": 80},
#              {"at": 6.0, "op": "exec", "src": "bravo", "dst": "alpha"}]}
# A fault step is applied at `at` and healed at `at + dur`. An op step starts
# at `at` and runs concurrently with everything else.

def random_fault(rng: random.Random) -> dict:
    kind = rng.choice(FAULTS)
    step: dict = {"fault": kind, "at": round(rng.uniform(0, 20), 1),
                  "dur": round(rng.choice([3, 8, 15, 30, 60, 90]) * rng.uniform(0.7, 1.3), 1)}
    if kind == "net.partition":
        a, b = rng.sample(DEVICES, 2)
        step.update(a=a, b=b, proto=rng.choice(["all", "udp"]))
    elif kind == "server.down":
        step["dur"] = min(step["dur"], 40.0)
    else:
        step["target"] = rng.choice(DEVICES)
    if kind == "net.impair":
        step["args"] = {"loss": rng.choice([0, 5, 20, 50]), "delay_ms": rng.choice([0, 80, 400, 1500]),
                        "jitter_ms": rng.choice([0, 50, 300]), "dup": rng.choice([0, 0, 5]),
                        "reorder": rng.choice([0, 0, 25])}
    return step


def random_op(rng: random.Random) -> dict:
    kind = rng.choice(OPS)
    at = round(rng.uniform(0, 40), 1)
    if kind == "exec":
        return {"op": "exec", "at": at, "src": rng.choice(DELEGATES), "dst": OWNER}
    if kind == "send":
        return {"op": "send", "at": at, "src": OWNER, "dst": rng.choice(DELEGATES),
                "kib": rng.choice([4, 256, 4096])}
    if kind == "status":
        # Asking your own machine must answer fast, even with its daemon frozen.
        d = rng.choice(DEVICES)
        return {"op": "status", "at": at, "src": d, "dst": d}
    if kind == "doctor":
        src = rng.choice(DEVICES)
        return {"op": "doctor", "at": at, "src": src, "dst": rng.choice([x for x in DEVICES if x != src])}
    return {"op": "reach", "at": at, "src": OWNER, "dst": rng.choice(DELEGATES)}


def random_schedule(rng: random.Random) -> dict:
    hooks: dict = {}
    if rng.random() < 0.3:
        d = rng.choice(DEVICES)
        k = rng.choice(sorted(RECOVERABLE_HOOKS))
        hooks[d] = {k: rng.choice(RECOVERABLE_HOOKS[k])}
    steps = [random_fault(rng) for _ in range(rng.randint(1, 3))]
    steps += [random_op(rng) for _ in range(rng.randint(1, 4))]
    return normalize({"version": 1, "seed": rng.randrange(1 << 30), "hooks": hooks, "steps": steps})


def normalize(s: dict) -> dict:
    s["steps"].sort(key=lambda st: (st["at"], json.dumps(st, sort_keys=True)))
    return s


def mutate(parent: dict, rng: random.Random) -> dict:
    s = copy.deepcopy(parent)
    s["seed"] = rng.randrange(1 << 30)
    for _ in range(rng.randint(1, 3)):
        faults = [st for st in s["steps"] if "fault" in st]
        r = rng.random()
        if r < 0.25:
            s["steps"].append(random_fault(rng))
        elif r < 0.40:
            s["steps"].append(random_op(rng))
        elif r < 0.55 and len(faults) > 1:
            s["steps"].remove(rng.choice(faults))
        elif r < 0.75 and s["steps"]:
            st = rng.choice(s["steps"])
            st["at"] = round(max(0.0, st["at"] + rng.uniform(-8, 8)), 1)
        elif r < 0.90 and faults:
            st = rng.choice(faults)
            st["dur"] = round(max(1.0, st["dur"] * rng.choice([0.25, 0.5, 2, 3])), 1)
        else:
            d = rng.choice(DEVICES)
            k = rng.choice(sorted(RECOVERABLE_HOOKS))
            s.setdefault("hooks", {}).setdefault(d, {})
            if k in s["hooks"][d]:
                del s["hooks"][d][k]
            else:
                s["hooks"][d][k] = rng.choice(RECOVERABLE_HOOKS[k])
    if not any("fault" in st for st in s["steps"]):
        s["steps"].append(random_fault(rng))
    return normalize(s)


def window_end(s: dict) -> float:
    ends = [st["at"] + st.get("dur", 0.0) for st in s["steps"] if "fault" in st]
    ends += [st["at"] for st in s["steps"] if "op" in st]
    return max(ends or [0.0])


# ---------------------------------------------------------- log signatures --
#
# The feedback signal. A daemon log line is reduced to its "kind": the
# timestamp is cut and every number, hex run, address, path and quoted value is
# replaced, then the first eight words are kept. A schedule is interesting
# when the union of kinds across all daemons contains one never seen before.

_TS = re.compile(r"^\S*\d{4}-\d\d-\d\dT[\d:.]+Z?\s*")
_SUBS = [
    (re.compile(r"'[^']*'|\"[^\"]*\"|`[^`]*`"), "Q"),
    (re.compile(r"(/[\w.\-]+)+"), "P"),
    (re.compile(r"\b[\da-f]{8,}\b", re.I), "H"),
    (re.compile(r"\b[\da-f]*:[\da-f:]{4,}\b", re.I), "H"),
    (re.compile(r"\d+(?:[.:]\d+)*"), "N"),
]


def line_kind(line: str) -> str | None:
    line = _TS.sub("", line.strip())
    if not line:
        return None
    for rx, rep in _SUBS:
        line = rx.sub(rep, line)
    words = line.split()[:8]
    return " ".join(words) if words else None


def kinds_of(text: str) -> set[str]:
    out = set()
    for ln in text.splitlines():
        k = line_kind(ln)
        if k:
            out.add(k)
    return out


# ------------------------------------------------------------------ world --

class World:
    """The fixture: namespaces, firewall chains, backend, three daemons."""

    def __init__(self, binary: Path, work: Path, py: str):
        self.bin = binary
        self.work = work
        self.py = py
        self.uid, self.gid = self._pick_user()
        self.backend: subprocess.Popen | None = None
        self.daemons: dict[str, subprocess.Popen | None] = {d: None for d in DEVICES}
        self.hooks: dict[str, dict] = {}
        self.incarnation: dict[str, int] = {d: 0 for d in DEVICES}
        self.bin_sha = self._sha(binary)
        self.can_netem = False
        self.snapshot = work / "snapshot"

    # -- preconditions ------------------------------------------------------
    @staticmethod
    def _pick_user() -> tuple[int, int]:
        uid = int(os.environ.get("SUDO_UID", "65534"))
        gid = int(os.environ.get("SUDO_GID", "65534"))
        if uid == 0:
            uid, gid = 65534, 65534
        return uid, gid

    @staticmethod
    def _sha(p: Path) -> str:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def preconditions(self) -> None:
        if os.geteuid() != 0:
            raise Refused("must run as root (network namespaces, tc, iptables)")
        for tool in ["ip", "iptables", "tc", "setpriv", "ss"]:
            if not shutil.which(tool):
                raise Refused(f"missing tool: {tool}")
        if not os.access(self.bin, os.X_OK):
            raise Refused(f"binary not executable: {self.bin}")
        free = shutil.disk_usage(self.work).free
        if free < 2 << 30:
            raise Refused(f"less than 2 GiB free under {self.work} ({free >> 20} MiB)")
        if not (REPO / "backend" / "app.py").exists():
            raise Refused("backend/app.py not found")
        r = sh([self.py, "-c", "import flask, flask_socketio, eventlet"], check=False)
        if r.returncode != 0:
            raise Refused(f"backend python ({self.py}) lacks flask/flask_socketio/eventlet")

    def assert_binary_unchanged(self) -> None:
        now = self._sha(self.bin)
        if now != self.bin_sha:
            raise Refused(f"binary changed under the run: {self.bin_sha[:12]} -> {now[:12]}")

    # -- network ------------------------------------------------------------
    def reap_stale(self) -> None:
        """Kill what a previous campaign left behind: daemons running from an
        older /tmp/chz.* work dir and anything on our port (a stale backend
        would answer health checks with another campaign's state)."""
        mine = str(self.work)
        victims = set()
        for p in Path("/proc").iterdir():
            if not p.name.isdigit() or int(p.name) == os.getpid():
                continue
            try:
                cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if "/tmp/chz." in cmd and mine not in cmd and "chaos.py" not in cmd:
                victims.add(int(p.name))
        r = sh(["ss", "-ltnpH", f"sport = :{PORT}"], check=False)
        victims |= {int(x) for x in re.findall(r"pid=(\d+)", r.stdout)}
        for pid in victims:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if victims:
            log(f"reaped {len(victims)} process(es) left by an earlier campaign")
            time.sleep(1)

    def net_up(self) -> None:
        self.reap_stale()
        self.net_down()
        sh(["sysctl", "-qw", "net.ipv4.ip_forward=1"])
        for d in DEVICES:
            i = dev_index(d)
            sh(["ip", "netns", "add", ns(d)])
            sh(["ip", "-n", ns(d), "link", "set", "lo", "up"])
            sh(["ip", "link", "add", f"chzr{i}", "type", "veth", "peer", "name", f"chzn{i}"])
            sh(["ip", "link", "set", f"chzn{i}", "netns", ns(d)])
            sh(["ip", "addr", "add", f"{gw_ip(d)}/24", "dev", f"chzr{i}"])
            sh(["ip", "link", "set", f"chzr{i}", "up"])
            sh(["ip", "-n", ns(d), "addr", "add", f"{dev_ip(d)}/24", "dev", f"chzn{i}"])
            sh(["ip", "-n", ns(d), "link", "set", f"chzn{i}", "up"])
            sh(["ip", "-n", ns(d), "route", "add", "default", "via", gw_ip(d)])
        # CHAOS: device-to-device forwarding (partitions go first, then accept;
        # runners with docker default FORWARD to DROP). CHAOS_IN: device to
        # backend; a counting rule per device (SYNs = connection attempts,
        # measured OUTSIDE the daemon) precedes the fault rules.
        for chain, hook in CHAINS:
            sh(["iptables", "-N", chain])
            sh(["iptables", "-I", hook, "1", "-j", chain])
        sh(["iptables", "-A", "CHAOS", "-s", SUBNET, "-d", SUBNET, "-j", "ACCEPT"])
        for d in DEVICES:
            sh(["iptables", "-A", "CHAOS_IN", "-s", dev_ip(d), "-p", "tcp", "--dport", str(PORT),
                "--syn", "-m", "comment", "--comment", f"syn-{d}"])
        # Prove netem exists before any schedule relies on it.
        r = sh(["tc", "qdisc", "add", "dev", "chzr1", "root", "netem", "delay", "1ms"], check=False)
        self.can_netem = r.returncode == 0
        if self.can_netem:
            sh(["tc", "qdisc", "del", "dev", "chzr1", "root"], check=False)
        else:
            log(f"netem unavailable ({r.stderr.strip()[:120]}); net.impair is DISABLED for this run")

    def net_down(self) -> None:
        for chain, hook in CHAINS:
            sh(["iptables", "-D", hook, "-j", chain], check=False)
            sh(["iptables", "-F", chain], check=False)
            sh(["iptables", "-X", chain], check=False)
        for d in DEVICES:
            sh(["ip", "netns", "del", ns(d)], check=False)
            sh(["ip", "link", "del", f"chzr{dev_index(d)}"], check=False)

    def syn_count(self, d: str) -> int:
        out = sh(["iptables", "-nvxL", "CHAOS_IN"]).stdout
        for ln in out.splitlines():
            if f"syn-{d} " in ln + " ":
                return int(ln.split()[0])
        raise RuntimeError(f"counting rule for {d} missing")

    # -- backend ------------------------------------------------------------
    def backend_start(self) -> None:
        env = dict(os.environ, PORT=str(PORT), FIL_ASYNC_MODE="eventlet", FIL_SELF_MONKEYPATCH="1",
                   FIL_CLAIM_LIMIT="1000000", FIL_PING_TIMEOUT="120", FIL_PING_INTERVAL="25")
        f = open(self.work / "backend.log", "ab")
        self.backend = subprocess.Popen([self.py, "app.py"], cwd=REPO / "backend", env=env,
                                        stdout=f, stderr=subprocess.STDOUT, start_new_session=True)
        for _ in range(60):
            if self.backend_healthy():
                return
            time.sleep(0.5)
        raise Refused("backend never became healthy (see backend.log)")

    def backend_healthy(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=1) as s:
                s.sendall(b"GET /api/health HTTP/1.0\r\nHost: x\r\n\r\n")
                return b" 200 " in s.recv(200)
        except OSError:
            return False

    def backend_stop(self) -> None:
        if self.backend and self.backend.poll() is None:
            self.backend.terminate()
            try:
                self.backend.wait(5)
            except subprocess.TimeoutExpired:
                self.backend.kill()
                self.backend.wait()
        self.backend = None

    # -- devices ------------------------------------------------------------
    def cfg(self, d: str) -> Path:
        return self.work / "dev" / d

    def server(self, d: str) -> str:
        return f"http://{gw_ip(d)}:{PORT}"

    def env_for(self, d: str, extra: dict | None = None) -> dict:
        c = self.cfg(d)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(c / "home"),
               "XDG_CONFIG_HOME": str(c / "home" / ".config"), "XDG_RUNTIME_DIR": str(c / "run"),
               "TUNLION_CONFIG_DIR": str(c / "cfg"), "TUNLION_L2": "1", "TUNLION_NO_UPDATE_CHECK": "1",
               "LANG": "C.UTF-8", "NO_COLOR": "1"}
        env.update(extra or {})
        return env

    def as_dev(self, d: str, args: list[str]) -> list[str]:
        return ["ip", "netns", "exec", ns(d), "setpriv", f"--reuid={self.uid}", f"--regid={self.gid}",
                "--clear-groups", "--", str(self.bin), "--server", self.server(d)] + args

    def cli(self, d: str, args: list[str], timeout: float) -> tuple[int | None, str, str, float]:
        """Run one CLI command as device d. rc None means it overran `timeout`."""
        t0 = time.monotonic()
        p = subprocess.Popen(self.as_dev(d, args), env=self.env_for(d), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
                             start_new_session=True)
        try:
            out, err = p.communicate(timeout=timeout)
            return p.returncode, out, err, time.monotonic() - t0
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            out, err = p.communicate()
            return None, out, err, time.monotonic() - t0

    def fresh_dirs(self) -> None:
        for d in DEVICES:
            c = self.cfg(d)
            for sub in ["cfg", "home/.config", "run", "drop", "files"]:
                (c / sub).mkdir(parents=True, exist_ok=True)
            os.chmod(c / "run", 0o700)
        os.chmod(self.work, 0o755)
        subprocess.run(["chown", "-R", f"{self.uid}:{self.gid}", str(self.work / "dev")], check=True)

    def daemon_start(self, d: str) -> None:
        self.incarnation[d] += 1
        logf = open(self.cfg(d) / f"daemon.{self.incarnation[d]}.log", "ab")
        env = self.env_for(d, self.hooks.get(d, {}))
        self.daemons[d] = subprocess.Popen(self.as_dev(d, ["up", "--dir", str(self.cfg(d) / "drop")]),
                                           env=env, stdout=logf, stderr=subprocess.STDOUT,
                                           stdin=subprocess.DEVNULL, start_new_session=True)

    def daemon_stop(self, d: str, sig: int = signal.SIGTERM) -> None:
        p = self.daemons.get(d)
        if not p or p.poll() is not None:
            return
        try:
            os.kill(p.pid, signal.SIGCONT)
            os.kill(p.pid, sig)
            p.wait(10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.kill(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()

    def all_daemon_logs(self) -> dict[str, str]:
        out = {}
        for d in DEVICES:
            parts = []
            for f in sorted(self.cfg(d).glob("daemon.*.log")):
                parts.append(f.read_text(errors="replace"))
            out[d] = "\n".join(parts)
        return out

    def cap_status(self, d: str, timeout: float = 3.0) -> dict | None:
        for path in [self.cfg(d) / "cfg" / "control.sock"]:
            try:
                s = socket.socket(socket.AF_UNIX)
                s.settimeout(timeout)
                s.connect(str(path))
                s.sendall(b'{"op":"cap-status"}\n')
                buf = b""
                while not buf.endswith(b"\n"):
                    c = s.recv(65536)
                    if not c:
                        break
                    buf += c
                s.close()
                return json.loads(buf)
            except (OSError, ValueError):
                continue
        return None

    # -- one-time setup, then snapshot --------------------------------------
    def setup(self) -> None:
        self.fresh_dirs()
        self.backend_start()
        rc, out, err, _ = self.cli(OWNER, ["init", "--name", OWNER, "--recovery-file",
                                           str(self.cfg(OWNER) / "cfg" / "rec.txt"), "--yes"], 60)
        if rc != 0:
            raise Refused(f"init failed rc={rc}: {err.strip()[-300:]}")
        self.daemon_start(OWNER)
        time.sleep(3)
        for d in DELEGATES:
            inv = self.cfg(OWNER) / "files" / f"{d}-inv.txt"
            rc, out, err, _ = self.cli(OWNER, ["add", "--for", d, "--allow", "shell", "--out", str(inv), "--yes"], 60)
            if rc != 0:
                raise Refused(f"add --for {d} failed rc={rc}: {err.strip()[-300:]}")
            dst = self.cfg(d) / "files" / "inv.txt"
            shutil.copy(inv, dst)
            os.chown(dst, self.uid, self.gid)
            rc, out, err, _ = self.cli(d, ["join", "--invite-file", str(dst), "--name", d, "--no-interactive"], 60)
            if rc != 0:
                raise Refused(f"join {d} failed rc={rc}: {err.strip()[-300:]}")
        self.daemon_stop(OWNER)
        if self.snapshot.exists():
            shutil.rmtree(self.snapshot)
        for d in DEVICES:
            shutil.copytree(self.cfg(d) / "cfg", self.snapshot / d, symlinks=True, ignore=RUNTIME_FILES)

    def reset_for_run(self, hooks: dict) -> None:
        """Every run starts from the same enrolled state with fresh daemons."""
        for d in DEVICES:
            self.daemon_stop(d, signal.SIGKILL)
        if not self.backend_healthy():
            self.backend_stop()
            self.backend_start()
        for d in DEVICES:
            c = self.cfg(d)
            shutil.rmtree(c / "cfg", ignore_errors=True)
            shutil.copytree(self.snapshot / d, c / "cfg", symlinks=True)
            for f in c.glob("daemon.*.log"):
                f.unlink()
            shutil.rmtree(c / "drop", ignore_errors=True)
            (c / "drop").mkdir()
        subprocess.run(["chown", "-R", f"{self.uid}:{self.gid}", str(self.work / "dev")], check=True)
        self.hooks = hooks
        self.incarnation = {d: 0 for d in DEVICES}
        for d in DEVICES:
            self.daemon_start(d)

    def teardown(self) -> None:
        for d in DEVICES:
            self.daemon_stop(d, signal.SIGKILL)
        self.backend_stop()
        self.net_down()


# ----------------------------------------------------------------- faults --
#
# Every fault returns an Applied record whose `engaged` callable is evaluated
# at heal time. A fault whose MECHANISM is absent at heal time (rule missing,
# qdisc missing, process not stopped) fails the run as an instrument error,
# never as a pass. Whether it BIT (counters moved) is recorded per fault and
# required in aggregate per campaign.

class Applied:
    def __init__(self, step: dict, heal, present, bit):
        self.step, self.heal, self.present, self.bit = step, heal, present, bit


def _ipt_counter(chain: str, comment: str) -> int:
    out = sh(["iptables", "-nvxL", chain]).stdout
    total = 0
    found = False
    for ln in out.splitlines():
        if f"/* {comment} */" in ln:
            total += int(ln.split()[0])
            found = True
    return total if found else -1


def apply_fault(w: World, st: dict, uid: str) -> Applied | None:
    k = st["fault"]
    tag = f"chz-{uid}"
    if k == "net.impair":
        if not w.can_netem:
            return None
        a = st.get("args", {})
        spec = []
        if a.get("delay_ms"):
            spec += ["delay", f"{a['delay_ms']}ms"] + ([f"{a['jitter_ms']}ms"] if a.get("jitter_ms") else [])
        if a.get("loss"):
            spec += ["loss", f"{a['loss']}%"]
        if a.get("dup"):
            spec += ["duplicate", f"{a['dup']}%"]
        if a.get("reorder") and a.get("delay_ms"):
            spec += ["reorder", f"{a['reorder']}%"]
        if not spec:
            spec = ["loss", "10%"]
        i = dev_index(st["target"])
        devs = [(None, f"chzr{i}"), (ns(st["target"]), f"chzn{i}")]

        def tc(n, *args):
            return sh((["ip", "netns", "exec", n] if n else []) + ["tc", *args], check=False)
        for n, dv in devs:
            tc(n, "qdisc", "replace", "dev", dv, "root", "netem", *spec)

        def heal():
            for n, dv in devs:
                tc(n, "qdisc", "del", "dev", dv, "root")

        def present():
            return all("netem" in tc(n, "qdisc", "show", "dev", dv).stdout for n, dv in devs)

        def bit():
            s = "".join(tc(n, "-s", "qdisc", "show", "dev", dv).stdout for n, dv in devs)
            sent = sum(int(x) for x in re.findall(r"Sent \d+ bytes (\d+) pkt", s))
            return sent > 0
        return Applied(st, heal, present, bit)

    if k == "net.partition":
        a, b = st["a"], st["b"]
        proto = [] if st.get("proto") == "all" else ["-p", "udp"]
        rules = [["-s", dev_ip(a), "-d", dev_ip(b)] + proto, ["-s", dev_ip(b), "-d", dev_ip(a)] + proto]
        for r in rules:
            sh(["iptables", "-I", "CHAOS", "1", *r, "-m", "comment", "--comment", tag, "-j", "DROP"])

        def heal():
            for r in rules:
                sh(["iptables", "-D", "CHAOS", *r, "-m", "comment", "--comment", tag, "-j", "DROP"], check=False)
        return Applied(st, heal, lambda: _ipt_counter("CHAOS", tag) >= 0,
                       lambda: _ipt_counter("CHAOS", tag) > 0)

    if k == "net.isolate":
        # The machine drops off every network at once (lid closed, Wi-Fi
        # gone): nothing in or out, to peers or to the server, no close sent.
        ip = dev_ip(st["target"])
        rules = [("CHAOS", ["-s", ip]), ("CHAOS", ["-d", ip]), ("CHAOS_IN", ["-s", ip]), ("CHAOS_OUT", ["-d", ip])]
        for chain, r in rules:
            sh(["iptables", "-I", chain, "1", *r, "-m", "comment", "--comment", tag, "-j", "DROP"])

        def heal():
            for chain, r in rules:
                sh(["iptables", "-D", chain, *r, "-m", "comment", "--comment", tag, "-j", "DROP"], check=False)

        def present():
            return all(_ipt_counter(c, tag) >= 0 for c in ("CHAOS", "CHAOS_IN", "CHAOS_OUT"))
        return Applied(st, heal, present,
                       lambda: sum(max(0, _ipt_counter(c, tag)) for c in ("CHAOS", "CHAOS_IN", "CHAOS_OUT")) > 0)

    if k in ("sig.blackhole", "sig.reset"):
        d = st["target"]
        target = ["-j", "DROP"] if k == "sig.blackhole" else ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]
        rule = ["-s", dev_ip(d), "-p", "tcp", "--dport", str(PORT), "-m", "comment", "--comment", tag]
        full = rule + (target[2:] if k == "sig.reset" else target)
        # Insert after the counting rules (1..3), so attempts are still counted.
        sh(["iptables", "-I", "CHAOS_IN", str(len(DEVICES) + 1), *full])
        killed = 0
        if k == "sig.reset":
            # A rule only bites when a packet crosses it, and an idle signaling
            # socket can be silent for a whole ping interval (25 s). Abort the
            # live connections from the server side too (tcp_abort sends RST),
            # so the reset happens now and is provable.
            r = sh(["ss", "-K", "-tn", "dst", dev_ip(d), "sport", "=", f":{PORT}"], check=False)
            killed = max(0, len([ln for ln in r.stdout.splitlines() if "ESTAB" in ln or dev_ip(d) in ln]))

        def heal():
            sh(["iptables", "-D", "CHAOS_IN", *full], check=False)
        return Applied(st, heal, lambda: _ipt_counter("CHAOS_IN", tag) >= 0,
                       lambda: killed > 0 or _ipt_counter("CHAOS_IN", tag) > 0)

    if k == "proc.freeze":
        d = st["target"]
        p = w.daemons.get(d)
        if not p or p.poll() is not None:
            return None
        os.kill(p.pid, signal.SIGSTOP)
        pid = p.pid

        def state():
            try:
                return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except OSError:
                return "?"
        seen = {"T": state() == "T"}

        def heal():
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass

        def present():
            seen["T"] = seen["T"] or state() == "T"
            return seen["T"]
        return Applied(st, heal, present, present)

    if k == "proc.kill":
        d = st["target"]
        p = w.daemons.get(d)
        if not p or p.poll() is not None:
            return None
        os.kill(p.pid, signal.SIGKILL)
        p.wait()

        def heal():
            w.daemon_start(d)
        return Applied(st, heal, lambda: True, lambda: True)

    if k == "server.down":
        w.backend_stop()

        def heal():
            w.backend_start()
        return Applied(st, heal, lambda: not w.backend_healthy() or True, lambda: True)
    raise ValueError(k)


# -------------------------------------------------------------------- ops --

def run_op(w: World, st: dict, phase: str) -> dict:
    kind = st["op"]
    src, dst = st["src"], st["dst"]
    res = {"op": kind, "src": src, "dst": dst, "phase": phase, "at": st.get("at"),
           "deadline": st.get("deadline", OP_DEADLINE[kind])}
    deadline = st.get("deadline", OP_DEADLINE[kind])
    if kind == "exec":
        token = f"CHZ{random.randrange(1 << 40):x}"
        cmd = st.get("cmd") or ["/bin/echo", token]
        rc, out, err, el = w.cli(src, ["exec", dst, "--", *cmd], deadline)
        res.update(rc=rc, elapsed=round(el, 2), ok=(rc == 0 and token in out))
        res["lie"] = rc == 0 and token not in out
    elif kind == "send":
        name = f"chz-{random.randrange(1 << 40):x}.bin"
        f = w.cfg(src) / "files" / name
        data = os.urandom(st.get("kib", 4) * 1024)
        f.write_bytes(data)
        os.chown(f, w.uid, w.gid)
        rc, out, err, el = w.cli(src, ["send", str(f), "--to", dst], deadline)
        got = None
        if rc == 0:
            for _ in range(20):
                hits = list((w.cfg(dst) / "drop").rglob(name))
                if hits and hits[0].stat().st_size == len(data):
                    got = hits[0].read_bytes()
                    break
                time.sleep(0.5)
        intact = got is not None and hashlib.sha256(got).digest() == hashlib.sha256(data).digest()
        res.update(rc=rc, elapsed=round(el, 2), ok=(rc == 0 and intact))
        # rc 0 with the file absent or different is the worst UX outcome there is.
        res["lie"] = rc == 0 and not intact
    elif kind == "status":
        rc, out, err, el = w.cli(src, ["status"], deadline)
        res.update(rc=rc, elapsed=round(el, 2), ok=rc == 0, lie=False)
    elif kind == "doctor":
        rc, out, err, el = w.cli(src, ["doctor", dst], deadline)
        res.update(rc=rc, elapsed=round(el, 2), ok=rc == 0, lie=False)
    else:
        rc, out, err, el = w.cli(src, ["reach", dst], deadline)
        res.update(rc=rc, elapsed=round(el, 2), ok=rc == 0, lie=False)
    res["stderr_tail"] = (err or "").strip()[-400:]
    res["stderr_full"] = (err or "").strip()[-20000:]
    res["stdout_tail"] = (out or "").strip()[-200:]
    return res


def judge_op(r: dict) -> list[dict]:
    """UX oracles that hold for every operation, faults or not."""
    f = []
    who = f"{r['op']} {r['src']}->{r['dst']}"
    if r["rc"] is None:
        f.append({"oracle": "O2-hang", "hard": True,
                  "what": f"{who} still running after {r.get('deadline', OP_DEADLINE[r['op']]):.0f}s ({r['phase']})"})
        return f
    if r["rc"] == 101:
        f.append({"oracle": "O4-panic", "hard": True, "what": f"{who} panicked: {r['stderr_tail'][-200:]}"})
    elif r["rc"] < 0:
        f.append({"oracle": "O4-signal", "hard": True, "what": f"{who} died by signal {-r['rc']}"})
    elif r["rc"] not in DOCUMENTED_RC:
        f.append({"oracle": "O6-undocumented-rc", "hard": True, "what": f"{who} exited {r['rc']}"})
    if r.get("lie"):
        f.append({"oracle": "O7-false-success", "hard": True,
                  "what": f"{who} exited 0 but the result was missing or wrong"})
    if r["rc"] not in (0, None) and not r["stderr_tail"]:
        f.append({"oracle": "O8-silent-failure", "hard": True,
                  "what": f"{who} failed (rc {r['rc']}) with nothing on stderr"})
    return f


# A failure message that tells the user the PEER is the problem: offline, not
# running `tunlion up`, never appeared. Matched loosely on purpose; the other
# conditions in judge_diagnosis carry the precision.
_BLAMES_PEER = re.compile(r"\boffline\b|is '?[\w-]+'? online|`tunlion up` (is not )?running|"
                          r"did not appear on the tunlion server|did not answer within", re.I)
# A hint that names the path between the machines as a possible cause is not
# a misdiagnosis, even when it also allows that the peer went away.
_NAMES_PATH = re.compile(r"firewall|\bpath\b|relay|\bUDP\b|network between", re.I)
# Faults that really can make the peer look offline. A partition between two
# devices or a degraded link cannot: the peer is still up and announced.
_PEER_DOWN_FAULTS = {"proc.freeze", "proc.kill", "sig.blackhole", "sig.reset", "net.isolate"}


def judge_diagnosis(r: dict, fault_windows: list[dict]) -> list[dict]:
    """O9: the command blamed the peer (offline, not running) while the peer
    was up: no fault that could take it offline overlapped the command (15 s
    of slack before it, for presence to settle), and the peer's daemon said it
    was connected to the server right after the failure."""
    if r.get("ok") or r.get("rc") in (None, 0) or "t_start" not in r:
        return []
    err = r.get("stderr_tail") or ""
    if not _BLAMES_PEER.search(err) or _NAMES_PATH.search(err):
        return []
    dst = r["dst"]
    lo, hi = r["t_start"] - 15.0, r["t_end"]
    for f in fault_windows:
        st = f["step"]
        end = f["end"] if f["end"] is not None else float("inf")
        if not (f["start"] < hi and end > lo):
            continue
        if st["fault"] == "server.down":
            return []
        if st["fault"] in _PEER_DOWN_FAULTS and st.get("target") == dst:
            return []
    if r.get("dst_signaling_after") != "connected":
        return []
    return [{"oracle": "O9-misdiagnosis", "hard": True,
             "what": f"{r['op']} {r['src']}->{dst} told the user the peer was offline or not running "
                     f"(rc {r['rc']}), but {dst} was up and connected; real cause was elsewhere: "
                     f"{r['stderr_tail'][-180:]}"}]


# ------------------------------------------------------------- one run ---

def run_schedule(w: World, sched: dict, label: str) -> dict:
    """Execute one schedule end to end. Returns the verdict (never raises for
    product misbehaviour; raises Refused for fixture problems)."""
    w.assert_binary_unchanged()
    w.reset_for_run(sched.get("hooks", {}))
    verdict: dict = {"label": label, "schedule": sched, "findings": [], "ops": [], "faults": []}

    # Baseline: the fixture must work before any fault, or the run proves nothing.
    seen = wait_signaling(w, DEVICES, 60, allow_unreported=True)
    bad = {d: v for d, v in seen.items() if v[0] not in ("connected", "unreported")}
    if bad:
        raise Refused(f"baseline: signaling not ready after 60s: {bad}")
    verdict["unreported_signaling"] = sorted(d for d, v in seen.items() if v[0] == "unreported")
    base = run_op(w, {"op": "exec", "src": "bravo", "dst": OWNER}, "baseline")
    if not base["ok"]:
        raise Refused(f"baseline exec bravo->alpha failed rc={base['rc']}: {base['stderr_tail'][-200:]}")

    t0 = time.monotonic()
    active: list[tuple[float, Applied]] = []
    timeline: list[dict] = []
    threads: list[threading.Thread] = []
    results: list[dict] = []
    lock = threading.Lock()
    pending = list(sched["steps"])
    n = 0
    while pending or active:
        now = time.monotonic() - t0
        while pending and pending[0]["at"] <= now:
            st = pending.pop(0)
            if "fault" in st:
                n += 1
                ap = apply_fault(w, st, f"{os.getpid()}-{n}")
                if ap:
                    active.append((st["at"] + st["dur"], ap))
                    timeline.append({"step": st, "start": now, "end": None, "ap": ap})
                    log(f"  t={now:5.1f} apply {json.dumps(st, sort_keys=True)}")
                else:
                    verdict["faults"].append({"step": st, "skipped": True})
            else:
                def go(st=st):
                    t_s = time.monotonic() - t0
                    r = run_op(w, st, "fault-window")
                    r["t_start"], r["t_end"] = round(t_s, 1), round(time.monotonic() - t0, 1)
                    if not r["ok"]:
                        r["dst_signaling_after"] = sig_state(w, st["dst"])[0]
                    with lock:
                        results.append(r)
                th = threading.Thread(target=go, daemon=True)
                th.start()
                threads.append(th)
        for item in list(active):
            end, ap = item
            if end <= now:
                present = ap.present()
                bit = ap.bit()
                if ap.step["fault"] == "net.isolate" and ap.step["dur"] >= STALE_LINK_AFTER:
                    verdict["findings"].extend(stale_links(w, ap.step["target"], ap.step["dur"]))
                ap.heal()
                active.remove(item)
                for tl in timeline:
                    if tl["ap"] is ap:
                        tl["end"] = now
                verdict["faults"].append({"step": ap.step, "present": present, "bit": bit})
                log(f"  t={now:5.1f} heal  {ap.step['fault']} present={present} bit={bit}")
                if not present:
                    raise Refused(f"instrument: fault mechanism absent at heal time: {ap.step}")
        time.sleep(0.2)
    for th in threads:
        th.join(max(OP_DEADLINE.values()) + 30)
    verdict["ops"].extend(results)
    fault_windows = [{"step": tl["step"], "start": tl["start"], "end": tl["end"]} for tl in timeline]
    verdict["fault_windows"] = [{"fault": f["step"]["fault"], "start": round(f["start"], 1),
                                 "end": None if f["end"] is None else round(f["end"], 1)} for f in fault_windows]
    for r in results:
        verdict["findings"].extend(judge_op(r))
        verdict["findings"].extend(judge_diagnosis(r, fault_windows))

    # After heal: every daemon reconnects, every path works, nobody storms.
    alive = [d for d in DEVICES if w.daemons[d] and w.daemons[d].poll() is None]
    for d in DEVICES:
        if d not in alive:
            rc = w.daemons[d].returncode if w.daemons[d] else None
            verdict["findings"].append({"oracle": "O3-daemon-died", "hard": True,
                                        "what": f"{d} daemon exited (rc {rc}) without being killed by the schedule"})
    seen = wait_signaling(w, alive, SETTLE_SIGNALING, allow_unreported=True)
    for d, (st, raw) in seen.items():
        if st == "down":
            verdict["findings"].append({"oracle": "O1-no-recovery", "hard": True,
                                        "what": f"{d} signaling not connected {SETTLE_SIGNALING:.0f}s after heal: {raw}"})
    for d in alive:
        if w.cap_status(d) is None:
            verdict["findings"].append({"oracle": "O3-unresponsive", "hard": True,
                                        "what": f"{d} daemon does not answer its control socket after heal"})
    post = []
    for st in [{"op": "exec", "src": "bravo", "dst": OWNER}, {"op": "exec", "src": "charlie", "dst": OWNER},
               {"op": "send", "src": OWNER, "dst": "bravo", "kib": 64},
               {"op": "send", "src": OWNER, "dst": "charlie", "kib": 64}]:
        r = run_op(w, st, "after-heal")
        if not r["ok"] and r["rc"] is not None:
            r2 = run_op(w, st, "after-heal-retry")
            post.append(r2)
            verdict["findings"].append({"oracle": "O1-first-try-after-heal", "hard": not r2["ok"],
                                        "what": f"{st['op']} {st['src']}->{st['dst']} failed after heal "
                                                f"(rc {r['rc']}: {r['stderr_tail'][-160:]}); retry ok={r2['ok']}"})
        post.append(r)
    verdict["ops"].extend(post)
    for r in post:
        verdict["findings"].extend(judge_op(r))
    # Quiet window, started AFTER the checks above so the CLI's own server
    # connections are not counted: only the daemons talk to the server now.
    syn0 = {d: w.syn_count(d) for d in DEVICES}
    time.sleep(STORM_WINDOW)
    for d in DEVICES:
        c = w.syn_count(d) - syn0[d]
        if c > STORM_MAX_CONNECTS:
            verdict["findings"].append({"oracle": "O5-reconnect-storm", "hard": True,
                                        "what": f"{d} opened {c} server connections in the post-heal window"})

    logs = w.all_daemon_logs()
    for d, text in logs.items():
        if "panicked at" in text:
            line = next(ln for ln in text.splitlines() if "panicked at" in ln)
            verdict["findings"].append({"oracle": "O4-daemon-panic", "hard": True, "what": f"{d}: {line[-240:]}"})
        stalls = [m.start() for m in re.finditer(r"event loop stalled", text)]
        if stalls and "event loop recovered" not in text[stalls[-1]:] and d in alive:
            verdict["findings"].append({"oracle": "O3-stalled-loop", "hard": True,
                                        "what": f"{d} logged an event-loop stall and never recovered or exited"})
    verdict["kinds"] = sorted(set().union(*(kinds_of(t) for t in logs.values())))
    verdict["hard"] = [f for f in verdict["findings"] if f["hard"]]
    verdict["elapsed_s"] = round(time.monotonic() - t0, 1)
    if verdict["hard"]:
        # Confirm and minimize replay the schedule and overwrite the daemon
        # logs. Keep the logs of THIS run, the one that failed.
        verdict["evidence_logs"] = {f"{d}-daemon.log": t for d, t in logs.items()}
        bl = w.work / "backend.log"
        if bl.exists():
            verdict["evidence_logs"]["backend.log"] = bl.read_text(errors="replace")[-400000:]
    record_run(w, verdict)
    return verdict


def record_run(w: "World", verdict: dict) -> None:
    """Every run leaves a record, clean or not: what was applied, whether it
    bit, every operation's exit code and latency, which rules fired. A clean
    record is the evidence of what was exercised."""
    if not getattr(w, "out", None):
        return
    runs = w.out / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    n = len(list(runs.glob("*.json")))
    rec = {k: verdict.get(k) for k in ("label", "schedule", "faults", "fault_windows", "ops", "findings", "elapsed_s",
                                       "unreported_signaling")}
    rec["kinds_count"] = len(verdict.get("kinds", []))
    safe = re.sub(r"[^\w.-]", "_", re.sub(r"\.json$", "", verdict["label"]))[:60]
    (runs / f"{n:04d}-{safe}.json").write_text(json.dumps(rec, indent=1, sort_keys=True))


def sig_state(w: World, d: str) -> tuple[str, object]:
    """('connected' | 'down' | 'unreported' | 'noanswer', raw signaling object).

    'unreported' means the daemon answered cap-status without a signaling
    object (some code paths, such as the no-self-heal baseline a canary
    selects, do not track it). It is never counted as recovered."""
    rep = w.cap_status(d)
    if rep is None:
        return "noanswer", None
    sig = rep.get("signaling")
    # The test-hooks no-self-heal path answers {"connected": false,
    # "state": "unknown"} while connected: it does not track the link.
    if not sig or sig.get("state") in (None, "unknown"):
        return "unreported", sig
    return ("connected" if sig.get("state") == "connected" else "down"), sig


def stale_links(w: World, gone: str, secs: float) -> list[dict]:
    """O10 (soft until tunlion documents a detection bound): after `gone` has
    been silent on every network for `secs`, a peer that still reports a warm
    link to it routes commands into a dead link (seen in production on
    2026-11-25: 'link still live; deferring drop' for 90 minutes)."""
    out = []
    for d in DEVICES:
        if d == gone:
            continue
        rep = w.cap_status(d) or {}
        for l in rep.get("links") or []:
            if l.get("name") == gone and l.get("warm"):
                out.append({"oracle": "O10-stale-link", "hard": False,
                            "what": f"{d} still reports a warm link to {gone} after {secs:.0f}s of total silence: {l}"})
    return out


def wait_signaling(w: World, devs: list[str], limit: float, allow_unreported: bool = False) -> dict:
    """Wait until every device is connected (or unreported, when allowed).
    Returns {device: (state, raw)} as last seen, for the caller to judge."""
    ok = {"connected", "unreported"} if allow_unreported else {"connected"}
    t0 = time.monotonic()
    seen = {}
    while True:
        seen = {d: sig_state(w, d) for d in devs}
        if all(st in ok for st, _ in seen.values()) or time.monotonic() - t0 >= limit:
            return seen
        time.sleep(1)


def finding_key(f: dict) -> str:
    """One bug, one report: oracle plus the device and op words, no numbers."""
    return f["oracle"] + "|" + re.sub(r"[\d.]+", "N", f["what"])[:80]


def save_finding(out: Path, verdict: dict, w: World, repro: str) -> Path:
    key = hashlib.sha1("\n".join(sorted(finding_key(f) for f in verdict["hard"])).encode()).hexdigest()[:10]
    d = out / "findings" / key
    d.mkdir(parents=True, exist_ok=True)
    (d / "schedule.json").write_text(json.dumps(verdict["schedule"], indent=2, sort_keys=True))
    v = {k: verdict[k] for k in ("label", "findings", "ops", "faults")}
    v["reproduced"] = repro
    (d / "verdict.json").write_text(json.dumps(v, indent=2, sort_keys=True))
    logs = d / "logs"
    logs.mkdir(exist_ok=True)
    # The failing run's own logs, captured when it was judged (confirm and
    # minimize runs since then have replaced the files on disk).
    for name, text in (verdict.get("evidence_logs") or {}).items():
        (logs / name).write_text(text)
    for i, o in enumerate(verdict.get("ops", [])):
        if not o.get("ok") and o.get("stderr_full"):
            (logs / f"op{i:02d}-{o['op']}-{o['src']}-{o['dst']}.stderr").write_text(o["stderr_full"])
    return d


def confirm(w: World, sched: dict, first: dict, tries: int = 2) -> str:
    want = {f["oracle"] for f in first["hard"]}
    hits = 1
    for i in range(tries):
        v = run_schedule(w, sched, f"confirm-{i}")
        if want & {f["oracle"] for f in v["hard"]}:
            hits += 1
    return f"{hits}/{tries + 1}"


def minimize(w: World, sched: dict, oracle_set: set, budget: int = 6) -> dict:
    """Drop fault steps one at a time while the same oracle still fires."""
    best = copy.deepcopy(sched)
    for st in [s for s in sched["steps"] if "fault" in s]:
        if budget <= 0:
            break
        cand = copy.deepcopy(best)
        cand["steps"] = [s for s in cand["steps"] if s != st]
        if not any("fault" in s for s in cand["steps"]):
            continue
        budget -= 1
        v = run_schedule(w, cand, "minimize")
        if oracle_set & {f["oracle"] for f in v["hard"]}:
            best = cand
    return best


# -------------------------------------------------------------- commands --

CANARY_SCHEDULE = {"version": 1, "seed": 0, "hooks": {},
                   "steps": [{"at": 2.0, "fault": "sig.reset", "target": "bravo", "dur": 10.0}]}


def cmd_canary(w: World, out: Path) -> int:
    """Arm A (healthy): must produce no hard finding. Arm B (self-heal
    disabled with TUNLION_TEST_NO_SIGNALING_RECONNECT on bravo): must produce
    O1-no-recovery for bravo. Either arm wrong means the instrument is."""
    a = run_schedule(w, copy.deepcopy(CANARY_SCHEDULE), "canary-healthy")
    sb = copy.deepcopy(CANARY_SCHEDULE)
    sb["hooks"] = {"bravo": {"TUNLION_TEST_NO_SIGNALING_RECONNECT": "1"}}
    b = run_schedule(w, sb, "canary-broken")
    (out / "canary.json").write_text(json.dumps(
        {arm: {k: v[k] for k in ("findings", "ops", "faults")} for arm, v in (("healthy", a), ("broken", b))},
        indent=2))
    caught = any(f["oracle"].startswith("O1") and "bravo" in f["what"] for f in b["hard"])
    bit = all(x.get("bit") for x in b["faults"])
    if a["hard"]:
        log(f"CANARY: healthy arm produced findings, the oracles are not trustworthy: {a['hard']}")
        save_finding(out, a, w, "canary-healthy-arm")
        return 4
    if not bit:
        log("CANARY: the signaling reset never bit (rule counter 0); the fault layer is broken")
        return 4
    if not caught:
        log(f"CANARY MISSED: a daemon with signaling self-heal disabled was not flagged: {b['findings']}")
        return 4
    # Hang arm: a command that really outlives its deadline must be killed and
    # classified as O2-hang. Proves deadline, kill and judgement end to end.
    hung = run_op(w, {"op": "exec", "src": "bravo", "dst": OWNER, "cmd": ["/bin/sleep", "20"], "deadline": 5.0},
                  "canary-hang")
    hang_found = [f["oracle"] for f in judge_op(hung)]
    if hung["rc"] is not None or "O2-hang" not in hang_found or hung["elapsed"] > 15:
        log(f"CANARY MISSED: the hang rule did not fire on a 20 s command with a 5 s deadline: {hung}")
        return 4
    log("canary: healthy arm clean, broken arm flagged, hang arm flagged. The instrument works.")
    return 0


def cmd_replay(w: World, out: Path, files: list[Path], repeat: int = 1) -> int:
    """Run each schedule `repeat` times. With repeat 1 a failure is confirmed
    once more; with repeat > 1 the failure RATE is the result (an
    intermittent bug and its fix are both measured as rates), and every
    failing repetition keeps its own evidence."""
    hard = 0
    rates = {}
    for f in files:
        sched = json.loads(f.read_text())
        fails = 0
        for i in range(repeat):
            log(f"replay {f.name}" + (f" ({i + 1}/{repeat})" if repeat > 1 else ""))
            v = run_schedule(w, sched, f.stem + (f"-r{i + 1}" if repeat > 1 else ""))
            if not v["hard"]:
                log("  clean")
                continue
            fails += 1
            repro = confirm(w, sched, v, tries=1) if repeat == 1 else f"repetition {i + 1}/{repeat}"
            d = save_finding(out, v, w, repro)
            log(f"  FINDING ({repro}) -> {d}: {[x['what'][:200] for x in v['hard']]}")
        rates[f.name] = f"{fails}/{repeat}"
        if repeat > 1:
            log(f"  {f.name}: failed {fails} of {repeat}")
        hard += 1 if fails else 0
    (out / "replay-rates.json").write_text(json.dumps(rates, indent=2))
    return 1 if hard else 0


def cmd_explore(w: World, out: Path, budget_s: float, seed: int, corpus: list[Path]) -> int:
    rng = random.Random(seed)
    queue = [json.loads(p.read_text()) for p in corpus]
    seen: set[str] = set()
    found: dict[str, Path] = {}
    runs = bites = refusals = 0
    t_end = time.monotonic() + budget_s
    while time.monotonic() < t_end:
        if queue and rng.random() < 0.8:
            sched = mutate(rng.choice(queue[-16:]), rng)
        else:
            sched = random_schedule(rng)
        if window_end(sched) + 200 > t_end - time.monotonic():
            break
        runs += 1
        try:
            v = run_schedule(w, sched, f"explore-{runs}")
            refusals = 0
        except Refused as e:
            # A baseline that fails proves nothing about the schedule; skip
            # it, but three in a row means the fixture itself is broken.
            if str(e).startswith("instrument"):
                raise
            refusals += 1
            log(f"  run {runs} refused: {e}")
            if refusals >= 3:
                raise
            continue
        bites += sum(1 for x in v["faults"] if x.get("bit"))
        new = set(v["kinds"]) - seen
        if new:
            seen |= new
            queue.append(sched)
            # Saved as it grows: a campaign stopped early keeps what it learned.
            grown = out / "corpus-grown"
            grown.mkdir(exist_ok=True)
            (grown / f"q{len(queue) - 1:03d}.json").write_text(json.dumps(sched, indent=2, sort_keys=True))
            log(f"  run {runs}: +{len(new)} new behaviours (total {len(seen)}), kept")
        if v["hard"]:
            key = "|".join(sorted({finding_key(f) for f in v["hard"]}))
            if key in found:
                continue
            repro = confirm(w, sched, v)
            small = minimize(w, sched, {f["oracle"] for f in v["hard"]})
            v["schedule"] = small
            found[key] = save_finding(out, v, w, repro)
            log(f"  FINDING ({repro}) -> {found[key]}")
    summary = {"runs": runs, "behaviours": len(seen), "faults_bit": bites,
               "findings": [str(p) for p in found.values()], "seed": seed}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    if runs and bites == 0:
        log("no fault bit in the whole campaign: the fault layer is not reaching the daemons")
        return 4
    return 1 if found else 0


def cmd_selftest() -> int:
    rng = random.Random(1)
    for _ in range(500):
        s = random_schedule(rng)
        for _ in range(5):
            s = mutate(s, rng)
        assert any("fault" in st for st in s["steps"]), s
        assert s["steps"] == sorted(s["steps"], key=lambda st: (st["at"], json.dumps(st, sort_keys=True)))
        for st in s["steps"]:
            if "fault" in st:
                assert st["fault"] in FAULTS and st["dur"] > 0
                if st["fault"] == "net.partition":
                    assert st["a"] != st["b"]
        json.loads(json.dumps(s))
    assert line_kind("2026-11-25T14:56:11Z tunlion: control socket at /tmp/x/a/control.sock") == \
        line_kind("2026-11-26T01:02:03Z tunlion: control socket at /tmp/y/b/control.sock")
    assert line_kind("peer 'bravo' reconnected after 3.2s") == line_kind("peer 'charlie' reconnected after 12s")
    assert line_kind("signaling reconnected") != line_kind("signaling link closed, reconnecting")
    assert judge_op({"op": "exec", "src": "b", "dst": "a", "phase": "x", "rc": None, "stderr_tail": ""})[0]["oracle"] == "O2-hang"
    assert judge_op({"op": "send", "src": "a", "dst": "b", "phase": "x", "rc": 0, "lie": True, "stderr_tail": ""})[0]["oracle"] == "O7-false-success"
    assert judge_op({"op": "exec", "src": "b", "dst": "a", "phase": "x", "rc": 6, "stderr_tail": ""})[0]["oracle"] == "O8-silent-failure"
    assert judge_op({"op": "exec", "src": "b", "dst": "a", "phase": "x", "rc": 6, "stderr_tail": "offline"}) == []
    blamed = {"op": "send", "src": "alpha", "dst": "bravo", "ok": False, "rc": 6, "t_start": 3.0, "t_end": 63.0,
              "dst_signaling_after": "connected",
              "stderr_tail": "Error: no peer connected within 60s: is 'bravo' online, with `tunlion up` running there?"}
    part = [{"step": {"fault": "net.partition", "a": "alpha", "b": "bravo"}, "start": 0.0, "end": 60.0}]
    assert judge_diagnosis(blamed, part)[0]["oracle"] == "O9-misdiagnosis"
    frozen = [{"step": {"fault": "proc.freeze", "target": "bravo"}, "start": 0.0, "end": 60.0}]
    assert judge_diagnosis(blamed, frozen) == []
    assert judge_diagnosis(dict(blamed, dst_signaling_after="down"), part) == []
    assert judge_diagnosis(dict(blamed, stderr_tail="connect timeout: couldn't reach 'bravo' in 45s"), part) == []
    old = [{"step": {"fault": "proc.kill", "target": "bravo"}, "start": 0.0, "end": 1.0}]
    assert judge_diagnosis(dict(blamed, t_start=10.0, t_end=40.0), old) == [], "slack: presence may lag a heal"
    assert judge_diagnosis(dict(blamed, t_start=70.0, t_end=80.0), old)[0]["oracle"] == "O9-misdiagnosis"
    fixed = dict(blamed, stderr_tail="no peer connected within 60s: 'bravo' is listed on the tunlion server, but no "
                 "connection to it came up: a firewall may block every path between you (direct UDP, and the relay), "
                 "or it went offline just now.")
    assert judge_diagnosis(fixed, part) == [], "naming the path is the correct diagnosis"
    for p in sorted((HERE / "corpus").glob("*.json")):
        s = json.loads(p.read_text())
        assert s.get("version") == 1 and s["steps"], p
        for st in s["steps"]:
            assert ("fault" in st) != ("op" in st), (p, st)
            if "fault" in st:
                assert st["fault"] in FAULTS, (p, st)
    print("selftest ok")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["canary", "replay", "explore", "selftest"])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--bin", type=Path, default=REPO / "target" / "release" / "tunlion")
    ap.add_argument("--out", type=Path, default=Path("chaos-out"))
    ap.add_argument("--python", default=os.environ.get("TUNLION_TEST_VENV", sys.executable))
    ap.add_argument("--budget-min", type=float, default=30.0)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    ap.add_argument("--repeat", type=int, default=1, help="replay: run each schedule N times and report the rate")
    ap.add_argument("--skip-canary", action="store_true", help="local debugging only; CI never passes this")
    a = ap.parse_args()
    if a.command == "selftest":
        return cmd_selftest()

    a.out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="chz.", dir="/tmp"))
    w = World(a.bin.resolve(), work, a.python)
    w.out = a.out
    try:
        w.preconditions()
        log(f"binary {w.bin} sha256 {w.bin_sha[:16]} (asserted unchanged before every run)")
        w.net_up()
        w.setup()
        if a.command == "canary" or not a.skip_canary:
            rc = cmd_canary(w, a.out)
            if rc or a.command == "canary":
                return rc
        corpus = []
        for f in a.files or [HERE / "corpus"]:
            corpus += sorted(f.glob("*.json")) if f.is_dir() else [f]
        if not corpus:
            raise Refused("no schedules to run")
        if a.command == "replay":
            return cmd_replay(w, a.out, corpus, a.repeat)
        return cmd_explore(w, a.out, a.budget_min * 60, a.seed, corpus)
    except Refused as e:
        log(f"REFUSED: {e}")
        return 3
    except Exception:
        # Exit 1 means "tunlion has a bug". A crash in this file must never
        # be read that way.
        import traceback
        traceback.print_exc()
        log("HARNESS ERROR: chaos.py itself failed; this is not a tunlion finding")
        return 5
    finally:
        try:
            shutil.copytree(work / "dev", a.out / "last-run-dev", dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns("*.sock", "home", "snapshot"))
        except Exception:
            pass
        w.teardown()


if __name__ == "__main__":
    sys.exit(main())
