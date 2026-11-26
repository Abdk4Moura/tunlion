#!/usr/bin/env python3
"""Stateful chaos fuzzer for tunlion (stage 1: real binaries, real kernel).

Three real daemons (alpha = owner, bravo and charlie = delegates enrolled with
a shell grant) each live in their own network namespace, routed through the
root namespace where the signaling backend runs. A SCHEDULE says which faults
to apply when (network impairment, partitions, signaling blackhole or reset,
SIGSTOP, SIGKILL and restart, backend restart) and which user operations to run
meanwhile (exec, send, reach, and `visit`: a transient device that enrolls,
lives briefly and vanishes). After every fault heals, ORACLES judge the run.

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
  hookcheck each test-hook "fault" alone must be clean (validates the list)
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

DEVICES = ["alpha", "bravo", "charlie"]          # index i -> subnet 10.<net>.(i+1).0/24
OWNER = "alpha"
DELEGATES = ["bravo", "charlie"]

# Several independent WORLDS run on one machine at once (the daemons are idle
# most of a run, so one world leaves the machine mostly idle). Everything
# global to a world is derived from its slot k: namespaces chz<k>_<dev>,
# veths chz<k>r<i>/chz<k>n<i>, subnet 10.(90+k).0.0/16, backend port
# 8155+k, iptables chains CHZ<k>/CHZ<k>_IN/CHZ<k>_OUT, the slot lock
# /run/tunlion-chaos.slot<k>.lock and the work dir /tmp/chz.w<k>.*. A world
# only ever reaps and tears down its own slot. 10.89 is skipped: the
# single-world version used it, and a crashed old campaign may have left
# rules for it.
BASE_PORT = 8155
MAX_SLOTS = 16

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
# The quiet window ends early when, STORM_QUIET_EXIT seconds in, no device has
# opened a single server connection. To be missed, a storm must stay silent
# for those first seconds and then fit 9+ connects into the rest: any storm
# steady enough to make 9 connects in 30 s (a gap under 3.4 s) shows up in
# the first 10 s. A device that connects at all gets the full 30 s window and
# the unchanged threshold. And a window already over the threshold is a
# finding at once (the counters only grow).
STORM_QUIET_EXIT = 10.0
LOOP_STALL_GRACE = 150.0    # a logged stall must be followed by recovery or exit
STALE_LINK_AFTER = 90.0     # O10: a peer silent this long should not still look warm

# VISITORS: transient devices that enroll with a reusable runner invitation,
# run `up` briefly and vanish with no goodbye (a lease worker whose VM is
# destroyed). The owner used to keep re-dialling every departed one forever and,
# once those dead links filled its link table, refused new enrollments
# (production, 2026-11-26; fix #735). A visitor is the op {"op": "visit",
# "src": "alpha", "dst": "vis<i>", "stay": s, "act": "none"|"send"}. Its device
# gets its own namespace at 10.<net>.(VISITOR_BASE+i).0/24 for its life only.
VISITOR_BASE = 10
MAX_VISITORS = 200
VISIT_STAY_MAX = 120.0
VISIT_JOIN_DEADLINE = 90.0  # the CLI gives up on an enrollment after 60 s itself
ENROLL_BOUND = 60.0         # O13: a visitor that enrolls slower than this is starved
VISIT_SEEN_DEADLINE = 45.0  # join done -> the owner must have answered the visitor
# O12: the stuck-retry ladder rebuilds a link at most MAX_ATTEMPTS times
# (crates/filament-peerloop/src/limits.rs) and then drops it. A departed peer
# established more often than that inside REDIAL_QUIET seconds that start
# REDIAL_GRACE after the last visitor left is being re-dialled without bound.
# A zombie was rebuilt about every 16 s, so the window holds 9 of them.
REDIAL_MAX = 5
REDIAL_GRACE = 5.0
REDIAL_QUIET = 150.0
# A whole visitor's life: join, being seen, one send, its stay, its removal.
OP_DEADLINE["visit"] = VISIT_JOIN_DEADLINE + VISIT_SEEN_DEADLINE + OP_DEADLINE["send"] + VISIT_STAY_MAX + 30.0

# CHAOS: device to device (FORWARD). CHAOS_IN: device to the backend (INPUT).
# CHAOS_OUT: the backend's replies to a device (OUTPUT), needed to isolate it.
# These are ROLE names; World.chain() maps a role to the world's own chain.
CHAINS = [("CHAOS", "FORWARD"), ("CHAOS_IN", "INPUT"), ("CHAOS_OUT", "OUTPUT")]

FAULTS = ["net.impair", "net.partition", "net.isolate", "sig.blackhole", "sig.reset",
          "proc.freeze", "proc.kill", "server.down"]
OPS = ["exec", "send", "reach", "status", "doctor"]

# Env hooks (test-hooks builds) that add INTERNAL faults with a designed
# recovery. Every entry must pass `chaos.py hookcheck` (the hook alone, no
# network fault, must be clean). TUNLION_TEST_DROP_FILE_END was here and
# produced a false finding: its recovery (the completion sweep) only runs once
# the sender's link is gone, and a confirmed send keeps the link up, so with
# the hook on every send fails by construction. The fuzzer may switch them on per daemon. Hooks that disable a
# recovery (NO_SIGNALING_RECONNECT, NO_DIRECT...) are not here: those are
# canaries, not faults.
RECOVERABLE_HOOKS = {
    "TUNLION_TEST_DIRECT_FLAKY": ["1"],
    # 1500 ms is the delay gate T3b uses to make a code transfer start on the
    # relay and switch to a direct path mid-stream (the #746 corruption).
    "TUNLION_TEST_DIRECT_DELAY_MS": ["500", "1500", "3000"],
    "TUNLION_TEST_ESTABLISH_DELAY_MS": ["500", "4000"],
    "TUNLION_TEST_DROP_PEER_LEFT": ["1"],
    "TUNLION_TEST_CORRUPT_ONCE": ["1"],
}


# Files a daemon creates while it runs. They are state of THAT process, not of
# the enrolled device, and a socket cannot be copied at all.
RUNTIME_FILES = shutil.ignore_patterns("*.sock", "up.pid", "up.exe", "up.ready", "up.inbox", "up.lock", "*.lock")


_ctx = threading.local()
_print_lock = threading.Lock()


def log(msg: str) -> None:
    w = getattr(_ctx, "world", None)
    tag = f" w{w}" if w is not None else ""
    with _print_lock:
        print(f"[chaos {time.strftime('%H:%M:%S')}{tag}] {msg}", flush=True)


class Aborted(Exception):
    """Another world stopped the campaign (canary failed, harness error)."""


# iptables from several worlds at once: -w waits for the xtables lock, and
# one in-process lock keeps nft transactions from racing each other.
_ipt_lock = threading.Lock()


def ipt(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    with _ipt_lock:
        return sh(["iptables", "-w", "10", *args], check=check, timeout=60)


class Refused(Exception):
    """A precondition is unmet; no result may be reported (exit 3)."""


def sh(cmd: list[str], check: bool = True, timeout: float = 30.0) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} -> rc={r.returncode}: {r.stderr.strip()[:300]}")
    return r


def visitor_no(name: str) -> int | None:
    m = re.fullmatch(r"vis(\d{1,3})", name)
    return int(m.group(1)) if m and 1 <= int(m.group(1)) <= MAX_VISITORS else None


def dev_index(name: str) -> int:
    if name in DEVICES:
        return DEVICES.index(name) + 1
    i = visitor_no(name)
    if i is None:
        raise ValueError(f"not a device or visitor name: {name}")
    return VISITOR_BASE + i


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
        op = {"op": "send", "at": at, "src": OWNER, "dst": rng.choice(DELEGATES),
              "kib": rng.choice([4, 256, 4096])}
        if rng.random() < 0.3:
            op["via"] = "stdout"
        return op
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


def check_visits(s: dict) -> None:
    """A visit step names a visitor slot of its own: two steps sharing a name
    would share one namespace and one config."""
    names = [st["dst"] for st in s["steps"] if st.get("op") == "visit"]
    for st in s["steps"]:
        if st.get("op") == "visit":
            if st.get("src") != OWNER or visitor_no(st["dst"]) is None:
                raise ValueError(f"visit must be from {OWNER} to vis<1..{MAX_VISITORS}>: {st}")
            if not 0 <= float(st.get("stay", 5.0)) <= VISIT_STAY_MAX or st.get("act", "none") not in ("none", "send"):
                raise ValueError(f"visit stay must be 0..{VISIT_STAY_MAX:.0f}s and act none|send: {st}")
    if len(names) != len(set(names)):
        raise ValueError(f"visitor names repeat in one schedule: {names}")
    if names and max(visitor_no(n) for n in names) >= MAX_VISITORS:
        raise ValueError(f"vis{MAX_VISITORS} is reserved for the final probe visitor")


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

    def __init__(self, binary: Path, work: Path, py: str, slot: int = 0, lock=None):
        self.bin = binary
        self.work = work
        self.py = py
        self.k = slot
        self._lock = lock            # the slot lock, held for the world's life
        self.port = BASE_PORT + slot
        self.net = 90 + slot
        self.subnet = f"10.{self.net}.0.0/16"
        self.stop: threading.Event = threading.Event()
        self.uid, self.gid = self._pick_user()
        self.backend: subprocess.Popen | None = None
        self.server_down = 0          # overlapping server.down faults now active
        self.daemons: dict[str, subprocess.Popen | None] = {d: None for d in DEVICES}
        self.hooks: dict[str, dict] = {}
        self.incarnation: dict[str, int] = {d: 0 for d in DEVICES}
        self.bin_sha = self._sha(binary)
        self.can_netem = False
        self.snapshot = work / "snapshot"
        self.visitors: dict[str, subprocess.Popen] = {}   # visitor name -> its `up`
        self.visit_inv: Path | None = None               # this run's reusable invitation
        self.visitor_logs: dict[str, str] = {}           # this run's departed visitors' logs

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

    # -- names of this world's slot ----------------------------------------
    def dev_ip(self, d: str) -> str:
        return f"10.{self.net}.{dev_index(d)}.1"

    def gw_ip(self, d: str) -> str:
        return f"10.{self.net}.{dev_index(d)}.254"

    def ns(self, d: str) -> str:
        return f"chz{self.k}_{d}"

    def veth_root(self, d: str) -> str:
        return f"chz{self.k}r{dev_index(d)}"

    def veth_dev(self, d: str) -> str:
        return f"chz{self.k}n{dev_index(d)}"

    def chain(self, role: str) -> str:
        return {"CHAOS": f"CHZ{self.k}", "CHAOS_IN": f"CHZ{self.k}_IN", "CHAOS_OUT": f"CHZ{self.k}_OUT"}[role]

    def preconditions(self) -> None:
        if os.geteuid() != 0:
            raise Refused("must run as root (network namespaces, tc, iptables)")
        if self._lock is None:
            raise Refused("world started without its slot lock")
        # The world's /16 must not be in use on this machine.
        r = sh(["ip", "-4", "-o", "addr", "show"], check=False)
        for ln in r.stdout.splitlines():
            if f" 10.{self.net}." in ln and "chz" not in ln:
                raise Refused(f"10.{self.net}.0.0/16 already in use here: {ln.strip()[:120]}")
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
        """Kill what a previous campaign left behind IN THIS SLOT (we hold its
        lock, so whatever uses it is dead weight): processes inside the
        slot's namespaces, processes naming an older /tmp/chz.w<k>.* work dir
        or this slot's server URL, and anything on the slot's port (a stale
        backend would answer health checks with another campaign's state).
        Other slots are never touched: another campaign may own them."""
        mine = str(self.work)
        victims = set()
        for d in DEVICES + self.visitor_names_present():
            r = sh(["ip", "netns", "pids", self.ns(d)], check=False)
            victims |= {int(x) for x in r.stdout.split() if x.isdigit()}
        marks = [f"/tmp/chz.w{self.k}.", f"http://10.{self.net}."]
        for p in Path("/proc").iterdir():
            if not p.name.isdigit() or int(p.name) == os.getpid():
                continue
            try:
                cmd = (p / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
            except OSError:
                continue
            if any(m in cmd for m in marks) and mine not in cmd and "chaos.py" not in cmd:
                victims.add(int(p.name))
        victims.discard(os.getpid())
        r = sh(["ss", "-ltnpH", f"sport = :{self.port}"], check=False)
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
            n, r, v = self.ns(d), self.veth_root(d), self.veth_dev(d)
            sh(["ip", "netns", "add", n])
            sh(["ip", "-n", n, "link", "set", "lo", "up"])
            sh(["ip", "link", "add", r, "type", "veth", "peer", "name", v])
            sh(["ip", "link", "set", v, "netns", n])
            sh(["ip", "addr", "add", f"{self.gw_ip(d)}/24", "dev", r])
            sh(["ip", "link", "set", r, "up"])
            sh(["ip", "-n", n, "addr", "add", f"{self.dev_ip(d)}/24", "dev", v])
            sh(["ip", "-n", n, "link", "set", v, "up"])
            sh(["ip", "-n", n, "route", "add", "default", "via", self.gw_ip(d)])
            # DNS inside a world fails at once, as on a machine with no
            # network. Without this the host's resolv.conf applies, and on
            # runners that list a forwarded resolver (Azure's 168.63.129.16)
            # every lookup is silently dropped: each daemon start then blocked
            # 24 s (measured), every run paid it, and a daemon restarted by
            # proc.kill came back 24 s late, so the same schedule meant a
            # different thing on different machines. `ip netns exec` binds
            # this file over /etc/resolv.conf.
            etc = Path("/etc/netns") / n
            etc.mkdir(parents=True, exist_ok=True)
            (etc / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        # CHAOS: device-to-device forwarding (partitions go first, then accept;
        # runners with docker default FORWARD to DROP). CHAOS_IN: device to
        # backend; a counting rule per device (SYNs = connection attempts,
        # measured OUTSIDE the daemon) precedes the fault rules.
        for role, hook in CHAINS:
            ipt(["-N", self.chain(role)])
            ipt(["-I", hook, "1", "-j", self.chain(role)])
        ipt(["-A", self.chain("CHAOS"), "-s", self.subnet, "-d", self.subnet, "-j", "ACCEPT"])
        for d in DEVICES:
            ipt(["-A", self.chain("CHAOS_IN"), "-s", self.dev_ip(d), "-p", "tcp", "--dport", str(self.port),
                 "--syn", "-m", "comment", "--comment", f"syn-{d}"])
        # Prove netem exists before any schedule relies on it.
        probe = self.veth_root(DEVICES[0])
        r = sh(["tc", "qdisc", "add", "dev", probe, "root", "netem", "delay", "1ms"], check=False)
        self.can_netem = r.returncode == 0
        if self.can_netem:
            sh(["tc", "qdisc", "del", "dev", probe, "root"], check=False)
        else:
            log(f"netem unavailable ({r.stderr.strip()[:120]}); net.impair is DISABLED for this run")

    def net_down(self) -> None:
        for role, hook in CHAINS:
            c = self.chain(role)
            while ipt(["-D", hook, "-j", c], check=False).returncode == 0:
                pass
            ipt(["-F", c], check=False)
            ipt(["-X", c], check=False)
        for d in DEVICES:
            sh(["ip", "netns", "del", self.ns(d)], check=False)
            sh(["ip", "link", "del", self.veth_root(d)], check=False)
            shutil.rmtree(Path("/etc/netns") / self.ns(d), ignore_errors=True)
        for v in self.visitor_names_present():
            self.visitor_remove(v)
        # Stray visitor veths and the blackholes left where visitors were.
        r = sh(["ip", "-o", "link", "show"], check=False)
        for m in re.finditer(rf"^\d+: (chz{self.k}r(\d+))[@:]", r.stdout, re.M):
            if int(m.group(2)) > VISITOR_BASE:
                sh(["ip", "link", "del", m.group(1)], check=False)
        r = sh(["ip", "route", "show", "type", "blackhole"], check=False)
        for m in re.finditer(rf"^blackhole (10\.{self.net}\.\d+\.0/24)", r.stdout, re.M):
            sh(["ip", "route", "del", "blackhole", m.group(1)], check=False)

    def syn_counts(self) -> dict[str, int]:
        """Every device's SYN counter, from one listing."""
        out = ipt(["-nvxL", self.chain("CHAOS_IN")]).stdout
        got = {}
        for d in DEVICES:
            for ln in out.splitlines():
                if f"syn-{d} " in ln + " ":
                    got[d] = int(ln.split()[0])
                    break
            else:
                raise RuntimeError(f"counting rule for {d} missing")
        return got

    # -- backend ------------------------------------------------------------
    def backend_start(self) -> None:
        if self.backend and self.backend.poll() is None:
            raise RuntimeError("backend_start with a backend already running (it would be orphaned)")
        env = dict(os.environ, PORT=str(self.port), FIL_ASYNC_MODE="eventlet", FIL_SELF_MONKEYPATCH="1",
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
            with socket.create_connection(("127.0.0.1", self.port), timeout=1) as s:
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
        return f"http://{self.gw_ip(d)}:{self.port}"

    def env_for(self, d: str, extra: dict | None = None) -> dict:
        c = self.cfg(d)
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(c / "home"),
               "XDG_CONFIG_HOME": str(c / "home" / ".config"), "XDG_RUNTIME_DIR": str(c / "run"),
               "TUNLION_CONFIG_DIR": str(c / "cfg"), "TUNLION_L2": "1", "TUNLION_NO_UPDATE_CHECK": "1",
               "LANG": "C.UTF-8", "NO_COLOR": "1"}
        env.update(extra or {})
        return env

    def as_dev(self, d: str, args: list[str]) -> list[str]:
        return ["ip", "netns", "exec", self.ns(d), "setpriv", f"--reuid={self.uid}", f"--regid={self.gid}",
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

    # -- visitors -----------------------------------------------------------
    def visitor_names_present(self) -> list[str]:
        """Visitor namespaces of THIS slot that exist now."""
        r = sh(["ip", "netns", "list"], check=False)
        pre = f"chz{self.k}_"
        out = []
        for ln in r.stdout.splitlines():
            n = (ln.split() or [""])[0]
            if n.startswith(pre) and visitor_no(n[len(pre):]) is not None:
                out.append(n[len(pre):])
        return out

    def visitor_subnet(self, v: str) -> str:
        return f"10.{self.net}.{dev_index(v)}.0/24"

    def visitor_up(self, v: str) -> None:
        """A fresh machine: its own namespace, address and config, nothing
        left from a visitor of the same name in an earlier run."""
        self.visitor_remove(v)
        sh(["ip", "route", "del", "blackhole", self.visitor_subnet(v)], check=False)
        n, r, dv = self.ns(v), self.veth_root(v), self.veth_dev(v)
        sh(["ip", "netns", "add", n])
        sh(["ip", "-n", n, "link", "set", "lo", "up"])
        sh(["ip", "link", "add", r, "type", "veth", "peer", "name", dv])
        sh(["ip", "link", "set", dv, "netns", n])
        sh(["ip", "addr", "add", f"{self.gw_ip(v)}/24", "dev", r])
        sh(["ip", "link", "set", r, "up"])
        sh(["ip", "-n", n, "addr", "add", f"{self.dev_ip(v)}/24", "dev", dv])
        sh(["ip", "-n", n, "link", "set", dv, "up"])
        sh(["ip", "-n", n, "route", "add", "default", "via", self.gw_ip(v)])
        etc = Path("/etc/netns") / n
        etc.mkdir(parents=True, exist_ok=True)
        (etc / "resolv.conf").write_text("nameserver 127.0.0.1\noptions timeout:1 attempts:1\n")
        c = self.cfg(v)
        shutil.rmtree(c, ignore_errors=True)
        for sub in ["cfg", "home/.config", "run", "drop", "files"]:
            (c / sub).mkdir(parents=True, exist_ok=True)
        os.chmod(c / "run", 0o700)
        subprocess.run(["chown", "-R", f"{self.uid}:{self.gid}", str(c)], check=True)

    def visitor_daemon_start(self, v: str) -> None:
        logf = open(self.cfg(v) / "daemon.1.log", "ab")
        self.visitors[v] = subprocess.Popen(self.as_dev(v, ["up", "--dir", str(self.cfg(v) / "drop")]),
                                            env=self.env_for(v), stdout=logf, stderr=subprocess.STDOUT,
                                            stdin=subprocess.DEVNULL, start_new_session=True)

    def visitor_vanish(self, v: str) -> None:
        """The machine is destroyed with no goodbye. Its traffic is dropped
        FIRST, so not even the FIN of a killed socket leaves (killing a
        process closes its sockets gracefully; a destroyed VM sends nothing),
        then every process in it dies and its namespace goes. Its subnet is
        blackholed so packets to it vanish silently, as they do towards a
        destroyed machine, instead of following the default route out."""
        ip = self.dev_ip(v)
        tag = f"chz-gone-{v}"
        C, C_IN, C_OUT = self.chain("CHAOS"), self.chain("CHAOS_IN"), self.chain("CHAOS_OUT")
        rules = [(C, ["-s", ip]), (C, ["-d", ip]), (C_IN, ["-s", ip]), (C_OUT, ["-d", ip])]
        for chain, r in rules:
            ipt(["-I", chain, "1", *r, "-m", "comment", "--comment", tag, "-j", "DROP"])
        try:
            self.visitor_remove(v)
            sh(["ip", "route", "replace", "blackhole", self.visitor_subnet(v)])
        finally:
            for chain, r in rules:
                ipt(["-D", chain, *r, "-m", "comment", "--comment", tag, "-j", "DROP"], check=False)

    def visitor_remove(self, v: str) -> None:
        p = self.visitors.pop(v, None)
        r = sh(["ip", "netns", "pids", self.ns(v)], check=False)
        for pid in {int(x) for x in r.stdout.split() if x.isdigit()} | ({p.pid} if p else set()):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if p:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                pass
        sh(["ip", "link", "del", self.veth_root(v)], check=False)
        sh(["ip", "netns", "del", self.ns(v)], check=False)
        shutil.rmtree(Path("/etc/netns") / self.ns(v), ignore_errors=True)

    def mint_visitor_invitation(self, uses: int) -> None:
        """One reusable runner invitation per run, as a lease pool uses one
        for every worker it brings up (`add --for runner --reuse N`)."""
        inv = self.cfg(OWNER) / "files" / f"visitors-{time.time_ns()}.inv"
        rc, out, err, _ = self.cli(OWNER, ["add", "--for", "runner", "--name", "visitor", "--reuse", str(uses),
                                           "--out", str(inv), "--yes", "--no-interactive"], 60)
        if rc != 0 or not inv.exists():
            raise Refused(f"instrument: visitor invitation not minted rc={rc}: {err.strip()[-300:]}")
        self.visit_inv = inv

    def list_warm(self, d: str, timeout: float = 3.0) -> list[dict] | None:
        try:
            s = socket.socket(socket.AF_UNIX)
            s.settimeout(timeout)
            s.connect(str(self.cfg(d) / "cfg" / "control.sock"))
            s.sendall(b'{"op":"list-warm"}\n')
            buf = b""
            while not buf.endswith(b"\n"):
                c = s.recv(65536)
                if not c:
                    break
                buf += c
            s.close()
            return json.loads(buf).get("links") or []
        except (OSError, ValueError, AttributeError):
            return None

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
        for v in self.visitor_names_present():
            self.visitor_remove(v)
        self.visit_inv = None
        self.server_down = 0
        if not self.backend_healthy():
            self.backend_stop()
            self.backend_start()
        # Exactly one server per world: an extra listener on the port (the
        # backend uses SO_REUSEPORT) would take part of the connections.
        r = sh(["ss", "-ltnpH", f"sport = :{self.port}"], check=False)
        extra = {int(x) for x in re.findall(r"pid=(\d+)", r.stdout)} - {self.backend.pid}
        if extra:
            raise Refused(f"instrument: {len(extra)} extra server(s) on port {self.port}: {sorted(extra)}")
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
    out = ipt(["-nvxL", chain]).stdout
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
    C, C_IN, C_OUT = w.chain("CHAOS"), w.chain("CHAOS_IN"), w.chain("CHAOS_OUT")
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
        devs = [(None, w.veth_root(st["target"])), (w.ns(st["target"]), w.veth_dev(st["target"]))]

        def tc(n, *args):
            return sh((["ip", "netns", "exec", n] if n else []) + ["tc", *args], check=False)
        # One netem qdisc per device, but impairments on the same device can
        # overlap. Each holds a place on a per-device stack: the newest active
        # spec is installed, and healing one re-installs what is still active
        # (or removes the qdisc when nothing is). Without this, the first heal
        # deleted the qdisc the other still relied on, and the second then
        # refused the whole campaign as "fault mechanism absent" (2026-11-26,
        # after 270 runs).
        stacks = w.__dict__.setdefault("netem_stacks", {})
        stack = stacks.setdefault(st["target"], [])
        token = object()
        stack.append((token, spec))

        def install(top):
            for n, dv in devs:
                tc(n, "qdisc", "replace", "dev", dv, "root", "netem", *top)
        install(spec)

        def heal():
            stack[:] = [(t, sp) for t, sp in stack if t is not token]
            if stack:
                install(stack[-1][1])
            else:
                for n, dv in devs:
                    tc(n, "qdisc", "del", "dev", dv, "root")

        def present():
            mine = any(t is token for t, _ in stack)
            return mine and all("netem" in tc(n, "qdisc", "show", "dev", dv).stdout for n, dv in devs)

        def bit():
            s = "".join(tc(n, "-s", "qdisc", "show", "dev", dv).stdout for n, dv in devs)
            sent = sum(int(x) for x in re.findall(r"Sent \d+ bytes (\d+) pkt", s))
            return sent > 0
        return Applied(st, heal, present, bit)

    if k == "net.partition":
        a, b = st["a"], st["b"]
        proto = [] if st.get("proto") == "all" else ["-p", "udp"]
        rules = [["-s", w.dev_ip(a), "-d", w.dev_ip(b)] + proto, ["-s", w.dev_ip(b), "-d", w.dev_ip(a)] + proto]
        for r in rules:
            ipt(["-I", C, "1", *r, "-m", "comment", "--comment", tag, "-j", "DROP"])

        def heal():
            for r in rules:
                ipt(["-D", C, *r, "-m", "comment", "--comment", tag, "-j", "DROP"], check=False)
        return Applied(st, heal, lambda: _ipt_counter(C, tag) >= 0,
                       lambda: _ipt_counter(C, tag) > 0)

    if k == "net.isolate":
        # The machine drops off every network at once (lid closed, Wi-Fi
        # gone): nothing in or out, to peers or to the server, no close sent.
        ip = w.dev_ip(st["target"])
        rules = [(C, ["-s", ip]), (C, ["-d", ip]), (C_IN, ["-s", ip]), (C_OUT, ["-d", ip])]
        for chain, r in rules:
            ipt(["-I", chain, "1", *r, "-m", "comment", "--comment", tag, "-j", "DROP"])

        def heal():
            for chain, r in rules:
                ipt(["-D", chain, *r, "-m", "comment", "--comment", tag, "-j", "DROP"], check=False)

        def present():
            return all(_ipt_counter(c, tag) >= 0 for c in (C, C_IN, C_OUT))
        return Applied(st, heal, present,
                       lambda: sum(max(0, _ipt_counter(c, tag)) for c in (C, C_IN, C_OUT)) > 0)

    if k in ("sig.blackhole", "sig.reset"):
        d = st["target"]
        target = ["-j", "DROP"] if k == "sig.blackhole" else ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"]
        rule = ["-s", w.dev_ip(d), "-p", "tcp", "--dport", str(w.port), "-m", "comment", "--comment", tag]
        full = rule + (target[2:] if k == "sig.reset" else target)
        # Insert after the counting rules (1..3), so attempts are still counted.
        ipt(["-I", C_IN, str(len(DEVICES) + 1), *full])
        killed = 0
        if k == "sig.reset":
            # A rule only bites when a packet crosses it, and an idle signaling
            # socket can be silent for a whole ping interval (25 s). Abort the
            # live connections from the server side too (tcp_abort sends RST),
            # so the reset happens now and is provable.
            r = sh(["ss", "-K", "-tn", "dst", w.dev_ip(d), "sport", "=", f":{w.port}"], check=False)
            killed = max(0, len([ln for ln in r.stdout.splitlines() if "ESTAB" in ln or w.dev_ip(d) in ln]))

        def heal():
            ipt(["-D", C_IN, *full], check=False)
        return Applied(st, heal, lambda: _ipt_counter(C_IN, tag) >= 0,
                       lambda: killed > 0 or _ipt_counter(C_IN, tag) > 0)

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
        # Overlapping server.down steps: the server stays down until the LAST
        # one heals. Starting one backend per heal used to orphan the first
        # (the attribute was overwritten); the backend binds with
        # SO_REUSEPORT, so the orphan kept serving half the connections and
        # the world's daemons split across two servers that never see each
        # other (false refusals, and false findings of any kind).
        w.server_down += 1
        w.backend_stop()

        def heal():
            w.server_down -= 1
            if w.server_down == 0:
                w.backend_start()
        return Applied(st, heal, lambda: not w.backend_healthy() or True, lambda: True)
    raise ValueError(k)


# -------------------------------------------------------------------- ops --

def run_visit(w: World, st: dict, phase: str) -> dict:
    """One visitor's life: a fresh machine joins with the run's reusable
    runner invitation, runs `up`, proves the owner answers it (`reach` the
    owner until it does), optionally sends one file, stays `stay` seconds and
    vanishes with no goodbye. Never raises: a broken mechanism is recorded as
    `mech_error` and judged (refused) with the other visitors."""
    v = st["dst"]
    res = {"op": "visit", "src": st["src"], "dst": v, "phase": phase, "at": st.get("at"),
           "deadline": OP_DEADLINE["visit"], "rc": None, "ok": False, "lie": False, "joined": False,
           "seen": False, "m_start": time.monotonic(), "m_engaged": None, "m_gone": None,
           "stderr_tail": "", "stdout_tail": "", "mech_error": None}
    try:
        w.visitor_up(v)
        if w.visit_inv is None:
            raise RuntimeError("no visitor invitation was minted for this run")
        inv = w.cfg(v) / "files" / "inv.txt"
        shutil.copy(w.visit_inv, inv)
        os.chown(inv, w.uid, w.gid)
    except Exception as e:
        res["mech_error"] = f"visitor {v} could not be set up: {e}"
        w.visitor_remove(v)
        res["m_gone"] = time.monotonic()
        return res
    try:
        rc, out, err, el = w.cli(v, ["join", "--invite-file", str(inv), "--name", v, "--no-interactive"],
                                 VISIT_JOIN_DEADLINE)
        res.update(rc=rc, join_s=round(el, 2), joined=rc == 0)
        res["stderr_tail"] = (err or "").strip()[-400:]
        res["stderr_full"] = (err or "").strip()[-20000:]
        res["stdout_tail"] = (out or "").strip()[-200:]
        if rc != 0:
            return res
        w.visitor_daemon_start(v)
        t_seen = time.monotonic() + VISIT_SEEN_DEADLINE
        tries = []
        while time.monotonic() < t_seen:
            r_rc, _, r_err, r_el = w.cli(v, ["reach", OWNER], min(20.0, max(1.0, t_seen - time.monotonic())))
            tries.append({"rc": r_rc, "elapsed": round(r_el, 2), "stderr_tail": (r_err or "").strip()[-200:]})
            if r_rc == 0:
                res["seen"] = True
                res["m_engaged"] = time.monotonic()
                break
            p = w.visitors.get(v)
            if p is None or p.poll() is not None:
                break
            time.sleep(1.0)
        res["reach"] = tries[-6:]
        res["ok"] = res["seen"]
        if not res["seen"]:
            res["stderr_tail"] = "visitor joined but the owner never answered it: " + \
                (tries[-1]["stderr_tail"] if tries else "no reach attempt")
            return res
        if st.get("act") == "send":
            a = run_op(w, {"op": "send", "src": v, "dst": OWNER, "kib": 16}, phase)
            res["act"] = {k: a.get(k) for k in ("rc", "ok", "lie", "elapsed", "stderr_tail")}
        time.sleep(max(0.0, min(float(st.get("stay", 5.0)), VISIT_STAY_MAX)))
        return res
    finally:
        p = w.visitors.get(v)
        res["daemon_rc_before_vanish"] = None if p is None else p.poll()
        logf = w.cfg(v) / "daemon.1.log"
        try:
            w.visitor_vanish(v)
        except Exception as e:
            res["mech_error"] = f"visitor {v} could not be removed: {e}"
        res["m_gone"] = time.monotonic()
        res["gone_wall"] = time.time()
        if logf.exists():
            res["daemon_log"] = logf.read_text(errors="replace")[-200000:]


# A send whose receiver writes to stdout: `send --word` on src, a one-shot
# `receive <code> -y -o -` on dst, its stdout read slowly so the pipe fills (the
# shape of gate T3). Stdout cannot be rewound, so the oracle is about what the
# reader got: either end exiting 0 while those bytes are not the source is O7.
STDOUT_WORD = "gigantic-element"
STDOUT_CODE = re.compile(rb"gigantic-element-[0-9]{3,5}", re.I)


def stdout_send_verdict(src: bytes, got: bytes, send_rc: int | None, recv_rc: int | None) -> tuple[bool, bool]:
    """(ok, lie) for a send to stdout. Pure."""
    intact = hashlib.sha256(got).digest() == hashlib.sha256(src).digest()
    ok = send_rc == 0 and recv_rc == 0 and intact
    return ok, (send_rc == 0 or recv_rc == 0) and not intact


def send_to_stdout(w: World, st: dict, res: dict, deadline: float) -> None:
    src, dst = st["src"], st["dst"]
    t0 = time.monotonic()
    tag = f"{random.randrange(1 << 40):x}"
    f = w.cfg(src) / "files" / f"chz-{tag}.bin"
    data = os.urandom(st.get("kib", 4) * 1024)
    f.write_bytes(data)
    os.chown(f, w.uid, w.gid)
    slog = w.cfg(src) / f"stdout-send-{tag}.log"
    rlog = w.cfg(dst) / f"stdout-recv-{tag}.log"
    with open(slog, "wb") as so:
        # A code send and its receive are one-shot processes with their own
        # transport, not the daemon's, so the device's hooks must reach them
        # too or the paths those hooks open (a mid-transfer upgrade to direct)
        # are unreachable: replaying the pre-#746 tree found 0/24 corruptions
        # without this, while gate T3b finds it with the hook on both ends.
        sp = subprocess.Popen(w.as_dev(src, ["send", str(f), "--word", STDOUT_WORD]),
                              env=w.env_for(src, w.hooks.get(src, {})),
                              stdout=so, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                              start_new_session=True)
    code = None
    while time.monotonic() - t0 < deadline and sp.poll() is None:
        m = STDOUT_CODE.search(slog.read_bytes())
        if m:
            code = m.group(0).decode()
            break
        time.sleep(0.3)
    got = bytearray()
    recv_rc = None
    rerr = b""
    if code:
        with open(rlog, "wb") as re_:
            rp = subprocess.Popen(w.as_dev(dst, ["receive", code, "-y", "-o", "-", "--timeout", "60"]),
                                  env=w.env_for(dst, w.hooks.get(dst, {})), stdout=subprocess.PIPE, stderr=re_,
                                  stdin=subprocess.DEVNULL, start_new_session=True)

        def drain() -> None:
            while True:
                b = rp.stdout.read(65536)
                if not b:
                    return
                got.extend(b)
                time.sleep(0.05)

        th = threading.Thread(target=drain, daemon=True)
        th.start()
        try:
            recv_rc = rp.wait(max(1.0, deadline - (time.monotonic() - t0)))
        except subprocess.TimeoutExpired:
            os.killpg(rp.pid, signal.SIGKILL)
            rp.wait()
        th.join(10)
        rerr = rlog.read_bytes()
    # A code send waits for its code to be claimed (it advertises minutes).
    # When the receiver ended without getting a byte, a sender still waiting
    # is doing what it says, not hanging: stop it after a grace and judge the
    # receiver's own exit. A sender that outlives a receiver that DID get data
    # (or succeeded) is still a hang. (False O2 on 2026-11-26: receiver hit
    # "Can't reach the tunlion server" under 50% loss, sender kept waiting.)
    unclaimed = code is not None and recv_rc not in (None, 0) and not got
    wait_for = 30.0 if unclaimed else max(1.0, deadline - (time.monotonic() - t0))
    stopped_waiting = False
    try:
        send_rc = sp.wait(wait_for)
    except subprocess.TimeoutExpired:
        os.killpg(sp.pid, signal.SIGKILL)
        sp.wait()
        send_rc = None
        stopped_waiting = unclaimed
    ok, lie = stdout_send_verdict(data, bytes(got), send_rc, recv_rc)
    # The op's rc is the first end that did not succeed (None: a hang), so the
    # rc and silence oracles judge whichever end failed. A sender we stopped
    # while it waited for a claim is judged by the receiver's exit instead.
    if stopped_waiting:
        rc = recv_rc
    else:
        rc = send_rc if send_rc != 0 or not code else recv_rc
    err = (b"send: " + slog.read_bytes()[-10000:] + b"\nreceive: " + rerr[-10000:]).decode(errors="replace")
    res.update(rc=rc, elapsed=round(time.monotonic() - t0, 2), ok=ok, lie=lie, via="stdout",
               send_rc=send_rc, recv_rc=recv_rc, got_bytes=len(got), want_bytes=len(data),
               sender_stopped_waiting_for_claim=stopped_waiting)
    res["stderr_tail"] = err.strip()[-400:]
    res["stderr_full"] = err.strip()[-20000:]
    res["stdout_tail"] = ""


def run_op(w: World, st: dict, phase: str) -> dict:
    kind = st["op"]
    if kind == "visit":
        return run_visit(w, st, phase)
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
    elif kind == "send" and st.get("via") == "stdout":
        send_to_stdout(w, st, res, deadline)
        return res
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
        what = f"{who} exited 0 but the result was missing or wrong"
        if r.get("via") == "stdout":
            what = (f"{who} via stdout: send rc {r.get('send_rc')}, receive rc {r.get('recv_rc')}, "
                    f"but stdout held {r.get('got_bytes')} bytes that are not the {r.get('want_bytes')}-byte source")
        f.append({"oracle": "O7-false-success", "hard": True, "what": what})
    if r["rc"] not in (0, None) and not r["stderr_tail"]:
        f.append({"oracle": "O8-silent-failure", "hard": True,
                  "what": f"{who} failed (rc {r['rc']}) with nothing on stderr"})
    return f


# A failure message that tells the user the PEER is the problem: offline, not
# running `tunlion up`, never appeared. Matched loosely on purpose; the other
# conditions in judge_diagnosis carry the precision.
_BLAMES_PEER = re.compile(r"\boffline\b|is '?[\w-]+'? online|`tunlion up` (is not )?running|"
                          r"did not appear on the tunlion server|did not answer within|"
                          r"may be unresponsive|running a build without", re.I)
# A hint that names the path between the machines as a possible cause is not
# a misdiagnosis, even when it also allows that the peer went away.
_NAMES_PATH = re.compile(r"firewall|\bpath\b|relay|\bUDP\b|network between", re.I)
# Faults that really can make the peer look offline. A partition between two
# devices or a degraded link cannot: the peer is still up and announced.
_PEER_DOWN_FAULTS = {"proc.freeze", "proc.kill", "sig.blackhole", "sig.reset", "net.isolate"}
# A message that says the problem is on this machine's side (#732, #736).
_BLAMES_SELF = re.compile(r"this machine's own connection|can't reach the tunlion server from this machine", re.I)
# Faults on a device's own network path that make such a message true.
_SELF_NET_FAULTS = {"net.impair", "net.isolate", "sig.blackhole", "sig.reset"}


def judge_local_status(r: dict, fault_windows: list[dict]) -> list[dict]:
    """O3b: a daemon keeps answering its OWN machine while only its network is
    faulted. `status` on a device whose daemon was not frozen or killed must
    not say "not responding": that is the event loop parked on network I/O,
    and the advice it prints (restart it) is wrong."""
    if r.get("op") != "status" or r.get("rc") != 6 or "t_start" not in r:
        return []
    if "not responding" not in (r.get("stderr_tail") or ""):
        return []
    lo, hi = r["t_start"], r["t_end"]
    for f in fault_windows:
        st = f["step"]
        end = f["end"] if f["end"] is not None else float("inf")
        if st["fault"] in ("proc.freeze", "proc.kill") and st.get("target") == r["src"] and f["start"] < hi and end > lo - 5:
            return []
    faults = sorted({f["step"]["fault"] for f in fault_windows})
    return [{"oracle": "O3b-unresponsive-during-network-fault", "hard": True,
             "what": f"status on {r['src']} said its daemon was not responding while only network faults "
                     f"were active ({', '.join(faults)}): {r['stderr_tail'][:200]}"}]


def judge_diagnosis(r: dict, fault_windows: list[dict]) -> list[dict]:
    """O9: the command blamed the peer (offline, not running) while the peer
    was up: no fault that could take it offline overlapped the command (15 s
    of slack before it, for presence to settle), and the peer's daemon said it
    was connected to the server right after the failure."""
    if r.get("ok") or r.get("rc") in (None, 0) or "t_start" not in r:
        return []
    err = r.get("stderr_tail") or ""
    dst = r["dst"]
    lo, hi = r["t_start"] - 15.0, r["t_end"]
    # A message that puts the cause on THIS machine's own connection is a
    # claim we can check: it is right only if a fault on the source's own
    # network overlapped the command. Blaming a healthy own link is just as
    # wrong as blaming a healthy peer.
    if _BLAMES_SELF.search(err):
        src = r["src"]
        for f in fault_windows:
            st = f["step"]
            if not _overlaps(f, lo, hi):
                continue
            if st["fault"] == "server.down" or (st["fault"] in _SELF_NET_FAULTS and st.get("target") == src):
                return []
        return [{"oracle": "O9-misdiagnosis", "hard": True,
                 "what": f"{r['op']} {src}->{dst} blamed this machine's own connection (rc {r['rc']}), but no "
                         f"fault touched {src}'s network: {err[-180:]}"}]
    if not _BLAMES_PEER.search(err) or _NAMES_PATH.search(err):
        return []
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


def _overlaps(f: dict, lo: float, hi: float) -> bool:
    end = f["end"] if f["end"] is not None else float("inf")
    return f["start"] < hi and end > lo


def judge_visits(visits: list[dict], fault_windows: list[dict]) -> list[dict]:
    """Every visitor must ENGAGE (join, then be answered by the owner) or the
    run proves nothing about it, like a fault whose mechanism is absent. A
    broken mechanism, or a visitor that fails before any other visitor proved
    the path, refuses the run. A visitor that fails AFTER another one engaged
    is O13: the owner stopped admitting newcomers (the 2026-11-26 link-table
    starvation), unless a fault of the schedule overlapped it."""
    vs = sorted(visits, key=lambda r: r["t_start"])
    for r in vs:
        if r.get("mech_error"):
            raise Refused("instrument: " + r["mech_error"])
    engaged = [r["t_engaged"] for r in vs if r.get("t_engaged") is not None]
    if not engaged:
        r = vs[0]
        raise Refused(f"no visitor engaged; first, {r['dst']}: joined={r.get('joined')} rc={r.get('rc')}: "
                      f"{(r.get('stderr_tail') or '')[-240:]}")
    out = []
    for r in vs:
        lo, hi = r["t_start"], r["t_gone"]
        if r.get("t_engaged") is not None:
            if r.get("join_s", 0) > ENROLL_BOUND:
                out.append({"oracle": "O13-enrollment-starved", "hard": True,
                            "what": f"visitor {r['dst']} took {r['join_s']:.0f}s to enroll (bound {ENROLL_BOUND:.0f}s)"})
            continue
        if any(_overlaps(f, lo, hi) for f in fault_windows):
            r["excused"] = "a fault of the schedule overlapped this visitor"
            continue
        if not any(e < lo for e in engaged):
            raise Refused(f"visitor {r['dst']} did not engage and no visitor before it had proved the path "
                          f"(rc {r.get('rc')}): {(r.get('stderr_tail') or '')[-240:]}")
        what = ("could not enroll" if not r.get("joined") else "enrolled but the owner never answered it")
        out.append({"oracle": "O13-enrollment-starved", "hard": True,
                    "what": f"visitor {r['dst']} {what} after an earlier visitor had engaged "
                            f"(rc {r.get('rc')}): {(r.get('stderr_tail') or '')[-200:]}"})
    return out


def judge_probe(r: dict, departed: int) -> list[dict]:
    """O13, final arm: after every visitor left, one more must still enroll
    within ENROLL_BOUND and be answered by the owner."""
    if r.get("mech_error"):
        raise Refused("instrument: " + r["mech_error"])
    if r.get("joined") and r.get("join_s", 0) <= ENROLL_BOUND and r.get("seen"):
        return []
    if not r.get("joined"):
        what = f"could not enroll (rc {r.get('rc')}, {r.get('join_s', 0):.0f}s)"
    elif r.get("join_s", 0) > ENROLL_BOUND:
        what = f"took {r['join_s']:.0f}s to enroll (bound {ENROLL_BOUND:.0f}s)"
    else:
        what = "enrolled but the owner never answered it"
    return [{"oracle": "O13-enrollment-starved", "hard": True,
             "what": f"a new visitor {what} after {departed} visitor(s) had left: "
                     f"{(r.get('stderr_tail') or '')[-200:]}"}]


_ESTABLISH = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)\s.*?\bESTABLISH peer=(\S+)", re.M)


def establish_events(text: str) -> list[tuple[int, str]]:
    """(epoch second, peer id) of every link the daemon (re)established."""
    import calendar
    return [(calendar.timegm(time.strptime(m.group(1), "%Y-%m-%dT%H:%M:%SZ")), m.group(2))
            for m in _ESTABLISH.finditer(text)]


def judge_redial(text: str, lo: float, hi: float, live: set[str], k: int = REDIAL_MAX) -> tuple[list[dict], dict]:
    """O12: in [lo, hi] every visitor is gone. A peer id, other than a live
    device's, that the owner established more than `k` times in that window is
    being re-dialled past the designed ladder (MAX_ATTEMPTS rebuilds, then
    drop). No ESTABLISH line in the whole log means debug logging is not
    reaching the file, so the rule could not see a storm: refused, never
    passed."""
    ev = establish_events(text)
    if not ev:
        raise Refused("instrument: the owner's log has no timestamped ESTABLISH line; O12 is blind")
    counts: dict[str, int] = {}
    for t, sid in ev:
        if int(lo) <= t <= hi and sid not in live:
            counts[sid] = counts.get(sid, 0) + 1
    out = [{"oracle": "O12-redial-departed", "hard": True,
            "what": f"alpha re-established departed peer {sid[:12]} {c} times in {hi - lo:.0f}s after every "
                    f"visitor had left (ladder bound {k})"}
           for sid, c in sorted(counts.items(), key=lambda x: -x[1]) if c > k]
    return out, counts


def visitor_oracles(w: World, visits: list[dict], t0: float, fault_windows: list[dict], verdict: dict) -> list[dict]:
    for r in visits:
        r["t_start"] = round(r.pop("m_start") - t0, 1)
        e = r.pop("m_engaged")
        r["t_engaged"] = None if e is None else round(e - t0, 1)
        r["t_gone"] = round(r.pop("m_gone") - t0, 1)
        log_text = r.pop("daemon_log", None)
        if log_text:
            w.visitor_logs[f"{r['dst']}-daemon.log"] = log_text
    found = judge_visits(visits, fault_windows)
    info: dict = {"visitors": len(visits), "engaged": sum(1 for r in visits if r.get("t_engaged") is not None)}
    verdict["visitors"] = info
    alpha = w.daemons.get(OWNER)
    if not alpha or alpha.poll() is not None:
        info["skipped"] = "the owner's daemon is not running"
        return found
    gone = max(r.get("gone_wall", 0.0) for r in visits)
    lo, hi = gone + REDIAL_GRACE, gone + REDIAL_GRACE + REDIAL_QUIET
    while time.time() < hi:
        if w.stop.is_set():
            raise Aborted()
        time.sleep(min(2.0, max(0.05, hi - time.time())))
    live = {l.get("pid") for l in (w.list_warm(OWNER) or []) if l.get("name") in DEVICES}
    f12, counts = judge_redial(w.all_daemon_logs()[OWNER], lo, hi, live)
    found += f12
    info["redial_window_s"] = round(hi - lo, 1)
    info["redial_counts"] = dict(sorted(counts.items(), key=lambda x: -x[1])[:20])
    used = max(visitor_no(r["dst"]) or 0 for r in visits)    # < MAX_VISITORS: check_visits
    pr = run_visit(w, {"op": "visit", "src": OWNER, "dst": f"vis{used + 1}", "stay": 0.0}, "probe")
    for k in ("m_start", "m_engaged", "m_gone"):
        pr.pop(k, None)
    if pr.get("daemon_log"):
        w.visitor_logs[f"vis{used + 1}-probe-daemon.log"] = pr.pop("daemon_log")
    info["probe"] = {k: pr.get(k) for k in ("dst", "rc", "joined", "join_s", "seen", "stderr_tail")}
    found += judge_probe(pr, len(visits))
    return found


# ------------------------------------------------------------- one run ---

def run_schedule(w: World, sched: dict, label: str) -> dict:
    """Execute one schedule end to end. Returns the verdict (never raises for
    product misbehaviour; raises Refused for fixture problems)."""
    t_wall = time.monotonic()
    w.assert_binary_unchanged()
    try:
        check_visits(sched)
    except ValueError as e:
        raise Refused(f"instrument: bad schedule: {e}")
    n_visits = sum(1 for st in sched["steps"] if st.get("op") == "visit")
    hooks = copy.deepcopy(sched.get("hooks", {}))
    if n_visits:
        # O12 reads the owner's ESTABLISH lines, which are debug level.
        hooks.setdefault(OWNER, {}).setdefault("TUNLION_LOG", "debug")
    w.visitor_logs = {}
    w.reset_for_run(hooks)
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
    if n_visits:
        w.mint_visitor_invitation(n_visits + 1)     # +1: the final probe visitor

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
        if w.stop.is_set():
            raise Aborted()
        time.sleep(0.2)
    for th in threads:
        th.join(max(OP_DEADLINE.values()) + 30)
    verdict["ops"].extend(results)
    fault_windows = [{"step": tl["step"], "start": tl["start"], "end": tl["end"]} for tl in timeline]
    verdict["fault_windows"] = [{"fault": f["step"]["fault"], "start": round(f["start"], 1),
                                 "end": None if f["end"] is None else round(f["end"], 1)} for f in fault_windows]
    for r in results:
        if r["op"] == "visit":
            if not r.get("mech_error"):
                verdict["findings"].extend(judge_op(r))
            continue
        verdict["findings"].extend(judge_op(r))
        verdict["findings"].extend(judge_diagnosis(r, fault_windows))
        verdict["findings"].extend(judge_local_status(r, fault_windows))

    # After heal: every daemon reconnects, every path works, nobody storms.
    alive = [d for d in DEVICES if w.daemons[d] and w.daemons[d].poll() is None]
    for d in DEVICES:
        if d not in alive:
            rc = w.daemons[d].returncode if w.daemons[d] else None
            verdict["findings"].append({"oracle": "O3-daemon-died", "hard": True,
                                        "what": f"{d} daemon exited (rc {rc}) without being killed by the schedule"})
    seen = wait_signaling(w, alive, SETTLE_SIGNALING, allow_unreported=True,
                          dumps=verdict.setdefault("thread_dumps", {}))
    for d, (st, raw) in seen.items():
        if st == "down":
            verdict["findings"].append({"oracle": "O1-no-recovery", "hard": True,
                                        "what": f"{d} signaling not connected {SETTLE_SIGNALING:.0f}s after heal: {raw}"})
    for d in alive:
        if w.cap_status(d) is None:
            verdict["findings"].append({"oracle": "O3-unresponsive", "hard": True,
                                        "what": f"{d} daemon does not answer its control socket after heal"})
            if d not in verdict["thread_dumps"]:
                verdict["thread_dumps"][d] = thread_dump(w.daemons[d].pid)
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
    verdict["storm"] = storm_window(w)
    for d, c in verdict["storm"]["syns"].items():
        if c > STORM_MAX_CONNECTS:
            verdict["findings"].append({"oracle": "O5-reconnect-storm", "hard": True,
                                        "what": f"{d} opened {c} server connections in the post-heal window"})

    # Visitors: every one engaged, the owner lets go of the departed ones,
    # and a newcomer is still admitted (O12, O13). After the storm window, so
    # the checks above keep their meaning.
    visits = [r for r in results if r["op"] == "visit"]
    if visits:
        verdict["findings"].extend(visitor_oracles(w, visits, t0, fault_windows, verdict))

    logs = w.all_daemon_logs()
    for d, text in logs.items():
        if "panicked at" in text:
            line = next(ln for ln in text.splitlines() if "panicked at" in ln)
            verdict["findings"].append({"oracle": "O4-daemon-panic", "hard": True, "what": f"{d}: {line[-240:]}"})
        # O11: the daemon's own per-iteration budget (PR #731, test-hooks
        # builds). One busy pass over 1 s is an await parked on the event
        # loop: the #729 bug class, caught even when it recovers.
        for m in re.finditer(r"LOOP-BUDGET-EXCEEDED (\d+) (\S+)", text):
            verdict["findings"].append({"oracle": "O11-loop-budget", "hard": True,
                                        "what": f"{d} event loop busy {m.group(1)} ms in one pass ({m.group(2)})"})
        stalls = [m.start() for m in re.finditer(r"event loop stalled", text)]
        if stalls and "event loop recovered" not in text[stalls[-1]:] and d in alive:
            verdict["findings"].append({"oracle": "O3-stalled-loop", "hard": True,
                                        "what": f"{d} logged an event-loop stall and never recovered or exited"})
    verdict["kinds"] = sorted(set().union(*(kinds_of(t) for t in logs.values())))
    verdict["hard"] = [f for f in verdict["findings"] if f["hard"]]
    verdict["elapsed_s"] = round(time.monotonic() - t0, 1)
    verdict["wall_s"] = round(time.monotonic() - t_wall, 1)
    if verdict["hard"]:
        # Confirm and minimize replay the schedule and overwrite the daemon
        # logs. Keep the logs of THIS run, the one that failed.
        verdict["evidence_logs"] = {f"{d}-daemon.log": t for d, t in logs.items()}
        verdict["evidence_logs"].update(getattr(w, "visitor_logs", {}))
        for d, dump in (verdict.get("thread_dumps") or {}).items():
            verdict["evidence_logs"][f"{d}-threads.txt"] = dump
        bl = w.work / "backend.log"
        if bl.exists():
            verdict["evidence_logs"]["backend.log"] = bl.read_text(errors="replace")[-400000:]
    record_run(w, verdict)
    return verdict


def storm_window(w: World, window: float = STORM_WINDOW, quiet_exit: float = STORM_QUIET_EXIT,
                 poll: float = 1.0, clock=time.monotonic, sleep=time.sleep, counts=None) -> dict:
    """Count each device's server connection attempts for up to `window`
    seconds. Ends early on a device over STORM_MAX_CONNECTS (counters only
    grow: the full window could not clear it) or, after `quiet_exit`
    seconds, when NO device has made a single attempt (see STORM_QUIET_EXIT
    for what that can miss). Returns the counts and the time it watched."""
    counts = counts or w.syn_counts
    base = counts()
    t0 = clock()
    c = {d: 0 for d in base}
    while True:
        sleep(poll)
        el = clock() - t0
        now = counts()
        c = {d: now[d] - base[d] for d in base}
        if any(v > STORM_MAX_CONNECTS for v in c.values()):
            why = "over"
            break
        if el >= window:
            why = "full"
            break
        if el >= quiet_exit and not any(c.values()):
            why = "quiet"
            break
    return {"syns": c, "watched_s": round(clock() - t0, 1), "ended": why}


def record_run(w: "World", verdict: dict) -> None:
    """Every run leaves a record, clean or not: what was applied, whether it
    bit, every operation's exit code and latency, which rules fired. A clean
    record is the evidence of what was exercised."""
    if not getattr(w, "out", None):
        return
    runs = w.out / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    with _out_lock:
        _run_seq[0] += 1
        n = _run_seq[0] - 1
    rec = {k: verdict.get(k) for k in ("label", "schedule", "faults", "fault_windows", "ops", "findings", "elapsed_s",
                                       "unreported_signaling", "storm", "wall_s", "visitors")}
    rec["world"] = w.k
    rec["kinds_count"] = len(verdict.get("kinds", []))
    safe = re.sub(r"[^\w.-]", "_", re.sub(r"\.json$", "", verdict["label"]))[:60]
    (runs / f"{n:04d}-w{w.k}-{safe}.json").write_text(json.dumps(rec, indent=1, sort_keys=True))


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


def thread_dump(pid: int) -> str:
    """Where every thread of a wedged process is. Kernel wait channels and
    stacks tell a thread blocked in a syscall from an idle runtime whose task
    awaits a future that never resolves; gdb (if present, and if the binary
    has symbols: CHAOS_SYMBOLS=1 in run-on-lease.sh) names the functions."""
    parts = []
    for t in sorted(Path(f"/proc/{pid}/task").glob("*"), key=lambda x: int(x.name)):
        def rd(name):
            try:
                return (t / name).read_text(errors="replace").strip()
            except OSError:
                return "?"
        parts.append(f"--- tid {t.name} comm={rd('comm')} wchan={rd('wchan')}\n{rd('stack')}")
    if shutil.which("gdb"):
        r = sh(["gdb", "-p", str(pid), "-batch", "-nx", "-ex", "set pagination off",
                "-ex", "thread apply all bt 40"], check=False, timeout=60)
        parts.append("=== gdb thread apply all bt\n" + r.stdout[-60000:])
    return "\n".join(parts)


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


def wait_signaling(w: World, devs: list[str], limit: float, allow_unreported: bool = False,
                   dumps: dict | None = None) -> dict:
    """Wait until every device is connected (or unreported, when allowed).
    Returns {device: (state, raw)} as last seen, for the caller to judge.
    With `dumps`, a daemon seen not answering has its threads captured the
    first time, while it is still stuck (it may exit later)."""
    ok = {"connected", "unreported"} if allow_unreported else {"connected"}
    t0 = time.monotonic()
    seen = {}
    while True:
        seen = {d: sig_state(w, d) for d in devs}
        if dumps is not None:
            for d, (st, _) in seen.items():
                p = w.daemons.get(d)
                if st == "noanswer" and d not in dumps and p and p.poll() is None:
                    dumps[d] = thread_dump(p.pid)
                    log(f"  {d} is not answering: captured its threads")
        if all(st in ok for st, _ in seen.values()) or time.monotonic() - t0 >= limit:
            return seen
        time.sleep(1)


_out_lock = threading.Lock()
_run_seq = [0]


def finding_key(f: dict) -> str:
    """One bug, one report: oracle plus the device and op words, no numbers."""
    return f["oracle"] + "|" + re.sub(r"[\d.]+", "N", f["what"])[:80]


def save_finding(out: Path, verdict: dict, w: World, repro: str) -> Path:
    with _out_lock:
        return _save_finding(out, verdict, w, repro)


def _save_finding(out: Path, verdict: dict, w: World, repro: str) -> Path:
    key = hashlib.sha1("\n".join(sorted(finding_key(f) for f in verdict["hard"])).encode()).hexdigest()[:10]
    d = out / "findings" / key
    d.mkdir(parents=True, exist_ok=True)
    # schedule.json is what to replay: the minimized schedule when there is
    # one. The logs, ops and faults below are from the run that FAILED, whose
    # schedule may hold faults minimization dropped, so that one is saved as
    # run-schedule.json and verdict.json names it. (Finding 5335b79ffb,
    # 2026-11-26: charlie's 39 s signaling outage looked unexplained because
    # schedule.json no longer had the sig.reset on charlie that caused it.)
    run_sched = verdict["schedule"]
    replay = verdict.get("minimized") or run_sched
    for stale in ("schedule.json", "run-schedule.json"):
        (d / stale).unlink(missing_ok=True)
    (d / "schedule.json").write_text(json.dumps(replay, indent=2, sort_keys=True))
    logs_from = "schedule.json"
    if replay != run_sched:
        logs_from = "run-schedule.json"
        (d / logs_from).write_text(json.dumps(run_sched, indent=2, sort_keys=True))
    v = {k: verdict[k] for k in ("label", "findings", "ops", "faults")}
    v["fault_windows"] = verdict.get("fault_windows")
    v["schedule_of_this_run"] = logs_from
    v["visitors"] = verdict.get("visitors")
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


def run_worlds(worlds: list[World], job, first=None) -> None:
    """Run job(w) in one thread per world. `first`, if given, runs on world 0
    before its job (the canary: once per machine, while the other worlds
    already work; a failed canary stops them and voids the campaign). The
    first exception in any world stops every world and is re-raised here."""
    errors: list[tuple[int, BaseException, str]] = []

    def body(w: World) -> None:
        _ctx.world = w.k
        try:
            if first is not None and w is worlds[0]:
                first(w)
            if not w.stop.is_set():
                job(w)
        except Aborted:
            pass
        except BaseException as e:
            import traceback
            errors.append((w.k, e, traceback.format_exc()))
            for x in worlds:
                x.stop.set()
    threads = [threading.Thread(target=body, args=(w,), name=f"world{w.k}", daemon=True) for w in worlds]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if errors:
        k, e, tb = errors[0]
        if not isinstance(e, Refused):
            log(f"world {k} crashed:\n{tb}")
        raise e


def cmd_canary(w: World, out: Path) -> int:
    """Arm A (healthy): must produce no hard finding. Arm B (self-heal
    disabled with TUNLION_TEST_NO_SIGNALING_RECONNECT on bravo): must produce
    O1-no-recovery for bravo. Either arm wrong means the instrument is."""
    a = run_schedule(w, copy.deepcopy(CANARY_SCHEDULE), "canary-healthy")
    sb = copy.deepcopy(CANARY_SCHEDULE)
    sb["hooks"] = {"bravo": {"TUNLION_TEST_NO_SIGNALING_RECONNECT": "1"}}
    b = run_schedule(w, sb, "canary-broken")
    (out / "canary.json").write_text(json.dumps(
        {arm: {k: v[k] for k in ("findings", "ops", "faults", "storm")} for arm, v in (("healthy", a), ("broken", b))},
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


def cmd_replay(worlds: list[World], out: Path, files: list[Path], repeat: int = 1, first=None) -> int:
    """Run each schedule `repeat` times, spread over the worlds. With repeat
    1 a failure is confirmed once more (on the same world); with repeat > 1
    the failure RATE is the result (an intermittent bug and its fix are both
    measured as rates), and every failing repetition keeps its own evidence."""
    lock = threading.Lock()
    scheds = {f: json.loads(f.read_text()) for f in files}
    items = [(f, i) for f in files for i in range(repeat)]
    fails = {f.name: 0 for f in files}

    def job(w: World) -> None:
        while not w.stop.is_set():
            with lock:
                if not items:
                    return
                f, i = items.pop(0)
            sched = scheds[f]
            log(f"replay {f.name}" + (f" ({i + 1}/{repeat})" if repeat > 1 else ""))
            v = run_schedule(w, sched, f.stem + (f"-r{i + 1}" if repeat > 1 else ""))
            if not v["hard"]:
                log(f"  clean ({f.name})")
                continue
            with lock:
                fails[f.name] += 1
            repro = confirm(w, sched, v, tries=1) if repeat == 1 else f"repetition {i + 1}/{repeat}"
            d = save_finding(out, v, w, repro)
            log(f"  FINDING {f.name} ({repro}) -> {d}: {[x['what'][:200] for x in v['hard']]}")
    run_worlds(worlds, job, first)
    rates = {name: f"{n}/{repeat}" for name, n in fails.items()}
    if repeat > 1:
        for name, r in rates.items():
            log(f"  {name}: failed {r}")
    (out / "replay-rates.json").write_text(json.dumps(rates, indent=2))
    return 1 if any(fails.values()) else 0


def cmd_explore(worlds: list[World], out: Path, budget_s: float, seed: int, corpus: list[Path], first=None) -> int:
    """Every world mutates from ONE shared queue and feeds ONE shared set of
    seen behaviours, so a schedule kept by one world is mutated by all."""
    lock = threading.Lock()
    queue = [json.loads(p.read_text()) for p in corpus]
    seen: set[str] = set()
    found: dict[str, Path | None] = {}
    tally = {"runs": 0, "bites": 0}
    per_world = {w.k: 0 for w in worlds}
    t_end = time.monotonic() + budget_s
    grown = out / "corpus-grown"

    def job(w: World) -> None:
        rng = random.Random(seed + 7919 * w.k)
        refusals = 0
        while time.monotonic() < t_end and not w.stop.is_set():
            with lock:
                parent = rng.choice(queue[-16:]) if queue and rng.random() < 0.8 else None
            sched = mutate(parent, rng) if parent is not None else random_schedule(rng)
            if window_end(sched) + 200 > t_end - time.monotonic():
                return
            with lock:
                tally["runs"] += 1
                n = tally["runs"]
            per_world[w.k] += 1
            try:
                v = run_schedule(w, sched, f"explore-{n}")
                refusals = 0
            except Refused as e:
                # A baseline that fails proves nothing about the schedule; skip
                # it, but three in a row means the fixture itself is broken.
                if str(e).startswith("instrument"):
                    raise
                refusals += 1
                log(f"  run {n} refused: {e}")
                if refusals >= 3:
                    raise
                continue
            key = None
            with lock:
                tally["bites"] += sum(1 for x in v["faults"] if x.get("bit"))
                new = set(v["kinds"]) - seen
                if new:
                    seen.update(new)
                    queue.append(sched)
                    # Saved as it grows: a campaign stopped early keeps what it learned.
                    grown.mkdir(exist_ok=True)
                    (grown / f"q{len(queue) - 1:03d}.json").write_text(json.dumps(sched, indent=2, sort_keys=True))
                    log(f"  run {n}: +{len(new)} new behaviours (total {len(seen)}), kept")
                if v["hard"]:
                    key = "|".join(sorted({finding_key(f) for f in v["hard"]}))
                    if key in found:
                        key = None
                    else:
                        found[key] = None      # claimed: no other world confirms it too
            if key is None:
                continue
            # A refused baseline inside confirm or minimize says nothing about
            # the finding: keep it, marked unconfirmed, instead of ending the
            # campaign (an instrument refusal still ends it).
            try:
                repro = confirm(w, sched, v)
                # Kept beside, never over, v["schedule"]: the logs, ops and
                # faults in this verdict all come from the run of v["schedule"].
                v["minimized"] = minimize(w, sched, {f["oracle"] for f in v["hard"]})
            except Refused as e:
                if str(e).startswith("instrument"):
                    raise
                repro = f"unconfirmed (a confirm or minimize run was refused: {e})"
                log(f"  {repro}")
            d = save_finding(out, v, w, repro)
            with lock:
                found[key] = d
            log(f"  FINDING ({repro}) -> {d}")
    run_worlds(worlds, job, first)
    summary = {"runs": tally["runs"], "runs_per_world": per_world, "behaviours": len(seen),
               "faults_bit": tally["bites"], "findings": [str(p) for p in found.values() if p], "seed": seed}
    (out / "summary.json").write_text(json.dumps(summary, indent=2))
    if tally["runs"] and tally["bites"] == 0:
        log("no fault bit in the whole campaign: the fault layer is not reaching the daemons")
        return 4
    return 1 if found else 0


def cmd_hookcheck(worlds: list[World], out: Path, repeat: int = 3, first=None) -> int:
    """Validate RECOVERABLE_HOOKS empirically: each hook alone, on the daemon
    that receives and serves, with a send and an exec and a negligible fault
    (a schedule needs one), must be clean every time. A hook that fails here
    is not a recoverable fault and would make the fuzzer report false bugs."""
    lock = threading.Lock()
    items = [(hook, val, i) for hook, values in sorted(RECOVERABLE_HOOKS.items()) for val in values
             for i in range(repeat)]
    fails: dict[str, int] = {}

    def job(w: World) -> None:
        while not w.stop.is_set():
            with lock:
                if not items:
                    return
                hook, val, i = items.pop(0)
            sched = {"version": 1, "seed": 0, "hooks": {"bravo": {hook: val}},
                     "steps": [{"at": 1.0, "fault": "net.impair", "target": "charlie", "dur": 2.0,
                                "args": {"delay_ms": 10, "dup": 0, "jitter_ms": 0, "loss": 0, "reorder": 0}},
                               {"at": 3.0, "op": "send", "src": OWNER, "dst": "bravo", "kib": 256},
                               {"at": 20.0, "op": "exec", "src": "bravo", "dst": OWNER}]}
            v = run_schedule(w, sched, f"hookcheck-{hook}={val}-{i + 1}")
            with lock:
                fails[f"{hook}={val}"] = fails.get(f"{hook}={val}", 0) + (1 if v["hard"] else 0)
    run_worlds(worlds, job, first)
    for k, n in sorted(fails.items()):
        log(f"hookcheck {k}: {n}/{repeat} failed")
    bad = {k: f"{n}/{repeat}" for k, n in fails.items() if n}
    (out / "hookcheck.json").write_text(json.dumps(bad, indent=2))
    if bad:
        log(f"HOOKS MISCLASSIFIED (remove them from RECOVERABLE_HOOKS): {bad}")
        return 4
    return 0


def selftest_visitors() -> None:
    """O12 and O13 judged on fixed inputs: the production log shape of the
    2026-11-26 zombie (one departed sid rebuilt every ~16 s), the designed
    ladder (at most MAX_ATTEMPTS rebuilds, then drop) and the engagement rules."""
    import calendar

    def stamp(t: int) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
    base = calendar.timegm((2026, 11, 26, 0, 0, 0, 0, 0, 0))
    lo, hi = base + 10, base + 10 + REDIAL_QUIET

    def est(t: int, sid: str) -> str:
        return f"{stamp(t)} tunlion: ESTABLISH peer={sid} caller=cli/src/conn.rs:7181 early=0 signals=0"
    zombie = [est(base + i * 16, "ZOMBIEsid1") for i in range(15)]           # forever, 2/5 again and again
    ladder = [est(base + 12 + i * 16, "LADDERsid2") for i in range(REDIAL_MAX)]  # gives up as designed
    live = [est(base + 20 + i * 5, "BRAVOsid") for i in range(20)]            # a live device's own sid
    noise = [f"{stamp(base + 30)} tunlion: peer 'bravo' reconnected", "not a stamped line ESTABLISH peer=X"]
    text = "\n".join(sorted(zombie + ladder + live + noise))
    f, counts = judge_redial(text, lo, hi, {"BRAVOsid"})
    assert [x["oracle"] for x in f] == ["O12-redial-departed"] and "ZOMBIEsid1"[:12] in f[0]["what"], f
    assert counts["ZOMBIEsid1"] > REDIAL_MAX and counts["LADDERsid2"] == REDIAL_MAX and "BRAVOsid" not in counts, counts
    f, _ = judge_redial(text, lo, hi, set())
    assert {x["what"].split()[4] for x in f} == {"ZOMBIEsid1", "BRAVOsid"}, "without the live set a busy sid counts"
    before = "\n".join(est(base - 200 + i * 16, "OLDsid") for i in range(10)) + "\n" + est(base + 20, "x")
    assert judge_redial(before, lo, hi, set())[0] == [], "dials before the window are not counted"
    try:
        judge_redial(f"{stamp(base)} tunlion: peer joined\n", lo, hi, set())
        raise AssertionError("an owner log without ESTABLISH lines must refuse, not pass")
    except Refused as e:
        assert str(e).startswith("instrument"), e
    # Engagement: refuse when nothing engaged or a failure has no earlier proof;
    # a failure after a proof is O13; a fault overlapping excuses it.
    ok = lambda name, t, j=2.0: {"dst": name, "t_start": t, "t_engaged": t + 5, "t_gone": t + 10,  # noqa: E731
                                 "joined": True, "join_s": j, "seen": True}
    bad = {"dst": "vis3", "t_start": 40.0, "t_engaged": None, "t_gone": 100.0, "joined": False, "rc": 1,
           "stderr_tail": "enrollment timed out after 60s (no response from peer)"}
    assert judge_visits([ok("vis1", 1.0), ok("vis2", 20.0)], []) == []
    f = judge_visits([ok("vis1", 1.0), ok("vis2", 20.0), bad], [])
    assert len(f) == 1 and f[0]["oracle"] == "O13-enrollment-starved" and "could not enroll" in f[0]["what"], f
    iso = [{"step": {"fault": "net.isolate", "target": OWNER}, "start": 30.0, "end": 60.0}]
    assert judge_visits([ok("vis1", 1.0), dict(bad)], iso) == [], "a fault of the schedule excuses it"
    for vs in ([dict(bad, t_start=0.0)], [dict(bad, t_start=0.0), ok("vis2", 20.0)]):
        try:
            judge_visits(vs, [])
            raise AssertionError(f"must refuse: {vs}")
        except Refused:
            pass
    try:
        judge_visits([dict(ok("vis1", 1.0), mech_error="visitor vis1 could not be set up: x")], [])
        raise AssertionError("a broken visitor mechanism must refuse")
    except Refused as e:
        assert str(e).startswith("instrument"), e
    assert judge_visits([ok("vis1", 1.0, j=75.0)], [])[0]["oracle"] == "O13-enrollment-starved"
    assert judge_probe(ok("vis15", 400.0), 14) == []
    assert judge_probe(dict(bad, dst="vis15"), 14)[0]["oracle"] == "O13-enrollment-starved"
    assert judge_probe(dict(ok("vis15", 400.0), seen=False), 14)[0]["oracle"] == "O13-enrollment-starved"
    # Visitor names map into the world's /16 without touching the devices.
    assert dev_index("vis1") == VISITOR_BASE + 1 and dev_index("alpha") == 1 and visitor_no("vis0") is None
    vw = World.__new__(World)
    vw.k, vw.net = 15, 105
    assert len(vw.veth_root(f"vis{MAX_VISITORS}")) <= 15 and vw.dev_ip(f"vis{MAX_VISITORS}").split(".")[2] == "210"
    for bad_s in ([{"op": "visit", "at": 1, "src": OWNER, "dst": "vis1"}] * 2,
                  [{"op": "visit", "at": 1, "src": "bravo", "dst": "vis1"}],
                  [{"op": "visit", "at": 1, "src": OWNER, "dst": f"vis{MAX_VISITORS}"}]):
        try:
            check_visits({"steps": bad_s})
            raise AssertionError(bad_s)
        except ValueError:
            pass


def selftest_save_finding() -> None:
    """A minimized finding keeps the schedule its logs came from."""
    import tempfile
    reset = {"at": 1.1, "dur": 25.8, "fault": "sig.reset", "target": "charlie"}
    impair = {"at": 15.8, "dur": 195.9, "fault": "net.impair", "target": "bravo", "args": {"loss": 50}}
    full = {"version": 1, "seed": 0, "hooks": {}, "steps": [reset, impair]}
    small = {"version": 1, "seed": 0, "hooks": {}, "steps": [impair]}
    hard = [{"oracle": "O2-hang", "hard": True, "what": "send alpha->bravo still running"}]
    base = {"label": "explore-1", "findings": hard, "hard": hard, "ops": [], "faults": [],
            "fault_windows": [{"fault": "sig.reset", "start": 1.2, "end": 27.0}]}
    with tempfile.TemporaryDirectory() as tmp:
        d = _save_finding(Path(tmp), dict(base, schedule=full, minimized=small), None, "3/3")
        assert json.loads((d / "schedule.json").read_text()) == small, "replay the minimized schedule"
        assert json.loads((d / "run-schedule.json").read_text()) == full, "the logs' own schedule is kept"
        v = json.loads((d / "verdict.json").read_text())
        assert v["schedule_of_this_run"] == "run-schedule.json" and v["fault_windows"][0]["fault"] == "sig.reset"
        # Nothing dropped (or no minimize ran): one schedule, no stale second file.
        d = _save_finding(Path(tmp), dict(base, schedule=full), None, "3/3")
        assert json.loads((d / "schedule.json").read_text()) == full
        assert not (d / "run-schedule.json").exists(), "a stale run-schedule.json would mislead"
        assert json.loads((d / "verdict.json").read_text())["schedule_of_this_run"] == "schedule.json"


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
    # T3's false success: both ends exit 0, stdout holds the file plus 60 KiB.
    src = os.urandom(4096)
    assert stdout_send_verdict(src, src, 0, 0) == (True, False)
    assert stdout_send_verdict(src, src[:1024] + src, 0, 0) == (False, True)
    assert stdout_send_verdict(src, src[:1024], 2, 0) == (False, True), "the receiver's rc 0 is a claim too"
    assert stdout_send_verdict(src, src[:1024], 2, 4) == (False, False), "an honest failure is not a lie"
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
    st_r = {"op": "status", "src": "charlie", "dst": "charlie", "rc": 6, "t_start": 39.2, "t_end": 40.8,
            "stderr_tail": "x running but not responding (pid 1): it did not answer on its control socket"}
    bh = [{"step": {"fault": "sig.blackhole", "target": "charlie"}, "start": 4.9, "end": 54.6}]
    assert judge_local_status(st_r, bh)[0]["oracle"] == "O3b-unresponsive-during-network-fault"
    fr = bh + [{"step": {"fault": "proc.freeze", "target": "charlie"}, "start": 10.7, "end": 72.9}]
    assert judge_local_status(st_r, fr) == [], "a frozen daemon is allowed to not respond"
    ex = dict(blamed, op="exec", src="bravo", dst="alpha", stderr_tail="Error: no answer from 'alpha' - it may be "
              "unresponsive or running a build without exec", dst_signaling_after="connected")
    assert judge_diagnosis(dict(ex, dst="bravo"), part)[0]["oracle"] == "O9-misdiagnosis"
    # The adaptive quiet window, on a fake clock and fake counters.
    def storm(series: list[dict]) -> dict:
        t = [0.0]
        it = iter(series)
        last = [None]

        def counts():
            try:
                last[0] = next(it)
            except StopIteration:
                pass
            return last[0]
        return storm_window(None, poll=1.0, clock=lambda: t[0],
                           sleep=lambda s: t.__setitem__(0, t[0] + s), counts=counts)
    z = {"alpha": 0, "bravo": 0, "charlie": 0}
    r = storm([z] * 40)
    assert r["ended"] == "quiet" and r["watched_s"] == STORM_QUIET_EXIT, r
    one = [z] * 5 + [dict(z, bravo=1)] * 40          # any attempt: the full window
    r = storm(one)
    assert r["ended"] == "full" and r["watched_s"] == STORM_WINDOW and r["syns"]["bravo"] == 1, r
    steady = [dict(z, charlie=i) for i in range(40)]  # 1 per second: over the line at 9
    r = storm(steady)
    assert r["ended"] == "over" and r["syns"]["charlie"] == STORM_MAX_CONNECTS + 1, r
    late = [z] * 12 + [dict(z, alpha=20)] * 30       # silent 10 s, then a burst: the documented blind spot
    assert storm(late)["ended"] == "quiet"
    # Overlapping server.down: one stop, ONE start, after the last heal.
    calls = []
    fw = World.__new__(World)
    fw.server_down, fw.k = 0, 0
    fw.backend_stop = lambda: calls.append("stop")
    fw.backend_start = lambda: calls.append("start")
    fw.backend_healthy = lambda: False
    a1 = apply_fault(fw, {"fault": "server.down", "at": 0, "dur": 9}, "t1")
    a2 = apply_fault(fw, {"fault": "server.down", "at": 1, "dur": 2}, "t2")
    a2.heal()
    assert calls.count("start") == 0, calls
    a1.heal()
    assert calls.count("start") == 1 and fw.server_down == 0, calls
    # Worlds never share a name, address, port or chain.
    ws = [World.__new__(World) for _ in range(3)]
    for k, x in enumerate(ws):
        x.k, x.net, x.port = k, 90 + k, BASE_PORT + k
    names = [(x.ns(d), x.veth_root(d), x.veth_dev(d), x.dev_ip(d), x.gw_ip(d)) for x in ws for d in DEVICES]
    flat = [n for t in names for n in t]
    assert len(flat) == len(set(flat)) and all(len(n) <= 15 for t in names for n in t[:3]), names
    assert len({x.chain(r) for x in ws for r, _ in CHAINS}) == 3 * len(CHAINS)
    assert re.search(r"LOOP-BUDGET-EXCEEDED (\d+) (\S+)",
                     "2026-11-25T23:01:02Z LOOP-BUDGET-EXCEEDED 2007 handler/Control:file-end slowest_ms=2007 budget_ms=1000").groups() == ("2007", "handler/Control:file-end")
    selftest_visitors()
    selfmsg = dict(blamed, src="alpha", dst="charlie", stderr_tail="charlie did not appear on the tunlion server "
                   "in time, but this machine's own connection to the server is slow (connecting took 23.1 s), "
                   "so charlie may be fine")
    own = [{"step": {"fault": "net.impair", "target": "alpha"}, "start": 0.0, "end": 80.0}]
    assert judge_diagnosis(selfmsg, own) == [], "a true self-blame is the right diagnosis"
    other = [{"step": {"fault": "net.impair", "target": "bravo"}, "start": 0.0, "end": 80.0}]
    assert judge_diagnosis(selfmsg, other)[0]["oracle"] == "O9-misdiagnosis", "blaming a healthy own link is wrong"
    # Overlapping impairments on one device: the stack logic, without tc.
    class _W:
        pass
    _w = _W()
    stacks = _w.__dict__.setdefault("netem_stacks", {})
    st_ = stacks.setdefault("charlie", [])
    t1, t2 = object(), object()
    st_ += [(t1, ["loss", "20%"]), (t2, ["duplicate", "5%"])]
    st_[:] = [(t, sp) for t, sp in st_ if t is not t1]
    assert st_ and st_[-1][1] == ["duplicate", "5%"] and not any(t is t1 for t, _ in st_), "first heal leaves the second"
    for p in sorted((HERE / "corpus").glob("*.json")) + sorted((HERE / "corpus-grown").glob("*.json")):
        s = json.loads(p.read_text())
        assert s.get("version") == 1 and s["steps"], p
        check_visits(s)
        for st in s["steps"]:
            assert ("fault" in st) != ("op" in st), (p, st)
            if "fault" in st:
                assert st["fault"] in FAULTS, (p, st)
            else:
                assert st["op"] in OPS + ["visit"], (p, st)
    selftest_save_finding()
    print("selftest ok")
    return 0


def mem_available_mib() -> int:
    for ln in Path("/proc/meminfo").read_text().splitlines():
        if ln.startswith("MemAvailable:"):
            return int(ln.split()[1]) // 1024
    return 0


def default_worlds() -> int:
    """Measured on the 4-core / 16 GB lease runner (see the throughput
    commit): about 2 worlds per core keeps the machine far from saturated,
    and a world needs well under 1 GiB."""
    cpus = os.cpu_count() or 1
    return max(1, min(MAX_SLOTS, 2 * cpus, mem_available_mib() // 1024))


class Sampler:
    """Machine load while the campaign runs: the evidence for the world
    count, and a warning sign if timing oracles start firing under load."""

    def __init__(self, every: float = 5.0):
        self.every, self.samples = every, []
        self.done = threading.Event()
        self.t = threading.Thread(target=self._run, daemon=True)

    @staticmethod
    def _cpu() -> tuple[int, int]:
        f = [int(x) for x in Path("/proc/stat").read_text().splitlines()[0].split()[1:]]
        idle = f[3] + (f[4] if len(f) > 4 else 0)
        return sum(f), idle

    def _run(self) -> None:
        last = self._cpu()
        while not self.done.wait(self.every):
            now = self._cpu()
            tot, idle = now[0] - last[0], now[1] - last[1]
            last = now
            self.samples.append({"busy": round(100 * (1 - idle / tot), 1) if tot else 0.0,
                                 "load1": float(Path("/proc/loadavg").read_text().split()[0]),
                                 "mem_avail_mib": mem_available_mib()})

    def summary(self) -> dict:
        s = self.samples
        if not s:
            return {}
        busy = sorted(x["busy"] for x in s)
        return {"samples": len(s), "cpu_busy_mean": round(sum(busy) / len(busy), 1),
                "cpu_busy_p95": busy[int(0.95 * (len(busy) - 1))], "cpu_busy_max": busy[-1],
                "load1_max": max(x["load1"] for x in s), "mem_avail_min_mib": min(x["mem_avail_mib"] for x in s),
                "cpus": os.cpu_count()}


def acquire_slots(n: int) -> list[tuple[int, object]]:
    """Up to n free world slots. Holds the old single-world lock SHARED, so a
    campaign of the old version (which took it exclusively and reaped every
    /tmp/chz.* daemon) cannot run beside this one."""
    import fcntl
    legacy = open("/run/tunlion-chaos.lock", "w")
    try:
        fcntl.flock(legacy, fcntl.LOCK_SH | fcntl.LOCK_NB)
    except BlockingIOError:
        raise Refused("a single-world chaos campaign holds /run/tunlion-chaos.lock")
    got = [(-1, legacy)]
    for k in range(MAX_SLOTS):
        if len(got) > n:
            break
        f = open(f"/run/tunlion-chaos.slot{k}.lock", "w")
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            got.append((k, f))
        except BlockingIOError:
            f.close()
    return got


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["canary", "replay", "explore", "hookcheck", "selftest"])
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--bin", type=Path, default=REPO / "target" / "release" / "tunlion")
    ap.add_argument("--out", type=Path, default=Path("chaos-out"))
    ap.add_argument("--python", default=os.environ.get("TUNLION_TEST_VENV", sys.executable))
    ap.add_argument("--budget-min", type=float, default=30.0)
    ap.add_argument("--seed", type=int, default=int(time.time()))
    ap.add_argument("--repeat", type=int, default=1, help="replay: run each schedule N times and report the rate")
    ap.add_argument("--worlds", type=int, default=0,
                    help="independent worlds run at once (0: by machine size, see default_worlds)")
    ap.add_argument("--skip-canary", action="store_true", help="local debugging only; CI never passes this")
    a = ap.parse_args()
    if a.command == "selftest":
        return cmd_selftest()

    a.out.mkdir(parents=True, exist_ok=True)
    worlds: list[World] = []
    sampler = Sampler()
    t_start = time.monotonic()
    canary_rc = [0]
    try:
        if os.geteuid() != 0:
            raise Refused("must run as root (network namespaces, tc, iptables)")
        want = 1 if a.command == "canary" else (a.worlds or default_worlds())
        slots = acquire_slots(want)
        if len(slots) == 1:
            raise Refused(f"no free world slot (all {MAX_SLOTS} /run/tunlion-chaos.slot*.lock held)")
        if len(slots) - 1 < want:
            log(f"only {len(slots) - 1} of {want} world slots free; running with those")
        bin_path = a.bin.resolve()
        for k, lockf in slots[1:]:
            work = Path(tempfile.mkdtemp(prefix=f"chz.w{k}.", dir="/tmp"))
            w = World(bin_path, work, a.python, k, lockf)
            w.out = a.out
            worlds.append(w)
        w0 = worlds[0]
        log(f"binary {w0.bin} sha256 {w0.bin_sha[:16]} (asserted unchanged before every run); "
            f"{len(worlds)} world(s): slots {[w.k for w in worlds]}; {os.cpu_count()} cpus, "
            f"{mem_available_mib()} MiB available")
        sampler.t.start()

        def bring_up(w: World) -> None:
            w.preconditions()
            w.net_up()
            w.setup()
        run_worlds(worlds, bring_up)
        if a.command == "canary":
            return cmd_canary(w0, a.out)

        def canary(w: World) -> None:
            rc = cmd_canary(w, a.out)
            if rc:
                canary_rc[0] = rc
                for x in worlds:
                    x.stop.set()
        first = None if a.skip_canary else canary
        corpus = []
        # replay: the curated regression set. explore: also the queue grown by
        # earlier campaigns, so each campaign starts where the last one stopped.
        default = [HERE / "corpus"] + ([HERE / "corpus-grown"] if a.command == "explore" else [])
        for f in a.files or default:
            corpus += sorted(f.glob("*.json")) if f.is_dir() else [f]
        if not corpus:
            raise Refused("no schedules to run")
        if a.command == "replay":
            rc = cmd_replay(worlds, a.out, corpus, a.repeat, first)
        elif a.command == "hookcheck":
            rc = cmd_hookcheck(worlds, a.out, a.repeat if a.repeat > 1 else 3, first)
        else:
            rc = cmd_explore(worlds, a.out, a.budget_min * 60, a.seed, corpus, first)
        # The canary ran beside the work: a broken instrument voids it all.
        return canary_rc[0] or rc
    except Refused as e:
        log(f"REFUSED: {e}")
        return canary_rc[0] or 3
    except Exception:
        # Exit 1 means "tunlion has a bug". A crash in this file must never
        # be read that way.
        import traceback
        traceback.print_exc()
        log("HARNESS ERROR: chaos.py itself failed; this is not a tunlion finding")
        return 5
    finally:
        sampler.done.set()
        wall = time.monotonic() - t_start
        try:
            (a.out / "throughput.json").write_text(json.dumps({
                "command": a.command, "worlds": len(worlds), "slots": [w.k for w in worlds],
                "wall_s": round(wall, 1), "schedule_runs": _run_seq[0],
                "runs_per_hour": round(3600 * _run_seq[0] / wall, 1) if wall > 0 else None,
                "resources": sampler.summary()}, indent=2))
        except Exception:
            pass
        for w in worlds:
            try:
                shutil.copytree(w.work / "dev", a.out / "last-run-dev" / f"w{w.k}", dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("*.sock", "home", "snapshot"))
            except Exception:
                pass
            w.teardown()


if __name__ == "__main__":
    sys.exit(main())
