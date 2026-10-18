#!/usr/bin/env python3
"""Durability soak for shell/link resilience — TEST-ONLY.

This harness exists to make one class of report measurable instead of anecdotal:
a native shell that reconnects by itself (the owner reported roughly every two
minutes), or a live shell that dies when a second connection/exec uses the same
peer. #498 fixed one transport-teardown race; this is the repeatable evidence
that the fix holds under concurrent use, and the regression detector for it.

It is deliberately a PROCESS-level, single-host harness. It never modifies
production code, never uses the real config dir, never starts a system service,
and never touches the host network beyond loopback. It is manual-dispatch in CI
because a 2-5 minute soak does not belong on every pull request.

WHAT IT ASSERTS (all failures, never skips)
  stable     Two native shells are alive at once in opposite directions. Over a
             bounded idle+active window, neither daemon logs an unsolicited PTY
             reattach, link drop, mux teardown, supersede, or warm-hold
             re-establish, and neither client logs a reconnect. Both remote shell
             PIDs are unchanged at the end.
  concurrent A one-shot `exec` in EACH direction and a real `forward` stream run
             while both shells are live. They must succeed, both shells must keep
             the same PID, and the daemons must stay quiet (no reattach/drop).
  signaling  The existing flaky_proxy fixture severs the signaling socket (not the
             data path) while both shells stay active. The daemons must report a
             reconnected socket, keep the shells (no reattach/drop), and the
             post-heal idle window must not reap the link.
  drop       An INTENTIONAL initiator-daemon restart destroys the link but leaves
             the peer (where the PTY lives) running. The client must reconnect and
             reattach the SAME session: same remote PID, same shell variable state,
             /proc/<pid> alive, and a `pty REATTACHED` line at the peer.

HOW LOSS IS INDUCED
  - signaling: runner/sim/flaky_proxy.py (existing, stdlib-only) in front of the
    local backend, toggled by its down-flag. This is a real socket sever.
  - link/session: SIGTERM the initiator daemon process. The remote PTY and its
    process stay on the peer daemon; the client's own reconnect loop has to get
    back to it. This is stronger and more deterministic than a lucky packet drop,
    and it exercises the same reattach path a WAN loss uses.

WHAT IT DOES NOT COVER
  - No NAT, TURN, or asymmetric routing. Everything is loopback on one Linux box.
  - No Windows<->Linux run. The PTY portability layer has its own tests, but a
    real Windows peer over a real network is still a manual matrix (documented in
    docs/testing/durability-soak.md).
  - It is not a 24h soak. It is bounded and repeatable; `--runs N` repeats it.

Stdlib only. Linux only (pty, process groups, SIGTERM semantics). Usage:

  TUNLION_BIN=/path/to/tunlion python3 cli/tests/durability_soak.py \
      --stable-secs 150 --runs 2

See docs/testing/durability-soak.md for artifacts and the manual matrix.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import errno
import hashlib
import json
import os
import platform
import pty
import re
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_DIR = ROOT / "cli"
BACKEND_DIR = ROOT / "backend"
PROXY = ROOT / "runner" / "sim" / "flaky_proxy.py"
# Workspace builds land at <root>/target; the pre-workspace layout had
# cli/target. Prefer the current one, keep the old as a fallback for local
# checkouts that still use it.
DEFAULT_BIN = ROOT / "target" / "release" / "tunlion"
LEGACY_BIN = CLI_DIR / "target" / "release" / "tunlion"

# Daemon log lines that mean a live shell/link was disturbed. Each is an
# assertion failure in a window where nothing was intentionally disturbed.
# Keep these as source-level phrases, not line numbers: a log line that moves
# is still the same claim, and a renamed line should be a visible diff here.
QUIET_DAEMON = (
    (r"pty REATTACHED", "unsolicited PTY reattach"),
    (r"pty reattach refused", "PTY reattach refused"),
    (r"drop_link\(", "link drop (drop_link)"),
    (r"closing streams", "live mux torn down"),
    (r"link went idle after deferred leave, dropping now", "deferred link reaped"),
    (r"reconnected, superseding old link", "same-device supersede"),
    (r"warm pty link to .* died", "warm PTY link died"),
    (r"warm link to .* is a zombie", "warm link zombie"),
    (r"warm-hold: will establish", "warm-hold re-establish"),
    (r"warm-hold: failed to connect", "warm-hold connect failure"),
    (r"re-establish for .* failed", "re-establish failure"),
    (r"tunnel (failed|closed|disconnected), closing streams", "transport teardown"),
)

QUIET_CLIENT = (
    # Current copy (the native PTY reconnects silently during a drop; the
    # forward/mesh path uses the status line). Kept alongside the older
    # spellings so a future rename is a visible diff, not a silent blind spot.
    (r"tunlion: link to .* lost, reconnecting", "client link-drop reconnect"),
    (r"tunlion: shell session ended after the reconnect window expired", "client reconnect window expired"),
    (r"\[filament: link dropped, reconnecting", "client link-drop reconnect (old spelling)"),
    (r"\[filament: session expired, reconnect window passed", "client reconnect window expired (old spelling)"),
)

# `exec` and cold `forward` use a short-lived client link of their own. When
# that process exits, the peer daemon legitimately logs a drop for IT. Those
# lines are not evidence that a live shell was torn down, so the concurrent and
# flap stages assert the PTY/session-specific signals plus unchanged shell PIDs,
# not every generic link drop. The stable stage has no such extra clients and
# keeps the full list.
QUIET_DAEMON_SESSION = (
    (r"pty REATTACHED", "unsolicited PTY reattach"),
    (r"pty reattach refused", "PTY reattach refused"),
    (r"warm pty link to .* died", "warm PTY link died"),
    (r"warm link to .* is a zombie", "warm link zombie"),
    (r"reconnected, superseding old link", "same-device supersede"),
    (r"warm-hold: will establish", "warm-hold re-establish"),
    (r"warm-hold: failed to connect", "warm-hold connect failure"),
    (r"re-establish for .* failed", "re-establish failure"),
)

# During the intentional signaling flap, a peer-left can legitimately be
# deferred while the data channel keeps flowing. The drop itself is still not
# allowed; only these informational lines are excused.
FLAP_EXTRA_ALLOWED = (
    r"signaling left, data channel still flowing, deferring drop",
    r"signaling reconnected",
    r"re-announcing presence",
    r"reconnected, keeping active link",
    r"ignore(?:d|ing) losing transport state",
)


class PrereqError(RuntimeError):
    """A prerequisite is missing. This is exit 2, never a skip."""


class Failure(RuntimeError):
    """The product under test failed an assertion. Exit 1."""


def log(msg: str) -> None:
    stamp = time.strftime("%H:%M:%S")
    print(f"[durability {stamp}] {msg}", flush=True)


def tail(path: Path, lines: int = 40) -> str:
    try:
        data = path.read_bytes().decode("utf-8", "replace").splitlines()
    except OSError as e:
        return f"<cannot read {path}: {e}>"
    return "\n".join(data[-lines:])


def read_from(path: Path, start: int, end: int | None = None) -> str:
    try:
        with path.open("rb") as f:
            f.seek(start)
            data = f.read() if end is None else f.read(max(0, end - start))
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


def wait_regex(
    path: Path,
    pattern: str,
    start: int = 0,
    timeout: float = 30.0,
    proc: subprocess.Popen | None = None,
    label: str = "pattern",
) -> re.Match | None:
    """Poll a growing log for a pattern. Condition-based, not a fixed sleep.

    Returns None on timeout (or if `proc` exits first); callers turn that into a
    FAIL with the log tail. Never treats absence as success.
    """
    rx = re.compile(pattern, re.MULTILINE)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        m = rx.search(read_from(path, start))
        if m:
            return m
        if proc is not None and proc.poll() is not None:
            return None
        time.sleep(0.1)
    return None


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def proc_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


class Daemon:
    """One `tunlion up` process in an isolated config dir, with an append log."""

    def __init__(self, run: "Run", name: str, cfg: Path, drop: Path):
        self.run = run
        self.name = name
        self.display_name = f"soak-{name}"
        self.cfg = cfg
        self.drop = drop
        self.log_path = run.dir / f"daemon-{name}.log"
        self.proc: subprocess.Popen | None = None
        self._fh = None

    def start(self) -> None:
        self.cfg.mkdir(parents=True, exist_ok=True)
        self.drop.mkdir(parents=True, exist_ok=True)
        self._fh = self.log_path.open("ab", buffering=0)
        cmd = [
            str(self.run.bin),
            "--server",
            self.run.server,
            "up",
            "--dir",
            str(self.drop),
            "--userspace",
            "--no-proxy-fallback",
        ]
        env = self.run.daemon_env(self)
        log(f"{self.name}: starting {' '.join(cmd[1:])}")
        self.proc = subprocess.Popen(
            cmd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=self._fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # The control socket binding is the daemon's own "serving" signal
        # (#211). Waiting for the file, not for a fixed sleep, is what keeps a
        # slow CI box from racing the first shell.
        sock = self.cfg / "control.sock"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise Failure(
                    f"{self.name} daemon exited during startup (rc={self.proc.returncode})\n"
                    f"--- daemon-{self.name}.log ---\n{tail(self.log_path)}"
                )
            if sock.exists():
                break
            time.sleep(0.1)
        else:
            raise Failure(
                f"{self.name} daemon never bound control.sock in 45s\n"
                f"--- daemon-{self.name}.log ---\n{tail(self.log_path)}"
            )
        # Give the signaling join a beat, but do not depend on it: clients wait
        # on their own establishment markers below.
        wait_regex(self.log_path, r"watching for|tunlion up,", timeout=20, proc=self.proc)
        log(f"{self.name}: daemon up (pid {self.proc.pid})")

    def stop(self, grace: float = 10.0, kill_group: bool = False) -> None:
        if self.proc is None or self.proc.poll() is not None:
            self._close_fh()
            return
        log(f"{self.name}: stopping daemon (pid {self.proc.pid})")
        try:
            if kill_group:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            else:
                self.proc.terminate()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            log(f"{self.name}: daemon ignored SIGTERM; SIGKILL")
            try:
                if kill_group:
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                else:
                    self.proc.kill()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._close_fh()

    def _close_fh(self) -> None:
        if self._fh is not None:
            try:
                self._fh.close()
            except OSError:
                pass
            self._fh = None

    def offset(self) -> int:
        try:
            return self.log_path.stat().st_size
        except OSError:
            return 0

    def force_restart_setup(self) -> None:
        """Remove stale runtime files after an intentional SIGTERM.

        The graceful path removes these itself; a SIGKILL or a crash leaves a
        stale control socket/pidfile. Removing them is a harness setup action,
        not a product repair.
        """
        for name in ("control.sock", "up.pid"):
            try:
                (self.cfg / name).unlink()
            except FileNotFoundError:
                pass
            except OSError as e:
                log(f"{self.name}: could not remove stale {name}: {e}")


class PtySession:
    """A real `tunlion shell` driven through a real PTY.

    The child gets the pty slave as stdin/stdout/stderr, so `is_terminal()` is
    true and the client takes its interactive raw-mode/reconnect path. Output is
    copied byte-for-byte to a transcript file; assertions poll that file rather
    than sleeping and hoping.
    """

    def __init__(self, run: "Run", label: str, args: list[str], env: dict[str, str]):
        self.run = run
        self.label = label
        self.args = args
        self.env = env
        self.transcript = run.dir / f"shell-{label}.log"
        self.master, slave = pty.openpty()
        self._set_winsize(120, 40)
        self._reader: threading.Thread | None = None
        self._eof = threading.Event()
        self.proc = subprocess.Popen(
            args,
            env=env,
            stdin=slave,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            close_fds=True,
        )
        os.close(slave)
        self._out = self.transcript.open("wb", buffering=0)
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()
        log(f"{label}: shell client pid {self.proc.pid}")

    def _set_winsize(self, cols: int, rows: int) -> None:
        import fcntl
        import struct
        import termios

        try:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        except OSError:
            pass

    def _read_loop(self) -> None:
        try:
            while True:
                try:
                    data = os.read(self.master, 1 << 16)
                except OSError as e:
                    if e.errno == errno.EIO:
                        break
                    break
                if not data:
                    break
                try:
                    self._out.write(data)
                except OSError:
                    break
        finally:
            self._eof.set()
            try:
                self._out.close()
            except OSError:
                pass

    def size(self) -> int:
        try:
            return self.transcript.stat().st_size
        except OSError:
            return 0

    def text_from(self, start: int) -> str:
        return read_from(self.transcript, start)

    def write(self, text: str) -> None:
        if self.proc.poll() is not None:
            raise Failure(
                f"{self.label}: shell client exited (rc={self.proc.returncode}) before input\n"
                f"--- transcript ---\n{tail(self.transcript)}"
            )
        data = text.encode()
        while data:
            try:
                n = os.write(self.master, data)
            except OSError as e:
                raise Failure(
                    f"{self.label}: writing to shell client failed: {e}\n"
                    f"--- transcript ---\n{tail(self.transcript)}"
                )
            data = data[n:]

    def command(self, line: str, pattern: str, timeout: float = 30.0) -> re.Match | None:
        start = self.size()
        self.write(line + "\r")
        return wait_regex(
            self.transcript,
            pattern,
            start=start,
            timeout=timeout,
            proc=self.proc,
            label=f"{self.label}:{pattern}",
        )

    def activity(self, nonce: str, timeout: float = 20.0) -> bool:
        # The typed line contains the literal `$$`, so the echoed input cannot
        # satisfy the digit-only output pattern.
        return (
            self.command(
                f'echo "DUR_ACT_{nonce}_$$_END"',
                rf"DUR_ACT_{re.escape(nonce)}_(\d+)_END",
                timeout=timeout,
            )
            is not None
        )

    def pid(self, timeout: float = 30.0) -> int:
        m = self.command('echo "DUR_PID_$$_END"', r"DUR_PID_(\d+)_END", timeout=timeout)
        if not m:
            raise Failure(
                f"{self.label}: no remote PID marker in {timeout}s\n"
                f"--- transcript ---\n{tail(self.transcript)}"
            )
        return int(m.group(1))

    def state(self, nonce: str, timeout: float = 30.0) -> bool:
        return (
            self.command(
                'echo "DUR_STATE_${DUR_STATE}_END"',
                rf"DUR_STATE_({re.escape(nonce)})_END",
                timeout=timeout,
            )
            is not None
        )

    def close(self, grace: float = 12.0) -> None:
        if self.proc.poll() is None:
            try:
                self.write("exit\r")
            except Failure:
                pass
            try:
                self.proc.wait(timeout=grace)
            except subprocess.TimeoutExpired:
                self.kill()
        self._cleanup()

    def kill(self) -> None:
        if self.proc.poll() is None:
            try:
                self.proc.kill()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        self._cleanup()

    def _cleanup(self) -> None:
        # Idempotent: teardown may run after close(), and closing an already
        # closed fd number is not an OSError waiting to happen — the number may
        # since have been reused by a socket or log file.
        if self.master < 0:
            return
        fd, self.master = self.master, -1
        try:
            os.close(fd)
        except OSError:
            pass


class EchoServer:
    """Tiny loopback TCP echo target for the forward gate."""

    def __init__(self, port: int):
        self.port = port
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", port))
        self._sock.listen(8)
        self._sock.settimeout(0.25)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._one, args=(conn,), daemon=True).start()

    def _one(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            while not self._stop.is_set():
                data = conn.recv(4096)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass


class Run:
    def __init__(self, base: Path, bin_path: Path, args: argparse.Namespace, index: int):
        self.base = base
        self.bin = bin_path
        self.args = args
        self.index = index
        stamp = time.strftime("%Y%m%d-%H%M%S")
        self.dir = base / f"run-{index}-{stamp}-{os.getpid()}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.checks: list[dict] = []
        self.evidence: dict = {}
        self._harness_log = (self.dir / "harness.log").open("a", buffering=1)
        self.procs: list[subprocess.Popen] = []
        self.daemons: list[Daemon] = []
        self.sessions: list[PtySession] = []
        self.backend: subprocess.Popen | None = None
        self.proxy: subprocess.Popen | None = None
        self.echo: EchoServer | None = None
        self.forward_proc: subprocess.Popen | None = None
        self.ports: dict[str, int] = {}

    # ---- logging / checks -------------------------------------------------

    def note(self, msg: str) -> None:
        log(msg)
        self._harness_log.write(f"[{time.strftime('%H:%M:%S')}] {msg}\n")
        self._harness_log.flush()

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        entry = {"name": name, "ok": bool(ok), "detail": detail}
        self.checks.append(entry)
        if ok:
            print(f"PASS: {name}", flush=True)
        else:
            print(f"FAIL: {name}\n{detail}", flush=True)
        return ok

    # ---- environment ------------------------------------------------------

    def base_env(self, cfg: Path, name: str) -> dict[str, str]:
        env = os.environ.copy()
        env.update(
            {
                "TUNLION_CONFIG_DIR": str(cfg),
                "TUNLION_NAME": name,
                "TUNLION_LOG": "debug",
                "NO_COLOR": "1",
                "TERM": "dumb",
                "RUST_BACKTRACE": "1",
                # Never touch the operator's real home from a daemon that can
                # serve a PTY or arm ssh trust. Everything lands in the run dir.
                "HOME": str(cfg),
                "USERPROFILE": str(cfg),
                # Pin the direct-QUIC candidate set to loopback. WebRTC still
                # races its own candidates, so the #498 losing-transport path
                # is exercised; pinning only keeps a multi-homed CI box from
                # failing to establish on an interface the peer cannot carry.
                "TUNLION_DIRECT_LOOPBACK_ONLY": "1",
            }
        )
        # Do not inherit fault/cap knobs from the developer's shell: this run
        # must exercise the shipped defaults, not a half-configured gate.
        for key in (
            "TUNLION_UID",
            "TUNLION_CAP_AUTHORITATIVE",
            "TUNLION_NO_WARM_REUSE",
            "TUNLION_DIRECT_TEST_BLOCK",
        ):
            env.pop(key, None)
        return env

    def daemon_env(self, d: Daemon) -> dict[str, str]:
        env = self.base_env(d.cfg, d.display_name)
        env.update(
            {
                "TUNLION_L2": "1",
                "TUNLION_SHELL": "/bin/bash",
                "TERM": "dumb",
            }
        )
        return env

    def client_env(self, cfg: Path, name: str) -> dict[str, str]:
        env = self.base_env(cfg, name)
        env["TERM"] = "xterm-256color"
        # TRACE is used only to prove the shell took the DAEMON's warm link
        # (`reusing warm link ... for pty`), which the intentional-drop stage
        # depends on. The trace call sites are establishment/signal-scoped, not
        # per-frame, so this does not turn the soak into a firehose.
        env["TUNLION_LOG"] = "trace"
        return env

    def run_cli(self, cfg: Path, name: str, argv: list[str], timeout: float = 45.0) -> subprocess.CompletedProcess:
        cmd = [str(self.bin), "--server", self.server] + argv
        self.note(f"cli({name}): {' '.join(argv)}")
        cp = subprocess.run(
            cmd,
            env=self.client_env(cfg, name),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        if cp.returncode != 0:
            raise Failure(
                f"cli({name}) {' '.join(argv)} failed rc={cp.returncode}\n"
                f"--- stdout ---\n{cp.stdout}\n--- stderr ---\n{cp.stderr}"
            )
        return cp

    def wait_http(self, url: str, timeout: float = 40.0) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=2) as r:
                    if r.status == 200:
                        return
            except Exception as e:  # noqa: BLE001 - health probe, reported below
                last = str(e)
            time.sleep(0.2)
        raise PrereqError(f"backend never became healthy at {url}: {last}")

    # ---- fixture setup ----------------------------------------------------

    def start_fixture(self) -> None:
        self.ports["backend"] = free_port()
        self.ports["proxy"] = free_port()
        while self.ports["proxy"] == self.ports["backend"]:
            self.ports["proxy"] = free_port()
        self.backend_url = f"http://127.0.0.1:{self.ports['backend']}"
        self.server = f"http://127.0.0.1:{self.ports['proxy']}"
        self.down_flag = self.dir / "signaling-down"

        backend_log = (self.dir / "backend.log").open("ab", buffering=0)
        env = os.environ.copy()
        env.update(
            {
                "PORT": str(self.ports["backend"]),
                "FIL_ASYNC_MODE": "eventlet",
                "FIL_SELF_MONKEYPATCH": "1",
                "FIL_CLAIM_LIMIT": "1000000",
                "FIL_PING_TIMEOUT": "120",
                "FIL_PING_INTERVAL": "25",
            }
        )
        self.backend = subprocess.Popen(
            [sys.executable, "app.py"],
            cwd=str(BACKEND_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=backend_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.procs.append(self.backend)
        self.wait_http(f"{self.backend_url}/api/health")
        self.note(f"backend healthy on {self.backend_url}")

        proxy_log = (self.dir / "proxy.log").open("ab", buffering=0)
        self.proxy = subprocess.Popen(
            [
                sys.executable,
                str(PROXY),
                "--listen",
                f"127.0.0.1:{self.ports['proxy']}",
                "--target",
                f"127.0.0.1:{self.ports['backend']}",
                "--down-flag",
                str(self.down_flag),
            ],
            cwd=str(ROOT),
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=proxy_log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        self.procs.append(self.proxy)
        if not wait_regex(self.dir / "proxy.log", r"listening on", timeout=20, proc=self.proxy):
            raise PrereqError(
                "flaky signaling proxy did not start\n"
                f"--- proxy.log ---\n{tail(self.dir / 'proxy.log')}"
            )
        self.note(f"signaling proxy on {self.server} -> {self.backend_url}")

        self.cfg_a = self.dir / "cfg-a"
        self.cfg_b = self.dir / "cfg-b"
        self.cfg_a.mkdir()
        self.cfg_b.mkdir()
        secret = secrets.token_hex(32)
        (self.cfg_a / "devices.json").write_text(
            json.dumps([{"name": "soak-b", "secret": secret}]) + "\n"
        )
        (self.cfg_b / "devices.json").write_text(
            json.dumps([{"name": "soak-a", "secret": secret}]) + "\n"
        )
        # Same-owner fleet pair: a reciprocal pair secret, no invitation/cert
        # ceremony. This is the existing shell-gates/exec-gates topology.

        self.daemon_a = Daemon(self, "a", self.cfg_a, self.dir / "drop-a")
        self.daemon_b = Daemon(self, "b", self.cfg_b, self.dir / "drop-b")
        self.daemons = [self.daemon_a, self.daemon_b]
        self.daemon_a.start()
        self.daemon_b.start()

        # Grant both directions explicitly. This is offline local state; it does
        # not require an owner identity and is exactly what shell-gates does.
        self.run_cli(self.cfg_b, "b", ["grant", "soak-a", "shell"], timeout=30)
        self.run_cli(self.cfg_a, "a", ["grant", "soak-b", "shell"], timeout=30)
        for label, cfg, peer in (("a", self.cfg_a, "soak-b"), ("b", self.cfg_b, "soak-a")):
            raw = (cfg / "devices.json").read_text()
            if '"shell"' not in raw:
                raise Failure(f"grant did not persist shell for {peer}: {raw}")
        self.note("both directions granted shell")
        self.wait_warm_links()

    def wait_warm_links(self) -> None:
        """Wait until each daemon holds a link, BEFORE any shell starts.

        The intentional-drop stage kills the initiator daemon, so the shell MUST
        be riding that daemon's warm link. A shell that cold-established from
        its own process would survive the kill and make the test meaningless
        (or, worse, pass without exercising reattach). We therefore refuse to
        start rather than silently measuring the wrong path.

        `warm-hold: established connection` is the daemon's own proactive link;
        `warm-hold: skip '<peer>' (link alive...)` also proves a live link
        already exists (the peer connected first).
        """
        pairs = (("a", "soak-b", self.daemon_a), ("b", "soak-a", self.daemon_b))

        def wait_one(label: str, peer: str, d: Daemon) -> None:
            pat = rf"warm-hold: (?:established connection to|skip) '{re.escape(peer)}'"
            m = wait_regex(d.log_path, pat, timeout=75, proc=d.proc)
            if not m:
                raise Failure(
                    f"daemon {label} never held a warm link to {peer}; refusing to "
                    "start shells on a cold path because the intentional-drop stage "
                    "would then kill the wrong side\n"
                    f"--- daemon-{label}.log ---\n{tail(d.log_path)}"
                )

        # Wait for BOTH at once, not one after the other: a relay link that has
        # been idle past the warm-reuse staleness window is deliberately not
        # reused, and a sequential wait would add that idle time to the second
        # daemon's link.
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
            futs = [ex.submit(wait_one, label, peer, d) for label, peer, d in pairs]
            for f in futs:
                f.result()
        for label, peer, _d in pairs:
            self.note(f"daemon {label}: warm link to {peer} is present")

    # ---- shell helpers ----------------------------------------------------

    def new_shell(self, label: str, cfg: Path, name: str, peer: str) -> PtySession:
        env = self.client_env(cfg, name)
        # Pin the session id so the intentional daemon restart reattaches THIS
        # shell deterministically. The acceptor still scopes it to the verified
        # device; this is the same mechanism a later `tunlion shell` uses to
        # pick a detached session back up.
        session_id = f"soak-{label}-{secrets.token_hex(4)}"
        env["TUNLION_SHELL_SESSION"] = session_id
        s = PtySession(
            self,
            label,
            [str(self.bin), "--server", self.server, "shell", peer],
            env,
        )
        s.peer = peer
        s.session_id = session_id
        self.sessions.append(s)
        return s

    def establish(self, s: PtySession, state_nonce: str) -> int:
        s.write(f"export DUR_STATE={state_nonce}\r")
        pid = s.pid(timeout=self.args.connect_timeout)
        if not s.state(state_nonce, timeout=20):
            raise Failure(
                f"{s.label}: shell state marker missing after establishment\n"
                f"--- transcript ---\n{tail(s.transcript)}"
            )
        if not proc_alive(pid):
            raise Failure(f"{s.label}: remote shell pid {pid} is not alive on this host")
        warm = re.search(
            rf"reusing warm link to '{re.escape(s.peer)}'",
            s.text_from(0),
        )
        if not warm:
            raise Failure(
                f"{s.label}: shell did not take the daemon's warm link to {s.peer}; "
                "the intentional-drop stage would kill a link this client does not use\n"
                f"--- transcript ---\n{tail(s.transcript)}"
            )
        self.note(f"{s.label}: remote shell pid {pid}, state {state_nonce}, warm link confirmed")
        return pid

    def assert_pid_state(self, s: PtySession, expected_pid: int, state_nonce: str, label: str) -> None:
        pid = s.pid(timeout=40)
        self.check(
            f"{label}: {s.label} remote shell PID unchanged ({expected_pid})",
            pid == expected_pid,
            f"expected pid {expected_pid}, got {pid}\n--- transcript ---\n{tail(s.transcript)}",
        )
        self.check(
            f"{label}: {s.label} remote shell state survived",
            s.state(state_nonce, timeout=20),
            f"shell variable DUR_STATE={state_nonce} not found after {label}\n"
            f"--- transcript ---\n{tail(s.transcript)}",
        )
        self.check(
            f"{label}: {s.label} remote process {expected_pid} alive",
            proc_alive(expected_pid),
            f"/proc/{expected_pid} gone",
        )

    # ---- log assertions ---------------------------------------------------

    def daemon_snapshot(self) -> dict[str, int]:
        return {d.name: d.offset() for d in self.daemons}

    def session_snapshot(self) -> dict[str, int]:
        return {s.label: s.size() for s in self.sessions}

    def violations(
        self,
        daemon_start: dict[str, int],
        client_start: dict[str, int] | None = None,
        allowed: tuple[str, ...] = (),
        daemon_patterns: tuple[tuple[str, str], ...] = QUIET_DAEMON,
    ) -> list[str]:
        out: list[str] = []
        allowed_rx = [re.compile(p) for p in allowed]
        for d in self.daemons:
            start = daemon_start.get(d.name, 0)
            text = read_from(d.log_path, start)
            for line in text.splitlines():
                if any(rx.search(line) for rx in allowed_rx):
                    continue
                for pat, why in daemon_patterns:
                    if re.search(pat, line):
                        out.append(f"{why}: daemon-{d.name}.log: {line.strip()}")
        if client_start:
            for s in self.sessions:
                start = client_start.get(s.label, 0)
                text = s.text_from(start)
                for line in text.splitlines():
                    for pat, why in QUIET_CLIENT:
                        if re.search(pat, line):
                            out.append(f"{why}: shell-{s.label}.log: {line.strip()}")
        return out

    def check_quiet(
        self,
        stage: str,
        daemon_start: dict[str, int],
        client_start: dict[str, int] | None = None,
        allowed: tuple[str, ...] = (),
        daemon_patterns: tuple[tuple[str, str], ...] = QUIET_DAEMON,
    ) -> None:
        v = self.violations(daemon_start, client_start, allowed, daemon_patterns)
        detail = ""
        if v:
            detail = f"{len(v)} unsolicited event(s):\n" + "\n".join(v[:40])
            if len(v) > 40:
                detail += f"\n... and {len(v) - 40} more"
        self.check(f"{stage}: no unsolicited reattach/drop/teardown", not v, detail)
        # Informational counts that are NOT failures on their own. #498's fix
        # legitimately logs "ignoring tunnel ... selected transport is alive".
        self.report_counts(stage, daemon_start)

    def report_counts(self, stage: str, daemon_start: dict[str, int]) -> None:
        for d in self.daemons:
            text = read_from(d.log_path, daemon_start.get(d.name, 0))
            reattach = len(re.findall(r"pty REATTACHED", text))
            drops = len(re.findall(r"drop_link\(", text))
            ignored = len(re.findall(r"ignoring tunnel .*selected transport is alive", text))
            self.note(
                f"{stage}: daemon-{d.name}: pty_reattach={reattach} "
                f"drop_link={drops} losing_candidate_ignored={ignored}"
            )
            self.evidence.setdefault("counts", {}).setdefault(stage, {})[d.name] = {
                "pty_reattach": reattach,
                "drop_link": drops,
                "losing_candidate_ignored": ignored,
            }

    # ---- scenario stages --------------------------------------------------

    def stage_stable(self, s1: PtySession, pid1: int, state1: str,
                     s2: PtySession, pid2: int, state2: str) -> None:
        total = self.args.stable_secs
        idle = int(total * 0.6)
        active = total - idle
        time.sleep(3)  # let the first prompt/replay settle before measuring
        d0 = self.daemon_snapshot()
        c0 = self.session_snapshot()
        self.note(f"stable window: {idle}s idle + {active}s active (total {total}s)")
        # Deliberate observation window, not a synchronization sleep: the failure
        # under test is a TIME-based churn, so elapsed quiet time is the input.
        deadline = time.monotonic() + idle
        while time.monotonic() < deadline:
            for s in (s1, s2):
                if s.proc.poll() is not None:
                    raise Failure(
                        f"stable: {s.label} shell exited during idle window "
                        f"(rc={s.proc.returncode})\n--- transcript ---\n{tail(s.transcript)}"
                    )
            time.sleep(0.5)
        self.note(f"stable: idle period complete ({idle}s with no input)")
        nonce = secrets.token_hex(4)
        deadline = time.monotonic() + active
        i = 0
        while time.monotonic() < deadline:
            i += 1
            for s in (s1, s2):
                if not s.activity(f"{nonce}{i}", timeout=15):
                    raise Failure(
                        f"stable: {s.label} did not answer activity probe {i}\n"
                        f"--- transcript ---\n{tail(s.transcript)}"
                    )
            time.sleep(max(0.2, min(5.0, self.args.probe_interval)))
        self.note(f"stable: {i} activity probes per shell complete")
        self.check_quiet("stable", d0, c0)
        self.assert_pid_state(s1, pid1, state1, "stable")
        self.assert_pid_state(s2, pid2, state2, "stable")

    def stage_concurrent(self, s1: PtySession, pid1: int, state1: str,
                         s2: PtySession, pid2: int, state2: str) -> None:
        d0 = self.daemon_snapshot()
        c0 = self.session_snapshot()
        marker = secrets.token_hex(6)
        reserved = set(self.ports.values())
        rport = free_port()
        while rport in reserved:
            rport = free_port()
        lport = free_port()
        while lport == rport or lport in reserved:
            lport = free_port()
        self.echo = EchoServer(rport)
        self.note(f"concurrent: echo server on 127.0.0.1:{rport}; forward lport {lport}")

        def exec_one(cfg: Path, name: str, peer: str) -> tuple[str, bool, str]:
            mk = f"DUR_EXEC_{name}_{marker}"
            try:
                cp = self.run_cli(
                    cfg,
                    name,
                    ["exec", peer, "--", "/bin/echo", mk],
                    timeout=self.args.command_timeout,
                )
                ok = mk in cp.stdout
                return (f"exec {name}->{peer}", ok, cp.stdout + cp.stderr)
            except Exception as e:  # noqa: BLE001 - reported as a failed assertion
                return (f"exec {name}->{peer}", False, str(e))

        def forward_one() -> tuple[str, bool, str]:
            fw_log = self.dir / "forward.log"
            fh = fw_log.open("ab", buffering=0)
            cmd = [
                str(self.bin),
                "--server",
                self.server,
                "forward",
                f"soak-b:{rport}",
                "--lport",
                str(lport),
            ]
            self.forward_proc = subprocess.Popen(
                cmd,
                env=self.client_env(self.cfg_a, "soak-a"),
                stdin=subprocess.DEVNULL,
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                if not wait_regex(fw_log, r"tunlion: (ready|listening)", timeout=60, proc=self.forward_proc):
                    return ("forward", False, f"forward never reported ready\n{tail(fw_log)}")
                payload = f"DUR_FWD_{marker}_END".encode()
                last = ""
                for _ in range(10):
                    try:
                        with socket.create_connection(("127.0.0.1", lport), timeout=5) as c:
                            c.sendall(payload)
                            got = b""
                            while len(got) < len(payload):
                                chunk = c.recv(4096)
                                if not chunk:
                                    break
                                got += chunk
                            if got == payload:
                                return ("forward", True, "byte-exact echo")
                            last = f"got {got!r}, want {payload!r}"
                    except OSError as e:
                        last = str(e)
                    time.sleep(0.2)
                return ("forward", False, last + "\n" + tail(fw_log))
            finally:
                if self.forward_proc.poll() is None:
                    try:
                        self.forward_proc.terminate()
                        self.forward_proc.wait(timeout=5)
                    except (OSError, subprocess.TimeoutExpired):
                        try:
                            self.forward_proc.kill()
                        except OSError:
                            pass
                try:
                    fh.close()
                except OSError:
                    pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
            futs = [
                ex.submit(exec_one, self.cfg_a, "a", "soak-b"),
                ex.submit(exec_one, self.cfg_b, "b", "soak-a"),
                ex.submit(forward_one),
            ]
            results = [f.result() for f in futs]
        for label, ok, detail in results:
            self.check(f"concurrent: {label} succeeded", ok, detail)
        time.sleep(3)  # settle stream cleanup before reading the link state
        self.check_quiet("concurrent", d0, c0, daemon_patterns=QUIET_DAEMON_SESSION)
        self.assert_pid_state(s1, pid1, state1, "concurrent")
        self.assert_pid_state(s2, pid2, state2, "concurrent")

    def stage_signaling_flap(self, s1: PtySession, pid1: int, state1: str,
                             s2: PtySession, pid2: int, state2: str) -> None:
        d0 = self.daemon_snapshot()
        c0 = self.session_snapshot()
        self.note("signaling flap: severing the signaling socket for ~8s")
        self.down_flag.write_text("down\n")
        nonce = secrets.token_hex(4)
        down_failures = 0
        for i in range(8):
            for s in (s1, s2):
                if not s.activity(f"{nonce}d{i}", timeout=10):
                    down_failures += 1
            time.sleep(1)
        self.down_flag.unlink(missing_ok=True)
        self.note("signaling flap: link healed; waiting for in-core reconnect evidence")
        reconnected = False
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            for d in self.daemons:
                if re.search(r"signaling reconnected", read_from(d.log_path, d0[d.name])):
                    reconnected = True
                    break
            if reconnected:
                break
            time.sleep(0.2)
        self.check(
            "signaling: injection was observed (daemon reconnected its socket)",
            reconnected,
            "neither daemon logged 'signaling reconnected' within 60s; the flap "
            "did not sever the socket, so the rest of this stage would be a fake green",
        )
        # Keep data flowing across the seam and through the old deferred sid's
        # idle-reap window. No drop is allowed while probes are flowing.
        for i in range(10):
            for s in (s1, s2):
                if not s.activity(f"{nonce}h{i}", timeout=15):
                    down_failures += 1
            time.sleep(1)
        self.check(
            "signaling: both shells answered probes across the outage",
            down_failures == 0,
            f"{down_failures} activity probe(s) failed during/after the signaling flap",
        )
        # Then stop touching them. A deferred peer-left must not turn into a
        # teardown just because the link went idle after the cosmetic reconnect.
        self.note("signaling: post-heal idle window (12s) — deferred leave must not reap")
        time.sleep(12)
        self.check_quiet(
            "signaling",
            d0,
            c0,
            allowed=FLAP_EXTRA_ALLOWED,
            daemon_patterns=QUIET_DAEMON_SESSION,
        )
        self.assert_pid_state(s1, pid1, state1, "signaling")
        self.assert_pid_state(s2, pid2, state2, "signaling")

    def stage_intentional_drop(self, s1: PtySession, pid1: int, state1: str,
                               s2: PtySession) -> None:
        self.note("drop: ending the reverse shell before the initiator daemon restart")
        s2.close(grace=12)
        # The session host is B. Killing A's daemon destroys the link but NOT the
        # PTY or its process on B. That is the property under test.
        d0 = self.daemon_snapshot()
        self.note("drop: SIGTERM initiator daemon A (session host B stays alive)")
        self.daemon_a.stop(grace=10, kill_group=False)
        self.daemon_a.force_restart_setup()
        time.sleep(1)
        self.daemon_a.start()
        self.note("drop: initiator daemon A restarted; waiting for PTY reattach at B")
        m = wait_regex(
            self.daemon_b.log_path,
            r"pty REATTACHED",
            start=d0["b"],
            timeout=90,
            proc=self.daemon_b.proc,
        )
        self.check(
            "drop: peer logged PTY reattach after the link loss",
            m is not None,
            "no 'pty REATTACHED' at the session host within 90s\n"
            f"--- daemon-b.log ---\n{tail(self.daemon_b.log_path)}\n"
            f"--- shell-a-to-b ---\n{tail(s1.transcript)}",
        )
        self.assert_pid_state(s1, pid1, state1, "drop")
        # Explicitly prove the client is usable after the reattach, not merely
        # that a log line exists.
        self.check(
            "drop: shell answered a fresh command after reattach",
            s1.activity("postdrop", timeout=30),
            f"no activity after reattach\n--- transcript ---\n{tail(s1.transcript)}",
        )

    # ---- teardown / summary ----------------------------------------------

    def teardown(self) -> None:
        for s in list(self.sessions):
            try:
                s.kill()
            except Exception:  # noqa: BLE001 - best-effort cleanup
                pass
        if self.echo:
            self.echo.stop()
        for d in self.daemons:
            try:
                d.stop(grace=6, kill_group=True)
            except Exception:  # noqa: BLE001
                pass
        for p in self.procs:
            if p.poll() is None:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except OSError:
                    pass
        try:
            self._harness_log.close()
        except OSError:
            pass

    def summary(self, result: str, error: str = "") -> dict:
        try:
            version = subprocess.run(
                [str(self.bin), "--version"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=20,
            ).stdout.strip()
        except Exception as e:  # noqa: BLE001 - evidence, not an assertion
            version = f"<version probe failed: {e}>"
        return {
            "result": result,
            "error": error,
            "binary": {
                "path": str(self.bin),
                "sha256": sha256(self.bin),
                "version": version,
            },
            "host": {
                "platform": platform.platform(),
                "kernel": platform.release(),
                "python": sys.version.split()[0],
                "cpus": os.cpu_count(),
            },
            "args": {
                "stable_secs": self.args.stable_secs,
                "probe_interval": self.args.probe_interval,
                "connect_timeout": self.args.connect_timeout,
                "command_timeout": self.args.command_timeout,
            },
            "ports": self.ports,
            "checks": self.checks,
            "evidence": self.evidence,
            "logs": sorted(p.name for p in self.dir.iterdir() if p.is_file()),
        }


def run_once(base: Path, bin_path: Path, args: argparse.Namespace, index: int) -> bool:
    run = Run(base, bin_path, args, index)
    result = "fail"
    error = ""
    try:
        run.note(f"run {index}: binary {bin_path} sha256 {sha256(bin_path)}")
        run.note(f"run {index}: work dir {run.dir}")
        run.start_fixture()
        state1 = f"s1{secrets.token_hex(4)}"
        state2 = f"s2{secrets.token_hex(4)}"
        # Snapshot BEFORE the second client exists: the owner's report is that a
        # second connection can tear down the first. A window that starts only
        # after both are established would miss exactly that failure.
        d_setup = run.daemon_snapshot()
        c_setup = run.session_snapshot()
        s1 = run.new_shell("a-to-b", run.cfg_a, "soak-a", "soak-b")
        s2 = run.new_shell("b-to-a", run.cfg_b, "soak-b", "soak-a")
        # Both clients are already running before either is awaited, so the
        # shells really are concurrent rather than sequential.
        pid1 = run.establish(s1, state1)
        pid2 = run.establish(s2, state2)
        run.check_quiet("setup", d_setup, c_setup, daemon_patterns=QUIET_DAEMON_SESSION)
        # Re-check the FIRST shell after the second has joined. Its own establish
        # marker was taken before that connection existed.
        run.assert_pid_state(s1, pid1, state1, "setup")
        run.assert_pid_state(s2, pid2, state2, "setup")
        run.check("setup: two simultaneous native shells established", True)
        run.note("both shells established; entering stable window")

        run.stage_stable(s1, pid1, state1, s2, pid2, state2)
        run.stage_concurrent(s1, pid1, state1, s2, pid2, state2)
        run.stage_signaling_flap(s1, pid1, state1, s2, pid2, state2)
        run.stage_intentional_drop(s1, pid1, state1, s2)

        s1.close(grace=12)
        result = "pass" if all(c["ok"] for c in run.checks) else "fail"
    except Failure as e:
        error = str(e)
        run.check("harness reached its assertions", False, error)
    except PrereqError:
        raise
    except Exception as e:  # noqa: BLE001 - a harness bug is a red run, not a skip
        error = f"{type(e).__name__}: {e}"
        import traceback

        traceback.print_exc()
        run.check("harness completed without an exception", False, error)
    finally:
        try:
            run.teardown()
        except Exception:  # noqa: BLE001
            pass
        summary = run.summary(result, error)
        (run.dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print("\n" + "=" * 72, flush=True)
        print(f"RESULT: {result.upper()}  ({run.dir})", flush=True)
        for c in run.checks:
            print(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['name']}", flush=True)
        if error:
            print(f"  error: {error}", flush=True)
        print(f"  artifacts: {run.dir}", flush=True)
        print("=" * 72 + "\n", flush=True)
        # Always keep the run dir. A pass is evidence too, and deleting the
        # directory on success is how a harness ends up unable to show what it
        # measured. Retention is the operator's/CI artifact step's job.
    return result == "pass"


def default_bin() -> str:
    for env in ("TUNLION_BIN", "FILAMENT_BIN"):
        value = os.environ.get(env)
        if value:
            return value
    if DEFAULT_BIN.is_file():
        return str(DEFAULT_BIN)
    return str(LEGACY_BIN)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", default=default_bin())
    parser.add_argument("--runs", type=int, default=1, help="repeat the whole scenario N times")
    parser.add_argument("--stable-secs", type=int, default=150, help="idle+active stable window")
    parser.add_argument("--probe-interval", type=float, default=5.0)
    parser.add_argument("--connect-timeout", type=float, default=60.0)
    parser.add_argument("--command-timeout", type=float, default=60.0)
    parser.add_argument(
        "--work-root",
        default=os.environ.get("DURABILITY_WORK_ROOT", "/tmp/tunlion-durability-soak"),
    )
    args = parser.parse_args()

    if not sys.platform.startswith("linux"):
        print(
            "PREREQUISITE: this harness drives Unix PTYs, process groups and SIGTERM; "
            "it is Linux-only. Windows<->Linux is the documented manual matrix, not a skip.",
            file=sys.stderr,
        )
        return 2
    bin_path = Path(args.bin).resolve()
    if not bin_path.is_file() or not os.access(bin_path, os.X_OK):
        print(
            f"PREREQUISITE: no executable tunlion at {bin_path}\n"
            "build it first: (cd cli && cargo build --release --features test-hooks)",
            file=sys.stderr,
        )
        return 2
    if not PROXY.is_file():
        print(f"PREREQUISITE: missing {PROXY}", file=sys.stderr)
        return 2
    if not (BACKEND_DIR / "app.py").is_file():
        print(f"PREREQUISITE: missing {BACKEND_DIR / 'app.py'}", file=sys.stderr)
        return 2
    if not Path("/bin/bash").exists():
        print("PREREQUISITE: /bin/bash is required for a predictable remote shell", file=sys.stderr)
        return 2
    if not Path("/bin/echo").exists():
        print("PREREQUISITE: /bin/echo is required for the exec gate", file=sys.stderr)
        return 2

    args.runs = max(1, int(args.runs))
    args.stable_secs = max(1, int(args.stable_secs))
    base = Path(args.work_root)
    base.mkdir(parents=True, exist_ok=True)
    log(f"work root: {base}")
    log(f"binary: {bin_path} (sha256 {sha256(bin_path)})")

    failures = 0
    for i in range(1, max(1, args.runs) + 1):
        log(f"=== run {i}/{args.runs} ===")
        try:
            if not run_once(base, bin_path, args, i):
                failures += 1
        except PrereqError as e:
            print(f"PREREQUISITE FAILURE: {e}", file=sys.stderr)
            return 2

    if failures:
        print(f"SOAK FAILED: {failures}/{args.runs} run(s) failed", file=sys.stderr)
        return 1
    print(f"SOAK PASSED: {args.runs}/{args.runs} run(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
