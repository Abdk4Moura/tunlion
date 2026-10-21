#!/usr/bin/env python3
"""Join input-category boundary regression harness. Remote worker only.

Args: <actual tunlion binary> [output directory]

Every case is a FAILED join input: invitation material, an explicit invitation
source that is malformed, a missing positional path, a positional credential,
or an oversize code. None may be reinterpreted as a valid pairing code, and
none may open a TCP connection. A loopback sentinel records every accepted TCP
connection and answers 503 immediately, so an accidental handshake fails fast
and is counted rather than silently succeeding.

Fixtures are fixed and harmless. Invitation material is delivered only through
--invite-file, --invite-fd (POSIX), or the environment, never in argv, except
for the two deliberate positional-material refusal cases. Each case gets a
fresh isolated TUNLION_CONFIG_DIR and inherited TUNLION_*/FIL_* values are
cleared, as in runner/pairing-code-e2e.py.

Expected cases (17 on POSIX, 15 elsewhere):
  invite-file-json, invite-file-malformed-prefix, invite-file-tlninv,
  invite-file-plain-code, invite-file-punctuation-code,
  invite-fd-json, invite-fd-malformed-prefix (POSIX only),
  env-authkey-raw-code, env-authkey-malformed,
  missing-path-dot, missing-path-slash, missing-path-extension,
  argv-invite-malformed, argv-invite-json, oversize-code

Exit 0 only when every case is refused with zero TCP connections, no
devices.json membership, and no raw material in output.
"""
import json
import os
from pathlib import Path
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

TIMEOUT = 20
ANSI = re.compile(r"\x1b\[[0-9;? ]*[A-Za-z]|\x1b\][^\x1b\x07]*(?:\x07|\x1b\\)")
# The parser's fixed help example is not a reflection of the input. Count how
# many times it appears so a second appearance (a real echo) is still caught.
FIXED_EXAMPLE = re.compile(r"\(like [a-z]+-[a-z]+-\d{4}\)")
SECRET_PREFIXES = ("TUNLION_", "FIL_")


class Sentinel(socketserver.ThreadingTCPServer):
    """Accept-and-count TCP server. Every connection is a boundary failure."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address):
        self._lock = threading.Lock()
        self._connections = []
        super().__init__(address, SentinelHandler)

    def get_request(self):
        connection, address = self.socket.accept()
        with self._lock:
            self._connections.append(address)
        return connection, address

    def count(self):
        with self._lock:
            return len(self._connections)

    def peers(self):
        with self._lock:
            return list(self._connections)

    def reset(self):
        with self._lock:
            self._connections.clear()

    def handle_error(self, request, client_address):
        # A client that disappears mid-response is not the subject of this test.
        pass


class SentinelHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            self.request.settimeout(1.0)
            self.request.sendall(
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        except OSError:
            pass


def environment(config, extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(SECRET_PREFIXES)}
    env.update(
        TUNLION_CONFIG_DIR=str(config),
        TUNLION_NONINTERACTIVE="1",
        NO_COLOR="1",
        TERM="dumb",
        LANG="C.UTF-8",
        LC_ALL="C.UTF-8",
    )
    if extra:
        env.update(extra)
    return env


def write_owner_only(path, text):
    path.write_text(text, encoding="utf-8")
    os.chmod(path, 0o600)


def start_case(root, name):
    case = root / name
    case.mkdir()
    config = case / "config"
    config.mkdir(mode=0o700)
    os.chmod(config, 0o700)
    return case, config


def run(name, binary, server, case, config, argv, env_extra=None, pass_fds=()):
    command = [binary, "--server", server, "--no-interactive", "join", *argv]
    kwargs = dict(
        cwd=str(case),
        env=environment(config, env_extra),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=TIMEOUT,
    )
    if pass_fds:
        kwargs["pass_fds"] = tuple(pass_fds)
    try:
        completed = subprocess.run(command, **kwargs)
    except subprocess.TimeoutExpired as error:
        output = (error.stdout or b"") + (error.stderr or b"")
        (case / "combined.log").write_bytes(output)
        raise AssertionError(
            f"{name}: timed out after {TIMEOUT}s; output:\n"
            f"{output.decode('utf-8', 'replace')[-4000:]}"
        )
    output = (completed.stdout or b"") + b"\n" + (completed.stderr or b"")
    (case / "combined.log").write_bytes(output)
    return completed, output


def devices_membership(config):
    path = config / "devices.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ["unparseable devices.json"]
    if isinstance(data, list):
        return data
    return [data] if data else []


def finish(name, config, sentinel, completed, output, *, payload,
           expect_any=(), must_contain=(), allow_fixed_example=False):
    # Give an accidental connection a moment to reach accept() before counting.
    time.sleep(0.2)
    text = ANSI.sub("", output.decode("utf-8", "replace")).replace("\r\n", "\n")
    low = text.lower()
    problems = []

    if completed.returncode == 0:
        problems.append("exit 0 (input was accepted)")
    if sentinel.count():
        problems.append(
            f"{sentinel.count()} TCP connection(s) reached the sentinel: "
            f"{sentinel.peers()}"
        )
    members = devices_membership(config)
    if members:
        problems.append(f"devices.json gained {len(members)} membership row(s)")
    for word in ("connecting", "transfer code", "transfercode"):
        if word in low:
            problems.append(f"output contains {word!r}")
    for required in must_contain:
        if required.lower() not in low:
            problems.append(f"output lacks {required!r}")
    if expect_any and not any(candidate.lower() in low for candidate in expect_any):
        problems.append(f"output lacks any of {expect_any!r}")
    if payload is not None:
        allowed = len(FIXED_EXAMPLE.findall(text)) if allow_fixed_example else 0
        if text.count(payload) > allowed:
            problems.append("output echoed raw input material")

    if problems:
        raise AssertionError(
            f"{name}: " + "; ".join(problems) +
            f"\n--- combined output ---\n{text[-4000:]}"
        )
    print(
        f"PASS {name}: exit {completed.returncode}, 0 TCP connections, "
        f"no membership, refused"
    )


def case_invite_file(binary, server, sentinel, root, name, text, **expect):
    case, config = start_case(root, name)
    sentinel.reset()
    fixture = case / "invitation.txt"
    write_owner_only(fixture, text)
    completed, output = run(
        name, binary, server, case, config, ["--invite-file", str(fixture)]
    )
    finish(name, config, sentinel, completed, output, **expect)


def case_invite_fd(binary, server, sentinel, root, name, text, **expect):
    case, config = start_case(root, name)
    sentinel.reset()
    fixture = case / "invitation-fd.txt"
    write_owner_only(fixture, text)
    with fixture.open("rb") as handle:
        completed, output = run(
            name, binary, server, case, config,
            ["--invite-fd", str(handle.fileno())],
            pass_fds=(handle.fileno(),),
        )
    finish(name, config, sentinel, completed, output, **expect)


def case_env(binary, server, sentinel, root, name, variable, text, **expect):
    case, config = start_case(root, name)
    sentinel.reset()
    completed, output = run(
        name, binary, server, case, config, [], env_extra={variable: text}
    )
    finish(name, config, sentinel, completed, output, **expect)


def case_argv(binary, server, sentinel, root, name, raw, **expect):
    case, config = start_case(root, name)
    sentinel.reset()
    completed, output = run(
        name, binary, server, case, config, [raw]
    )
    finish(name, config, sentinel, completed, output, **expect)


def run_all(binary, server, sentinel, root):
    json_payload = '["brave-otter-3141"]'
    malformed_prefix = "filament-invite:brave-otter-3141"
    unknown_format = ("unknown format",)
    decoded_but_invalid = ("base64url", "valid v2 invitation")

    case_invite_file(
        binary, server, sentinel, root, "invite-file-json", json_payload,
        payload=json_payload, expect_any=unknown_format,
    )
    case_invite_file(
        binary, server, sentinel, root, "invite-file-malformed-prefix",
        malformed_prefix, payload=malformed_prefix,
        expect_any=decoded_but_invalid,
    )
    case_invite_file(
        binary, server, sentinel, root, "invite-file-tlninv",
        "TLNINV-brave-otter-3141", payload="TLNINV-brave-otter-3141",
        expect_any=unknown_format,
    )
    case_invite_file(
        binary, server, sentinel, root, "invite-file-plain-code",
        "brave-otter-3141", payload="brave-otter-3141",
        expect_any=unknown_format, allow_fixed_example=True,
    )
    case_invite_file(
        binary, server, sentinel, root, "invite-file-punctuation-code",
        "brave__otter!3141", payload="brave__otter!3141",
        expect_any=unknown_format,
    )

    if os.name == "posix":
        case_invite_fd(
            binary, server, sentinel, root, "invite-fd-json", json_payload,
            payload=json_payload, expect_any=unknown_format,
        )
        case_invite_fd(
            binary, server, sentinel, root, "invite-fd-malformed-prefix",
            malformed_prefix, payload=malformed_prefix,
            expect_any=decoded_but_invalid,
        )

    case_env(
        binary, server, sentinel, root, "env-authkey-raw-code",
        "TUNLION_AUTHKEY", "brave-otter-3141",
        payload="brave-otter-3141", expect_any=unknown_format,
        allow_fixed_example=True,
    )
    case_env(
        binary, server, sentinel, root, "env-authkey-malformed",
        "TUNLION_AUTHKEY", malformed_prefix,
        payload=malformed_prefix, expect_any=decoded_but_invalid,
    )

    for name, raw in (
        ("missing-path-dot", "./brave-otter-3141"),
        ("missing-path-slash", "brave/otter/3141"),
        ("missing-path-extension", "invite.txt"),
    ):
        case_argv(
            binary, server, sentinel, root, name, raw,
            payload=raw, expect_any=("cannot read the invitation file",),
        )

    case_argv(
        binary, server, sentinel, root, "argv-invite-malformed",
        malformed_prefix, payload=malformed_prefix,
        expect_any=("passed in argv",),
    )
    case_argv(
        binary, server, sentinel, root, "argv-invite-json",
        json_payload, payload=json_payload,
        expect_any=("passed in argv",),
    )
    for name, wrapped in (
        ("argv-wrapped-json", '`["brave-otter-3141"]`'),
        ("argv-wrapped-token", "'TLNINV-brave-otter-3141'"),
    ):
        case_argv(binary, server, sentinel, root, name, wrapped,
                  payload=wrapped, expect_any=("passed in argv",))

    oversized = "a" * 20 + "-" + "b" * 23 + "-1234"
    assert len(oversized) == 49
    case_argv(
        binary, server, sentinel, root, "oversize-code", oversized,
        payload=oversized, must_contain=("48", "truncat"),
    )


def main(argv):
    if len(argv) not in (2, 3):
        print(f"usage: {argv[0]} <tunlion binary> [output directory]", file=sys.stderr)
        return 2

    binary = argv[1]
    if os.sep not in binary and (found := shutil.which(binary)):
        binary = found
    binary = str(Path(binary).resolve())
    if not Path(binary).is_file():
        print(f"not a file: {binary}", file=sys.stderr)
        return 2

    if len(argv) == 3:
        output = Path(argv[2]).resolve()
        output.mkdir(parents=True, exist_ok=False)
    else:
        output = Path(tempfile.mkdtemp(prefix="tunlion-join-input-boundary-"))

    sentinel = Sentinel(("127.0.0.1", 0))
    thread = threading.Thread(
        target=sentinel.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    thread.start()
    server = f"http://127.0.0.1:{sentinel.server_address[1]}"
    print(f"binary: {binary}")
    print(f"server sentinel: {server}")
    print(f"output: {output}")
    try:
        run_all(binary, server, sentinel, output)
    finally:
        sentinel.shutdown()
        sentinel.server_close()
        thread.join(timeout=5)
        if thread.is_alive():
            print("warning: sentinel thread did not stop", file=sys.stderr)
    print(f"PASS all join-input boundary cases; evidence in {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
