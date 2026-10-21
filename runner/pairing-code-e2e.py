#!/usr/bin/env python3
"""Two real CLI clients + real loopback signaling; no seeded pair secrets.

Remote worker only. Args: candidate binary, backend venv python, output dir,
optional --transfer (additional legacy-identity regression probe).
Fresh isolated configs are never the worker's own Tunlion identity. Exercises
ordinary pairing, not the separately tracked ownership/membership redesign.

One scenario runs `join` with NO positional code in a PTY, so the CLI's inline
GUIDED prompt must read the exact code (the narrow/chosen-words case). The other
runs the non-interactive `join <code> --no-interactive` argv (wide/generated).
A third, fresh config replays the consumed code through argv and must be rejected.
"""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import pty
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import termios
import threading
import time
import urllib.request

ANSI = re.compile(rb'\x1b\[[0-9;? ]*[A-Za-z]|\x1b\][^\x1b\x07]*(?:\x07|\x1b\\)')
SYNC_END = b'\x1b[?2026l'


def environment(config):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('TUNLION_', 'FIL_'))}
    env.update(TUNLION_CONFIG_DIR=str(config), TERM='xterm-256color', LANG='C.UTF-8')
    return env


def read_until(master, output, needle, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if select.select([master], [], [], .1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            if needle in ANSI.sub(b'', output):
                return
    raise AssertionError(f'Missing {needle!r}: {ANSI.sub(b"", output).decode(errors="replace")}')


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class Stream:
    """Background reader for a second PTY (the guided joiner) so the creator's
    transcript can be followed concurrently without blocking either side."""

    def __init__(self, master):
        self.master = master
        self.output = bytearray()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                ready = select.select([self.master], [], [], .1)[0]
            except (OSError, ValueError):
                break
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                break
            if not chunk:
                break
            self.output.extend(chunk)

    def wait(self, needle, seconds=90, strip=True):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            hay = ANSI.sub(b'', bytes(self.output)) if strip else bytes(self.output)
            if needle in hay:
                return
            time.sleep(.02)
        hay = ANSI.sub(b'', bytes(self.output)) if strip else bytes(self.output)
        raise AssertionError(f'guided joiner missing {needle!r}: {hay[-3000:]!r}')

    def more(self, marker, count, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if bytes(self.output).count(marker) >= count:
                return
            time.sleep(.02)
        raise AssertionError(f'guided joiner produced no frame; transcript: {bytes(self.output)[-3000:]!r}')

    def close(self):
        self._stop.set()
        self._thread.join(timeout=1)


def start_guided(binary, server, config, code, cols, rows):
    """Spawn `join` with no positional code in an isolated config. The inline
    entry must accept the same code a non-interactive argv join would."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    before = termios.tcgetattr(slave)
    process = subprocess.Popen([binary, '--server', server, 'join', '--name', 'sender'],
                               env=environment(config), stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    stream = Stream(master)
    try:
        # The first synchronized frame means the inline reader is ready for keys.
        stream.wait(SYNC_END, 30, strip=False)
        # Raw mode must already have echo off; otherwise a paste is kernel-echoed.
        assert termios.tcgetattr(master)[3] & termios.ECHO == 0, 'guided prompt left terminal echo on'
        frames = bytes(stream.output).count(SYNC_END)
        # Bracket markers in OUTPUT can only be a kernel echo of our paste: the
        # UI consumes them, and EnableBracketedPaste is ESC[?2004h.
        # User punctuation is an entry separator, not a lossy password edit.
        # The shared boundary must recover the exact code the creator minted.
        typed = '---' + code.replace('-', '__!') + '---'
        os.write(master, b'\x1b[200~' + typed.encode() + b'\x1b[201~')
        stream.more(SYNC_END, frames + 1, 15)
        prompt = bytes(stream.output)
        assert b'\x1b[?1049' not in prompt, 'guided join entered the alternate screen'
        assert b'\x1b[2J' not in prompt, 'guided join cleared the whole screen'
        assert b'\x1b[200~' not in prompt and b'\x1b[201~' not in prompt, \
            'guided prompt echoed raw paste bytes'
        os.write(master, b'\r')
        return process, master, stream, before
    except BaseException:
        stop(process)
        stream.close()
        os.close(master)
        raise


def case(binary, server, root, cols, rows, generated, transfer=False, guided=False):
    root.mkdir()
    a, b, replay = (root / name for name in ('inviter', 'joiner', 'replay'))
    for directory in (a, b, replay):
        directory.mkdir(mode=0o700)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
    before = termios.tcgetattr(slave)
    creator = subprocess.Popen([binary, '--server', server, 'add', '--name', 'receiver'],
                               env=environment(a), stdin=slave, stdout=slave, stderr=slave)
    os.close(slave)
    transcript = bytearray()
    joiner = receiver = guided_master = guided_stream = None
    try:
        read_until(master, transcript, b'choose words')
        if not generated:
            os.write(master, b'\x1b[200~abalaka-world\x1b[201~')
            read_until(master, transcript, b'creates abalaka-world-')
        os.write(master, b'\r')
        read_until(master, transcript, b'One claim')
        plain = ANSI.sub(b'', transcript).replace(b'\r', b'')
        codes = re.findall(rb'^  ([a-z]+(?:-[a-z]+)+-[0-9]{4})$', plain, re.M)
        assert len(codes) == 1, plain.decode(errors='replace')
        code = codes[0].decode()
        assert generated or code.startswith('abalaka-world-')
        assert creator.poll() is None, 'inviter auto-completed before a joiner'
        assert b'\x1b[?1049' not in transcript and b'\x1b[2J' not in transcript
        # A local Enter on the waiting side cannot impersonate remote acceptance.
        os.write(master, b'\r')
        assert not (a / 'devices.json').exists()

        if guided:
            joiner, guided_master, guided_stream, guided_before = start_guided(
                binary, server, b, code, cols, rows)
            read_until(master, transcript, b'mutually remembered', 120)
            assert joiner.wait(timeout=45) == 0, \
                ANSI.sub(b'', bytes(guided_stream.output)).decode(errors='replace')
            joiner_plain = ANSI.sub(b'', bytes(guided_stream.output))
            assert b'\x1b[?1049' not in guided_stream.output, 'guided join used alt screen'
            assert b'\x1b[2J' not in guided_stream.output, 'guided join used a full clear'
            assert b'\x1b[200~' not in guided_stream.output and \
                b'\x1b[201~' not in guided_stream.output, 'guided prompt echoed the paste'
            flags = termios.ECHO | termios.ICANON
            assert termios.tcgetattr(guided_master)[3] & flags == guided_before[3] & flags, \
                'guided join did not restore the terminal'
            (root / 'joiner-guided.ansi').write_bytes(bytes(guided_stream.output))
            (root / 'joiner-guided.txt').write_bytes(joiner_plain)
        else:
            with (root / 'joiner.log').open('wb') as log:
                joiner = subprocess.Popen([binary, '--server', server, 'join', code,
                                           '--name', 'sender', '--no-interactive'],
                                          env=environment(b), stdin=subprocess.DEVNULL,
                                          stdout=log, stderr=log)
                read_until(master, transcript, b'mutually remembered', 120)
                assert joiner.wait(timeout=45) == 0, (root / 'joiner.log').read_text()
        assert creator.wait(timeout=45) == 0
        flags = termios.ECHO | termios.ICANON
        assert termios.tcgetattr(master)[3] & flags == before[3] & flags
        left = next(row for row in json.loads((a / 'devices.json').read_text()) if row.get('name') == 'receiver')
        right = next(row for row in json.loads((b / 'devices.json').read_text()) if row.get('name') == 'sender')
        assert left.get('secret') and hmac.compare_digest(left['secret'], right['secret'])
        rejected = subprocess.run([binary, '--server', server, 'join', code, '--no-interactive'],
                                  env=environment(replay), capture_output=True, timeout=20)
        assert rejected.returncode != 0, 'one-time code admitted another client'
        assert not (replay / 'devices.json').exists()
        drop = root / 'received'
        drop.mkdir()
        with (root / 'receiver.log').open('wb') as log:
            receiver = subprocess.Popen([binary, '--server', server, 'up', '--userspace',
                                         '--dir', str(drop), '--no-interactive'],
                                        env=environment(b), stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=log)
            reachable = subprocess.run([binary, '--server', server, 'reach', 'receiver',
                                        '--timeout', '30', '--json'], env=environment(a),
                                       capture_output=True, timeout=40)
            assert reachable.returncode == 0, reachable.stderr.decode()
            (root / 'reach.json').write_bytes(reachable.stdout)
            (root / 'inviter.ansi').write_bytes(transcript)
            (root / 'inviter.txt').write_bytes(ANSI.sub(b'', transcript))
            if not transfer:
                route = 'guided inline join' if guided else 'noninteractive argv join'
                print(f'PASS {cols}x{rows}: {route}, {"generated" if generated else "chosen"} words, '
                      'live PAKE, matching peer stores, single use, authenticated reach')
                return
            payload = root / 'pairing-proof.txt'
            payload.write_bytes(b'Real code pairing, then known-peer transfer.\n' * 128)
            sent = subprocess.run([binary, '--server', server, 'send', str(payload),
                                   '--to', 'receiver', '--timeout', '45', '--json'],
                                  env=environment(a), capture_output=True, timeout=55)
            (root / 'send.log').write_bytes(sent.stdout + sent.stderr)
            assert sent.returncode == 0, sent.stderr.decode()
            received = drop / payload.name
            assert received.is_file()
            assert hashlib.sha256(received.read_bytes()).digest() == hashlib.sha256(payload.read_bytes()).digest()
        (root / 'inviter.ansi').write_bytes(transcript)
        (root / 'inviter.txt').write_bytes(ANSI.sub(b'', transcript))
        route = 'guided inline join' if guided else 'noninteractive argv join'
        print(f'PASS {cols}x{rows}: {route}, {"generated" if generated else "chosen"} words, '
              'live PAKE, matching peer stores, single use, reach + verified transfer')
    finally:
        (root / 'inviter.ansi').write_bytes(transcript)
        for process in (creator, joiner, receiver):
            stop(process)
        if guided_stream:
            guided_stream.close()
        if guided_master is not None:
            try:
                os.close(guided_master)
            except OSError:
                pass
        os.close(master)


if __name__ == '__main__':
    binary, python, output = sys.argv[1:4]
    transfer = '--transfer' in sys.argv[4:]
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    server = f'http://127.0.0.1:{port}'
    backend_env = dict(os.environ, FIL_DEV='1', FIL_SECRET=secrets.token_hex(32),
                       FIL_ASYNC_MODE='eventlet', FIL_SELF_MONKEYPATCH='1', FIL_CLAIM_LIMIT='1000000')
    with (output / 'backend.log').open('wb') as log:
        fixture = subprocess.Popen([python, '-c',
            f'from app import app, socketio; socketio.run(app, host="127.0.0.1", port={port}, log_output=False)'],
            cwd=Path(__file__).resolve().parents[1] / 'backend', env=backend_env, stdout=log, stderr=log)
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(server + '/api/health', timeout=1):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise AssertionError('Loopback signaling fixture did not become ready')
            # Narrow/chosen-words: the GUIDED inline prompt must accept the exact
            # code. Wide/generated: keep the non-interactive argv path covered.
            case(binary, server, output / 'narrow', 40, 12, False, transfer, guided=True)
            case(binary, server, output / 'wide', 96, 24, True, transfer, guided=False)
        finally:
            stop(fixture)
