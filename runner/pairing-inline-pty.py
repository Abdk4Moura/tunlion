#!/usr/bin/env python3
"""Real Rust event-loop smoke, no network/config/production test commands.

Build: cargo test -p filament-cli --locked --no-run
Run: python3 runner/pairing-inline-pty.py target/debug/deps/tunlion-<hash>
Pass the executable test binary (not the installed CLI).
"""
import fcntl
import os
import pty
import re
import select
import struct
import subprocess
import sys
import termios
import time
import unicodedata


class Session:
    def __init__(self, binary, driver, width, height, no_color=False, term='xterm-256color'):
        self.master, slave = pty.openpty()
        self.before = termios.tcgetattr(slave)
        self.width = width
        self.driver = driver
        self.reservations = 1
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', height, width, 0, 0))
        env = dict(os.environ, TERM=term, LANG='C.UTF-8')
        for key in ('NO_COLOR', 'TUNLION_COLOR'):
            env.pop(key, None)
        if no_color:
            env['NO_COLOR'] = '1'
        self.process = subprocess.Popen(
            [binary, '--ignored', '--exact', 'codeentry::tests::' + driver,
              '--nocapture', '--test-threads=1', '--color', 'never'], stdin=slave, stdout=slave,
            stderr=slave, env=env)
        os.close(slave)
        self.output = bytearray()
        self.observer = None

    def read_until(self, marker, timeout=10):
        start = len(self.output)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if select.select([self.master], [], [], .1)[0]:
                try:
                    chunk = os.read(self.master, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                self.output.extend(chunk)
                if self.observer:
                    self.observer(chunk)
                if marker in self.output[start:]:
                    if self.observer:
                        self.drain_frame()
                    return
        raise AssertionError(f'Missing {marker!r}: {bytes(self.output)!r}')

    def drain_frame(self):
        # A renderer can split a frame across writes. Let a VT observer see the
        # final caret positioning, not just the chunk containing a hint label.
        while select.select([self.master], [], [], .03)[0]:
            try:
                chunk = os.read(self.master, 65536)
            except OSError:
                return
            if not chunk:
                return
            self.output.extend(chunk)
            self.observer(chunk)

    def send(self, keys):
        os.write(self.master, keys)

    def wait_frame(self):
        self.read_until(b'\x1b[?2026l')

    def expect_no_update(self):
        assert not select.select([self.master], [], [], .15)[0], 'unchanged input repainted'
        assert self.process.poll() is None
        assert b'ENTRY:' not in self.output

    def finish(self, expected, no_color=False, plain=False):
        self.read_until(expected)
        self.process.wait(timeout=10)
        assert self.process.returncode == 0
        flags = termios.ECHO | termios.ICANON
        assert termios.tcgetattr(self.master)[3] & flags == self.before[3] & flags
        assert b'\x1b[?1049' not in self.output  # no alternate screen
        assert b'\x1b[2J' not in self.output  # no full clear
        if plain:
            assert b'\x1b' not in self.output, bytes(self.output)
            return
        assert b'\x1b[6 q' in self.output  # thin caret requested
        assert b'\x1b[0 q' in self.output  # user's default restored
        assert b'\x1b[?2004l' in self.output  # bracketed paste disabled
        # Exclude test-harness receipts, which are not the inline UI. Every
        # painted row must leave the last cell empty (no implicit wrapping).
        if self.driver == 'pty_picker_driver':
            painted = bytes(self.output).split(b'\x1b[2K', 1)[1].split(expected, 1)[0]
            painted = re.sub(rb'\x1b\][^\x1b\x07]*(?:\x07|\x1b\\)', b'', painted)
            painted = re.sub(rb'\x1b\[[0-9;? ]*[A-Za-z]', b'', painted)
            for line in re.split(r'[\r\n]', painted.decode('utf-8')):
                cells = sum(0 if unicodedata.combining(c) else
                            2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
                            for c in line)
                assert cells < self.width, (self.width, line)
        else:
            # Entry clears its reservation once, never per keystroke. Dirty
            # suffixes have no intervening blank input/header/hint frames.
            assert self.output.count(b'\x1b[2K') == 3 * self.reservations
            assert b'\x1b[?25l' not in self.output  # no cursor hide/show flashing
            assert b'  | ' not in self.output
        assert self.output.count(b'\x1b[?2026l') == self.output.count(b'\x1b[?2026h') + 1
        if no_color:
            assert b'\x1b]12;' not in self.output
            assert b'\x1b[33m' not in self.output
        else:
            assert b'\x1b]12;#e6b450' in self.output
            assert b'\x1b]112' in self.output
            if self.driver == 'pty_picker_driver':
                assert b'\x1b[33m' in self.output

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        os.close(self.master)


def entry(binary, width, height, ending, expected, no_color=False):
    session = Session(binary, 'pty_entry_driver', width, height, no_color)
    try:
        session.wait_frame()
        # Newline, Ctrl-C and Esc inside paste are data, never submission/cancel.
        session.send(b'\x1b[200~abalaka\nworld\x03\x1b\x1b[201~')
        session.wait_frame()
        assert session.process.poll() is None
        assert b'ENTRY:' not in session.output
        # A credential accidentally pasted into this code-only reader is refused
        # wholesale, so its payload cannot leak into any retained frame.
        session.send(b'\x1b[200~filament-invite:v2:S3CRET_PAYLOAD\x1b[201~')
        session.wait_frame()
        assert b'that is an invitation' in session.output
        assert b'S3CRET' not in session.output
        session.send(b'\r')
        session.expect_no_update()
        assert b'ENTRY:' not in session.output  # refused paste cannot submit old input
        session.send(b'\x15')  # Ctrl-U explicitly clears the refusal and field
        session.wait_frame()
        session.send(b'\x1b[200~abalaka-world\x1b[201~')
        session.wait_frame()
        session.send(ending)
        session.finish(expected, no_color)
    finally:
        session.close()


def picker(binary):
    session = Session(binary, 'pty_picker_driver', 40, 12)
    try:
        session.read_until(b'Devices')
        session.send(b'\x1b[B' * 9)
        session.read_until(b'Device 9')
        session.send(b'\r')
        session.finish(b'PICK:Some(9)')
    finally:
        session.close()


def plain(binary):
    session = Session(binary, 'pty_entry_driver', 40, 12, term='dumb')
    try:
        session.read_until(b'Type two words')  # echo is already disabled
        session.send(b'filament-invite:v2:S3CRET_PAYLOAD\r')
        session.read_until(b'that is an invitation')
        assert b'S3CRET' not in session.output
        assert b'ENTRY:' not in session.output
        session.send(b'\x15abalaka-world\r')
        session.finish(b'ENTRY:Submitted("abalaka-world")', plain=True)
    finally:
        session.close()
    session = Session(binary, 'pty_picker_driver', 40, 12, term='dumb')
    try:
        session.read_until(b'Choose a number')
        session.send(b'99\r')
        session.read_until(b'Choose 1 through 12')
        session.send(b'10\r')
        session.finish(b'PICK:Some(9)', plain=True)
        assert bytes(session.output).count(b'tunlion / Devices') == 1
    finally:
        session.close()


if __name__ == '__main__':
    binary = os.path.abspath(sys.argv[1])
    for width, height in ((40, 12), (96, 24)):
        entry(binary, width, height, b'\r', b'ENTRY:Submitted("abalaka-world")')
        entry(binary, width, height, b'\x1b', b'ENTRY:Cancelled')
        entry(binary, width, height, b'\x03', b'ENTRY:Interrupted')
        print(f'PASS {width}x{height}: paste, submit/cancel/interrupt, caret and terminal cleanup')
    entry(binary, 40, 12, b'\x1b', b'ENTRY:Cancelled', no_color=True)
    picker(binary)
    plain(binary)
    print('PASS: NO_COLOR, narrow picker, escape-free TERM=dumb entry/picker, hidden credentials')
