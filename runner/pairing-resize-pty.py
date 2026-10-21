#!/usr/bin/env python3
"""Real Rust PTY + xterm.js reflow, editing and visual-state assertions.

Remote-only tools: @xterm/headless@6.0.0 (NODE_PATH). Arguments: test binary,
optional output directory. Snapshot events also drive browser visual review.
"""
import base64
import fcntl
import json
import os
from pathlib import Path
import runpy
import signal
import struct
import subprocess
import sys
import termios

HERE = Path(__file__).resolve().parent
Session = runpy.run_path(str(HERE / 'pairing-inline-pty.py'))['Session']


class Probe:
    def __init__(self, session, cols=96, rows=24):
        self.session = session
        self.initial = [cols, rows]
        self.events = []
        self.process = subprocess.Popen(
            ['node', str(HERE / 'terminal-probe.cjs'), str(cols), str(rows)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.frame = None
        session.observer = self.feed

    def command(self, message):
        self.events.append(message)
        self.process.stdin.write(json.dumps(message) + '\n')
        self.process.stdin.flush()
        self.frame = json.loads(self.process.stdout.readline())
        for reply in self.frame['replies']:
            self.session.send(base64.b64decode(reply))
        return self.frame

    def feed(self, data):
        return self.command({'data': base64.b64encode(data).decode()})

    def resize(self, cols, rows):
        self.command({'resize': [cols, rows]})  # real terminal reflows first
        self.session.reservations += 1
        fcntl.ioctl(self.session.master, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        os.kill(self.session.process.pid, signal.SIGWINCH)

    def save(self, directory, name):
        Path(directory).mkdir(parents=True, exist_ok=True)
        Path(directory, name + '.json').write_text(json.dumps({
            'initial': self.initial, 'events': self.events, 'frame': self.frame}, indent=2))
        print(name + ':\n' + '\n'.join(self.frame['lines']))

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=5)


def assert_entry(probe, rows, bottom=False):
    frame = probe.frame
    y = frame['cursorY']
    assert 'choose words' in frame['lines'][y - 1], frame
    assert not frame['lines'][y].strip() or frame['lines'][y].startswith('  '), frame
    assert '|' not in frame['lines'][y], 'redundant input marker returned'
    assert frame['inputCell']['bold'] == 0, frame['inputCell']
    assert frame['inputCell']['foreground'] != 3, 'input text was repainted as a yellow marker'
    if bottom:
        assert y == rows - 2, ('resize must reserve a fresh bottom region, never guess reflowed coordinates', frame)


def entry(binary, out):
    session = Session(binary, 'pty_entry_driver', 96, 24)
    probe = Probe(session)
    try:
        session.wait_frame()
        assert_entry(probe, 24)
        # Longer than both widths: the caret must remain visible while the field
        # scrolls horizontally. xterm then reflows that prior wide frame.
        words = b'abalaka-world-abalaka-world-brave-otter'
        session.send(b'\x1b[200~' + words + b'\x1b[201~')
        session.wait_frame()
        probe.resize(40, 12)
        session.wait_frame()
        assert_entry(probe, 12, bottom=True)
        base = probe.frame['baseY']
        for _ in range(4):
            session.send(b'x')
            session.wait_frame()
            assert_entry(probe, 12, bottom=True)
            assert probe.frame['baseY'] == base, 'typing after resize scrolled the screen'
        probe.save(out, 'entry-narrow-reflow')
        probe.resize(96, 24)
        session.wait_frame()
        assert_entry(probe, 24, bottom=True)
        # Real Home/Delete/End/Backspace/Ctrl-U, not an editor simulation.
        session.send(b'\x15')
        session.wait_frame()
        session.send(b'\x1b[200~xabalaka-worldz\x1b[201~')
        session.wait_frame()
        session.send(b'\x1b[H\x1b[3~\x1b[F\x7f')
        session.wait_frame()
        assert 'Enter creates abalaka-world-1740' in '\n'.join(probe.frame['lines'])
        probe.save(out, 'entry-wide-edited')
        session.send(b'\r')
        session.finish(b'ENTRY:Submitted("abalaka-world")')
    finally:
        session.close()
        probe.close()


def picker(binary, out):
    session = Session(binary, 'pty_picker_driver', 96, 24)
    probe = Probe(session)
    try:
        session.read_until(b'Device 6')
        probe.resize(40, 12)
        session.read_until(b'Device 5')
        assert probe.frame['cursorY'] == 11, probe.frame
        session.send(b'\x1b[B' * 9)
        session.read_until(b'Device 9')
        probe.save(out, 'picker-narrow-reflow')
        base = probe.frame['baseY']
        session.send(b'\x1b[A')
        session.read_until(b'Device 8')
        assert probe.frame['baseY'] == base, 'picker drifted after viewport change'
        session.send(b'\r')
        session.finish(b'PICK:Some(8)')
    finally:
        session.close()
        probe.close()


if __name__ == '__main__':
    destination = sys.argv[2] if len(sys.argv) > 2 else '/tmp/pairing-terminal-review'
    entry(os.path.abspath(sys.argv[1]), destination)
    picker(os.path.abspath(sys.argv[1]), destination)
    print('PASS: xterm reflow, stable typing, native editing, yellow marker and viewport')
