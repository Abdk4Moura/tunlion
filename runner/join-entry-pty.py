#!/usr/bin/env python3
"""Real Rust PTY harness for join_entry::read_input (inline, masked GUIDED join).

Remote-only. Build the test binary first:
    cargo test -p filament-cli --locked --no-run
Run:
    python3 runner/join-entry-pty.py target/debug/deps/tunlion-<hash> [outdir] [--no-probe]
Pass the executable TEST binary, not the installed CLI. The driver is
`join_entry::tests::pty_driver` and prints only:
    JOIN:submitted len=N
    JOIN:cancelled
    JOIN:interrupted
It never prints the submitted value, so this harness cannot (and must not) see a
token. `len=N` is the UTF-8 byte length of the zeroizing submitted buffer.

The VT snapshot assertions need @xterm/headless@6.0.0 on NODE_PATH, the same
dependency pairing-resize-pty.py uses. --no-probe keeps the raw-transcript,
terminal-restore and no-escape checks, but cannot assert the retained frame.

CONTRACT ASSUMED BY THE CHECKS (adjust together with cli/src/join_entry.rs):
  * `read_input` returns Submitted(sanitized buffer), Cancelled or Interrupted;
    the driver's `len=N` is the submitted UTF-8 byte length.
  * the inline reader uses the shared three-row EntryPainter: prompt, input,
    hint; the native caret parks on the input row, which is probe row
    `cursorY`, and the hint is the row below it.
  * initial paint and each resize reserve exactly three fresh rows
    (`ESC[2K`); ordinary keys never clear a row.
  * accepted invitation/JSON material is a non-empty mask, and the input row
    never contains its prefix or payload.
"""
import base64
import fcntl
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DRIVER = 'join_entry::tests::pty_driver'
BEGIN_SYNC = b'\x1b[?2026h'
END_SYNC = b'\x1b[?2026l'
RESULT = re.compile(rb'JOIN:(submitted len=(\d+)|cancelled|interrupted)')
ANSI = re.compile(rb'\x1b\[[0-9;? ]*[A-Za-z]|\x1b\][^\x1b\x07]*(?:\x07|\x1b\\)')

CODE = 'brave-otter-3141'
# 49 bytes: a structurally-ready claim, one byte past the 48-byte code ceiling.
CODE_49 = 'brave-otter-' + 'a' * 32 + '-3141'
# The same ready shape exactly at the ceiling.
CODE_48 = 'brave-otter-' + 'a' * 31 + '-3141'
# 49 bytes with a six-digit trailing group: still over the protocol ceiling.
CODE_49_SIX = 'brave-otter-' + 'a' * 30 + '-123456'
# Opaque credentials that merely contain a slash. They are not paths and must
# not be painted; unique so they cannot be confused with the code constants.
OPAQUE_B64 = 'YWJj/ZGVmT1BBUVVFLXNlY3JldA'
OPAQUE_URL = 'https://host/?token=Unique9f3aSecret'
# 50 visible characters, 49-byte code once the leading '?' is deleted.
STICKY_OVER = '?' + 'brave-otter-' + 'z' * 32 + '-3141'
PAYLOAD = 'S3CRET-PAYLOAD-DO-NOT-ECHO-7f3a9c'
INVITE = 'filament-invite:v2:' + PAYLOAD
TLNINV = 'TLNINV-' + PAYLOAD
LEFT_CLEAR = b'\x1b[2K'


def set_size(fd, cols, rows):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))


class Session:
    """One driver process on a PTY. Standalone by design: the ENTRY/picker
    fixture in pairing-inline-pty.py encodes rules for other drivers."""

    def __init__(self, binary, cols, rows, term='xterm-256color', no_color=False, extra_env=None):
        self.master, slave = pty.openpty()
        self.before = termios.tcgetattr(slave)
        self.width = cols
        self.height = rows
        self.reservations = 1
        set_size(slave, cols, rows)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('TUNLION_', 'FIL_'))}
        env.update(TERM=term, LANG='C.UTF-8')
        env.pop('NO_COLOR', None)
        env.pop('TUNLION_COLOR', None)
        if no_color:
            env['NO_COLOR'] = '1'
        env.update(extra_env or {})
        self.process = subprocess.Popen(
            [binary, '--ignored', '--exact', DRIVER, '--nocapture',
             '--test-threads=1', '--color', 'never'],
            stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        self.output = bytearray()
        self.observer = None

    # ----------------------------------------------------------- reading --
    def _read(self, timeout):
        if not select.select([self.master], [], [], timeout)[0]:
            return False
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return False
        if not chunk:
            return False
        self.output.extend(chunk)
        if self.observer:
            self.observer(chunk)
        return True

    def drain(self, idle=.04):
        deadline = time.monotonic() + idle
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
            if not select.select([self.master], [], [], remaining)[0]:
                return
            if not self._read(0):
                return

    def read_until(self, predicate, timeout=10, label='output'):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate(self.output):
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if not self._read(min(.1, remaining)) and self.process.poll() is not None:
                break
        if predicate(self.output):
            return
        raise AssertionError(
            f'missing {label}: {ANSI.sub(b"", bytes(self.output))[-3000:]!r}')

    def syncs(self):
        return self.output.count(END_SYNC)

    def wait_frame(self, timeout=10):
        """Wait for the next synchronized-update End, not for a hint string.
        EntryPainter paints only changed suffixes, so old text is not repeated."""
        start = self.syncs()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.syncs() > start:
                self.drain(.05)  # let the VT see the final caret positioning
                return
            self._read(min(.1, max(0, deadline - time.monotonic())))
        raise AssertionError(
            f'missing synchronized frame: {ANSI.sub(b"", bytes(self.output))[-2000:]!r}')

    def wait_optional_frame(self, seconds=.4):
        """True when a frame arrives, False on a bounded idle sample. Used for
        inputs whose UI may legitimately be a no-op (ignored Enter)."""
        start = self.syncs()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.syncs() > start:
                self.drain(.04)
                return True
            self._read(.05)
        return self.syncs() > start

    def expect_idle(self, seconds=.35):
        assert not select.select([self.master], [], [], seconds)[0], \
            'an ignored key repainted or re-rendered the UI'
        assert self.process.poll() is None

    # ----------------------------------------------------------- writing --
    def send(self, keys):
        os.write(self.master, keys)

    def paste(self, text):
        self.send(b'\x1b[200~' + text + b'\x1b[201~')

    def resize(self, cols, rows):
        """Real terminal resize: one new reservation is the only legal clear."""
        set_size(self.master, cols, rows)
        self.width = cols
        self.height = rows
        self.reservations += 1
        os.kill(self.process.pid, signal.SIGWINCH)

    def wait_result(self, timeout=15):
        self.read_until(
            lambda out: RESULT.search(ANSI.sub(b'', bytes(out))) is not None,
            timeout, 'JOIN result (driver contract)')
        match = RESULT.search(ANSI.sub(b'', bytes(self.output)))
        assert match, ANSI.sub(b'', bytes(self.output))[-2000:]
        value = match.group(1)
        if value.startswith(b'submitted'):
            return 'submitted', int(match.group(2))
        return value.decode(), 0

    # ---------------------------------------------------------- lifecycle --
    def finish(self, plain=False, no_color=False):
        if self.process.poll() is None:
            self.process.wait(timeout=10)
        assert self.process.returncode == 0, bytes(self.output)[-2000:]
        flags = termios.ECHO | termios.ICANON
        assert termios.tcgetattr(self.master)[3] & flags == self.before[3] & flags, \
            'terminal ECHO/ICANON was not restored'
        assert b'\x1b[?1049' not in self.output, 'alternate screen used'
        assert b'\x1b[2J' not in self.output, 'full clear used'
        if plain:
            assert b'\x1b' not in self.output, bytes(self.output)
            return
        assert BEGIN_SYNC in self.output
        assert self.output.count(END_SYNC) == self.output.count(BEGIN_SYNC) + 1, \
            'synchronized update was left open or unbalanced'
        assert b'\x1b[6 q' in self.output, 'thin caret was not requested'
        assert b'\x1b[0 q' in self.output, "user's caret was not restored"
        assert b'\x1b[?2004h' in self.output, 'bracketed paste was not enabled'
        assert b'\x1b[?2004l' in self.output, 'bracketed paste was not disabled'
        assert b'\x1b[?25l' not in self.output, 'cursor hide/show flashing'
        assert b'  | ' not in self.output, 'static input marker is back'
        # EntryPainter reserves exactly three rows once, and again only after a
        # resize. A per-keystroke clear is a repaint and fails here.
        assert self.output.count(LEFT_CLEAR) == 3 * self.reservations, \
            (self.output.count(LEFT_CLEAR), self.reservations)
        if no_color:
            assert b'\x1b]12;' not in self.output
            assert b'\x1b[33m' not in self.output
            assert b'\x1b]112' not in self.output
        else:
            assert b'\x1b]12;#e6b450' in self.output
            assert b'\x1b]112' in self.output

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()
        try:
            os.close(self.master)
        except OSError:
            pass


class Probe:
    """NDJSON bridge to a real VT emulator; mirrors pairing-resize-pty.py."""

    def __init__(self, session, cols, rows):
        self.session = session
        self.initial = [cols, rows]
        self.events = []
        self.frame = None
        try:
            self.process = subprocess.Popen(
                ['node', str(HERE / 'terminal-probe.cjs'), str(cols), str(rows)],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        except FileNotFoundError as error:
            raise AssertionError(
                'terminal-probe needs node and @xterm/headless@6.0.0 on NODE_PATH; '
                'rerun with --no-probe for the transcript-only checks') from error
        session.observer = self.feed

    def command(self, message):
        self.events.append(message)
        self.process.stdin.write(json.dumps(message) + '\n')
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            raise AssertionError(
                'terminal-probe exited; install @xterm/headless@6.0.0 and point NODE_PATH at it')
        self.frame = json.loads(line)
        for reply in self.frame['replies']:
            self.session.send(base64.b64decode(reply))
        return self.frame

    def feed(self, data):
        return self.command({'data': base64.b64encode(data).decode()})

    def resize(self, cols, rows):
        self.command({'resize': [cols, rows]})  # real VT reflows first
        self.session.resize(cols, rows)

    def text(self):
        return '' if self.frame is None else '\n'.join(self.frame['lines'])

    def input_row(self):
        if self.frame is None:
            return ''
        y = self.frame['cursorY']
        return self.frame['lines'][y] if 0 <= y < len(self.frame['lines']) else ''

    def hint_row(self):
        if self.frame is None:
            return ''
        y = self.frame['cursorY'] + 1
        return self.frame['lines'][y] if 0 <= y < len(self.frame['lines']) else ''

    def save(self, directory, name):
        if directory is None:
            return
        Path(directory).mkdir(parents=True, exist_ok=True)
        Path(directory, name + '.json').write_text(json.dumps({
            'initial': self.initial, 'events': self.events, 'frame': self.frame}, indent=2))
        print(name + ':\n' + self.text())

    def close(self):
        try:
            self.process.stdin.close()
        except OSError:
            pass
        self.process.wait(timeout=5)


# ---------------------------------------------------------------- helpers --
def frame_leaks(probe, secrets):
    if probe is None:
        return
    text = probe.text() + '\n' + probe.input_row()
    for secret in secrets:
        needle = secret.decode() if isinstance(secret, bytes) else secret
        assert needle not in text, (needle, text)


def assert_no_payload(session, probe, secrets):
    for secret in secrets:
        needle = secret.encode() if isinstance(secret, str) else secret
        assert needle not in session.output, ('credential leaked', 'raw PTY transcript')
    frame_leaks(probe, secrets)


def assert_masked(probe, session, secrets, label):
    """The payload never reaches the wire; the cursor row shows a mask, not the
    invitation prefix. This assumes the inline input row is under the caret
    (EntryPainter parks it there). Prefixed hints elsewhere in the UI are fine;
    only the input row is inspected for the prefix."""
    assert_no_payload(session, probe, [PAYLOAD])
    if probe is None:
        return
    row = probe.input_row()
    assert row.strip(), f'{label}: nothing was painted for accepted invitation material'
    lowered = row.lower()
    for secret in secrets:
        assert secret not in row, (label, row)
    assert 'filament-invite' not in lowered, (label, row)
    assert 'tlninv-' not in lowered, (label, row)
    assert '{' not in row, (label, row)
    assert '|' not in row, (label, 'static input marker')


def assert_fully_masked(probe, session, secrets, label):
    """The material is masked for its whole length, not merely absent from the
    visible prefix. No frame wait: callers drain after the edit because a
    clipped row can legitimately repaint nothing."""
    assert_no_payload(session, probe, secrets)
    if probe is None:
        return
    row = probe.input_row().strip()
    assert row, f'{label}: masked row is empty'
    assert set(row) == {'*'}, (label, 'unmasked cell in input row', probe.input_row())


def cursor_only_since(session, offset, label):
    delta = ANSI.sub(b'', bytes(session.output[offset:]))
    assert delta == b'', (label, 'navigation repainted text', delta)


def live(binary, cols, rows, probe_frame=True, no_color=False):
    session = Session(binary, cols, rows, no_color=no_color)
    try:
        probe = Probe(session, cols, rows) if probe_frame else None
    except BaseException:
        session.close()
        raise
    return session, probe


# ------------------------------------------------------------------ cases --
def code_live(binary, cols, rows, out, probe_frame, no_color=False):
    """Live steering at each keystroke, explicit Enter, ignored Enter/navigation."""
    session, probe = live(binary, cols, rows, probe_frame, no_color)
    try:
        session.wait_frame()
        assert session.output.count(LEFT_CLEAR) == 3
        assert_no_payload(session, probe, [PAYLOAD])
        empty_hint = probe.hint_row() if probe else ''

        # Enter on an empty buffer is the explicit no-op: no frame, no result.
        before = session.syncs()
        clears = session.output.count(LEFT_CLEAR)
        session.send(b'\r')
        session.expect_idle(.4)
        assert session.syncs() == before, 'ignored Enter painted a frame'
        assert session.output.count(LEFT_CLEAR) == clears
        assert b'JOIN:' not in session.output

        for character in CODE[:5]:
            session.send(character.encode())
            session.wait_frame()
        assert b'JOIN:' not in session.output
        partial_hint = probe.hint_row() if probe else ''
        if probe:
            assert partial_hint != empty_hint, 'hint did not nudge as characters arrived'

        for character in CODE[5:]:
            session.send(character.encode())
            session.wait_frame()
        if probe:
            complete_hint = probe.hint_row().lower()
            assert complete_hint != partial_hint.lower(), 'ready hint did not replace the nudge'
            assert any(word in complete_hint for word in ('enter', 'accept', 'ready')), \
                ('ready hint missing an explicit Enter cue', complete_hint)
        session.expect_idle(.2)

        # Home/End/Left move the native caret only: no text repaint, no clear.
        offset = len(session.output)
        clears = session.output.count(LEFT_CLEAR)
        for key in (b'\x1b[D', b'\x1b[H', b'\x1b[F'):
            session.send(key)
            session.wait_frame()
        cursor_only_since(session, offset, 'navigation')
        assert session.output.count(LEFT_CLEAR) == clears
        assert session.output.count(LEFT_CLEAR) == 3

        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        assert_no_payload(session, probe, [PAYLOAD])
        session.finish(no_color=no_color)
        if probe:
            probe.save(out, f'join-code-{cols}x{rows}' + ('-nocolor' if no_color else ''))
    finally:
        session.close()
        if probe:
            probe.close()


def invite_edits(binary, cols, rows, out, probe_frame):
    """Invitation is masked, stays masked through prefix edits, never leaks."""
    session, probe = live(binary, cols, rows, probe_frame)
    invite = INVITE.encode()
    try:
        session.wait_frame()
        session.paste(invite)
        session.wait_frame()
        assert_masked(probe, session, [PAYLOAD], 'invitation paste')

        # Prefix edits are the sticky-mask test: with the prefix gone, a naive
        # renderer would unmask and dump the payload.
        session.send(b'\x1b[H')
        session.wait_frame()
        assert_masked(probe, session, [PAYLOAD], 'after Home')
        for _ in range(2):
            session.send(b'\x1b[3~')
            # The mask is wider than the row, so deleting a clipped prefix
            # character can leave the visible cells, caret and hint identical.
            # The shared painter then correctly emits NO frame; accept either a
            # frame or a bounded no-op, and let the submitted length below prove
            # both edits happened. Payload checks stay on every step and at exit.
            session.wait_optional_frame(.4)
            assert_masked(probe, session, [PAYLOAD], 'after prefix Delete')
        assert b'JOIN:' not in session.output  # paste/edits are never submission

        session.send(b'\r')
        kind, length = session.wait_result()
        assert kind == 'submitted'
        # Assumed value semantics: raw bytes minus the two deleted prefix bytes.
        assert length == len(invite) - 2, (length, len(invite))
        assert_no_payload(session, probe, [PAYLOAD])
        session.finish()
        if probe:
            probe.save(out, f'join-invite-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def json_and_tlninv(binary, cols, rows, out, probe_frame):
    """Leading-whitespace multiline JSON and TLNINV- are masked; embedded
    newlines never submit. Ctrl-U resets between kinds."""
    session, probe = live(binary, cols, rows, probe_frame)
    document = ('   {\n  "invite": "' + INVITE + '",\n  "note": "second line"\n}').encode()
    try:
        session.wait_frame()
        session.paste(document)
        assert session.wait_optional_frame(.8), 'multiline JSON paste painted no frame'
        assert session.process.poll() is None
        assert b'JOIN:' not in session.output, 'newline inside pasted JSON submitted'
        session.expect_idle(.3)
        assert_masked(probe, session, [PAYLOAD], 'multiline JSON')
        if probe:
            assert '{' not in probe.input_row()

        session.send(b'\x15')  # Ctrl-U
        session.wait_frame()
        assert probe is None or not probe.input_row().strip(), 'Ctrl-U left text behind'

        session.paste(TLNINV.encode())
        session.wait_frame()
        assert_masked(probe, session, [PAYLOAD], 'TLNINV-')
        session.send(b'\x15')
        session.wait_frame()

        session.paste(document)
        session.wait_frame()
        session.send(b'\r')
        kind, length = session.wait_result()
        assert kind == 'submitted', kind
        assert length > 0
        assert_no_payload(session, probe, [PAYLOAD])
        session.finish()
        if probe:
            probe.save(out, f'join-json-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def paste_specials(binary, cols, rows, out, probe_frame):
    """Enter/Esc/Ctrl-C inside a bracketed paste are data, never actions."""
    session, probe = live(binary, cols, rows, probe_frame)
    try:
        session.wait_frame()
        session.paste(b'abc\r\x1b\x03def')
        session.wait_frame()
        session.expect_idle(.25)
        assert session.process.poll() is None
        assert b'JOIN:' not in session.output, 'pasted control bytes acted as keys'

        session.send(b'\x15')  # Ctrl-U resets the buffer
        session.wait_frame()
        assert probe is None or not probe.input_row().strip()
        session.paste(CODE.encode())
        session.wait_frame()
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-paste-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def oversize(binary, cols, rows, out, probe_frame):
    """Paste above the 64 KiB bound is refused wholesale, and Enter stays
    blocked until Ctrl-U; a 49-byte ready-shaped code is refused while the
    48-byte boundary still submits."""
    session, probe = live(binary, cols, rows, probe_frame)
    big = b'a' * (64 * 1024 + 1)
    try:
        session.wait_frame()
        offset = len(session.output)
        session.paste(big)
        session.wait_optional_frame(1.0)
        assert len(session.output) - offset < 8192, 'oversize paste was echoed or painted'
        assert big not in session.output
        assert b'JOIN:' not in session.output

        session.send(b'\r')
        session.wait_optional_frame(.4)
        assert b'JOIN:' not in session.output, 'Enter submitted a refused oversize buffer'
        session.send(b'\x15')
        session.wait_frame()

        code49 = CODE_49.encode()
        assert len(code49) == 49
        session.paste(code49)
        session.wait_frame()
        session.send(b'\r')
        session.wait_optional_frame(.4)
        assert b'JOIN:' not in session.output, '49-byte code bypassed the 48-byte ceiling'

        session.send(b'\x15')
        session.wait_frame()

        code48 = CODE_48.encode()
        assert len(code48) == 48
        session.paste(code48)
        session.wait_frame()
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', 48), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-oversize-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def unicode_path(binary, cols, rows, out, probe_frame):
    """A Unicode path buffer is edited by scalar value, never sliced mid-byte."""
    session, probe = live(binary, cols, rows, probe_frame)
    path = '/tmp/邀请函-δ.json'.encode()
    try:
        session.wait_frame()
        session.paste(path)
        session.wait_frame()
        assert session.process.poll() is None
        session.send(b'\x1b[H')
        session.wait_frame()
        for _ in range(5):
            session.send(b'\x1b[C')
            session.wait_frame()
        session.send(b'\x1b[3~')  # delete one whole CJK scalar
        session.wait_frame()
        bytes(session.output).decode('utf-8')  # a mid-codepoint split raises here
        session.expect_idle(.2)

        session.send(b'\x15')
        session.wait_frame()
        session.paste(CODE.encode())
        session.wait_frame()
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-unicode-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def hardening(binary, cols, rows, out, probe_frame):
    """Focused regressions for the incoming join_entry hardening.

    No action below waits for a synchronized frame: a clipped row may correctly
    repaint nothing. Each step uses bounded drain, and every submit asserts the
    exact byte length (the only value the driver exposes).
    """
    for text in ('-' + CODE_48, '--' + CODE_48[1:]):
        session, probe = live(binary, cols, rows, probe_frame)
        try:
            session.wait_frame()
            session.paste(text.encode())
            session.drain(.2)
            session.send(b'\r')
            # Raw input remains intact; the typed boundary trims/collapses
            # separators before the now-checked protocol normalizer sees it.
            assert session.wait_result() == ('submitted', len(text))
            session.finish()
        finally:
            session.close()
            if probe:
                probe.close()

    # 1. A pasted trailing newline is data. The row is longer than 48 bytes, but
    #    the normalized code is exactly 48, so Enter must submit the full row.
    session, probe = live(binary, cols, rows, probe_frame)
    try:
        session.wait_frame()
        session.paste((CODE_48 + '\n').encode())
        session.drain(.4)
        assert b'JOIN:' not in session.output, 'pasted newline submitted by itself'
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE_48) + 1), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-newline-48-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()

    # 2. A 49-byte code ending in a six-digit group is still over the ceiling.
    session, probe = live(binary, cols, rows, probe_frame)
    try:
        session.wait_frame()
        session.paste(CODE_49_SIX.encode())
        session.drain(.4)
        session.send(b'\r')
        session.drain(.4)
        assert b'JOIN:' not in session.output, 'six-digit-suffix 49-byte code submitted'
        assert session.process.poll() is None
        session.send(b'\x15')
        session.drain(.15)
        session.paste(CODE.encode())
        session.drain(.2)
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-six-digit-49-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()

    # 3. Sticky masking is presentation, not a limit exemption. '?' makes the
    #    field secret; deleting it leaves a real 49-byte code, still masked and
    #    still blocked.
    code_over = STICKY_OVER[1:]
    session, probe = live(binary, cols, rows, probe_frame)
    try:
        session.wait_frame()
        session.paste(STICKY_OVER.encode())
        session.drain(.4)
        assert b'JOIN:' not in session.output
        assert_fully_masked(probe, session, [STICKY_OVER], 'sticky masked paste')
        session.send(b'\x1b[H')
        session.drain(.15)
        session.send(b'\x1b[3~')
        session.drain(.4)
        assert_fully_masked(probe, session, [STICKY_OVER, code_over], 'sticky masked over-limit code')
        if probe:
            assert '48' in probe.hint_row(), ('limit hint missing while masked', probe.hint_row())
        session.send(b'\r')
        session.drain(.4)
        assert b'JOIN:' not in session.output, 'masked over-limit code submitted'
        assert session.process.poll() is None
        session.send(b'\x15')
        session.drain(.15)
        session.paste(CODE.encode())
        session.drain(.2)
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-sticky-limit-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()

    # 4. A slash does not make an opaque credential a path. Neither a base64
    #    blob nor a URL may be painted; Ctrl-U drops each before the code.
    session, probe = live(binary, cols, rows, probe_frame)
    try:
        session.wait_frame()
        for index, token in enumerate((OPAQUE_B64, OPAQUE_URL)):
            session.paste(token.encode())
            session.drain(.4)
            assert token.encode() not in session.output, f'opaque credential painted: {token}'
            assert_fully_masked(probe, session, [token], f'opaque credential {index}')
            session.send(b'\x15')
            session.drain(.15)
        session.paste(CODE.encode())
        session.drain(.2)
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, f'join-opaque-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def ending(binary, cols, rows, keys, expected, out, probe_frame=True, no_color=False):
    session = Session(binary, cols, rows, no_color=no_color)
    probe = Probe(session, cols, rows) if probe_frame else None
    try:
        session.wait_frame()
        session.paste(CODE[:5].encode())
        session.wait_frame()
        session.send(keys)
        kind, _ = session.wait_result()
        assert kind == expected, (kind, expected)
        assert_no_payload(session, probe, [PAYLOAD])
        session.finish(no_color=no_color)
        if no_color and probe:
            probe.save(out, f'join-cancel-nocolor-{cols}x{rows}')
    finally:
        session.close()
        if probe:
            probe.close()


def resize(binary, out, probe_frame=True):
    """Resize is the only other permitted reservation: exactly three new clears,
    then normal typing keeps the same rows."""
    session = Session(binary, 96, 24)
    probe = Probe(session, 96, 24) if probe_frame else None
    try:
        session.wait_frame()
        assert session.output.count(LEFT_CLEAR) == 3
        for character in CODE[:5]:
            session.send(character.encode())
            session.wait_frame()
        if probe:
            probe.resize(40, 12)
        else:
            session.resize(40, 12)
        session.wait_frame()
        assert session.output.count(LEFT_CLEAR) == 6, 'resize did not reserve exactly once'
        for character in CODE[5:]:
            session.send(character.encode())
            session.wait_frame()
        assert session.output.count(LEFT_CLEAR) == 6, 'typing after resize cleared rows'
        if probe:
            probe.resize(96, 24)
        else:
            session.resize(96, 24)
        session.wait_frame()
        assert session.output.count(LEFT_CLEAR) == 9, 'second resize did not reserve exactly once'
        session.send(b'\r')
        kind, length = session.wait_result()
        assert (kind, length) == ('submitted', len(CODE)), (kind, length)
        session.finish()
        if probe:
            probe.save(out, 'join-resize-96x24-40x12')
    finally:
        session.close()
        if probe:
            probe.close()


def dumb(binary):
    """TERM=dumb: hidden input, zero escape bytes, no alternate screen."""
    for text, expected in ((INVITE, len(INVITE)), (CODE, len(CODE))):
        session = Session(binary, 40, 12, term='dumb')
        try:
            session.read_until(lambda out: len(out) > 0, 10, 'dumb prompt')
            session.drain(.25)
            session.send(text.encode() + b'\r')
            kind, length = session.wait_result()
            assert (kind, length) == ('submitted', expected), (kind, length)
            assert PAYLOAD.encode() not in session.output
            session.finish(plain=True)
        finally:
            session.close()


def main(argv):
    if len(argv) < 2:
        raise SystemExit('usage: join-entry-pty.py <test-binary> [outdir] [--no-probe]')
    binary = os.path.abspath(argv[1])
    rest = [argument for argument in argv[2:] if not argument.startswith('--')]
    out = Path(rest[0]).resolve() if rest else None
    probe_frame = '--no-probe' not in argv[2:]
    if probe_frame and shutil.which('node') is None:
        raise SystemExit('node is required for VT snapshots; install @xterm/headless@6.0.0 '
                         'on NODE_PATH or pass --no-probe')

    for cols, rows in ((40, 12), (96, 24)):
        code_live(binary, cols, rows, out, probe_frame)
        invite_edits(binary, cols, rows, out, probe_frame)
        json_and_tlninv(binary, cols, rows, out, probe_frame)
        paste_specials(binary, cols, rows, out, probe_frame)
        oversize(binary, cols, rows, out, probe_frame)
        hardening(binary, cols, rows, out, probe_frame)
        unicode_path(binary, cols, rows, out, probe_frame)
        ending(binary, cols, rows, b'\x1b', 'cancelled', out, probe_frame)
        ending(binary, cols, rows, b'\x03', 'interrupted', out, probe_frame)
        print(f'PASS {cols}x{rows}: live nudge/Enter, masked invite+JSON through edits, '
              'paste data, 64KiB/48-byte bounds, newline-normalized 48, six-digit '
              'suffix, sticky masked over-limit, opaque slash/URL, Ctrl-U, Unicode, '
              'cancel/interrupt')
    ending(binary, 40, 12, b'\x1b', 'cancelled', out, probe_frame, no_color=True)
    resize(binary, out, probe_frame)
    dumb(binary)
    print('PASS: NO_COLOR, initial+resize-only clears, TERM=dumb hidden with no escapes')


if __name__ == '__main__':
    main(sys.argv)
