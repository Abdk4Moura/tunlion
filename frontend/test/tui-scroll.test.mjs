import test from 'node:test'
import assert from 'node:assert/strict'
import {
  SCROLL_APPLICATION, SCROLL_CURSOR_KEYS, SCROLL_HISTORY,
  applicationWheelActive, isMouseReport, latin1Bytes, pageLines, scrollModeKey, scrollRoute,
  wheelDeltaForDirection,
} from '../src/lib/tui-scroll.js'
import { frame, parseFrame } from '../src/net/protocol/wire.js'

test('ordinary normal-buffer shell scrolls local history', () => {
  assert.equal(scrollRoute('normal', 'none'), SCROLL_HISTORY)
  assert.equal(scrollRoute('normal', undefined), SCROLL_HISTORY)
})

test('a mouse-reporting app owns the wheel, even in the normal buffer', () => {
  // A partial TUI (a fuzzy finder, a file picker, an inline editor) can keep
  // scrollback while enabling mouse tracking. The old route keyed only on the
  // alternate buffer and scrolled its history instead of the app.
  for (const mode of ['vt200', 'drag', 'any']) {
    assert.equal(scrollRoute('normal', mode), SCROLL_APPLICATION)
    assert.equal(scrollRoute('alternate', mode), SCROLL_APPLICATION)
    assert.equal(applicationWheelActive(scrollRoute('normal', mode)), true)
  }
})

test('X10 is click-only: it must not pretend to report wheel', () => {
  // xterm's X10 protocol rejects wheel events. In a normal-buffer X10 app the
  // honest route is local history; in the alternate screen there is no history,
  // so the standard wheel->cursor-key fallback applies.
  assert.equal(scrollRoute('normal', 'x10'), SCROLL_HISTORY)
  assert.equal(scrollRoute('alternate', 'x10'), SCROLL_CURSOR_KEYS)
})

test('alternate screen without wheel reporting uses xterm cursor-key fallback', () => {
  assert.equal(scrollRoute('alternate', 'none'), SCROLL_CURSOR_KEYS)
  assert.equal(scrollRoute('alternate', undefined), SCROLL_CURSOR_KEYS)
  assert.equal(applicationWheelActive(SCROLL_CURSOR_KEYS), false)
})

test('unknown modes fail safe to the ordinary history route', () => {
  assert.equal(scrollRoute('normal', 'future-protocol'), SCROLL_HISTORY)
  assert.equal(scrollRoute(undefined, undefined), SCROLL_HISTORY)
})

test('a page leaves one line of context and always moves at least one line', () => {
  assert.equal(pageLines(24), 23)
  assert.equal(pageLines(1), 1)
  assert.equal(pageLines(0), 23) // no rows yet: use the 24-row default
  assert.equal(pageLines(undefined), 23)
})

test('wheel direction follows xterm: negative deltaY is up', () => {
  assert.equal(wheelDeltaForDirection(-1), -1)
  assert.equal(wheelDeltaForDirection(1), 1)
  assert.equal(wheelDeltaForDirection(0), 1)
})

test('a gesture context is buffer + mouse mode, so either change aborts it', () => {
  assert.equal(scrollModeKey('normal', 'none'), 'normal:none')
  assert.notEqual(scrollModeKey('normal', 'none'), scrollModeKey('normal', 'vt200'))
  assert.notEqual(scrollModeKey('normal', 'vt200'), scrollModeKey('alternate', 'vt200'))
  assert.equal(scrollModeKey(undefined, undefined), 'normal:none')
})

test('only generated SGR mouse reports bypass sticky text modifiers', () => {
  assert.equal(isMouseReport('\x1b[<64;13;8M'), true)
  assert.equal(isMouseReport('\x1b[<65;13;8M'), true)
  assert.equal(isMouseReport('\x1b[<64;1013;800M'), true)
  assert.equal(isMouseReport('a'), false)
  assert.equal(isMouseReport('\x1b[A'), false)
  assert.equal(isMouseReport('\x1b[<64;13;8Mtail'), false)
  assert.equal(isMouseReport(''), false)
})

test('legacy xterm mouse strings become raw Latin-1 bytes, not UTF-8', () => {
  // ESC [ M, wheel-up code 96, column 1-based 151 + 32 = 183, row 8 + 32 = 40.
  const report = '\x1b[M' + String.fromCharCode(96, 183, 40)
  const bytes = Array.from(latin1Bytes(report))
  assert.deepEqual(bytes, [27, 91, 77, 96, 183, 40])
  // The UTF-8 encoding of the same string would be longer and wrong.
  assert.notDeepEqual(bytes, Array.from(new TextEncoder().encode(report)))
})

test('legacy report bytes survive the transport frame unchanged', () => {
  const bytes = latin1Bytes('\x1b[M' + String.fromCharCode(96, 183, 40))
  const parsed = parseFrame(frame(0x80000001, bytes, 7).buffer)
  assert.deepEqual(Array.from(parsed.payload), [27, 91, 77, 96, 183, 40])
})
