// Mode-aware scrolling for the browser shell.
//
// A terminal is not one scroll context. xterm itself already routes a wheel
// event differently depending on what the application asked for:
//
//   - normal buffer + no mouse tracking: the wheel scrolls local scrollback;
//   - any buffer + VT200/DRAG/ANY tracking: xterm encodes the wheel report using
//     the protocol/encoding the application selected (SGR, legacy, pixels);
//   - alternate buffer + no wheel-capable tracking: no scrollback exists, so
//     xterm converts the wheel into an Up/Down cursor key, honouring the
//     application's DECCKM (applicationCursorKeys) mode.
//
// X10 is deliberately not in the reporting set: it is click-only and xterm's
// X10 protocol rejects wheel events. Pretending it accepts them would swallow
// the gesture, so in a normal-buffer X10 app we keep local history scrolling.
export const WHEEL_REPORTING_MODES = Object.freeze(['vt200', 'drag', 'any'])

export const SCROLL_HISTORY = 'history'          // local xterm scrollback
export const SCROLL_APPLICATION = 'application'  // xterm-encoded wheel report
export const SCROLL_CURSOR_KEYS = 'cursor-keys'  // xterm wheel -> Up/Down keys

// Pick the route a touch gesture / accessory page should use. `bufferType` is
// term.buffer.active.type ('normal' | 'alternate'); `mouseTrackingMode` is
// term.modes.mouseTrackingMode ('none' | 'x10' | 'vt200' | 'drag' | 'any').
export function scrollRoute(bufferType, mouseTrackingMode) {
  const mode = mouseTrackingMode || 'none'
  if (WHEEL_REPORTING_MODES.includes(mode)) return SCROLL_APPLICATION
  if (bufferType === 'alternate') return SCROLL_CURSOR_KEYS
  return SCROLL_HISTORY
}

// True when the wheel belongs to the application (a TUI), including a partial
// TUI that keeps the normal buffer with its scrollback. History-only chrome
// (the custom scrollbar and scroll-to-bottom button) must stay out of its way.
export function applicationWheelActive(route) {
  return route === SCROLL_APPLICATION
}

// A page button moves a page but leaves one line of context, like a pager.
export function pageLines(rows) {
  return Math.max(1, (Number(rows) || 24) - 1)
}

// xterm's wheel contract: negative deltaY = up, positive = down.
export function wheelDeltaForDirection(dir) {
  return dir < 0 ? -1 : 1
}
