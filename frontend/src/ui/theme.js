// Design tokens for the browser UI (the "tunlion browser" design: warm paper and
// ink, one orange accent). One object per theme carries the new token names
// (bg, surf, ink, sub, rule, soft, acc, ok, bad, warn, inv) AND the older names
// the shared pieces still read (text, panel, line, dim, recv, onAccent, ...), so
// WebTerminal, DeviceSheet, CommandPalette and DiagPanel render in the same
// palette without each being rewritten.
//
// Colours are plain hex (converted from the design's oklch values) so every
// browser we support renders them identically.
//
// warn is pinned: the relay-honesty gate asserts the relay chip is exactly this
// amber in each theme, and it is the one colour that must read as "not direct".

export const FONT_SANS = "system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif"
export const FONT_MONO = "ui-monospace, 'SFMono-Regular', 'JetBrains Mono', Menlo, Consolas, 'Liberation Mono', monospace"

const LIGHT = {
  bg: '#f7f6f2', surf: '#ffffff', ink: '#1d1c1a', sub: '#5d5a53', rule: '#dedad0', soft: '#efede6',
  acc: '#d55c13', accInk: '#a53e00',
  ok: '#137738', okBg: '#d6f0da', bad: '#af3b43', badBg: '#ffe3e1',
  warn: '#9A6B00', warnBg: '#ffffff',
  inv: '#ffffff',
}

const DARK = {
  bg: '#141412', surf: '#1d1c1a', ink: '#f2efe6', sub: '#a29e94', rule: '#33312d', soft: '#26251f',
  acc: '#e36927', accInk: '#f19266',
  ok: '#73c385', okBg: '#1a3520', bad: '#f58a8b', badBg: '#472021',
  warn: '#FFC857', warnBg: 'rgba(255,200,87,.14)',
  inv: '#141412',
}

// The terminal is always dark, in both themes: it is where people read output
// for minutes at a time, and the design keeps it dark on a light page too.
export const TERMINAL = { ...DARK, bg: '#121210', surf: '#1d1c1a' }

export function makeTheme(mode) {
  const b = mode === 'light' ? LIGHT : DARK
  return {
    mode: mode === 'light' ? 'light' : 'dark',
    ...b,
    // older names, mapped onto the new palette
    text: b.ink,
    panel: b.surf,
    panel2: b.soft,
    line: b.rule,
    lineSoft: b.soft,
    grid: b.soft,
    dim: b.sub,
    faint: b.sub,
    recv: b.ink,
    onAccent: b.inv,
    accent: b.ink,
  }
}

export function terminalTheme() {
  return { ...makeTheme('dark'), ...TERMINAL, text: TERMINAL.ink, panel: TERMINAL.surf, panel2: TERMINAL.soft, line: TERMINAL.rule, lineSoft: TERMINAL.soft }
}

// The system preference, used when the person has not picked a theme.
export function systemMode() {
  try {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  } catch (e) {
    return 'dark'
  }
}
