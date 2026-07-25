# Web-shell mobile redesign — 2026-06-15

Built the agenda-A redesign in `frontend/src/ui/WebTerminal.jsx` (+277/-12, one file).
Kept xterm.js as the rendering core; everything is additive on top of the existing
freeze/IME/scroll hardening (none of it touched). Vite prod build clean; verified
live on `?preview=webterm&touch=1` with Playwright (390×740, no console errors).

## What shipped (all four picks)
1. **Font sizing** — per-device persisted `fontPx` (localStorage `webterm.fontPx`),
   replaces the old hardcoded 13/13.5. `A−`/`A+` header buttons (0.5px steps,
   9–28 clamp) + two-finger **pinch-to-zoom** on the terminal. Every change refits
   so the PTY learns the new cols/rows. Verified: A+ grows text and reflows.
2. **Symbol drawer** — `sym` key toggles an expandable, scrollable punctuation row
   (`~ / | - _ = + : ; ' " \` * # & $ % @ ! ? \ . , ( ) [ ] { } < >`). Each sends
   the literal char through the sticky-modifier path (Ctrl-[ still composes).
3. **Status pill** — explicit states: **live** / **relayed** (from the `route`
   prop) / **reconnecting…** (a `connecting` after we've already been ready) /
   **connecting…** / **ended**, tinted by state, with a pulse while reconnecting.
4. **Command mode** — header toggle (`⌨ term` ⇄ `❯ cmd`, persisted). A real
   `<input>` above the accessory bar: the OS keyboard + its autocomplete/paste type
   here, Enter sends the whole line + CR to the PTY. **History** (↑/↓, persisted to
   `webterm.history`, capped 200) and **autocomplete** (your history first, then a
   common-command list; Tab accepts the top, tap a suggestion to accept). A
   full-screen TUI (alt-screen flip) **auto-switches to terminal mode** for its
   lifetime and **flips back** on exit — verified round-trip with the mock `tui`.

## Verified with Playwright (mock shell)
live pill · A+ grows+reflows · sym drawer opens/sends · cmd toggle · `git`→suggest
list · Tab→`git status` · run `ls`→output · ↑→recalls `ls` · `tui`→auto term mode →
`exit-tui`→auto back to cmd · localStorage persists fontPx/mode/history.

## Not driven headlessly (logic-verified, watch on real hardware)
- **Pinch-to-zoom**: two-finger gesture is hard to synthesize in Playwright; it
  shares the exact `fontPx` path that A−/A+ proved. Try it on the phone.
- **reconnecting… pill**: the mock's connect→ready window is ~60ms, too fast to
  catch in a screenshot; it's pure derived state (`seenReady && connecting`).
- Command mode in cmd-mode does not aggressively steal focus back from xterm if you
  tap the output area (tap focuses xterm raw). Acceptable for v1; flag if it bites.

## Not done / deliberately deferred
- Customizable accessory-bar order (agenda mentioned it; lower value than the above).
- Not committed/pushed — push triggers the Cloudflare auto-deploy, so this waits for
  your real-device pass first.
