# opencode-in-the-web-shell isolation harness (throwaway)

Throwaway test rig (NOT part of the shipped app, not bundled by vite) used to
isolate why `opencode` (an opentui-based TUI doing heavy terminal-capability
detection) would not open in the Filament web shell while plain TUIs (vim/htop/
less) work.

It runs `opencode` in the SAME xterm.js the web shell uses (@xterm/xterm 6.0.0 +
@xterm/addon-fit 0.11.0, with the exact WebTerminal.jsx options) wired to a real
PTY via node-pty over a plain websocket, NOT over the filament data channel. That
splits the problem cleanly:

- Case A: opencode fails even here, so the gap is xterm.js capabilities/options.
- Case B: opencode works here but not in the filament shell, so the gap is the
  filament PTY bridge.

## Result: Case B. opencode renders and is fully interactive in plain xterm.js.

See `opencode-in-plain-xterm.png`: the full opencode TUI (logo, "Ask anything"
input box, model bar, status bar, version 1.15.10) painted in plain xterm.js
6.0.0. Typing into it echoes into the input box. opencode enters the alternate
screen and lays out a usable UI.

xterm.js DID answer the probes opencode actually depends on: OSC 10/11 (fg/bg),
CPR (ESC[6n -> ESC[row;colR), DECRQM (ESC[?n$p -> ESC[?n;v$y), Primary DA
(ESC[c -> ESC[?1;2c), OSC 4 palette. It correctly IGNORES the ones opencode does
not need to start: XTVERSION (ESC[>0q), kitty keyboard (ESC[?u), OSC 1337
capabilities, and the OSC 66 text-sizing protocol. opencode does NOT hang on the
unanswered probes: a bare PTY that answers NOTHING still reaches alt-screen and
paints (see probe-bare-pty.py).

## Probe / response bytes (captured)

opencode startup probes (bare PTY, repr):
  ESC[?2031h OSC10;? OSC11;? ESC[>0q ESC[?25l ESC[s ESC[6n
  ESC[?1016$p ESC[?2027$p ESC[?2031$p ESC[?1004$p ESC[?2004$p ESC[?2026$p
  ESC[?u OSC99(notifications) OSC1337;Capabilities
  OSC66;w=1; ESC[6n OSC66;s=2; ESC[6n  (text-sizing measure)
  ESC[?1049h (alt screen) ... ESC[14t OSC4;0;?

xterm.js replies (captured via term.onData in index.html, window.__state().sent):
  OSC10;rgb:ffff/ffff/ffff  OSC11;rgb:0000/0000/0000
  ESC[1;1R (CPR)  ESC[?1016;2$y ESC[?2027;0$y ESC[?2031;0$y ESC[?1004;2$y
  ESC[?2004;2$y ESC[?2026;2$y  ESC[?1;2c (DA)  OSC4;N;rgb:... (palette)

## COLORTERM finding (the one always-do fix)

Without COLORTERM, opencode emits 256-color (38;5;N). With COLORTERM=truecolor it
emits 24-bit color (38;2;R;G;B). Verified in this harness (?colorterm=1 vs 0):
270 truecolor codes / 0 palette codes WITH it; 0 / many WITHOUT it. Fix applied
in cli/src/l2.rs next to the TERM line.

## How to run

    cd experiments/opencode-webshell-harness
    npm init -y && npm install node-pty ws
    cp ../../frontend/node_modules/@xterm/xterm/lib/xterm.js .
    cp ../../frontend/node_modules/@xterm/xterm/css/xterm.css .
    cp ../../frontend/node_modules/@xterm/addon-fit/lib/addon-fit.js .
    PORT=8799 node bridge.js
    # then open http://127.0.0.1:8799/?cmd=opencode&colorterm=1 in a browser
    # (or drive with Playwright). window.__state() and window.__viewport() expose
    # buffer state and the rendered text for assertions.

probe-bare-pty.py captures opencode's raw startup bytes in a bare PTY that answers
nothing, to prove it does not hang on unanswered queries.

## Note on the harness's own delivery bug (instructive)

The first version mis-rendered (0 bytes reached xterm) because node-pty hands
onData a JS STRING and ws.send(string) sends a TEXT frame, which index.html was
parsing as a control JSON message and dropping. The fix was to send PTY output as
a BINARY frame (Buffer). The REAL filament bridge already frames PTY bytes as
binary in BOTH directions (cli send_frame -> raw bytes; frontend _onMessage ->
Uint8Array via DataView), so it does not have this class of bug. This is exactly
the kind of text-vs-binary mistake to rule out in any PTY transport, and it is
ruled out for filament.
