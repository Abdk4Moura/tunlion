# Filament session results, 2026-06-14

## Shipped to prod (live)
- 3-segment + user-chosen pairing codes, with live steering (auto-dash, 2-word
  floor, machine-assigned connect number).
- `pair --word` split fix (keeps both words; one shared `split_chosen_code` used by
  CLI and browser).
- Interactive, color-coded CLI code entry for `pair`/`recv`/`send` (no flags),
  script-safe gate (`--no-interactive` / `FILAMENT_NONINTERACTIVE` / non-TTY).
- CLI guided-entry redraw fixed: single in-place line, consistent on every shell
  (was walking down one line per keystroke on your shell).
- Frontend hardening: a stale/old server now shows a clear message instead of the
  silent "create code does nothing" hang.
- Polish: correct CLI version stamp, honest create preview, em dashes removed.

## create-code prod bug: fixed end to end
Root causes unwound:
1. The droplet API ran a stale (pre-v2) image. Rebuilt + redeployed (v2).
2. A rogue duplicate filament stack on `4-days-late-snaphost` was running the same
   tunnel since Jun 13, so Cloudflare load-balanced half the traffic to an old v1
   backend. That machine's stack was fully nuked (containers, image, /opt/filament,
   tunnel token).
3. The single-replica API's redis message queue was unstable under eventlet;
   disabled it (in-memory mode). Emits deliver directly now.
Verified in a real browser: create-code mints a code, choose-your-own steering works.

## Pending your push (on local main, not pushed)
The transfer batch: ephemeral PAKE on `send --code`/`recv` (transfers now run the
same mutual-auth ceremony as pairing, then discard the secret), plus a browser
"receive with code" path. Byte-exact transfer verified, pairing unchanged, downgrade
refused loudly. Held for your review.

## In flight
- Fixing the one real caveat in that batch: the recv side could mis-latch onto the
  wrong peer in a shared room. A per-peer ceremony fix is building now; after it
  lands I push the batch with the fix included.

## Captured for next
- Web shell issues you reported: no full TUI/opencode rendering, keyboard-toggle
  hangs, no copy/paste, disconnects lose progress. Biggest fix = persistent PTY that
  reattaches on reconnect. Stopgap today: run shell work inside `tmux` so a drop
  does not lose it.
- Browser to CLI transport-resilience e2e on real hardware (queued).

## Redis question
Settled: stay in-memory (single replica). If you ever scale, the Cloudflare-native
answer is Durable Objects (rooms as DOs), not KV/D1/Queues, but that is a signaling
rewrite onto Workers.
