# Filament update, 2026-06-14 (later)

## All shipped to prod (main = 9602b38, pushed)
Everything below is live (frontend on Cloudflare Pages; CLI installed; web-shell
daemon restarted on the new build).

### Pairing + codes
- 3-segment, user-chosen codes with live steering (auto-dash, 2-word floor,
  machine-assigned connect number).
- One shared `split_chosen_code` for CLI and browser.
- Interactive, color-coded CLI code entry (script-safe gate).
- create-code prod bug fully fixed (stale image redeployed, rogue duplicate tunnel
  on 4-days-late-snaphost nuked, redis message-queue disabled for the single
  replica). Verified in a real browser.

### Transfers (new)
- Ephemeral PAKE on `send --code` / `recv`: transfers now run the same mutual-auth
  ceremony as pairing, then discard the secret. Words never hit the server, the MAC
  binds DTLS fingerprints, nothing is stored.
- Browser "receive with code": claim a code and download in the browser.
- Shared-room mis-latch fixed: per-peer ceremonies, a decoy peer can no longer
  hijack the receive; the real sender wins, byte-exact.

### Web shell (all four, now live)
- Persistence: the PTY survives a disconnect and reattaches on reconnect (stable
  session id, output replay, idle/lifetime caps). Drops no longer lose progress.
- Keyboard show/hide no longer hangs (coalesced safe-fit).
- Full TUIs (opencode, vim, htop) render (fit-before-size + SIGWINCH + raw output).
- Copy and paste work (select-to-copy, paste control, mobile affordances).
- ACTION: refresh the web shell once to pick up the new frontend and daemon.

## What's left
- Browser to CLI transport-resilience end-to-end on real hardware (queued next).
- Minor: a couple of old l1a test scripts (gate1/gate3) have stale hardcoded paths
  and expect the old 3-word code shape; harmless, a cleanup.

## Honest caveats
- Web-shell persistence is proven by a unit test + the wire contract; a genuine
  end-to-end transport drop against the live daemon was not driven headlessly, so
  watch it the first time and tell me if a reconnect ever loses the session.
