# Filament roadmap

Single source of truth for what is in flight, next, and parked. Design detail
lives in `docs/design-*.md`; this file is the backlog and ordering. Keep it short
and current: move items to Shipped when done, add new ones under Backlog or
Exploration.

## Now (in flight)

- **Windows Service + UAC elevation** (PR #21). ShellExecuteW "runas" with a
  Scheduled-Task fallback on decline, firewall rule, userspace fallback. Blocked
  on a real-Windows-runner UAC smoke test (CI cannot drive the elevation prompt).
- **Per-OS capability CI harness** (opencode, starting). Two local nodes paired
  without the hosted signaling server, over the userspace netstack. Spec:
  `docs/design-per-os-ci.md`.

## Next (sequenced)

1. **Per-OS CI, complete.** Capability smoke tests (pair, send/recv, pty
   interactive+exec, forward, expose/proxy) on ubuntu/macos/windows, gated as
   required checks, plus `filament doctor` + support matrix. This is the
   self-policing layer that stops the Windows-regression whack-a-mole.
2. **Finish mount end to end.** Protocol landed (PR #23). Remaining: wire the FUSE
   bridge (fuser 0.17 API), then WinFsp/ProjFS client adapters, then the
   name/metadata model per the spec (raw-byte paths, escaping, capability
   handshake). Rules: `docs/design-cross-platform-capabilities.md`.
3. **ControlChannel: named-pipe warm IPC on Windows.** Today Windows
   forward/ssh/pty/netcat always cold-establish. A named pipe brings warm-path
   parity. Pure speed win.
4. **0.5.1 release.** Cut once #21 verifies. Bundles the reconnect fix (#19), the
   mount stale-dir fix (#22), and Windows elevation (#21).

## Backlog (smaller, known)

- `--shell-user` real Windows implementation (currently only warns).
- Run `filament proxy` automatically as part of `filament up` when kernel TUN is
  unavailable, on a known port.
- HTTP CONNECT proxy alongside SOCKS5 (Tailscale parity; some tools only speak
  HTTP proxy).
- Serve a PAC file so a browser routes only `*.mesh` through the proxy.
- MagicDNS / hosts-file management polish.

## Shipped recently

- ShellHost: Windows pty shell fix, customizable shell, one-shot exec (0.5.0).
- Five-channel distribution via OIDC trusted publishing (crates.io, npm, winget,
  Homebrew, GitHub), no long-lived tokens.
- Reconnect/staircase flap fix (#19); mount stale-dir + honest no-sshd message
  (#22); mesh-native mount protocol foundation (#23).
- macOS osascript shell-arg escaping; branch protection + auto-merge on `main`.
