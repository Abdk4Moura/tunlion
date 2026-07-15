# Per-OS capability CI and `filament doctor`

**Status:** spec. Companion to
[design-cross-platform-capabilities.md](design-cross-platform-capabilities.md).
Goal: stop finding platform regressions by hand.

## Why

We keep shipping Windows breakage that Linux checks miss: the pty `/bin/sh` shell
bug, then the `unsafe extern` (edition 2024) build break. Both were caught late,
by a human, after a "green" claim. Two root causes, both addressed here:

1. **No capability-level tests.** Unit tests build and pass on Linux while a real
   capability (pty, mount) is broken on Windows. Building is not exercising.
2. **"Green" has meant "green on my Linux box," not CI.** See the process rule at
   the bottom.

## Principle

Test each capability end to end, on each OS, at zero privilege. The userspace
netstack lets us pair two local instances and exercise real capabilities with no
kernel TUN and no admin, so the suite runs on stock GitHub runners.

## Covered vs not

**Covered (the smoke suite: userspace, deterministic):** pair, send/recv
(byte-exact), pty interactive, pty exec one-shot, forward, expose/proxy, and mount
once it is end to end.

**Not covered on stock runners (needs the manual/record path):** privileged and
interactive flows: the UAC prompt, kernel TUN creation, and system-service
install. These need admin or an interactive desktop and cannot run on stock
runners. They are verified separately (the Windows-runner record pipeline).
Document this boundary in the suite; never fake a pass for them.

## The harness (foundation, build first)

Two filament instances on one runner, paired WITHOUT the hosted signaling server:

- **Preferred:** a test-only direct pairing path (local loopback handshake) that
  bypasses the hosted signaling server, so CI has no external dependency and no
  network flakiness.
- **Fallback:** spin up a local signaling instance and point both at
  `--server http://127.0.0.1:<port>`.
- Force the **userspace netstack** (no TUN) so it is zero-privilege and
  deterministic.
- Generous timeouts plus a couple of retries; capability tests over real async
  networking are inherently a little flaky.

## The hard parts (design them, do not discover them)

- **Headless pty on Windows.** There is no real TTY on CI. The interactive pty
  test must drive a pseudo-console (ConPTY on Windows, openpty on Unix) with piped
  stdin/stdout and assert on output, not a real terminal. This is the exact class
  of thing that broke before, so it is the highest-risk test to get right.
- **Shell-family differences.** The exec one-shot test asserts the correct
  invocation per family (`-c` for sh/bash/zsh/fish, `-Command` for PowerShell,
  `/c` for cmd), not a POSIX assumption.
- **mount.** Add only once mount is end to end (FUSE/WinFsp wired). Assert a file
  round-trips byte-exact, including a binary blob containing `0x0D 0x0A` to lock in
  byte-transparency, and that a non-UTF-8 filename survives on Linux.

## Matrix and gating

- GitHub Actions matrix: `ubuntu-latest`, `macos-latest`, `windows-latest`.
- Run the smoke suite on each, alongside the existing build/unit jobs.
- Make each a **required status check** (branch protection is already on `main`
  with admin bypass, so this arms auto-merge and blocks red PRs without blocking
  admin release pushes).

## `filament doctor` and the support matrix

- Each capability declares the adapter methods it needs (ShellHost, MountHost
  {FUSE | WinFsp | ProjFS}, ControlChannel, TUN).
- The adapter reports supported-or-not on this host.
- `filament doctor` prints the matrix: capability by supported-here, with an honest
  "X needs Y here: <link>" for gaps. This is the `--install` honest-fallback
  pattern made systematic.
- CI snapshots `filament doctor --json` per OS and asserts it, so the matrix itself
  is regression-tested.

## Sequencing (for opencode)

1. Two-local-nodes harness (direct pairing, userspace netstack). Foundation.
2. pair + send/recv smoke test (proves the harness; simplest, byte-exact assert).
3. pty interactive + exec (headless ConPTY; the hard one).
4. forward + expose/proxy.
5. 3-OS matrix in the workflow; make the jobs required checks.
6. `filament doctor` + support matrix; snapshot-assert in CI.
7. mount smoke test once the mesh-native mount is end to end.

## Process rule (non-code, non-negotiable)

"Green" means the CI run is green on all three OSes, read from `gh pr checks` or
the Actions run, NOT a local Linux `cargo test`. Report per-OS status. This CI
exists precisely because local-Linux-green has repeatedly masked Windows-red.
