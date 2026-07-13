# Making Windows a first-class node

**Status:** design / plan. Windows currently *compiles and runs*, but roughly
every path behind `#[cfg(unix)]` degrades to a stub, a no-op, or a `bail!`. This
plan takes Windows from "it builds" to "it feels native" — in three phases, with
correctness and safety first.

> **Scope note — this is really "first-class on every host."** Windows is the
> worst-off, so it drives the plan, but several host-integration assumptions bite
> **macOS and non-systemd Linux** too. The clearest example is **service
> management**: the code assumes systemd (see the dedicated section below), which
> is already broken on macOS (launchd), on Alpine/Void/Gentoo/Devuan
> (OpenRC/runit/s6/SysV), and on Windows. Treat the `platform/` abstraction as
> cross-platform, not Windows-only.

## What "first-class" means here

Two bars, in order:

1. **Correct & safe** — nothing on Windows is silently *wrong*. State lands in
   the right place, secrets are protected, self-update works, and CI proves it.
   (Several items today fail this bar, not merely the next one.)
2. **Native feel** — the daily paths (`send`, `recv`, `ssh`, `pty`, `up`) are as
   fast and as integrated on Windows as on Linux: warm-link reuse, ConPTY,
   service autostart, firewall, the mesh.

The data plane already helps us: the QUIC/WebRTC transfer core, `portable-pty`
(ConPTY), `crossterm`, and the **Wintun** TUN backend (`tun/windows.rs`) are all
cross-platform today. The gap is the *host integration* layer around them.

## Current reality (grounded)

| Subsystem | Windows today | Anchor |
|---|---|---|
| **Config/data dir** | HOME is unset → resolves to `./.config/filament` (cwd-relative). No `APPDATA` support anywhere. | `settings.rs:233` |
| **File permissions** | Every `0600`/`0700` is a **no-op**. Private ed25519 key, `devices.json` secrets, `peerconf` written unhardened. | `sshkeys.rs:48`, `main.rs:1280` |
| **Warm-link IPC** | Absent. `ctl::Req` uninhabited, `try_ping`→`None`. `filament up` binds no control socket. Every `ssh`/`pty`/`netcat`/`forward`/`ping` cold-establishes (~1s+). | `ctl.rs:638` |
| **Self-update** | Downloads + verifies checksum, then `bail!("zip self-update not supported")`. No in-place update. | `main.rs:6150` |
| **Service/autostart** | No Windows Service. `--install --system` bails; `--install` writes a dead systemd unit and fails to enable. No watchdog. | `main.rs:1920`, `1945` |
| **`.mesh` ssh-over-L3** | Absent (`cfg(target_os="linux")`). `l3_dest`→`None`; `ssh`/`mount`/`rsync` always fall to the L2 tunnel. | `l2.rs:2907`, `3224` |
| **`serve-tun`** | Hard `bail!("Linux-only")` **despite Wintun existing**. | `main.rs:5851` |
| **`recv -o -`** | `bail!("not supported on this platform yet")`. | `main.rs:9907` |
| **Wintun L3 core** | **Implemented, near-parity** (addr/route via `netsh`, netstack fallback). | `tun/windows.rs` |
| **hosts path** | Correctly cross-platform (`…\System32\drivers\etc\hosts`). | `l3.rs:504` |
| **CI** | Windows is **build-only**; the test suite runs on Linux only. Windows runtime regressions are invisible. | `test.yml:24-64` |

The through-line: most of these are *host-integration* stubs, and the two
worst — config dir and permissions — mean a Windows install writes **secrets to
an unpredictable, unprotected location.** That's the thing to fix first.

## Abstraction strategy — a `platform` layer, not more `#[cfg]`

Today platform logic is ~90 scattered `#[cfg]` sites. Consolidate the *policy*
behind a small set of traits in a new `platform/` module, with `unix.rs` /
`windows.rs` implementations, so call sites stay platform-free and the Windows
behavior is defined in one place per concern:

- `Paths` — config/data/cache/state dirs, ssh dir. (Windows: `%APPDATA%` /
  `%LOCALAPPDATA%` via the `directories` crate; Unix: XDG/`$HOME` as today.)
- `SecretFile` — create-or-open a file locked to the current user. (Unix:
  `chmod 0600`; Windows: a per-user DACL via `SetNamedSecurityInfo`/ICACLS, or
  DPAPI-wrapped contents.)
- `ControlChannel` — the warm-link IPC listener/dialer. (Unix: `UnixListener`;
  Windows: a named pipe `\\.\pipe\filament-<uid>`.)
- `ServiceHost` — install/uninstall/notify-ready/watchdog. (Unix: systemd;
  Windows: SCM service or a Scheduled Task.)
- `SelfUpdate` — stage + swap the running binary. (Unix: `rename` over exe;
  Windows: rename-away-then-replace + relaunch.)

This is the enabling refactor for P1/P2; P0 can begin against it incrementally.

## Service management — detect, don't assume systemd

Today the service layer *is* systemd. `filament up --install` (`main.rs:1945`)
writes `~/.config/systemd/user/filament.service` and runs `systemctl`
**unconditionally**; `install_system_service` (`main.rs:1759`) is a
`#[cfg(target_os = "linux")]` systemd unit; `sdnotify.rs` speaks systemd's
`Type=notify` readiness/watchdog protocol. On macOS, on non-systemd Linux
(OpenRC/runit/s6/SysV), and on Windows, `--install` therefore writes a **dead
unit file and runs a failing `systemctl`** — a broken experience, not a
graceful one.

Key reframe: **the daemon needs none of this.** `filament up` is just a
long-running process; service integration is *only* for autostart + supervision.
So the answer is an abstraction with an **honest fallback**, not "port systemd
everywhere."

### `ServiceHost` — detect the machine's manager and adapt

- **Detect** the manager, in order:
  - Linux: systemd (`/run/systemd/system`) → OpenRC → runit → s6 → SysV
  - macOS: launchd
  - Windows: Service Control Manager (or a Scheduled Task for a per-user,
    no-admin install)
  - else: `None`
- **Backends** generate the right artifact — systemd unit / launchd plist / SCM
  service / rc script — and map `notify_ready()` / `watchdog()` onto each (a
  **no-op** where the manager has no such protocol; the daemon still runs fine).
- **Graceful fallback** when no supported manager is detected: **do not write a
  dead unit.** Print exact, copy-pasteable instructions for running `filament up`
  at boot on that system, and/or offer a `--foreground` mode for the user to wire
  into whatever they use. Honest beats broken.

### Coverage decision (settled)

**Big-3 native backends + honest fallback.** Ship native
`systemd` (have) + `launchd` (macOS) + `Windows Service`, and **detect**
everything else (OpenRC/runit/s6/SysV) to emit correct manual instructions rather
than a broken unit. The long-tail init systems are just template generators that
can be added later on demand once the trait exists — not a blocker.

### Priority

The **"stop writing dead systemd units off-systemd"** fix is a *correctness bug*,
not a feature — pull it forward (P0/early-P1): gate `--install` on detection and
fall back to instructions. That one change un-breaks macOS + non-systemd Linux +
Windows immediately, before any native launchd/SCM backend lands.

## Phase 0 — Correct & safe (Windows stops being *wrong*)

The bar-1 items. None are "features"; they're "the current behavior is broken or
unsafe on Windows."

1. **Config/data dir → `%APPDATA%`.** Add the `directories` crate; route every
   HOME-derived path (`settings.rs:233`, `ctl.rs:36`, `sshkeys.rs:20`,
   `net.rs:669`, `overlay.rs:108`, `main.rs:1191/1947`, `diag.rs:268`) through
   `Paths`. Migrate any state found in a legacy `./.config` on first run. **This
   is the single highest-impact fix.**
2. **Protect secrets on Windows.** Implement `SecretFile` with a per-user DACL
   (or DPAPI) for the private key, `devices.json`, `peerconf`, pairing secrets,
   and overlay state. Today `chmod` is a literal no-op (`sshkeys.rs:49`).
3. **CI runs the test suite on Windows.** Add a `cargo test` job on
   `windows-latest` to `test.yml` (today it only *builds* there). Gate merges on
   it. Without this, every P0/P1 fix is unverified.
4. **Self-update on Windows.** Implement the `.zip` unpack + the
   rename-away-the-running-exe swap (`filament.exe`→`filament.exe.old`, write
   new, relaunch) in `SelfUpdate` (`main.rs:6150`). Until then, keep the current
   honest `bail!` pointing at winget.
5. **Clean up stale refusals & comments.** `serve-tun` bails "Linux-only" though
   Wintun works (`main.rs:5851`); `l2.rs`/`tun/mod.rs` comments still claim the
   mesh is Linux-only. Make the `bail!`s match reality (enable where the backend
   exists; keep an honest message where it truly doesn't).

6. **Stop assuming systemd (bug fix).** Gate `filament up --install`
   (`main.rs:1945`) on `ServiceHost` detection so it no longer writes a dead
   systemd unit + runs a failing `systemctl` on macOS / non-systemd Linux /
   Windows. Where no supported manager is found, print instructions instead. See
   *Service management* above. (Correctness fix; precedes the native launchd/SCM
   backends in P2.)

Exit criteria: a fresh Windows install writes protected state to `%APPDATA%`,
`filament update` self-updates, `filament up --install` never emits a dead unit,
and CI runs the suite on `windows-latest` green.

## Phase 1 — Native daily paths (parity on what people run hourly)

6. **Warm-link IPC over a named pipe.** Implement `ControlChannel` on
   `\\.\pipe\filament-<user>`; wire `filament up`'s daemon to serve it and the
   client fast paths (`ssh`/`pty`/`netcat`/`forward`/`ping`) to reuse it. This
   removes the ~1s cold-establish tax on Windows and lights up live-reconfig
   (`settings.rs:585`). Biggest *felt* speed win on Windows.
7. **ConPTY warm path + live resize.** The ConPTY *acceptor* already works
   (`portable-pty`). Add the Windows warm-pty client path (currently
   `#[cfg(unix)]`, `l2.rs:2141`) and a resize signal to replace SIGWINCH
   (`l2.rs:2076`) — Windows console resize events instead.
8. **ssh-over-mesh on Windows.** Generalize the `cfg(target_os="linux")` L3 ssh
   helpers (`l3_mesh_addr`, `probe_sshd`, `run_ssh`'s L3 block, `l3_dest`,
   `revive_l3`) to `#[cfg(l3)]` so they run wherever the TUN backend exists.
   Windows 10+ ships OpenSSH; adjust ProxyCommand quoting for `cmd`/PowerShell.
9. **Terminal polish.** Ensure VT/ANSI is enabled on legacy conhost, the
   interactive pickers and colored output render in Windows Terminal + conhost,
   and `is_terminal`-based interactivity behaves (it does today via `crossterm`).

## Phase 2 — Native OS integration (Windows-idiomatic, not just ported)

10. **Native service backends — launchd + Windows Service (SCM).** With the P0
    detection + fallback already in place (see *Service management*), add the
    remaining big-3 native backends: **launchd** on macOS (a
    `~/Library/LaunchAgents/*.plist` + `launchctl`) and **Windows Service / SCM**
    (or a Scheduled Task for a per-user, no-admin install), mapping
    notify-ready/watchdog (`sdnotify.rs:42` is a no-op today) onto each. systemd
    already exists; OpenRC/runit/SysV stay on the detect-and-instruct fallback
    until there's demand for native generators.
11. **Firewall automation.** On first `up`, offer to add the inbound UDP rule via
    `netsh advfirewall` (with consent), so QUIC direct connect works without a
    silent Windows Firewall block. Mirror `ensure_net_admin_for_l3`'s advisory
    hint (`tun/windows.rs:198`) with a real action.
12. **Code-sign the `.exe` (SmartScreen).** Authenticode-sign the released
    binary so Windows doesn't SmartScreen-warn on the curl-less install; pairs
    with the winget manifest (`Abdk4Moura.Filament`) already referenced in
    release notes.
13. **Elevation UX for L3.** Wintun adapter creation needs Administrator; today
    it just prints a hint (`tun/windows.rs:198`). Add a clear elevation prompt /
    relaunch-as-admin path for `serve-tun` / kernel-TUN mode, and make
    `ensure_hosts_writable` (`tun/windows.rs:205`, a no-op) actually grant the
    hosts-file ACL when elevated.
14. **Shell integration (stretch).** An Explorer "Send with Filament" context-menu
    entry and drag-to-send, matching the AirDrop-like framing.

## Cross-cutting

- **CI matrix:** the P0 `cargo test` on `windows-latest` is the linchpin — it
  turns every subsequent item from "hope it works" to "proven." Add a
  Windows-specific smoke test (pair → send → recv over loopback) too.
- **Docs:** a `filament(1)` platform-notes section + install doc for winget /
  signed binary; retire the stale "Linux-only" comments as features land.
- **Sequencing/ownership:** P0 is self-contained and unblocks a *trustworthy*
  Windows build (do it first, in order). P1 depends on the `platform` refactor
  (ControlChannel/Pty). P2 is independent polish that can proceed in parallel
  once P0 lands.

## Bottom line

The transfer core, ConPTY, crossterm, and Wintun already run on Windows — the
work is the host layer: **put state in `%APPDATA%`, protect the secrets, prove it
in CI, then give Windows the warm-link, the service, and the firewall so it
stops feeling like a port and starts feeling native.**
