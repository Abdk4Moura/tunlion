# Cross-platform capabilities: one mesh, one adapter layer

**Status:** design. This is the framing document for making every filament
capability (send/recv, pty/shell, forward, expose, netcat, ssh, mount) work the
same on Linux, macOS, and Windows. The phased task list lives in
[design-windows-first-class.md](design-windows-first-class.md); this document is
the architecture those tasks build toward.

## The problem: platform assumptions baked into each feature

We keep discovering platform bugs one at a time, by hitting them:

- pty hardcodes the shell as `$SHELL` then `/bin/bash` then `/bin/sh`, so it
  spawns a nonexistent shell on Windows and the session dies instantly.
- warm forward/reuse uses a unix-domain socket, absent on Windows.
- mount shells out to `sshfs`, which is unix/FUSE only.
- config used `$HOME`, unset on Windows.
- service install wrote a systemd unit unconditionally.

Each feature breaks in its own way, and we find out when a user does. That is
whack-a-mole. The fix is structural.

## The unifying model

The **mesh is already uniform.** The crypto-addressed overlay plus the
direct-QUIC / userspace-netstack transport is identical on all three platforms
(kernel TUN via wintun / utun / tun where privileged, the zero-privilege
netstack otherwise). Every capability is the same shape underneath: *move an
authenticated byte stream, or a request/response, between two peers over that
mesh.* That layer is platform-independent and done.

All divergence lives at the **endpoints**: what a peer does with the stream on
its own OS. Spawn a shell. Bind a local socket. Mount a filesystem. Read a
config path. So the rule is:

> Push every OS-specific endpoint operation behind one `platform` adapter layer.
> Build each capability on `(uniform mesh) + (platform trait)`. A new capability
> then works everywhere by construction, or fails with one honest message from
> the adapter instead of a cryptic crash.

### Three layers

```
  Capabilities   send · recv · pty · forward · expose · netcat · ssh · mount
        │                     (platform-independent logic)
        ▼
  Mesh services  authenticated byte stream · request/response · file protocol
        │                     (uniform: same wire on every OS)
        ▼
  Platform       Paths · SecretFile · ServiceHost · ShellHost · ControlChannel
  adapters       · MountHost           (the ONLY place OS specifics live)
```

Nothing above the adapter layer contains a `#[cfg(...)]` for OS behavior. When
one is unavoidable, it belongs in `platform/`.

## The platform adapter traits

Three exist (opencode landed them in the Windows P0 work). Three are the
remaining extraction:

| Trait | Owns | Unix | Windows |
|---|---|---|---|
| `Paths` | config/data/cache dirs | XDG / `$HOME` | `%APPDATA%` |
| `SecretFile` | owner-only file writes | `chmod 0600` | per-user DACL |
| `ServiceHost` | autostart/supervision | systemd (detect others) | SCM / Task Scheduler |
| **`ShellHost`** | spawn a shell / run a command | login shell + `-c` | powershell/cmd + `-Command`/`/c` |
| **`ControlChannel`** | warm-reuse IPC, local sockets | unix-domain socket | named pipe |
| **`MountHost`** | mount a remote folder locally | FUSE | WinFsp / ProjFS |

### `ShellHost` has two modes, and they are not the same operation

pty into pop-os opens fish, because the login shell is respected via `$SHELL`.
That is correct and stays. But running a *command* in a shell is not uniform, so
`ShellHost` is two operations:

1. **`interactive()`** spawns the login shell as a PTY. Resolution order, first
   match wins:
   1. `filament up --shell-program "<cmd>"` (explicit, one-off)
   2. `FILAMENT_SHELL` env var
   3. `filament set shell "<cmd>"` config value (persists; fits the daemon)
   4. `$SHELL` on Unix, `%ComSpec%` / powershell on Windows (platform default)
   5. hardcoded fallback (`/bin/bash`→`/bin/sh`, `cmd.exe`)

   The value is argv-split, so it can carry args: `FILAMENT_SHELL="pwsh -NoLogo"`,
   `bash -l`, `nu`, `fish`.

2. **`exec(cmd)`** runs a one-shot command string (for `filament <peer> '<cmd>'`)
   via the resolved shell's own command flag: `-c` for sh/bash/zsh/fish,
   `-Command` for PowerShell, `/c` for `cmd.exe`. The command runs in whatever
   shell that box actually uses (fish included), using the right invocation,
   rather than assuming POSIX. This is what makes remote automation honest across
   a mixed fleet.

### `ControlChannel`

The data path for forward/expose is already portable TCP. Only the warm-reuse
IPC (sibling process to the daemon) is a unix-domain socket. `ControlChannel`
abstracts it: unix socket on Unix, named pipe (`\\.\pipe\filament-<user>`) on
Windows. Until then, Windows forward/ssh/pty/netcat still work, just always
cold-establish (no warm speedup).

## Mount: go mesh-native, not sshfs-per-platform

Decision: **a filament-native file protocol over the mesh, with thin per-OS
mount adapters.** Not WinFsp+sshfs-win as a permanent answer.

Rationale: the same philosophy that lets pty work without an sshd should apply to
mount. sshfs drags in FUSE + an sshd + platform packaging, and it is the reason
mount does not exist on Windows at all. Instead:

- **Server side (any peer):** serve a small SFTP-like request/response protocol
  over the authenticated mesh stream (open, read, write, readdir, stat, rename,
  truncate). Uniform wire, no sshd, no FUSE dependency to *serve*.
- **Client side (`MountHost`):** a thin adapter that presents that protocol as a
  local mount: FUSE on Linux/macOS, WinFsp or Projected File System on Windows.
  The adapter is the only platform-specific piece, and where none is available it
  fails with an honest "mount needs WinFsp on Windows: <link>", or offers a
  plain `filament pull`/`sync` fallback.

This makes mount self-contained and uniform like pty, and it means one wire
protocol to test rather than N sshfs integrations. WinFsp remains an option for
the *client adapter*, not the whole design.

## Reachability: two tiers, elevated and not

filament reaches peers two ways. The choice is about privilege, not features.

### Elevated: the always-on service owns the kernel TUN

`filament up --install` registers filament as a system service that runs
privileged: systemd with CAP_NET_ADMIN on Linux, a LaunchDaemon as root on macOS,
a Windows Service as LocalSystem. Because the service is privileged it creates the
kernel TUN itself (wintun / utun / `/dev/net/tun`), at boot, once. The result is
Tailscale parity: every native app (ssh, curl, the browser, anything) reaches
`<peer>.mesh` transparently through the kernel route, MagicDNS resolves via the
hosts file, and the user's own `filament` commands are unprivileged clients of the
service. One UAC or pkexec prompt at install, never again.

This is the whole answer to "kernelspace on Windows without much ado": the user
never touches wintun or Administrator; the LocalSystem service creates the adapter
for them. Requirements:

- **Elevate with a GUI prompt, and fall back on decline.** `filament up --install`
  triggers the OS elevation dialog (UAC on Windows via ShellExecute "runas",
  polkit/pkexec on Linux) so the user grants admin from a popup, not by opening an
  admin shell. If they approve, the privileged service installs (kernel TUN,
  autostart at boot). If they decline, do not fail: fall back to a user-level
  autostart that runs `filament up` in userspace (a per-user Scheduled Task at
  logon on Windows, a `systemd --user` unit on Linux, a LaunchAgent on macOS), so
  the user still gets always-on, just in the userspace tier with no admin. So
  `--install` has two outcomes by consent: privileged-and-kernel, or
  unprivileged-and-userspace, and never a hard failure. After install, nothing
  needs elevation.
- **Add the inbound firewall rule** during install (netsh on Windows) so direct
  QUIC is not silently blocked.
- **Security:** a privileged always-on daemon plus `--shell` spawns shells as
  LocalSystem/root. Keep `--shell` opt-in (it is) and require `--shell-user` for a
  drop-to-account. That flag needs a real Windows implementation; it currently
  only warns. Default `--install` is networking-only; shell stays a deliberate
  extra step so default-on is never a footgun.

### Non-elevated: userspace overlay plus a proxy, zero install

Where the user cannot or will not elevate (a container, a locked-down box, a
laptop just trying it out), filament uses the in-process userspace netstack at
zero privilege. This is **not** a degraded mode for filament's own features:
send/recv, pty/shell, forward, expose, dial, and mount all tunnel over the
authenticated data channel and need no kernel route, so a non-elevated user has
the full capability set.

The one thing kernel TUN gives that userspace cannot is transparent access from
*arbitrary native apps* to *arbitrary* overlay addresses. filament already closes
that with `filament proxy`, a local SOCKS5 proxy (Tailscale's userspace-networking
model): point a browser, curl, git, or ssh's ProxyCommand at it and
`<peer>.mesh:<port>` rides the mesh, while non-mesh hosts go direct. To make that
comfortable rather than a manual chore:

- **Run the proxy as part of `filament up`** when kernel TUN is unavailable, on a
  known port, so presence and the proxy arrive together (no separate
  `filament proxy` step to remember).
- **Add an HTTP CONNECT proxy alongside SOCKS5** (some tools only speak HTTP
  proxy), matching Tailscale.
- **Print copy-paste config** for the common tools (`ALL_PROXY`, `git http.proxy`,
  ssh `ProxyCommand`), and optionally serve a PAC file so a browser routes only
  `*.mesh` through the proxy and everything else direct.

The mental model: elevated is transparent and native, non-elevated is zero-install
and proxy-mediated, and both deliver the full filament feature set. The user picks
their comfort level, and the honest fallback tells them which tier they are on and
how to reach the other.

## Making "does it work on Windows" answerable

Two mechanisms, so we stop finding gaps by accident:

1. **Capability-support matrix.** Each capability declares which adapter methods
   it needs. The adapter reports supported-or-not per platform, so an unsupported
   combination prints "X needs Y here" instead of failing. This is the honest
   fallback we already ship for `--install`, made systematic. `filament doctor`
   can print the matrix for the current host.
2. **Per-OS CI.** Run capability smoke tests (pair, send, pty interactive + exec,
   forward) on Linux, macOS, and Windows, not only build + unit tests. A platform
   regression is caught by CI, not by a user on their box.

## Current status per capability

| Capability | Windows | Path to uniform |
|---|---|---|
| send / recv | works | already uniform |
| netcat | works | already uniform |
| expose | works (TCP + overlay) | already uniform |
| forward | works, always cold | `ControlChannel` named pipe |
| pty / shell | fixing (`/bin/sh` bug) | `ShellHost` (interactive + exec) |
| ssh | client works; needs peer sshd | pty is the no-sshd path; leave |
| **mount** | **absent (sshfs)** | mesh-native file protocol + `MountHost` |

## Sequencing

1. `ShellHost` (interactive + exec + customization). In progress; fixes pty on
   Windows and adds the one-shot mode and the shell override.
2. `ControlChannel`: named-pipe warm IPC, lights up the warm fast paths on
   Windows.
3. Per-OS capability CI + the support matrix. Makes the rest self-policing.
4. Mount: the mesh-native file protocol + per-OS `MountHost` adapters.

## Bottom line

The mesh is one thing on every OS. Keep it that way, put every endpoint operation
behind one adapter layer, prove it with a support matrix and per-OS CI, and each
capability works everywhere or says exactly why not. Mount becomes native like
pty rather than an sshfs port.
