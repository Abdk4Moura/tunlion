# filament — command-surface simplification spec

Status: design (UX pass). Companion to `design-pairing-ux.md` (the model) and
`ux-spec-pairing.md` (the surface UX). Goal: a new user meets ~6–8 verbs, not 32.

## The one-sentence spec

**The noun is the command** (`filament <file|code|device|device:port>` covers send /
receive / shell / forward), **six named everyday verbs** carry the rest (`pair`,
`devices`, `up`, `mint`, `requests`, `doctor`), the **reach cluster collapses 8→4** and
**config 5→1** via `--off`/param folding, identity-admin hides behind one `identity`
noun, **`revoke` and the direction-carrying verbs stay first-class**, and **everything
renamed lives on as a hidden deprecated alias** that still runs and teaches its
replacement in one stderr line.

## Current inventory (32 top-level variants; `pty`/`ping` already hidden)

- **Move bytes:** `send`, `recv`, `backup`
- **Fleet / trust:** `pair`, `devices` (`forget`/`rename`), `introduce`, `grant`, `revoke`
- **Reach a service (8):** `forward`, `dial`, `netcat`, `proxy`, `expose`, `unexpose`, `ssh`, `pty`, `mount`, `unmount`, `serve-tun`
- **Daemon:** `up`, `down`, `status`
- **Diagnose:** `ping`, `doctor`
- **Config (5):** `set`, `get`, `unset`, `addr`, `config`
- **Plumbing:** `update`, `completions`, `man`

Two structural problems: the reach cluster is 8 verbs for "get to a port on a peer,"
and config is 5 verbs for read/write/reset. Everything else just needs grouping.

## Reduced surface — before → after

Legend: **keep** · **positional** (`filament <thing>`) · **merge→X** · **flag**
(`--off`/param) · **ns:X** (namespaced) · **alias** (hidden, deprecated, still works).

| current | disposition | after |
|---|---|---|
| `send FILE` | positional + keep | `filament <file>`; `send` stays explicit |
| `recv CODE` | positional + keep | `filament <code>`; `recv` stays explicit |
| `ssh DEV` | merge→shell | `filament shell <dev>` / bare `filament <dev>`; `ssh`=alias (arg passthrough preserved) |
| `pty DEV` (hidden) | merge→shell | folded into `shell`; `pty`=alias |
| `netcat DEV RPORT` | merge→reach | `filament reach <dev>:<rport>`; `netcat`=alias |
| `dial DEV PORT` | merge→reach | `filament reach <dev>:<port>`; `dial`=alias |
| `forward LP DEV RP` | keep + positional | `filament <dev>:<rport>` (persistent listener); verb stays |
| `proxy` | flag→reach | `filament reach --socks [--port]`; `proxy`=alias |
| `expose PORT` | keep | `filament expose <port>` (`--list`, `--peer`) |
| `unexpose PORT` | flag | `filament expose <port> --off`; `unexpose`=alias |
| `mount …` | keep | `filament mount <dev>:<dir> <mnt>` |
| `unmount MNT` | flag | `filament mount --off <mnt>`; `unmount`=alias |
| `serve-tun` | ns:net (advanced) | `filament net serve-tun`; alias kept |
| `pair` | keep (everyday) | `filament pair` |
| `devices` | keep (everyday) | `filament devices` (+ `forget`/`rename`/`promote`) |
| `introduce A B` | ns:devices | `filament devices vouch <a> <b>`; alias kept |
| `grant DEV CAP` | keep | `filament grant <dev> <cap>` |
| `revoke DEV CAP` | keep (do NOT merge) | `filament revoke <dev> <cap>` — see below |
| `up` | keep (everyday) | `filament up` |
| `down` | keep | `filament down` |
| `status` | keep + absorb | absorbs `ping`, `cap-status`, `addr --json` |
| `ping DEV` (hidden) | merge→status/doctor | `filament status <dev>` / `doctor <dev>`; alias kept |
| `doctor` | keep | `filament doctor [dev]` |
| `addr` | keep (thin) | `filament addr`; device-info → `devices <name>` |
| `set K V` | keep + absorb | `set K V` write · `set K` read · `set K --unset` reset |
| `get K` | merge→set | `filament set <k>`; `get`=alias (bare stdout preserved) |
| `unset K` | flag→set | `filament set <k> --unset`; `unset`=alias |
| `config …` | alias | hidden raw escape hatch stays |
| `backup` | keep (tail) | `filament backup` (rsync) |
| `update` | keep (tail) | `filament update` |
| `completions`/`man` | keep hidden | plumbing |
| *(new)* `mint` | new, everyday | `filament mint` |
| *(new)* `requests` | new, everyday | `filament requests` |
| *(new)* identity-admin | ns:identity | `identity init\|restore\|rotate\|revoke\|certify\|promote` |
| *(new)* `restore` | top-level alias of `identity restore` | emergency discoverability |

**Net: reach cluster 8→4** (`reach`, `forward`, `expose`, `mount`); **config 5→1**.

## Positional rules — target shape → action

`filament <thing>` resolves by the **shape of the token**, deny-by-default on ambiguity.

| token shape | example | resolves to |
|---|---|---|
| path (`/`, `./`, `~/`, known ext) or existing file with no name-clash | `report.pdf`, `./notes` | **send** |
| pairing-code grammar (hyphenated speakable words) | `clever-lynx-63` | **receive** |
| bare word = known device petname | `laptop` | **shell** |
| `device:port` | `laptop:5432` | **forward** (local listener → peer port) |
| `device.mesh` / `.mesh:port` | `gpu.mesh:8080` | **reach** over the mesh |
| nothing, at a TTY | `filament` | guided picker |
| nothing, non-TTY | (piped) | print help, non-zero exit (never block) |

**Tie-breaks (explicit — guessing wrong is a security event):**
- Bare word that is BOTH a device and a cwd file → refuse + disambiguate.
- Path form always wins for files; device petnames never contain `/` or `.`, so the
  namespaces are structurally disjoint except the bare-word overlap.
- Code-vs-device collision is near-impossible (distinct grammar); if ever, the device
  wins (you named something you already trust); force with `filament recv <code>`.
- **Positional never escalates:** `filament laptop` opens a shell ONLY if `laptop`
  already holds the `shell` cap. No cap → it connects and says so. The positional
  shortcut is a **router, never an authorizer**.

## `filament --help` after

```
filament — send files and reach machines, peer to peer. no account.

USAGE
  filament <file>              send it            (mints a one-time code + QR)
  filament <code>              claim a code and receive
  filament <device>            open a shell on a device you know
  filament <device>:<port>     forward a local port to that device

EVERYDAY
  pair        add your own device, or let someone in
  devices     who you trust  (fleet · external · needs-review)
  up          always-on drop target (trusted devices only)
  mint        a key that lets a machine join, scoped and expiring
  requests    approvals waiting for you
  doctor      diagnose a link that won't connect

MORE  (run `filament <cmd> --help`)
  reach · forward · expose · mount     reach a service on a peer
  shell · backup                       remote shell · rsync sync
  grant · revoke                       change what a device may do
  status · down · addr · set           daemon, address, settings
  identity                             init · restore · rotate · revoke
  net serve-tun · update               advanced · self-update
```

New user meets: 4 positional forms + 6 everyday verbs = **~6–8, not 24**.

## Backward-compat / deprecation

Nothing is deleted. Every renamed verb becomes a `#[command(hide = true)]` alias that
still runs, prints one dim stderr line teaching the new form (reusing the `↳` token),
and exits with the same status it always did:

```
note: `filament netcat` is now `filament reach`. Same behavior.
↳ filament reach laptop:5432
```

Rules: **stderr only** (stdout stays script-clean), **once per invocation**,
suppressible with `FILAMENT_NO_DEPRECATION=1`, **never changes exit code or output**,
`--json` consumers never see it. Aliases live the whole 0.x line; earliest removal is a
1.0 major with a migration note.

Alias map: `ssh→shell`, `pty→shell`, `netcat→reach`, `dial→reach`, `proxy→reach --socks`,
`unexpose→expose --off`, `unmount→mount --off`, `get→set`, `unset→set --unset`,
`ping→status`, `introduce→devices vouch`, `serve-tun→net serve-tun`.

## What must NOT be simplified (guard against over-merging)

- **`revoke` stays first-class — NOT `grant --off`.** The most safety-critical,
  most-grepped, most-muscle-memory action in a trust tool must stay discoverable exactly
  when someone is panicking (lost laptop). Symmetry with `expose --off` is convenience;
  `revoke` is a safety verb.
- **`forward` (persistent local listener, `ssh -L`) vs `reach` (one-shot stdio pipe,
  ProxyCommand/`nc`) are different mental models** — they share the positional shortcut
  but stay separate verbs; collapsing forces a mode flag that contradicts the name.
- **`expose` (server side) vs `reach`/`forward` (client side) are inverses, not
  duplicates** — merging erases direction, the one thing a user must not get wrong.
- **`ssh` alias keeps arg passthrough** (`user@host`, `-p`, remote commands, scp
  bootstrap): `shell` gains a `-- <args>` passthrough; the merge is at the verb level,
  not the capability level.
- **`serve-tun` is genuinely advanced** (lab / static two-endpoint PSK VPN) — namespaced
  under `net`, not folded into `up`/`reach`, to keep the signaling mesh distinct from the
  static tunnel.
- **`up`/`down`/`status` stay flat, not under a `daemon` noun** — `up` is everyday;
  namespacing the most common daemon action to hide two rare siblings is backwards.
