---
name: tunlion
description: Move files, run commands, and reach ports using the tunlion CLI (peer to peer, end-to-end encrypted, no cloud upload). Use for sending or receiving with a one-time code, reaching known paired or fleet devices, running an authorized command on another machine, forwarding or publishing a port, enrolling a device, or managing tunlion access. Fleet siblings need no pairwise pairing. New enrollment and external transfers require the user's explicit intent. Do not use for cloud uploads, email delivery, or accessing machines without authorization.
---

# tunlion

tunlion connects the user's devices directly (QUIC or WebRTC, relay only as a
fallback). Every command below is the one correct form; do not guess other
flags. When unsure of a flag, run `tunlion <command> --help`, which also lists
the exit codes that command can return.

## Rules

1. Always pass `--json` on commands that support it: `init add join id status
   set reach send receive sync doctor addr devices skill promote demote`. Other commands refuse
   `--json`; read their exit code and stderr instead.
2. Decide by exit code, never by parsing human text. Under `--json`,
   `ok` is true exactly when the exit code is 0, and a failure is one object:
   `{"ok":false,"error":{"code":"unknown_device","exit":3,"message":"..."}}`.
3. In a noninteractive tool session, prompts do not appear; commands that need
   confirmation (`down`, `reset`, `revoke`, `devices forget`, `demote`,
   `expose --off`) fail unless you pass `-y`. Pass `-y` only when the user asked for that exact
   action. `reset` wipes this machine's identity: never run it unless the user
   explicitly asked. `tunlion demo` is a tour for people at a terminal; do not
   run it.
4. Device names come from `tunlion devices --json` (the list is under
   `data.devices`). Never invent one.
5. Never put invitation material on the command line. Write it to a file and
   pass the path (`join <path>` or `join --invite-file <path>`).
6. Do not retry blindly. Act on the exit code using the table below.

## Exit codes and what to do

| Exit | `error.code` | Meaning | Do this |
|---|---|---|---|
| 0 | | success | report the result |
| 1 | `error` | other error | report the message; do not retry |
| 2 | `usage`, `corrupt_state` | bad flags, local file problem, corrupt state file | fix the command; for `corrupt_state` report the named file, do not delete it |
| 3 | `unknown_device` | no paired device by that name | run `tunlion devices --json`, pick an exact name or ask the user |
| 4 | `denied` | the peer, a capability, or the system refused | stop and tell the user; it needs their consent (for example `tunlion grant <device> shell` run on the other machine) |
| 5 | `still_relayed` | `reach --until-direct` timed out on a relay | the link works; report that it is relayed |
| 6 | `unreachable` | peer offline or did not answer in time | retry once after `tunlion reach <device> --json`; if still 6, tell the user the device looks offline |
| 7 | `network` | cannot reach the tunlion server | check this machine's internet; stop |
| 8 | `partial` | some files moved, some did not | report which; re-running `sync` moves only what is missing |
| 9 | `no_identity` | this device was never set up | stop; the user must run `tunlion init` or `tunlion join` |
| 10 | | `up`: a daemon already runs with different settings | run `tunlion down -y` first only if the user wants the new settings |
| 11 | | `status`: no daemon running | start one with `tunlion up --detach` if the task needs it |
| 12 | `local_resource` | disk, quota, open files or memory ran out here | stop and report |
| 13 | `tls_certificate` | the tunlion server's TLS certificate was not trusted (a TLS-inspecting proxy, or a missing CA) | stop; tell the user to set `SSL_CERT_FILE` to their CA bundle |
| 126 / 127 | | `exec`: remote command not executable / not on PATH | fix the command name or path |
| 130 / 143 | | interrupted / terminated | report; do not retry automatically |
| 141 | | output closed early (`| head`) | expected for piped reads |

`exec` passes the remote command's own exit status through, so a remote
status of 3 looks like tunlion's 3; the reason line on stderr says which.

## Tasks

### Set up a machine with an auth key (CI, a borrowed box)

```bash
# one command: join if this machine has no identity, then serve
TUNLION_AUTHKEY=filament-invite:v2:... tunlion up --detach

# or, when the join and the serve are separate steps
TUNLION_AUTHKEY=filament-invite:v2:... tunlion join
tunlion up --detach
```

The key may also come from `--authkey-file <path>` on `up` (use `-` for stdin).
It is never accepted as an argument: argv is visible in `ps` and in shell
history. `TUNLION_INVITE` is accepted as a second environment name. Without an
identity and without a key, `up` still exits 9.

To mint the key on the owner, see `tunlion add --for runner --reuse N --out`.
Every invitation that can still be claimed is listed by `tunlion devices --json`
under `data.invitations` (name, kind, allow, uses, usesLeft, maxUses, expires,
id). `tunlion add --withdraw <name> -y` takes one back: from then on the owner
refuses every claim with it (`--json` reports what was withdrawn). Devices
that already joined with it keep their access; cut one off with
`tunlion demote <device> --to cut -y`.

### Fleet permissions and limits

An ordinary pairing is not fleet enrollment. `add --for device` (also
`add <name>`) enrolls one of the user's devices; `add --for person` is external;
`add --for runner` is temporary unattended enrollment, not lasting membership.
Never enroll someone else's or a borrowed machine as the user's own device just
to avoid a refusal. Invitation ceilings cannot be widened by a later grant.

Fleet siblings prove their own certificate under the same owner and are admitted
against the owner's signed roster. They need no pairwise pairing. Their one
default is file transfer into the receiver's configured inbox, not arbitrary
filesystem writes. Shell/exec, mount, forwarding and routes are not implied.
Other relationship types have their own bounds; do not generalize sibling
defaults to an owner link or an invitation-bounded device. A certificate-less
authenticated pair keeps shell access granted explicitly on the serving
machine. An anonymous peer is transfer-only. A replacement transport does not inherit the previous one's
fleet verification or nonces.

The target can grant locally. The owner can distribute `transfer`, `mount` or
`shell` with `grant <subject> <cap> --on <target>`. A successful owner command
records intent, not delivery or effective access. On the target,
`fleet.owner_grants` defaults to `files` (transfer/mount only); `all` permits
owner shell grants; `off` refuses owner sets but does not remove the sibling
inbox default. Do not change this setting or add grants to bypass a denial.
Local denies, device revocation and certificate expiry override grants.

Owner sets expire without refresh (15 minutes by default). Withdrawing one or
narrowing the target policy refuses new sessions once effective, but does NOT
terminate an already-open session. Whole-device revocation closes affected
sibling links, but owner roster removal must reach each sibling first, and
neither a cut nor a capability revoke is known to end every session kind. Do
not claim a global cut before delivery/link closure is verified. A held roster
can remain the admission input past its validity timestamp; unlike owner-grant sets,
it does not automatically remove an offline-from-owner sibling on expiry.
No rendezvous-secret
rotation or multi-hop routing is implemented. Different versions enforce their
own receiver policy.

### Check what is available

```bash
tunlion status --json           # is the daemon up on this machine (exit 11 if not)
tunlion devices --json          # known devices, fleet siblings, open invitations
tunlion reach <device> --json   # reachable? direct or relay, and rtt
```

### Send a file

To a known paired device or fleet sibling (no code; the receiver must be running
`tunlion up`, and its authorization still applies):

```bash
tunlion send <path>... --to <device> --json
```

To anyone, with a one-time code the user reads out or pastes:

```bash
tunlion send <path> --code --timeout 600 --json > send.out &
```

`send` blocks until the receiver claims the code, so run it in the background.
With `--json` it prints one line per event: the first line is
`{"event":"code","code":"grouchy-manatee-136","receive":"tunlion receive grouchy-manatee-136",...}`.
Give the user that code right away, then wait for the process; its last line
is the result object and its exit code is the outcome. If nobody claims the
code within `--timeout` seconds (default 60), it exits 6. The other side runs
`tunlion receive <code>` or opens https://tunlion.autumated.com. Exit 0 means
every file was delivered and verified by the receiver's checksum.
Use `-` as the path to send stdin (add `--name <file name>`).

### Receive a file

```bash
tunlion receive <code> --dir <dir> --json
tunlion receive <code> --dir <dir> --timeout 300 --json   # give up after 5 min
```

A code is already consent; no prompt appears. `-o -` streams a single file to
stdout. `--timeout` bounds the wait for a sender: if nothing has arrived by the
deadline the command exits 6 (`unreachable`) with "nothing arrived within Ns",
which is different from a transfer that failed (1) or was refused (4). Use it in
scripts and CI so a missing peer cannot hang the job. `--timeout 0` waits
without limit, and `--timeout` conflicts with `--keep-open`.

### Keep a directory updated on another device

```bash
tunlion sync <local-dir> <device>:<remote-dir> --json
tunlion sync <local-dir> <device>:<remote-dir> --dry-run --json   # plan only
```

One-way, only changed chunks move. Files deleted locally stay on the device
unless `--delete` is passed; pass it only if the user asked.

### Run a command on another device

```bash
tunlion exec <device> -- <command> <args>...
```

Arguments cross exactly, with no shell. Add `--shell` only when the command
needs pipes or globbing, then pass one string: `tunlion exec <device> --shell -- 'ls | wc -l'`.
Other options: `--cwd <dir>`, `--env KEY=VALUE`. Exit 4 means the device has not
granted this one `shell`; tell the user, do not try to work around it.
Do not use `tunlion shell`; it is an interactive terminal for humans.

### Reach a port on another device

```bash
tunlion forward <device>:<port>              # local listener on the same port
tunlion forward <device>:<port> --lport <n>  # different local port
tunlion forward <device>:<port> --stdio      # stdin/stdout, e.g. ssh ProxyCommand
```

`forward` runs until stopped; start it in the background and stop it by its
pid when done. A refusal is not permission to try another access path.
An explicitly published service may be a separate authorized path; use it only
when that access is within the user's request and the service's policy permits it.

### Publish a local port to the mesh

```bash
tunlion expose <port> [--to <host:port>] [--peer <device>,...]
tunlion expose --list
tunlion expose <port> --off
```

Peers reach it at `<this-device>.mesh:<port>`. It persists across restarts.

### Run the receiver on this machine

```bash
tunlion up --detach     # background daemon, survives the terminal closing
tunlion down -y         # stop it
```

Do not add `--shell` or `--install` unless the user asked: `--shell` lets
every paired device run commands here, and `--install` creates a login
service.

### Pair a new device

On this machine:

```bash
tunlion add <name> --out <file> --json     # one of the user's devices
tunlion add --name <name> --json          # ordinary pairing, no fleet membership
tunlion add --for person --out <file> --json
```

Get the file to the other machine; there the user (or you) runs
`tunlion join <file> --json`. Pairing always needs consent on both ends; never
try to pair silently.

### Change what a device may do

Distinguish revoking a capability from cutting off a device. Withdrawing an
invitation stops future claims, not devices already enrolled. An invitation's
own capability ceiling cannot be narrowed with a capability revoke; follow the
command's refusal rather than reporting success. Owner-grant withdrawal is
delivery/expiry bounded and does not close existing sessions (see above).

```bash
tunlion demote <device> --to cut -y --json   # cut it off (limits above)
tunlion promote <device> -y --json           # one step up (from cut off: back to where it was)
```

Rungs: `cut`, `paired`, `device` (one of the user's devices), `shell` (it can
act as the user). `--json` reports `from`, `to` and the `undo` command. Never
promote to `shell` unless the user asked for exactly that. Making a paired
device one of the user's devices needs a one-time code typed on it, so it
refuses under `--json` (exit 2): tell the user to run `tunlion promote
<device>` at a terminal.

### Diagnose a link

```bash
tunlion doctor <device> --json   # per-phase ladder and verdict
tunlion doctor --json            # environment preflight, no device
```

## Environment

- `TUNLION_CONFIG_DIR=<dir>` uses a separate identity and state (for tests or
  a second identity). Default is `~/.config/tunlion` on Linux, the platform's
  config directory elsewhere.
- `TUNLION_NONINTERACTIVE=1` is implied when stdin is not a TTY.
- `--relay` forces the relay; `--no-relay` fails instead of using one. Leave
  both off unless the user asked.
