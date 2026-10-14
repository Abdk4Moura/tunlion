---
name: tunlion
description: Move files, run commands, and reach ports between the user's own paired devices with the tunlion CLI (peer to peer, end-to-end encrypted, no cloud upload). Use when the user asks to send or receive a file to/from one of their devices or a one-time code, run a command or open a shell on another machine they own, check whether a device is reachable, tunnel to or publish a port, or pair a new device. Do not use for uploading to cloud services, emailing files, or machines that are not paired with tunlion.
---

# tunlion

tunlion connects the user's devices directly (QUIC or WebRTC, relay only as a
fallback). Every command below is the one correct form; do not guess other
flags. When unsure of a flag, run `tunlion <command> --help`, which also lists
the exit codes that command can return.

## Rules

1. Always pass `--json` on commands that support it: `init add join id status
   set reach send receive sync doctor addr devices skill`. Other commands refuse
   `--json`; read their exit code and stderr instead.
2. Decide by exit code, never by parsing human text. Under `--json`,
   `ok` is true exactly when the exit code is 0, and a failure is one object:
   `{"ok":false,"error":{"code":"unknown_device","exit":3,"message":"..."}}`.
3. You are never at a TTY. Prompts do not appear; commands that need
   confirmation (`down`, `reset`, `revoke`, `devices forget`, `devices revoke`,
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
| 126 / 127 | | `exec`: remote command not executable / not on PATH | fix the command name or path |
| 130 / 143 | | interrupted / terminated | report; do not retry automatically |
| 141 | | output closed early (`| head`) | expected for piped reads |

`exec` passes the remote command's own exit status through, so a remote
status of 3 looks like tunlion's 3; the reason line on stderr says which.

## Tasks

### Check what is available

```bash
tunlion status --json           # is the daemon up on this machine (exit 11 if not)
tunlion devices --json          # paired devices and their names
tunlion reach <device> --json   # reachable? direct or relay, and rtt
```

### Send a file

To a paired device (no code, the device must be running `tunlion up`):

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
```

A code is already consent; no prompt appears. `-o -` streams a single file to
stdout.

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
pid when done. If refused for lack of `shell`, the port may already be
published with `expose`: try `<device>.mesh:<port>` directly.

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
tunlion add --for person --out <file> --json
```

Get the file to the other machine; there the user (or you) runs
`tunlion join <file> --json`. Pairing always needs consent on both ends; never
try to pair silently.

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
