# Exec acceptor in `filament-peerloop`

Status: implementation branch `work/exec-server-peerloop`, rebased onto `main`
`1c74c4a99d27080936ca3ece993f2b685a868383` (the dispatch/identity/enrollment/
roster/Core-host stack). The review-approved branch was `b77dbcb2` on the
earlier `e86ed8ee` base; the remote verification below ran on the same exec code
at `afb631e5` over `7748ab1f`.

## What moved

`cli/src/exec_recv.rs::handle_exec_open` and `serve_exec` are now one library
state machine in:

- `crates/filament-peerloop/src/shell/exec_server.rs` (feature `exec-server`):
  admission call, mux creation, stream-cap and collision refusal, ack, detached
  serve task, stdout/stderr pumps, stdin EOF/channel death, heartbeat/link
  liveness, forwarded signals, live revocation/expiry/ceiling cancellation,
  exit status (`code` or `128+signal`), stream-end sentinels and named closes.
- `crates/filament-peerloop/src/recv/servers/exec.rs`: the `exec-open` entry
  point. With the feature off it sends the named
  `exec receive is not available in this build` close and compiles no backend.

The CLI keeps only the machine-bound process adapter in
`cli/src/exec_recv.rs`: PATH/env/home facts, the account drop argv, the real
spawn (own process group, parent-death/job-object containment, `SERVED_GROUPS`
record) and the child handle. `ExecProcess` / `ExecChild` are the seam; the
library never reads a settings path, an environment variable, a process token
or an ambient global.

New Cargo features:

- `filament-peerloop/exec-server` (default on) implies `dispatch`, because the
  exec module imports `recv::dispatch`; `--no-default-features --features
  exec-server` is therefore also a valid compile profile.
- `tunlion/exec-server` (default on), which also compiles the CLI adapter.

Reduced profiles that explicitly omit defaults (`--no-default-features
--features dispatch`, or the CLI's `mesh,mount-server` check) leave
`exec-server` off. They answer a well-formed L2-half `exec-open` with the named
refusal and compile no CLI spawn backend.

Android nuance: this is NOT a claim that phones never serve exec. A default
Android CLI release (default features on) compiles `exec-server` and its process
adapter exactly as the default desktop CLI does. Only a reduced profile that
explicitly disables default features omits it.

## #542 rebase overlap

This branch is based on #542 and changes only:

- `crates/filament-peerloop/src/shell/exec.rs` (adds process seam + moved pure
  helpers; parser untouched)
- `crates/filament-peerloop/src/shell/admit.rs` (`Admitted` gains
  `admitted_via_ceiling`)
- `crates/filament-peerloop/src/shell/exec_server.rs` (new)
- `crates/filament-peerloop/src/recv/servers.rs` and `recv/servers/exec.rs`
- `crates/filament-peerloop/src/host.rs` (four narrow host facts:
  `device_key_known`, `gate_settle_ms`, `reinvite_for`, `peer_liveness_alive`)
- `crates/filament-peerloop/Cargo.toml`, `cli/Cargo.toml`
- `cli/src/exec_recv.rs` (adapter only), `cli/src/recv_ports.rs`,
  `cli/src/exec_send.rs`, `cli/src/host_impl.rs`

It does not touch #543/#544/#545 files, the dispatch loop, or the owner's
worktree. Rebase order after #542: this branch's `shell/*` and `recv/servers/*`
changes apply directly; the `host.rs` additions are default methods, so other
host implementations keep compiling. If #543+ later moves device-store reads
behind `RecvStore`, `device_key_known`/`reinvite_for` should be rerouted through
that port rather than reimplemented in the exec module.

## Tests

- Library unit tests use a deterministic fake transport and fake child for ack
  order, separate stream sids, exact argv, user-like env baseline, cwd refusal, tty
  refusal, user-drop refuse-not-downgrade, exit code and ladder.
- The real-binary `cli/tests/exec-gates.sh` is the end-to-end proof: gates A-R
  are 22 passing observations, and `revoke-gates.yml` enforces that count.
  Gate L covers the `--shell-user` drop's identity and target-user environment
  (HOME/USER/SHELL/XDG, no daemon profile).
- CI compiles the library/CLI with `exec-server` off in the existing Android
  boundary jobs. The remote worker additionally ran
  `--no-default-features --features exec-server` to prove feature implication.

## Remote verification (2026-10-20)

Tested source `afb631e5df240660eed73caf115c2509c87c79f3`, tarball
`exec-server-afb631e5df24.tar.gz` (sha256
`71469b442b95d40d06c032ef02ec190c01bfa6997b03ec4cdfc1ac360a08cff7`).

- `cargo test -p tunlion-peerloop --lib --locked` — 372 passed.
- `cargo test -p tunlion-peerloop --lib --locked --no-default-features
  --features exec-server` — 281 passed (proves `exec-server` implies `dispatch`).
- `cargo test -p tunlion-peerloop --lib --locked --no-default-features
  --features dispatch` — 277 passed, including both reduced-refusal tests.
- `cargo check -p tunlion --locked --no-default-features --features
  mesh,mount-server` — passed.
- Release binary from the same source + `cli/tests/exec-gates.sh` — **21/21
  passed** (argv/streams/stdin/EPIPE/exit/signal/bulk/rsync/initiator death/
  revocation/daemon kill/forget/shell-user).

Worker artifacts: `/home/runner/work/_temp/tunlion-work/results/exec-server-afb631e5df24/`.
The shared `build.lock` was held by an unrelated invisible job during this run,
so the job used its own target under
`jobs/exec-server-afb631e5df24/cargo-target` with `CARGO_BUILD_JOBS=2`; no
other job's files or target were touched.
