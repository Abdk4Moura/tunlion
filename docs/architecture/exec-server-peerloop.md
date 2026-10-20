# Exec acceptor in `filament-peerloop`

Status: implementation branch `work/exec-server-peerloop`, based on the
immutable #542 head `e86ed8ee66388851de9b99b4145a7ae864690d44`.

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

- `filament-peerloop/exec-server` (default on)
- `filament-cli/exec-server` (default on), which also compiles the CLI adapter.

Reduced profiles (`--no-default-features --features dispatch`, Android's
CLI check with `mesh,mount-server`) leave `exec-server` off. They still answer a
well-formed `exec-open` with the named refusal; no spawn backend is compiled.

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
  order, separate stream sids, exact argv, env allowlist, cwd refusal, tty
  refusal, user-drop refuse-not-downgrade, exit code and ladder.
- The existing real-binary `cli/tests/exec-gates.sh` (gates A-R) remains the
  end-to-end proof and is unchanged.
- CI compiles the library/CLI with `exec-server` off in the existing Android
  boundary jobs.
