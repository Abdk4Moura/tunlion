# The engine driver, and what is still linked out

> Status: first production-used driver path landed. The receive **dispatch
> body** is still in the CLI. `Core::start` therefore still refuses by name.

## What moved

`filament_peerloop::driver` now owns the engine *runtime* around a receive or
daemon dispatch, not just a cancellation latch:

- `Cancellation` — the latched, per-call stop request (unchanged).
- `Readiness` / `ReadyWatch` — a publish-once readiness edge with an awaitable
  half. The dispatch raises it after required setup; a supervisor can wait with
  a bound. A dispatch that returns without publishing reports `NotPublished`,
  never "ready".
- `Engine<T>` — spawns exactly one dispatch task, owns its `JoinHandle`, and
  exposes `ready`, `request_stop`, `stop`, `stop_within` and `wait`. `Drop`
  requests stop and detaches; it never joins.

Everything is instance-owned. There are no process globals, no signals, no
`std::process::exit`, and no child process. The runtime itself belongs to the
caller: the CLI's process runtime, or the runtime `tunlion-core` creates per
`Core` when the caller has none.

## Who uses it

- **CLI `recv` / `up`.** `cli/src/recv_cmd.rs::recv_cmd` starts the one engine
  task through `Engine::start` and awaits `Engine::wait`. The task runs the
  unchanged production dispatch `recv_run`. The CLI still owns process policy:
  signal installation (`recv_lifecycle::Signals`), the 130/143 exit codes, the
  JSON interrupt envelope, the pid/ready markers and the cleanup resources in
  `RecvCleanup`. `up_cmd` reaches the same driver; it does not have a second
  acceptor.
- **`tunlion-core`.** `Core::start_with_dispatch` starts the same `Engine` for
  a Rust embedder that has the dispatch, and `Core::stop` requests stop and
  waits for the dispatch's own epilogue. This is Rust-only on purpose: UniFFI
  cannot carry a closure, and `Core::start` must not pretend it can.

## What is still linked out, and why `Core::start` refuses

The dispatch body is `cli/src/recv_cmd.rs::recv_run` — roughly 7,700 lines
spanning the outer accept loop and ~40 `Ev` arms, reaching ~118 crate-root
items across ~40 CLI modules. Moving it is the `filament-peerloop` step of
`docs/design-libfilament.md` ("one driver replacing the eight hand-written
loops"), assembled from the crates below it. The sectors that still carry CLI
config/devices/session state (a non-exhaustive audit at this commit):

- transfer session admission, offers, `Ev::Control`, `Ev::Chunk`,
  `Ev::MaybeComplete` and `cli/src/session.rs` pumps;
- identity challenge / expose / cert-renew / auth-key-enroll responses and the
  provisional-identity store (`cli/src/identity_lifecycle.rs`,
  `identity_state.rs`);
- the device store (`devices_load`, `devices_touch`, …) and capability writes;
- the daemon control server handlers that carry `l2::Mux`, `DaemonMounts` and
  the persistent mount store (`cli/src/daemon_ctl.rs`);
- mount restore, pty/exec-store bindings (`WarmPtys`), sshd, L3 proxy,
  subnet-forward reconciliation, roster/presence pushes and sdnotify.

Until those are library-callable, the safe outcome is the one the code keeps:
`Core::start` returns `EngineNotLinked`, and an Android caller that wants the
receive loop keeps using the reviewable CLI surface. The engine runtime is no
longer the blocker; the dispatch body's sectors are.

## Verification

CI-only (no local Rust builds, tests or binding generation). The moved code has
in-memory `#[tokio::test]` coverage for latched/repeated cancellation, publish
once, readiness observed across tasks, `NotPublished` on early return, bounded
`TimedOut`, independent instances, `stop` joining the dispatch epilogue, and
`Drop` requesting stop without joining. `tunlion-core` tests cover
`start_with_dispatch` / `stop` running and stopping one owned dispatch both
inside and outside an ambient runtime, refusing a second start, and the
no-engine stop no-op. Android keeps the reduced `filament-peerloop` profile:
no `mount-server`, `forward-server` or `mesh` sectors compile into the library.
