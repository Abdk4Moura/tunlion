# The engine driver, and what is still linked out

> Status: the receive **dispatch body** is library-owned now. It lives in
> `filament-peerloop::recv::dispatch`; the CLI is the process adapter.
> `Core::start` still refuses by name because it has no host composition for
> the dispatch's capability ports yet.

## What moved

`filament_peerloop::driver` now owns the engine *runtime* around a receive or
daemon dispatch, not just a cancellation latch:

- `Cancellation` — the latched, per-call stop request (unchanged).
- `Readiness` / `ReadyWatch` — a publish-once readiness edge with an awaitable
  half. The dispatch raises it after required setup; a supervisor can wait with
  a bound. A dispatch that returns without publishing reports `NotPublished`,
  never "ready".
- `Engine<T>` — spawns exactly one dispatch task, owns its `JoinHandle`, and
  exposes `ready`, `request_stop`, `stop`, `stop_within` and `wait`. `stop` /
  `wait` consume the engine and join the dispatch's own epilogue. `stop_within`
  borrows instead: on a bound expiry it returns `TimedOut` and **retains** the
  task (the `JoinHandle` is not dropped), so a caller can retry or observe it
  and must not report it stopped. `Drop` requests stop and detaches; it never
  joins.

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
  a Rust embedder that has the dispatch; `Core::stop` / `stop_within` request
  stop and join its own epilogue. This is Rust-only on purpose: UniFFI cannot
  carry a closure, and `Core::start` must not pretend it can.

  `Core` owns exactly one engine per instance, behind one mutex, with an
  explicit slot state machine:

  | slot | start allowed | `status().engine` | what it means |
  |---|---|---|---|
  | `None` | yes | `NotLinked` | nothing was ever started |
  | `Running(engine)` | no | `Running`, or `FinishedUnjoined` once finished | the one engine; a finished task is still unjoined |
  | `Stopping` | no | `Stopping` | a stop claimed the slot and is joining |
  | `Unstopped(engine)` | no | `TimedOut` while live, `FinishedUnjoined` once finished | a stop bound expired; the task is retained and not joined |
  | `Ended(Ok)` | yes | `Stopped` | the task was joined and returned cleanly |
  | `Ended(Err)` | yes | `Failed` | the task was joined and returned an error (or panicked) |

  A start replaces only `None` / `Ended` — states where the prior task was
  actually **joined** and its outcome retrieved. While a stop is claimed
  (`Stopping`) a concurrent start and a concurrent stop both fail with
  `EngineStopping`; a bound expiry (`TimedOut`) refuses a start with
  `EngineNotStopped` until the retained task is joined. A task that finished on
  its own is `FinishedUnjoined` and refuses a start with `EngineNotJoined`: its
  `JoinHandle` still owns the `Ok`, `Err` or panic, so replacing the slot would
  discard it. `stop` / `stop_within` is what joins that handle and records
  `Stopped` or `Failed`. A stop future dropped mid-join returns the task to the
  slot as `Unstopped` via `StopClaim::drop`, so the task is never detached on
  the floor. `Stopped` is therefore only recorded after a confirmed join.

  `Core::drop` is a fallback, not a joined stop: it requests cancellation by
  dropping the engine slot, then calls `shutdown_background` on the
  instance-owned runtime. That is non-blocking and safe inside another Tokio
  async context (dropping a `Runtime` there would panic); any task that has not
  observed cancellation is abandoned with the runtime. Callers that need the
  dispatch epilogue use `stop` first.

## What is still linked out, and why `Core::start` refuses

`recv_run` moved to `crates/filament-peerloop/src/recv/dispatch.rs` with the
transfer/consent/file arms, the reconnect loop, cleanup and the file/event
helpers. The CLI's `recv_cmd` builds a `RecvPorts` and calls
`recv::dispatch::drive`; `up_cmd` reaches the same path.

The loop no longer names a CLI function. The remaining machine-bound sectors
arrive through five narrow traits in `recv::ports`:

- `RecvIdentity` — proof/expose, cert renewal, auth-key enrolment, provisional
  identity, device naming/revocation and the fleet host answers. The CLI
  implementation forwards to `identity_lifecycle`, `renewal_lifecycle`,
  `device_view`, `identity_state` and `fleet`.
- `RecvStore` — the mutating half of the devices/capability store
  (`devices_store`, `device_caps`).
- `RecvServers` — the optional inbound servers: PTY, exec, forward, sync, mount
  and ssh-sign, plus live `expose` reconciliation. The CLI implementation
  forwards to `l2`'s PTY sessions, `exec_recv`, `sync_cmd`, `mount_recv`,
  `ssh_ca` and `expose`.
- `RecvDaemon` — warm links, mounts, bootstraps, reach liveness, revocation
  snapshots and the userspace proxy. The CLI implementation forwards to
  `daemon_ctl`, `revocation_live`, `wg`, `subnet_forward`, `sshd` and
  `proxy_state`.
- `RecvPrompt` — the code prompt/confirmation and raw-mode guard.

`RecvEnv` is the process snapshot the CLI resolves (name, uid, terminal
interactivity, quiet window, L2/direct posture, consent token).

For Core, the blocker is now **composition, not dispatch**: there is no
non-CLI implementation of `RecvIdentity`/`RecvStore`/`RecvServers`/`RecvDaemon`.
`Core::start` therefore keeps returning `EngineNotLinked`; an embedder that
supplies those and the existing `HostServices` uses `start_with_dispatch` with
`recv::dispatch::drive` today.

Next linkage work, in order:

1. Add a `CoreHost` composition that implements `HostServices`, `RecvEnv` and
   the five ports for an embedder with no CLI modules (the server sectors can
   be omitted behind the `dispatch` feature's server capability; reduced
   profiles already omit them).
2. Move the device-store mutations behind `HostServices` (or a storage crate) so
   `RecvStore` has a host-neutral implementation.
3. Move the identity lifecycle handlers into a `recv-identity` library feature,
   using `filament-id`/`filament-cap` and the host store instead of CLI
   `identity_lifecycle`/`renewal_lifecycle`.
4. Have `Core::start` construct `HostServices + RecvPorts` and call
   `Engine::start(..., recv::dispatch::drive(...))`; only then remove the
   `EngineNotLinked` arm.

## Verification

CI-only (no local Rust builds, tests or binding generation). The moved code has
in-memory `#[tokio::test]` coverage for latched/repeated cancellation, publish
once, readiness observed across tasks, `NotPublished` on early return, bounded
`TimedOut` that retains the task and can still join it, independent instances,
`stop` joining the dispatch epilogue, `Drop` requesting stop without joining,
and a blocked `announce` that keeps `is_ready` / `wait` unready until the
announcement returns. `tunlion-core` tests cover, deterministically
(channel-gated dispatches, no sleeps): start/stop one owned dispatch both inside
and outside an ambient runtime; dropping `Core` inside another runtime's
`block_on` after it created its own runtime (non-blocking `shutdown_background`,
no panic); refusing a start while a stop is in flight (`EngineStopping`);
refusing a concurrent stop while one is in flight; a stop bound expiry retaining
the task and refusing restart (`TimedOut` / `EngineNotStopped`) until it is
joined; a dropped stop future retaining the task via `StopClaim::drop`; a
natural `Err` and a natural panic remaining `FinishedUnjoined` and refusing
restart (`EngineNotJoined`) until `stop` joins and reports `Failed`; a dispatch
error recorded as `Failed`; the no-engine stop no-op; and that `Core::start`
stays `EngineNotLinked` without installing a slot. Android keeps the reduced
`filament-peerloop` profile: no `mount-server`, `forward-server` or `mesh`
sectors compile into the library.
