# The engine driver, and what is still linked out

> Status: the receive **dispatch body** is library-owned and `Core::start`
> composes a real reduced host around it. Identity/store/enrollment/roster/
> depart are library implementations; absent server/daemon endpoints are
> explicit refusals, not successes.

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
  | `Starting(engine)` | no | `Starting` | `Core::start` spawned the dispatch and is waiting for readiness |
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

## What is still linked out

`recv_run` moved to `crates/filament-peerloop/src/recv/dispatch.rs` with the
transfer/consent/file arms, the reconnect loop, cleanup and the file/event
helpers. The CLI's `recv_cmd` builds a `RecvPorts` and calls
`recv::dispatch::drive`; `up_cmd` reaches the same path.

The loop no longer names a CLI function. The remaining machine-bound sectors
arrive through grouped capability traits in `recv::ports` (their method count is
the host-effect surface, not a split target):

- `RecvIdentity` — proof/expose, cert renewal, auth-key enrolment, provisional
  identity, device naming/revocation and the fleet host answers. Proof/expose,
  renewal, provisional identity, naming/revocation and the local certificate
  now live in `recv::identity::IdentityService` and `recv::store`, with an
  explicit store root, overlay-key path and log sink. Auth-key enrolment lives
  in `recv::enrollment` with its own `EnrollmentState` (nonces, live burns,
  rate-limit windows) and the durable `used-invitations`/`armed` reads on the
  same explicit store. Roster verification/storage and the depart signature
  binding moved to `recv::roster` and `recv::membership`; the fleet rendezvous
  facts moved to `recv::fleet_rv::FleetService` with an explicit announce path
  and route list. The CLI forwards all of them.
- `RecvStore` — the mutating half of the devices/capability store. Its
  host-neutral implementation now lives in `recv::store`: a `DeviceStore`
  opened on an explicit root implements the whole port (device records, the
  capability store's owner-signed ops, provisional/local identity sidecars).
  The CLI constructs one on its process config directory and forwards, so there
  is one implementation rather than a callback-only wrapper.
- `RecvServers` — the process effects of the optional inbound servers. The
  forward admission protocol moved to `recv::servers::open_forward`; the CLI
  still supplies PTY/exec/sync/mount/ssh primitives through this boundary.
- `RecvDaemon` — warm links, mounts, bootstraps, reach liveness, revocation
  snapshots and the userspace proxy. The CLI implementation forwards to
  `daemon_ctl`, `revocation_live`, `wg`, `subnet_forward`, `sshd` and
  `proxy_state`.
- `RecvPrompt` — the code prompt/confirmation and raw-mode guard.

`RecvEnv` is the process snapshot the CLI resolves (name, uid, terminal
interactivity, quiet window, L2/direct posture, consent token).

`Core::start` now validates identity/config, takes the same-root `up.lock`
lease, starts the real `recv::dispatch::drive` on the Core runtime and waits
its publish-once readiness edge. The reduced `tunlion-core` host composes
`DeviceStore`, `IdentityService`, `EnrollmentService`, roster/depart and a
logical `CoreHost`; it refuses PTY/exec/ssh/sync/mount/warm/proxy/wireguard/
sshd endpoints explicitly. Fleet is optional and not composed in this profile.
The remaining work is the real server/daemon handlers and the capability policy
site, not identity composition.

Next linkage work, in order:

1. Implement the real PTY/exec/ssh/sync/mount/warm/proxy/wireguard/sshd
   handlers behind the reduced profile's explicit refusals.
2. Compose the capability policy site for Core (today gated shell/forward
   actions deny by default in the reduced profile).
3. Optionally compose `recv::fleet_rv::FleetService` when the mesh/fleet profile
   is enabled.

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
error recorded as `Failed`; the no-engine stop no-op; and a real
`Core::start` -> dispatch -> `stop_blocking` integration over a local signaling
stub. Android keeps the reduced `filament-peerloop` profile: no
`mount-server`, `forward-server` or `mesh` sectors compile into the core
library.
