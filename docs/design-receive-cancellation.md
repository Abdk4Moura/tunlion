# Receive invocation cancellation (first lifecycle seam)

This slice uses the existing `main -> dispatch -> up_logs::up_cmd -> recv_cmd`
driver (also used by one-shot receive). It does not link a second driver or
change `Core::start`: that still returns `EngineNotLinked`.

## Boundary implemented

- `filament_peerloop::driver::Cancellation` is a cloneable, latched **per-call**
  input. Repeated requests are harmless; dropping a handle does not request stop.
  There is no process-global cancellation state. A biased outer race stops the
  inline future even when its transport await or event receiver is pending.
- `recv_cmd` is the process adapter. It installs invocation-owned signal listeners
  before network startup and retains the existing signal-specific 130/143 exit,
  JSON interrupt envelope, and emergency watchdog policy. Patient connect no
  longer installs its own Ctrl-C/exit path. Send/pair policy is unchanged.
- `recv_driver` accepts that explicit cancellation input. Its `recv_run` body
  retains the protocol handlers and existing command arguments. Cancellation,
  ordinary return and error all reach `RecvCleanup::finish` before returning a
  `DriverOutcome`. Compatibility `Ev::Interrupted` also requests the same latch;
  OS signals do not depend on draining the event queue.
- State, Conn, the current signaling client (including after reconnect), the
  control-listener task, and the daemon stall observer are retained outside the
  cancellable future. Cleanup aborts **and joins** the control listener, makes a
  best-effort bounded stop of the stall observer before the potentially slow
  flush, flushes admitted receive entries using the existing best-effort partial
  parking, closes links, yields for close frames, and bounds signaling disconnect
  to one second. The driver's local TTY guard restores the terminal when the
  future is dropped. CLI signal exit removes daemon pid/ready markers; ordinary
  daemon return retains up_cmd's cleanup.

Return proves completion of **this epilogue**, not a fully stopped engine. The
caller must await the driver; arbitrarily dropping its supervisor is not an
async cleanup API. Panics and an outer drop of `recv_driver` do not run
`RecvCleanup::finish`; the watchdog still disconnect-wakes itself, but nothing
joins it and the sink stays alive until the observer returns.

## The stall observer has an explicit owner

`cli/src/recv_lifecycle.rs::LoopWatchdog` replaces the process-global
`loop_watchdog` module in `cli/src/recv_cmd.rs`. The heartbeat, `Once` latch and
forever thread are gone. This PR owns **one watchdog OS thread and its stop
handle**, not a receive-driver task: `RecvCleanup` owns the observer, `recv_run`
starts it on the first daemon tick, and the cleanup epilogue attempts to stop it
**before** `flush_inflight`. That ordering matters: the loop intentionally stops
turning while cleanup runs, so the old forever thread could report a false
"event loop stalled" during a slow flush and retained the first invocation's
`LogSink` for the process lifetime.

Stopping drops a wake channel (a sleeping observer wakes immediately) and makes
one `spawn_blocking` join attempt with a one-second bound. The outcome is
explicit:

- `NotStarted`: no thread or waiter existed.
- `Joined`: the observer thread was joined; its sink reference is released.
- `Detached`: the bound expired (or the waiter could not run). The observer and
  the `spawn_blocking` waiter are left to finish on their own. The observer keeps
  the sink `Arc` alive and the waiter stays registered until the observer exits.
  Repeated `stop` returns `Detached` and registers no second waiter.

`Drop` disconnects the wake channel and drops both handles without joining. A
panic, or an outer drop that bypasses `RecvCleanup::finish`, therefore does not
stop or join the observer synchronously.

## Readiness is deliberately NOT migrated

The only readiness change is that the existing Unix control-listener wait now
distinguishes success, sender drop, and timeout; neither failure announces up.
This is **control-listener readiness only**, not engine/dispatch readiness.

The existing daemon console banner still precedes Conn/sector initialization;
sdnotify and `up.ready` still precede awaited mount restoration. No new engine
ready channel or claim is made. The next small migration must choose one
dispatch-ready edge after required setup, move all three CLI advertisements to
consume it, and move optional restoration after dispatch (or explicitly bound
it). Only then should a readiness input/result be exposed for the driver.

## Remaining process ownership / limits

- stdin remains a CLI-only OS thread, reaped by process exit, not joined here.
  Interactive prompts and TTY restoration perform synchronous process I/O; the
  outer async race cannot preempt a synchronous blocking call.
- The CLI force-exit watchdog remains a detached Tokio task and can bypass a
  stuck cleanup after its grace. It does not prove an OS-thread deadline during
  scheduler starvation. The receive adapter no longer uses LAST_SIGNAL; other
  commands keep their existing process-global signal policy.
- `cli/src/recv_cmd.rs::recv_run`'s daemon-only
  `#[cfg(l3)]` auto-proxy `tokio::spawn(l2::proxy_serve(...))` (inside the
  userspace-L3 branch) is still detached. It owns the bound SOCKS listener and
  the `proxy_state` record; `l2::proxy_serve` in `cli/src/l2.rs` then spawns
  per-connection handlers and an optional HTTP listener that are not owned by
  the invocation. Cancellation currently leaves all of them to process exit.
- The short-lived spawns inside the loop (identity-hold timers, deferred
  re-injection, the route-label observer) are still fire-and-forget; they hold
  `Arc`s for up to `PROVEN_CHALLENGE_DEADLINE`, not OS resources.
- Config hooks, consent tokens, pid/ready markers, systemd notifications and
  presentation are still CLI/process concerns. This driver is **not embeddable**
  merely with NoHost.
- Control connection children, signaling mapping/read pumps (including during
  cancelled connect), session pumps, retry/transport reader tasks, mux/sector
  resources and asynchronous peer-close work are not comprehensively collected
  or joined. Joining the listener proves its future/listener is dropped, not
  that every already accepted control connection has terminated.
- Existing blocking writes are not first awaited by `flush_inflight`. Parking
  partials is not a durability barrier or proof that all writers stopped.
  Cleanup itself is not cancellable and flush has no new deadline. There is no
  shutdown-timeout/no-thread guarantee or safe restart promise at this seam.

Next ownership step: collect these producers/resources and admitted writes into
an explicit invocation task/resource owner, settle pending requests, then join
them before claiming Stopped or releasing a future engine lease. Audit remaining
instance-sensitive transport globals before claiming concurrent engine isolation.
Runtime ownership, Core linkage, stop/FFI state and Android composition remain
later work; Android must not launch the CLI as its engine.

## Verification scope

Focused in-memory tests cover latched/repeated cancellation, pre-poll precedence,
two independently cancelled/returning invocations, cancellation while awaiting
work, ordinary errors, task-destructor completion before return, and control
readiness success/drop/timeout. The watchdog tests cover a normal bounded
stop/join, repeated stop without a second waiter, a late tick after stop not
restarting the observer, the never-started case, `Drop` waking a blocked
observer without joining it, and a deterministic timeout/detach where the sink
is retained until release. Cleanup tests assert the production order
(`watchdog` before task destructors and `flush`) and that the cancellation
return path then joins a started watchdog and releases its sink. CLI tests call
the real receive return seam for pre-cancellation and validation failure without
filesystem/network setup or process exit. These are not integration proof of
all-resource shutdown.

Existing Test CI collects the CLI and filament-peerloop tests and retains daemon
stop, command/receive, cross-platform and Core gates. No local Rust build, test,
or binding generation was used for this change. This slice is independent of
the host-ownership PR #501: it changes neither HostServices, muxes nor Conn
constructors/public callers.
