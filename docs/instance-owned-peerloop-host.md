# Instance-owned peer-loop hosts

`filament-peerloop` no longer installs or looks up a process host. Each `Conn`
already owns an `Arc<dyn HostServices>`; its L2 muxes now receive clones of that
same host. Independent connections can therefore retain independent hosts in
one process, without first-install-wins sharing.

## Constructor migration

- `Mux::new(transport)` becomes `Mux::new(transport, host)`.
- `Mux::with_host(transport, host)` remains an equivalent explicit constructor.
- `host::install_process_host` and `host::process_host` are removed.
- For intentionally inert behavior, pass `Arc::new(host::NoHost)` explicitly.
  There is no missing-host fallback. The one-argument constructor is covered by
  a compile-fail doctest.

Receiver and daemon-control mux construction uses `conn.host.clone()`. Standalone
CLI commands inject the existing `host_impl::cli_host()` adapter at their command
composition boundary. Nothing in the library imports CLI or platform services.
An Android/in-process embedder supplies its own host, not a spawned CLI.

Regression tests exercise simultaneous muxes with distinct dial refusals and
live-session cut reasons, plus an explicit inert mux that cannot inherit either
host. Existing routing, stream-cap, collision, teardown and inert-dial tests keep
their behavior, with explicit inert hosts.

## Remaining globals and next seam

This removes host ownership globals in `filament-peerloop`, not every global in
the dependency graph. `filament-transport::hooks` still has process-wide logging,
network/interface, settings, membership and config-path callbacks; transport
address caches and CLI-owned config/capability state also remain unchanged.
Those are separate isolation seams, not substitutes for a mux's host. Full
transport/config isolation needs a subsequent bounded slice; this change does
not claim all transport behavior is instance-isolated.

Validation is CI-only: no local Rust builds, tests or binding generation.
