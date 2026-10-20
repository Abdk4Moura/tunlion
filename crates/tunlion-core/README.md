# tunlion-core

tunlion as a library any process can call. Android is what forced the surface
into existence. It is one caller. A desktop embedding or another language
binding uses the same types.

Contract: `docs/android-ffi.md`.

Slice 1 opens an explicit config directory and mints a recoverable identity.
`Core::start` now composes the reduced library host, takes the same-root engine
lease and runs the real `recv::dispatch::drive`, waiting for readiness.
`Core::stop` / `stop_blocking` join it; `start_with_dispatch` remains for Rust
embedders that supply their own dispatch. It never spawns the `tunlion` binary.
The remaining real server/daemon handlers are listed in
`docs/engine-driver.md`.

`stop` / `stop_within` join the dispatch and reap its outcome. `Drop` is only a
fallback: it requests cancellation and shuts the instance runtime down
non-blocking (`shutdown_background`), so it is safe inside an async context but
does not prove the epilogue returned. A task that finished on its own stays
`FinishedUnjoined` (never `Stopped`) until `stop` joins it.
