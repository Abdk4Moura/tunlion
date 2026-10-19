# tunlion-core

tunlion as a library any process can call. Android is what forced the surface
into existence. It is one caller. A desktop embedding or another language
binding uses the same types.

Contract: `docs/android-ffi.md`.

Slice 1 opens an explicit config directory and mints a recoverable identity.
The engine *runtime* is linked: `Core` owns one `filament_peerloop::driver::
Engine` per instance (`start_with_dispatch` / `stop`). The receive *dispatch
body* is still in the CLI, so the credential-side `start` refuses by name with
`EngineNotLinked` until it is library-callable. It never spawns the `tunlion`
binary. Remaining sectors: `docs/engine-driver.md`.

`stop` / `stop_within` join the dispatch and reap its outcome. `Drop` is only a
fallback: it requests cancellation and shuts the instance runtime down
non-blocking (`shutdown_background`), so it is safe inside an async context but
does not prove the epilogue returned. A task that finished on its own stays
`FinishedUnjoined` (never `Stopped`) until `stop` joins it.
