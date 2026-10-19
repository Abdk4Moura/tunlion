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
