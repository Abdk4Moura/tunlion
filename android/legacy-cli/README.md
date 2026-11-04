# Quarantined CLI adapter sources

These files are kept as historical regression material only. They are outside
every Gradle source set and are not compiled into the app, the test APKs, or
the shipped package.

`CliTunlionCore.kt` and `CliProcess.kt` launched a packaged CLI executable
through `ProcessBuilder`. The Android client now uses the shared native core
through UniFFI, and packing a second protocol implementation into the APK would
make it possible for the shipped app to regress to a subprocess backend. The
adapter is therefore not part of the build.

`CliProcessTest.kt` and `CliAndroidAcceptanceTest.kt` exercised that removed
adapter. They prove nothing about the native client and are not run. The native
replacements are:

- `NativeCoreAcceptanceTest` for bindings surface behavior.
- `NativeAdapterAcceptanceTest` for a real receive, verified publication and
  typed device facts.
- `DeviceAuthorityUiTest` for the relationship and action-state UI contract.

The app packages `libtunlion_core.so` only. The Android app workflow fails the
build if the APK contains a `libtunlion_cli.so` entry, a `tunlion` executable
asset, or any other `assets/` payload.
