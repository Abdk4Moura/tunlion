# Android Core acceptance

This minimal test APK loads the CI-built `libtunlion_core.so` through the
generated UniFFI Kotlin bindings and JNA. It does **not** contain or launch the
Android CLI.

The `android Core FFI acceptance` job in `.github/workflows/android.yml`:

1. Downloads the library and Kotlin bindings from the same workflow revision.
2. Assembles and installs this APK on an x86_64 API 30 emulator.
3. Commits an identity through FFI, starts the real dispatch, verifies a second
   instance cannot take its lease, stops, and starts a successor on the same root.
4. Uses a real Linux CLI sender against a local signaling fixture. The APK calls
   `receiveCode` and verifies the file bytes, size, SHA-256 and returned summary
   inside its Android app sandbox. The host also requires a verified sender exit.

The blocking FFI calls run on the instrumentation worker, not Android's UI
thread. Missing artifacts, a missing code, timeout, and sender failure fail the
job; there is no skip-to-green fallback. Test XML is uploaded even on failure.

This tests the x86_64 Android runtime and the actual JNI/FFI boundary. The arm64
artifact is compiled separately; this is not evidence of a physical arm64 phone
or iPad, nor a cellular/NAT/TURN test.
