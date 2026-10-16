# Tunlion for Android

This is the native Kotlin and Jetpack Compose app. It follows the Tunlion
browser UI's warm paper, ink, and orange palette, while using a compact
device-first layout inspired by Tailscale's interaction model.

Build a debug APK with:

```sh
gradle :app:assembleDebug
```

The current preview builds the navigation, home/availability, pairing-code,
files, and settings surfaces. `TunlionCore` is the app boundary. The native
library binding and peer loop are not linked in this preview, so actions that
require them fail closed with an explanation. The app never launches the CLI
and never shows demo peers or simulated success.
