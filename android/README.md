# Tunlion for Android

This is the native Kotlin and Jetpack Compose app. It follows the Tunlion
browser UI's warm paper, ink, and orange palette, while using a compact
device-first layout inspired by Tailscale's interaction model.

Build a debug APK with:

```sh
gradle :app:assembleDebug
```

The preview uses one journey: set up this phone, connect a device, select it,
then send a file. Home contains this phone's availability and known devices;
code entry is a dedicated task, Files is contextual, and Settings lives in the
header. There is no bottom navigation bar. Screen changes use short slide/fade
transitions and in-flight actions prevent repeated submission.

`TunlionCore` is the app boundary. `NativeTunlionCore` uses generated UniFFI
bindings for real identity preparation, confirmation, and loading. Recovery
words stay in memory until confirmed, and screenshot capture is blocked during
recovery setup. The peer loop is not linked yet: connection and file operations
refuse with an explanation and never show demo peers or simulated success.

The app workflow pins native source and libraries from the same PR 467 commit
(`0a5a0b0`) while that prerequisite is reviewed. Kotlin is generated in CI from
the matching library metadata. Local builds need those generated bindings in
`app/build/generated/uniffi` and the native libraries in `app/src/main/jniLibs`.

## Preview feedback

Shake twice while the app is visible to select a region, review the crop, add a
comment, and open Android's share sheet. The comment is included in both the
message and the PNG so it survives share targets that discard accompanying
text. Choose this conversation as the destination if available, or attach the
shared image here yourself. The app cannot send directly into an assistant
session.

Shake feedback is enabled by default in this experimental preview. It uses
only the foreground accelerometer, a two-peak threshold, and a ten-second
cooldown. Disable it in Settings, or use the manual feedback button there.
Screenshots stay in memory until you choose Share; only the crop and comment
are written to private cache. No automatic upload, photo-library write,
storage permission, or background sensor listener is used. Shared feedback
files older than 24 hours are cleaned up on the next share.
