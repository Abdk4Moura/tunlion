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

Navigation uses Jetpack's `NavHost`, with Android predictive back enabled. Back
gestures seek the destination transition before release; cancelling keeps the
current destination and its form state. Back returns to the previous task,
including Files or setup, rather than always jumping home. Recovery words and
capture protection remain active until the recovery destination is disposed
after a committed pop, not when a gesture merely starts.

`TunlionCore` is the app boundary. The temporary `CliTunlionCore` backend drives
the real Rust CLI for all operations. There is no FFI dependency in this preview.
The workflow builds the ARM64 and x86_64 CLI from the same revision as the app,
packages it as `libtunlion_cli.so`, and enables Android native-library extraction
so the signed executable can run from `nativeLibraryDir`. Local builds require
the same ABI binaries under `app/src/main/jniLibs/` and a standard Android debug
keystore under `.signing/preview.keystore`.

- Commands use argument arrays, private explicit config paths, structured JSON
  and exit codes. Stdout and stderr are drained separately without logging
  invitation material or codes. Cancellation terminates and reaps the child.
- CLI identity setup happens in a private draft directory. Confirmation promotes
  the complete state directory; cancelling discards it. Capture is blocked while
  recovery words are visible. Existing identities and pairings are never replaced.
- Availability owns an attached `up --userspace` child in a foreground service,
  with bounded restart backoff. Off waits for shutdown and removes its notification.
- User-started pair/transfer operations have a foreground service while the app
  is backgrounded. UI snapshots are polled only while the Activity is started.
- Invitations are copied into owner-only private files and passed by path, never
  as invitation bytes in argv. Picker content is staged privately for sending.
- Verified receive history drives publication into `Download/Tunlion` through
  MediaStore on Android 10+, with an export journal to avoid duplicate saves.
  Android 8/9 uses a user-selected SAF folder. No storage permission is requested.
- The UI reports verified completion only from CLI outcomes/history. Unknown
  peer presence and routes are left unknown, not invented from stored names.

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
