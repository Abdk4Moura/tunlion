# tunlion for Android: build spec (v1)

Status: ready to build, 2026-10-15. The Android app (`android/`) calls the shared
Rust core through UniFFI. The Android CLI build in `cli/` is a separate platform
compatibility track and is not the app. v1 ships when the native core and app
acceptance tests pass on a real phone.

## What v1 is

A phone app that makes the phone a first-class tunlion device, in the spirit of
the Tailscale app (one switch, a device list, share-to-send) but tunlion's model:
no account, pairing by a short code, permissions written only on the device that
grants them.

v1 does:

1. Set this phone up, or join with a code (pairing code or invitation).
2. Show my devices: name, online or not, direct or relayed, and the plain line
   (what each side may use, and until when).
3. Send files: from the app, and as an Android share-sheet target
   ("Send with tunlion"), to a device or as a code.
4. Receive files: by code, and automatically from my own paired devices while the
   app is available; saved to `Download/Tunlion`.
5. Pair: show a code (with QR), or type or scan one.
6. Shell: open a terminal on a device that granted this phone shell.
7. Be available: a foreground service with a persistent notification, switched on
   and off from the app (the Tailscale-style switch).

v1 does NOT do: the mesh VPN (phase 2), mount, port forward UI (phase 2),
serving a shell from the phone (never by default), multi-user profiles.

## Architecture (v1): Kotlin app calls the Rust library

The Android app calls the shared tunlion Rust core through UniFFI. It does not
spawn the CLI or duplicate protocol logic. The library surface, lifecycle,
records, typed errors, file staging, and shell byte interface are specified in
[`docs/android-ffi.md`](android-ffi.md). Keep UI and service code behind the
Kotlin `TunlionCore` interface; its first implementation uses the generated
UniFFI bindings.

- Build `crates/tunlion-core` as `libtunlion_core.so` for
  `aarch64-linux-android` (phones) and `x86_64-linux-android` (emulator), and
  package it under `jniLibs/<abi>/`.
- `Core.open` uses `Context.filesDir/tunlion`; identity keys stay in this
  private app directory. The foreground service owns the notification and calls
  `Core.start` / `Core.stop`. No child process is involved.
- Poll `Core.status()` every 2 seconds while the app is foregrounded. The core
  owns its runtime and reports long-running transfer, pairing, and shell work
  through typed callbacks.
- The app stages picker/share-sheet files privately for sending. Verified
  received files are published to `Download/Tunlion` through `MediaStore`.
  Invitation material is passed as bytes to the native library, never through
  command-line arguments or logs.

## Track A: Android CLI compatibility (merged prerequisite)

A1. **Build for Android.** `target_os = "android"` is not `"linux"` in Rust, and
    `cli/src` has 83 Linux-only `cfg` blocks. For each: either extend it to
    Android (`any(target_os = "linux", target_os = "android")`) where the code is
    plain Linux userspace (procfs reads, sockets), or give Android an explicit
    stub where it needs things an app cannot use (systemd, `ip`, kernel TUN, FUSE,
    sudoers, sshd config). `fuser` and kernel TUN stay off on Android.
A2. **Paths and services on Android.** No `systemd`, no `$HOME` assumptions:
    honour `TUNLION_CONFIG_DIR` and `--dir` everywhere; `up --install` refuses on
    Android with a clear message (the app is the service manager).
A3. **CI build.** A workflow job that builds `aarch64-linux-android` and
    `x86_64-linux-android` with the NDK (cargo-ndk) and uploads both binaries as
    artifacts. Gate it like the other Rust jobs (`scripts/check_ci_paths.py`).
A4. **Acceptance (core):** on an emulator or phone via `adb shell`, running the
    binary from a `run-as` app directory: `init`, `add` (code shown), `join` from
    a desktop, `send --to`, `receive <code>`, `shell` to a desktop, `up --userspace`
    stays up 30 minutes, `status --json` valid throughout.

## Track B: Android app (`android/`)

- Kotlin, Jetpack Compose, minSdk 26, targetSdk current. Single activity.
- Gradle builds in CI on Linux; the APK is a CI artifact. Local builds are
  optional (Android Studio on Windows), not required.
- Design: follow the tunlion design project (tokens in `tl-ui.jsx`: ink, paper,
  accent; Instrument Sans and IBM Plex Mono, bundled as font resources, never
  fetched at runtime). Light and dark. The same nouns as the CLI and web app:
  code, device, remember, my devices, shell, files, cut off, forget, ends.
- Screens:
  1. **Home**: the availability switch at the top ("Available" / "Off"), then
     "Enter a code" (one box, plus a scan button), then My devices.
  2. **Device**: plain line, online state and route, buttons only for access this
     phone holds (Send files, Shell), Forget.
  3. **Send**: pick files or arrive from the share sheet; choose a device or
     "Make a code"; progress; done state with "verified".
  4. **Receive**: incoming transfer notification; code entry; saved-to location.
  5. **Pair**: show code (large text and QR) or enter/scan; result.
  6. **Shell**: full-screen terminal, key bar (Esc, Tab, Ctrl, Alt, arrows,
     `| / ~ -`), reconnecting state, End.
  7. **Settings**: this device's name, inbox folder, about, licences.
- Permissions: notifications (foreground service, incoming files), camera only
  when scanning, no storage permission (use the system pickers and
  MediaStore for `Download/Tunlion`), no location, no contacts.
- Components exported: only the share-sheet `ACTION_SEND` / `ACTION_SEND_MULTIPLE`
  activity. Nothing else is exported.

## Acceptance (v1, real phone + a desktop running tunlion 0.9.0)

1. Fresh install, "I have a code": joins a desktop's `tunlion add` code; both
   sides list each other.
2. Share a photo from the gallery with "Send with tunlion" to the desktop; it
   arrives verified.
3. Desktop `tunlion send file --to phone` while the app is Available and in the
   background; the phone notifies and saves it to `Download/Tunlion`.
4. Desktop `tunlion send file --code`; the phone receives it by typing the code.
5. Desktop grants the phone shell; the phone opens a shell, runs `hostname`,
   survives switching Wi-Fi to mobile data (reconnecting, then resumes).
6. Availability off: no process left running, no notification.
7. A device that has not granted shell shows no Shell button.
8. Dark mode, font scaling 200%, TalkBack labels on every control.

## Security rules (non-negotiable)

- Keys never leave the app's private storage; no backups of the config dir
  (`android:allowBackup="false"`, or exclude it in the backup rules).
- No telemetry, no analytics SDKs, no network calls except tunlion's own.
- Never pass invitation material on a command line: write it to a private file
  and pass the path (`join <path>`).
- The app never grants this phone's shell on its own; `grant` only from the user's
  explicit action, with the same warning the CLI shows.

## Phase 2 (after v1)

Mesh VPN through Android's `VpnService` (tunlion gets a `--tun-fd` mode for the
userspace overlay); port forwards; Android Keystore-wrapped keys.
