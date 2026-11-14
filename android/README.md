# Tunlion for Android

This is the native Kotlin and Jetpack Compose app. It follows the Tunlion
browser UI's warm paper, ink, and orange palette, while using a compact
device-first layout inspired by Tailscale's interaction model.

Build a debug APK with:

```sh
gradle :app:assembleDebug
```

The current native slice covers identity setup, file-code transfer,
invitation-file preview and join, and shared-core device policy. The device
screen displays stored access states, can revoke a capability, and can cut off,
forget, or restore a device. These are local policy changes, not claims that a
peer was contacted or an active session ended. Spoken-code enrollment remains
unlinked. No Kotlin policy engine or browser fleet behavior is implied.

Navigation uses Jetpack's `NavHost`, with Android predictive back enabled. Back
gestures seek the destination transition before release; cancelling keeps the
current destination and its form state. Back returns to the previous task,
including Files or setup, rather than always jumping home. Recovery words and
capture protection remain active until the recovery destination is disposed
after a committed pop, not when a gesture merely starts.

`TunlionCore` is the app boundary. `MainActivity` and `AvailabilityService` use
one process-owned `NativeTunlionCore`, backed by the generated UniFFI
`CoreSession`. Blocking calls run off the UI thread. The previous CLI adapter
and its acceptance harness are quarantined under `android/legacy-cli/`, outside
every Gradle source set, and are not compiled or run. The app packages no CLI
executable and never starts a subprocess; the app workflow rejects an APK that
contains `libtunlion_cli.so` or an executable `assets/` payload.

The `Android app` workflow builds both `libtunlion_core.so` ABIs and generates
Kotlin bindings from the same checkout. JNA uses the Android AAR so native
dispatch is packaged. The APK, instrumentation APK, source head and SHA256
manifest are separate artifacts. Source-only edits do not constitute a build
or device verification; use the workflow or an approved leased Android worker.

- Identity setup uses core-owned `PendingIdentity`. Confirmation writes through
  `commitIdentity`; going back closes the pending object without saving. Existing
  preview config directories are reused without replacing or parsing keys.
- Availability starts the native reduced receiver in a foreground service. It
  does not grant terminal or folder authority. Off waits for the native join.
- One native engine slot exists. Turn availability off before code transfers.
  Code sends allocate with `createCode`, show the actual code, then `waitSend`
  checks receiver acknowledgments. Code receive uses `receiveCode`.
- File selection uses SAF document URIs, stages only the selected files in
  private cache, and keeps staging until the blocking sender returns.
  Cancellation requests native stop independently of the blocked caller, holding
  the operation lease until cleanup. No resume after process death is promised.
- Verified core receive history drives publication into `Download/Tunlion` via
  MediaStore on Android 10+; Android 8/9 uses a user-selected SAF folder. Private
  originals are kept on publication failure and publication retries on refresh.
  The integrated core persists a bounded receiver completion journal, so a
  verified receipt and its public copy are separate, checkable facts. No
  directory scan is substituted for verification evidence.
- Identity state is explicit: not read yet, blank, local owner identity, or joined
  through stored device records without a local owner fingerprint. A blank phone
  is offered setup or join, never a fabricated identity or device list.
- Pairing is carrier-first. The spoken code and invitation file are carrier
  facts, not relationship facts; the relationship choices are labelled intent
  only. Temporary worker stays disabled for a spoken code and is invitation
  file only. An invitation file is read once into memory and handed to the
  core's `previewInvitation`; the screen shows only the core's preview fields
  and offers Join only when the preview succeeded and the core's `expired` flag
  is false. Join passes the same bytes to `joinInvitation`. Spoken-code
  enrollment is still not linked.
- The device list is projected from core `devices()`, not from Kotlin policy or
  CLI output. It shows the stored relationship (paired, fleet, temporary,
  unknown) and every returned action state (effective, pending, blocked,
  unsupported, unknown), keyed by the core `ActionKind` enum rather than a
  display string, including expiry and local revocation. Presence stays
  unknown unless the core reports `Live`; the snapshot does not probe peers. A
  stored relationship or recorded grant is never shown as proof that a remote
  action currently works.
- Sending to a stored device is offered as an explicit attempt only when the
  core reports outbound authorization as unknown. The result screen reports the
  receiver's per-file delivery acknowledgment from `SendResult`; an attempt
  that was not acknowledged is never shown as delivered.
- Capability revocation and device cut-off, forget, and restore use shared-core
  operations and typed receipts. They update this phone's policy only; the app
  does not claim that the peer was contacted or an existing session ended.
  Capability grants and active-session termination are not exposed in the device
  UI. Spoken-code enrollment remains unlinked, and the client does not mint
  relationship or permission authority.
- Discovery, expiry enforcement beyond stored facts, and recovery import still
  need core APIs. No successful stub or inferred remote permission is used.
  Offline and route facts remain unknown.

## Client parity

Android is an adapter over the shared core, not a second fleet model. It
projects core identity, device policy, and transfer receipts; invitation-file
preview/join, capability revocation, and device removal call shared-core APIs.
It does not evaluate access or claim remote effects. Spoken-code enrollment,
capability granting in the device UI, active-session termination, and
browser/WASM parity remain outside this client slice and are not reimplemented
in Kotlin.

## Native acceptance

`NativeCoreAcceptanceTest` checks real native identity confirmation, mismatch
rejection without writes, duplicate identity refusal and malformed-code refusal.
`NativeAdapterAcceptanceTest` drives a real desktop sender through the app
adapter, verifies the published bytes against the sender's SHA-256, and checks
the typed `devices()` projection without exporting pair secrets.
`DeviceAuthorityUiTest` checks the relationship and action-state UI contract,
including that an unknown remote send permission permits only an explicit
attempt and that forget and cut-off require confirmation and show core receipts.
`DevicePolicyFfiTest` checks native policy mapping, ceiling refusal, and the
local-only receipts for forget, cut-off, and restore.
`NativePeerAcceptanceTest` requires a real sender plus `code`, `sha256`, `bytes`
instrumentation arguments and verifies exact stored bytes against the digest.
These tests must run on a leased worker or CI. `CliAndroidAcceptanceTest` is
quarantined under `android/legacy-cli/` and is not evidence for the native
adapter.

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
