# Android native core FFI contract

Status: v1 contract for `crates/tunlion-core` and `android/`. The Android app
uses the same Rust core as the CLI. It does not execute the CLI or implement a
second copy of the protocol.

## Binding and ownership

- Export one UniFFI object, `Core`, from a Rust crate built as a `cdylib` named
  `tunlion_core`. Package it as
  `jniLibs/<abi>/libtunlion_core.so` for `arm64-v8a` and `x86_64`.
- `Core.open(config_dir: String)` opens the app-private directory
  `Context.filesDir/tunlion`. It creates the directory if needed and rejects a
  non-directory or unusable path. Identity keys and all other private state are
  stored only below this directory. Do not accept a separate key path.
- The Rust object owns its runtime, worker threads, and cancellation state.
  Tokio types, Rust channels, file handles, and internal protocol types never
  cross FFI. Kotlin may call exported methods from the binder or main thread;
  methods either return a bounded local result or start work and report it
  through callbacks. No exported method may block waiting for a peer or a file
  transfer to finish.
- The Android foreground service owns the persistent notification. `Core`
  reports engine lifecycle and transfer events; it does not create Android
  notifications or retain an Android `Context`.
- All callback interfaces are UniFFI callback interfaces. Callbacks are
  delivered off the UI thread, are serialized per `Core`, and must not be used
  after `stop`. Kotlin unregisters listeners before releasing the object.

## Lifecycle and identity

The Kotlin-facing surface is:

```text
Core.open(config_dir) -> Core
Core.load_identity() -> IdentitySummary?
Core.create_identity() -> PendingIdentityView
Core.confirm_identity() -> IdentitySummary
Core.cancel_identity_setup()
Core.start(listener: CoreListener)
Core.stop()
Core.status() -> StatusSnapshot
```

`create_identity` uses `filament_id::PendingIdentity::generate`. It returns the
recovery phrase and fingerprint once in `PendingIdentityView`; a second call
while a setup is pending returns a typed error. The
phrase is not logged, persisted, or returned by status. The pending identity is
held only in memory until the caller has shown and confirmed the phrase.
`confirm_identity` commits that same pending identity through
`filament_id::PendingIdentity::commit` and `secret-write`; calling it without a
pending identity is a typed error. `cancel_identity_setup` drops the pending
secret without writing it. There is no API to replace an existing identity.
`load_identity` returns only the public fingerprint and display name, never key
material or a recovery phrase.

`start` is idempotent when already running. It starts the engine and returns
only after the engine has actually started. `stop` is idempotent; when it
returns, the engine is stopped, all engine-owned threads are joined, and no
callback from that run can arrive later. Stopping does not erase identity or
known devices. The Android service turns its notification on only after a
successful `start`, and turns it off after `stop`. Availability off means
`stop` has completed. Until the peer loop is linked, `start` returns the named
`EngineNotLinked` error; it must never report a running engine in that state.

The public data records use only UniFFI-supported primitives and records:

```text
IdentitySummary { fingerprint: String, device_name: String }
PendingIdentityView { fingerprint: String, recovery_phrase: String }
StatusSnapshot {
    device_name: String?,
    engine_running: Boolean,
    devices: List<DeviceStatus>
}
DeviceStatus {
    device_id: String,             // opaque stable identity; not a display name
    name: String,
    online: Boolean,
    route: Route?,                 // Direct or Relayed; null while offline/unknown
    plain_line: String,            // human-readable permissions on both sides
    grants_to_this_device: List<CapabilityGrant>,
    grants_to_peer: List<CapabilityGrant>
}
Route = Direct | Relayed
Capability = SendFiles | Shell
CapabilityGrant { capability: Capability, ends_unix_seconds: UInt64? }
```

`status` is a snapshot and never starts or wakes the engine. The app may poll it
every two seconds while foregrounded. A permission end time is an absolute Unix
timestamp in seconds; null means no known finite end. `plain_line` is display
text, not a machine-readable permission source. The app gates actions on
`grants_to_this_device`, never by parsing `plain_line`.

## Pairing and remembered devices

```text
Core.create_pairing_code(listener: PairingListener) -> OperationId
Core.join_pairing_code(code: String, remember: Boolean,
                       listener: OperationListener) -> OperationId
Core.join_invitation(invitation: Vec<UInt8>, remember: Boolean,
                     listener: OperationListener) -> OperationId
Core.set_remembered(device_id: String, remember: Boolean)
```

`create_pairing_code` starts the existing CLI-equivalent enrollment ceremony;
`PairingListener.on_code(code, expires_unix_seconds)` is called as soon as the
short code is ready; `on_completed` or `on_failed` ends the operation. Joining
with a code or invitation requires the caller to supply the exact user input.
Invitation bytes cross the FFI as bytes, never as argv, a
command string, or loggable text. The app owns QR encoding/decoding and passes
the decoded code or invitation bytes to the core. `remember` has the same
meaning as in the CLI and web app. `set_remembered` changes only this device's
local remembered-device state; it does not grant a permission on either side.

## Files and receive location

Long-running file work uses an opaque `OperationId` and `OperationListener`:

```text
Core.send_to(device_id: String, files: List<StagedFile>,
             listener: OperationListener) -> OperationId
Core.send_by_code(file: StagedFile, listener: OperationListener) -> OperationId
Core.receive_by_code(code: String, listener: OperationListener) -> OperationId
Core.cancel_operation(operation_id: OperationId)
Core.remove_private_file(path: String)
CoreListener.on_incoming_transfer(transfer: IncomingTransfer)
```

`OperationId` is an opaque UUID string. `StagedFile` is the record
`{ private_path: String, display_name: String }`; the path is app-private. The
Android layer stages content selected through the system picker into
private app storage before calling the core, and removes the staged copy after
the operation completes or is cancelled. The core reads from that path and
never interprets a content URI. Incoming file bytes are written by the core to
a temporary file in its private config directory. On verified completion,
`OperationListener.on_file_ready(file: PrivateFile)` gives Kotlin
`PrivateFile { private_path: String, display_name: String, size_bytes: UInt64,
verified: Boolean }`. Kotlin then publishes it to `Download/Tunlion` through
`MediaStore` and calls `Core.remove_private_file`; that method accepts only
paths under the core's private transfer directory. Do not request broad
storage permission.

`OperationListener` has typed methods `on_started(operation_id)`,
`on_progress(operation_id, completed_bytes, total_bytes: UInt64?)`,
`on_code_ready(operation_id, code, expires_unix_seconds)`,
`on_file_ready(operation_id, file)`, `on_completed(operation_id)`,
`on_failed(operation_id, error)`, and `on_cancelled(operation_id)`.
`PairingListener` has `on_code(operation_id, code, expires_unix_seconds)` and
the same terminal callbacks. `CoreListener` has `on_incoming_transfer(transfer)`
and `on_file_ready(file)` for automatic receiving while Available.
Callbacks are terminal exactly once per operation, except progress events. The
core verifies the transfer before reporting a file ready. `IncomingTransfer` is
`{ transfer_id: String, device_id: String, device_name: String,
display_name: String, size_bytes: UInt64 }`; it identifies an incoming transfer
from a paired device that the engine's trust policy will receive while
Available. Receiving a code is
explicit user intent; automatic receive while Available accepts only the
existing trust policy for known paired devices. The app provides the
`CoreListener` while started so those inbound transfers can be surfaced.

## Shell

```text
Core.open_shell(device_id: String, listener: ShellListener) -> ShellSession
ShellSession.write(data: Vec<UInt8>)
ShellSession.resize(columns: UInt16, rows: UInt16)
ShellSession.close()
ShellListener.on_output(data: Vec<UInt8>)
ShellListener.on_closed(exit_code: Int32?)
ShellListener.on_error(error: CoreError)
```

Opening a shell is allowed only when the peer has granted this phone shell
capability. Otherwise it fails with `Denied`. The phone does not expose a shell
server and the app has no method to grant shell access to itself. Terminal
input/output is byte-oriented; resizing uses terminal columns and rows. Kotlin
renders the terminal and owns its keyboard and reconnecting presentation.

## Errors

Every fallible API returns `Result<T, CoreError>` through UniFFI. Kotlin branches
on `kind`, never parses `message`. The enum mirrors the CLI exit-code meanings
where applicable:

```text
ErrorKind =
    Error                           // exit 1: other failure
  | Usage                           // exit 2: invalid input or local file problem
  | CorruptState                    // exit 2: corrupt state; preserve the file
  | UnknownDevice                   // exit 3
  | Denied                          // exit 4: peer, capability, or system refused
  | StillRelayed                    // exit 5: direct-route request timed out
  | Unreachable                     // exit 6
  | Network                         // exit 7: tunlion service unreachable
  | Partial                         // exit 8: partial transfer
  | NoIdentity                      // exit 9
  | AlreadyRunningDifferentSettings // exit 10
  | NotRunning                      // exit 11
  | LocalResource                   // exit 12
  | Interrupted                     // exit 130
  | Terminated                      // exit 143
  | EngineNotLinked                 // start before the peer loop is linked
  | FeatureNotLinked                // operation path not linked yet

CoreError { kind: ErrorKind, message: String }
```

`message` is safe user-facing context but is not a control-flow contract. Shell
remote exit status is reported by `ShellListener.on_closed`, not mapped to a
local `CoreError`. CLI-only pipe status 141 and `exec` passthrough statuses 126
and 127 do not apply to this API. Add new error kinds compatibly; never reuse a
kind for a different failure.

## Threading and ABI

- Add `crates/tunlion-core` as a workspace crate with `crate-type = ["cdylib",
  "rlib"]`. UniFFI is the sole binding layer; do not hand-write JNI.
- Build with the NDK for `aarch64-linux-android` and
  `x86_64-linux-android`; map these to Android ABIs `arm64-v8a` and `x86_64`.
  The Android workflow builds and uploads both native libraries without
  replacing the existing Android CLI binary workflow.
- Export a Kotlin `TunlionCore` interface that the UI and service depend on.
  Its first implementation delegates to the generated UniFFI bindings. This
  keeps presentation independent of future native binding changes without
  introducing a subprocess implementation.
- Rust owns a single runtime per `Core`. Short methods take a snapshot under
  synchronization and return. Long work is scheduled onto that runtime and
  reports via callbacks. `stop` cancels and joins all engine work; no runtime or
  Tokio handle is visible to Kotlin.
- Config directory keys are written through `secret-write` and the
  `filament-id::KeyStore` implementation. On Android, owner-only Unix file and
  directory modes are required. Add an explicit Android platform arm to
  `secret-write` if its current cfg selection does not apply there; never shell
  out to `icacls` on Android.

## Deliberate first-slice limits

The first library export may implement identity open/create/commit/load and
status while the peer loop is being extracted. `start` must then return
`EngineNotLinked`; it must not simulate availability. Pairing, file, receive,
and shell methods must return `FeatureNotLinked` until their real engine path is
connected. Do not fake success, spawn the CLI, or reimplement protocol behavior
in Kotlin. The app UI can be built against this contract while each native
operation becomes live.
