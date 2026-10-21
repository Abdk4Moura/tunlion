# tunlion-core: a library any process can call

Status: the receive engine is linked. `CoreSession.start`, `stop`,
`receive_code`, `create_code`, `wait_send`, `send_by_code` and
`send_to_device` exist. Receive runs the real shared `recv::dispatch::drive`;
send runs the library sender engine over the same `Conn`, `Session`, SPAKE2
ceremony, `filament-proto` controls and shared `stream_one` byte loop. The CLI
is one process adapter, not the owner of the dispatch body. The reduced host
serves the transfer path and refuses absent desktop endpoints by name.

This is **not** yet a complete FFI product. Pairing create/join, remember, a
directory/stdin send, fleet rendezvous, resume-after-link-loss, and the
app-facing receive/incoming-transfer stream still do not exist. `create_code`
allocates a real transfer code for a one-shot file send; it is not a pairing
code. `start` can serve an already-paired config directory; it cannot make one.

Android is why this crate exists now. It is not the owner of the API. Kotlin
is one binding. A Rust caller, a desktop embedding, or a later language
binding uses the same `Core`. Do not put Android types in this crate. Config
is a directory the caller passes in. On a phone that directory happens to be
`Context.filesDir/tunlion`. On anything else it is whatever directory the
caller owns.

The Kotlin app (Luna) codes against this contract. The app does not spawn the
`tunlion` binary. The CLI Android build stays as proof the protocol compiles
for the NDK. It is not the core.

## What the library is

One Rust type, `Core`, opened on an explicit config directory. On Android that
directory is `Context.filesDir/tunlion`. The library does not read
`TUNLION_CONFIG_DIR`. Keys never leave that directory.

Binding: UniFFI. Crate type `cdylib` plus `rlib`, packaged as
`jniLibs/<abi>/libtunlion_core.so` for `arm64-v8a` and `x86_64`. Not a
hand-written JNI layer.

The Kotlin bindings are generated, not written by hand and not committed. CI
produces them as the `tunlion-core-kotlin` artifact, from the same `.so` the app
links, so the bindings and the symbols cannot drift:

```
cd crates/tunlion-core
cargo run --features cli --bin uniffi-bindgen -- \
  generate --library target/release/libtunlion_core.so \
  --language kotlin --out-dir kotlin
```

The repository **does** have a root workspace `Cargo.toml`. Bindgen still runs
from `crates/tunlion-core` because it shells out to `cargo metadata` and needs
that package's metadata, not the virtual workspace root.

`uniffi::setup_scaffolding!()` in `src/lib.rs` is what exports the surface.
`tunlion_core_abi_version` is a plain build proof and not part of the API. Do
not call it from the app.

Threading: the engine owns its runtime. Kotlin calls in and gets a result or a
callback. Tokio types do not cross the boundary. `start`, `stop` and
`receive_code` are synchronous; `receive_code` blocks for the whole transfer,
so call them off the UI thread.

Core settings come only from the explicit config directory, not
`TUNLION_CONFIG_DIR` or other `TUNLION_*` settings. The transport underneath
still inherits its existing process environment (for example `TUNLION_DIRECT`,
`TUNLION_L2`, `TUNLION_PUBLIC_IP` and timeout overrides); the library does not
scrub it.

Errors are the `CoreError` enum. The app does not parse CLI stderr. Exit-code
meanings in `cli/skills/tunlion/SKILL.md` stay the meaning when a call maps to
a verb. They are not the wire format of this crate.

## Calls that exist now

The names below are the Rust types. The generated Kotlin uses the object names
`CoreSession` and `PendingIdentity`, with the same methods. `CoreSession.open`
is the constructor.

`open(config_dir) -> Core` / `CoreSession.open(config_dir)`

Creates the directory if needed (mode `0700` on Unix, which includes Android).
Does not create an identity. Does not start an engine.

`begin_identity() -> UncommittedIdentity` / `PendingIdentity`

Mints a 12-word recovery phrase in memory. Writes nothing. Fails with
`AlreadyExists` if `identity.ed25519` is already in the config dir. The phrase
is shown once, from `phrase()`. The pending value holds the seed. Dropping it
without `commit_identity` leaves the disk unchanged.

`commit_identity(pending, confirmed_phrase) -> fingerprint`

Writes the key only if the confirmed phrase is the same 12 words. Word order
and a single space between words are what matter; extra whitespace is ignored.
A mismatch returns `PhraseMismatch`, writes nothing, and does NOT consume the
phrase: the caller may ask again. This is the confirm-then-commit order. Do not
commit first and delete on failure.

`fingerprint() -> Option<String>`

`Some` of the first 8 hex characters of the Ed25519 public key, from
`filament-id`. `None` if no identity file exists. Does not mint.

`status() -> Status`

`fingerprint` as above. `engine` is `NotLinked` until `start` installs an
engine. A missing identity is not an error. It is `fingerprint: None`.

`start() -> Result<(), CoreError>`

Rejects a missing identity, an unreadable `config`, or an explicitly empty
`server`; a missing `server` uses the compiled default. Takes the same-root
`up.lock` lease, claims the engine slot before any host/runtime work, starts the
real receive dispatch on the Core runtime and waits its readiness edge before
returning. It never spawns the `tunlion` binary. The reduced Core host refuses
PTY/exec/ssh/sync/mount/forward/warm/proxy/wireguard/sshd endpoints by name, and
composes only the default shadow transfer gate. Each start mints a fresh random
consent token; the daemon path accepts proven links, not a guessable token. The
Android profile does not enable the optional `fleet` feature.

`start` is bounded but can block: up to 30 seconds waiting readiness and then
up to 5 seconds trying to join a failed startup. If that cleanup times out,
`start` returns `CoreError::Stop` and retains the task and `up.lock`; the
status is `TimedOut` and a restart is refused until a later `stop` joins it.
It returns `Ok` only after the dispatch published readiness and was still alive
under the engine lock; a dispatch that publishes and immediately returns is
joined and reported as an error, never `Ok`.

`stop() -> Result<(), CoreError>`

Synchronous; cancels and joins the engine without carrying a Tokio runtime
across the FFI boundary. The reduced Core starts no stdin owner, so it has no
detached stdin to report. A dispatch that does not finish within the 5-second
bound is retained and reported as `TimedOut` / `CoreError::Stop`, never
`Stopped`.

`receive_code(code, dir, yes, timeout) -> ReceiveSummary`

Runs the real one-shot `recv::dispatch::drive` with `code: Some`,
`daemon: false`, `keep_open: false`, `output: None`, the same reduced
`CoreHost`/ports/identity/store as `start`, and the caller's `dir`. `yes`
accepts matching offers without a prompt; `timeout` is the seconds to wait for
a sender, matching the CLI's `--timeout`.

**This call blocks** until the transfer finishes, the timeout expires with
nothing received, the sender/refusal path ends, or `stop` cancels it. Call it
off the UI thread. No Tokio runtime crosses the boundary; the library owns its
runtime. A one-shot receive has transfer-completion semantics, so it does not
wait for the daemon readiness edge that `start` publishes.

The code must be a well-formed claim: words followed by a trailing 3-5 digit
nameplate (`brave-otter-ruby-3141`). Malformed input returns `Usage` before any
network work, and the code/words are never logged. `stop` / `stop_blocking`
cancels an in-flight receive and it returns `Cancelled`, never a fake empty
success. A deadline with nothing received returns `Unreachable`, the library
equivalent of the CLI's exit 6.

`ReceiveSummary` is small and stable:

```text
ReceiveSummary { stored: Vec<StoredFile>, refused: Vec<RefusedFile>, bytes: u64 }
StoredFile { name, stored_name, bytes, sha256: Option<String> }
RefusedFile { name, reason, message }
```

A file is in exactly one list. Files stored or refused before an error are
returned in the summary rather than silently dropped. Refusal reasons are the
existing transfer vocabulary (`no_space`, `declined`, `no_tty`, ...); the
library does not re-implement admission, consent, verification or the reduced
profile's refusals, and the CLI's process exit codes stay out of the FFI.

`receive_code` and `start` honor the persistent `relay` setting: `relay always`
uses relay-only ICE (both peers can be behind hard NAT), while the default
`auto` stays direct-first with relay fallback. The real CLI sender + Core relay
acceptance is `cli/tests/core-receive-relay-nat-gates.sh`.

`receive_code` takes the same-directory `up.lock` lease and releases it on
completion, refusal or error. It refuses with `EngineAlreadyRunning` when this
Core already owns an engine, and with `EngineLease` when another Core or CLI
daemon owns the root.

`create_code(paths, timeout) -> CreatedCode`

Starts a one-shot library sender for regular-file `paths` and returns a real,
claimable transfer code plus its remaining lifetime. It is not a random-words
helper: the engine connects to the configured signaling server, registers a v2
nameplate (`pair-create`), keeps the socket and room alive in this Core's engine
slot, and returns only after the server acknowledges the allocation. The files
are resolved and hashed first, so a bad local path fails without spending a
code. The code stays claimable until a receiver uses it, its TTL expires, or
`stop` cancels the engine. Call `wait_send` to collect the transfer and release
the same-root lease. This call is synchronous; it does network work but is
bounded (30s for the allocation), so call it off the UI thread.

`wait_send() -> SendResult`

Blocks until the code send started by `create_code` completes, fails, or `stop`
cancels it; joins the engine and releases the root lease. It returns the code,
its expiry, one `SentFile` per input with `name`, `stored_name`, `bytes`,
`sha256`, `delivered`, and the total stored bytes. `delivered` is true only for
the receiver's whole-file `delivery-ack` (or a file with no digest to verify).
A failure is typed (`Usage`, `Unreachable`, `Refused`, `Partial`, `Cancelled`,
`Engine`), never a fake success.

`send_by_code(paths, timeout) -> SendResult`

The blocking convenience form: allocate the code, wait for the transfer, return
the summary. Because the code is only returned at the end, an app that must show
it before the receiver claims should use `create_code` then `wait_send`.

`send_to_device(paths, device, timeout) -> SendResult`

The same one-shot engine for an already paired device petname. It subscribes to
that device's presence channel, proves the pair secret and the device identity,
then sends. Unknown names fail with `Usage` before any transfer; a device that
never appears fails with `Unreachable`. Fleet siblings, brokered rendezvous and
the CLI's interactive/`--remember` paths are not part of this API.

The shared send engine currently accepts **regular files** only. Directories,
stdin, and the CLI's tar spool are not exposed; they remain CLI concerns. The
timeout bounds the whole send call. There is no resume after a link loss in this
slice, and the engine uses the same direct-QUIC/WebRTC transports as the CLI.

`status().engine` is the slot state a UI polls: `NotLinked` (nothing started),
`Starting` (startup claimed the Core, or the dispatch is spawned and readiness
is pending), `Running`, `Stopping` (a stop is joining), `FinishedUnjoined` (the task returned
but its handle has not been joined, so its `Ok` / `Err` / panic is still owned
by `Core`), `Stopped` (confirmed join), `Failed` (the joined dispatch returned
an error or panicked), and `TimedOut` (a stop bound expired and the task is
retained). `Stopped` and `Failed` are only reported after a confirmed join; a
finished-but-unjoined task is `FinishedUnjoined`, never `Stopped`, and a
restart is refused with `EngineNotJoined` until `stop` joins it. `TimedOut` is
not `Stopped`, and a restart is refused while a retained task may still run.

`Core::drop` is a fallback, not a joined stop. It requests cancellation, drops
the `up.lock` and shuts the instance runtime down with `shutdown_background`
(non-blocking and safe inside an async context); tasks that have not observed
cancellation are abandoned. Reopening the same config directory immediately
after `drop` can therefore race that abandoned work. Callers that need the
dispatch epilogue call `stop` first.

Identity bytes are `filament-id`'s format: `filament-id-seed-v1\0` plus the
32-byte seed, written by `secret-write` (mode `0600` on Unix). Do not invent a
second file. Do not call `UserKey::generate`. That path writes a PKCS8 key and
no recovery phrase. The phone uses `PendingIdentity`.

## Calls that do not exist yet

These are the rest of issue #465. Do not stub them as success.

- pairing: create a pairing code, join a code, remember.
- directories, stdin, and send resume.
- an app-facing receive/incoming-transfer **stream**. `receive_code` is one
  blocking call with a final summary; there is no progress/event/callback
  surface, and `start` writes accepted files to the config directory's inbox
  rather than telling the app about them.
- shell bytes and resize, only toward a device that granted shell. The phone
  does not serve a shell (`openpty` on Android already refuses).

`up` on the CLI is `recv_cmd(..., daemon: true)`. There is no separate daemon
loop. The library `Engine` driver runs that function's dispatch, not a copy of
`send_cmd`. The send-side mechanics shared with the CLI (`send::stream`,
`send::ceremony`, `send::source`, `send::liveness`) live in
`filament-peerloop`; Core's one-shot sender composes them with `Conn`, `Session`
and the `filament-proto` controls. The CLI keeps argument parsing, interactive
choices and fleet brokering; it does not provide the library sender.

`Conn` now lives in `filament-peerloop::conn`; `cli/src/conn.rs` is only a
re-export shim. The library owns link state and adoption. The CLI still owns
argument parsing, terminal copy, the pidfile, service install, the control
socket, and `/etc` writes. `Core::start` now runs the library dispatch with the
reduced host; the remaining server/daemon handlers and the optional fleet
profile are listed in `docs/engine-driver.md`.
Lookups use the petname (`verified_name`), never the broadcast display name. A
signaling close is current only when it carries the live client id and the same
link generation.

## What a caller must not do

- Do not `Runtime.exec` the CLI and call that this library.
- Do not pass invitation material as a loggable string in an argument list.
  Pass bytes into the library call, once that call exists.
- Do not rename frozen `filament/` protocol literals.
- Do not treat `tunlion_core_abi_version` as an API.

## Future, not this crate's v1

Mesh VPN via `VpnService` and a tun fd for the userspace overlay. Kernel TUN
stays closed. Port-forward UI. Mount. The phone serving a shell. Android
Keystore behind `filament-id`'s `KeyStore` trait. Member-to-member links.
Browser device key. A public hub.
