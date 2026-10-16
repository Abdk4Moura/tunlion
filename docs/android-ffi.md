# tunlion-core: a library any process can call

Status: slice 1 of issue #465. The engine is not linked yet. `start` refuses,
by name, until it is.

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

Run it from inside the crate. The bindgen shells out to `cargo metadata`, and
this repo has no root manifest, so the repo root fails.

`uniffi::setup_scaffolding!()` in `src/lib.rs` is what exports the surface.
`tunlion_core_abi_version` is a plain build proof and not part of the API. Do
not call it from the app.

Threading: the engine will own its runtime. Kotlin calls in and gets a result
or a callback. Tokio types do not cross the boundary.

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

`fingerprint` as above. `engine` is `NotLinked` until the peer loop is in this
crate. A missing identity is not an error. It is `fingerprint: None`.

`start() -> Result<(), CoreError>`

Returns `EngineNotLinked`. It must not report the engine as up.

Identity bytes are `filament-id`'s format: `filament-id-seed-v1\0` plus the
32-byte seed, written by `secret-write` (mode `0600` on Unix). Do not invent a
second file. Do not call `UserKey::generate`. That path writes a PKCS8 key and
no recovery phrase. The phone uses `PendingIdentity`.

## Calls that do not exist yet

These are the rest of issue #465. Do not stub them as success.

- `stop`. Availability off will mean no engine thread and no notification.
  There is no child process to kill.
- create a code, join a code, remember.
- send to a device, send by code, receive, incoming transfer.
- shell bytes and resize, only toward a device that granted shell. The phone
  does not serve a shell (`openpty` on Android already refuses).

`up` on the CLI is `recv_cmd(..., daemon: true)`. There is no separate daemon
loop. Linking the engine means that function's driver, not a copy of
`send_cmd`. `send_cmd` stays in the CLI. The library will call
`filament-transfer` and `filament-proto` for the byte mechanics.

`Conn` lives in `cli/src/conn.rs`, not in `main.rs`. The library will own link
state and adoption. The CLI keeps argument parsing, terminal copy, the pidfile,
service install, the control socket, and `/etc` writes. Lookups use the
petname (`verified_name`), never the broadcast display name. A signaling close
is current only when it carries the live client id and the same link
generation.

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
