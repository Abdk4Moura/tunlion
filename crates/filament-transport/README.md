# filament-transport

Host hooks for [filament](https://github.com/Abdk4Moura/filament)'s transport
ladder.

The ladder itself (the `Transport` trait, direct QUIC, WebRTC, relay failover)
still lives in the CLI. This crate holds what was *blocking* it from leaving: the
handful of places connection code reached sideways into terminal output, user
settings, config paths, and interface enumeration.

Those files now call `hooks::` instead of `crate::ui` / `crate::doctor` /
`crate::settings` / `crate::platform` / `crate::interact`. With no CLI references
left in them, moving them here becomes a file move rather than a refactor — which
is the point. The transport is what the reliability story rests on, and a
half-verified transport is worse than a coupled one.

```rust
// The host installs its answers once at startup.
filament_transport::hooks::set_trace(|m| eprintln!("{m}"));
filament_transport::hooks::set_config_path(|n| my_config_dir().join(n));
```

Every hook has a safe default, so a consumer that installs nothing still gets a
working transport with diagnostics discarded.

Function pointers rather than a trait object, deliberately: these are
process-global facts, not per-connection policy, and threading a `&dyn Host`
through 4,000 lines of connection code would be a larger and riskier change than
the coupling it removes.

MIT licensed.
