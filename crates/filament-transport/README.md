# filament-transport

The transport ladder for [tunlion](https://github.com/Abdk4Moura/tunlion).

The ladder itself (the `Transport` trait, direct QUIC, WebRTC, relay failover)
still lives in the CLI. This crate holds the reusable transport core: signalling,
the direct-QUIC path, and the discovery helpers the CLI drives.

## Two kinds of host answer

**Configuration and discovery are per engine.** Construct one
`TransportContext` for an engine and clone it into that engine's sessions and
detached tasks:

```rust
use filament_transport::TransportContext;

let settings_root = config_root.clone();
let membership_root = config_root.clone();
let context = TransportContext::new(
    Some(config_root.join("signaling-dns.json")), // None disables persistence
    move |key, peer| my_settings_read(&settings_root, key, peer),
    move |peer| my_raw_membership(&membership_root, peer),
);
```

* `dns_cache_path` is the exact optional cache file. `None` means persistence is
  off; it never falls back to the current directory.
* The setting and membership callbacks are owned closures, so an embedding host
  can capture its own root, store or live-read view. They are never installed
  process-wide.
* The public-IP and peer-observed-IP caches live in the same context, so two
  engines in one process cannot overwrite each other's discovery.
* `TransportContext::default()` has no settings, no membership rules and no DNS
  persistence. It does not consult a legacy hook or the filesystem.

## Breaking change: correctness hooks removed

The old process-global setters `hooks::set_settings_get_str`,
`hooks::set_raw_membership` and `hooks::set_config_path` (and their getters) are
gone. Their silent first-install-wins behavior could not name a root or engine,
and the config-path fallback could read the working directory. Callers must pass
a `TransportContext` to the APIs listed below instead. The diagnostic setters
(`set_trace`, `set_debug`, `set_say`, `set_critical`) remain.

## Scope limit: CLI `HostServices` is still ambient

This change moves the transport's correctness reads. The CLI's existing
`HostServices` implementation still resolves several non-transport reads (for
example `settings_get_str` used by L2/bind paths) through the process config
root. That is a pre-existing seam, not changed here; full per-engine CLI host
isolation needs a separate host-wide migration.

Pass the context explicitly to `net::{fetch_config, fetch_auto_room,
http_get_json, connect_signaling, reconnect_signaling}` and
`direct::{gather_candidates, warm_public_ip, observed_public_ip, race_connect,
race_connect_labeled}`. `Conn` stores one and uses it for foreground and
spawned config/ICE work; `holepunch::connect` inherits the originating `Conn`
context.

**Diagnostics remain process-global for now.** `hooks::{set_trace, set_debug,
set_say, set_critical}` install first-wins sinks shared by every engine in the
process, and `ip_class`, `iface_for_ip`, `resolve_iface_name` are descriptive
probes. They are not configuration and are never consulted for membership or
eligibility decisions. Per-engine log routing is a separate follow-up.

MIT licensed.
