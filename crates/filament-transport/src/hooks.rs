//! Host hooks: the few things the transport genuinely cannot answer itself.
//!
//! A transport should not know where this machine keeps config files, how a user
//! configured membership, or how to draw a line on a terminal. It also cannot
//! enumerate local interfaces without shelling out, which is host business.
//!
//! Rather than reach for those, the crate asks. The CLI installs its answers once
//! at startup; anything not installed has a safe default, so a library consumer
//! that installs nothing still gets a working transport with no diagnostics.
//!
//! This is deliberately function pointers rather than a trait object threaded
//! through every call site: the hooks are process-global facts, and threading a
//! `&dyn Host` through 4,000 lines of connection code would be a far larger
//! change than the coupling it removes.

use std::sync::OnceLock;

/// Diagnostics. Default: discard.
pub type LogFn = fn(&str);
static TRACE: OnceLock<LogFn> = OnceLock::new();
static DEBUG: OnceLock<LogFn> = OnceLock::new();

pub fn set_trace(f: LogFn) {
    let _ = TRACE.set(f);
}
pub fn set_debug(f: LogFn) {
    let _ = DEBUG.set(f);
}
pub fn trace(msg: &str) {
    if let Some(f) = TRACE.get() {
        f(msg)
    }
}
pub fn debug(msg: &str) {
    if let Some(f) = DEBUG.get() {
        f(msg)
    }
}

/// A message meant for the person, not the log. Default: discard, because a
/// library has no terminal to write to and should not assume one.
static SAY: OnceLock<LogFn> = OnceLock::new();
pub fn set_say(f: LogFn) {
    let _ = SAY.set(f);
}
pub fn say(msg: &str) {
    if let Some(f) = SAY.get() {
        f(msg)
    }
}

/// Classify a remote IP (private, CGNAT, public, ...). Default: "?".
pub type IpClassFn = fn(std::net::IpAddr) -> String;
static IP_CLASS: OnceLock<IpClassFn> = OnceLock::new();
pub fn set_ip_class(f: IpClassFn) {
    let _ = IP_CLASS.set(f);
}
pub fn ip_class(ip: std::net::IpAddr) -> String {
    IP_CLASS.get().map(|f| f(ip)).unwrap_or_else(|| "?".into())
}

/// Which local interface owns this address, and is it a VPN? Default: unknown.
pub type IfaceForIpFn = fn(std::net::IpAddr) -> Option<(String, bool)>;
static IFACE_FOR_IP: OnceLock<IfaceForIpFn> = OnceLock::new();
pub fn set_iface_for_ip(f: IfaceForIpFn) {
    let _ = IFACE_FOR_IP.set(f);
}
pub fn iface_for_ip(ip: std::net::IpAddr) -> Option<(String, bool)> {
    IFACE_FOR_IP.get().and_then(|f| f(ip))
}

/// Interface name for a local address string. Enumerating interfaces means
/// shelling out on Linux, which is host business. Default: "?".
pub type ResolveIfaceFn = fn(&str) -> String;
static RESOLVE_IFACE: OnceLock<ResolveIfaceFn> = OnceLock::new();
pub fn set_resolve_iface_name(f: ResolveIfaceFn) {
    let _ = RESOLVE_IFACE.set(f);
}
pub fn resolve_iface_name(addr: &str) -> String {
    RESOLVE_IFACE.get().map(|f| f(addr)).unwrap_or_else(|| "?".into())
}

/// User configuration. Default: unset, i.e. every default applies.
pub type SettingsGetFn = fn(&str, Option<&str>) -> Option<String>;
static SETTINGS_GET: OnceLock<SettingsGetFn> = OnceLock::new();
pub fn set_settings_get_str(f: SettingsGetFn) {
    let _ = SETTINGS_GET.set(f);
}
pub fn settings_get_str(key: &str, peer: Option<&str>) -> Option<String> {
    SETTINGS_GET.get().and_then(|f| f(key, peer))
}

pub type MembershipFn = fn(Option<&str>) -> String;
static MEMBERSHIP: OnceLock<MembershipFn> = OnceLock::new();
pub fn set_raw_membership(f: MembershipFn) {
    let _ = MEMBERSHIP.set(f);
}
pub fn raw_membership(peer: Option<&str>) -> String {
    MEMBERSHIP.get().map(|f| f(peer)).unwrap_or_default()
}

/// Where a named config file lives. Default: the current directory, which is
/// only ever used by a consumer that installed no hook at all.
pub type ConfigPathFn = fn(&str) -> std::path::PathBuf;
static CONFIG_PATH: OnceLock<ConfigPathFn> = OnceLock::new();
pub fn set_config_path(f: ConfigPathFn) {
    let _ = CONFIG_PATH.set(f);
}
pub fn config_path(name: &str) -> std::path::PathBuf {
    CONFIG_PATH.get().map(|f| f(name)).unwrap_or_else(|| std::path::PathBuf::from(name))
}
