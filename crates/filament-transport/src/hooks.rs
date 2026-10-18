//! Shared process diagnostics and descriptive machine probes only.
//! First-installed sinks are shared across engines, not isolated log routing.
//! Configuration and discovery state belong to `TransportContext`; no probe
//! here may consult configuration to make membership/eligibility decisions.

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

/// A must-see line (printed even under `-q`). Default: discard, for the same
/// reason as `say`: a library has no terminal, and a caller that wants the
/// line installs a sink.
static CRITICAL: OnceLock<LogFn> = OnceLock::new();
pub fn set_critical(f: LogFn) {
    let _ = CRITICAL.set(f);
}
pub fn critical(msg: &str) {
    if let Some(f) = CRITICAL.get() {
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
