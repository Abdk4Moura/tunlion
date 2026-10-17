//! HOST INTERFACES: what the peer loop asks for instead of importing the CLI.
//!
//! `Conn` is the orchestration state every command's event loop manipulates. It reaches the host in exactly two ways: it renders lines to
//! a terminal, and it reads the machine's own facts (settings, devices.json, the
//! owner key, the rendezvous channel derivation, the relay policy, whether a
//! link is a proven fleet device). This module is the seam: two traits the CLI
//! implements over its real functions, handed to `Conn` as `Arc<dyn ...>` fields.
//!
//! Why traits rather than the process-global function pointers
//! `filament-transport::hooks` uses: those hooks are facts about the process
//! (where config lives, how a peer was named) that every transport call needs to
//! see, so threading a `&dyn Host` through 4,000 lines bought nothing. The peer
//! loop is different: it is ONE object, it is constructed per session, and the
//! whole point of this slice is to let a caller supply a different sink (a test
//! capture, a daemon journal, silence on a library consumer) per `Conn`. So the
//! interface is an owned trait object on the state, not a global.
//!
//! Nothing here has an opinion about how a peer was found, authenticated or
//! named, where files live, or how anything is rendered: the CLI answers those
//! from its own modules, and this crate never calls back into it.

use std::fmt;
use std::time::Duration;

use filament_cap::capability::PrincipalKind;
use filament_id::DeviceCert;

/// Terminal tone, mirroring `cli::ui::Tone`. The crate carries the WORD (which
/// role a span plays); the host decides what escapes, if any, that word means.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tone {
    /// The brand: the warm accent, bold. Commands to type, codes, headings.
    Brand,
    /// The same accent without the weight: progress fill, the active choice.
    Accent,
    Ok,
    Err,
    Warn,
    Dim,
    Bold,
}

/// Output verbosity level, mirroring `cli::ui::Level`. Lower = more important.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Critical = 0,
    Info = 1,
    Debug = 2,
    Trace = 3,
}

/// The terminal surface `Conn` uses. Every method mirrors the `cli::ui` function
/// of the same name, so the CLI adapter is a one-line pass-through and the
/// behavior is byte-identical. Formatting (`format!`) stays at the call site;
/// this trait only takes the finished `&str`.
pub trait LogSink: Send + Sync + 'static {
    /// DEBUG (`-v`): resilience internals.
    fn debug(&self, line: &str);
    /// TRACE (`-vv` / `TUNLION_LOG=trace`): ICE candidates, per-frame detail.
    fn trace(&self, line: &str);
    /// INFO (the default): the normal useful lines.
    fn say(&self, line: &str);
    /// CRITICAL: must-see lines, printed even under `-q`.
    fn critical(&self, line: &str);
    /// Color a span with `tone`, or return it unchanged when color is off.
    fn paint(&self, tone: Tone, s: &str) -> String;
    /// The success glyph (unicode on a capable tty, an ASCII fallback else).
    fn glyph_ok(&self) -> &'static str;
    /// The warning glyph.
    fn glyph_warn(&self) -> &'static str;
    /// Is `level` at or below the configured verbosity ceiling?
    fn enabled(&self, level: Level) -> bool;
}

/// A [`LogSink`] that discards everything and renders no color. The host-free
/// default: a library consumer that installs nothing gets silence, and a test
/// can assert pure logic without a terminal.
#[derive(Clone, Copy, Default)]
pub struct NoLog;

impl LogSink for NoLog {
    fn debug(&self, _line: &str) {}
    fn trace(&self, _line: &str) {}
    fn say(&self, _line: &str) {}
    fn critical(&self, _line: &str) {}
    fn paint(&self, _tone: Tone, s: &str) -> String {
        s.to_string()
    }
    fn glyph_ok(&self) -> &'static str {
        "ok"
    }
    fn glyph_warn(&self) -> &'static str {
        "!"
    }
    fn enabled(&self, _level: Level) -> bool {
        false
    }
}

/// A recording [`LogSink`] for tests: it keeps each line with the level it was
/// emitted at and colors nothing, so a test can assert exactly what `Conn`
/// decided to say (and at which verbosity) without touching stdout.
#[derive(Default)]
pub struct VecLog {
    lines: std::sync::Mutex<Vec<(Level, String)>>,
}

impl VecLog {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&self, level: Level, line: &str) {
        self.lines
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((level, line.to_string()));
    }

    /// Drain the recorded lines, leaving the sink empty again.
    pub fn take(&self) -> Vec<(Level, String)> {
        std::mem::take(&mut self.lines.lock().unwrap_or_else(|e| e.into_inner()))
    }
}

impl LogSink for VecLog {
    fn debug(&self, line: &str) {
        self.push(Level::Debug, line);
    }
    fn trace(&self, line: &str) {
        self.push(Level::Trace, line);
    }
    fn say(&self, line: &str) {
        self.push(Level::Info, line);
    }
    fn critical(&self, line: &str) {
        self.push(Level::Critical, line);
    }
    fn paint(&self, _tone: Tone, s: &str) -> String {
        s.to_string()
    }
    fn glyph_ok(&self) -> &'static str {
        "ok"
    }
    fn glyph_warn(&self) -> &'static str {
        "!"
    }
    fn enabled(&self, _level: Level) -> bool {
        true
    }
}

/// The non-terminal host facts `Conn` reads. Same rationale as [`LogSink`]: one
/// owned object per session, implemented by the CLI over its own modules.
///
/// `roster_snapshot_json` deliberately returns JSON TEXT, not a `serde_json`
/// `Value`, so this crate keeps no serde dependency and the returned blob's
/// ownership is unambiguous; the caller parses it exactly once.
pub trait HostServices: Send + Sync + 'static {
    /// The current unix time in seconds, from the host's clock.
    fn now_secs(&self) -> u64 {
        0
    }
    /// The stored device certificate for `name`, valid or not. The peer loop
    /// runs `verify` itself so the expiry rule stays in one place.
    fn device_cert_for(&self, _name: &str) -> Option<DeviceCert> {
        None
    }
    /// The persisted auth-key ceiling for `name`, when that record is a
    /// delegated (joined) device.
    fn principal_ceiling_for(&self, _name: &str) -> Option<Vec<String>> {
        None
    }
    /// The persisted principal record for a device certificate.
    fn persisted_principal_for_cert(&self, _cert: &DeviceCert) -> PersistedPrincipal {
        PersistedPrincipal::owner()
    }
    /// `min(cert_expiry, not_after, last_seen + max_offline)`. The CLI owns the
    /// three-clock composer; this trait only carries its answer.
    fn principal_deadline(
        &self,
        cert_expires: u64,
        _not_after: Option<u64>,
        _last_seen: Option<u64>,
        _max_offline: Option<u64>,
    ) -> u64 {
        cert_expires
    }
    /// A `settings::get_str` lookup with no per-peer override: the configured
    /// value, or `None`.
    fn settings_get_str(&self, key: &str) -> Option<String>;
    /// Every known device as `(petname, rendezvous secret)`.
    fn devices_load(&self) -> Vec<(String, String)>;
    /// Same install (our own daemon / another process of this device)?
    fn is_self_uid(&self, my_uid: &str, peer_uid: Option<&str>) -> bool;
    /// The reconnect window for an unannounced vanish (env-overridable).
    fn rejoin_unwarned(&self) -> Duration;
    /// The one-line honest relay banner.
    fn relay_banner(&self) -> String;
    /// The `--no-relay` hard direct-only promise.
    fn relay_forbidden(&self) -> bool;
    /// The rendezvous channel for a pair secret (frozen protocol derivation).
    fn channel_of(&self, secret: &str) -> String;
    /// The owner-signed roster blob, serialized, or `None` when this device has
    /// no owner key or minting fails.
    fn roster_snapshot_json(&self) -> Option<String>;
    /// Is there a fleet rendezvous value on this machine at all?
    fn fleet_rv_present(&self) -> bool;
}

/// The persisted principal record behind a device certificate: the kind plus
/// the three clocks `principal_deadline` composes. A plain struct rather than a
/// tuple so the crate and the host cannot disagree about ordering.
#[derive(Clone, Debug)]
pub struct PersistedPrincipal {
    pub kind: PrincipalKind,
    pub not_after: Option<u64>,
    pub max_offline: Option<u64>,
    pub last_seen: Option<u64>,
}

impl PersistedPrincipal {
    /// A missing or malformed record FAILS CLOSED as a ceiling-less delegated
    /// principal (denies everything), so a half-persisted record can never
    /// silently become an owner.
    pub fn owner() -> Self {
        Self {
            kind: PrincipalKind::OwnerDevice,
            not_after: None,
            max_offline: None,
            last_seen: None,
        }
    }
}

/// An inert [`HostServices`]: no settings, no devices, no owner key, relay
/// permitted, no fleet. The host-free default for a library consumer and a base
/// for tests that only care about one method.
#[derive(Clone, Copy, Default)]
pub struct NoHost;

impl HostServices for NoHost {
    fn settings_get_str(&self, _key: &str) -> Option<String> {
        None
    }
    fn devices_load(&self) -> Vec<(String, String)> {
        Vec::new()
    }
    fn is_self_uid(&self, _my_uid: &str, _peer_uid: Option<&str>) -> bool {
        false
    }
    fn rejoin_unwarned(&self) -> Duration {
        Duration::from_secs(25)
    }
    fn relay_banner(&self) -> String {
        String::new()
    }
    fn relay_forbidden(&self) -> bool {
        false
    }
    fn channel_of(&self, _secret: &str) -> String {
        String::new()
    }
    fn roster_snapshot_json(&self) -> Option<String> {
        None
    }
    fn fleet_rv_present(&self) -> bool {
        false
    }
}

/// One static colored status line for a peer: `✓ name  note`.
///
/// Lifted out of the CLI's `main.rs` (where it was `peer_entry`) so the roster
/// renderer in `Conn` can build the line from the injected [`LogSink`] without
/// importing a CLI helper. Byte-identical: the same three `paint` calls.
pub fn peer_entry(log: &dyn LogSink, name: &str, mark: &str, tone: Tone, note: &str) -> String {
    let mut s = format!("{} {}", log.paint(tone, mark), log.paint(Tone::Bold, name));
    if !note.is_empty() {
        s.push_str(&format!("  {}", log.paint(Tone::Dim, note)));
    }
    s
}

/// The pure predicate behind a link's `fleet_proven` flag: a same-owner fleet
/// device whose identity is Proven and whose local name came from that proven
/// key. Takes plain booleans so this crate needs no `filament-cap` dependency;
/// the CLI's `shell_gate::fleet_link_proven` is the enum-shaped wrapper over it,
/// so the rule is written once.
pub fn fleet_link_proven(
    is_fleet_device: bool,
    is_proven: bool,
    has_device_pub: bool,
    has_verified_name: bool,
) -> bool {
    is_fleet_device && is_proven && has_device_pub && has_verified_name
}

impl fmt::Debug for NoLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoLog")
    }
}

impl fmt::Debug for NoHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoHost")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nolog_discards_lines_and_renders_no_color() {
        let log = NoLog;
        log.debug("d");
        log.trace("t");
        log.say("s");
        log.critical("c");
        assert_eq!(log.paint(Tone::Warn, "x"), "x");
        assert_eq!(log.glyph_ok(), "ok");
        assert_eq!(log.glyph_warn(), "!");
        assert!(!log.enabled(Level::Critical));
    }

    #[test]
    fn veclog_records_each_line_with_its_level() {
        let log = VecLog::new();
        log.debug("a");
        log.trace("b");
        log.say("c");
        log.critical("d");
        assert_eq!(
            log.take(),
            vec![
                (Level::Debug, "a".to_string()),
                (Level::Trace, "b".to_string()),
                (Level::Info, "c".to_string()),
                (Level::Critical, "d".to_string()),
            ]
        );
        // take() drains.
        assert!(log.take().is_empty());
    }

    #[test]
    fn peer_entry_formats_mark_name_and_note() {
        let log = VecLog::new();
        assert_eq!(peer_entry(&log, "alpha", "ok", Tone::Ok, ""), "ok alpha");
        assert_eq!(
            peer_entry(&log, "alpha", "ok", Tone::Ok, "away"),
            "ok alpha  away"
        );
    }

    #[test]
    fn fleet_link_proven_is_a_conjunction() {
        assert!(fleet_link_proven(true, true, true, true));
        assert!(!fleet_link_proven(false, true, true, true));
        assert!(!fleet_link_proven(true, false, true, true));
        assert!(!fleet_link_proven(true, true, false, true));
        assert!(!fleet_link_proven(true, true, true, false));
    }

    #[test]
    fn nohost_is_inert_and_permissive() {
        let host = NoHost;
        assert_eq!(host.settings_get_str("k"), None);
        assert!(host.devices_load().is_empty());
        assert!(!host.is_self_uid("me", Some("me-1")));
        assert!(!host.relay_forbidden());
        assert!(!host.fleet_rv_present());
        assert_eq!(host.roster_snapshot_json(), None);
    }
}
