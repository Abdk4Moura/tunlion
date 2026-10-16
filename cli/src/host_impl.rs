//! HOST GLUE: the CLI's answers to `filament-peerloop`'s host traits.
//!
//! `filament-peerloop::host` defines [`LogSink`] and [`HostServices`]; this
//! module implements them over the CLI's real functions, so a `Conn` built via
//! `Conn::for_command` behaves byte-for-byte as it did when it imported those
//! functions directly. The point of the indirection is that the peer-loop state
//! no longer names the CLI at all, which is what makes its later `git mv` into
//! the crate a move rather than a rewrite.
//!
//! Two helpers whose callers live in frozen modules (`recv_cmd`,
//! `renewal_lifecycle`) could not take a `&dyn` sink without editing those
//! modules, so they are DEFINED here and re-exported from `conn` under their old
//! names. That keeps every call site resolving unchanged.

use std::sync::Arc;
use std::time::Duration;

use filament_peerloop::host::{HostServices, Level, LogSink, Tone};

/// The terminal `ui` module, as a [`LogSink`].
pub(crate) struct CliLog;

impl LogSink for CliLog {
    fn debug(&self, line: &str) {
        crate::ui::debug(line);
    }
    fn trace(&self, line: &str) {
        crate::ui::trace(line);
    }
    fn say(&self, line: &str) {
        crate::ui::say(line);
    }
    fn critical(&self, line: &str) {
        crate::ui::critical(line);
    }
    fn paint(&self, tone: Tone, s: &str) -> String {
        crate::ui::paint(tone_to_ui(tone), s)
    }
    fn glyph_ok(&self) -> &'static str {
        crate::ui::glyph_ok()
    }
    fn glyph_warn(&self) -> &'static str {
        crate::ui::glyph_warn()
    }
    fn enabled(&self, level: Level) -> bool {
        crate::ui::enabled(level_to_ui(level))
    }
}

fn tone_to_ui(tone: Tone) -> crate::ui::Tone {
    match tone {
        Tone::Brand => crate::ui::Tone::Brand,
        Tone::Accent => crate::ui::Tone::Accent,
        Tone::Ok => crate::ui::Tone::Ok,
        Tone::Err => crate::ui::Tone::Err,
        Tone::Warn => crate::ui::Tone::Warn,
        Tone::Dim => crate::ui::Tone::Dim,
        Tone::Bold => crate::ui::Tone::Bold,
    }
}

fn level_to_ui(level: Level) -> crate::ui::Level {
    match level {
        Level::Critical => crate::ui::Level::Critical,
        Level::Info => crate::ui::Level::Info,
        Level::Debug => crate::ui::Level::Debug,
        Level::Trace => crate::ui::Level::Trace,
    }
}

/// The CLI's config/identity/filesystem facts, as [`HostServices`].
pub(crate) struct CliHost;

impl HostServices for CliHost {
    fn settings_get_str(&self, key: &str) -> Option<String> {
        crate::settings::get_str(key, None)
    }
    fn devices_load(&self) -> Vec<(String, String)> {
        crate::devices_load()
    }
    fn is_self_uid(&self, my_uid: &str, peer_uid: Option<&str>) -> bool {
        crate::is_self_uid(my_uid, peer_uid)
    }
    fn rejoin_unwarned(&self) -> Duration {
        crate::rejoin_unwarned()
    }
    fn relay_banner(&self) -> String {
        crate::relay_banner()
    }
    fn relay_forbidden(&self) -> bool {
        crate::relay_forbidden()
    }
    fn channel_of(&self, secret: &str) -> String {
        crate::channel_of(secret)
    }
    fn roster_snapshot_json(&self) -> Option<String> {
        let owner = crate::load_owner_key()?;
        let now = crate::identity::now_secs();
        let (blob, _changed) = crate::roster::mint_roster(&owner, now).ok()?;
        serde_json::to_string(&blob).ok()
    }
    fn fleet_rv_present(&self) -> bool {
        crate::fleet::rv().is_some()
    }
}

/// A fresh [`LogSink`] over the real terminal UI.
pub(crate) fn cli_log() -> Arc<dyn LogSink> {
    Arc::new(CliLog)
}

/// A fresh [`HostServices`] over the real CLI.
pub(crate) fn cli_host() -> Arc<dyn HostServices> {
    Arc::new(CliHost)
}

/// A peer's message needs a reply, but its link has no transport attached, so
/// it is dropped. Say so. The sender cannot tell a dropped message from a slow
/// one and waits out its own deadline: that is how the join hang looked from
/// the joiner's side, and one line here would have named it on the owner's.
/// Since the transports announce a link before reading it (net.rs
/// `announce_then_read`, direct.rs `UnreadTransport`), this is reachable only
/// for a link that went away between the frame being queued and handled.
///
/// Defined here (re-exported from `conn`) because its callers include frozen
/// modules; it renders through `ui` directly, which is exactly the host's job.
pub(crate) fn dropped_no_transport(pid: &str, what: &str) {
    crate::ui::say(&format!(
        "tunlion: {what} from {pid} dropped: its link has no transport attached, so nothing was sent back"
    ));
}

/// The owner public key that names this machine's resources.
///
/// Prefers the local user key (an owner device holds one), and falls back to the
/// `user_pub` inside this device's own certificate (a joined device does not).
/// Both are the SAME key: a device certificate is signed by the owner, and
/// carries the owner's public half. Using only the first is a bug that silently
/// disables capability resources on every fleet member.
///
/// Defined here (re-exported from `conn`) because its callers include frozen
/// modules; it reads the keystore and the config dir, which is host business.
pub(crate) fn owner_pub_for_resources() -> Option<[u8; 32]> {
    if let Ok(Some(k)) = crate::identity::UserKey::load(&crate::platform::PlatformKeyStore) {
        return Some(k.public_key_bytes());
    }
    let raw = std::fs::read_to_string(crate::local_device_cert_path()).ok()?;
    let record: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let cert = crate::identity::DeviceCert::from_json(&record["cert"])?;
    Some(cert.user_pub)
}
