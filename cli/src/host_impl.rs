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

use filament_cap::capability::{ActionCounts, GateDecision, ShadowCounts};
use filament_peerloop::host::{
    CapGate, HostServices, Level, LogSink, PersistedPrincipal, StorageFailure, Tone,
};
#[cfg(l3)]
use filament_peerloop::mesh::MeshTunnel;

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
    fn say_folded(&self, line: &str) {
        crate::ui::say_folded(line);
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
    fn glyph_err(&self) -> &'static str {
        crate::ui::glyph_err()
    }
    fn glyph_arrow(&self) -> &'static str {
        crate::ui::glyph_arrow()
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

/// So `Conn::roster` (which now speaks `Tone`) keeps accepting `ui::Tone` from
/// the frozen command modules (`recv_cmd`, `send_cmd`) unchanged.
impl From<crate::ui::Tone> for Tone {
    fn from(tone: crate::ui::Tone) -> Self {
        match tone {
            crate::ui::Tone::Brand => Tone::Brand,
            crate::ui::Tone::Accent => Tone::Accent,
            crate::ui::Tone::Ok => Tone::Ok,
            crate::ui::Tone::Err => Tone::Err,
            crate::ui::Tone::Warn => Tone::Warn,
            crate::ui::Tone::Dim => Tone::Dim,
            crate::ui::Tone::Bold => Tone::Bold,
        }
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

#[async_trait::async_trait]
impl HostServices for CliHost {
    fn config_dir(&self) -> std::path::PathBuf {
        crate::settings::config_dir()
    }
    fn settings_get_str(&self, key: &str) -> Option<String> {
        crate::settings::get_str(key, None)
    }
    fn settings_get_str_for(&self, key: &str, peer: Option<&str>) -> Option<String> {
        crate::settings::get_str(key, peer)
    }
    fn settings_get_bool(&self, key: &str) -> bool {
        crate::settings::get_bool(key, None)
    }
    fn user_key(&self) -> Option<crate::identity::UserKey> {
        crate::identity::UserKey::load(&crate::platform::PlatformKeyStore)
            .ok()
            .flatten()
    }
    fn create_inbox_dir(&self, dir: &std::path::Path) -> std::io::Result<()> {
        crate::platform::create_inbox_dir(dir)
    }
    fn serving_user(&self) -> Option<String> {
        crate::platform::current_username()
    }
    fn free_space(&self, dir: &std::path::Path) -> Option<u64> {
        crate::platform::free_space(dir)
    }
    fn storage_failure(&self, e: &std::io::Error) -> Option<StorageFailure> {
        crate::platform::storage_failure(e)
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
    #[cfg(l3)]
    fn hostname(&self) -> String {
        crate::l3::hostname()
    }
    fn overlay_identity(&self) -> Result<filament_overlay::Identity, String> {
        crate::overlay::load_identity().map_err(|e| e.to_string())
    }
    fn overlay_pubkey(&self) -> Result<[u8; 32], String> {
        crate::overlay::overlay_pubkey_bytes().map_err(|e| e.to_string())
    }
    fn overlay_sign_possession(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        crate::overlay::overlay_sign_possession(msg).map_err(|e| e.to_string())
    }
    #[cfg(l3)]
    fn l3_start(
        &self,
        cidr: &str,
        mtu: u32,
        identity: Option<filament_overlay::Identity>,
        mode: filament_peerloop::mesh::L3Mode,
    ) -> Result<std::sync::Arc<dyn MeshTunnel>, String> {
        let mesh = crate::l3::L3::start(cidr, mtu, identity, mode).map_err(|e| e.to_string())?;
        Ok(mesh)
    }
    fn ssh_host_pubkeys(&self) -> Vec<String> {
        crate::sshkeys::host_pubkeys()
    }
    fn install_authorized_key(&self, device: &str, pubkey: &str) -> Result<(), String> {
        crate::sshkeys::install_authorized_key(device, pubkey).map_err(|e| e.to_string())
    }
    async fn restore_mounts(&self, server: &str, relay: bool) -> Result<(), String> {
        crate::mount::restore_mounts(server, relay)
            .await
            .map_err(|e| e.to_string())
    }
    fn is_mount_point(&self, local: &str) -> bool {
        crate::mount::is_mount_point(local)
    }
    fn remove_mount(&self, local: &str) -> Result<(), String> {
        crate::mount::remove_mount(local).map_err(|e| e.to_string())
    }
    fn ensure_self_genesis_header(&self, user_key: &crate::identity::UserKey) -> bool {
        crate::ensure_self_genesis_header(&self.config_dir(), user_key)
    }
    fn cap_store(&self) -> Vec<serde_json::Value> {
        crate::capability::load_cap_store(&self.config_dir())
    }
    fn cap_authoritative(&self) -> bool {
        crate::capability::cap_authoritative()
    }
    fn cap_shadow_counts(&self) -> ShadowCounts {
        crate::capability::cap_shadow_counts()
    }
    fn cap_action_counts(&self) -> Vec<ActionCounts> {
        crate::capability::cap_action_counts()
    }
    fn cap_gate_effective(&self, gate: CapGate<'_>) -> GateDecision {
        crate::capability::cap_gate_effective(
            gate.legacy_allowed,
            gate.outcome,
            gate.action,
            gate.resource,
            gate.device_pub,
            gate.user_pub,
            gate.binding,
            gate.cert_expires,
            gate.auth_key_caps,
            gate.own_user_pub,
            gate.scoped_in_bounds,
            gate.has_explicit_grant,
            gate.cert_revoked,
            gate.denied,
            gate.ceiling_authorizes,
        )
    }
    fn now_secs(&self) -> u64 {
        crate::identity::now_secs()
    }
    fn device_cert_for(&self, name: &str) -> Option<filament_id::DeviceCert> {
        crate::device_cert_for(name)
    }
    fn principal_ceiling_for(&self, name: &str) -> Option<Vec<String>> {
        crate::principal_ceiling_for(name)
    }
    fn persisted_principal_for_cert(
        &self,
        cert: &filament_id::DeviceCert,
    ) -> PersistedPrincipal {
        let (kind, not_after, max_offline, last_seen) =
            crate::persisted_principal_for_cert(cert);
        PersistedPrincipal {
            kind,
            not_after,
            max_offline,
            last_seen,
        }
    }
    fn principal_deadline(
        &self,
        cert_expires: u64,
        not_after: Option<u64>,
        last_seen: Option<u64>,
        max_offline: Option<u64>,
    ) -> u64 {
        crate::effective_principal_deadline(cert_expires, not_after, last_seen, max_offline).0
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
