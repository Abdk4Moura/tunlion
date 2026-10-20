//! HOST INTERFACES: what the peer loop asks for instead of importing the CLI.
//!
//! `Conn` is the orchestration state every command's event loop manipulates. It reaches the host in exactly two ways: it renders lines to
//! a terminal, and it reads the machine's own facts (settings, devices.json, the
//! owner key, the rendezvous channel derivation, the relay policy, whether a
//! link is a proven fleet device, the capability store the gates read, the
//! consent queue, the capability store writes, the control socket, and the
//! daemon-status snapshots). This module is the seam: two traits the CLI
//! implements over its real functions, handed to `Conn` as `Arc<dyn ...>`
//! fields.
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
use std::path::{Path, PathBuf};
#[cfg(feature = "mesh")]
use std::sync::Arc;
use std::time::Duration;

use filament_cap::capability::{
    ActionCounts, BindingStrength, CapOutcome, GateDecision, PrincipalKind, ShadowCounts,
};
use filament_id::{DeviceCert, UserKey};
#[cfg(feature = "mesh")]
use filament_overlay::Identity;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::consent::{PendingRequest, RequestBar};
use crate::control::Req;
#[cfg(feature = "mesh")]
use crate::mesh::{L3Mode, MeshTunnel};

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
    /// INFO with the host's repeat folding: one line per distinct text per
    /// window, the copies counted. Hosts that do not fold just say it.
    fn say_folded(&self, line: &str) {
        self.say(line);
    }
    /// CRITICAL: must-see lines, printed even under `-q`.
    fn critical(&self, line: &str);
    /// Color a span with `tone`, or return it unchanged when color is off.
    fn paint(&self, tone: Tone, s: &str) -> String;
    /// The success glyph (unicode on a capable tty, an ASCII fallback else).
    fn glyph_ok(&self) -> &'static str;
    /// The failure glyph.
    fn glyph_err(&self) -> &'static str {
        "x"
    }
    /// The "to" arrow used in flow and route lines.
    fn glyph_arrow(&self) -> &'static str {
        "->"
    }
    /// The warning glyph.
    fn glyph_warn(&self) -> &'static str;
    /// Is `level` at or below the configured verbosity ceiling?
    fn enabled(&self, level: Level) -> bool;

    /// A warning with a title, an optional explanation and optional remedies.
    /// The default degrades to ordinary lines so a silent/library sink needs no
    /// new implementation; the terminal host overrides it with its boxed form.
    fn caution(&self, title: &str, body: Option<&str>, actions: &[String]) {
        self.say(title);
        if let Some(body) = body {
            self.say(body);
        }
        for action in actions {
            self.say(action);
        }
    }
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

/// Why a live session must end now, as the host decided it.
///
/// The peer loop runs the re-check on its own cadence, but only the host can
/// read the device store and the invitation deadline. The host supplies the
/// cause (which picks the line the loop prints) and the exact reason string
/// (which rides the close frame, so the initiator's exit code and remedy are
/// the same as a refusal at open).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveCut {
    pub cause: LiveCutCause,
    /// The invitation end in UTC seconds for an expiry, so a caller can build
    /// the re-invite frame without parsing the human reason back into a time.
    /// `None` for a revocation, or a host whose reason did not name one.
    pub expires_at: Option<u64>,
    pub reason: String,
}

/// The two decisions a live re-check can reach. The words differ because the
/// remedy differs: a revocation cannot be repaired by a grant, an expiry can.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiveCutCause {
    Revoked,
    Expired,
}

/// A local storage failure a receiver reports to the sender as a typed refusal
/// instead of going silent. The vocabulary is host-free: the host classifies
/// its own io errors into these words, and the peer loop only carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageFailure {
    NoSpace,
    NameTooLong,
    ReadOnly,
    Permission,
}

/// How to reach a peer with sshfs, as the host resolved it: managed key paths,
/// the bootstrap result and the optional L3 destination. The mount handler owns
/// the argv; this is only the machine's answer about where the peer is.
#[derive(Clone, Debug)]
pub struct MountTransport {
    pub login: String,
    pub host: String,
    pub rport: u16,
    pub key_path: PathBuf,
    pub known_hosts_path: PathBuf,
    /// `login@peer.mesh` when an L3 path is proven reachable; `None` falls back
    /// to the L2 ProxyCommand.
    pub direct_dest: Option<String>,
}

/// The non-terminal host facts `Conn` reads. Same rationale as [`LogSink`]: one
/// owned object per session, implemented by the CLI over its own modules.
///
/// `roster_snapshot_json` deliberately returns JSON TEXT, not a `serde_json`
/// `Value`, so this crate keeps no serde dependency and the returned blob's
/// ownership is unambiguous; the caller parses it exactly once.
///
/// The mesh and overlay-key methods exist only with the `mesh` Cargo feature
/// (enabled by default). Disabling it removes those ports and the mesh module,
/// not common identity, authorization or stream multiplexing.
///
/// The mesh, overlay-key, ssh-key and mount methods further down are host
/// effects an embedding host must opt into. Their inert defaults are honest,
/// not permissive: they REFUSE with a reason (or, where the question is a
/// yes/no, answer no) rather than pretend the feature exists. A host that
/// implements none of them still runs the receive loop; it serves no overlay,
/// installs no ssh key and restores no mount, and the loop says so.
#[async_trait::async_trait]
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
    /// This machine's config directory: the root every stored fact (settings,
    /// devices, grants, keys) lives under. The peer loop never joins a filename
    /// onto it; it only hands the resolved path to a caller that already owns
    /// the layout.
    fn config_dir(&self) -> PathBuf {
        PathBuf::new()
    }
    /// A `settings::get_str` lookup with no per-peer override: the configured
    /// value, or `None`.
    fn settings_get_str(&self, key: &str) -> Option<String>;
    /// The same lookup with an optional per-peer override, resolved exactly as
    /// the host's own settings reader resolves it.
    fn settings_get_str_for(&self, key: &str, peer: Option<&str>) -> Option<String> {
        match peer {
            None => self.settings_get_str(key),
            Some(_) => None,
        }
    }
    /// A `settings::get_bool` lookup with no per-peer override.
    fn settings_get_bool(&self, _key: &str) -> bool {
        false
    }
    /// The same boolean lookup with an optional per-peer override.
    fn settings_get_bool_for(&self, key: &str, peer: Option<&str>) -> bool {
        match peer {
            None => self.settings_get_bool(key),
            Some(_) => self.settings_get_bool(key),
        }
    }
    /// The owner user key, when this machine holds one. A joined device holds
    /// no user signing key, so this is `None` there.
    fn user_key(&self) -> Option<UserKey> {
        None
    }
    /// Create the receiving inbox, applying the host's own permissions policy
    /// (owner-only on unix). An existing directory is left as the user set it.
    fn create_inbox_dir(&self, _dir: &Path) -> std::io::Result<()> {
        Ok(())
    }
    /// The login name this process serves as, from the host's own account
    /// database rather than an environment variable.
    fn serving_user(&self) -> Option<String> {
        None
    }
    /// Bytes available to this user on the filesystem holding `dir`, or `None`
    /// when the host cannot say.
    fn free_space(&self, _dir: &Path) -> Option<u64> {
        None
    }
    /// Classify an io error as a typed storage failure, or `None`.
    fn storage_failure(&self, _e: &std::io::Error) -> Option<StorageFailure> {
        None
    }
    /// Create a private directory (owner-only on unix) for a receive inbox
    /// that was deleted while the daemon ran.
    fn create_private_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)
    }
    /// Publish a finalized receive: the `.part` already holds the bytes; the
    /// host applies the ordinary create mode through the handle before rename.
    fn publish_received_file(&self, _file: &std::fs::File) -> std::io::Result<()> {
        Ok(())
    }
    /// Extract an archive after a received file was stored, when the host's
    /// settings ask for it. `Err` is a rendered reason, never fatal to storage.
    fn extract_received_archive(
        &self,
        _path: &Path,
        _dir: &Path,
    ) -> std::result::Result<usize, String> {
        Err("auto-extract is not available on this host".to_string())
    }
    /// Append the receiver's structured transfer-history record.
    #[cfg(feature = "dispatch")]
    fn record_received_file(&self, _record: &crate::recv::files::ReceivedFileRecord) {}
    /// Append one line to the daemon's upload log, if it keeps one.
    #[cfg(feature = "dispatch")]
    fn append_receive_log(&self, _line: &str) {}
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
    /// This machine's short host label, as the mesh uses it for `<name>.mesh`.
    ///
    /// A host with no mesh endpoint may leave the empty default: the loop only
    /// asks once an overlay is up, and an empty label is a true "no name"
    /// rather than an invented one.
    #[cfg(feature = "mesh")]
    fn hostname(&self) -> String {
        String::new()
    }
    /// Load, and on first use create, this machine's overlay identity key.
    ///
    /// HOST-BOUND: the key is a file the host owns, and generating one is a
    /// write. A host that does not implement this REFUSES with a reason, so the
    /// loop disables the crypto overlay and says why instead of claiming an
    /// address it cannot prove. To get the overlay, implement this plus
    /// [`l3_start`](HostServices::l3_start).
    #[cfg(feature = "mesh")]
    fn overlay_identity(&self) -> Result<Identity, String> {
        Err("this host has no overlay key store".to_string())
    }
    /// This device's overlay public key, loading the identity as
    /// [`overlay_identity`](HostServices::overlay_identity) does.
    #[cfg(feature = "mesh")]
    fn overlay_pubkey(&self) -> Result<[u8; 32], String> {
        self.overlay_identity().map(|id| id.public_key_bytes())
    }
    /// Sign a device-possession proof with the overlay key.
    #[cfg(feature = "mesh")]
    fn overlay_sign_possession(&self, msg: &[u8]) -> Result<[u8; 64], String> {
        self.overlay_identity().map(|id| id.sign(msg))
    }
    /// Start the mesh packet endpoint on `cidr` with this device's identity.
    ///
    /// HOST-BOUND: this creates a TUN device or a userspace netstack, which the
    /// library cannot do (and an Android embedder would supply through
    /// `VpnService`). A host that does not implement it REFUSES with a reason;
    /// the receive loop then serves with no overlay (`L3 disabled: ...`) rather
    /// than pretending a route exists. Implementing this and
    /// [`hostname`](HostServices::hostname) is what turns the feature on.
    #[cfg(feature = "mesh")]
    fn l3_start(
        &self,
        _cidr: &str,
        _mtu: u32,
        _identity: Option<Identity>,
        _mode: L3Mode,
    ) -> Result<Arc<dyn MeshTunnel>, String> {
        Err("this host has no mesh overlay endpoint".to_string())
    }
    /// The public host keys this machine's sshd offers a bootstrap peer.
    ///
    /// HOST-BOUND: they are this machine's own key files. The inert answer is
    /// empty, which is a true "I have no host keys to vouch for", never a
    /// fabricated list.
    fn ssh_host_pubkeys(&self) -> Vec<String> {
        Vec::new()
    }
    /// Install the tunlion-managed block for `device` in this user's
    /// authorized_keys.
    ///
    /// HOST-BOUND: it writes `$HOME/.ssh`. A host that does not implement it
    /// REFUSES, and the receiving loop sends the peer an install-failed refusal
    /// instead of an ack.
    fn install_authorized_key(&self, _device: &str, _pubkey: &str) -> Result<(), String> {
        Err("this host does not manage ssh authorized_keys".to_string())
    }
    /// Restore the auto-restore mounts this host recorded.
    ///
    /// HOST-BOUND: each mount is a FUSE/WinFsp device the host creates. A host
    /// with no mount support REFUSES, and the receive loop logs the warning it
    /// already logged on a restore failure, rather than reporting zero restored.
    async fn restore_mounts(&self, _server: &str, _relay: bool) -> Result<(), String> {
        Err("this host does not support mounts".to_string())
    }
    /// Is `local` a live mount point?
    ///
    /// HOST-BOUND: it reads the host's mount table. A host that cannot mount
    /// answers `false`; that is a true "no mount of mine is live here", not a
    /// claim that the path is useless.
    fn is_mount_point(&self, _local: &str) -> bool {
        false
    }
    /// Remove `local` from this host's mount table.
    ///
    /// HOST-BOUND. A host with no mount support REFUSES; the receive loop
    /// already ignores this result while reaping a dead tracked mount.
    fn remove_mount(&self, _local: &str) -> Result<(), String> {
        Err("this host does not support mounts".to_string())
    }
    /// Resolve everything sshfs needs to reach `peer` (managed key, pinned host
    /// key, bootstrap/cache, optional L3 destination).
    ///
    /// HOST-BOUND: this establishes/uses a peer link and reads the key store.
    /// A host without ssh-bootstrap REFUSES; the mount handler reports the
    /// bootstrap failure and spawns nothing.
    async fn prepare_mount_transport(
        &self,
        _server: &str,
        _peer: &str,
        _relay: bool,
        _port: u16,
    ) -> Result<MountTransport, String> {
        Err("this host cannot bootstrap an ssh transport".to_string())
    }
    /// This process's executable path, used to build the L2 ProxyCommand.
    fn current_exe(&self) -> PathBuf {
        std::env::current_exe().unwrap_or_default()
    }
    /// Atomic, owner-only write of a private file (temp + rename where the host
    /// supports it). Defaults to a plain write for embedders; the CLI uses its
    /// `SecretFile`.
    fn write_private_file(&self, path: &Path, data: &[u8]) -> std::io::Result<()> {
        std::fs::write(path, data)
    }
    /// The legacy `capExpires.<capability>` deadline for a device record, if
    /// any. Used by the ssh-certificate validity clamp.
    fn device_cap_expiry(&self, _name: &str, _capability: &str) -> Option<u64> {
        None
    }
    /// Is this device public key present in the device store? The settle-hold
    /// decision needs it to know whether a proof could ever bind.
    fn device_known(&self, _device_pub: &[u8; 32]) -> bool {
        false
    }
    /// Seed the owner's self genesis capability header and its ratchet when
    /// this machine has an owner key and the store lacks them. A store WRITE,
    /// so it belongs here; returns whether anything was written.
    fn ensure_self_genesis_header(&self, _user_key: &UserKey) -> bool {
        false
    }
    /// The capability store this host holds, already parsed: the `caps.json`
    /// array exactly as its loader returns it (empty when the file is missing
    /// or unreadable). The peer loop never joins a path or opens the file; it
    /// hands this slice to `filament-cap`'s pure evaluators.
    fn cap_store(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
    /// Is capability enforcement authoritative (live-gating) rather than the
    /// legacy shadow mode? The host owns the switch and its default.
    fn cap_authoritative(&self) -> bool {
        false
    }
    /// This process's shadow gate counters, as `cap-status` reports them.
    fn cap_shadow_counts(&self) -> ShadowCounts {
        ShadowCounts::default()
    }
    /// This process's per-action shadow gate counters, sorted by action.
    fn cap_action_counts(&self) -> Vec<ActionCounts> {
        Vec::new()
    }
    /// Record one gate evaluation (counters, shadow diagnostics, the mode
    /// switch) and return the effective decision. The host owns the policy
    /// site: its counters live in its process and its diagnostics go to its
    /// log, so the peer loop asks for the verdict instead of re-deriving it.
    /// An inert host has no policy site and fails closed.
    fn cap_gate_effective(&self, _gate: CapGate<'_>) -> GateDecision {
        GateDecision::Deny { cap_reason: None }
    }
    /// Is this device's certificate revoked in the host's own store? Keyed by
    /// the resolved device key, never by a display name. An inert host records
    /// no revocations, so it answers no.
    fn cert_revoked_for(&self, _device_pub: Option<&[u8; 32]>) -> bool {
        false
    }
    /// The delegated access this host's device record grants, read fresh at the
    /// gate. `None` means the record is not a delegated principal, which is
    /// also the inert answer: a host with no device store has admitted no
    /// guest, so no guest deadline is being enforced.
    fn delegated_access_for(&self, _device_pub: &[u8; 32]) -> Option<DelegatedAccess> {
        None
    }
    /// Has the owner explicitly denied this capability to `name`? A revoke is a
    /// decision, so the gate reads it before any policy default. An inert host
    /// records no denies.
    fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
        false
    }
    /// Does this device's store record grant `capability` to `name`? An inert
    /// host records no devices, so it grants nothing.
    fn device_allows(&self, _name: &str, _capability: &str) -> bool {
        false
    }
    /// Is this device key present in the host's device store at all? Used by
    /// the settle-then-evaluate park: a key with no record can never become
    /// Proven and must not occupy hold budget.
    fn device_key_known(&self, _device_pub: &[u8; 32]) -> bool {
        false
    }
    /// How long an unproven shell-class open may be parked for proof.
    fn gate_settle_ms(&self) -> u64 {
        0
    }
    /// The re-invite that restores this device's original invitation, when the
    /// host's identity store knows it. A denial or expiry frame carries it.
    fn reinvite_for(&self, _device_pub: &[u8; 32]) -> Option<crate::refusal::Reinvite> {
        None
    }
    /// Does the persisted, owner-signed enrolment ceiling cover `action` for
    /// this device key? Read fresh, never cached; an inert host has no ceiling
    /// and so covers nothing.
    fn ceiling_covers_action(&self, _device_pub: Option<&[u8; 32]>, _action: &str) -> bool {
        false
    }
    /// Every pending consent request this host holds, parsed from its own
    /// store. A refused action from an identified peer lands here until the
    /// owner approves or denies it.
    ///
    /// An inert host has no consent queue, so it holds none: the loop answers
    /// "no requests" instead of inventing one.
    fn requests_load(&self) -> Vec<PendingRequest> {
        Vec::new()
    }
    /// Persist the consent queue, in the host's own format and location.
    ///
    /// An inert host has nowhere to write it. This is a no-op rather than an
    /// error because the caller's only recovery is a retry it cannot make; the
    /// absent store is already visible as an empty
    /// [`requests_load`](HostServices::requests_load).
    fn requests_save(&self, _requests: &[PendingRequest]) {}
    /// Apply the TTL and the device-store bar to `requests`, setting expired or
    /// withdrawn statuses and persisting the queue when anything changed.
    ///
    /// HOST-BOUND: the bar reads this machine's device store and its
    /// key-revocation list, and a change is a store write. An inert host has
    /// neither, so there is nothing to expire and nothing to persist.
    fn requests_expire(&self, _requests: &mut Vec<PendingRequest>) {}
    /// Why `peer` cannot be let in by an approval, when it cannot: revoked
    /// here, forgotten, or past its delegated access. `None` when it is barred
    /// by nothing.
    ///
    /// HOST-BOUND: it reads the device store and the key-revocation list. An
    /// inert host records no devices, so it answers `None`; an approval it
    /// cannot act on still fails explicitly at
    /// [`device_set_cap`](HostServices::device_set_cap).
    fn request_bar(&self, _peer: &str) -> Option<RequestBar> {
        None
    }
    /// Record one pending consent request for a refused open.
    ///
    /// The host owns the unverified/empty-name filter, the capability filter,
    /// the [`request_bar`](Self::request_bar) check, TTL expiry, dedup, bounded
    /// eviction, persistence and any notify hook. This is the missing WRITE
    /// side of the queue the library already reads; it is deliberately one
    /// method, not a sector-hooks trait. An inert host records nothing.
    fn enqueue_request_if_requestable(&self, _peer: &str, _capability: &str) {}
    /// Record a capability grant (`grant == true`) or revoke in this host's
    /// device store, bounded by `expires` when given.
    ///
    /// HOST-BOUND: a store write. A host with no device store REFUSES with a
    /// reason, so the loop rejects the approval instead of reporting a grant it
    /// did not record.
    fn device_set_cap(
        &self,
        _name: &str,
        _capability: &str,
        _grant: bool,
        _expires: Option<u64>,
    ) -> Result<(), String> {
        Err("this host has no device store to record a grant in".to_string())
    }
    /// Issue the owner-signed bounded grant for `device`, returning whether one
    /// was written. An uncertified device or a host with no owner key writes
    /// nothing and returns `Ok(false)` in the CLI, which is why the result is
    /// not merely success.
    ///
    /// HOST-BOUND: it signs with this machine's owner key and appends to the
    /// capability store. A host with neither REFUSES with a reason.
    fn issue_signed_bounded_grant(
        &self,
        _device: &str,
        _capability: &str,
        _expires: u64,
    ) -> Result<bool, String> {
        Err("this host has no owner-signed grant store".to_string())
    }
    /// The local control socket's path, when this host serves one.
    ///
    /// HOST-BOUND: the path is derived from the host's config directory (and
    /// may be shortened for the kernel's socket-path limit). A host that serves
    /// no control socket answers `None` rather than naming a path it will never
    /// bind.
    fn control_sock_path(&self) -> Option<PathBuf> {
        None
    }
    /// Bind this host's control socket and forward each parsed request to `tx`,
    /// firing `ready` once the listener is accepting.
    ///
    /// HOST-BOUND: the library carries no Unix-socket server. A host that does
    /// not implement it REFUSES, and the daemon refuses to call itself up
    /// instead of starting a daemon no sibling command can reach.
    async fn serve_control(
        &self,
        _tx: mpsc::UnboundedSender<Req>,
        _ready: Option<oneshot::Sender<()>>,
    ) -> Result<(), String> {
        Err("this host serves no control socket".to_string())
    }
    /// Open a local TCP stream on a peer's request (the L2 acceptor's dial).
    ///
    /// HOST-BOUND: this opens a socket on this machine, to a target the PEER
    /// named. The caller has already applied the loopback rule and the
    /// operator's per-device allowlist; this method is the capability itself,
    /// and the inert default REFUSES rather than silently granting a library
    /// consumer the ability to dial on a peer's behalf. The CLI's implementation
    /// is the same `TcpStream::connect` the acceptor always ran, so its ack and
    /// close traffic (including the dial error text) is unchanged.
    async fn connect_local_stream(
        &self,
        _host: &str,
        _port: u16,
    ) -> std::io::Result<tokio::net::TcpStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "this host does not open local sockets on a peer's request",
        ))
    }
    /// Why a live session must end now, if it must. `idev` is the peer's
    /// device key as this link resolved it; `None` (an unidentified peer, or a
    /// warm/initiator bridge that does not gate liveness) never cuts.
    ///
    /// An inert host has no device store and no invitation deadlines, so it has
    /// no opinion: silence is the honest answer, not a fabricated "still fine".
    fn live_session_cut(&self, _idev: Option<&[u8; 32]>) -> Option<LiveCut> {
        None
    }
    /// Is this peer's composed access deadline still ahead? `None` means the
    /// host cannot resolve the identity (no opinion); `Some(false)` ends a live
    /// session. Revocation has its own check in [`live_session_cut`](Self::live_session_cut).
    fn peer_liveness_alive(&self, _idev: Option<&[u8; 32]>) -> Option<bool> {
        None
    }
    /// The cadence a long-lived stream re-asks [`live_session_cut`](Self::live_session_cut).
    ///
    /// The CLI's value matches its PTY loop and its `TUNLION_REVOKE_RECHECK_MS`
    /// test knob; an inert host never cuts, so the default only sets a ticker.
    fn revoke_recheck_interval(&self) -> Duration {
        Duration::from_secs(5)
    }
    /// The `signaling` object of a daemon status reply: this host's live link
    /// to its signaling server.
    ///
    /// A host with no signaling link has nothing to report, so the inert answer
    /// is JSON null. That is an explicit "no fact", never a fabricated
    /// connected state.
    fn signaling_snapshot(&self) -> Value {
        Value::Null
    }
    /// Publish the current invocation's signaling health for observational
    /// callers (`status`/`doctor`). The loop owns the state; this is a cache.
    fn report_signaling(&self, _snapshot: Value) {}
    /// The `launch` object of a daemon status reply: how this host was started,
    /// in the effective form the host's own `up` comparison reads.
    ///
    /// HOST-BOUND: it reads this machine's environment and settings and names
    /// this device. A host with no launch posture reports JSON null rather than
    /// a made-up one.
    fn launch_report(
        &self,
        _server: &str,
        _dir: &Path,
        _relay: bool,
        _shell_user: Option<&str>,
        _no_proxy_fallback: bool,
    ) -> Value {
        Value::Null
    }
}

/// The delegated access a host's device record grants: the ceiling it was
/// admitted with and the one moment its access ends. The gate needs only these
/// two facts; the host composes the deadline from its own three clocks.
#[derive(Clone, Debug)]
pub struct DelegatedAccess {
    pub ceiling: Vec<String>,
    pub deadline: u64,
}

impl DelegatedAccess {
    /// Past the deadline the device has no access at all.
    pub fn expired(&self, now: u64) -> bool {
        now >= self.deadline
    }
}

/// One capability gate query, as the peer loop shapes it. A struct rather than
/// fifteen positional arguments, so the crate and the host cannot disagree
/// about ordering, and a new input is a named field at every call site.
pub struct CapGate<'a> {
    pub legacy_allowed: bool,
    pub outcome: &'a CapOutcome,
    pub action: &'a str,
    pub resource: &'a str,
    pub device_pub: Option<&'a [u8; 32]>,
    pub user_pub: Option<&'a [u8; 32]>,
    pub binding: BindingStrength,
    pub cert_expires: Option<u64>,
    pub auth_key_caps: Option<&'a [String]>,
    pub own_user_pub: Option<&'a [u8; 32]>,
    pub scoped_in_bounds: bool,
    pub has_explicit_grant: bool,
    pub cert_revoked: bool,
    pub denied: bool,
    pub ceiling_authorizes: bool,
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
/// permitted, no fleet. Pass it explicitly to opt into host-free behavior;
/// constructors never select it as a fallback.
#[derive(Clone, Copy, Default)]
pub struct NoHost;

#[async_trait::async_trait]
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
        assert_eq!(host.settings_get_str_for("k", Some("peer")), None);
        assert!(!host.settings_get_bool("k"));
        assert_eq!(host.config_dir(), std::path::PathBuf::new());
        assert!(host.user_key().is_none());
        assert_eq!(host.serving_user(), None);
        assert_eq!(host.free_space(std::path::Path::new(".")), None);
        assert!(host
            .storage_failure(&std::io::Error::from(std::io::ErrorKind::StorageFull))
            .is_none());
        assert!(host.devices_load().is_empty());
        assert!(!host.is_self_uid("me", Some("me-1")));
        assert!(!host.relay_forbidden());
        assert!(!host.fleet_rv_present());
        assert_eq!(host.roster_snapshot_json(), None);
        assert!(host.cap_store().is_empty());
        assert!(!host.cap_authoritative());
        assert_eq!(host.cap_shadow_counts().la_authorized, 0);
        assert!(host.cap_action_counts().is_empty());
        // The gate's store reads answer inertly: no revocation, no delegated
        // guest, no deny, no grant, no ceiling. None of them can turn a
        // refusal into an allow.
        assert!(!host.cert_revoked_for(Some(&[0u8; 32])));
        assert!(host.delegated_access_for(&[0u8; 32]).is_none());
        assert!(!host.device_capability_denied("alpha", "shell"));
        assert!(!host.device_allows("alpha", "shell"));
        assert!(!host.ceiling_covers_action(Some(&[0u8; 32]), "shell"));
        assert!(!host.ceiling_covers_action(None, "shell"));
    }

    #[tokio::test]
    async fn nohost_refuses_the_features_it_cannot_provide() {
        let host = NoHost;
        // Not permissive: every feature hook that could claim success refuses
        // with a reason a caller can print, and the yes/no questions answer no.
        assert!(host.ssh_host_pubkeys().is_empty());
        assert!(host
            .install_authorized_key("dev", "ssh-ed25519 AAAA")
            .is_err());
        assert!(!host.is_mount_point("/tmp/m"));
        assert!(host.remove_mount("/tmp/m").is_err());
        let restored = host.restore_mounts("srv", false).await;
        assert!(restored.is_err());
        // A peer-requested dial is a capability, not a default. An inert host
        // refuses it instead of opening a socket the peer named.
        assert!(host.connect_local_stream("127.0.0.1", 22).await.is_err());
        assert!(host.live_session_cut(Some(&[0u8; 32])).is_none());
        assert_eq!(host.revoke_recheck_interval(), Duration::from_secs(5));
    }

    #[cfg(feature = "mesh")]
    #[test]
    fn nohost_refuses_mesh_endpoints_and_overlay_keys() {
        let host = NoHost;
        assert_eq!(host.hostname(), "");
        assert!(host.overlay_identity().is_err());
        assert!(host.overlay_pubkey().is_err());
        assert!(host.overlay_sign_possession(b"m").is_err());
        assert!(host
            .l3_start("fd00::1/128", 1280, None, L3Mode::Auto)
            .is_err());
    }

    #[tokio::test]
    async fn nohost_has_no_consent_store_device_store_or_control_socket() {
        let host = NoHost;
        // A host with no consent store holds no requests and has nowhere to
        // persist one: the loop lists none rather than inventing a queue.
        assert!(host.requests_load().is_empty());
        host.requests_save(&[]);
        let mut requests = Vec::new();
        host.requests_expire(&mut requests);
        assert!(requests.is_empty());
        assert_eq!(host.request_bar("alpha"), None);
        // Device-store writes are refused with a reason, never reported as a
        // grant that was not recorded.
        let set = host.device_set_cap("alpha", "shell", true, Some(1));
        assert!(set.is_err(), "{set:?}");
        let signed = host.issue_signed_bounded_grant("alpha", "shell", 1);
        assert!(signed.is_err(), "{signed:?}");
        // No Unix-socket server and no path it would pretend to bind.
        assert_eq!(host.control_sock_path(), None);
        let (tx, _rx) = mpsc::unbounded_channel();
        assert!(host.serve_control(tx, None).await.is_err());
        // A status reply from a host with no signaling link and no launch
        // posture says so with null, not with a fabricated connected state.
        assert_eq!(host.signaling_snapshot(), Value::Null);
        assert_eq!(
            host.launch_report("s", Path::new("."), false, None, false),
            Value::Null
        );
    }
}
