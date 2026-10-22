//! The real host composition for a reduced Core engine.
//!
//! The identity/store/roster/depart facts are library implementations; this
//! module is the small host adapter around them. It does not copy a trust rule:
//! it forwards to `DeviceStore`, `IdentityService`, `EnrollmentService`,
//! `recv::roster` and `recv::membership`.
//!
//! A Core profile here serves the receive/transfer path and explicitly refuses
//! every absent server/daemon endpoint. Capability-gated shell/forward opens
//! deny by default because the capability policy site is not composed in this
//! profile; that is a refusal, never an allow.

use async_trait::async_trait;
use filament_cap::capability::{BindingStrength, GateDecision, CAP_TRANSFER};
use filament_id::{now_secs, DeviceCert, UserKey};
use filament_peerloop::conn::Conn;
use filament_peerloop::host::{
    CapGate, DelegatedAccess, HostServices, LiveCut, LiveCutCause, LogSink, PersistedPrincipal,
};
use filament_peerloop::l2::Mux;
use filament_peerloop::recv::enrollment::EnrollmentService;
#[cfg(feature = "fleet")]
use filament_peerloop::recv::fleet_rv::FleetService;
use filament_peerloop::recv::identity::IdentityService;
use filament_peerloop::recv::ports::{RawMode, RecvDaemon, RecvIdentity, RecvPrompt, RecvServers};
use filament_peerloop::recv::store::{
    effective_principal_deadline, DeviceStore, OverlayKey, PRINCIPAL_STATE_LAPSED,
    PRINCIPAL_STATE_REVOKED,
};
use filament_peerloop::recv::MeshTunnel;
use filament_peerloop::shell_gate::ShellPolicy;
use filament_transport::net::{Ev, Transport};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// The explicit settings a Core reads from its own config directory. No
/// `TUNLION_*` environment and no ambient path.
#[derive(Clone, Default)]
pub struct CoreSettings {
    values: HashMap<String, String>,
}

impl CoreSettings {
    pub fn load(root: &Path) -> std::io::Result<Self> {
        let raw = match std::fs::read_to_string(root.join("config")) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(error) => return Err(error),
        };
        let mut values = HashMap::new();
        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(2, char::is_whitespace);
            let key = parts.next().expect("a non-empty line has a key");
            // A bare key is an explicit empty value, not a missing setting.
            // That distinction is what lets `start` reject `server` instead of
            // silently substituting the production endpoint.
            let value = parts.next().map(str::trim).unwrap_or("");
            values.insert(key.to_string(), value.to_string());
        }
        Ok(Self { values })
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.values.get(key).cloned()
    }

    pub fn bool(&self, key: &str) -> bool {
        self.get(key)
            .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "yes" | "on"))
    }

    pub fn u64(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    /// The persistent relay policy. `always` forces relay-only ICE; the default
    /// `auto` and `never` keep a direct-first policy (the reducer still decides
    /// whether relay fallback is allowed).
    pub fn relay_only(&self) -> bool {
        self.get("relay")
            .is_some_and(|value| value.eq_ignore_ascii_case("always"))
    }

    /// The transport-facing setting read. `prefer` is stored as a JSON
    /// order/strategy object; the transport wants its `o` value.
    pub fn setting(&self, key: &str, _peer: Option<&str>) -> Option<String> {
        let raw = self.values.get(key)?;
        if key == "prefer" {
            if let Ok(v) = serde_json::from_str::<Value>(raw) {
                if let Some(value) = v["o"].as_str() {
                    return Some(value.to_string());
                }
            }
        }
        Some(raw.clone())
    }

    /// The raw membership/interfaces JSON the transport expects.
    pub fn membership(&self, _peer: Option<&str>) -> String {
        self.values.get("interfaces").cloned().unwrap_or_default()
    }
}

fn trusted_owner_pub(store: &DeviceStore, overlay: &OverlayKey) -> Option<[u8; 32]> {
    let local = overlay.public_key_bytes().ok();
    store.owner_pub_for_resources(local.as_ref())
}

fn delegated_access_for(store: &DeviceStore, device_pub: &[u8; 32]) -> Option<DelegatedAccess> {
    let record = store.devices_find_by_device_pub(device_pub)?;
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    let ceiling = record["principalCeiling"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let cert_expires = DeviceCert::from_json(&record["deviceCert"])
        .map(|c| c.expires)
        .unwrap_or(0);
    let (mut deadline, _) = effective_principal_deadline(
        cert_expires,
        Some(record["principalExpires"].as_u64().unwrap_or(0)),
        record["lastSeen"].as_u64(),
        record["principalMaxOffline"].as_u64(),
    );
    if record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED) {
        deadline = 0;
    } else if record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED) {
        let at = record["lapsedAt"].as_u64().unwrap_or(0);
        if at < deadline {
            deadline = at;
        }
    }
    Some(DelegatedAccess { ceiling, deadline })
}

fn ceiling_covers(store: &DeviceStore, device_pub: &[u8; 32], action: &str) -> bool {
    let Some(record) = store.devices_find_by_device_pub(device_pub) else {
        return false;
    };
    if record["principalKind"].as_str() != Some("delegated") {
        return false;
    }
    record["principalCeiling"].as_array().is_some_and(|items| {
        items
            .iter()
            .filter_map(|v| v.as_str())
            .any(|c| c.eq_ignore_ascii_case(action))
    })
}

/// The host facts for one Core instance.
#[derive(Clone)]
pub struct CoreHost {
    root: PathBuf,
    store: DeviceStore,
    settings: CoreSettings,
    overlay: OverlayKey,
}

impl CoreHost {
    pub fn new(
        root: PathBuf,
        store: DeviceStore,
        settings: CoreSettings,
        overlay: OverlayKey,
    ) -> Self {
        Self {
            root,
            store,
            settings,
            overlay,
        }
    }
}

#[async_trait]
impl HostServices for CoreHost {
    fn now_secs(&self) -> u64 {
        now_secs()
    }

    fn device_cert_for(&self, name: &str) -> Option<DeviceCert> {
        self.store.device_cert_for(name)
    }

    fn device_cert_for_key(&self, device_pub: &[u8; 32]) -> Option<DeviceCert> {
        self.store.devices_find_by_device_pub(device_pub)
            .and_then(|record| DeviceCert::from_json(&record["deviceCert"]))
    }

    fn owner_user_pub(&self) -> Option<[u8; 32]> {
        trusted_owner_pub(&self.store, &self.overlay)
    }

    fn device_known(&self, device_pub: &[u8; 32]) -> bool {
        self.store.devices_find_by_device_pub(device_pub).is_some()
    }

    fn principal_ceiling_for(&self, name: &str) -> Option<Vec<String>> {
        let record = self
            .store
            .devices_records()
            .into_iter()
            .find(|d| d["name"].as_str() == Some(name))?;
        if record["principalKind"].as_str() != Some("delegated") {
            return None;
        }
        Some(
            record["principalCeiling"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
        )
    }

    fn persisted_principal_for_cert(&self, cert: &DeviceCert) -> PersistedPrincipal {
        let owner = self.store.owner_pub_from_keystore();
        let (kind, not_after, max_offline, last_seen) = self
            .store
            .persisted_principal_for_cert(cert, owner.as_ref());
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
        effective_principal_deadline(cert_expires, not_after, last_seen, max_offline).0
    }

    fn config_dir(&self) -> PathBuf {
        self.root.clone()
    }

    fn settings_get_str(&self, key: &str) -> Option<String> {
        self.settings.setting(key, None)
    }

    fn settings_get_str_for(&self, key: &str, peer: Option<&str>) -> Option<String> {
        self.settings.setting(key, peer)
    }

    fn settings_get_bool(&self, key: &str) -> bool {
        self.settings.bool(key)
    }

    fn user_key(&self) -> Option<UserKey> {
        UserKey::load(&self.store.keystore()).ok().flatten()
    }

    fn create_inbox_dir(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)
    }

    fn devices_load(&self) -> Vec<(String, String)> {
        self.store.devices_load()
    }

    fn is_self_uid(&self, my_uid: &str, peer_uid: Option<&str>) -> bool {
        peer_uid == Some(my_uid)
    }

    fn rejoin_unwarned(&self) -> Duration {
        Duration::from_secs(25)
    }

    fn relay_banner(&self) -> String {
        "relay".to_string()
    }

    fn relay_forbidden(&self) -> bool {
        false
    }

    fn channel_of(&self, secret: &str) -> String {
        filament_peerloop::recv::store::channel_of(secret)
    }

    fn roster_snapshot_json(&self) -> Option<String> {
        let owner = self.user_key()?;
        let self_pub = self.overlay.public_key_bytes().ok();
        let ttl = self.settings.u64("roster.ttl").unwrap_or(15 * 60);
        let (blob, _) = filament_peerloop::recv::roster::mint_roster(
            &self.store,
            &owner,
            now_secs(),
            self_pub.as_ref(),
            ttl,
        )
        .ok()?;
        serde_json::to_string(&blob).ok()
    }

    fn fleet_rv_present(&self) -> bool {
        #[cfg(feature = "fleet")]
        {
            self.store.fleet_rv().is_some()
        }
        #[cfg(not(feature = "fleet"))]
        {
            false
        }
    }

    fn cap_store(&self) -> Vec<Value> {
        self.store.cap_store()
    }

    fn cap_authoritative(&self) -> bool {
        self.settings.bool("cap-authoritative")
    }

    fn cap_gate_effective(&self, gate: CapGate<'_>) -> GateDecision {
        // The reduced Core composes exactly one capability decision: the
        // default (shadow) transfer gate. It does not pretend to implement the
        // authoritative capability policy, and it never lets a shell/exec/
        // mount/forward open through a policy site that is not composed.
        if gate.action != CAP_TRANSFER {
            return GateDecision::Deny {
                cap_reason: Some(format!(
                    "{} opens are not served by this core profile",
                    gate.action
                )),
            };
        }
        if gate.cert_revoked {
            return GateDecision::Deny {
                cap_reason: Some("device revoked".to_string()),
            };
        }
        if gate.denied {
            return GateDecision::Deny {
                cap_reason: Some("explicitly denied by the owner".to_string()),
            };
        }
        if let Some(caps) = gate.auth_key_caps {
            if !caps
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(CAP_TRANSFER))
            {
                return GateDecision::Deny {
                    cap_reason: Some("delegated ceiling excludes transfer".to_string()),
                };
            }
            if let Some(expires) = gate.cert_expires {
                if now_secs() >= expires {
                    return GateDecision::Deny {
                        cap_reason: Some("delegated access has expired".to_string()),
                    };
                }
            }
        }
        if self.cap_authoritative() {
            return GateDecision::Deny {
                cap_reason: Some(
                    "authoritative capability policy is not composed in this core profile"
                        .to_string(),
                ),
            };
        }
        let same_owner = matches!(
            (gate.own_user_pub, gate.user_pub),
            (Some(own), Some(peer)) if own == peer && *peer != [0u8; 32]
        );
        let fleet_ok = same_owner
            && gate.scoped_in_bounds
            && gate.binding == BindingStrength::Proven
            && !gate.cert_revoked;
        if fleet_ok || gate.legacy_allowed {
            GateDecision::Allow
        } else {
            GateDecision::Deny {
                cap_reason: Some(
                    "transfer needs legacy consent or a proven same-owner fleet link".to_string(),
                ),
            }
        }
    }

    fn cert_revoked_for(&self, device_pub: Option<&[u8; 32]>) -> bool {
        device_pub
            .map(|p| self.store.device_cert_revoked(p))
            .unwrap_or(false)
    }

    fn delegated_access_for(&self, device_pub: &[u8; 32]) -> Option<DelegatedAccess> {
        delegated_access_for(&self.store, device_pub)
    }

    fn device_capability_denied(&self, _name: &str, _capability: &str) -> bool {
        false
    }

    fn device_allows(&self, _name: &str, _capability: &str) -> bool {
        false
    }

    fn ceiling_covers_action(&self, device_pub: Option<&[u8; 32]>, action: &str) -> bool {
        device_pub.is_some_and(|p| ceiling_covers(&self.store, p, action))
    }

    fn device_set_cap(
        &self,
        _name: &str,
        _capability: &str,
        _grant: bool,
        _expires: Option<u64>,
    ) -> Result<(), String> {
        Err("capability writes are not composed in this core profile".to_string())
    }

    fn issue_signed_bounded_grant(
        &self,
        _device: &str,
        _capability: &str,
        _expires: u64,
    ) -> Result<bool, String> {
        Err("capability writes are not composed in this core profile".to_string())
    }

    fn control_sock_path(&self) -> Option<PathBuf> {
        None
    }

    async fn serve_control(
        &self,
        _tx: mpsc::UnboundedSender<filament_peerloop::control::Req>,
        _ready: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Result<(), String> {
        Err("this core profile serves no control socket".to_string())
    }

    async fn connect_local_stream(
        &self,
        _host: &str,
        _port: u16,
    ) -> std::io::Result<tokio::net::TcpStream> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "this core profile does not open local sockets on a peer's request",
        ))
    }

    fn live_session_cut(&self, idev: Option<&[u8; 32]>) -> Option<LiveCut> {
        let idev = idev?;
        if self.store.device_cert_revoked(idev) {
            return Some(LiveCut {
                cause: LiveCutCause::Revoked,
                expires_at: None,
                reason: "device revoked".to_string(),
            });
        }
        delegated_access_for(&self.store, idev)
            .filter(|access| access.expired(now_secs()))
            .map(|access| LiveCut {
                cause: LiveCutCause::Expired,
                expires_at: Some(access.deadline),
                reason: filament_peerloop::refusal::expired_reason(access.deadline),
            })
    }

    fn revoke_recheck_interval(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn signaling_snapshot(&self) -> Value {
        Value::Null
    }

    fn report_signaling(&self, _snapshot: Value) {}

    fn launch_report(
        &self,
        _server: &str,
        _dir: &Path,
        _relay: bool,
        _shell_user: Option<&str>,
        _no_proxy_fallback: bool,
    ) -> Value {
        json!({
            "server": _server,
            "dir": _dir.display().to_string(),
            "relay": _relay,
        })
    }
}

/// The real `RecvIdentity` composition. All trust-bearing methods forward to
/// the library services. Fleet is composed only under the `fleet` feature; the
/// default Android/reduced profile refuses it by name.
pub struct CoreIdentity {
    store: DeviceStore,
    overlay: OverlayKey,
    identity: IdentityService,
    enrollment: EnrollmentService,
    #[cfg(feature = "fleet")]
    fleet: FleetService,
}

impl CoreIdentity {
    pub fn new(
        store: DeviceStore,
        overlay: OverlayKey,
        display_name: String,
        settle_ms: u64,
        log: Arc<dyn LogSink>,
    ) -> Self {
        let identity = IdentityService::new(
            store.clone(),
            overlay.clone(),
            display_name.clone(),
            settle_ms,
            log.clone(),
        );
        let enrollment =
            EnrollmentService::new(store.clone(), overlay.clone(), display_name.clone(), log);
        #[cfg(feature = "fleet")]
        let fleet = FleetService::new(
            store.clone(),
            overlay.clone(),
            store.root().join("overlay.announce-seq"),
            display_name.clone(),
            Vec::new(),
        );
        Self {
            store,
            overlay,
            identity,
            enrollment,
            #[cfg(feature = "fleet")]
            fleet,
        }
    }

    fn trusted_owner(&self) -> Option<[u8; 32]> {
        trusted_owner_pub(&self.store, &self.overlay)
    }
}

#[async_trait]
impl RecvIdentity for CoreIdentity {
    async fn issue_proven_challenge_and_hold(
        &self,
        conn: &Conn,
        pid: &str,
        t: &Arc<dyn Transport>,
        pending_proven: &Arc<std::sync::Mutex<HashMap<String, (Arc<dyn Transport>, Instant)>>>,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) {
        self.identity
            .issue_proven_challenge_and_hold(conn, pid, t, pending_proven, identity_nonces)
            .await
    }
    async fn respond_to_identity_challenge(&self, t: &Arc<dyn Transport>, v: &Value) {
        self.identity.respond_to_identity_challenge(t, v).await
    }
    fn handle_identity_expose(
        &self,
        conn: &mut Conn,
        pid: &str,
        v: &Value,
        identity_nonces: &mut HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        self.identity
            .handle_identity_expose(conn, pid, v, identity_nonces)
    }
    fn store_provisional_identity(&self, name: &str, cert: &DeviceCert) -> anyhow::Result<()> {
        self.identity.store().store_provisional_identity(name, cert)
    }
    fn load_provisional_identity(&self, name: &str) -> Option<DeviceCert> {
        self.identity.store().load_provisional_identity(name)
    }
    fn clear_provisional_identity(&self, name: &str) {
        self.identity.store().clear_provisional_identity(name)
    }
    fn local_device_cert(&self) -> Option<DeviceCert> {
        self.identity.local_device_cert()
    }
    async fn maybe_request_cert_renewal(&self, conn: &Conn, pid: &str) {
        self.identity.maybe_request_cert_renewal(conn, pid).await
    }
    async fn respond_to_cert_renew_request(&self, conn: &mut Conn, pid: String) {
        self.identity.respond_to_cert_renew_request(conn, pid).await
    }
    async fn handle_cert_renew_ack(&self, v: &Value) {
        self.identity.handle_cert_renew_ack(v).await
    }
    async fn respond_to_auth_key_enroll_request(&self, conn: &mut Conn, pid: String, v: Value) {
        self.enrollment
            .respond_to_auth_key_enroll_request(conn, pid, v)
            .await
    }
    async fn handle_auth_key_enroll_response(&self, conn: &mut Conn, pid: String, v: Value) {
        self.enrollment
            .handle_auth_key_enroll_response(conn, pid, v)
            .await
    }
    fn gate_settle_ms(&self) -> u64 {
        self.identity.gate_settle_ms()
    }
    fn hold_expired(&self, held: Instant) -> bool {
        held <= Instant::now()
    }
    async fn resend_identity_challenge(
        &self,
        conn: &Conn,
        pid: &str,
        identity_nonces: &HashMap<String, ([u8; 32], Instant, [u8; 32])>,
    ) -> bool {
        self.identity
            .resend_identity_challenge(conn, pid, identity_nonces)
            .await
    }
    fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        self.identity.device_name_for_pub(device_pub)
    }
    fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        self.identity.device_cert_revoked(device_pub)
    }
    fn owner_pub_for_resources(&self) -> Option<[u8; 32]> {
        self.identity.owner_pub_for_resources()
    }
    fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<filament_peerloop::refusal::Reinvite> {
        self.identity.reinvite_for(device_pub)
    }
    fn reinvite_refusal(
        &self,
        mut refusal: filament_peerloop::refusal::Refusal,
        device_pub: Option<&[u8; 32]>,
    ) -> filament_peerloop::refusal::Refusal {
        // Same rule as the CLI adapter: only an expiry carries a re-invite, and
        // only when the decision did not already name one.
        if refusal.code == filament_peerloop::refusal::Code::Expired && refusal.reinvite.is_none()
        {
            refusal.reinvite = device_pub.and_then(|d| self.identity.reinvite_for(d));
        }
        refusal
    }
    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        self.identity.enroll_channel(public_key)
    }
    fn is_armed(&self) -> bool {
        self.identity.is_armed()
    }
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        _owner_pub: &[u8; 32],
        now: u64,
    ) -> anyhow::Result<bool> {
        let Some(trusted) = self.trusted_owner() else {
            anyhow::bail!("this device holds no trusted owner key for roster verification");
        };
        filament_peerloop::recv::roster::verify_and_store_roster(&self.store, blob, &trusted, now)
    }
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        filament_peerloop::recv::membership::verify_depart(device_pub, msg, sig)
    }
    fn fleet_channel(&self) -> Option<String> {
        #[cfg(feature = "fleet")]
        {
            self.fleet.channel()
        }
        #[cfg(not(feature = "fleet"))]
        {
            None
        }
    }
    fn fleet_rv(&self) -> Option<String> {
        #[cfg(feature = "fleet")]
        {
            self.fleet.rv()
        }
        #[cfg(not(feature = "fleet"))]
        {
            None
        }
    }
    fn is_fleet_channel(&self, ch: &str) -> bool {
        #[cfg(feature = "fleet")]
        {
            self.fleet.is_fleet_channel(ch)
        }
        #[cfg(not(feature = "fleet"))]
        {
            let _ = ch;
            false
        }
    }
    fn make_fleet_hello(&self, cb: &[u8], name: &str) -> anyhow::Result<Value> {
        #[cfg(feature = "fleet")]
        {
            self.fleet.make_hello(cb, name)
        }
        #[cfg(not(feature = "fleet"))]
        {
            let _ = (cb, name);
            anyhow::bail!("fleet is not enabled in this core profile")
        }
    }
    fn fleet_owner_pub(&self) -> Option<[u8; 32]> {
        #[cfg(feature = "fleet")]
        {
            self.fleet.owner_pub()
        }
        #[cfg(not(feature = "fleet"))]
        {
            None
        }
    }
}

/// The exact close frame a reduced Core sends for an open it does not serve.
fn named_close_frame(sid: u64, what: &str) -> Value {
    json!({
        "type": "l2-close",
        "sid": sid,
        "err": format!("{what} is not served by this core profile"),
    })
}

/// The exact control reply a reduced Core daemon sends for an unsupported
/// local request.
fn daemon_refusal_frame(what: &str) -> Value {
    json!({
        "ok": false,
        "err": format!("{what} is not served by this core profile"),
    })
}

async fn refuse_control(conn: &Conn, pid: &str, v: &Value, what: &str) {
    let sid = v["sid"].as_u64().unwrap_or(0);
    conn.log.say(&format!(
        "core: refused {what} from {pid}: this profile does not serve that endpoint"
    ));
    if let Some(t) = conn.transport_of(pid) {
        let _ = t.send_control(&named_close_frame(sid, what)).await;
    }
}

/// Reduced inbound-server profile: every open is an explicit refusal.
pub struct CoreServers;

#[async_trait]
impl RecvServers for CoreServers {
    async fn open_exec(
        &mut self,
        conn: &mut Conn,
        pid: String,
        v: &Value,
        _policy: &ShellPolicy,
        _shell_user: &Option<String>,
        _muxes: &mut HashMap<String, Arc<Mux>>,
        _l2_enabled: bool,
        _parked: &mut Vec<filament_peerloop::recv::dispatch::ParkedOpen>,
    ) {
        refuse_control(conn, &pid, v, "exec-open").await;
    }
    async fn ssh_sign(
        &mut self,
        conn: &mut Conn,
        pid: &str,
        _t: Arc<dyn Transport>,
        v: &Value,
        _policy: &ShellPolicy,
        _parked: &mut Vec<filament_peerloop::recv::dispatch::ParkedOpen>,
    ) {
        refuse_control(conn, pid, v, "ssh-sign-request").await;
    }
    fn is_exposed(&self, _port: u16) -> bool {
        false
    }
    fn forward_target_allowed(&self, _name: &str, _host: &str, _port: u16) -> bool {
        false
    }
    async fn exec_control(
        &mut self,
        _pid: &str,
        _v: &Value,
        _muxes: &HashMap<String, Arc<Mux>>,
    ) -> bool {
        false
    }
    async fn apply_reconfigure(
        &mut self,
        _key: &str,
        _dir: &mut PathBuf,
        _shell_policy: &mut ShellPolicy,
        _shell_user: &mut Option<String>,
        _l2_enabled: bool,
        _sess: &mut filament_peerloop::session::Session,
        _sio: &filament_signal::Client,
        _my_uid: &str,
    ) -> bool {
        false
    }
    async fn start_expose(&mut self, _tunnel: Arc<dyn MeshTunnel>) -> usize {
        0
    }
    async fn reconcile_expose(&mut self, _tunnel: &Arc<dyn MeshTunnel>) -> usize {
        0
    }
    async fn reload_expose(&mut self) -> usize {
        0
    }
}

/// Reduced daemon profile: local control requests get an explicit error, not a
/// silent success; warm/mount/proxy/wireguard endpoints are absent.
pub struct CoreDaemon {
    root: PathBuf,
    store: DeviceStore,
    overlay: OverlayKey,
}

impl CoreDaemon {
    pub fn new(root: PathBuf, store: DeviceStore, overlay: OverlayKey) -> Self {
        Self {
            root,
            store,
            overlay,
        }
    }

    fn reject(req: filament_peerloop::control::Req, what: &str) {
        let reply = daemon_refusal_frame(what);
        tokio::spawn(async move {
            req.reply(&reply).await;
        });
    }
}

#[async_trait]
impl RecvDaemon for CoreDaemon {
    async fn warm_req(
        &mut self,
        _conn: &Conn,
        _muxes: &mut HashMap<String, Arc<Mux>>,
        _tx: &mpsc::UnboundedSender<Ev>,
        req: filament_peerloop::control::Req,
    ) {
        Self::reject(req, "warm-link reuse");
    }
    async fn list_warm(&mut self, req: filament_peerloop::control::Req, _conn: &Conn) {
        Self::reject(req, "warm-link listing");
    }
    async fn mount(&mut self, req: filament_peerloop::control::Req, _server: &str, _relay: bool) {
        Self::reject(req, "mount");
    }
    async fn unmount(&mut self, req: filament_peerloop::control::Req) {
        Self::reject(req, "unmount");
    }
    async fn list_mounts(&mut self, req: filament_peerloop::control::Req) {
        Self::reject(req, "mount listing");
    }
    async fn mount_health(&mut self, req: filament_peerloop::control::Req) {
        Self::reject(req, "mount health");
    }
    async fn mount_health_tick(&mut self, _host: &dyn HostServices) {}
    async fn warm_bootstrap(
        &mut self,
        _conn: &Conn,
        _tx: &mpsc::UnboundedSender<Ev>,
        req: filament_peerloop::control::Req,
    ) {
        Self::reject(req, "warm bootstrap");
    }
    async fn reach_ping(&mut self, conn: &Conn, pid: &str, _v: &Value) {
        conn.log.say(&format!(
            "core: reach is not served in this profile (peer {pid})"
        ));
    }
    async fn reach_pong(&mut self, _conn: &Conn, _pid: &str, _v: &Value) {}
    fn peer_present(
        &self,
        _alive: bool,
        _direct: bool,
        _heard_ms: Option<u64>,
        _idle_ms: u64,
    ) -> bool {
        false
    }
    async fn complete_warm_bootstrap(&mut self, _conn: &Conn, _pid: &str, _reply: &Value) {}
    fn reap_warm_bootstraps(&mut self) {}
    fn revocation_snapshot(&self) -> Option<(String, String)> {
        None
    }
    fn prune_to_store(&self, _held: &mut Vec<(String, String)>) -> HashSet<String> {
        HashSet::new()
    }
    fn key_listed(&self, device_pub: &[u8; 32]) -> bool {
        self.store.device_key_revoked(device_pub, now_secs())
    }
    fn enroll_channel(&self, public_key: &[u8; 32]) -> String {
        filament_cap::ephemeral::enroll_channel(public_key)
    }
    fn is_armed(&self) -> bool {
        self.store.is_armed()
    }
    fn verify_and_store_roster(
        &self,
        blob: &Value,
        _owner_pub: &[u8; 32],
        now: u64,
    ) -> anyhow::Result<bool> {
        let Some(trusted) = trusted_owner_pub(&self.store, &self.overlay) else {
            anyhow::bail!("this device holds no trusted owner key for roster verification");
        };
        filament_peerloop::recv::roster::verify_and_store_roster(&self.store, blob, &trusted, now)
    }
    fn verify_depart(
        &self,
        device_pub: &[u8; 32],
        msg: &str,
        sig: &[u8; 64],
    ) -> std::result::Result<(), &'static str> {
        filament_peerloop::recv::membership::verify_depart(device_pub, msg, sig)
    }
    fn fleet_share_root(&self) -> PathBuf {
        self.root.clone()
    }
    fn mark_daemon_ready(&mut self) {}
    fn record_proxy(&self, _bind: &str, _port: u16) {}
    fn maybe_hint_local_wedge(&mut self, _shown: &mut bool) {}
    fn wg_usable(&self) -> bool {
        false
    }
    fn wg_claim_attempt(&self, _addr: &str) -> bool {
        false
    }
    fn wg_release_attempt(&self, _addr: &str) {}
    fn wg_local_offer(&self) -> anyhow::Result<(String, u16)> {
        anyhow::bail!("wireguard is not served by this core profile")
    }
    async fn wg_adopt_peer(
        &mut self,
        _peer_pub: &str,
        _peer_overlay: &str,
        _our_overlay: &str,
        _mtu: u32,
        _peer_underlay: std::net::IpAddr,
        _peer_wg_port: u16,
    ) -> anyhow::Result<()> {
        anyhow::bail!("wireguard is not served by this core profile")
    }
    fn subnet_enable(
        &mut self,
        _ifname: &str,
        _prefixes: &[String],
        _snat: bool,
    ) -> anyhow::Result<()> {
        anyhow::bail!("subnet forwarding is not served by this core profile")
    }
    fn configure_sshd_overlay(&mut self, _v6: &str, _v4: &str) -> anyhow::Result<()> {
        anyhow::bail!("sshd overlay is not served by this core profile")
    }
    async fn start_overlay_servers(&mut self, _host: &dyn HostServices) -> Vec<String> {
        Vec::new()
    }
    fn daemon_alive(&self) -> Option<u32> {
        None
    }
    async fn start_proxy(
        &mut self,
        _server: &str,
        _relay: bool,
    ) -> std::result::Result<(u16, Vec<String>), String> {
        Err("proxy is not served by this core profile".to_string())
    }
    fn sdnotify_ready(&self) {}
    fn sdnotify_status(&self, _status: &str) {}
    fn sdnotify_watchdog(&self) {}
    fn request_reload(&mut self) {}
}

pub struct CorePrompt;

impl RecvPrompt for CorePrompt {
    fn ask_code(&self, _prompt: &str) -> anyhow::Result<Option<String>> {
        Err(anyhow::anyhow!(
            "interactive code entry is not available in this core profile"
        ))
    }
    fn line(&self, _prompt: &str) -> anyhow::Result<String> {
        Err(anyhow::anyhow!(
            "interactive prompts are not available in this core profile"
        ))
    }
    fn echo(&self, _ch: char) {}
    fn enter_raw_mode(&self) -> Option<Box<dyn RawMode>> {
        None
    }
    fn spawn_stdin(
        &self,
        _tx: mpsc::UnboundedSender<Ev>,
        _question_open: Arc<std::sync::atomic::AtomicBool>,
        _present: Arc<dyn filament_peerloop::present::Presentation>,
    ) -> Option<Box<dyn filament_peerloop::recv::ports::StdinOwner>> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_cap::capability::CapOutcome;

    fn host() -> CoreHost {
        let dir = tempfile::tempdir().unwrap().keep();
        CoreHost::new(
            dir.clone(),
            DeviceStore::open(&dir),
            CoreSettings::default(),
            OverlayKey::new(dir.join("overlay.ed25519")),
        )
    }

    fn cap_gate<'a>(outcome: &'a CapOutcome, action: &'a str, legacy: bool) -> CapGate<'a> {
        CapGate {
            legacy_allowed: legacy,
            outcome,
            action,
            resource: "self",
            device_pub: None,
            user_pub: None,
            binding: BindingStrength::None,
            cert_expires: None,
            auth_key_caps: None,
            own_user_pub: None,
            scoped_in_bounds: true,
            has_explicit_grant: false,
            cert_revoked: false,
            denied: false,
            ceiling_authorizes: false,
        }
    }

    #[test]
    fn relay_setting_maps_only_always_to_relay_only() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config");
        for (raw, want) in [
            ("relay always\n", true),
            ("relay auto\n", false),
            ("relay never\n", false),
            ("", false),
        ] {
            std::fs::write(&config, raw).unwrap();
            let settings = CoreSettings::load(dir.path()).unwrap();
            assert_eq!(settings.relay_only(), want, "{raw:?}");
        }
    }

    #[test]
    fn the_reduced_core_composes_the_shadow_transfer_gate_only() {
        let host = host();
        let unauthorized = CapOutcome::Unprovisioned;
        assert!(host
            .cap_gate_effective(cap_gate(&unauthorized, CAP_TRANSFER, true))
            .allowed());
        assert!(!host
            .cap_gate_effective(cap_gate(&unauthorized, CAP_TRANSFER, false))
            .allowed());
        // A shell open is refused by name even when legacy trust would allow it.
        let denial = host.cap_gate_effective(cap_gate(&unauthorized, "shell", true));
        assert!(!denial.allowed());
        assert!(denial
            .deny_reason("")
            .contains("shell opens are not served by this core profile"));
    }

    #[test]
    fn core_server_and_daemon_refusals_are_named_frames() {
        for what in ["pty-open", "exec-open", "ssh-sign-request"] {
            let frame = named_close_frame(17, what);
            assert_eq!(frame["type"], "l2-close");
            assert_eq!(frame["sid"], 17);
            assert!(
                frame["err"]
                    .as_str()
                    .is_some_and(|reason| reason.contains(what)),
                "the close must name {what}: {frame}"
            );
        }
        for what in ["warm-link reuse", "mount", "warm bootstrap"] {
            let frame = daemon_refusal_frame(what);
            assert_eq!(frame["ok"], false);
            assert!(
                frame["err"]
                    .as_str()
                    .is_some_and(|reason| reason.contains(what)),
                "the control error must name {what}: {frame}"
            );
        }
    }

    #[test]
    fn the_transfer_gate_still_honors_revocation_and_delegated_ceilings() {
        let host = host();
        let authorized = CapOutcome::Authorized;
        let mut g = cap_gate(&authorized, CAP_TRANSFER, true);
        g.cert_revoked = true;
        assert!(!host.cap_gate_effective(g).allowed());

        let caps = vec!["shell".to_string()];
        let mut g = cap_gate(&authorized, CAP_TRANSFER, true);
        g.auth_key_caps = Some(&caps);
        assert!(!host.cap_gate_effective(g).allowed());

        let caps = vec!["transfer".to_string()];
        let mut g = cap_gate(&authorized, CAP_TRANSFER, true);
        g.auth_key_caps = Some(&caps);
        g.cert_expires = Some(now_secs().saturating_sub(1));
        assert!(!host.cap_gate_effective(g).allowed());
    }
}
