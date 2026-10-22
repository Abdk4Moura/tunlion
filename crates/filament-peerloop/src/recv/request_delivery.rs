//! Production adapters for the durable transfer inbox. No certificate or
//! permission observation captured at approval is reused as current authority.
use super::requests::{Limits, RequestError, RequestRecord, RequestState, RequestStore, SenderIdentity, SenderRelation};
use crate::host::HostServices;
use anyhow::{anyhow, bail, Context, Result};
use filament_cap::capability::{self as cap, PrincipalKind};
use std::fmt;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const DIRECTORY: &str = "transfer-requests";
pub const OFFER_TTL: u64 = 7 * 24 * 60 * 60;

#[derive(Debug)]
pub enum PermitError {
    /// The request, sender, certificate, ceiling, or destination no longer
    /// authorizes this delivery. The caller must fail/clean its own artifact.
    Authority(anyhow::Error),
    /// The store could not be read or written. Keep the placed artifact so a
    /// later retry can recover the receipt.
    Transient(anyhow::Error),
}

impl PermitError {
    fn authority(message: impl Into<String>) -> Self {
        Self::Authority(anyhow!(message.into()))
    }

    fn store(error: RequestError) -> Self {
        let transient = matches!(&error, RequestError::Storage(_) | RequestError::Corrupt(_));
        if transient {
            Self::Transient(anyhow!(error))
        } else {
            Self::Authority(anyhow!(error))
        }
    }

    pub fn is_authority(&self) -> bool {
        matches!(self, Self::Authority(_))
    }
}

impl fmt::Display for PermitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(error) => write!(f, "{error}"),
            Self::Transient(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for PermitError {}

pub enum Admission {
    Waiting(RequestRecord),
    Denied,
    Delivered,
    Receive(DeliveryPermit),
}

pub fn admit(conn: &mut crate::conn::Conn, pid: &str, offer: &Value, root: &Path) -> Result<Admission> {
    let auth = crate::shell_gate::peer_authz(conn, pid);
    if auth.binding != cap::BindingStrength::Proven
        || !conn.link(pid).is_some_and(|link| link.trusted)
    { bail!("durable transfers require a proven paired sender"); }
    let device = auth.idev.ok_or_else(|| anyhow!("sender identity is unresolved"))?;
    let host = conn.host.as_ref();
    let wire_id = offer["request"].as_str()
        .ok_or_else(|| anyhow!("offer has no durable request identity"))?;
    if wire_id.is_empty() || wire_id.len() > 128
        || wire_id.chars().any(char::is_control)
    { bail!("invalid transfer offer identity"); }
    let device_id = hex::encode(device);
    let offer_id = hex::encode(Sha256::digest(format!("{device_id}:{wire_id}").as_bytes()));
    let sender = match current_sender(host, &device_id) {
        Ok(sender) => sender,
        Err(error) => {
            // The sender was approved, then revoked/removed/expired before it
            // re-offered. Retire the receiver record instead of leaving an
            // un-actionable Approved row that no fresh authority can satisfy.
            let _ = fail_offer(host, &offer_id);
            return Err(error);
        }
    };
    if auth.iusr.map(hex::encode).as_deref() != Some(sender.user_id.as_str()) {
        bail!("link identity does not match the current sender certificate");
    }
    let raw_name = offer["name"].as_str().ok_or_else(|| anyhow!("offer has no file name"))?;
    let name = filament_transfer::safe_incoming_name(raw_name);
    if name != raw_name { bail!("offer file name is not a safe basename"); }
    let manifest = super::requests::canonical_manifest(&[super::requests::ManifestEntry {
        path: name.clone(),
        size: offer["size"].as_u64().ok_or_else(|| anyhow!("offer has no exact size"))?,
        sha256: offer["full"].as_str().ok_or_else(|| anyhow!("offer requires a whole-file SHA-256"))?.to_owned(),
        mtime: 0,
    }], &Limits::default())?;
    super::files::ensure_inbox(host, root)?;
    let destination = super::unique_path(&std::fs::canonicalize(root)?, &name);
    let auto_destination = owned_sender(host, &sender).then(|| destination.to_string_lossy().into_owned());
    let inbox = store(host)?;
    // Housekeeping: a daemon with no CLI list still eventually retires an
    // abandoned Delivering record when another offer arrives.
    for event in inbox.expire(host.now_secs())? {
        host.transfer_request_event(&event);
    }
    let (record, event) = inbox.propose(&offer_id, &sender, &manifest, OFFER_TTL,
        auto_destination.as_deref(), host.now_secs())?;
    if let Some(event) = event { host.transfer_request_event(&event); }
    match record.state {
        RequestState::Pending => Ok(Admission::Waiting(record)),
        RequestState::Approved | RequestState::Delivering => {
            let permit = DeliveryPermit::from_record(&record, root)?;
            // Validate the destination and the request-specific staged artifact
            // BEFORE begin_delivery. A wrong/foreign final file is a terminal
            // collision, never a reason to leave a permanent Delivering record.
            let recovering = match permit.recoverable() {
                Ok(recovering) => recovering,
                Err(error) => {
                    let _ = permit.remove_final_if_own();
                    let _ = permit.fail(host);
                    permit.clean_staged();
                    return Err(error.into());
                }
            };
            if recovering {
                // The bytes are already placed. Do not reserve their size again:
                // a nearly full disk must still be able to commit the receipt.
                let (_, event) = inbox.begin_delivery(record.id, record.rev, &sender, host.now_secs())?;
                if let Some(event) = event { host.transfer_request_event(&event); }
                match permit.complete(host) {
                    Ok(()) => {
                        permit.clean_staged();
                        return Ok(Admission::Delivered);
                    }
                    Err(PermitError::Authority(error)) => {
                        let _ = permit.remove_final_if_own();
                        let _ = permit.fail(host);
                        permit.clean_staged();
                        return Err(error);
                    }
                    Err(PermitError::Transient(error)) => return Err(error),
                }
            }
            let (_record, event) = inbox.begin_delivery_with_budget_sample(
                record.id,
                record.rev,
                &sender,
                host.now_secs(),
                // A host that cannot report free space (CoreHost today) passes
                // None: the store then reserves nothing. This is a documented
                // limitation, not an atomic space reservation.
                || host.free_space(root),
            )?;
            if let Some(event) = event { host.transfer_request_event(&event); }
            Ok(Admission::Receive(permit))
        }
        RequestState::Fulfilled => {
            // Receipt already committed; remove a leftover staged artifact if
            // the previous process crashed before cleaning it.
            if let Ok(permit) = DeliveryPermit::from_record(&record, root) {
                permit.clean_staged();
            }
            Ok(Admission::Delivered)
        }
        _ => {
            if let Ok(permit) = DeliveryPermit::from_record(&record, root) {
                let _ = permit.remove_final_if_own();
                permit.clean_staged();
            }
            Ok(Admission::Denied)
        }
    }
}

pub fn owner_id(host: &dyn HostServices) -> Result<String> {
    // A joined device has no user signing key, but its certificate carries the
    // owner's public half. Ask the host explicitly instead of inferring
    // ownership from an empty capability store.
    if let Some(owner) = host.owner_user_pub() {
        return Ok(hex::encode(owner));
    }
    let (owner, _) = cap::fleet_inputs_in(
        &host.cap_store(), "self", cap::CAP_TRANSFER, None, None, None, host.now_secs(),
    );
    owner.map(hex::encode)
        .or_else(|| host.user_key().map(|key| hex::encode(key.public_key_bytes())))
        .ok_or_else(|| anyhow!("local owner identity is unavailable"))
}

pub fn store(host: &dyn HostServices) -> Result<RequestStore> {
    let root = host.config_dir();
    if root.as_os_str().is_empty() { bail!("transfer request storage is unavailable"); }
    Ok(RequestStore::open(root.join(DIRECTORY), owner_id(host)?, Limits::default())?)
}

fn fail_offer(host: &dyn HostServices, offer_id: &str) -> Result<()> {
    let inbox = store(host)?;
    if let Some(record) = inbox
        .snapshot(None)?
        .requests
        .into_iter()
        .find(|record| record.offer_id == offer_id)
    {
        if matches!(record.state, RequestState::Approved | RequestState::Delivering) {
            let (_, event) = inbox.fail(record.id, record.rev, host.now_secs())?;
            if let Some(event) = event {
                host.transfer_request_event(&event);
            }
        }
    }
    Ok(())
}

/// Resolve by cryptographic device id, never by the sender's displayed name.
/// Stored certificates are re-verified against the current host clock and the
/// device must still be a known member of the local store.
pub fn current_sender(host: &dyn HostServices, device_id: &str) -> Result<SenderIdentity> {
    let device: [u8; 32] = hex::decode(device_id)?.try_into()
        .map_err(|_| anyhow!("invalid sender device identity"))?;
    if !host.device_known(&device) || host.cert_revoked_for(Some(&device)) {
        bail!("sender is unknown or revoked");
    }
    let cert = host.device_cert_for_key(&device)
        .ok_or_else(|| anyhow!("sender certificate is unavailable"))?;
    cert.verify(host.now_secs())?;
    let principal = host.persisted_principal_for_cert(&cert);
    let mut deadline = host.principal_deadline(
        cert.expires, principal.not_after, principal.last_seen, principal.max_offline,
    );
    if let Some(ceiling) = principal.kind.auth_key_caps() {
        if !ceiling.iter().any(|action| action.eq_ignore_ascii_case(cap::CAP_TRANSFER)) {
            bail!("sender's invitation does not permit transfers");
        }
    }
    if let Some(access) = host.delegated_access_for(&device) {
        deadline = deadline.min(access.deadline);
        if !access.ceiling.iter().any(|action| action.eq_ignore_ascii_case(cap::CAP_TRANSFER)) {
            bail!("sender's delegated scope does not permit transfers");
        }
    }
    if deadline <= host.now_secs() { bail!("sender's authority expired"); }
    let user_id = hex::encode(cert.user_pub);
    // A joined/delegated device is signed by the same owner user key, but it is
    // NOT an owned device. Relationship follows the principal record, never the
    // certificate's issuer alone.
    let owner_device = matches!(principal.kind, PrincipalKind::OwnerDevice)
        && host.delegated_access_for(&device).is_none()
        && user_id == owner_id(host)?;
    let relation = if owner_device {
        SenderRelation::SameOwner
    } else {
        SenderRelation::PairedExternal
    };
    Ok(SenderIdentity {
        device_id: device_id.to_owned(), user_id, relation,
        verified: true, known: true, revoked: false,
        expires_at: Some(deadline), is_primary: false,
    })
}

pub fn owned_sender(host: &dyn HostServices, sender: &SenderIdentity) -> bool {
    if sender.relation != SenderRelation::SameOwner { return false; }
    let Ok(device) = hex::decode(&sender.device_id) else { return false; };
    let Ok(device) = <[u8;32]>::try_from(device) else { return false; };
    host.device_cert_for_key(&device)
        .is_some_and(|cert| matches!(host.persisted_principal_for_cert(&cert).kind, PrincipalKind::OwnerDevice)
            && host.delegated_access_for(&cert.device_pub).is_none())
}

/// Approvals select exactly one basename below the configured inbox. Canonical
/// parents are compared again at delivery, so a replaced root symlink does not
/// redirect an old approval.
pub fn confined_destination(root: &Path, destination: &Path) -> Result<PathBuf> {
    let root = std::fs::canonicalize(root).context("receive root is unavailable")?;
    let name = match destination.components().last() {
        Some(Component::Normal(name)) if !name.is_empty() => name,
        _ => bail!("destination must be a plain file name"),
    };
    let parent = destination.parent().ok_or_else(|| anyhow!("destination has no parent"))?;
    if std::fs::canonicalize(parent)? != root { bail!("destination is outside the receive root"); }
    Ok(root.join(name))
}

#[derive(Clone, Debug)]
pub struct DeliveryPermit {
    pub request_id: u64,
    pub device_id: String,
    pub digest: String,
    pub size: u64,
    pub file_sha256: String,
    pub destination: PathBuf,
    pub receive_root: PathBuf,
    /// Shared across per-chunk writer tasks so a revocation is noticed within a
    /// bounded interval instead of on every frame.
    last_authority_check: Arc<Mutex<Instant>>,
}

impl DeliveryPermit {
    pub fn fail(&self, host: &dyn HostServices) -> Result<()> {
        let inbox = store(host)?;
        if let Some(record) = inbox.snapshot(None)?.requests.into_iter().find(|record| record.id == self.request_id) {
            if matches!(record.state, RequestState::Approved | RequestState::Delivering) {
                let (_, event) = inbox.fail(record.id, record.rev, host.now_secs())?;
                if let Some(event) = event { host.transfer_request_event(&event); }
            }
        }
        Ok(())
    }

    pub fn from_record(record: &RequestRecord, root: &Path) -> Result<Self> {
        if record.manifest.count != 1 || record.manifest.entries.len() != 1 {
            bail!("request is not a one-file manifest");
        }
        let entry = &record.manifest.entries[0];
        let destination = record.destination.as_ref().ok_or_else(|| anyhow!("request has no destination"))?;
        Ok(Self {
            request_id: record.id,
            device_id: record.sender.device_id.clone(),
            digest: record.manifest.digest.clone(),
            size: record.manifest.total_bytes,
            file_sha256: entry.sha256.clone(),
            destination: confined_destination(root, Path::new(destination))?,
            receive_root: std::fs::canonicalize(root)?,
            last_authority_check: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// The request-specific staging path. It is deliberately not derived from
    /// the peer's display name, so two offers cannot share a partial.
    pub fn staged_path(&self) -> PathBuf {
        self.receive_root.join(format!(".tunlion-request-{}.part", self.request_id))
    }

    pub fn staged_meta_path(&self) -> PathBuf {
        let mut path = self.staged_path().as_os_str().to_owned();
        path.push(".meta");
        PathBuf::from(path)
    }

    /// Remove only this request's staged artifact. Never touches the final path.
    pub fn clean_staged(&self) {
        let _ = std::fs::remove_file(self.staged_path());
        let _ = std::fs::remove_file(self.staged_meta_path());
    }

    fn verify_file(&self, path: &Path) -> Result<(), PermitError> {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| PermitError::authority(format!("cannot inspect {}: {error}", path.display())))?;
        if !metadata.file_type().is_file() {
            return Err(PermitError::authority(format!("{} is not a regular file", path.display())));
        }
        if metadata.len() != self.size {
            return Err(PermitError::authority(format!(
                "{} has {} bytes, expected {}",
                path.display(), metadata.len(), self.size
            )));
        }
        let hash = self.safe_hash(path)?;
        if hash != self.file_sha256 {
            return Err(PermitError::authority(format!(
                "{} does not match the approved SHA-256",
                path.display()
            )));
        }
        Ok(())
    }

    /// Read through the receive-root confinement primitive. No path component
    /// may be a symlink, and the opened handle must still be a regular file.
    fn safe_hash(&self, path: &Path) -> Result<String, PermitError> {
        let relative = path.strip_prefix(&self.receive_root)
            .map_err(|_| PermitError::authority("path is outside the receive root"))?;
        #[cfg(feature = "mount-server")]
        let mut file = crate::mount_proto::safe_open_beneath(
            &self.receive_root, relative, 0, true, 0,
        ).map_err(|error| PermitError::authority(format!(
            "cannot open {} safely: {error}", path.display()
        )))?;
        #[cfg(not(feature = "mount-server"))]
        let _ = relative;
        #[cfg(not(feature = "mount-server"))]
        let mut file = {
            // Core builds omit the mount protocol feature. Keep the same
            // canonical-root check and verify the opened path afterwards; the
            // full component-by-component safe-open belongs to a mount-enabled
            // host.
            let canonical = std::fs::canonicalize(path)
                .map_err(|error| PermitError::authority(format!("cannot resolve {}: {error}", path.display())))?;
            if !canonical.starts_with(&self.receive_root) {
                return Err(PermitError::authority("path is outside the receive root"));
            }
            std::fs::File::open(&canonical)
                .map_err(|error| PermitError::authority(format!("cannot open {}: {error}", path.display())))?
        };
        let metadata = file.metadata()
            .map_err(|error| PermitError::authority(format!("cannot stat {}: {error}", path.display())))?;
        if !metadata.file_type().is_file() {
            return Err(PermitError::authority(format!("{} is not a regular file", path.display())));
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = file.read(&mut buffer)
                .map_err(|error| PermitError::authority(format!("cannot read {}: {error}", path.display())))?;
            if read == 0 { break; }
            hasher.update(&buffer[..read]);
        }
        Ok(hasher.finalize().iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// True only when the final path and the request-specific staged part are
    /// the same artifact by file identity. This is Unix-only; a matching hash
    /// does not prove identity and must never authorize deleting a destination.
    pub fn same_artifact(&self) -> bool {
        let part = std::fs::symlink_metadata(self.staged_path());
        let final_path = std::fs::symlink_metadata(&self.destination);
        let (Ok(part), Ok(final_meta)) = (part, final_path) else { return false; };
        if !part.file_type().is_file() || !final_meta.file_type().is_file() {
            return false;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            part.dev() == final_meta.dev() && part.ino() == final_meta.ino()
        }
        #[cfg(not(unix))]
        {
            let _ = (part, final_meta);
            false
        }
    }

    /// Remove the final path only when it is this request's own staged artifact.
    /// Never removes a foreign file at the approved destination.
    pub fn remove_final_if_own(&self) -> bool {
        self.same_artifact() && std::fs::remove_file(&self.destination).is_ok()
    }

    /// A crash-recovery candidate: the destination exists, and it is the
    /// request-specific staged artifact by file identity. A bare file that
    /// merely matches the digest is not enough, and non-Unix hosts cannot prove
    /// identity, so they refuse recovery rather than guess.
    pub fn recoverable(&self) -> Result<bool, PermitError> {
        let final_meta = match std::fs::symlink_metadata(&self.destination) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(PermitError::authority(format!(
                "cannot inspect {}: {error}", self.destination.display()
            ))),
        };
        if !final_meta.file_type().is_file() {
            return Err(PermitError::authority("approved destination is occupied"));
        }
        let part = self.staged_path();
        let part_meta = std::fs::symlink_metadata(&part)
            .map_err(|_| PermitError::authority("recovery artifact is missing"))?;
        if !part_meta.file_type().is_file() {
            return Err(PermitError::authority("recovery artifact is not a regular file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if part_meta.dev() != final_meta.dev() || part_meta.ino() != final_meta.ino() {
                return Err(PermitError::authority(
                    "approved destination is not this request's staged artifact",
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (part_meta, final_meta, part);
            Err(PermitError::authority(
                "this platform cannot prove the staged artifact identity; remove the destination and retry",
            ))
        }
        #[cfg(unix)]
        {
            self.verify_file(&part)?;
            self.verify_file(&self.destination)?;
            Ok(true)
        }
    }

    /// Verify the final path after placement. Unix also requires the same file
    /// identity as the staged part; non-Unix has no identity primitive here, so
    /// it verifies the bytes just linked and never claims crash recovery.
    pub fn verify_final(&self) -> Result<(), PermitError> {
        #[cfg(unix)]
        if !self.same_artifact() {
            return Err(PermitError::authority(
                "final destination is not this request's staged artifact",
            ));
        }
        self.verify_file(&self.destination)
    }

    /// Bounded per-chunk authority check. Admission and placement use
    /// [`check`](Self::check), which always re-resolves; this only skips the
    /// expensive re-read for frames that arrive inside the interval.
    pub fn check_if_due(&self, host: &dyn HostServices) -> Result<(), PermitError> {
        let mut last = self
            .last_authority_check
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if last.elapsed() < Duration::from_secs(2) {
            return Ok(());
        }
        *last = Instant::now();
        drop(last);
        self.check(host).map(|_| ())
    }

    pub fn check(&self, host: &dyn HostServices) -> Result<(RequestRecord, SenderIdentity), PermitError> {
        let sender = current_sender(host, &self.device_id)
            .map_err(|error| PermitError::authority(format!("sender no longer authorizes delivery: {error}")))?;
        let store = store(host).map_err(PermitError::Transient)?;
        let record = store.snapshot(None)
            .map_err(PermitError::store)?
            .requests
            .into_iter()
            .find(|record| record.id == self.request_id)
            .ok_or_else(|| PermitError::authority("transfer request no longer exists"))?;
        if record.state != RequestState::Delivering
            || record.manifest.digest != self.digest
            || record.sender.device_id != sender.device_id
            || record.sender.user_id != sender.user_id
            || record.sender.relation != sender.relation
            || record.destination.as_deref() != self.destination.to_str()
        {
            return Err(PermitError::authority(
                "transfer request no longer authorizes this delivery",
            ));
        }
        confined_destination(&self.receive_root, &self.destination)
            .map_err(|error| PermitError::authority(format!("destination no longer confined: {error}")))?;
        Ok((record, sender))
    }

    pub fn complete(&self, host: &dyn HostServices) -> Result<(), PermitError> {
        let (record, sender) = self.check(host)?;
        let store = store(host).map_err(PermitError::Transient)?;
        let (_, event) = store
            .complete(record.id, record.rev, &sender, host.now_secs())
            .map_err(PermitError::store)?;
        if let Some(event) = event { host.transfer_request_event(&event); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_id::{DeviceCert, UserKey};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Host {
        root: PathBuf,
        cert: DeviceCert,
        revoked: AtomicBool,
        known: AtomicBool,
        now: AtomicU64,
    }
    impl Host {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("request-delivery-{}-{}", std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(root.join("inbox")).unwrap();
            let external = UserKey::from_seed(&[2; 32]).unwrap();
            Self { root, cert: DeviceCert::certify(&external, [3;32], 1, 10000).unwrap(),
                revoked: AtomicBool::new(false), known: AtomicBool::new(true), now: AtomicU64::new(10) }
        }
        fn approve(&self) -> DeliveryPermit {
            let sender = current_sender(self, &hex::encode(self.cert.device_pub)).unwrap();
            let manifest = super::super::requests::canonical_manifest(&[super::super::requests::ManifestEntry {
                path: "payload".into(), size: 3, sha256: hex::encode(Sha256::digest(b"abc")), mtime: 0,
            }], &Limits::default()).unwrap();
            let inbox = store(self).unwrap();
            let (record, _) = inbox.propose("offer", &sender, &manifest, 100, None, 10).unwrap();
            let destination = self.root.join("inbox/payload");
            let (record, _) = inbox.accept(record.id, record.rev, destination.to_str().unwrap(), &sender, 10).unwrap();
            let (record, _) = inbox.begin_delivery(record.id, record.rev, &sender, 10).unwrap();
            DeliveryPermit::from_record(&record, &self.root.join("inbox")).unwrap()
        }
    }
    impl Drop for Host { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.root); } }
    #[async_trait::async_trait]
    impl HostServices for Host {
        fn config_dir(&self) -> PathBuf { self.root.clone() }
        fn now_secs(&self) -> u64 { self.now.load(Ordering::Relaxed) }
        fn user_key(&self) -> Option<UserKey> { Some(UserKey::from_seed(&[1;32]).unwrap()) }
        fn device_known(&self, _: &[u8;32]) -> bool { self.known.load(Ordering::Relaxed) }
        fn cert_revoked_for(&self, _: Option<&[u8;32]>) -> bool { self.revoked.load(Ordering::Relaxed) }
        fn device_cert_for(&self, _: &str) -> Option<DeviceCert> { Some(self.cert.clone()) }
        fn settings_get_str(&self, _: &str) -> Option<String> { None }
        fn devices_load(&self) -> Vec<(String,String)> { vec![("external".into(), "peer".into())] }
        fn is_self_uid(&self, _: &str, _: Option<&str>) -> bool { false }
        fn rejoin_unwarned(&self) -> Duration { Duration::from_secs(25) }
        fn relay_banner(&self) -> String { String::new() }
        fn relay_forbidden(&self) -> bool { false }
        fn channel_of(&self, _: &str) -> String { String::new() }
        fn roster_snapshot_json(&self) -> Option<String> { None }
        fn fleet_rv_present(&self) -> bool { false }
    }

    #[test]
    fn access_request_file_is_never_replaced() {
        let host = Host::new();
        let access = host.root.join("requests.json");
        std::fs::write(&access, "[]").unwrap();
        host.approve();
        assert_eq!(std::fs::read_to_string(access).unwrap(), "[]");
        assert!(store(&host).unwrap().store_path().starts_with(host.root.join(DIRECTORY)));
    }

    #[test]
    fn persisted_approval_cannot_override_fresh_revocation_removal_or_expiry() {
        let host = Host::new();
        let permit = host.approve();
        assert!(permit.check(&host).is_ok());
        host.revoked.store(true, Ordering::Relaxed);
        assert!(permit.check(&host).is_err());
        host.revoked.store(false, Ordering::Relaxed);
        host.known.store(false, Ordering::Relaxed);
        assert!(permit.check(&host).is_err());
        host.known.store(true, Ordering::Relaxed);
        host.now.store(10001, Ordering::Relaxed);
        assert!(permit.check(&host).is_err());
    }

    #[test]
    fn waiting_state_and_exact_destination_survive_reopen() {
        let host = Host::new();
        let permit = host.approve();
        let snapshot = store(&host).unwrap().snapshot(None).unwrap();
        assert_eq!(snapshot.requests[0].state, RequestState::Delivering);
        assert_eq!(snapshot.requests[0].destination.as_deref(), permit.destination.to_str());
        assert!(!owned_sender(&host, &snapshot.requests[0].sender));
        assert!(confined_destination(&host.root.join("inbox"), &host.root.join("escaped")).is_err());
        assert!(
            confined_destination(&host.root.join("inbox"), &host.root.join("inbox/..")).is_err(),
            "a parent component is not a plain file name"
        );
    }

    #[tokio::test]
    async fn actual_file_placement_commits_a_receipt_without_replacing_destinations() {
        use std::sync::{Arc, Mutex};
        use std::sync::atomic::{AtomicI64, AtomicU64};
        let host = Host::new();
        let permit = host.approve();
        let part = permit.staged_path();
        std::fs::write(&part, b"abc").unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&part).unwrap();
        let inc = super::super::IncomingFile {
            durable: Some(permit.clone()), id: "wire".into(), name: "payload".into(), size: 3,
            received: Arc::new(AtomicU64::new(3)), ranges: Arc::new(Mutex::new(vec![(0,3)])),
            file: Arc::new(file), part_path: part,
            full: Some(hex::encode(Sha256::digest(b"abc"))), inflight: Arc::new(AtomicI64::new(0)),
            end_seen: Arc::new(AtomicBool::new(true)), completion: Arc::new(super::super::CompletionGate::default()),
            ack_sid: 0, last_tick: 3, bar: Box::new(crate::present::NoBar),
            write_err: Arc::new(Mutex::new(None)), stdout: None,
        };
        assert!(super::super::files::finalize_incoming(&host, &crate::host::NoLog, inc,
            &host.root.join("inbox"), None, true, "external", &super::super::RecvReport::default(),
            &Arc::new(Mutex::new(std::collections::HashMap::new()))).await.unwrap());
        assert_eq!(std::fs::read(&permit.destination).unwrap(), b"abc");
        assert_eq!(store(&host).unwrap().snapshot(None).unwrap().requests[0].state, RequestState::Fulfilled);
    }

    #[test]
    fn a_matching_final_without_the_staged_part_is_not_recovery() {
        let host = Host::new();
        let permit = host.approve();
        std::fs::write(&permit.destination, b"abc").unwrap();
        assert!(
            permit.recoverable().is_err(),
            "a final file that merely matches the digest is not proof of placement"
        );
        assert!(permit.destination.exists(), "recovery validation must not remove a foreign file");
    }

    #[cfg(unix)]
    #[test]
    fn recovery_requires_the_final_to_be_the_same_inode_as_the_staged_part() {
        let host = Host::new();
        let permit = host.approve();
        std::fs::write(permit.staged_path(), b"abc").unwrap();
        assert!(!permit.recoverable().unwrap(), "no final yet");
        std::fs::hard_link(permit.staged_path(), &permit.destination).unwrap();
        assert!(permit.recoverable().unwrap());
        assert!(permit.verify_final().is_ok());
        std::fs::remove_file(&permit.destination).unwrap();
        std::fs::write(&permit.destination, b"abc").unwrap();
        assert!(
            permit.recoverable().is_err(),
            "a separate file with the same bytes is not this request's artifact"
        );
    }

    #[test]
    fn a_transient_store_error_is_classified_without_touching_the_artifact() {
        let host = Host::new();
        let permit = host.approve();
        let part = permit.staged_path();
        std::fs::write(&part, b"abc").unwrap();
        let store = store(&host).unwrap();
        let path = store.store_path();
        let original = std::fs::read(&path).unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(permit.check(&host), Err(PermitError::Transient(_))));
        assert!(part.exists(), "a transient store read must keep the staged artifact");
        assert!(!permit.destination.exists());
        std::fs::write(&path, original).unwrap();
    }

    #[tokio::test]
    async fn a_foreign_destination_is_not_overwritten_or_removed() {
        use std::sync::{Arc, Mutex};
        use std::sync::atomic::{AtomicI64, AtomicU64};
        let host = Host::new();
        let permit = host.approve();
        let part = permit.staged_path();
        std::fs::write(&part, b"abc").unwrap();
        std::fs::write(&permit.destination, b"keep").unwrap();
        let file = std::fs::OpenOptions::new().read(true).write(true).open(&part).unwrap();
        let inc = super::super::IncomingFile {
            durable: Some(permit.clone()), id: "wire".into(), name: "payload".into(), size: 3,
            received: Arc::new(AtomicU64::new(3)), ranges: Arc::new(Mutex::new(vec![(0,3)])),
            file: Arc::new(file), part_path: part,
            full: Some(hex::encode(Sha256::digest(b"abc"))), inflight: Arc::new(AtomicI64::new(0)),
            end_seen: Arc::new(AtomicBool::new(true)), completion: Arc::new(super::super::CompletionGate::default()),
            ack_sid: 0, last_tick: 3, bar: Box::new(crate::present::NoBar),
            write_err: Arc::new(Mutex::new(None)), stdout: None,
        };
        assert!(!super::super::files::finalize_incoming(&host, &crate::host::NoLog, inc,
            &host.root.join("inbox"), None, true, "external", &super::super::RecvReport::default(),
            &Arc::new(Mutex::new(std::collections::HashMap::new()))).await.unwrap());
        assert_eq!(std::fs::read(&permit.destination).unwrap(), b"keep");
        assert_eq!(
            store(&host).unwrap().snapshot(None).unwrap().requests[0].state,
            RequestState::Failed
        );
    }
}
