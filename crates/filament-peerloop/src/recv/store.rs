//! The device and identity stores, with an explicit root.
//!
//! This is the host-neutral half of what the receive dispatch asks for through
//! [`RecvStore`](crate::recv::ports::RecvStore): `devices.json` and the
//! identity-side records that live beside it. Every entry point is a method on
//! a [`DeviceStore`] built from an explicit directory, and the only filesystem
//! dependency is that directory. Nothing here reads `TUNLION_CONFIG_DIR`,
//! `directories`, a process-global path or a process-global cache.
//!
//! The CLI is a thin adapter over this module: `cli/src/devices_store.rs`
//! constructs one `DeviceStore` on the process config directory and forwards,
//! so production keeps one implementation while an embedder (Core) can pass its
//! own config directory.
//!
//! What moves here, verbatim in behaviour:
//!
//! * the locked atomic read/modify/write of `devices.json` and its pure
//!   record-merge rules (`upsert_peer_record`, `refuse_unowned_rewrite`,
//!   `free_device_name`, `insert_new_peer_record`, `place_joined_owner`);
//! * the store reads used by the dispatch and by identity resolution
//!   (`device_cert_for`, `device_cert_valid_for`, `devices_find_by_device_pub`,
//!   `device_cert_revoked`, `devices_load`, `any_shell_grant`, `devices_info`);
//! * the store mutations behind the `RecvStore` port (`devices_touch`,
//!   `devices_remove`, `devices_sweep_lapsed`, `mark_lapsed_now`,
//!   `mark_bounded_cap_source`, `promote_provisional_identity`, the capability
//!   store's owner-signed ops);
//! * the identity-side files: the provisional identity record, the local
//!   device certificate record, and the owner key discovered through an
//!   explicit [`RootKeyStore`].
//!
//! The persistence formats are unchanged: `devices.json` is still a JSON array
//! of records with the same field names, the capability store is still
//! `caps.json`, the local certificate is still `identity/device-cert.json`, the
//! provisional records are still `provisional_<name>.json`, and writes still go
//! through the shared owner-only atomic writer (`secret-write`).
//!
//! Deliberately NOT here: certificate verification policy itself (that stays in
//! `filament-id`), capability evaluation (that stays in `filament-cap`), and the
//! protocol lifecycle handlers (proof/expose/renew/enrol), which need the
//! overlay signing key and the process-local enrollment/nonce/burn state. Those
//! remain on the `RecvIdentity` adapter and are the exact remaining obstacle to
//! a non-CLI `CoreHost`.

use anyhow::{Context, Result};
use filament_cap::capability::{
    now_secs as cap_now_secs, superseded_by_tombstone, CapOp, PrincipalKind, CAP_TOMBSTONE_TYPE,
};
use filament_cap::ephemeral::Reuse;
use filament_id::{now_secs, DeviceCert, KeyStore, UserKey};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// The device store's file name, relative to the root.
pub const DEVICES_FILE: &str = "devices.json";
/// The cross-process lock sidecar used for `devices.json` writes.
pub const DEVICES_LOCK_FILE: &str = "devices.json.lock";
/// The local device certificate record, relative to the root.
pub const LOCAL_DEVICE_CERT_FILE: &str = "identity/device-cert.json";
/// How long a provisional identity is worth keeping. It exists to bridge one
/// session's identity proof to that session's overlay announcement, which
/// follows within seconds; an hour is generous.
pub const PROVISIONAL_TTL_SECS: u64 = 3600;
/// Durable invitation-use file, kept apart from device records.
pub const USED_INVITATIONS_FILE: &str = "used-invitations.json";
/// The cross-process lock sidecar used for the invitation-use read/modify/write.
/// It is derived from the data file's own path (append `.lock`), so every
/// caller of [`record_invitation_use_at`] for one file locks the same sidecar.
pub const USED_INVITATIONS_LOCK_FILE: &str = "used-invitations.json.lock";

/// Why an invitation use was refused. The wire reason is what the joiner sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvitationRefusal {
    AlreadyUsed,
    UseLimitReached,
    Unverifiable,
    /// The owner withdrew the invitation (`tunlion add --withdraw`). Durable:
    /// it lives in the same locked file as the use count.
    Withdrawn,
}

/// The wire reason for a withdrawn invitation. A 0.9.1 joiner prints any
/// reason it does not know as `enrollment denied: <reason>`, so this is a
/// whole sentence that reads correctly there too.
pub const WITHDRAWN_WIRE_REASON: &str = "the owner withdrew this invitation";

impl InvitationRefusal {
    pub fn wire_reason(self) -> &'static str {
        match self {
            InvitationRefusal::AlreadyUsed => "already used",
            InvitationRefusal::UseLimitReached => "use limit reached",
            InvitationRefusal::Unverifiable => "enrollment denied",
            InvitationRefusal::Withdrawn => WITHDRAWN_WIRE_REASON,
        }
    }
}

/// One invitation's line in the durable use file, as the owner's listing
/// needs it: how many claims were admitted and whether it was withdrawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationLedgerEntry {
    pub key_id: String,
    pub uses: u64,
    pub expires: u64,
    pub withdrawn: bool,
}

/// Terminal principal states written to `principalState` on a device record.
pub const PRINCIPAL_STATE_LAPSED: &str = "lapsed";
pub const PRINCIPAL_STATE_REVOKED: &str = "revoked";

/// The three clocks that can end a delegated device's recognition. The binding
/// one is whichever expires first; the state display names it so "X time left"
/// never lies about which bound is actually in charge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineClock {
    /// The device certificate's own expiry (`verify` fails past it).
    CertExpiry,
    /// The signed absolute stop (`not_after` from the auth key).
    AbsoluteStop,
    /// The liveness budget (`last_seen + effective_max_offline`).
    LivenessBudget,
}

/// A keystore whose root is the caller's config directory. This is the
/// explicit, per-instance counterpart of the CLI's `PlatformKeyStore`: it never
/// reads an environment variable to find the directory.
#[derive(Clone, Debug)]
pub struct RootKeyStore {
    root: PathBuf,
}

impl RootKeyStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl KeyStore for RootKeyStore {
    fn write_secret(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        secret_write::SecretFile::write(path, data)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }

    fn config_path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

/// The overlay signing key for one instance, at an explicit path.
///
/// The key is an Ed25519 PKCS8 file used for possession proofs. Loading,
/// generating and signing need only `ring`, not the overlay/announce feature:
/// an Android transfer/shell-client engine needs the key and certificate
/// primitives without pulling in mesh, fleet, mounts or forward serving. The
/// announce wrapper is available under `mesh` via [`OverlayKey::identity`].
#[derive(Clone, Debug)]
pub struct OverlayKey {
    path: PathBuf,
}

impl OverlayKey {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the PKCS8 bytes, generating and persisting the key on first use.
    pub fn load_pkcs8(&self) -> Result<Vec<u8>> {
        match std::fs::read(&self.path) {
            Ok(bytes) => Ok(bytes),
            Err(_) => {
                let rng = ring::rand::SystemRandom::new();
                let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|_| anyhow::anyhow!("overlay key generation failed"))?;
                secret_write::SecretFile::write(&self.path, doc.as_ref())
                    .context("write overlay key")?;
                Ok(doc.as_ref().to_vec())
            }
        }
    }

    pub fn keypair(&self) -> Result<ring::signature::Ed25519KeyPair> {
        let pkcs8 = self.load_pkcs8()?;
        ring::signature::Ed25519KeyPair::from_pkcs8(&pkcs8)
            .map_err(|_| anyhow::anyhow!("overlay key is corrupt"))
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        use ring::signature::KeyPair;
        let keypair = self.keypair()?;
        let mut out = [0u8; 32];
        out.copy_from_slice(keypair.public_key().as_ref());
        Ok(out)
    }

    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        let keypair = self.keypair()?;
        let mut out = [0u8; 64];
        out.copy_from_slice(keypair.sign(msg).as_ref());
        Ok(out)
    }

    /// The overlay announce identity, for the mesh/fleet features.
    #[cfg(feature = "mesh")]
    pub fn identity(&self) -> Result<filament_overlay::Identity> {
        filament_overlay::Identity::from_pkcs8(&self.load_pkcs8()?)
    }
}

/// The one error a caller must be able to tell apart: a store file exists but
/// does not parse. The CLI maps it to its `corrupt_state` exit kind; a library
/// embedder gets the same sentence instead of silently treating damage as an
/// empty store.
#[derive(Debug)]
pub struct CorruptStore {
    path: PathBuf,
    why: String,
    backup_exists: bool,
}

impl CorruptStore {
    fn new(path: PathBuf, why: String) -> Self {
        let backup_exists = backup_path(&path).exists();
        Self {
            path,
            why,
            backup_exists,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The full refusal, including how to recover.
    pub fn message(&self) -> String {
        let recover = if self.backup_exists {
            format!(
                "Fix it, or restore the last good copy: cp {} {}",
                backup_path(&self.path).display(),
                self.path.display()
            )
        } else {
            "Fix it, or move it aside to start with an empty one (that forgets what it held)"
                .to_string()
        };
        format!(
            "{} cannot be parsed ({}). It is not read as empty, and nothing writes over it until it is fixed. {recover}",
            self.path.display(),
            self.why
        )
    }
}

impl std::fmt::Display for CorruptStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for CorruptStore {}

/// The frozen rendezvous channel derivation (`filament-pair:` domain). Shared
/// by pairing and fleet; one implementation.
pub fn channel_of(secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Walk up to the deepest existing ancestor, then create downwards, so
        // each directory WE create is tightened and nothing pre-existing is.
        // `create_dir_all` alone asks for 0777 and lets umask decide, which
        // under `umask 0000` leaves the config dir and identity/ world-writable.
        let mut missing = Vec::new();
        let mut cur = Some(dir);
        while let Some(p) = cur {
            if p.as_os_str().is_empty() || p.exists() {
                break;
            }
            missing.push(p.to_path_buf());
            cur = p.parent();
        }
        for p in missing.iter().rev() {
            match std::fs::DirBuilder::new().mode(0o700).create(p) {
                Ok(()) => tighten_new_dir(p),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists && p.is_dir() => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

fn tighten_new_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".bak");
    path.with_file_name(name)
}

/// Keep the current file as `<name>.bak`, best effort. Never blocks the write
/// it protects.
fn keep_backup(path: &Path) {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if !raw.trim().is_empty() {
            let _ = secret_write::SecretFile::write_str(&backup_path(path), &raw);
        }
    }
}

/// Refuse to overwrite a JSON array that no longer parses, then keep a backup.
fn before_write_json_array(path: &Path) -> io::Result<()> {
    match std::fs::read_to_string(path) {
        Ok(raw) => {
            if raw.trim().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "{} is empty; refusing to overwrite a truncated store",
                        path.display()
                    ),
                ));
            }
            match serde_json::from_str::<Value>(&raw) {
                Ok(v) if v.is_array() => {}
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} is not a JSON array", path.display()),
                    ))
                }
                Err(e) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("{} cannot be parsed ({e})", path.display()),
                    ))
                }
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    keep_backup(path);
    Ok(())
}

/// An exclusive, cross-process lock on a sidecar file. On Unix this is
/// `flock`; on Windows `LockFileEx`; elsewhere it is an ordinary open (the
/// store's own atomic rename still prevents torn writes).
struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    /// Try to take the lock without waiting. `Ok(None)` means another process
    /// holds it; every other failure is an I/O error.
    fn try_acquire(path: &Path) -> io::Result<Option<Self>> {
        #[allow(unused_mut)]
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
            if rc != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Ok(None);
                }
                return Err(error);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::{
                LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
            };
            use windows_sys::Win32::System::IO::OVERLAPPED;
            let handle = file.as_raw_handle() as HANDLE;
            let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
            let ok = unsafe {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            if ok == 0 {
                let error = io::Error::last_os_error();
                // ERROR_LOCK_VIOLATION (33): another process holds the lease.
                if error.raw_os_error() == Some(33) {
                    return Ok(None);
                }
                return Err(error);
            }
        }
        Ok(Some(Self { _file: file }))
    }

    fn acquire(path: &Path) -> io::Result<Self> {
        #[allow(unused_mut)]
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            let fd = file.as_raw_fd();
            let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
            if rc != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::HANDLE;
            use windows_sys::Win32::Storage::FileSystem::LockFileEx;
            use windows_sys::Win32::System::IO::OVERLAPPED;
            let handle = file.as_raw_handle() as HANDLE;
            let mut overlapped = unsafe { std::mem::zeroed::<OVERLAPPED>() };
            let ok = unsafe {
                LockFileEx(
                    handle,
                    windows_sys::Win32::Storage::FileSystem::LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self { _file: file })
    }
}

/// A held engine lease on one config root. Dropping it releases the lock.
pub struct CoreLease {
    _lock: StoreLock,
}

/// The device and identity store for one config directory.
///
/// `owner_pub` is the key owner-signed capability operations are verified
/// against. It is explicit per instance: the CLI supplies
/// `fleet::my_owner_pub()`, and an embedder supplies the key from its own
/// keystore. `None` means "this instance has no owner key", which makes the two
/// owner-capability reads fail closed (empty / zero), exactly as the CLI did
/// when `my_owner_pub()` was `None`.
#[derive(Clone, Debug)]
pub struct DeviceStore {
    root: PathBuf,
    owner_pub: Option<[u8; 32]>,
}

impl DeviceStore {
    /// Open the store rooted at `root`. Does not create or read anything.
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            owner_pub: None,
        }
    }

    /// Set the owner key this instance verifies owner-signed capability ops
    /// against. Omit for a device that holds no owner key.
    pub fn with_owner_pub(mut self, owner_pub: Option<[u8; 32]>) -> Self {
        self.owner_pub = owner_pub;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn keystore(&self) -> RootKeyStore {
        RootKeyStore::new(&self.root)
    }

    /// Take the same-root engine election (`up.lock`) without waiting. A
    /// competing Core or CLI daemon on this config makes this return `None`, so
    /// only one engine serves a root.
    pub fn try_acquire_engine_lease(&self) -> io::Result<Option<CoreLease>> {
        create_private_dir_all(&self.root)?;
        Ok(StoreLock::try_acquire(&self.root.join("up.lock"))?
            .map(|lock| CoreLease { _lock: lock }))
    }

    pub fn devices_path(&self) -> PathBuf {
        self.root.join(DEVICES_FILE)
    }

    pub fn devices_lock_path(&self) -> PathBuf {
        self.root.join(DEVICES_LOCK_FILE)
    }

    pub fn cap_store_path(&self) -> PathBuf {
        self.root.join("caps.json")
    }

    pub fn local_device_cert_path(&self) -> PathBuf {
        self.root.join(LOCAL_DEVICE_CERT_FILE)
    }

    fn provisional_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("provisional_{name}.json"))
    }

    /// Lock, read, mutate, and atomically write `devices.json`. The
    /// read-modify-write is atomic across processes via the lock sidecar, so a
    /// daemon's liveness sweep and a concurrent `grant`/`revoke`/`add`/`join`
    /// cannot lose each other's update. The closure runs on the freshly-read
    /// array; if it returns Err the file is NOT written, and if the store cannot
    /// be read or parsed the write is skipped too.
    pub fn with_devices_mut<T>(&self, f: impl FnOnce(&mut Vec<Value>) -> Result<T>) -> Result<T> {
        let p = self.devices_path();
        if let Some(dir) = p.parent() {
            create_private_dir_all(dir)
                .with_context(|| format!("create config dir {}", dir.display()))?;
        }
        let _lock = StoreLock::acquire(&self.devices_lock_path())
            .with_context(|| format!("lock {}", self.devices_lock_path().display()))?;
        let mut arr: Vec<Value> = match std::fs::read_to_string(&p) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(|e| CorruptStore::new(p.clone(), e.to_string()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(anyhow::anyhow!("read devices.json: {e}")),
        };
        let out = f(&mut arr)?;
        keep_backup(&p);
        secret_write::SecretFile::write_str(&p, &serde_json::to_string_pretty(&arr)?)
            .context("atomic write devices.json")?;
        Ok(out)
    }

    /// The capability store array, already parsed (empty when missing or
    /// unreadable). The peer loop hands this to `filament-cap`'s pure evaluators.
    pub fn cap_store(&self) -> Vec<Value> {
        self.load_cap_store()
    }

    /// The protocol rendezvous derivation shared by pairing and fleet. Pure.
    pub fn channel_of(secret: &str) -> String {
        channel_of(secret)
    }

    /// The raw records, tolerating a missing or malformed store (the read-side
    /// contract every existing caller had).
    pub fn devices_records(&self) -> Vec<Value> {
        std::fs::read_to_string(self.devices_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .unwrap_or_default()
    }

    /// `(name, secret)` pairs for records that have a pair secret. A record
    /// without one is a fleet index entry, not a dial target.
    pub fn devices_load(&self) -> Vec<(String, String)> {
        self.devices_records()
            .iter()
            .filter_map(|d| {
                Some((
                    d["name"].as_str()?.to_string(),
                    d["secret"].as_str()?.to_string(),
                ))
            })
            .collect()
    }

    pub fn device_cert_for(&self, name: &str) -> Option<DeviceCert> {
        self.devices_records()
            .into_iter()
            .find(|d| d["name"].as_str() == Some(name))
            .and_then(|d| DeviceCert::from_json(&d["deviceCert"]))
    }

    /// The certificate stored for `name` IF it is still valid right now.
    pub fn device_cert_valid_for(&self, name: &str) -> Option<DeviceCert> {
        self.device_cert_for(name)
            .filter(|c| c.verify(now_secs()).is_ok())
    }

    pub fn device_record_exists(&self, name: &str) -> bool {
        self.devices_records()
            .iter()
            .any(|d| d["name"].as_str() == Some(name))
    }

    pub fn device_name_for_pub(&self, device_pub: &[u8; 32]) -> Option<String> {
        let key = hex::encode(device_pub);
        self.devices_records()
            .iter()
            .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
            .and_then(|d| d["name"].as_str().map(str::to_string))
    }

    pub fn devices_find_by_device_pub(&self, device_pub: &[u8; 32]) -> Option<Value> {
        let key = hex::encode(device_pub);
        self.devices_records()
            .into_iter()
            .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
    }

    /// Is the stored record named `name` revoked? False when there is no
    /// record. (The separate revoked-key list is checked by the caller: it is
    /// fleet state, not the device store.)
    pub fn device_record_revoked(&self, name: &str) -> bool {
        self.devices_records()
            .iter()
            .any(|d| d["name"].as_str() == Some(name) && record_is_revoked(d))
    }

    /// The key revocations at `revoked-keys.json`, fail-closed: absent is
    /// empty, unreadable or unparseable is an error.
    pub fn key_revocations_path(&self) -> PathBuf {
        self.root.join("revoked-keys.json")
    }

    fn load_key_revocations(&self) -> std::result::Result<Vec<Value>, ()> {
        let path = self.key_revocations_path();
        match std::fs::metadata(&path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(()),
            Ok(_) => {}
        }
        let raw = std::fs::read_to_string(&path).map_err(|_| ())?;
        serde_json::from_str::<Vec<Value>>(&raw).map_err(|_| ())
    }

    /// Is this device key revoked by the separate key list, at `now`?
    pub fn device_key_revoked(&self, device_pub: &[u8; 32], now: u64) -> bool {
        let key = hex::encode(device_pub);
        match self.load_key_revocations() {
            Ok(entries) => entries.iter().any(|e| {
                e["devicePub"].as_str() == Some(key.as_str())
                    && e["certExpires"].as_u64().map_or(true, |exp| exp > now)
            }),
            Err(()) => true,
        }
    }

    /// The store half of `device_cert_revoked`, with the same fail-closed
    /// reading: an absent store means no records; an existing but unreadable or
    /// unparseable store is treated as revoked, never as "nothing". The
    /// separate key list is consulted first.
    pub fn device_cert_revoked(&self, device_pub: &[u8; 32]) -> bool {
        if self.device_key_revoked(device_pub, now_secs()) {
            return true;
        }
        let p = self.devices_path();
        match std::fs::metadata(&p) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
            Err(_) => return true,
            Ok(_) => {}
        }
        let Ok(raw) = std::fs::read_to_string(&p) else {
            return true;
        };
        let Ok(arr) = serde_json::from_str::<Vec<Value>>(&raw) else {
            return true;
        };
        let key = hex::encode(device_pub);
        match arr
            .iter()
            .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
        {
            None => false, // unknown device, not revoked
            Some(d) => {
                d["certRevoked"].as_bool().unwrap_or(false) || self.sibling_record_delisted(d)
            }
        }
    }

    /// Fleet auto-mesh revocation, as seen from a JOINED device.
    ///
    /// A sibling is a device we never paired with: we hold no pair secret for
    /// it, only the index record a verified `fleet-hello` wrote. We did not
    /// decide to trust it, the owner did, by certifying it. So the owner is
    /// also the only one who can withdraw that decision, and the owner's
    /// statement of who is still in the fleet is the signed roster it pushes
    /// (`recv::roster`). A sibling the newest roster we hold no longer lists
    /// was revoked or forgotten on the owner, and is refused here exactly as a
    /// locally revoked device is.
    ///
    /// The roster only ever NARROWS: being listed authorizes nothing (the
    /// certificate is still the evidence, and capability is still the gate).
    /// Not transitive: the roster is signed by the owner key this device
    /// already holds, never by a peer.
    ///
    /// Not delisted, by construction: anything on the owner device (its own
    /// records are authoritative), a device we hold a pair secret for (that is
    /// our own pairwise decision, unchanged by auto-mesh), and a certificate
    /// from a different owner (cross-owner behaviour is unchanged).
    fn sibling_record_delisted(&self, record: &Value) -> bool {
        if record["secret"].as_str().is_some_and(|s| !s.is_empty()) {
            return false;
        }
        let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) else {
            return false;
        };
        if self.owner_pub_from_keystore().is_some() {
            return false;
        }
        let Some(owner) = self.owner_pub_for_resources(None) else {
            return false;
        };
        if cert.user_pub != owner {
            return false;
        }
        !self.owner_roster_lists(&cert.device_pub, &owner)
    }

    /// May a same-owner sibling be admitted over the fleet channel at all?
    /// On the owner device: yes (its local records and revocations decide).
    /// On a joined device: only when the newest owner-signed roster it holds
    /// lists the device. No roster held means no admission: without a roster
    /// there is no channel by which a revocation could reach us, so admitting
    /// would make revocation unenforceable here. Expiry of the held roster is
    /// deliberately not consulted: it is still the owner's latest statement,
    /// and a listing can only narrow.
    pub fn sibling_admissible(&self, device_pub: &[u8; 32]) -> bool {
        if self.owner_pub_from_keystore().is_some() {
            return true;
        }
        let Some(owner) = self.owner_pub_for_resources(None) else {
            return false;
        };
        self.owner_roster_lists(device_pub, &owner)
    }

    /// Does the stored roster (signed by `owner`, verified at receipt) list
    /// `device_pub`? A missing, unreadable or foreign-owner roster lists no one.
    pub fn owner_roster_lists(&self, device_pub: &[u8; 32], owner: &[u8; 32]) -> bool {
        let Ok(raw) = std::fs::read_to_string(self.root.join("roster.json")) else {
            return false;
        };
        let Ok(r) = serde_json::from_str::<Value>(&raw) else {
            return false;
        };
        if r["owner_pub"].as_str() != Some(hex::encode(owner).as_str()) {
            return false;
        }
        let key = hex::encode(device_pub);
        r["devices"]
            .as_array()
            .is_some_and(|a| a.iter().any(|d| d["device_pub"].as_str() == Some(key.as_str())))
    }

    /// Update the `lastSeen` timestamp and overlay addresses for a known device.
    pub fn devices_touch(
        &self,
        name: &str,
        v6: Option<std::net::Ipv6Addr>,
        v4: Option<std::net::Ipv4Addr>,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let _ = self.devices_touch_at(name, v6, v4, now);
    }

    /// Clock-injectable form of [`DeviceStore::devices_touch`].
    pub fn devices_touch_at(
        &self,
        name: &str,
        v6: Option<std::net::Ipv6Addr>,
        v4: Option<std::net::Ipv4Addr>,
        now: u64,
    ) -> Result<()> {
        self.with_devices_mut(|arr| {
            for d in arr.iter_mut() {
                if d["name"].as_str() == Some(name) {
                    d["lastSeen"] = json!(now);
                    if let Some(v6) = v6 {
                        d["overlayV6"] = json!(v6.to_string());
                    }
                    if let Some(v4) = v4 {
                        d["overlayV4"] = json!(v4.to_string());
                    }
                    break;
                }
            }
            Ok(())
        })
    }

    /// Read the `lastSeen` timestamp and overlay addresses for a known device.
    pub fn devices_info(&self, name: &str) -> Option<(u64, Option<String>, Option<String>)> {
        let arr = self.devices_records();
        let d = arr.iter().find(|d| d["name"].as_str() == Some(name))?;
        let last_seen = d["lastSeen"].as_u64();
        let v6 = d["overlayV6"].as_str().map(|s| s.to_string());
        let v4 = d["overlayV4"].as_str().map(|s| s.to_string());
        Some((last_seen.unwrap_or(0), v6, v4))
    }

    /// Sweep the device store for lapsed delegated records. Returns how many
    /// records newly lapsed.
    pub fn devices_sweep_lapsed(&self, now: u64) -> usize {
        self.with_devices_mut(|arr| Ok(sweep_lapsed(arr, now)))
            .unwrap_or(0)
    }

    pub fn devices_remove(&self, name: &str) -> Result<()> {
        self.with_devices_mut(|arr| {
            arr.retain(|d| d["name"].as_str() != Some(name));
            Ok(())
        })
    }

    /// Store a pair secret handed to us over the NETWORK (`pair-keep`,
    /// `pair-intro`) as a NEW record and return the name it landed under. Never
    /// re-keys an existing record, whatever name the peer asked for.
    pub fn devices_store(&self, name: &str, secret: &str) -> Result<String> {
        self.devices_store_new(name, secret, None)
    }

    pub fn devices_store_new(
        &self,
        name: &str,
        secret: &str,
        introduced_by: Option<&str>,
    ) -> Result<String> {
        let clean = sanitize_device_name(name);
        self.with_devices_mut(|arr| insert_new_peer_record(arr, &clean, secret, introduced_by))
    }

    pub fn devices_store_joined_owner(
        &self,
        owner_name: &str,
        secret: &str,
        owner_cert: &DeviceCert,
        caps: &[String],
        scope: u8,
    ) -> Result<String> {
        let clean = sanitize_device_name(owner_name);
        self.with_devices_mut(|arr| {
            place_joined_owner(arr, &clean, secret, owner_cert, caps, scope)
        })
    }

    pub fn device_was_introduced(&self, name: &str) -> bool {
        self.devices_records()
            .iter()
            .find(|d| d["name"].as_str() == Some(name))
            .is_some_and(|d| d.get("introducedBy").is_some_and(|v| !v.is_null()))
    }

    /// Record what the owner invited this device as (`person`). Display only:
    /// the signed ceiling, not this field, bounds what the device may do.
    pub fn devices_mark_invited_as(&self, name: &str, kind: &str) -> Result<()> {
        self.with_devices_mut(|arr| {
            if let Some(rec) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
                rec["invitedAs"] = json!(kind);
            }
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn devices_upsert_atomic(
        &self,
        name: &str,
        secret: Option<&str>,
        cert: Option<&DeviceCert>,
        caps: Option<&[String]>,
        scope: Option<u8>,
        user_key_hex: Option<&str>,
        delegated: Option<(&[String], u64, u64, u64)>,
        allow_reanchor: bool,
    ) -> Result<String> {
        let clean = sanitize_device_name(name);
        let name = clean.as_str();
        self.with_devices_mut(|arr| {
            refuse_unowned_rewrite(arr, name, secret, cert, allow_reanchor)?;
            let final_name = upsert_peer_record(
                arr,
                name,
                secret,
                cert,
                caps,
                scope,
                user_key_hex,
                delegated,
            );
            Ok(final_name)
        })
    }

    /// Promote a provisional identity into the durable store through the one
    /// locked read-modify-write path.
    pub fn promote_provisional_identity(
        &self,
        name: &str,
        cert: &DeviceCert,
        scope: u8,
    ) -> Result<()> {
        self.with_devices_mut(|arr| {
            filament_id::apply_peer_identity(arr, name, cert, scope)
                .map_err(|e| anyhow::anyhow!("{e}"))
        })
        .map(|_| ())
    }

    /// The vouch write: guard and write in ONE lock cycle.
    pub fn update_peer_identity(
        &self,
        name: &str,
        peer_cert: &DeviceCert,
        scope: u8,
    ) -> Result<()> {
        self.with_devices_mut(|arr| {
            filament_id::apply_peer_identity(arr, name, peer_cert, scope)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            upsert_peer_record(
                arr,
                name,
                None,
                Some(peer_cert),
                None,
                Some(scope),
                None,
                None,
            );
            Ok(())
        })?;
        Ok(())
    }

    pub fn mark_bounded_cap_source(
        &self,
        name: &str,
        capability: &str,
        source: &str,
    ) -> Result<()> {
        self.with_devices_mut(|arr| {
            let Some(device) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) else {
                anyhow::bail!("unknown device '{name}'")
            };
            let obj = device
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("invalid device record"))?;
            let mut sources = obj
                .get("capSources")
                .and_then(|v| v.as_object())
                .cloned()
                .unwrap_or_default();
            sources.insert(capability.to_string(), json!(source));
            obj.insert("capSources".into(), json!(sources));
            Ok(())
        })
    }

    /// Mark a device record lapsed immediately (advisory depart, or manual).
    /// The record is KEPT (evidence survives). Returns the device name.
    pub fn mark_lapsed_now(&self, device_pub: &[u8; 32]) -> Option<String> {
        let key = hex::encode(device_pub);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.with_devices_mut(|arr| {
            let name = arr
                .iter()
                .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(&key))
                .and_then(|d| d["name"].as_str().map(str::to_string))
                .ok_or_else(|| anyhow::anyhow!("device not in the store"))?;
            for d in arr.iter_mut() {
                if d["name"].as_str() == Some(&name) {
                    d["principalState"] = json!(PRINCIPAL_STATE_LAPSED);
                    d["lapsedAt"] = json!(now);
                    break;
                }
            }
            Ok(name)
        })
        .ok()
    }

    /// The name a device was introduced under, used by the capability source
    /// bookkeeping. Kept as a read helper for callers that already have the
    /// record.
    pub fn any_shell_grant(&self) -> bool {
        !shell_grant_names_at(&self.devices_path()).is_empty()
    }

    /// The persisted principal for a certificate. `own_user_pub` is the owner
    /// key this device trusts, when it has one; the caller supplies it so this
    /// module never guesses at host policy.
    pub fn persisted_principal_for_cert(
        &self,
        cert: &DeviceCert,
        own_user_pub: Option<&[u8; 32]>,
    ) -> (PrincipalKind, Option<u64>, Option<u64>, Option<u64>) {
        principal_from_records(&self.devices_records(), cert, own_user_pub)
    }

    /// This device's own certificate as stored, with the same three sources the
    /// CLI always used: the local certificate record, then the record under the
    /// process display name, then any record whose key is this device's key.
    pub fn local_device_cert(
        &self,
        local_device_pub: Option<&[u8; 32]>,
        display_name: &str,
    ) -> Option<DeviceCert> {
        if let (Some(local_device_pub), Ok(raw)) = (
            local_device_pub,
            std::fs::read_to_string(self.local_device_cert_path()),
        ) {
            if let Ok(value) = serde_json::from_str::<Value>(&raw) {
                if let Some(cert) = DeviceCert::from_json(&value["cert"]) {
                    if cert.device_pub == *local_device_pub && cert.verify(now_secs()).is_ok() {
                        return Some(cert);
                    }
                }
            }
        }
        if let Some(cert) = self.device_cert_for(display_name) {
            if cert.verify(now_secs()).is_ok() {
                return Some(cert);
            }
        }
        let local_device_pub = local_device_pub?;
        self.devices_records().into_iter().find_map(|d| {
            let cert = DeviceCert::from_json(&d["deviceCert"])?;
            (cert.device_pub == *local_device_pub && cert.verify(now_secs()).is_ok())
                .then_some(cert)
        })
    }

    /// This device's own certificate as stored, WITHOUT the expiry check: for
    /// saying "your access expired" truthfully, never for authorizing anything.
    pub fn own_cert_ignoring_expiry(&self, local_device_pub: &[u8; 32]) -> Option<DeviceCert> {
        let raw = std::fs::read_to_string(self.local_device_cert_path()).ok()?;
        let value: Value = serde_json::from_str(&raw).ok()?;
        let cert = DeviceCert::from_json(&value["cert"])?;
        (cert.device_pub == *local_device_pub).then_some(cert)
    }

    /// The key that identifies "same mesh as me": the owner key if this device
    /// holds one, else the issuer key in its own certificate.
    pub fn owner_pub_for_resources(&self, local_device_pub: Option<&[u8; 32]>) -> Option<[u8; 32]> {
        if let Ok(Some(key)) = UserKey::load(&self.keystore()) {
            return Some(key.public_key_bytes());
        }
        // The old process path did not require the overlay key to be readable
        // before reading the certificate's issuer: a joined device with a
        // broken overlay key still answered "who do I answer to". Keep that
        // safe fallback, then prefer the local-key-matched certificate when
        // the overlay key is available.
        if let Some(cert) = local_device_pub.and_then(|p| self.own_cert_ignoring_expiry(p)) {
            return Some(cert.user_pub);
        }
        self.local_device_cert_record()
            .as_ref()
            .and_then(|record| DeviceCert::from_json(&record["cert"]))
            .map(|cert| cert.user_pub)
    }

    /// The owner key from the explicit keystore, when this device holds one.
    pub fn owner_pub_from_keystore(&self) -> Option<[u8; 32]> {
        UserKey::load(&self.keystore())
            .ok()
            .flatten()
            .map(|key| key.public_key_bytes())
    }

    /// Whether this instance has an identity at all: a user key in the
    /// explicit keystore, or a local certificate record.
    pub fn has_identity(&self) -> bool {
        self.owner_pub_from_keystore().is_some() || self.local_device_cert_path().exists()
    }

    /// Bootstrap internal identity only for a requested mutation. Shares the
    /// CLI's cross-process identity lock; repeated inspection must not call it.
    /// Never replace an existing/corrupt owner key or turn a joined device into
    /// a new owner. The explicit root must already exist with host permissions.
    pub fn ensure_identity_on_mutation(&self) -> Result<()> {
        let _lock = StoreLock::acquire(&self.root.join("identity.lock"))
            .context("lock identity bootstrap")?;
        if UserKey::load(&self.keystore())?.is_some() || self.local_device_cert_path().exists() {
            return Ok(());
        }
        filament_id::PendingIdentity::generate()?.commit(&self.keystore())?;
        Ok(())
    }

    /// Explicit recovery-confirmed creation participates in the same lock as
    /// implicit bootstrap, so the two mutation paths cannot replace each other.
    pub fn commit_pending_identity(&self, pending: filament_id::PendingIdentity) -> Result<UserKey> {
        let _lock = StoreLock::acquire(&self.root.join("identity.lock"))
            .context("lock identity commit")?;
        anyhow::ensure!(!self.local_device_cert_path().exists(), "this device already has joined identity state");
        pending.commit(&self.keystore())
    }

    /// Any unexpired armed invitation? Prunes expired entries on read, so the
    /// file self-cleans and a stale entry never keeps the enrollment room open.
    pub fn is_armed(&self) -> bool {
        let path = self.root.join("armed.json");
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return false;
        };
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            return false;
        };
        let arr = value.as_array().cloned().unwrap_or_default();
        let now = cap_now_secs();
        let before = arr.len();
        let entries: Vec<Value> = arr
            .into_iter()
            .filter(|e| {
                e["key_id"].as_str().is_some() && e["expires"].as_u64().is_some_and(|exp| exp > now)
            })
            .collect();
        if entries.len() != before {
            if let Ok(body) = serde_json::to_string_pretty(&entries) {
                let _ = secret_write::SecretFile::write_str(&path, &body);
            }
        }
        !entries.is_empty()
    }

    /// The `invitee_name` field recorded for an outstanding invitation, while
    /// it is unexpired. Explicit-root port of `cli/src/armed.rs`.
    pub fn invitee_name(&self, key_id: &str) -> Option<String> {
        let now = cap_now_secs();
        self.armed_entries()
            .into_iter()
            .find(|e| {
                e["key_id"].as_str() == Some(key_id)
                    && e["expires"].as_u64().is_some_and(|x| x > now)
            })
            .and_then(|e| e["name"].as_str().map(str::to_string))
            .filter(|n| !n.trim().is_empty())
    }

    /// The `invitee_kind` (`person`/`device`) recorded for an outstanding
    /// invitation, while it is unexpired.
    pub fn invitee_kind(&self, key_id: &str) -> Option<String> {
        let now = cap_now_secs();
        self.armed_entries()
            .into_iter()
            .find(|e| {
                e["key_id"].as_str() == Some(key_id)
                    && e["expires"].as_u64().is_some_and(|x| x > now)
            })
            .and_then(|e| e["kind"].as_str().map(str::to_string))
    }

    fn armed_entries(&self) -> Vec<Value> {
        let Ok(raw) = std::fs::read_to_string(self.root.join("armed.json")) else {
            return Vec::new();
        };
        serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    /// The owner-signed `cap_header` for resource "self", if this store has one.
    pub fn owner_cap_header(&self) -> Option<Value> {
        self.load_cap_store().into_iter().find(|e| {
            e.get("type").and_then(|v| v.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        })
    }

    /// The fleet rendezvous secret at this instance's `fleet.rv`, if any.
    pub fn fleet_rv(&self) -> Option<String> {
        let raw = std::fs::read_to_string(self.root.join("fleet.rv")).ok()?;
        let s = raw.trim().to_string();
        (hex::decode(&s).map(|b| b.len()).ok() == Some(32)).then_some(s)
    }

    /// The owner's copy, minted on first use. Only a device holding the owner
    /// key calls this; every other device receives it at enrollment.
    pub fn fleet_rv_load_or_create(&self) -> anyhow::Result<String> {
        if let Some(s) = self.fleet_rv() {
            return Ok(s);
        }
        let s = crate::secret::fresh_secret();
        self.store_fleet_rv(&s)?;
        Ok(s)
    }

    /// Persist a fleet rendezvous secret received at enrollment.
    pub fn store_fleet_rv(&self, hex_secret: &str) -> anyhow::Result<()> {
        if hex::decode(hex_secret).map(|b| b.len()).ok() != Some(32) {
            anyhow::bail!("fleet rendezvous secret must be 32 bytes of hex");
        }
        secret_write::SecretFile::write_str(&self.root.join("fleet.rv"), hex_secret)?;
        Ok(())
    }

    /// Whether `name` is pinned to a DIFFERENT device identity than
    /// `device_pub_hex`.
    pub fn name_pinned_by_other(&self, name: &str, device_pub_hex: &str) -> bool {
        self.devices_records().iter().any(|d| {
            d["name"].as_str() == Some(name)
                && d["deviceCert"]["devicePub"]
                    .as_str()
                    .is_some_and(|p| p != device_pub_hex)
        })
    }

    /// Durable invitation-use count, keyed by the enrolment public key. This is
    /// the cross-restart replay guard; the in-memory burn is only the live
    /// engine's fast path. The whole read/modify/write is serialized across
    /// processes by the per-root sidecar lock, so two stores over the same root
    /// cannot both admit the same one-use invitation.
    pub fn record_invitation_use(
        &self,
        key_id: &str,
        reuse: &Reuse,
        expires: u64,
        now: u64,
    ) -> std::result::Result<(), InvitationRefusal> {
        record_invitation_use_at(
            &self.root.join(USED_INVITATIONS_FILE),
            key_id,
            reuse,
            expires,
            now,
        )
    }

    /// Withdraw an outstanding invitation so it can never be claimed again.
    /// See [`withdraw_invitation_at`].
    pub fn withdraw_invitation(
        &self,
        key_id: &str,
        expires: u64,
        now: u64,
    ) -> std::result::Result<(), InvitationRefusal> {
        withdraw_invitation_at(&self.root.join(USED_INVITATIONS_FILE), key_id, expires, now)
    }

    /// Is this invitation withdrawn? `Err` when the file cannot be read: the
    /// caller decides how to fail (the enrolment path refuses).
    pub fn invitation_withdrawn(
        &self,
        key_id: &str,
        now: u64,
    ) -> std::result::Result<bool, InvitationRefusal> {
        invitation_withdrawn_at(&self.root.join(USED_INVITATIONS_FILE), key_id, now)
    }

    /// Every unexpired line of the durable use file, for the owner's listing.
    /// An unreadable file lists nothing (the listing is advisory; admission
    /// fails closed on its own).
    pub fn invitation_ledger(&self, now: u64) -> Vec<InvitationLedgerEntry> {
        invitation_ledger_at(&self.root.join(USED_INVITATIONS_FILE), now).unwrap_or_default()
    }

    /// What to re-invite an expired delegated device with: the ceiling it was
    /// admitted with and the lifetime its invitation granted. Pure over the
    /// record, so the refusal text and the re-invitation cannot drift.
    pub fn reinvite_for(&self, device_pub: &[u8; 32]) -> Option<crate::refusal::Reinvite> {
        let key = hex::encode(device_pub);
        self.devices_records()
            .iter()
            .find(|d| d["deviceCert"]["devicePub"].as_str() == Some(key.as_str()))
            .and_then(reinvite_from_record)
    }

    /// The local certificate record's `{name, cert}` object, if it parses.
    pub fn local_device_cert_record(&self) -> Option<Value> {
        std::fs::read_to_string(self.local_device_cert_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
    }

    /// Persist the local certificate record atomically, owner-only.
    pub fn write_local_device_cert_record(&self, record: &Value) -> Result<()> {
        let path = self.local_device_cert_path();
        secret_write::SecretFile::write_str(&path, &serde_json::to_string_pretty(record)?)
            .with_context(|| format!("write local device certificate to {}", path.display()))
    }

    // ---------------------------------------------------------- provisional --

    /// Store a provisional identity (held in a sidecar, not durable trust) for
    /// the later overlay check.
    pub fn store_provisional_identity(&self, name: &str, peer_cert: &DeviceCert) -> Result<()> {
        let p = self.provisional_path(name);
        let now = now_secs();
        if let Some(dir) = p.parent() {
            sweep_stale_provisional(dir, now);
        }
        let data = json!({
            "name": name,
            "deviceCert": peer_cert.to_json(),
            "storedAt": now
        });
        secret_write::SecretFile::write_str(&p, &serde_json::to_string_pretty(&data)?)?;
        Ok(())
    }

    pub fn load_provisional_identity(&self, name: &str) -> Option<DeviceCert> {
        let raw = std::fs::read_to_string(self.provisional_path(name)).ok()?;
        let v: Value = serde_json::from_str(&raw).ok()?;
        DeviceCert::from_json(&v["deviceCert"])
    }

    pub fn clear_provisional_identity(&self, name: &str) {
        let _ = std::fs::remove_file(self.provisional_path(name));
    }

    // ---------------------------------------------------------- capabilities --

    fn load_cap_store(&self) -> Vec<Value> {
        std::fs::read_to_string(self.cap_store_path())
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    fn save_cap_store(&self, store: &[Value]) -> io::Result<()> {
        let p = self.cap_store_path();
        let data = serde_json::to_string_pretty(&json!(store))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        before_write_json_array(&p)?;
        secret_write::SecretFile::write_str(&p, &data)
    }

    /// Every capability OP this device holds that the FLEET owner signed.
    pub fn owner_signed_cap_ops(&self) -> Vec<Value> {
        let Some(owner) = self.owner_pub else {
            return Vec::new();
        };
        self.load_cap_store()
            .into_iter()
            .filter(|e| {
                e.get("type").and_then(|v| v.as_str()) != Some(CAP_TOMBSTONE_TYPE)
                    && CapOp::from_json(e)
                        .map(|op| op.grantor == owner)
                        .unwrap_or(false)
            })
            .collect()
    }

    /// Merge fleet policy received from a peer, keeping only what the OWNER
    /// signed, and of that only REVOCATIONS. Returns how many were newly stored.
    ///
    /// Grant and modify ops are dropped. The owner's grant ops are about the
    /// owner's own resource, whose id is derived from the owner key and so reads
    /// the same on every fleet device: merging them let a grant made ON the
    /// owner authorize the same subject on every other device, which is not
    /// what the owner decided, and it was the capability store's only
    /// network-origin write. Authority for another fleet device now travels as
    /// an owner-signed set naming that device (`verify_and_store_fleet_grants`),
    /// kept OUT of the capability store. A revocation only ever narrows, so it
    /// is still accepted.
    pub fn merge_owner_cap_ops(&self, ops: &[Value]) -> usize {
        self.merge_owner_cap_ops_outcome(ops).unwrap_or(0)
    }

    /// The diagnosable form of [`DeviceStore::merge_owner_cap_ops`]. A storage
    /// failure is returned to the adapter, which can log it; the port method
    /// keeps its `usize` contract and reports "nothing merged" (0) on error.
    pub fn merge_owner_cap_ops_outcome(&self, ops: &[Value]) -> anyhow::Result<usize> {
        let Some(owner) = self.owner_pub else {
            return Ok(0);
        };
        let mut store = self.load_cap_store();
        let now = cap_now_secs();
        let mut added = 0usize;
        for v in ops {
            let Some(op) = CapOp::from_json(v) else {
                continue;
            };
            if op.grantor != owner || op.verify(&owner, now).is_err() {
                continue;
            }
            if op.op != filament_cap::capability::CapOpKind::Revoke {
                continue;
            }
            if superseded_by_tombstone(&store, &op) {
                continue;
            }
            let dup = store.iter().any(|e| e == v);
            if !dup {
                store.push(v.clone());
                added += 1;
            }
        }
        if added > 0 {
            self.save_cap_store(&store)
                .map_err(|e| anyhow::anyhow!("fleet policy not stored: {e}"))?;
        }
        Ok(added)
    }
}

/// May this use be admitted, given `uses` already recorded? Pure.
pub fn admit_invitation_use(
    uses: u64,
    reuse: &Reuse,
) -> std::result::Result<(), InvitationRefusal> {
    match reuse {
        Reuse::Once if uses >= 1 => Err(InvitationRefusal::AlreadyUsed),
        Reuse::N(max) if uses >= u64::from(*max) => Err(InvitationRefusal::UseLimitReached),
        _ => Ok(()),
    }
}

/// The lock sidecar for a use file: the data file's name with `.lock` appended.
/// It lives beside the data file, so the lock is per root and every caller that
/// names the same data file names the same lock.
fn invitation_use_lock_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    path.with_file_name(name)
}

/// Parse the durable use list, refusing anything that is not the exact shape
/// this store writes. A malformed entry must not be read as `uses: 0` (which
/// would reset a consumed invitation), so the whole file is `Unverifiable`
/// rather than silently rewritten. Extra fields are kept: the legacy format is
/// the object keys `keyId`, `uses` and `expires`, and unknown keys do not make
/// an otherwise valid count ambiguous.
fn parse_invitation_uses(raw: &str) -> std::result::Result<Vec<Value>, InvitationRefusal> {
    let entries: Vec<Value> =
        serde_json::from_str(raw).map_err(|_| InvitationRefusal::Unverifiable)?;
    {
        let mut key_ids = HashSet::with_capacity(entries.len());
        for entry in &entries {
            let object = entry.as_object().ok_or(InvitationRefusal::Unverifiable)?;
            let key_id = object
                .get("keyId")
                .and_then(Value::as_str)
                .ok_or(InvitationRefusal::Unverifiable)?;
            object
                .get("uses")
                .and_then(Value::as_u64)
                .ok_or(InvitationRefusal::Unverifiable)?;
            object
                .get("expires")
                .and_then(Value::as_u64)
                .ok_or(InvitationRefusal::Unverifiable)?;
            // `withdrawn` is optional (older files never wrote it), but when it
            // is present it must be a boolean: a value this store cannot read
            // must not be taken as "not withdrawn".
            if object.get("withdrawn").is_some_and(|w| !w.is_boolean()) {
                return Err(InvitationRefusal::Unverifiable);
            }
            if !key_ids.insert(key_id) {
                // Two counts for one invitation are ambiguous. Refusing is safer
                // than picking one and overwriting the other (which could reset a
                // consumed count).
                return Err(InvitationRefusal::Unverifiable);
            }
        }
    }
    Ok(entries)
}

/// Count one use of `key_id` at an explicit path. The use is written BEFORE the
/// caller admits anything, so a crash can lose a use but never grant an extra
/// one. A file that exists but cannot be parsed (or contains an entry whose
/// `uses`/`keyId`/`expires` is missing or is the wrong type) is `Unverifiable`
/// (fail closed), and such a file is never overwritten.
///
/// The ENTIRE read/admit/write runs under an exclusive sidecar lock beside
/// `path`. The in-memory burn is per process, so without this lock two
/// `DeviceStore` instances over one root could both read `uses: 0` and both
/// write `uses: 1`, admitting a one-use invitation twice. A lock that cannot be
/// taken is `Unverifiable`: "I could not check whether this was used" is not
/// "it was not used".
pub fn record_invitation_use_at(
    path: &Path,
    key_id: &str,
    reuse: &Reuse,
    expires: u64,
    now: u64,
) -> std::result::Result<(), InvitationRefusal> {
    if let Some(dir) = path.parent() {
        create_private_dir_all(dir).map_err(|_| InvitationRefusal::Unverifiable)?;
    }
    // Bind the guard before the read: it is released only after the atomic
    // write below, so the whole read-modify-write is one critical section.
    let _lock = StoreLock::acquire(&invitation_use_lock_path(path))
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    let mut entries = match std::fs::read_to_string(path) {
        Ok(raw) => parse_invitation_uses(&raw)?,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(_) => return Err(InvitationRefusal::Unverifiable),
    };
    entries.retain(|e| e["expires"].as_u64().map_or(true, |x| x > now));
    let existing = entries.iter().find(|e| e["keyId"].as_str() == Some(key_id));
    // A withdrawn invitation is refused before its count is even consulted:
    // `--reuse forever` has no count to run out, and a bounded one may have
    // uses left. Withdrawal is the owner's word that none of them remain.
    if existing.is_some_and(|e| e["withdrawn"].as_bool() == Some(true)) {
        return Err(InvitationRefusal::Withdrawn);
    }
    let uses = existing.and_then(|e| e["uses"].as_u64()).unwrap_or(0);
    admit_invitation_use(uses, reuse)?;
    let next = uses.checked_add(1).ok_or(InvitationRefusal::Unverifiable)?;
    entries.retain(|e| e["keyId"].as_str() != Some(key_id));
    entries.push(json!({
        "keyId": key_id,
        "uses": next,
        "expires": expires,
        "lastUsed": now,
    }));
    let body =
        serde_json::to_string_pretty(&entries).map_err(|_| InvitationRefusal::Unverifiable)?;
    keep_backup(path);
    secret_write::SecretFile::write_str(path, &body)
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    Ok(())
}

fn read_invitation_uses(path: &Path) -> std::result::Result<Vec<Value>, InvitationRefusal> {
    match std::fs::read_to_string(path) {
        Ok(raw) => parse_invitation_uses(&raw),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(_) => Err(InvitationRefusal::Unverifiable),
    }
}

/// Withdraw `key_id` at an explicit path: from now on every claim of it is
/// refused with [`InvitationRefusal::Withdrawn`], by any process over this
/// root, across restarts, until the invitation's own expiry (after which it
/// cannot verify at all, so the line is pruned like a use count).
///
/// Runs under the same sidecar lock as [`record_invitation_use_at`], so a
/// claim and a withdrawal are ordered: a claim either counted before the
/// withdrawal (and the enrolment path re-checks before it admits anything), or
/// it reads the withdrawal and is refused. The use count already recorded is
/// kept, and `expires` is never shortened. An unreadable file is
/// `Unverifiable` and is left untouched, so the caller can say the withdrawal
/// did NOT happen rather than overwrite a count.
pub fn withdraw_invitation_at(
    path: &Path,
    key_id: &str,
    expires: u64,
    now: u64,
) -> std::result::Result<(), InvitationRefusal> {
    if let Some(dir) = path.parent() {
        create_private_dir_all(dir).map_err(|_| InvitationRefusal::Unverifiable)?;
    }
    let _lock = StoreLock::acquire(&invitation_use_lock_path(path))
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    let mut entries = read_invitation_uses(path)?;
    entries.retain(|e| e["expires"].as_u64().map_or(true, |x| x > now));
    let (uses, kept_expires) = entries
        .iter()
        .find(|e| e["keyId"].as_str() == Some(key_id))
        .map(|e| (e["uses"].as_u64().unwrap_or(0), e["expires"].as_u64().unwrap_or(0)))
        .unwrap_or((0, 0));
    entries.retain(|e| e["keyId"].as_str() != Some(key_id));
    entries.push(json!({
        "keyId": key_id,
        "uses": uses,
        "expires": expires.max(kept_expires),
        "withdrawn": true,
        "withdrawnAt": now,
    }));
    let body =
        serde_json::to_string_pretty(&entries).map_err(|_| InvitationRefusal::Unverifiable)?;
    keep_backup(path);
    secret_write::SecretFile::write_str(path, &body)
        .map_err(|_| InvitationRefusal::Unverifiable)?;
    Ok(())
}

/// Is `key_id` withdrawn at an explicit path? Read under the same lock as the
/// writers, so the answer is ordered against a withdrawal in progress.
pub fn invitation_withdrawn_at(
    path: &Path,
    key_id: &str,
    now: u64,
) -> std::result::Result<bool, InvitationRefusal> {
    let _lock = match StoreLock::acquire(&invitation_use_lock_path(path)) {
        Ok(lock) => lock,
        // No directory yet means no file: nothing was ever withdrawn here.
        Err(_) if !path.exists() && path.parent().is_some_and(|d| !d.exists()) => {
            return Ok(false)
        }
        Err(_) => return Err(InvitationRefusal::Unverifiable),
    };
    let entries = read_invitation_uses(path)?;
    Ok(entries.iter().any(|e| {
        e["keyId"].as_str() == Some(key_id)
            && e["expires"].as_u64().is_some_and(|x| x > now)
            && e["withdrawn"].as_bool() == Some(true)
    }))
}

/// Every unexpired line of the use file at an explicit path. Read-only.
pub fn invitation_ledger_at(
    path: &Path,
    now: u64,
) -> std::result::Result<Vec<InvitationLedgerEntry>, InvitationRefusal> {
    Ok(read_invitation_uses(path)?
        .iter()
        .filter_map(|e| {
            let expires = e["expires"].as_u64()?;
            (expires > now).then(|| InvitationLedgerEntry {
                key_id: e["keyId"].as_str().unwrap_or_default().to_string(),
                uses: e["uses"].as_u64().unwrap_or(0),
                expires,
                withdrawn: e["withdrawn"].as_bool() == Some(true),
            })
        })
        .collect())
}

/// Strip terminal escape sequences and control characters from a device
/// petname before it is stored. Pure.
pub fn sanitize_device_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        if !c.is_control() {
            out.push(c);
        }
    }
    out.trim().to_string()
}

/// The single moment a delegated device stops being recognized:
/// `min(cert_expiry, not_after, last_seen + max_offline)`.
pub fn effective_principal_deadline(
    cert_expires: u64,
    not_after: Option<u64>,
    last_seen: Option<u64>,
    max_offline: Option<u64>,
) -> (u64, DeadlineClock) {
    let mut deadline = cert_expires;
    let mut clock = DeadlineClock::CertExpiry;
    if let Some(na) = not_after {
        if na < deadline {
            deadline = na;
            clock = DeadlineClock::AbsoluteStop;
        }
    }
    if let (Some(ls), Some(mo)) = (last_seen, max_offline) {
        if ls > 0 {
            let budget_deadline = ls.saturating_add(mo);
            if budget_deadline < deadline {
                deadline = budget_deadline;
                clock = DeadlineClock::LivenessBudget;
            }
        }
    }
    (deadline, clock)
}

/// Resolve the persisted principal record for a device cert. A missing or
/// malformed record FAILS CLOSED as a ceiling-less delegated principal.
pub fn principal_from_records(
    records: &[Value],
    cert: &DeviceCert,
    own_user_pub: Option<&[u8; 32]>,
) -> (PrincipalKind, Option<u64>, Option<u64>, Option<u64>) {
    let record = records.iter().find(|record| {
        DeviceCert::from_json(&record["deviceCert"])
            .map(|stored| stored.device_pub == cert.device_pub)
            .unwrap_or(false)
    });
    if let Some(record) = record {
        if record["principalKind"].is_null() {
            return (PrincipalKind::OwnerDevice, None, None, None);
        }
        if record["principalKind"].as_str() == Some("delegated") {
            let caps = record["principalCeiling"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let expires = record["principalExpires"].as_u64().unwrap_or(0);
            let max_offline = record["principalMaxOffline"].as_u64();
            let last_seen = record["lastSeen"].as_u64();
            return (
                PrincipalKind::Delegated { caps },
                Some(expires),
                max_offline,
                last_seen,
            );
        }
        return (
            PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    let is_same_owner = own_user_pub
        .map(|owner| *owner == cert.user_pub)
        .unwrap_or(false);
    if is_same_owner {
        return (
            PrincipalKind::Delegated { caps: Vec::new() },
            Some(0),
            None,
            None,
        );
    }
    (PrincipalKind::OwnerDevice, None, None, None)
}

/// What to re-invite an expired delegated device with: the ceiling it was
/// admitted with and the lifetime its invitation granted (`principalIssued`,
/// stamped at enrolment, to `principalExpires`). Pure.
pub fn reinvite_from_record(record: &Value) -> Option<crate::refusal::Reinvite> {
    if record["principalKind"].as_str() != Some("delegated") {
        return None;
    }
    let ceiling: Vec<String> = record["principalCeiling"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .filter(|c| !c.starts_with("route:"))
                .collect()
        })
        .unwrap_or_default();
    let end = record["principalExpires"].as_u64()?;
    let start = record["principalIssued"]
        .as_u64()
        .or_else(|| record["addedAt"].as_u64())
        .unwrap_or(end);
    (!ceiling.is_empty()).then(|| crate::refusal::Reinvite {
        ceiling,
        lifetime: end.saturating_sub(start).max(1),
    })
}

/// Sweep the device records for lapsed delegated records. Pure.
pub fn sweep_lapsed(records: &mut Vec<Value>, now: u64) -> usize {
    let mut changed = 0;
    for record in records.iter_mut() {
        if record["principalKind"].as_str() != Some("delegated") {
            continue;
        }
        if record["certRevoked"].as_bool() == Some(true)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
            || record["principalState"].as_str() == Some(PRINCIPAL_STATE_LAPSED)
        {
            continue;
        }
        let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) else {
            continue;
        };
        let not_after = record["principalExpires"].as_u64();
        let last_seen = record["lastSeen"].as_u64();
        let max_offline = record["principalMaxOffline"].as_u64();
        let (deadline, _clock) =
            effective_principal_deadline(cert.expires, not_after, last_seen, max_offline);
        if deadline <= now {
            record["principalState"] = json!(PRINCIPAL_STATE_LAPSED);
            record["lapsedAt"] = json!(now);
            changed += 1;
        }
    }
    changed
}

/// Is this device record revoked (the certificate marker, or a durable device
/// revoke)? Pure.
pub fn record_is_revoked(record: &Value) -> bool {
    record["certRevoked"].as_bool() == Some(true)
        || record["principalState"].as_str() == Some(PRINCIPAL_STATE_REVOKED)
}

/// The names of records whose capability list includes `shell`.
pub fn shell_grant_names_at(path: &Path) -> Vec<String> {
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(arr) = serde_json::from_str::<Value>(&raw) else {
        return Vec::new();
    };
    let mut names: Vec<String> = arr
        .as_array()
        .into_iter()
        .flatten()
        .filter(|d| {
            d.get("caps")
                .and_then(|c| c.as_array())
                .map(|list| list.iter().any(|c| c.as_str() == Some("shell")))
                .unwrap_or(false)
        })
        .filter_map(|d| d.get("name").and_then(|n| n.as_str()).map(String::from))
        .collect();
    names.sort();
    names
}

/// Upsert the (secret, cert, caps, scope) fields for `name` into `arr` as ONE
/// record, returning the final stored name (auto-suffixed on a new-name
/// collision). Pure.
pub fn upsert_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: Option<&str>,
    cert: Option<&DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
) -> String {
    // For existing name, update in place preserving other fields.
    if let Some(existing) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
        if let Some(s) = secret {
            existing["secret"] = json!(s);
        }
        if let Some(c) = cert {
            existing["userKey"] = json!(hex::encode(c.user_pub));
            existing["deviceCert"] = c.to_json();
        } else if let Some(uk) = user_key_hex {
            existing["userKey"] = json!(uk);
        }
        if let Some(caps) = caps {
            existing["caps"] = json!(caps);
            existing["v"] = json!(2);
        }
        if let Some(sc) = scope {
            existing["identityScope"] = json!(sc);
        }
        if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
            existing["principalKind"] = json!("delegated");
            existing["principalCeiling"] = json!(ceiling);
            existing["principalExpires"] = json!(expires);
            existing["principalMaxOffline"] = json!(max_offline);
            existing["principalMaxOfflineCeiling"] = json!(max_offline_ceiling);
            existing["principalIssued"] = json!(now_secs());
            existing["principalState"] = Value::Null;
            if let Some(map) = existing.as_object_mut() {
                map.remove("lapsedAt");
            }
        }
        return existing["name"].as_str().unwrap_or(name).to_string();
    }

    // New device: auto-suffix if collision. Case-insensitive, as the store's
    // naming rule always was.
    let mut final_name = name.to_string();
    let taken = |a: &Vec<Value>, n: &str| {
        a.iter().any(|d| {
            d["name"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(n))
        })
    };
    if taken(arr, name) {
        let mut suffix = 2;
        let mut new_name = format!("{name}-{suffix}");
        while taken(arr, &new_name) {
            suffix += 1;
            new_name = format!("{name}-{suffix}");
        }
        eprintln!("  note: '{name}' already exists, pairing as '{new_name}'");
        final_name = new_name;
    }

    let mut obj = serde_json::Map::new();
    obj.insert("name".to_string(), json!(&final_name));
    if let Some(s) = secret {
        obj.insert("secret".to_string(), json!(s));
    }
    if let Some(c) = cert {
        obj.insert("userKey".to_string(), json!(hex::encode(c.user_pub)));
        obj.insert("deviceCert".to_string(), c.to_json());
    } else if let Some(uk) = user_key_hex {
        obj.insert("userKey".to_string(), json!(uk));
    }
    obj.insert("v".to_string(), json!(2));
    if let Some(caps) = caps {
        obj.insert("caps".to_string(), json!(caps));
    }
    if let Some(sc) = scope {
        obj.insert("identityScope".to_string(), json!(sc));
    }
    if let Some((ceiling, expires, max_offline, max_offline_ceiling)) = delegated {
        obj.insert("principalKind".to_string(), json!("delegated"));
        obj.insert("principalCeiling".to_string(), json!(ceiling));
        obj.insert("principalExpires".to_string(), json!(expires));
        obj.insert("principalMaxOffline".to_string(), json!(max_offline));
        obj.insert(
            "principalMaxOfflineCeiling".to_string(),
            json!(max_offline_ceiling),
        );
        obj.insert("principalIssued".to_string(), json!(now_secs()));
    }
    obj.insert(
        "addedAt".to_string(),
        json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)),
    );
    arr.push(Value::Object(obj));
    final_name
}

/// The writer's ownership guard: a cert under an existing name must match the
/// pinned key, and a secret under an existing name must be the same secret,
/// unless the caller holds the owner-decision opt-out. Pure.
pub fn refuse_unowned_rewrite(
    arr: &[Value],
    name: &str,
    secret: Option<&str>,
    cert: Option<&DeviceCert>,
    allow_reanchor: bool,
) -> Result<()> {
    if allow_reanchor {
        return Ok(());
    }
    let Some(existing) = arr.iter().find(|d| d["name"].as_str() == Some(name)) else {
        return Ok(());
    };
    if let Some(c) = cert {
        let incoming = hex::encode(c.device_pub);
        let pinned_matches = existing["deviceCert"]["devicePub"]
            .as_str()
            .is_some_and(|pinned| pinned == incoming.as_str());
        if !pinned_matches {
            anyhow::bail!(
                "refusing to re-anchor record '{name}': presented key {incoming} is not the pinned identity"
            );
        }
    }
    if let Some(s) = secret {
        if existing["secret"].as_str() != Some(s) {
            anyhow::bail!(
                "refusing to re-key record '{name}': a new pair secret for an existing device needs an owner re-pair (`tunlion add {name}` on the owner device)"
            );
        }
    }
    Ok(())
}

/// A name no record holds, compared case-insensitively. Pure.
pub fn free_device_name(arr: &[Value], name: &str) -> String {
    let taken = |n: &str| {
        arr.iter().any(|d| {
            d["name"]
                .as_str()
                .is_some_and(|e| e.eq_ignore_ascii_case(n))
        })
    };
    if !taken(name) {
        return name.to_string();
    }
    let mut suffix = 2u32;
    loop {
        let candidate = format!("{name}-{suffix}");
        if !taken(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

/// Insert a NEW secret-only record and never touch an existing one. Pure.
pub fn insert_new_peer_record(
    arr: &mut Vec<Value>,
    name: &str,
    secret: &str,
    introduced_by: Option<&str>,
) -> Result<String> {
    if arr.iter().any(|d| d["secret"].as_str() == Some(secret)) {
        anyhow::bail!("refusing to store a pair secret another device record already holds");
    }
    let free = free_device_name(arr, name);
    let stored = upsert_peer_record(arr, &free, Some(secret), None, None, None, None, None);
    if let Some(hub) = introduced_by {
        if let Some(rec) = arr
            .iter_mut()
            .find(|d| d["name"].as_str() == Some(stored.as_str()))
        {
            rec["introducedBy"] = json!(hub);
        }
    }
    Ok(stored)
}

/// Record the fleet owner a join acknowledgement certified, without re-keying
/// anything that is not provably that owner. Pure.
pub fn place_joined_owner(
    arr: &mut Vec<Value>,
    owner_name: &str,
    secret: &str,
    owner_cert: &DeviceCert,
    caps: &[String],
    scope: u8,
) -> Result<String> {
    let incoming = hex::encode(owner_cert.device_pub);
    let pinned_to = |d: &Value| d["deviceCert"]["devicePub"].as_str().map(str::to_string);
    if let Some(same) = arr
        .iter()
        .find(|d| pinned_to(d).as_deref() == Some(incoming.as_str()))
        .and_then(|d| d["name"].as_str().map(str::to_string))
    {
        return Ok(upsert_peer_record(
            arr,
            &same,
            Some(secret),
            Some(owner_cert),
            Some(caps),
            Some(scope),
            None,
            None,
        ));
    }
    if arr
        .iter()
        .any(|d| d["name"].as_str() == Some(owner_name) && pinned_to(d).is_some())
    {
        anyhow::bail!(
            "already have a different fleet owner recorded as '{owner_name}': forget it first, then join"
        );
    }
    if arr.iter().any(|d| d["secret"].as_str() == Some(secret)) {
        anyhow::bail!("refusing to store a pair secret another device record already holds");
    }
    let free = free_device_name(arr, owner_name);
    Ok(upsert_peer_record(
        arr,
        &free,
        Some(secret),
        Some(owner_cert),
        Some(caps),
        Some(scope),
        None,
        None,
    ))
}

/// Remove provisional identity records under `dir` older than
/// [`PROVISIONAL_TTL_SECS`] (by their `storedAt`, or the file's mtime when that
/// is unreadable). Returns how many were removed.
pub fn sweep_stale_provisional(dir: &Path, now: u64) -> usize {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in rd.flatten() {
        let path = entry.path();
        let is_provisional = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("provisional_") && n.ends_with(".json"));
        if !is_provisional {
            continue;
        }
        let stored_at = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|v| v["storedAt"].as_u64())
            .or_else(|| {
                entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
            })
            .unwrap_or(0);
        if now.saturating_sub(stored_at) >= PROVISIONAL_TTL_SECS
            && std::fs::remove_file(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

#[cfg(feature = "dispatch")]
mod port_impl {
    use super::*;
    use crate::recv::ports::RecvStore;
    use async_trait::async_trait;

    #[async_trait]
    impl RecvStore for DeviceStore {
        fn devices_path(&self) -> PathBuf {
            DeviceStore::devices_path(self)
        }

        fn devices_touch(
            &self,
            name: &str,
            v6: Option<std::net::Ipv6Addr>,
            v4: Option<std::net::Ipv4Addr>,
        ) {
            DeviceStore::devices_touch(self, name, v6, v4)
        }

        fn devices_remove(&self, name: &str) -> Result<()> {
            DeviceStore::devices_remove(self, name)
        }

        fn devices_store(&self, name: &str, secret: &str) -> Result<String> {
            DeviceStore::devices_store(self, name, secret)
        }

        fn devices_store_new(
            &self,
            name: &str,
            secret: &str,
            introduced_by: Option<&str>,
        ) -> Result<String> {
            DeviceStore::devices_store_new(self, name, secret, introduced_by)
        }

        fn device_was_introduced(&self, name: &str) -> bool {
            DeviceStore::device_was_introduced(self, name)
        }

        fn devices_sweep_lapsed(&self, now: u64) -> usize {
            DeviceStore::devices_sweep_lapsed(self, now)
        }

        fn devices_upsert_atomic(
            &self,
            name: &str,
            secret: Option<&str>,
            cert: Option<&DeviceCert>,
            caps: Option<&[String]>,
            scope: Option<u8>,
            user_key_hex: Option<&str>,
            delegated: Option<(&[String], u64, u64, u64)>,
            allow_reanchor: bool,
        ) -> Result<String> {
            DeviceStore::devices_upsert_atomic(
                self,
                name,
                secret,
                cert,
                caps,
                scope,
                user_key_hex,
                delegated,
                allow_reanchor,
            )
        }

        fn promote_provisional_identity(
            &self,
            name: &str,
            cert: &DeviceCert,
            scope: u8,
        ) -> Result<()> {
            DeviceStore::promote_provisional_identity(self, name, cert, scope)
        }

        fn mark_bounded_cap_source(
            &self,
            name: &str,
            capability: &str,
            source: &str,
        ) -> Result<()> {
            DeviceStore::mark_bounded_cap_source(self, name, capability, source)
        }

        fn merge_owner_cap_ops(&self, ops: &[Value]) -> usize {
            DeviceStore::merge_owner_cap_ops(self, ops)
        }

        fn owner_signed_cap_ops(&self) -> Vec<Value> {
            DeviceStore::owner_signed_cap_ops(self)
        }

        fn mark_lapsed_now(&self, device_pub: &[u8; 32]) -> Option<String> {
            DeviceStore::mark_lapsed_now(self, device_pub)
        }

        fn sanitize_device_name(&self, name: &str) -> String {
            sanitize_device_name(name)
        }

        fn devices_find_by_device_pub(&self, device_pub: &[u8; 32]) -> Option<Value> {
            DeviceStore::devices_find_by_device_pub(self, device_pub)
        }

        fn any_shell_grant(&self) -> bool {
            DeviceStore::any_shell_grant(self)
        }
    }
}

// ---------------------------------------------------------------------------
// Owner-signed fleet grant sets (see filament_cap::fleet_grants)
// ---------------------------------------------------------------------------

/// Owner side: grants the owner made FOR another fleet device. Local, plain.
pub const FLEET_GRANTS_AUTHORED_FILE: &str = "fleet-grants.json";
/// Owner side: per-target mint state, so an unchanged set keeps its epoch.
pub const FLEET_GRANTS_STATE_FILE: &str = "fleet-grants-state.json";
/// Receiver side: the newest accepted set about THIS device, as received.
/// Never merged into the capability store.
pub const FLEET_GRANTS_HELD_FILE: &str = "fleet-grants-held.json";
/// The `config` line key that holds `fleet.owner_grants` (the CLI's typed
/// settings registry writes it; `cli/src/settings.rs` pins the same string).
/// Written only by a local `tunlion set`; no network message reaches it.
pub const OWNER_GRANT_POLICY_STORE_KEY: &str = "fleet_owner_grants";

impl DeviceStore {
    fn json_array_at(&self, file: &str) -> Vec<Value> {
        std::fs::read_to_string(self.root.join(file))
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .unwrap_or_default()
    }

    /// The grants this OWNER device has made for other fleet devices.
    pub fn fleet_grants_authored(&self) -> Vec<Value> {
        self.json_array_at(FLEET_GRANTS_AUTHORED_FILE)
    }

    /// Record (or replace) "`subject` may `cap` on `target`", owner side.
    /// `expires` 0 means no grant-level expiry.
    pub fn fleet_grant_add(
        &self,
        target_pub: &[u8; 32],
        subject_pub: &[u8; 32],
        cap: &str,
        expires: u64,
    ) -> Result<()> {
        let mut all = self.fleet_grants_authored();
        let (t, s) = (hex::encode(target_pub), hex::encode(subject_pub));
        all.retain(|g| !(g["target_pub"] == t && g["subject_pub"] == s && g["cap"] == cap));
        all.push(json!({"target_pub": t, "subject_pub": s, "cap": cap, "expires": expires}));
        secret_write::SecretFile::write_str(
            &self.root.join(FLEET_GRANTS_AUTHORED_FILE),
            &serde_json::to_string_pretty(&all)?,
        )?;
        Ok(())
    }

    /// Remove "`subject` may `cap` on `target`". Returns whether one existed.
    pub fn fleet_grant_remove(&self, target_pub: &[u8; 32], subject_pub: &[u8; 32], cap: &str) -> Result<bool> {
        let mut all = self.fleet_grants_authored();
        let (t, s) = (hex::encode(target_pub), hex::encode(subject_pub));
        let before = all.len();
        all.retain(|g| !(g["target_pub"] == t && g["subject_pub"] == s && g["cap"] == cap));
        let removed = all.len() != before;
        if removed {
            secret_write::SecretFile::write_str(
                &self.root.join(FLEET_GRANTS_AUTHORED_FILE),
                &serde_json::to_string_pretty(&all)?,
            )?;
        }
        Ok(removed)
    }

    /// Has this owner ever authored a grant for `target_pub` (now, or in a set
    /// it minted before)? A device that never had one is sent nothing.
    pub fn fleet_grants_ever_for(&self, target_pub: &[u8; 32]) -> bool {
        let t = hex::encode(target_pub);
        self.fleet_grants_authored()
            .iter()
            .any(|g| g["target_pub"].as_str() == Some(t.as_str()))
            || std::fs::read_to_string(self.root.join(FLEET_GRANTS_STATE_FILE))
                .ok()
                .and_then(|r| serde_json::from_str::<Value>(&r).ok())
                .is_some_and(|v| v.get(&t).is_some())
    }

    /// Mint and sign the current set about `target_pub`, owner side.
    ///
    /// A subject the owner has revoked is left out, so the next push withdraws
    /// its grants everywhere (the receivers' revocation checks deny it anyway;
    /// this keeps the signed statement honest). The epoch bumps only when the
    /// content changes; `valid_until` refreshes once half the TTL has passed.
    pub fn mint_fleet_grant_set(
        &self,
        owner: &UserKey,
        target_pub: &[u8; 32],
        now: u64,
        ttl_secs: u64,
    ) -> Result<Value> {
        let t = hex::encode(target_pub);
        let mut grants: Vec<filament_id::FleetGrant> = self
            .fleet_grants_authored()
            .iter()
            .filter(|g| g["target_pub"].as_str() == Some(t.as_str()))
            .filter_map(|g| {
                let subject_pub: [u8; 32] = hex::decode(g["subject_pub"].as_str()?).ok()?.try_into().ok()?;
                let expires = g["expires"].as_u64().unwrap_or(0);
                if self.device_cert_revoked(&subject_pub) || (expires != 0 && expires <= now) {
                    return None;
                }
                Some(filament_id::FleetGrant { subject_pub, cap: g["cap"].as_str()?.to_string(), expires })
            })
            .collect();
        grants.sort_by(|a, b| (a.subject_pub, a.cap.as_str()).cmp(&(b.subject_pub, b.cap.as_str())));
        let hash = {
            use sha2::{Digest, Sha256};
            let probe = filament_id::FleetGrantSet {
                owner_pub: owner.public_key_bytes(),
                target_pub: *target_pub,
                epoch: 0,
                valid_until: 0,
                grants: grants.clone(),
            };
            let mut h = Sha256::new();
            h.update(probe.canonical_bytes());
            h.finalize().iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        let state_path = self.root.join(FLEET_GRANTS_STATE_FILE);
        let mut state: serde_json::Map<String, Value> = std::fs::read_to_string(&state_path)
            .ok()
            .and_then(|r| serde_json::from_str(&r).ok())
            .unwrap_or_default();
        let prev = state.get(&t).cloned().unwrap_or(Value::Null);
        let (pe, ph, pu) = (
            prev["epoch"].as_u64().unwrap_or(0),
            prev["hash"].as_str().unwrap_or("").to_string(),
            prev["valid_until"].as_u64().unwrap_or(0),
        );
        let epoch = if pe == 0 || ph != hash { pe + 1 } else { pe };
        let valid_until = if ph == hash && pu > now.saturating_add(ttl_secs / 2) {
            pu
        } else {
            now.saturating_add(ttl_secs)
        };
        if epoch != pe || valid_until != pu {
            state.insert(t.clone(), json!({"epoch": epoch, "hash": hash, "valid_until": valid_until}));
            secret_write::SecretFile::write_str(&state_path, &serde_json::to_string_pretty(&state)?)?;
        }
        let set = filament_id::FleetGrantSet {
            owner_pub: owner.public_key_bytes(),
            target_pub: *target_pub,
            epoch,
            valid_until,
            grants,
        };
        let sig = set.sign(owner.keypair())?;
        let mut blob = set.to_json();
        blob["sig"] = json!(hex::encode(sig));
        Ok(blob)
    }

    fn parse_signed_set(blob: &Value) -> Option<(filament_id::FleetGrantSet, bool)> {
        let set = filament_id::FleetGrantSet::from_json(blob)?;
        let sig: [u8; 64] = hex::decode(blob["sig"].as_str()?).ok()?.try_into().ok()?;
        let ok = set.verify(&sig).is_ok();
        Some((set, ok))
    }

    fn held_fleet_grants_raw(&self) -> Option<Value> {
        std::fs::read_to_string(self.root.join(FLEET_GRANTS_HELD_FILE))
            .ok()
            .and_then(|r| serde_json::from_str::<Value>(&r).ok())
    }

    /// Receiver side: judge a pushed set and store it on `Accept`. A malformed
    /// set is an error; every other outcome is the pure judgement.
    pub fn verify_and_store_fleet_grants(
        &self,
        blob: &Value,
        my_owner: &[u8; 32],
        my_device: &[u8; 32],
        now: u64,
    ) -> Result<filament_cap::fleet_grants::GrantSetJudgement> {
        use filament_cap::fleet_grants::{judge_grant_set_under, GrantSetHeader, GrantSetJudgement};
        let Some((set, sig_ok)) = Self::parse_signed_set(blob) else {
            anyhow::bail!("malformed fleet grant set");
        };
        let held = self
            .held_fleet_grants_raw()
            .and_then(|h| Some((h["epoch"].as_u64()?, h["valid_until"].as_u64()?)));
        let h = GrantSetHeader {
            owner_pub: set.owner_pub,
            target_pub: set.target_pub,
            epoch: set.epoch,
            valid_until: set.valid_until,
        };
        let j = judge_grant_set_under(self.owner_grant_policy(), &h, sig_ok, my_owner, my_device, now, held);
        if j == GrantSetJudgement::Accept {
            let mut keep = set.to_json();
            keep["sig"] = blob["sig"].clone();
            keep["received_at"] = json!(now);
            secret_write::SecretFile::write_str(
                &self.root.join(FLEET_GRANTS_HELD_FILE),
                &serde_json::to_string_pretty(&keep)?,
            )?;
        }
        Ok(j)
    }

    /// This device's `fleet.owner_grants`, read from its own `config` file on
    /// every call (so a `tunlion set` applies to the next decision, with no
    /// restart). Absent means the default (`files`); unreadable means `off`.
    pub fn owner_grant_policy(&self) -> filament_cap::fleet_grants::OwnerGrantPolicy {
        let raw = std::fs::read_to_string(self.root.join("config")).ok();
        let v = raw.as_deref().and_then(|r| {
            r.lines().find_map(|l| {
                let (k, v) = l.split_once(char::is_whitespace)?;
                (k == OWNER_GRANT_POLICY_STORE_KEY).then(|| v.trim().to_string())
            })
        });
        filament_cap::fleet_grants::OwnerGrantPolicy::from_stored(v.as_deref())
    }

    /// Receiver side, what the gates ask: does the held set grant `subject` the
    /// `action` now, AND does this device's `fleet.owner_grants` let an owner
    /// grant of that kind apply? The policy is read at this moment, so a set
    /// accepted under `all` stops granting shell the instant the device's owner
    /// narrows it to `files`.
    pub fn fleet_grant_applies(&self, subject: &[u8; 32], action: &str, now: u64) -> bool {
        self.owner_grant_policy().applies(action) && self.fleet_grant_held(subject, action, now)
    }

    /// Receiver side: does the held set grant `subject` the `action` now?
    /// (Held and valid; whether it APPLIES is [`DeviceStore::fleet_grant_applies`].)
    ///
    /// The held file is re-verified on every read (signature, owner, target):
    /// a file that was edited, or that predates a change of owner, grants
    /// nothing. Only meaningful on a joined device; the owner holds none.
    pub fn fleet_grant_held(&self, subject: &[u8; 32], action: &str, now: u64) -> bool {
        use filament_cap::fleet_grants::{grant_set_allows, HeldGrant};
        let Some(raw) = self.held_fleet_grants_raw() else {
            return false;
        };
        let Some((set, sig_ok)) = Self::parse_signed_set(&raw) else {
            return false;
        };
        let Some(owner) = self.owner_pub_for_resources(None) else {
            return false;
        };
        let Some(me) = self.local_device_cert_record().and_then(|r| DeviceCert::from_json(&r["cert"])) else {
            return false;
        };
        if !sig_ok || set.owner_pub != owner || set.target_pub != me.device_pub {
            return false;
        }
        let grants: Vec<HeldGrant> = set
            .grants
            .iter()
            .map(|g| HeldGrant { subject_pub: g.subject_pub, cap: g.cap.clone(), expires: g.expires })
            .collect();
        grant_set_allows(set.valid_until, &grants, subject, action, now)
    }

    /// Receiver side, for display: the held, valid owner grants for `subject`,
    /// split into those that apply under this device's `fleet.owner_grants` and
    /// those held but not applied.
    pub fn fleet_grant_caps_split(&self, subject: &[u8; 32], now: u64) -> (Vec<String>, Vec<String>) {
        let policy = self.owner_grant_policy();
        self.fleet_grant_caps_for(subject, now)
            .into_iter()
            .partition(|c| policy.applies(c))
    }

    /// Receiver side: the capabilities the held set grants `subject` now, for
    /// display (`devices`). Same checks as [`DeviceStore::fleet_grant_held`];
    /// the local policy is not applied here (see `fleet_grant_caps_split`).
    pub fn fleet_grant_caps_for(&self, subject: &[u8; 32], now: u64) -> Vec<String> {
        let Some(raw) = self.held_fleet_grants_raw() else {
            return Vec::new();
        };
        let Some(set) = filament_id::FleetGrantSet::from_json(&raw) else {
            return Vec::new();
        };
        let mut caps: Vec<String> = set
            .grants
            .iter()
            .filter(|g| g.subject_pub == *subject)
            .map(|g| g.cap.clone())
            .filter(|c| self.fleet_grant_held(subject, c, now))
            .collect();
        caps.sort();
        caps.dedup();
        caps
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_bootstrap_is_mutating_serialized_and_never_replaces_existing_state() {
        let root = std::env::temp_dir().join(format!("fil-identity-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        assert!(!store.has_identity());
        assert!(!root.join("identity.ed25519").exists());
        let workers: Vec<_> = (0..4).map(|_| {
            let root=root.clone();
            std::thread::spawn(move || {
                let store=DeviceStore::open(&root);
                store.ensure_identity_on_mutation().unwrap();
                store.owner_pub_from_keystore().unwrap()
            })
        }).collect();
        let keys: Vec<_> = workers.into_iter().map(|w|w.join().unwrap()).collect();
        assert!(keys.iter().all(|key|key==&keys[0]));
        std::fs::write(root.join("identity.ed25519"),b"corrupt existing key").unwrap();
        assert!(store.ensure_identity_on_mutation().is_err());
        assert_eq!(std::fs::read(root.join("identity.ed25519")).unwrap(),b"corrupt existing key");
        std::fs::remove_file(root.join("identity.ed25519")).unwrap();
        std::fs::create_dir_all(root.join("identity")).unwrap();
        std::fs::write(store.local_device_cert_path(),b"existing joined state").unwrap();
        store.ensure_identity_on_mutation().unwrap();
        assert!(!root.join("identity.ed25519").exists());
        // Only this test's unique fixture directory, not production state.
        std::fs::remove_file(store.local_device_cert_path()).unwrap();
        std::fs::remove_dir(root.join("identity")).unwrap();
        std::fs::remove_file(root.join("identity.lock")).unwrap();
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    fn stale_provisional_identities_are_collected_and_fresh_ones_kept() {
        let dir = std::env::temp_dir().join(format!("fil-st-{}-{}", std::process::id(), line!()));
        std::fs::create_dir_all(&dir).unwrap();
        let now = 10_000_000u64;
        let write = |name: &str, at: u64| {
            std::fs::write(
                dir.join(format!("provisional_{name}.json")),
                serde_json::json!({"name": name, "storedAt": at}).to_string(),
            )
            .unwrap();
        };
        write("peer-old", now - PROVISIONAL_TTL_SECS - 1);
        write("peer-older", 1);
        write("peer-fresh", now - 5);
        std::fs::write(dir.join("devices.json"), b"[]").unwrap();
        assert_eq!(sweep_stale_provisional(&dir, now), 2);
        assert!(
            dir.join("provisional_peer-fresh.json").exists(),
            "a live session keeps its record"
        );
        assert!(!dir.join("provisional_peer-old.json").exists());
        assert!(
            dir.join("devices.json").exists(),
            "only provisional records are swept"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_store_is_rooted_at_its_instance_directory() {
        let dir = std::env::temp_dir().join(format!("fil-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = DeviceStore::open(&dir);
        store
            .devices_upsert_atomic(
                "alpha",
                Some(&"a".repeat(64)),
                None,
                Some(&["transfer".to_string()]),
                None,
                None,
                None,
                false,
            )
            .unwrap();
        assert_eq!(
            store.devices_load(),
            vec![("alpha".to_string(), "a".repeat(64))]
        );
        assert_eq!(store.device_name_for_pub(&[0u8; 32]), None);
        let other = DeviceStore::open(dir.join("other"));
        assert!(
            other.devices_load().is_empty(),
            "instances do not share a root"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_device_name_strips_escape_junk() {
        let dirty = "\u{1b}[?1;2c\u{1b}[?1;2c\u{1b}[>0;276;0cpixel";
        assert_eq!(sanitize_device_name(dirty), "pixel");
        assert_eq!(sanitize_device_name("  lap\u{7}top \n"), "laptop");
        assert_eq!(sanitize_device_name("agboola@pop-os"), "agboola@pop-os");
    }
}

#[cfg(test)]
mod store_guards {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Barrier};

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-guard-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn competing_writers_lose_no_update() {
        let root = unique("writers");
        let store = DeviceStore::open(&root);
        store
            .with_devices_mut(|arr| {
                arr.push(json!({"name": "base", "secret": "s0"}));
                Ok(())
            })
            .unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for i in 0..2 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store
                    .with_devices_mut(|arr| {
                        arr.push(json!({"name": format!("w{i}"), "secret": format!("s{i}")}));
                        Ok(())
                    })
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        let names: Vec<String> = store
            .devices_records()
            .iter()
            .filter_map(|d| d["name"].as_str().map(str::to_string))
            .collect();
        assert!(names.contains(&"base".to_string()));
        assert!(names.contains(&"w0".to_string()));
        assert!(names.contains(&"w1".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_store_is_refused_and_never_overwritten() {
        let root = unique("corrupt");
        std::fs::create_dir_all(&root).unwrap();
        let p = root.join(DEVICES_FILE);
        let garbage = b"{garbage";
        std::fs::write(&p, garbage).unwrap();
        let store = DeviceStore::open(&root);
        let error = store.devices_remove("alpha").unwrap_err();
        assert!(error.downcast_ref::<CorruptStore>().is_some());
        assert_eq!(std::fs::read(&p).unwrap(), garbage);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cap_store_keeps_a_backup_and_refuses_to_write_over_damage() {
        let root = unique("caps");
        std::fs::create_dir_all(&root).unwrap();
        let store = DeviceStore::open(&root);
        let p = store.cap_store_path();
        std::fs::write(&p, br#"[{"a":1}]"#).unwrap();
        store.save_cap_store(&[json!({"b": 2})]).unwrap();
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"b\""));
        assert!(std::fs::read_to_string(backup_path(&p))
            .unwrap()
            .contains("\"a\""));

        let garbage = b"{garbage";
        std::fs::write(&p, garbage).unwrap();
        assert!(store.save_cap_store(&[json!({"c": 3})]).is_err());
        assert_eq!(std::fs::read(&p).unwrap(), garbage);

        // A failed backup is best effort and never blocks the write it protects.
        std::fs::write(&p, br#"[{"ok":true}]"#).unwrap();
        let bak = backup_path(&p);
        let _ = std::fs::remove_file(&bak);
        std::fs::create_dir(&bak).unwrap();
        assert!(store.save_cap_store(&[json!({"d": 4})]).is_ok());
        assert!(std::fs::read_to_string(&p).unwrap().contains("\"d\""));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn armed_state_needs_a_key_id_and_does_not_cross_instances() {
        let root = unique("armed");
        let a = root.join("a");
        let b = root.join("b");
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let future = cap_now_secs() + 600;
        std::fs::write(
            a.join("armed.json"),
            json!([{"key_id": "aa".repeat(32), "expires": future}]).to_string(),
        )
        .unwrap();
        let store_a = DeviceStore::open(&a);
        let store_b = DeviceStore::open(&b);
        assert!(store_a.is_armed());
        assert!(!store_b.is_armed());

        std::fs::write(
            a.join("armed.json"),
            json!([{"expires": future}]).to_string(),
        )
        .unwrap();
        assert!(
            !store_a.is_armed(),
            "an entry without a key id is not armed"
        );
        std::fs::write(
            a.join("armed.json"),
            json!([{"key_id": "aa".repeat(32), "expires": cap_now_secs() - 1}]).to_string(),
        )
        .unwrap();
        assert!(!store_a.is_armed(), "an expired entry is not armed");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn owner_pub_falls_back_to_the_local_certificate_issuer() {
        let root = unique("owner-fallback");
        let store = DeviceStore::open(&root);
        let user = UserKey::from_seed(&[7u8; 32]).unwrap();
        let cert = DeviceCert::certify(&user, [7u8; 32], now_secs(), 60).unwrap();
        store
            .write_local_device_cert_record(&json!({"name": "joined", "cert": cert.to_json()}))
            .unwrap();
        assert_eq!(
            store.owner_pub_for_resources(None),
            Some(user.public_key_bytes()),
            "a broken/unreadable overlay key must not hide the certificate issuer"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn one_engine_lease_per_root_and_a_dropped_lease_can_be_retaken() {
        let root = unique("lease");
        let a = DeviceStore::open(&root);
        let b = DeviceStore::open(&root);
        let held = a.try_acquire_engine_lease().unwrap().expect("first lease");
        assert!(b.try_acquire_engine_lease().unwrap().is_none());
        drop(held);
        assert!(b.try_acquire_engine_lease().unwrap().is_some());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_durable_invitation_use_survives_a_fresh_store() {
        let root = unique("invitation-use");
        let first = DeviceStore::open(&root);
        first
            .record_invitation_use("key", &Reuse::Once, 1_000, 10)
            .unwrap();
        // A restart is a fresh store over the same root: nothing in memory.
        let second = DeviceStore::open(&root);
        assert_eq!(
            second.record_invitation_use("key", &Reuse::Once, 1_000, 11),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(
            second.record_invitation_use("other", &Reuse::Once, 1_000, 11),
            Ok(())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_corrupt_used_invitation_file_fails_closed() {
        let root = unique("invitation-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(USED_INVITATIONS_FILE), b"{garbage").unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("key", &Reuse::Once, 1_000, 10),
            Err(InvitationRefusal::Unverifiable)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    // ------------------------------------------------ invitation withdrawal --

    #[test]
    fn a_withdrawn_reusable_invitation_is_refused_and_stays_refused_after_a_restart() {
        let root = unique("withdraw-reusable");
        let store = DeviceStore::open(&root);
        // `--reuse forever`: no count can ever run out, so only withdrawal
        // stops it. One claim first, the shape the owner reported.
        assert_eq!(store.record_invitation_use("k", &Reuse::Reusable, 10_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("k", 10_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 10_000, 102),
            Err(InvitationRefusal::Withdrawn)
        );
        // A restart is a fresh store over the same root: nothing in memory.
        let reopened = DeviceStore::open(&root);
        assert_eq!(reopened.invitation_withdrawn("k", 103), Ok(true));
        assert_eq!(
            reopened.record_invitation_use("k", &Reuse::Reusable, 10_000, 103),
            Err(InvitationRefusal::Withdrawn)
        );
        // The use already counted is kept, not reset by the withdrawal.
        let ledger = reopened.invitation_ledger(104);
        assert_eq!(ledger.len(), 1);
        assert_eq!(ledger[0].uses, 1);
        assert!(ledger[0].withdrawn);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_withdrawn_bounded_invitation_is_refused_with_uses_left_and_before_any_use() {
        let root = unique("withdraw-bounded");
        let store = DeviceStore::open(&root);
        assert_eq!(store.record_invitation_use("n", &Reuse::N(20), 10_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("n", 10_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("n", &Reuse::N(20), 10_000, 102),
            Err(InvitationRefusal::Withdrawn)
        );
        // Never claimed at all: the withdrawal writes a line of its own.
        assert_eq!(store.invitation_withdrawn("fresh", 100), Ok(false));
        assert_eq!(store.withdraw_invitation("fresh", 10_000, 100), Ok(()));
        assert_eq!(
            store.record_invitation_use("fresh", &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::Withdrawn)
        );
        // Another invitation is unaffected.
        assert_eq!(store.record_invitation_use("other", &Reuse::Once, 10_000, 101), Ok(()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_withdrawal_lasts_to_the_signed_end_and_is_never_shortened() {
        let root = unique("withdraw-expiry");
        let store = DeviceStore::open(&root);
        // A use recorded with the signed expiry, then a withdrawal that names a
        // SHORTER one (a stale or wrong local copy): the line keeps the later
        // end, so the refusal cannot lapse while the invitation still verifies.
        assert_eq!(store.record_invitation_use("k", &Reuse::Reusable, 5_000, 100), Ok(()));
        assert_eq!(store.withdraw_invitation("k", 1_000, 101), Ok(()));
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 5_000, 4_999),
            Err(InvitationRefusal::Withdrawn),
            "one second before the signed end it is still refused"
        );
        assert_eq!(store.invitation_withdrawn("k", 4_999), Ok(true));
        // At the end the invitation itself no longer verifies (the enrolment
        // path checks that first), and the line is pruned like a count.
        assert_eq!(store.invitation_withdrawn("k", 5_000), Ok(false));
        assert!(store.invitation_ledger(5_000).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn counting_another_invitation_keeps_a_withdrawal() {
        let root = unique("withdraw-keep");
        let store = DeviceStore::open(&root);
        assert_eq!(store.withdraw_invitation("gone", 10_000, 100), Ok(()));
        // Every use rewrites the file; the rewrite must carry the flag along.
        for t in 0..3 {
            assert_eq!(store.record_invitation_use("live", &Reuse::Reusable, 10_000, 101 + t), Ok(()));
        }
        assert_eq!(
            store.record_invitation_use("gone", &Reuse::Reusable, 10_000, 200),
            Err(InvitationRefusal::Withdrawn)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn withdrawal_fails_closed_on_an_unreadable_file() {
        let root = unique("withdraw-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(USED_INVITATIONS_FILE), b"{garbage").unwrap();
        let store = DeviceStore::open(&root);
        // The withdrawal says it did not happen and leaves the file alone.
        assert_eq!(
            store.withdraw_invitation("k", 10_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        assert_eq!(
            std::fs::read(root.join(USED_INVITATIONS_FILE)).unwrap(),
            b"{garbage"
        );
        // And the in-flight check refuses rather than admits.
        assert_eq!(
            store.invitation_withdrawn("k", 100),
            Err(InvitationRefusal::Unverifiable)
        );
        // A `withdrawn` this store cannot read is not "not withdrawn".
        std::fs::write(
            root.join(USED_INVITATIONS_FILE),
            br#"[{"keyId":"k","uses":0,"expires":10000,"withdrawn":"yes"}]"#,
        )
        .unwrap();
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 10_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_root_has_nothing_withdrawn() {
        let root = unique("withdraw-none");
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(DeviceStore::open(&root).invitation_withdrawn("k", 1), Ok(false));
    }

    #[test]
    fn a_withdrawal_racing_claims_is_ordered_by_the_lock() {
        // Many claimers over separate stores on one root (separate processes
        // in production), one withdrawal in the middle. Every claim that
        // returned Ok counted BEFORE the withdrawal: none is admitted after it.
        let root = unique("withdraw-race");
        std::fs::create_dir_all(&root).unwrap();
        let mut handles = Vec::new();
        for i in 0..16u64 {
            let root = root.clone();
            handles.push(std::thread::spawn(move || {
                let store = DeviceStore::open(&root);
                store.record_invitation_use("race", &Reuse::Reusable, 10_000, 100 + i)
            }));
        }
        {
            let store = DeviceStore::open(&root);
            store.withdraw_invitation("race", 10_000, 100).unwrap();
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let ok = results.iter().filter(|r| r.is_ok()).count() as u64;
        let ledger = DeviceStore::open(&root).invitation_ledger(0);
        assert_eq!(ledger.len(), 1);
        assert!(ledger[0].withdrawn);
        assert_eq!(ledger[0].uses, ok, "every admitted claim is counted, and none after the withdrawal");
        for r in &results {
            assert!(matches!(r, Ok(()) | Err(InvitationRefusal::Withdrawn)), "{r:?}");
        }
        assert_eq!(
            DeviceStore::open(&root).record_invitation_use("race", &Reuse::Reusable, 10_000, 500),
            Err(InvitationRefusal::Withdrawn)
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn an_empty_directory_path_is_a_noop() {
        create_private_dir_all(Path::new("")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nested_roots_are_private_and_existing_ancestors_are_left_alone() {
        use std::os::unix::fs::PermissionsExt;
        let root = unique("perms");
        let deep = root.join("a").join("b").join("c");
        create_private_dir_all(&deep).unwrap();
        for path in [root.join("a"), root.join("a").join("b"), deep] {
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o700,
                "{} must be owner-only",
                path.display()
            );
        }
        let existing = root.join("existing");
        std::fs::create_dir(&existing).unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o755)).unwrap();
        let child = existing.join("child");
        create_private_dir_all(&child).unwrap();
        assert_eq!(
            std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777,
            0o755,
            "an existing ancestor's mode is the user's choice"
        );
        assert_eq!(
            std::fs::metadata(&child).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    const CHILD_ROOT_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_ROOT";
    const CHILD_GATE_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_GATE";
    const CHILD_READY_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_READY";
    const CHILD_RESULT_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_RESULT";
    const CHILD_KEY_ENV: &str = "TUNLION_INVITATION_LOCK_CHILD_KEY";

    fn durable_uses(root: &Path, key: &str) -> Option<u64> {
        let raw = std::fs::read_to_string(root.join(USED_INVITATIONS_FILE)).ok()?;
        let entries: Vec<Value> = serde_json::from_str(&raw).ok()?;
        entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some(key))
            .and_then(|entry| entry["uses"].as_u64())
    }

    fn durable_entry_count(root: &Path) -> usize {
        std::fs::read_to_string(root.join(USED_INVITATIONS_FILE))
            .ok()
            .and_then(|raw| serde_json::from_str::<Vec<Value>>(&raw).ok())
            .map_or(0, |entries| entries.len())
    }

    #[test]
    fn concurrent_stores_admit_a_once_invitation_exactly_once() {
        let root = unique("invitation-once-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 16;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for _ in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("shared-key", &Reuse::Once, 10_000, 100)
            }));
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for thread in threads {
            match thread.join().unwrap() {
                Ok(()) => admitted += 1,
                Err(InvitationRefusal::AlreadyUsed) => refused += 1,
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
        assert_eq!(admitted, 1, "exactly one concurrent writer may admit");
        assert_eq!(refused, writers - 1);
        assert_eq!(durable_uses(&root, "shared-key"), Some(1));
        // A fresh instance proves the refusal is the durable count, not memory.
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use("shared-key", &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(durable_uses(&root, "shared-key"), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_stores_never_exceed_a_bounded_budget() {
        let root = unique("invitation-bounded-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 16;
        let budget = 4;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for _ in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("bounded-key", &Reuse::N(4), 10_000, 100)
            }));
        }
        let mut admitted = 0usize;
        let mut refused = 0usize;
        for thread in threads {
            match thread.join().unwrap() {
                Ok(()) => admitted += 1,
                Err(InvitationRefusal::UseLimitReached) => refused += 1,
                Err(other) => panic!("unexpected refusal: {other:?}"),
            }
        }
        assert_eq!(admitted, budget, "the durable budget must not be exceeded");
        assert_eq!(refused, writers - budget);
        assert_eq!(durable_uses(&root, "bounded-key"), Some(budget as u64));
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use("bounded-key", &Reuse::N(4), 10_000, 101),
            Err(InvitationRefusal::UseLimitReached)
        );
        assert_eq!(durable_uses(&root, "bounded-key"), Some(budget as u64));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn concurrent_distinct_keys_do_not_lose_updates() {
        let root = unique("invitation-distinct-race");
        std::fs::create_dir_all(&root).unwrap();
        let writers = 12;
        let barrier = Arc::new(Barrier::new(writers));
        let mut threads = Vec::new();
        for i in 0..writers {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                let key = format!("key-{i}");
                barrier.wait();
                let outcome = store.record_invitation_use(&key, &Reuse::Once, 10_000, 100);
                (key, outcome)
            }));
        }
        let mut keys = Vec::new();
        for thread in threads {
            let (key, outcome) = thread.join().unwrap();
            assert_eq!(outcome, Ok(()), "distinct key {key} must be admitted");
            keys.push(key);
        }
        assert_eq!(
            durable_entry_count(&root),
            writers,
            "no distinct-key update may be lost"
        );
        for key in keys {
            assert_eq!(durable_uses(&root, &key), Some(1));
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn independent_roots_do_not_share_the_use_lock() {
        let first = unique("invitation-root-first");
        let second = unique("invitation-root-second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut threads = Vec::new();
        for root in [first.clone(), second.clone()] {
            let store = DeviceStore::open(&root);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.record_invitation_use("same-key", &Reuse::Once, 10_000, 100)
            }));
        }
        for thread in threads {
            assert_eq!(thread.join().unwrap(), Ok(()));
        }
        assert_eq!(durable_uses(&first, "same-key"), Some(1));
        assert_eq!(durable_uses(&second, "same-key"), Some(1));
        let _ = std::fs::remove_dir_all(&first);
        let _ = std::fs::remove_dir_all(&second);
    }

    fn wait_for_file(path: &Path, deadline: std::time::Instant) -> bool {
        while !path.exists() {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            std::thread::yield_now();
        }
        true
    }

    fn wait_for_child(
        child: &mut std::process::Child,
        deadline: std::time::Instant,
    ) -> Option<std::process::ExitStatus> {
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Some(status),
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        return child.wait().ok();
                    }
                    std::thread::yield_now();
                }
                Err(_) => {
                    let _ = child.kill();
                    return child.wait().ok();
                }
            }
        }
    }

    #[test]
    fn used_invitation_lock_child() {
        let Some(root) = std::env::var_os(CHILD_ROOT_ENV) else {
            // Ordinary test runs only collect this helper; the parent test
            // below spawns this same binary with the environment set.
            return;
        };
        let gate = PathBuf::from(std::env::var_os(CHILD_GATE_ENV).expect("child gate env"));
        let ready = PathBuf::from(std::env::var_os(CHILD_READY_ENV).expect("child ready env"));
        let result = PathBuf::from(std::env::var_os(CHILD_RESULT_ENV).expect("child result env"));
        let key = std::env::var(CHILD_KEY_ENV).expect("child key env");
        // Announce that this independent process is alive and waiting BEFORE
        // the parent releases the gate, so the callers race and do not merely
        // run one after another.
        std::fs::write(&ready, b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        while !gate.exists() {
            if std::time::Instant::now() > deadline {
                panic!("parent did not release the process gate");
            }
            std::thread::yield_now();
        }
        let outcome = DeviceStore::open(PathBuf::from(root)).record_invitation_use(
            &key,
            &Reuse::Once,
            10_000,
            100,
        );
        let text = match outcome {
            Ok(()) => "ok".to_string(),
            Err(InvitationRefusal::AlreadyUsed) => "err:AlreadyUsed".to_string(),
            Err(other) => format!("err:unexpected:{other:?}"),
        };
        std::fs::write(result, text).unwrap();
    }

    #[test]
    fn the_use_lock_is_shared_by_independent_processes() {
        let root = unique("invitation-process-lock");
        std::fs::create_dir_all(&root).unwrap();
        let gate = root.join("start.gate");
        let exe = std::env::current_exe().unwrap();
        let key = "process-shared-key";
        let writers = 8usize;
        let mut children: Vec<(usize, std::process::Child, PathBuf, PathBuf)> = Vec::new();
        for i in 0..writers {
            let ready = root.join(format!("child-{i}.ready"));
            let result = root.join(format!("child-{i}.result"));
            let mut command = std::process::Command::new(&exe);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x08000000;
                command.creation_flags(CREATE_NO_WINDOW);
            }
            command
                .arg("--nocapture")
                .arg("--test-threads=1")
                .arg("used_invitation_lock_child")
                .env(CHILD_ROOT_ENV, &root)
                .env(CHILD_GATE_ENV, &gate)
                .env(CHILD_READY_ENV, &ready)
                .env(CHILD_RESULT_ENV, &result)
                .env(CHILD_KEY_ENV, key);
            match command.spawn() {
                Ok(child) => children.push((i, child, ready, result)),
                Err(e) => {
                    // Never leave already-spawned helpers spinning.
                    let _ = std::fs::write(&gate, b"go");
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
                    for (_, mut child, _, _) in children {
                        let _ = wait_for_child(&mut child, deadline);
                    }
                    panic!("spawn lock helper {i}: {e}");
                }
            }
        }
        let pids: HashSet<u32> = children.iter().map(|(_, child, _, _)| child.id()).collect();
        assert_eq!(
            pids.len(),
            writers,
            "the helpers must be independent processes"
        );

        // Wait until every independent process has announced readiness, then
        // release them together. The deadline keeps a broken helper from
        // hanging the suite forever.
        let ready_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut not_ready = Vec::new();
        for (i, _, ready, _) in &children {
            if !wait_for_file(ready, ready_deadline) {
                not_ready.push(*i);
            }
        }
        // Always release the gate: even a child that never announced still
        // has its own deadline, and the parent must reap every one.
        let gate_released = std::fs::write(&gate, b"go").is_ok();

        let run_deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut admitted = 0usize;
        let mut already_used = 0usize;
        let mut failures = Vec::new();
        if !gate_released {
            failures.push("could not release the process gate".to_string());
        }
        for (i, mut child, _, result_path) in children {
            let status = wait_for_child(&mut child, run_deadline);
            let result = std::fs::read_to_string(&result_path).unwrap_or_default();
            let clean = status.as_ref().is_some_and(|status| status.success());
            if !clean {
                failures.push(format!(
                    "child {i} did not exit cleanly (status {status:?}, result {result:?})"
                ));
            }
            match result.as_str() {
                "ok" => admitted += 1,
                "err:AlreadyUsed" => already_used += 1,
                other => failures.push(format!("child {i} returned {other:?}")),
            }
        }
        if !not_ready.is_empty() || !failures.is_empty() {
            let _ = std::fs::remove_dir_all(&root);
            panic!("not ready: {not_ready:?}; failures: {failures:?}");
        }
        assert_eq!(
            admitted, 1,
            "exactly one process may admit a once-only invitation"
        );
        assert_eq!(
            already_used,
            writers - 1,
            "every loser must report the exact AlreadyUsed refusal"
        );
        assert_eq!(durable_uses(&root, key), Some(1));
        let reopened = DeviceStore::open(&root);
        assert_eq!(
            reopened.record_invitation_use(key, &Reuse::Once, 10_000, 101),
            Err(InvitationRefusal::AlreadyUsed)
        );
        assert_eq!(durable_uses(&root, key), Some(1));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_use_lock_that_cannot_be_taken_refuses_and_never_writes() {
        let root = unique("invitation-lock-fail");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        assert_eq!(
            invitation_use_lock_path(&data),
            root.join(USED_INVITATIONS_LOCK_FILE),
            "the sidecar name must match the published lock path"
        );
        let original = br#"[{"keyId":"key","uses":0,"expires":10000,"lastUsed":1}]"#;
        std::fs::write(&data, original).unwrap();
        // A directory at the sidecar path makes the exclusive open fail.
        std::fs::create_dir(root.join(USED_INVITATIONS_LOCK_FILE)).unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("key", &Reuse::Once, 10_000, 100),
            Err(InvitationRefusal::Unverifiable),
            "a lock that cannot be taken must fail closed"
        );
        assert_eq!(std::fs::read(&data).unwrap(), original);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn semantically_corrupt_use_entries_fail_closed_and_are_not_overwritten() {
        let root = unique("invitation-semantic-corrupt");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        let corrupt = [
            // No key id.
            r#"[{}]"#,
            // Missing or wrongly-typed uses (the old code read these as 0).
            r#"[{"keyId":"k","expires":10000}]"#,
            r#"[{"keyId":"k","uses":"1","expires":10000}]"#,
            r#"[{"keyId":"k","uses":-1,"expires":10000}]"#,
            r#"[{"keyId":"k","uses":1.5,"expires":10000}]"#,
            // Wrongly-typed key id / expiry.
            r#"[{"keyId":7,"uses":1,"expires":10000}]"#,
            r#"[{"keyId":"k","uses":1}]"#,
            r#"[{"keyId":"k","uses":1,"expires":"later"}]"#,
            // Not an object.
            r#"[1]"#,
            // Two counts for one invitation are ambiguous.
            r#"[{"keyId":"k","uses":0,"expires":10000},{"keyId":"k","uses":0,"expires":10000}]"#,
        ];
        let store = DeviceStore::open(&root);
        for body in corrupt {
            std::fs::write(&data, body).unwrap();
            assert_eq!(
                store.record_invitation_use("k", &Reuse::Once, 20_000, 100),
                Err(InvitationRefusal::Unverifiable),
                "semantically corrupt body {body}"
            );
            assert_eq!(
                std::fs::read_to_string(&data).unwrap(),
                body,
                "semantically corrupt body {body} must not be rewritten"
            );
        }
        // A valid u64 that would overflow the increment is also refused.
        let overflow = r#"[{"keyId":"k","uses":18446744073709551615,"expires":10000}]"#;
        std::fs::write(&data, overflow).unwrap();
        assert_eq!(
            store.record_invitation_use("k", &Reuse::Reusable, 20_000, 100),
            Err(InvitationRefusal::Unverifiable)
        );
        assert_eq!(std::fs::read_to_string(&data).unwrap(), overflow);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_normal_legacy_use_file_is_read_and_kept_in_the_same_format() {
        let root = unique("invitation-legacy");
        std::fs::create_dir_all(&root).unwrap();
        let data = root.join(USED_INVITATIONS_FILE);
        let legacy = r#"[
            {"keyId":"old","uses":2,"expires":10000,"lastUsed":5,"extra":"keep"},
            {"uses":0,"expires":20000,"keyId":"other"}
        ]"#;
        std::fs::write(&data, legacy).unwrap();
        let store = DeviceStore::open(&root);
        assert_eq!(
            store.record_invitation_use("other", &Reuse::N(2), 20_000, 100),
            Ok(())
        );
        let raw = std::fs::read_to_string(&data).unwrap();
        let entries: Vec<Value> = serde_json::from_str(&raw).unwrap();
        let old = entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some("old"))
            .expect("the untouched entry stays");
        assert_eq!(old["uses"].as_u64(), Some(2));
        assert_eq!(old["expires"].as_u64(), Some(10_000));
        assert_eq!(old["extra"].as_str(), Some("keep"));
        let other = entries
            .iter()
            .find(|entry| entry["keyId"].as_str() == Some("other"))
            .expect("the used entry stays");
        assert_eq!(other["uses"].as_u64(), Some(1));
        assert_eq!(other["expires"].as_u64(), Some(20_000));
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod sibling_roster_revocation {
    //! Fleet auto-mesh revocation on a JOINED device: the owner's signed roster
    //! is the only voice that can withdraw a sibling, and it can only narrow.
    use super::*;
    use filament_id::{DeviceCert, UserKey};
    use serde_json::json;

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-sib-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct Joined {
        root: PathBuf,
        store: DeviceStore,
        owner: UserKey,
        sib: [u8; 32],
    }

    /// A joined device: its own certificate from `owner`, and one sibling
    /// indexed the way a verified fleet-hello writes it (no pair secret).
    fn joined(tag: &str) -> Joined {
        let root = unique(tag);
        let store = DeviceStore::open(&root);
        let owner = UserKey::from_seed(&[21u8; 32]).unwrap();
        let now = now_secs();
        let me = DeviceCert::certify(&owner, [1u8; 32], now, 3600).unwrap();
        store
            .write_local_device_cert_record(&json!({"name": "me", "cert": me.to_json()}))
            .unwrap();
        let sib = [2u8; 32];
        let sib_cert = DeviceCert::certify(&owner, sib, now, 3600).unwrap();
        std::fs::write(
            store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "sib", "deviceCert": sib_cert.to_json(), "caps": []},
            ]))
            .unwrap(),
        )
        .unwrap();
        Joined { root, store, owner, sib }
    }

    fn write_roster(j: &Joined, owner_pub: [u8; 32], listed: &[[u8; 32]]) {
        let devices: Vec<Value> = listed
            .iter()
            .map(|d| json!({"device_pub": hex::encode(d), "petname": "x"}))
            .collect();
        std::fs::write(
            j.root.join("roster.json"),
            serde_json::to_string(&json!({
                "owner_pub": hex::encode(owner_pub),
                "epoch": 3, "valid_until": 1, "received_at": 0,
                "devices": devices,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn listed_sibling_is_admissible_and_not_revoked() {
        let j = joined("listed");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32], j.sib]);
        assert!(j.store.sibling_admissible(&j.sib));
        assert!(!j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_sibling_the_owner_delisted_is_refused_and_reads_revoked() {
        let j = joined("delisted");
        write_roster(&j, j.owner.public_key_bytes(), &[[1u8; 32]]);
        assert!(!j.store.sibling_admissible(&j.sib));
        assert!(j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn no_roster_means_no_sibling_admission() {
        // Fail closed: with no roster there is no way a revocation could
        // reach this device, so a sibling is not admitted.
        let j = joined("none");
        assert!(!j.store.sibling_admissible(&j.sib));
        assert!(j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn a_roster_from_another_owner_lists_no_one() {
        let j = joined("foreign");
        let other = UserKey::from_seed(&[22u8; 32]).unwrap();
        write_roster(&j, other.public_key_bytes(), &[j.sib]);
        assert!(!j.store.sibling_admissible(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn paired_and_cross_owner_records_are_never_governed_by_the_roster() {
        let j = joined("exempt");
        write_roster(&j, j.owner.public_key_bytes(), &[]);
        let now = now_secs();
        // A device we PAIRED with (it has a pair secret): our own decision.
        let paired_pub = [3u8; 32];
        let paired = DeviceCert::certify(&j.owner, paired_pub, now, 3600).unwrap();
        // A device certified by a DIFFERENT owner, no secret.
        let other = UserKey::from_seed(&[23u8; 32]).unwrap();
        let foreign_pub = [4u8; 32];
        let foreign = DeviceCert::certify(&other, foreign_pub, now, 3600).unwrap();
        std::fs::write(
            j.store.devices_path(),
            serde_json::to_string(&json!([
                {"name": "paired", "secret": "ab".repeat(32), "deviceCert": paired.to_json()},
                {"name": "foreign", "deviceCert": foreign.to_json()},
            ]))
            .unwrap(),
        )
        .unwrap();
        assert!(!j.store.device_cert_revoked(&paired_pub));
        assert!(!j.store.device_cert_revoked(&foreign_pub));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn the_owner_device_is_never_governed_by_a_roster() {
        let j = joined("owner");
        UserKey::generate(&j.store.keystore()).unwrap();
        // Even with no roster at all, the owner admits by its own records.
        assert!(j.store.sibling_admissible(&j.sib));
        assert!(!j.store.device_cert_revoked(&j.sib));
        let _ = std::fs::remove_dir_all(&j.root);
    }

    #[test]
    fn the_roster_file_name_matches_the_roster_module() {
        #[cfg(feature = "dispatch")]
        assert_eq!(crate::recv::roster::ROSTER_FILE, "roster.json");
    }
}

#[cfg(test)]
mod fleet_grant_set_security {
    //! Owner-signed fleet grant sets, end to end through the store: an owner
    //! mints, a joined device judges and holds, the gate asks. Each test is one
    //! attack or failure the design must survive.
    use super::*;
    use filament_cap::fleet_grants::{GrantSetJudgement, GrantSetRefusal};
    use filament_id::{DeviceCert, FleetGrant, FleetGrantSet, UserKey};
    use serde_json::json;

    fn unique(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-fg-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    const ME: [u8; 32] = [0x21; 32];
    const BRAVO: [u8; 32] = [0x22; 32];

    /// A joined device certified by `owner`, plus the owner's own store with
    /// both devices on record.
    fn fleet(tag: &str) -> (UserKey, DeviceStore, DeviceStore, PathBuf, PathBuf) {
        let owner = UserKey::from_seed(&[0x41; 32]).unwrap();
        let now = now_secs();
        let oroot = unique(&format!("{tag}-owner"));
        let ostore = DeviceStore::open(&oroot);
        let me_cert = DeviceCert::certify(&owner, ME, now, 3600).unwrap();
        let b_cert = DeviceCert::certify(&owner, BRAVO, now, 3600).unwrap();
        std::fs::write(
            ostore.devices_path(),
            serde_json::to_string(&json!([
                {"name": "charlie", "secret": "aa".repeat(32), "deviceCert": me_cert.to_json()},
                {"name": "bravo", "secret": "bb".repeat(32), "deviceCert": b_cert.to_json()},
            ]))
            .unwrap(),
        )
        .unwrap();
        let jroot = unique(&format!("{tag}-joined"));
        let jstore = DeviceStore::open(&jroot);
        jstore
            .write_local_device_cert_record(&json!({"name": "charlie", "cert": me_cert.to_json()}))
            .unwrap();
        (owner, ostore, jstore, oroot, jroot)
    }

    fn cleanup(a: PathBuf, b: PathBuf) {
        let _ = std::fs::remove_dir_all(a);
        let _ = std::fs::remove_dir_all(b);
    }

    #[test]
    fn an_owner_grant_reaches_its_target_and_grants_only_what_it_says() {
        let (owner, ostore, jstore, a, b) = fleet("happy");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        let j = jstore
            .verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now)
            .unwrap();
        assert_eq!(j, GrantSetJudgement::Accept);
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", now));
        assert!(!jstore.fleet_grant_held(&BRAVO, "mount", now), "no cap it does not list");
        assert!(!jstore.fleet_grant_held(&[0x99; 32], "shell", now), "no third party");
        assert!(!jstore.load_cap_store().iter().any(|_| true), "never written into the cap store");
        cleanup(a, b);
    }

    #[test]
    fn a_compromised_sibling_cannot_author_a_set() {
        let (owner, _ostore, jstore, a, b) = fleet("forge");
        let now = now_secs();
        let sibling = UserKey::from_seed(&[0x42; 32]).unwrap();
        let set = FleetGrantSet {
            owner_pub: owner.public_key_bytes(), // claims to be the owner's
            target_pub: ME,
            epoch: 1,
            valid_until: now + 600,
            grants: vec![FleetGrant { subject_pub: BRAVO, cap: "shell".into(), expires: 0 }],
        };
        let mut blob = set.to_json();
        blob["sig"] = json!(hex::encode(set.sign(sibling.keypair()).unwrap()));
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::BadSignature)
        );
        // Honestly signed with its own key instead: another owner, refused.
        let mut honest = set.clone();
        honest.owner_pub = sibling.public_key_bytes();
        let mut blob = honest.to_json();
        blob["sig"] = json!(hex::encode(honest.sign(sibling.keypair()).unwrap()));
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherOwner)
        );
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn a_set_relayed_from_another_device_or_another_fleet_is_refused() {
        let (owner, ostore, jstore, a, b) = fleet("relay");
        let now = now_secs();
        // A genuine owner set about BRAVO, relayed to charlie by bravo.
        ostore.fleet_grant_add(&BRAVO, &ME, "shell", 0).unwrap();
        let for_bravo = ostore.mint_fleet_grant_set(&owner, &BRAVO, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&for_bravo, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherTarget)
        );
        // A genuine set from ANOTHER owner, about a device with our key bytes.
        let other = UserKey::from_seed(&[0x43; 32]).unwrap();
        let (_o2, o2store, _j2, a2, b2) = fleet("relay-other");
        o2store.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let foreign = o2store.mint_fleet_grant_set(&other, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&foreign, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OtherOwner)
        );
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
        cleanup(a2, b2);
    }

    #[test]
    fn replay_is_a_no_op_and_an_older_set_cannot_win_back_a_revoked_grant() {
        let (owner, ostore, jstore, a, b) = fleet("replay");
        let now = now_secs();
        let op = owner.public_key_bytes();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let granted = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Stale);
        // The owner withdraws it: a newer epoch without the grant.
        assert!(ostore.fleet_grant_remove(&ME, &BRAVO, "shell").unwrap());
        let withdrawn = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert!(withdrawn["epoch"].as_u64() > granted["epoch"].as_u64());
        assert_eq!(jstore.verify_and_store_fleet_grants(&withdrawn, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        // A sibling replays the OLD set that still granted it: refused as stale.
        assert_eq!(jstore.verify_and_store_fleet_grants(&granted, &op, &ME, now).unwrap(), GrantSetJudgement::Stale);
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn an_expired_set_is_never_applied_and_a_held_one_lapses() {
        let (owner, ostore, jstore, a, b) = fleet("expiry");
        let now = now_secs();
        let op = owner.public_key_bytes();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 60).unwrap();
        let until = blob["valid_until"].as_u64().unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &op, &ME, until).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::Expired)
        );
        assert_eq!(jstore.verify_and_store_fleet_grants(&blob, &op, &ME, now).unwrap(), GrantSetJudgement::Accept);
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", until - 1));
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", until), "owner offline past validity: lapsed");
        cleanup(a, b);
    }

    #[test]
    fn a_revoked_subject_is_left_out_of_the_next_set() {
        let (owner, ostore, jstore, a, b) = fleet("revoked");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore
            .with_devices_mut(|arr| {
                for d in arr.iter_mut() {
                    if d["name"] == "bravo" {
                        d["certRevoked"] = json!(true);
                    }
                }
                Ok(())
            })
            .unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert!(blob["grants"].as_array().unwrap().is_empty());
        jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap();
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        cleanup(a, b);
    }

    #[test]
    fn a_tampered_held_file_grants_nothing() {
        let (owner, ostore, jstore, a, b) = fleet("tamper");
        let now = now_secs();
        ostore.fleet_grant_add(&ME, &BRAVO, "transfer", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap();
        let p = jstore.root().join(FLEET_GRANTS_HELD_FILE);
        let raw = std::fs::read_to_string(&p).unwrap().replace("\"transfer\"", "\"shell\"");
        std::fs::write(&p, raw).unwrap();
        assert!(!jstore.fleet_grant_held(&BRAVO, "shell", now));
        assert!(!jstore.fleet_grant_held(&BRAVO, "transfer", now));
        cleanup(a, b);
    }

    fn set_policy(store: &DeviceStore, v: &str) {
        std::fs::write(store.root().join("config"), format!("name charlie\n{OWNER_GRANT_POLICY_STORE_KEY} {v}\n")).unwrap();
    }

    #[test]
    fn under_the_default_files_policy_an_owner_shell_grant_is_held_but_not_applied() {
        use filament_cap::fleet_grants::OwnerGrantPolicy;
        let (owner, ostore, jstore, a, b) = fleet("pol-files");
        let now = now_secs();
        assert_eq!(jstore.owner_grant_policy(), OwnerGrantPolicy::Files, "no config: the default");
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert!(jstore.fleet_grant_held(&BRAVO, "shell", now), "the signed set is kept whole");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "files: shell never applies");
        assert!(jstore.fleet_grant_applies(&BRAVO, "mount", now), "files: mount applies");
        assert_eq!(
            jstore.fleet_grant_caps_split(&BRAVO, now),
            (vec!["mount".to_string()], vec!["shell".to_string()])
        );
        cleanup(a, b);
    }

    #[test]
    fn an_incoming_set_cannot_set_or_widen_the_local_owner_grant_policy() {
        use filament_cap::fleet_grants::OwnerGrantPolicy;
        let (owner, ostore, jstore, a, b) = fleet("pol-net");
        let now = now_secs();
        set_policy(&jstore, "files");
        let cfg = jstore.root().join("config");
        let before = std::fs::read(&cfg).unwrap();
        // A genuine owner-signed set carrying shell, with every spelling of the
        // setting a hostile or confused owner could add riding along. The
        // signature covers the set's own fields only; nothing else is read.
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let mut blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        blob["fleet.owner_grants"] = json!("all");
        blob[OWNER_GRANT_POLICY_STORE_KEY] = json!("all");
        blob["settings"] = json!({"fleet.owner_grants": "all", "fleet_owner_grants": "all"});
        blob["policy"] = json!("all");
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert_eq!(std::fs::read(&cfg).unwrap(), before, "config untouched");
        assert_eq!(jstore.owner_grant_policy(), OwnerGrantPolicy::Files);
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "a set carrying shell is not applied under files");
        // The other network paths that write local state: the fleet-policy
        // relay (revocations only) and a roster. Neither touches the setting.
        assert_eq!(jstore.merge_owner_cap_ops(&[json!({"fleet.owner_grants": "all"})]), 0);
        assert_eq!(std::fs::read(&cfg).unwrap(), before);
        // And where the device never set it, receiving sets does not create it.
        let (owner2, ostore2, jstore2, a2, b2) = fleet("pol-net-none");
        ostore2.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        let mut blob2 = ostore2.mint_fleet_grant_set(&owner2, &ME, now, 600).unwrap();
        blob2["fleet.owner_grants"] = json!("all");
        jstore2.verify_and_store_fleet_grants(&blob2, &owner2.public_key_bytes(), &ME, now).unwrap();
        assert!(!jstore2.root().join("config").exists());
        assert_eq!(jstore2.owner_grant_policy(), OwnerGrantPolicy::Files);
        assert!(!jstore2.fleet_grant_applies(&BRAVO, "shell", now));
        cleanup(a, b);
        cleanup(a2, b2);
    }

    #[test]
    fn under_off_every_owner_set_is_refused_and_nothing_is_kept() {
        let (owner, ostore, jstore, a, b) = fleet("pol-off");
        let now = now_secs();
        set_policy(&jstore, "off");
        ostore.fleet_grant_add(&ME, &BRAVO, "transfer", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Refuse(GrantSetRefusal::OwnerGrantsOff)
        );
        assert!(!jstore.root().join(FLEET_GRANTS_HELD_FILE).exists());
        for c in ["transfer", "mount", "shell"] {
            assert!(!jstore.fleet_grant_applies(&BRAVO, c, now), "{c}");
        }
        cleanup(a, b);
    }

    #[test]
    fn narrowing_the_policy_applies_at_once_to_a_set_already_held() {
        let (owner, ostore, jstore, a, b) = fleet("pol-narrow");
        let now = now_secs();
        set_policy(&jstore, "all");
        ostore.fleet_grant_add(&ME, &BRAVO, "shell", 0).unwrap();
        ostore.fleet_grant_add(&ME, &BRAVO, "mount", 0).unwrap();
        let blob = ostore.mint_fleet_grant_set(&owner, &ME, now, 600).unwrap();
        assert_eq!(
            jstore.verify_and_store_fleet_grants(&blob, &owner.public_key_bytes(), &ME, now).unwrap(),
            GrantSetJudgement::Accept
        );
        assert!(jstore.fleet_grant_applies(&BRAVO, "shell", now), "all: shell applies");
        // No new set arrives; only the local setting changes.
        set_policy(&jstore, "files");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now), "files: shell stops at once");
        assert!(jstore.fleet_grant_applies(&BRAVO, "mount", now));
        set_policy(&jstore, "off");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "mount", now), "off: the held set grants nothing");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "shell", now));
        // An unreadable value is the narrowest, not the widest.
        set_policy(&jstore, "everything");
        assert!(!jstore.fleet_grant_applies(&BRAVO, "mount", now));
        cleanup(a, b);
    }

    #[test]
    fn the_network_relay_merges_revocations_only_never_grants() {
        // The old `fleet-policy` relay was the capability store's one network
        // write. A grant op signed by the owner must no longer enter it.
        let owner = UserKey::from_seed(&[0x44; 32]).unwrap();
        let root = unique("relay-merge");
        let store = DeviceStore::open(&root).with_owner_pub(Some(owner.public_key_bytes()));
        let mut op = filament_cap::capability::CapOp {
            op: filament_cap::capability::CapOpKind::Grant,
            grantor: owner.public_key_bytes(),
            target_kind: 0x01,
            target: BRAVO,
            resource: "self".into(),
            permissions: vec!["shell".into()],
            expires: now_secs() + 3600,
            issued_at: now_secs(),
            version: 1,
            sig: [0u8; 64],
        };
        op.sig = filament_cap::capability::sign_cap_op(&op, owner.keypair());
        assert_eq!(store.merge_owner_cap_ops(&[op.to_json()]), 0);
        assert!(store.load_cap_store().is_empty());
        let _ = std::fs::remove_dir_all(root);
    }
}
