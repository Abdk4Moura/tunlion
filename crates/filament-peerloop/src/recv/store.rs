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
use filament_id::{now_secs, DeviceCert, KeyStore, UserKey};
use serde_json::{json, Value};
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
/// The CLI's `overlay` module used to own this and resolved the path from the
/// process config directory. The cryptography and the on-disk format are
/// unchanged (PKCS8, owner-only, generated on first use); only the path is now
/// a constructor argument, so a Core instance never reads another instance's
/// key or an environment variable.
#[cfg(feature = "mesh")]
#[derive(Clone, Debug)]
pub struct OverlayKey {
    path: PathBuf,
}

#[cfg(feature = "mesh")]
impl OverlayKey {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load the overlay key, generating and persisting it on first use.
    pub fn load(&self) -> Result<filament_overlay::Identity> {
        let pkcs8 = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(_) => {
                let rng = ring::rand::SystemRandom::new();
                let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|_| anyhow::anyhow!("overlay key generation failed"))?;
                secret_write::SecretFile::write(&self.path, doc.as_ref())
                    .context("write overlay key")?;
                doc.as_ref().to_vec()
            }
        };
        filament_overlay::Identity::from_pkcs8(&pkcs8)
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        Ok(self.load()?.public_key_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> Result<[u8; 64]> {
        Ok(self.load()?.sign(msg))
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
            Some(d) => d["certRevoked"].as_bool().unwrap_or(false),
        }
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
    /// signed. Returns how many were newly stored.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    use serde_json::json;
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
        let user = UserKey::generate().unwrap();
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
}
