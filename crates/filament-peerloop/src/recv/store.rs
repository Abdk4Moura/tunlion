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
    apply_header, now_secs as cap_now_secs, self_resource_id, superseded_by_tombstone,
    update_ratchet, CapHeader, CapOp, PrincipalKind, CAP_TOMBSTONE_TYPE,
};
use filament_id::{now_secs, DeviceCert, KeyStore, UserKey};
use serde_json::{json, Value};
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

mod fleet_grants;
mod invitations;
mod records;

pub use fleet_grants::{
    FLEET_GRANTS_AUTHORED_FILE, FLEET_GRANTS_HELD_FILE, FLEET_GRANTS_STATE_FILE,
    OWNER_GRANT_POLICY_STORE_KEY,
};
pub use invitations::{
    admit_invitation_use, invitation_ledger_at, invitation_withdrawn_at, record_invitation_use_at,
    withdraw_invitation_at, ArmedInvitation, InvitationLedgerEntry, InvitationRefusal,
    USED_INVITATIONS_FILE, USED_INVITATIONS_LOCK_FILE, WITHDRAWN_WIRE_REASON,
};
pub use records::{
    effective_principal_deadline, ephemeral_record_ended, free_device_name,
    insert_new_peer_record, place_joined_owner, principal_from_records, record_is_ephemeral,
    record_is_revoked, refuse_unowned_rewrite, reinvite_from_record, sanitize_device_name,
    shell_grant_names_at, sibling_record_ended, sweep_lapsed, sweep_stale_provisional,
    upsert_peer_record,
};

/// The device store's file name, relative to the root.
pub const DEVICES_FILE: &str = "devices.json";
/// The cross-process lock sidecar used for `devices.json` writes.
pub const DEVICES_LOCK_FILE: &str = "devices.json.lock";
/// The capability store's file name, relative to the root.
pub const CAP_STORE_FILE: &str = "caps.json";
/// The cross-process lock sidecar used for the `caps.json` read/modify/write.
pub const CAP_STORE_LOCK_FILE: &str = "caps.json.lock";
/// The key-revocation block's file name, relative to the root.
///
/// PROVENANCE IS PART OF THE FORMAT: an entry here means "FORGOTTEN", and
/// nothing else. It is written only by the removal service's Forget mode and
/// lifted by an explicit re-add or `promote`. Every peer-facing path reads a
/// hit as "not recognized", on admission and mid-session alike.
pub const KEY_REVOCATIONS_FILE: &str = "revoked-keys.json";
/// The cross-process lock sidecar used for the `revoked-keys.json`
/// read/modify/write.
pub const KEY_REVOCATIONS_LOCK_FILE: &str = "revoked-keys.json.lock";
/// On a JOINED device: the keys of fleet siblings whose index record the sweep
/// removed because the owner's roster stopped listing them. Removing the record
/// must not remove the revocation it carried, so each removal leaves an entry
/// here, read while the held roster still does not list the key. Not the
/// forget block above: an entry here means "delisted by the owner", and it
/// lifts by itself once the owner lists the device again.
pub const DELISTED_SIBLINGS_FILE: &str = "delisted-siblings.json";

/// A read of [`DELISTED_SIBLINGS_FILE`]: its entries, or why it is unusable.
type DelistedRead = std::result::Result<Vec<Value>, String>;
/// The last read of each store's file, by path: mtime, length, when it was
/// read, and what it held. Process-wide because callers open a fresh
/// `DeviceStore` per call; a daemon has one path, so this stays tiny, and it
/// is emptied if it ever grows past [`DELISTED_CACHE_PATHS`].
#[allow(clippy::type_complexity)]
static DELISTED_CACHE: std::sync::Mutex<
    Option<std::collections::HashMap<PathBuf, (Option<SystemTime>, u64, SystemTime, DelistedRead)>>,
> = std::sync::Mutex::new(None);
const DELISTED_CACHE_PATHS: usize = 256;
/// A cached read is trusted only for a file whose mtime was at least this far
/// before the read. File times are coarse (a clock tick, or worse on some
/// filesystems), so a same-length rewrite inside one tick of the previous
/// write keeps (mtime, length); such a recently written file is re-read every
/// time instead, and any later rewrite lands on a later mtime.
const DELISTED_CACHE_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);
/// This process's last failed write to [`DELISTED_SIBLINGS_FILE`], by the
/// path it was for.
static DELISTED_WRITE_ERROR: std::sync::Mutex<Option<(PathBuf, String)>> =
    std::sync::Mutex::new(None);

/// How to recover a damaged delisted-sibling store at `p`: restore its `.bak`
/// when there is one, else move it aside. Shared with `tunlion doctor`.
pub fn delisted_recovery(p: &Path) -> String {
    let bak = backup_path(p);
    if bak.exists() {
        format!("restore the last good copy: cp {} {}", bak.display(), p.display())
    } else {
        "move it aside to start with an empty one (that drops what it held)".to_string()
    }
}

/// May a cached read of a file with this mtime, taken at `read_at`, stand in
/// for reading it again? Only when the file had settled before the read. Pure.
fn delisted_cache_trusted(mtime: Option<SystemTime>, read_at: SystemTime) -> bool {
    mtime.is_some_and(|m| {
        m.checked_add(DELISTED_CACHE_SETTLE)
            .is_some_and(|settled| settled <= read_at)
    })
}
/// The local device certificate record, relative to the root.
pub const LOCAL_DEVICE_CERT_FILE: &str = "identity/device-cert.json";
/// How long a provisional identity is worth keeping. It exists to bridge one
/// session's identity proof to that session's overlay announcement, which
/// follows within seconds; an hour is generous.
pub const PROVISIONAL_TTL_SECS: u64 = 3600;
/// One structured receive-history row.
///
/// Lives here, not in `recv::files`, because a host that persists receipts
/// without the dispatch feature still needs the shape. The dispatch receive
/// path re-exports it from `recv::files` for its existing callers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceivedFileRecord {
    pub time: u64,
    pub peer: Option<String>,
    pub file: String,
    pub stored: Option<String>,
    pub bytes: u64,
    pub sha256: Option<String>,
    pub ok: bool,
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
pub(crate) fn keep_backup(path: &Path) {
    if let Ok(raw) = std::fs::read_to_string(path) {
        if !raw.trim().is_empty() {
            let _ = secret_write::SecretFile::write_str(&backup_path(path), &raw);
        }
    }
}

/// `keep_backup` for `devices.json`, minus every pair secret this write
/// removes. The backup is the last good copy for recovering a damaged store,
/// not an undo: a secret the write drops (a declined remember, a forgotten or
/// re-keyed device) must not survive beside it in `.bak`, or "nothing stored"
/// and "forgot" are untrue on disk. A record keeps its place in the backup
/// while its secret is still held (a rename keeps it), and a record that holds
/// no secret is kept as it was.
fn keep_devices_backup(path: &Path, next: &[Value]) {
    let Ok(raw) = std::fs::read_to_string(path) else { return };
    let Ok(prev) = serde_json::from_str::<Vec<Value>>(&raw) else { return keep_backup(path) };
    if prev.is_empty() {
        return;
    }
    let held: std::collections::HashSet<&str> = next.iter().filter_map(|d| d["secret"].as_str()).collect();
    let kept: Vec<&Value> = prev
        .iter()
        .filter(|d| d["secret"].as_str().is_none_or(|s| held.contains(s)))
        .collect();
    if let Ok(text) = serde_json::to_string_pretty(&kept) {
        let _ = secret_write::SecretFile::write_str(&backup_path(path), &text);
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

enum JsonArrayBackup {
    Plain,
    Devices,
    CheckedPlain,
}

fn read_json_array_checked(path: &Path, label: &str) -> Result<Vec<Value>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => serde_json::from_str(&raw)
            .map_err(|e| CorruptStore::new(path.to_path_buf(), e.to_string()).into()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(anyhow::anyhow!("read {label}: {e}")),
    }
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

    /// The exact two store files the revocation sweep compares: `devices.json`
    /// and the key-revocation block. `None` means unreadable or malformed, so a
    /// sweep must do nothing rather than treat it as "everything was removed".
    /// Missing files are empty content, not an error.
    pub fn revocation_snapshot(&self) -> Option<(String, String)> {
        let read_or_empty = |path: &Path| -> Option<String> {
            match std::fs::read_to_string(path) {
                Ok(content) => Some(content),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Some(String::new()),
                Err(_) => None,
            }
        };
        let devices = read_or_empty(&self.devices_path())?;
        if !devices.trim().is_empty()
            && !matches!(serde_json::from_str::<Value>(&devices), Ok(Value::Array(_)))
        {
            return None;
        }
        let revoked = read_or_empty(&self.key_revocations_path())?;
        Some((devices, revoked))
    }

    /// Remove from `held` every pair whose secret the current store no longer
    /// holds, returning the removed SECRETS. An unreadable store removes
    /// nothing: absence of evidence is not a removal. Matching is on the
    /// secret, the fact that proves, never on the display name.
    pub fn prune_held(&self, held: &mut Vec<(String, String)>) -> std::collections::HashSet<String> {
        // Parse the SAME snapshot that decided the sweep may run. Re-reading the
        // store here let a file change between the two reads prune everything.
        let Some((devices, _)) = self.revocation_snapshot() else {
            return std::collections::HashSet::new();
        };
        let records: Vec<Value> = if devices.trim().is_empty() {
            Vec::new()
        } else {
            match serde_json::from_str(&devices) {
                Ok(records) => records,
                Err(_) => return std::collections::HashSet::new(),
            }
        };
        // A matching secret keeps its trust but follows the store's CURRENT
        // name: the held name keys certificates, grants and dialing one layer
        // down, so a rename must not let an old name resolve a new record.
        let current: std::collections::HashMap<String, String> = records
            .iter()
            .filter_map(|record| {
                let name = record["name"].as_str()?.to_string();
                let secret = record["secret"].as_str()?.to_string();
                Some((secret, name))
            })
            .collect();
        let mut removed = std::collections::HashSet::new();
        held.retain_mut(|(name, secret)| match current.get(secret) {
            Some(current_name) => {
                *name = current_name.clone();
                true
            }
            None => {
                removed.insert(secret.clone());
                false
            }
        });
        removed
    }

    pub fn devices_lock_path(&self) -> PathBuf {
        self.root.join(DEVICES_LOCK_FILE)
    }

    pub fn cap_store_path(&self) -> PathBuf {
        self.root.join(CAP_STORE_FILE)
    }

    pub fn local_device_cert_path(&self) -> PathBuf {
        self.root.join(LOCAL_DEVICE_CERT_FILE)
    }

    pub fn config_path(&self) -> PathBuf {
        self.root.join("config")
    }

    fn config_lock_path(&self) -> PathBuf {
        self.root.join("config.lock")
    }

    /// Run `f` under the same `identity.lock` the owner-key bootstrap and the
    /// join acknowledgement use. A blank device claiming an invitation and a
    /// concurrent first-run owner bootstrap must not both decide who owns this
    /// directory.
    pub fn with_identity_lock<T>(&self, f: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        create_private_dir_all(&self.root)
            .with_context(|| format!("create config dir {}", self.root.display()))?;
        let _lock = StoreLock::acquire(&self.root.join("identity.lock"))
            .with_context(|| format!("lock {}", self.root.join("identity.lock").display()))?;
        f(self)
    }

    fn provisional_path(&self, name: &str) -> PathBuf {
        self.root.join(format!("provisional_{name}.json"))
    }

    fn with_json_array_mut<T>(
        &self,
        path: &Path,
        lock_path: &Path,
        label: &str,
        backup: JsonArrayBackup,
        f: impl FnOnce(&mut Vec<Value>) -> Result<(T, bool)>,
    ) -> Result<T> {
        if let Some(dir) = path.parent() {
            create_private_dir_all(dir)
                .with_context(|| format!("create config dir {}", dir.display()))?;
        }
        let _lock = StoreLock::acquire(lock_path)
            .with_context(|| format!("lock {}", lock_path.display()))?;
        let mut arr = read_json_array_checked(path, label)?;
        let (out, changed) = f(&mut arr)?;
        if changed {
            match backup {
                JsonArrayBackup::Plain => keep_backup(path),
                JsonArrayBackup::Devices => keep_devices_backup(path, &arr),
                JsonArrayBackup::CheckedPlain => {
                    before_write_json_array(path)?;
                    keep_backup(path);
                }
            }
            secret_write::SecretFile::write_str(path, &serde_json::to_string_pretty(&arr)?)
                .with_context(|| format!("atomic write {label}"))?;
        }
        Ok(out)
    }

    /// Lock, read, mutate, and atomically write `devices.json`. The
    /// read-modify-write is atomic across processes via the lock sidecar, so a
    /// daemon's liveness sweep and a concurrent `grant`/`revoke`/`add`/`join`
    /// cannot lose each other's update. The closure runs on the freshly-read
    /// array; if it returns Err the file is NOT written, and if the store cannot
    /// be read or parsed the write is skipped too.
    pub fn with_devices_mut<T>(&self, f: impl FnOnce(&mut Vec<Value>) -> Result<T>) -> Result<T> {
        self.with_json_array_mut(
            &self.devices_path(),
            &self.devices_lock_path(),
            "devices.json",
            JsonArrayBackup::Devices,
            |arr| Ok((f(arr)?, true)),
        )
    }

    /// The device records, fail-closed: a missing file is empty, but an
    /// existing file that cannot be read or parsed is an error rather than an
    /// empty fleet. Removal planning uses this so a corrupt store cannot be
    /// mistaken for "no record to remove" (the tolerant [`devices_records`]
    /// remains for read-only display paths).
    pub fn devices_snapshot(&self) -> Result<Vec<Value>> {
        read_json_array_checked(&self.devices_path(), "devices.json")
    }

    /// The key-revocation entries, fail-closed: absent is empty, unreadable or
    /// unparseable is an error.
    pub fn key_revocation_entries(&self) -> Result<Vec<Value>> {
        read_json_array_checked(&self.key_revocations_path(), "revoked-keys.json")
    }

    /// Lock, read, mutate and atomically write `revoked-keys.json`. The
    /// closure returns the facts it lifted and whether the file changed; an
    /// empty lift therefore does not create or rewrite the file. A corrupt
    /// list is an error and is never written over.
    pub(crate) fn with_key_revocations_mut<T>(
        &self,
        f: impl FnOnce(&mut Vec<Value>) -> Result<(T, bool)>,
    ) -> Result<T> {
        self.with_json_array_mut(
            &self.key_revocations_path(),
            &self.root.join(KEY_REVOCATIONS_LOCK_FILE),
            "revoked-keys.json",
            JsonArrayBackup::Plain,
            f,
        )
    }

    /// The capability store, fail-closed: absent is empty, unreadable or
    /// unparseable is an error. The tolerant [`cap_store`] stays for the
    /// read-only evaluators, which already treat damage as "no grants".
    pub fn cap_store_checked(&self) -> Result<Vec<Value>> {
        read_json_array_checked(&self.cap_store_path(), "caps.json")
    }

    /// Lock, read, mutate and atomically write `caps.json`. The closure
    /// returns whether anything changed, so a no-op revoke does not rewrite
    /// the store. `before_write_json_array` refuses to replace a corrupt or
    /// truncated file.
    pub fn with_cap_store_mut<T>(
        &self,
        f: impl FnOnce(&mut Vec<Value>) -> Result<(T, bool)>,
    ) -> Result<T> {
        self.with_json_array_mut(
            &self.cap_store_path(),
            &self.root.join(CAP_STORE_LOCK_FILE),
            "caps.json",
            JsonArrayBackup::CheckedPlain,
            f,
        )
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

    /// Persist a receiver completion fact, not a file-existence observation.
    /// Uses the same bounded JSON schema and stable writer sidecar as CLI
    /// history. A corrupt journal is preserved and reported, never overwritten.
    pub fn record_received_file(&self, record: &ReceivedFileRecord) -> io::Result<()> {
        create_private_dir_all(&self.root)?;
        let path = self.root.join("transfers.json");
        let _lock = StoreLock::acquire(&path.with_extension("json.lock"))?;
        let mut rows: Vec<Value> = match std::fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(error) => return Err(error),
        };
        rows.push(json!({
            "time": record.time, "direction": "in", "peer": record.peer,
            "file": record.file, "stored": record.stored, "bytes": record.bytes,
            "sha256": record.sha256, "ok": record.ok,
        }));
        if rows.len() > 200 {
            rows.drain(..rows.len() - 200);
        }
        let body = serde_json::to_string(&rows)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        secret_write::SecretFile::write_str(&path, &body)
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

    /// A device record's capability ceiling, with the v1 baseline `["transfer"]`
    /// when the record predates `caps`. An unknown name is empty. Used by the
    /// core host for a LAN delegated principal; the CLI host reads the same
    /// field through `device_caps`.
    pub fn device_caps(&self, name: &str) -> Vec<String> {
        let Some(record) = self
            .devices_records()
            .into_iter()
            .find(|d| d["name"].as_str() == Some(name))
        else {
            return Vec::new();
        };
        match record.get("caps").and_then(|c| c.as_array()) {
            Some(list) => list
                .iter()
                .filter_map(|c| c.as_str().map(str::to_string))
                .collect(),
            None => vec!["transfer".to_string()],
        }
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

    /// Receiver-local denial, independent of invitation and owner grants.
    pub fn device_capability_denied(&self, name: &str, capability: &str) -> bool {
        self.devices_records().iter()
            .find(|record| record["name"].as_str() == Some(name))
            .and_then(|record| record["deniedCaps"].as_array())
            .is_some_and(|caps| caps.iter().any(|cap| cap.as_str() == Some(capability)))
    }

    /// The key revocations at `revoked-keys.json`, fail-closed: absent is
    /// empty, unreadable or unparseable is an error.
    pub fn key_revocations_path(&self) -> PathBuf {
        self.root.join(KEY_REVOCATIONS_FILE)
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
            // Unknown device: not revoked, unless it is a sibling whose record
            // was removed for being delisted (the removal kept its revocation).
            None => self.delisted_sibling_tombstoned(device_pub),
            Some(d) => {
                d["certRevoked"].as_bool().unwrap_or(false) || self.sibling_record_delisted(d)
            }
        }
    }

    /// The delisted-sibling entries: `None` when the file is absent, `Err`
    /// (with why) when it exists but cannot be read or parsed. Parsed once per
    /// change of the file (path, mtime, length), so an unknown key at the
    /// transfer gate costs a `stat`, not a read; a file written within
    /// [`DELISTED_CACHE_SETTLE`] of the read is always re-read.
    fn delisted_entries(&self) -> Option<DelistedRead> {
        let p = self.root.join(DELISTED_SIBLINGS_FILE);
        let meta = match std::fs::metadata(&p) {
            Ok(m) => m,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return None,
            Err(e) => return Some(Err(format!("cannot be read ({e})"))),
        };
        let (mtime, len) = (meta.modified().ok(), meta.len());
        if let Ok(cache) = DELISTED_CACHE.lock() {
            if let Some((cm, cl, read_at, read)) = cache.as_ref().and_then(|c| c.get(&p)) {
                if *cm == mtime && *cl == len && delisted_cache_trusted(*cm, *read_at) {
                    return Some(read.clone());
                }
            }
        }
        let read_at = SystemTime::now();
        // An empty file does not parse either: nothing writes one, so it is a
        // truncation, never "no entries".
        let read: DelistedRead = match std::fs::read_to_string(&p) {
            Ok(raw) => serde_json::from_str::<Vec<Value>>(&raw)
                .map_err(|e| format!("cannot be parsed ({e})")),
            Err(e) => Err(format!("cannot be read ({e})")),
        };
        if let Ok(mut cache) = DELISTED_CACHE.lock() {
            let c = cache.get_or_insert_with(Default::default);
            if c.len() >= DELISTED_CACHE_PATHS {
                c.clear();
            }
            c.insert(p, (mtime, len, read_at, read.clone()));
        }
        Some(read)
    }

    /// Does a delisted-sibling entry (see [`DELISTED_SIBLINGS_FILE`]) still
    /// refuse `device_pub`? Only on a joined device, only while the entry's
    /// certificate has not run out, and only while neither the entry's owner
    /// nor the owner this device answers to NOW lists the key in the held
    /// roster. Fail-closed like the record read: absent is nothing, unreadable
    /// or unparseable refuses (and is reported, see
    /// [`DeviceStore::delisted_siblings_problem`]).
    pub fn delisted_sibling_tombstoned(&self, device_pub: &[u8; 32]) -> bool {
        if self.owner_pub_from_keystore().is_some() {
            return false;
        }
        // No owner key here, so the owner this device answers to is its own
        // certificate's issuer: the rest of `owner_pub_for_resources`, without
        // loading the keystore a second time.
        let entries = match self.delisted_entries() {
            None => return false,
            Some(Err(_)) => return true,
            Some(Ok(entries)) => entries,
        };
        let key = hex::encode(device_pub);
        let now = now_secs();
        let current_owner = self.joined_owner_pub();
        entries.iter().any(|e| {
            if e["devicePub"].as_str() != Some(key.as_str())
                || !e["certExpires"].as_u64().is_some_and(|exp| exp > now)
            {
                return false;
            }
            // Lifted once the owner lists the device again, including an
            // entry written under an earlier enrolment's owner.
            if current_owner.is_some_and(|o| self.owner_roster_lists(device_pub, &o)) {
                return false;
            }
            let owner = e["ownerPub"]
                .as_str()
                .and_then(|h| hex::decode(h).ok())
                .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok());
            match owner {
                Some(owner) => !self.owner_roster_lists(device_pub, &owner),
                None => true,
            }
        })
    }

    /// The owner a joined device answers to, from its own certificate record:
    /// `owner_pub_for_resources(None)` minus the keystore load, for callers
    /// that already found no owner key.
    fn joined_owner_pub(&self) -> Option<[u8; 32]> {
        self.local_device_cert_record()
            .as_ref()
            .and_then(|record| DeviceCert::from_json(&record["cert"]))
            .map(|cert| cert.user_pub)
    }

    /// Why the delisted-sibling store needs a person, if it does: the file
    /// exists but does not read or parse (every key with no record is then
    /// refused as revoked), and/or this process's last write to it failed (a
    /// removed sibling's revocation could not be kept, so its record was; the
    /// next successful sweep clears this). The daemon says this loudly;
    /// `None` when all is well.
    pub fn delisted_siblings_problem(&self) -> Option<String> {
        let p = self.root.join(DELISTED_SIBLINGS_FILE);
        let damaged = match self.delisted_entries() {
            Some(Err(why)) => Some(format!(
                "{} {why}; until it is fixed every device with no record here is refused as revoked. Fix it, or {}",
                p.display(),
                delisted_recovery(&p)
            )),
            _ => None,
        };
        let failed_write = DELISTED_WRITE_ERROR
            .lock()
            .ok()
            .and_then(|g| g.as_ref().filter(|(at, _)| *at == p).map(|(_, why)| why.clone()));
        match (damaged, failed_write) {
            (Some(d), Some(w)) => Some(format!("{d}; and {w}")),
            (d, w) => d.or(w),
        }
    }

    /// Record that the sweep removed these delisted siblings' records:
    /// `(device key hex, certificate expiry)`. Called under the devices lock,
    /// BEFORE the shortened device list is written, so there is no moment at
    /// which the record is gone and the entry is not there yet. The outcome is
    /// kept for [`DeviceStore::delisted_siblings_problem`].
    fn tombstone_delisted_siblings(
        &self,
        owner: &[u8; 32],
        removed: &[(String, u64)],
        now: u64,
    ) -> Result<()> {
        let p = self.root.join(DELISTED_SIBLINGS_FILE);
        let r = self.write_delisted(&p, owner, removed, now);
        if let Ok(mut cache) = DELISTED_CACHE.lock() {
            if let Some(c) = cache.as_mut() {
                c.remove(&p);
            }
        }
        if let Ok(mut last) = DELISTED_WRITE_ERROR.lock() {
            match &r {
                Err(e) => {
                    *last = Some((
                        p.clone(),
                        format!(
                            "{}: a removed sibling's revocation could not be kept ({e:#}); its record was kept instead",
                            p.display()
                        ),
                    ))
                }
                // A success clears this path's failure, never another's.
                Ok(()) => {
                    if last.as_ref().is_some_and(|(at, _)| *at == p) {
                        *last = None;
                    }
                }
            }
        }
        r
    }

    fn write_delisted(
        &self,
        p: &Path,
        owner: &[u8; 32],
        removed: &[(String, u64)],
        now: u64,
    ) -> Result<()> {
        // A file that does not parse is never written over: it stays for a
        // person to inspect or restore (the state-file doctrine).
        let mut entries: Vec<Value> = match std::fs::read_to_string(p) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("{} cannot be parsed ({e})", p.display()))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(anyhow::anyhow!("read {}: {e}", p.display())),
        };
        let owner_hex = hex::encode(owner);
        // An entry whose certificate ran out refuses nothing any more.
        entries.retain(|e| e["certExpires"].as_u64().is_some_and(|exp| exp > now));
        for (key, expires) in removed {
            entries.retain(|e| {
                !(e["devicePub"].as_str() == Some(key.as_str())
                    && e["ownerPub"].as_str() == Some(owner_hex.as_str()))
            });
            entries.push(json!({
                "devicePub": key,
                "ownerPub": owner_hex,
                "certExpires": expires,
            }));
        }
        keep_backup(p);
        secret_write::SecretFile::write_str(p, &serde_json::to_string_pretty(&entries)?)
            .context("atomic write delisted-siblings.json")?;
        Ok(())
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

    /// Is `device_pub` a sibling this device recognizes for a possession proof:
    /// a device record carries it, OR, on a JOINED device only, the owner's
    /// signed roster lists it. On a joined device the roster is the
    /// authorization fact and the record is only an index entry whose write can
    /// fail or be refused, so a listed sibling without one keeps its kind. On
    /// the OWNER device the roster is not the authority (its own records are),
    /// so there only a record counts: a key with no record is not recognized,
    /// even though `sibling_admissible` admits every key there. Revocation is
    /// unaffected: a recognized but revoked key is still cut by the sweep.
    pub fn sibling_recognized(&self, device_pub: &[u8; 32]) -> bool {
        if self.devices_find_by_device_pub(device_pub).is_some() {
            return true;
        }
        if self.owner_pub_from_keystore().is_some() {
            return false;
        }
        self.joined_owner_pub()
            .is_some_and(|owner| self.owner_roster_lists(device_pub, &owner))
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
    /// records newly lapsed, plus how many ended records were removed: an
    /// ephemeral device whose lease or offline budget is over, and (on a
    /// joined device) a fleet sibling whose certificate expired or that the
    /// owner's roster no longer lists. Those are not evidence worth keeping,
    /// they are the stale rows a device list should not show.
    pub fn devices_sweep_lapsed(&self, now: u64) -> usize {
        // On a joined device: the owner whose siblings we index, and whether
        // we hold a roster from it (no roster means we cannot tell a delisted
        // sibling from one we simply have not heard about, so nothing is
        // pruned for delisting). Read outside the devices lock.
        let sibling_owner = if self.owner_pub_from_keystore().is_none() {
            self.owner_pub_for_resources(None)
        } else {
            None
        };
        let roster_held = sibling_owner.is_some_and(|o| self.owner_roster_held(&o));
        self.with_devices_mut(|arr| {
            let lapsed = sweep_lapsed(arr, now);
            let before = arr.len();
            // Siblings removed for being DELISTED (certificate still valid):
            // their revocation outlives the record (DELISTED_SIBLINGS_FILE).
            let mut delisted: Vec<(String, u64)> = Vec::new();
            arr.retain(|record| {
                if record_is_ephemeral(record) {
                    return !ephemeral_record_ended(record, now);
                }
                let Some(owner) = sibling_owner else { return true };
                let ended = sibling_record_ended(record, &owner, now, |device_pub| {
                    roster_held && !self.owner_roster_lists(device_pub, &owner)
                });
                if ended {
                    if let Some(cert) = DeviceCert::from_json(&record["deviceCert"]) {
                        if cert.expires > now {
                            delisted.push((hex::encode(cert.device_pub), cert.expires));
                        }
                    }
                }
                !ended
            });
            if let (Some(owner), false) = (sibling_owner, delisted.is_empty()) {
                // Fails the whole sweep (nothing removed) if it cannot be kept.
                self.tombstone_delisted_siblings(&owner, &delisted, now)?;
            }
            Ok(lapsed + (before - arr.len()))
        })
        .unwrap_or(0)
    }

    /// Mark a record as an ephemeral device (a CI lease, a borrowed box) and
    /// stamp it seen now: it exists while it is present and is removed, not
    /// kept, once its lease or offline budget ends or it departs.
    pub fn devices_mark_ephemeral(&self, name: &str, now: u64) -> Result<()> {
        self.with_devices_mut(|arr| {
            if let Some(rec) = arr.iter_mut().find(|d| d["name"].as_str() == Some(name)) {
                rec["ephemeral"] = json!(true);
                rec["lastSeen"] = json!(now);
            }
            Ok(())
        })
    }

    /// Do we hold a roster signed by `owner` at all?
    fn owner_roster_held(&self, owner: &[u8; 32]) -> bool {
        std::fs::read_to_string(self.root.join("roster.json"))
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .is_some_and(|r| r["owner_pub"].as_str() == Some(hex::encode(owner).as_str()))
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

    /// Store a `pair-keep` secret idempotently. The same secret can arrive more
    /// than once when the sender retries across a path handoff; each repeat
    /// must return the existing record instead of minting a suffixed duplicate.
    pub fn devices_store_remembered(&self, name: &str, secret: &str) -> Result<String> {
        if let Some(existing) = self
            .devices_records()
            .iter()
            .find(|d| d["secret"].as_str() == Some(secret))
            .and_then(|d| d["name"].as_str())
        {
            return Ok(existing.to_string());
        }
        self.devices_store(name, secret)
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
            // An ephemeral device that departs is gone: drop the record, so
            // nothing renews it, nothing lists it, and its key is refused.
            if arr
                .iter()
                .any(|d| d["name"].as_str() == Some(&name) && record_is_ephemeral(d))
            {
                arr.retain(|d| d["name"].as_str() != Some(&name));
                return Ok(name);
            }
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

    /// One `key value` per line, matching the CLI's long-standing config
    /// format. The read/modify/write runs under `config.lock` so a name set by
    /// a join cannot be lost to another setting written at the same time.
    pub fn set_config(&self, key: &str, value: &str) -> Result<()> {
        create_private_dir_all(&self.root)
            .with_context(|| format!("create config dir {}", self.root.display()))?;
        let _lock = StoreLock::acquire(&self.config_lock_path())
            .with_context(|| format!("lock {}", self.config_lock_path().display()))?;
        let p = self.config_path();
        let mut lines: Vec<String> = std::fs::read_to_string(&p)
            .unwrap_or_default()
            .lines()
            .filter(|l| l.split_whitespace().next() != Some(key))
            .map(|l| l.to_string())
            .collect();
        lines.push(format!("{key} {value}"));
        secret_write::SecretFile::write_str(&p, &(lines.join("\n") + "\n"))
            .context("atomic write config")
    }

    /// A config value, trimmed. A bare key (empty value) reads as absent, the
    /// same rule the CLI's `config_get` used.
    pub fn config_value(&self, key: &str) -> Option<String> {
        std::fs::read_to_string(self.config_path())
            .ok()?
            .lines()
            .find_map(|line| {
                let (k, v) = line.split_once(char::is_whitespace)?;
                (k == key && !v.trim().is_empty()).then(|| v.trim().to_string())
            })
    }

    pub fn device_name(&self) -> Option<String> {
        self.config_value("name")
    }

    pub fn set_device_name(&self, name: &str) -> Result<()> {
        self.set_config("name", name)
    }

    /// Verify and store the owner's signed capability header for resource
    /// `self`. This is a network-origin write, so it is parsed from JSON,
    /// checked as a genesis header under the owner key named by the verified
    /// owner certificate, and only then applied through the shared
    /// `apply_header` chain (which also advances the ratchet).
    ///
    /// Returns `false` when a self header is already present: a duplicate from
    /// a replayed acknowledgement must not fork or rewrite the chain.
    pub fn store_owner_cap_header(
        &self,
        header_json: &Value,
        owner_pub: &[u8; 32],
    ) -> Result<bool> {
        let header =
            CapHeader::from_json(header_json).ok_or_else(|| anyhow::anyhow!("cap header is malformed"))?;
        if header.resource != "self" {
            anyhow::bail!(
                "cap header resource '{}' is not this device's 'self' resource",
                header.resource
            );
        }
        if header.owner_pub != *owner_pub {
            anyhow::bail!("cap header is signed by a different owner than the verified certificate");
        }
        create_private_dir_all(&self.root)
            .with_context(|| format!("create config dir {}", self.root.display()))?;
        let lock_path = self.root.join("caps.json.lock");
        let _lock = StoreLock::acquire(&lock_path)
            .with_context(|| format!("lock {}", lock_path.display()))?;
        let mut store = self.load_cap_store();
        let already = store.iter().any(|e| {
            e.get("type").and_then(|x| x.as_str()) == Some("cap_header")
                && e["resource"].as_str() == Some("self")
        });
        if already {
            return Ok(false);
        }
        if header.resource == "self" {
            // The legacy fleet header is STORED under the caller-facing alias
            // `self`, but its signature commits to the self-certifying derived
            // resource id. Rebuild that signed view before verifying; do not
            // weaken the check to the stored alias.
            let mut signed = header.clone();
            signed.resource = self_resource_id(owner_pub);
            signed.verify_signed_by(owner_pub)?;
            store.push(header.to_json());
            update_ratchet(&mut store, owner_pub, header.issued_at)?;
        } else {
            // A real resource header must be a genesis with a self-certifying
            // id; `apply_header` verifies it before writing.
            apply_header(&mut store, &header)?;
        }
        self.save_cap_store(&store)
            .map_err(|e| anyhow::anyhow!("owner capability header not stored: {e}"))?;
        Ok(true)
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

        fn devices_overlay(&self, name: &str) -> (Option<String>, Option<String>) {
            self.devices_info(name).map(|(_, v6, v4)| (v6, v4)).unwrap_or((None, None))
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
        fn delisted_siblings_problem(&self) -> Option<String> {
            DeviceStore::delisted_siblings_problem(self)
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
mod tests;
