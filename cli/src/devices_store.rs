//! The devices store, as the CLI's process adapter.
//!
//! The implementation moved to `filament_peerloop::recv::store` so an
//! embedder (Core) can open the same store on an explicit directory. This
//! module is the CLI's thin shim: it builds one [`DeviceStore`] on the
//! process config directory and forwards, keeping the old free-function names
//! so every existing caller and test resolves unchanged.
//!
//! Nothing here re-implements a merge rule, a path or a write. The pure record
//! functions are re-exported directly from the library.

use crate::exit_codes;
use anyhow::Result;
use filament_peerloop::recv::store::{CorruptStore, DeviceStore};
use serde_json::Value;
use std::path::PathBuf;

pub(crate) use filament_peerloop::recv::store::{
    free_device_name, insert_new_peer_record, place_joined_owner, refuse_unowned_rewrite,
    sanitize_device_name, upsert_peer_record,
};

/// The store for this process's config directory. The CLI is the process
/// adapter, so this is the one place the directory is resolved from `Paths`
/// (which honours `TUNLION_CONFIG_DIR` for tests and managed deployments).
pub(crate) fn store() -> DeviceStore {
    DeviceStore::open(crate::platform::Paths::config_dir())
}

/// The same store with this process's owner key attached, for the two
/// owner-signed capability operations. A device without an owner key gets the
/// same fail-closed empty result it always did.
pub(crate) fn store_with_owner() -> DeviceStore {
    store().with_owner_pub(crate::fleet::my_owner_pub())
}

/// Map the library's typed corrupt-store error to the CLI's exit kind, so a
/// damaged `devices.json` is still exit 2 / `corrupt_state`, not a generic
/// failure. Every other error passes through untouched.
fn map_error(error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<CorruptStore>() {
        Ok(corrupt) => exit_codes::CorruptState(corrupt.message()).into(),
        Err(other) => other,
    }
}

pub(crate) fn devices_path() -> PathBuf {
    store().devices_path()
}

/// Lock, read, mutate, and atomically write devices.json.
pub(crate) fn with_devices_mut<T>(f: impl FnOnce(&mut Vec<Value>) -> Result<T>) -> Result<T> {
    store().with_devices_mut(f).map_err(map_error)
}

/// Whether `name` is pinned to a DIFFERENT device identity than
/// `device_pub_hex`.
pub(crate) fn name_pinned_by_other(name: &str, device_pub_hex: &str) -> bool {
    store().devices_records().iter().any(|d| {
        d["name"].as_str() == Some(name)
            && d["deviceCert"]["devicePub"]
                .as_str()
                .is_some_and(|p| p != device_pub_hex)
    })
}

/// Record the fleet owner after a join.
pub(crate) fn devices_store_joined_owner(
    owner_name: &str,
    secret: &str,
    owner_cert: &crate::identity::DeviceCert,
    caps: &[String],
    scope: u8,
) -> Result<String> {
    store()
        .devices_store_joined_owner(owner_name, secret, owner_cert, caps, scope)
        .map_err(map_error)
}

/// Store a pair secret handed to us over the NETWORK as a NEW record.
pub(crate) fn devices_store_new(
    name: &str,
    secret: &str,
    introduced_by: Option<&str>,
) -> Result<String> {
    store()
        .devices_store_new(name, secret, introduced_by)
        .map_err(map_error)
}

/// Whether the record `name` was created by a `pair-intro`.
pub(crate) fn device_was_introduced(name: &str) -> bool {
    store().device_was_introduced(name)
}

pub(crate) fn devices_mark_invited_as(name: &str, kind: &str) -> Result<()> {
    store()
        .devices_mark_invited_as(name, kind)
        .map_err(map_error)
}

pub(crate) fn devices_upsert_atomic(
    name: &str,
    secret: Option<&str>,
    cert: Option<&crate::identity::DeviceCert>,
    caps: Option<&[String]>,
    scope: Option<u8>,
    user_key_hex: Option<&str>,
    delegated: Option<(&[String], u64, u64, u64)>,
    allow_reanchor: bool,
) -> Result<String> {
    store()
        .devices_upsert_atomic(
            name,
            secret,
            cert,
            caps,
            scope,
            user_key_hex,
            delegated,
            allow_reanchor,
        )
        .map_err(map_error)
}

pub(crate) fn devices_load() -> Vec<(String, String)> {
    store().devices_load()
}
