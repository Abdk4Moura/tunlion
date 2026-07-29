// sshkeys — thin CLI shim over the standalone `authkeys-managed` crate.
//
// The managed-ssh logic (managed keypair, private known_hosts, the removable
// `# BEGIN/END filament-managed <device>` authorized_keys block, and the
// bootstrap cache) now lives in `authkeys-managed`, which is decoupled from the
// CLI's config-dir resolution: every config-rooted function takes
// `config_dir: &Path`. This shim injects `crate::settings::config_dir()` and
// re-exports the config-independent items verbatim, so every existing
// `crate::sshkeys::X` call site (main.rs, l2.rs, capability.rs) resolves
// unchanged with zero call-site churn.

use anyhow::Result;
use std::path::PathBuf;

// Config-independent surface: re-exported directly (authorized_keys_path is
// $HOME-rooted; validate/strip/has_block/host_pubkeys read no config dir).
pub use authkeys_managed::{
    authorized_keys_path, has_block, host_pubkeys, install_authorized_key, remove_authorized_key,
    strip_block, validate_pubkey,
};

// Config-rooted surface: forward with the CLI's config dir injected.

pub fn managed_key_path() -> PathBuf {
    authkeys_managed::managed_key_path(&crate::settings::config_dir())
}

pub fn known_hosts_path() -> PathBuf {
    authkeys_managed::known_hosts_path(&crate::settings::config_dir())
}

pub fn ensure_managed_key() -> Result<String> {
    authkeys_managed::ensure_managed_key(&crate::settings::config_dir())
}

pub fn pin_host_keys(dest_token: &str, hostkeys: &[String]) -> Result<()> {
    authkeys_managed::pin_host_keys(&crate::settings::config_dir(), dest_token, hostkeys)
}

pub fn host_pinned(dest_token: &str) -> bool {
    authkeys_managed::host_pinned(&crate::settings::config_dir(), dest_token)
}

pub fn bootstrap_cache_get(device: &str) -> Option<Option<String>> {
    authkeys_managed::bootstrap_cache_get(&crate::settings::config_dir(), device)
}

pub fn bootstrap_cache_put(device: &str, user: Option<&str>) {
    authkeys_managed::bootstrap_cache_put(&crate::settings::config_dir(), device, user)
}

pub fn bootstrap_cache_clear(device: &str) {
    authkeys_managed::bootstrap_cache_clear(&crate::settings::config_dir(), device)
}
