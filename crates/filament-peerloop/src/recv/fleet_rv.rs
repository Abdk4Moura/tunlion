//! Fleet rendezvous facts, with an explicit root, key and route set.
//!
//! The rendezvous secret, its channel derivation, our owner key and the
//! `fleet-hello` built from our overlay identity are host facts. This service
//! takes all of them explicitly: no `Paths`, no `std::env`, and no global L3
//! route source. The wire shape and the binding (`announce` is bound to the
//! link's channel binding) are unchanged from `cli/src/fleet.rs`.

use crate::recv::identity::local_device_cert;
use crate::recv::store::{DeviceStore, OverlayKey};
use anyhow::{anyhow, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// The fleet rendezvous channel derivation. PROTOCOL LITERAL: frozen, do not
/// rename; both sides derive the same meeting point from the shared secret.
pub fn channel_of(secret: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"filament-pair:");
    h.update(secret.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// One engine's fleet facts.
pub struct FleetService {
    store: DeviceStore,
    overlay: OverlayKey,
    announce_seq_path: PathBuf,
    display_name: String,
    /// The advertised prefixes this instance wants in its fleet hello. The CLI
    /// adapter resolves its settings/config once; Core supplies its own list.
    routes: Vec<String>,
}

impl FleetService {
    pub fn new(
        store: DeviceStore,
        overlay: OverlayKey,
        announce_seq_path: impl Into<PathBuf>,
        display_name: impl Into<String>,
        routes: Vec<String>,
    ) -> Self {
        Self {
            store,
            overlay,
            announce_seq_path: announce_seq_path.into(),
            display_name: display_name.into(),
            routes,
        }
    }

    /// A copy of this service with a different explicit route set. The CLI
    /// adapter calls this with its current config; Core passes its own list.
    pub fn with_routes(&self, routes: Vec<String>) -> Self {
        Self {
            store: self.store.clone(),
            overlay: self.overlay.clone(),
            announce_seq_path: self.announce_seq_path.clone(),
            display_name: self.display_name.clone(),
            routes,
        }
    }

    pub fn store(&self) -> &DeviceStore {
        &self.store
    }

    pub fn announce_seq_path(&self) -> &Path {
        &self.announce_seq_path
    }

    pub fn routes(&self) -> &[String] {
        &self.routes
    }

    pub fn rv(&self) -> Option<String> {
        self.store.fleet_rv()
    }

    pub fn rv_load_or_create(&self) -> Result<String> {
        self.store.fleet_rv_load_or_create()
    }

    pub fn store_rv(&self, hex_secret: &str) -> Result<()> {
        self.store.store_fleet_rv(hex_secret)
    }

    /// The fleet meeting point derived from the rendezvous secret.
    pub fn channel(&self) -> Option<String> {
        self.rv().map(|s| channel_of(&s))
    }

    pub fn is_fleet_channel(&self, ch: &str) -> bool {
        !ch.is_empty() && self.channel().as_deref() == Some(ch)
    }

    /// Our owner key: the keystore's user key, else the issuer key in our own
    /// device certificate. Same precedence as the old host path.
    pub fn owner_pub(&self) -> Option<[u8; 32]> {
        self.store.owner_pub_from_keystore().or_else(|| {
            local_device_cert(&self.store, &self.overlay, &self.display_name)
                .map(|cert| cert.user_pub)
        })
    }

    /// Build our `fleet-hello` for a link whose channel binding is `cb`.
    pub fn make_hello(&self, cb: &[u8], name: &str) -> Result<Value> {
        let id = self.overlay.load()?;
        let seq = filament_overlay::next_announce_seq_at(&self.announce_seq_path);
        let announce = if self.routes.is_empty() {
            id.announce(seq, cb)
        } else {
            id.announce_with_routes(seq, cb, self.routes.clone())
        };
        let cert = local_device_cert(&self.store, &self.overlay, &self.display_name)
            .ok_or_else(|| anyhow!("this device holds no certificate to present"))?;
        Ok(filament_fleet::build_hello(&announce, &cert, name))
    }
}

/// The rendezvous secret as a 32-byte hex string, if it parses.
pub fn valid_rv(hex_secret: &str) -> Option<String> {
    let s = hex_secret.trim().to_string();
    (hex::decode(&s).map(|b| b.len()).ok() == Some(32)).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use filament_id::UserKey;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fil-fleet-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn service(root: &Path) -> FleetService {
        FleetService::new(
            DeviceStore::open(root),
            OverlayKey::new(root.join("overlay.ed25519")),
            root.join("overlay.announce-seq"),
            "test-device",
            Vec::new(),
        )
    }

    #[test]
    fn independent_roots_do_not_share_the_rendezvous_secret() {
        let a_root = temp("a");
        let b_root = temp("b");
        let a = service(&a_root);
        let b = service(&b_root);
        let secret = "aa".repeat(32);
        a.store_rv(&secret).unwrap();
        assert_eq!(a.rv().as_deref(), Some(secret.as_str()));
        assert_eq!(b.rv(), None);
        assert_eq!(a.channel(), Some(channel_of(&secret)));
        assert!(a.is_fleet_channel(&channel_of(&secret)));
        assert!(!b.is_fleet_channel(&channel_of(&secret)));
        let _ = std::fs::remove_dir_all(&a_root);
        let _ = std::fs::remove_dir_all(&b_root);
    }

    #[test]
    fn owner_pub_prefers_the_explicit_keystore_then_our_certificate() {
        let root = temp("owner");
        let store = DeviceStore::open(&root);
        let user = UserKey::generate(&store.keystore()).unwrap();
        let service = FleetService::new(
            store,
            OverlayKey::new(root.join("overlay.ed25519")),
            root.join("overlay.announce-seq"),
            "test-device",
            Vec::new(),
        );
        assert_eq!(service.owner_pub(), Some(user.public_key_bytes()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_wrong_length_rendezvous_secret_is_refused() {
        assert!(valid_rv("abcd").is_none());
        assert!(valid_rv(&"zz".repeat(32)).is_none());
        assert!(valid_rv(&"aa".repeat(32)).is_some());
    }
}
