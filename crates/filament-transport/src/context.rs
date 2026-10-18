//! Configuration and discovery ownership for one engine. Clone for its sessions
//! and detached tasks; construct independently for another engine.
use std::{net::IpAddr, path::{Path, PathBuf}, sync::Arc};
use tokio::sync::Mutex;

type Settings = dyn Fn(&str, Option<&str>) -> Option<String> + Send + Sync;
type Membership = dyn Fn(Option<&str>) -> String + Send + Sync;

#[derive(Clone)]
pub struct TransportContext(Arc<Inner>);

struct Inner {
    dns_cache_path: Option<PathBuf>,
    settings: Arc<Settings>,
    membership: Arc<Membership>,
    public_ip: Mutex<Option<crate::direct::PubIpEntry>>,
    observed_ip: Mutex<Option<IpAddr>>,
}

impl Default for TransportContext {
    /// No settings, membership restrictions, or DNS persistence. Never reads an
    /// ambient config root or falls back to a file in the current directory.
    fn default() -> Self {
        Self::new(
            None,
            |_: &str, _: Option<&str>| None,
            |_: Option<&str>| String::new(),
        )
    }
}

impl TransportContext {
    /// `dns_cache_path` is the exact optional cache filename. Callbacks are
    /// immutable but may perform live reads of an explicitly captured store.
    pub fn new(
        dns_cache_path: Option<PathBuf>,
        settings: impl Fn(&str, Option<&str>) -> Option<String> + Send + Sync + 'static,
        membership: impl Fn(Option<&str>) -> String + Send + Sync + 'static,
    ) -> Self {
        let settings: Arc<Settings> = Arc::new(settings);
        let membership: Arc<Membership> = Arc::new(membership);
        Self(Arc::new(Inner {
            dns_cache_path,
            settings,
            membership,
            public_ip: Mutex::new(None),
            observed_ip: Mutex::new(None),
        }))
    }

    pub fn dns_cache_path(&self) -> Option<&Path> { self.0.dns_cache_path.as_deref() }
    pub fn setting(&self, key: &str, peer: Option<&str>) -> Option<String> { (self.0.settings)(key, peer) }
    pub fn membership(&self, peer: Option<&str>) -> String { (self.0.membership)(peer) }
    pub(crate) fn public_ip_cache(&self) -> &Mutex<Option<crate::direct::PubIpEntry>> { &self.0.public_ip }
    pub(crate) fn observed_ip(&self) -> &Mutex<Option<IpAddr>> { &self.0.observed_ip }
}
