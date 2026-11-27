//! Configuration and discovery ownership for one engine. Clone for its sessions
//! and detached tasks; construct independently for another engine.
use std::{net::IpAddr, path::{Path, PathBuf}, sync::Arc};
use tokio::sync::Mutex;

type Settings = dyn Fn(&str, Option<&str>) -> Option<String> + Send + Sync;
type Membership = dyn Fn(Option<&str>) -> String + Send + Sync;

#[derive(Clone)]
pub struct TransportContext(Arc<Inner>);

#[cfg(feature = "sim")]
pub trait SignalingConnector: Send + Sync {
    fn connect<'a>(
        &'a self,
        server: &'a str,
        tx: tokio::sync::mpsc::UnboundedSender<filament_signal::Incoming>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<filament_signal::Client>> + Send + 'a>,
    >;
}

#[cfg(feature = "sim")]
pub trait HttpBackend: Send + Sync {
    fn get_json<'a>(
        &'a self,
        url: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = anyhow::Result<serde_json::Value>> + Send + 'a>,
    >;
}

struct Inner {
    dns_cache_path: Option<PathBuf>,
    settings: Arc<Settings>,
    membership: Arc<Membership>,
    public_ip: Mutex<Option<crate::direct::PubIpEntry>>,
    observed_ip: Mutex<Option<IpAddr>>,
    #[cfg(feature = "sim")]
    signaling_connector: Option<Arc<dyn SignalingConnector>>,
    #[cfg(feature = "sim")]
    http_backend: Option<Arc<dyn HttpBackend>>,
    #[cfg(feature = "sim")]
    peer_factory: Option<Arc<dyn crate::net::PeerFactory>>,
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
            #[cfg(feature = "sim")]
            signaling_connector: None,
            #[cfg(feature = "sim")]
            http_backend: None,
            #[cfg(feature = "sim")]
            peer_factory: None,
        }))
    }

    pub fn dns_cache_path(&self) -> Option<&Path> { self.0.dns_cache_path.as_deref() }
    pub fn setting(&self, key: &str, peer: Option<&str>) -> Option<String> { (self.0.settings)(key, peer) }
    pub fn membership(&self, peer: Option<&str>) -> String { (self.0.membership)(peer) }
    pub(crate) fn public_ip_cache(&self) -> &Mutex<Option<crate::direct::PubIpEntry>> { &self.0.public_ip }
    pub(crate) fn observed_ip(&self) -> &Mutex<Option<IpAddr>> { &self.0.observed_ip }

    #[cfg(feature = "sim")]
    pub fn with_signaling_connector(&self, connector: Arc<dyn SignalingConnector>) -> Self {
        Self(Arc::new(Inner {
            dns_cache_path: self.0.dns_cache_path.clone(),
            settings: Arc::clone(&self.0.settings),
            membership: Arc::clone(&self.0.membership),
            public_ip: Mutex::new(None),
            observed_ip: Mutex::new(None),
            signaling_connector: Some(connector),
            http_backend: self.0.http_backend.clone(),
            peer_factory: self.0.peer_factory.clone(),
        }))
    }

    #[cfg(feature = "sim")]
    pub fn signaling_connector(&self) -> Option<&Arc<dyn SignalingConnector>> {
        self.0.signaling_connector.as_ref()
    }

    #[cfg(feature = "sim")]
    pub fn with_http_backend(&self, backend: Arc<dyn HttpBackend>) -> Self {
        Self(Arc::new(Inner {
            dns_cache_path: self.0.dns_cache_path.clone(),
            settings: Arc::clone(&self.0.settings),
            membership: Arc::clone(&self.0.membership),
            public_ip: Mutex::new(None),
            observed_ip: Mutex::new(None),
            signaling_connector: self.0.signaling_connector.clone(),
            http_backend: Some(backend),
            peer_factory: self.0.peer_factory.clone(),
        }))
    }

    #[cfg(feature = "sim")]
    pub fn http_backend(&self) -> Option<&Arc<dyn HttpBackend>> {
        self.0.http_backend.as_ref()
    }

    #[cfg(feature = "sim")]
    pub fn with_peer_factory(&self, factory: Arc<dyn crate::net::PeerFactory>) -> Self {
        Self(Arc::new(Inner {
            dns_cache_path: self.0.dns_cache_path.clone(),
            settings: Arc::clone(&self.0.settings),
            membership: Arc::clone(&self.0.membership),
            public_ip: Mutex::new(None),
            observed_ip: Mutex::new(None),
            signaling_connector: self.0.signaling_connector.clone(),
            http_backend: self.0.http_backend.clone(),
            peer_factory: Some(factory),
        }))
    }

    #[cfg(feature = "sim")]
    pub fn peer_factory(&self) -> Option<&Arc<dyn crate::net::PeerFactory>> {
        self.0.peer_factory.as_ref()
    }
}
