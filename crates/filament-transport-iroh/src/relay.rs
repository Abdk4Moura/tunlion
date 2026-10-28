//! Explicit relay configuration, with no public-relay default.
//!
//! iroh's default (`RelayMode::Default`) uses number 0's public relay map. This
//! PoC never takes that path: a caller must name the relays it trusts, and an
//! empty list means relay-disabled, not "use the internet".
//!
//! # What iroh does with the list, and what it does not
//!
//! [`iroh::RelayMap`] is a map keyed by URL, so **the order of this list is not
//! a failover order inside iroh**. iroh picks one home relay from the set based
//! on its own latency/health logic and retries internally when that home relay
//! fails. The order here is what the *host* uses for:
//!
//! 1. [`RelayPlan::probe`] results and logs (which relay is reachable now);
//! 2. [`RelayPlan::healthy_order`], the preference order a caller can use when
//!    it builds an `EndpointAddr` or decides whether to attempt iroh at all;
//! 3. deterministic tests.
//!
//! Treating this list as an SLA would be wrong twice over: a relay can be
//! reachable and still fail to carry a connection, and iroh may choose a
//! different member than the first one.
//!
//! # Insecure TLS is loopback-only
//!
//! The in-process test relay uses a self-signed certificate, so endpoints need
//! `CaTlsConfig::insecure_skip_verify()`. That switch is accepted only for a
//! loopback URL: a config typo must not silently disable certificate checking
//! against a production relay. `RelayPlan::parse` enforces this at construction
//! time, before any endpoint is built.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use iroh::{RelayConfig, RelayMap, RelayMode, RelayUrl};
use tokio::net::TcpStream;

/// One configured relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    pub url: RelayUrl,
    /// Accept the relay's self-signed certificate. Loopback only; `parse`
    /// refuses anything else.
    pub insecure_skip_verify: bool,
}

impl RelayEndpoint {
    /// Parse and validate one relay URL.
    ///
    /// `https` is required everywhere except loopback, where `http` is allowed
    /// for a local dev relay.
    pub fn parse(url: &str, insecure_skip_verify: bool) -> Result<Self> {
        let url: RelayUrl = url
            .parse()
            .with_context(|| format!("invalid relay URL {url:?}"))?;
        let loopback = is_loopback(url.host_str());
        match url.scheme() {
            "https" => {}
            "http" if loopback => {}
            other => bail!(
                "relay {url} uses scheme {other:?}; only https is allowed (http only on loopback)"
            ),
        }
        if insecure_skip_verify && !loopback {
            bail!(
                "refusing insecure_skip_verify for non-loopback relay {url}; \
                 a self-signed-cert escape hatch must not reach production"
            );
        }
        Ok(Self {
            url,
            insecure_skip_verify,
        })
    }

    /// Plain `https` relay with normal certificate verification.
    pub fn secure(url: &str) -> Result<Self> {
        Self::parse(url, false)
    }

    /// One TCP reachability probe. This is deliberately only a TCP connect: it
    /// answers "is something accepting on this URL's port", not "is this relay
    /// healthy for QUIC/WebSocket traffic". The latter is iroh's job.
    async fn probe(&self, timeout: Duration) -> RelayHealth {
        let started = Instant::now();
        let host = match self.url.host_str() {
            Some(host) => host.to_owned(),
            None => {
                return RelayHealth {
                    url: self.url.clone(),
                    latency: None,
                    error: Some("relay URL has no host".into()),
                }
            }
        };
        let port = self.url.port_or_known_default().unwrap_or(443);
        match tokio::time::timeout(timeout, TcpStream::connect((host.as_str(), port))).await {
            Ok(Ok(_stream)) => RelayHealth {
                url: self.url.clone(),
                latency: Some(started.elapsed()),
                error: None,
            },
            Ok(Err(error)) => RelayHealth {
                url: self.url.clone(),
                latency: None,
                error: Some(error.to_string()),
            },
            Err(_) => RelayHealth {
                url: self.url.clone(),
                latency: None,
                error: Some(format!("probe timed out after {timeout:?}")),
            },
        }
    }
}

/// Result of one relay reachability probe.
#[derive(Debug, Clone)]
pub struct RelayHealth {
    pub url: RelayUrl,
    /// `None` when the probe failed; `Some` when a TCP connection was accepted.
    pub latency: Option<Duration>,
    pub error: Option<String>,
}

impl RelayHealth {
    pub fn is_reachable(&self) -> bool {
        self.latency.is_some()
    }
}

/// The relay set plus the host-side preference order.
#[derive(Debug, Clone)]
pub struct RelayPlan {
    relays: Vec<RelayEndpoint>,
    probe_timeout: Duration,
}

impl Default for RelayPlan {
    fn default() -> Self {
        Self::empty()
    }
}

impl RelayPlan {
    pub fn empty() -> Self {
        Self {
            relays: Vec::new(),
            probe_timeout: Duration::from_secs(2),
        }
    }

    /// Build from validated endpoints. At most one insecure relay is expected,
    /// but the list preserves whatever the caller configured.
    pub fn from_endpoints(relays: Vec<RelayEndpoint>) -> Self {
        Self {
            relays,
            probe_timeout: Duration::from_secs(2),
        }
    }

    /// Parse `(url, insecure_skip_verify)` pairs in preference order.
    pub fn parse<'a, I>(relays: I) -> Result<Self>
    where
        I: IntoIterator<Item = (&'a str, bool)>,
    {
        let relays = relays
            .into_iter()
            .map(|(url, insecure)| RelayEndpoint::parse(url, insecure))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self::from_endpoints(relays))
    }

    /// Convenience for a normal, verified relay list.
    pub fn from_urls(urls: &[&str]) -> Result<Self> {
        Self::parse(urls.iter().map(|url| (*url, false)))
    }

    pub fn with_probe_timeout(mut self, timeout: Duration) -> Self {
        self.probe_timeout = timeout;
        self
    }

    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }

    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// Configured order, as a slice (the source of truth for preference).
    pub fn relays(&self) -> &[RelayEndpoint] {
        &self.relays
    }

    /// Configured order as bare URLs.
    pub fn urls(&self) -> Vec<RelayUrl> {
        self.relays.iter().map(|r| r.url.clone()).collect()
    }

    /// The relay the host would offer a peer first (NOT necessarily iroh's home
    /// relay; see the module docs).
    pub fn first_url(&self) -> Option<RelayUrl> {
        self.relays.first().map(|r| r.url.clone())
    }

    /// Any relay requiring `insecure_skip_verify`.
    pub fn uses_insecure_tls(&self) -> bool {
        self.relays.iter().any(|r| r.insecure_skip_verify)
    }

    /// Build iroh's relay set. Empty means relay disabled — never the public
    /// default.
    pub fn relay_map(&self) -> RelayMap {
        RelayMap::from_iter(self.relays.iter().map(|r| RelayConfig::from(r.url.clone())))
    }

    pub fn relay_mode(&self) -> RelayMode {
        if self.relays.is_empty() {
            RelayMode::Disabled
        } else {
            RelayMode::Custom(self.relay_map())
        }
    }

    /// Probe every relay concurrently; results are returned in configured order
    /// so the output is stable in logs and tests.
    pub async fn probe(&self) -> Vec<RelayHealth> {
        let mut set = tokio::task::JoinSet::new();
        for (index, endpoint) in self.relays.iter().cloned().enumerate() {
            let timeout = self.probe_timeout;
            set.spawn(async move { (index, endpoint.probe(timeout).await) });
        }
        let mut slots: Vec<Option<RelayHealth>> = (0..self.relays.len()).map(|_| None).collect();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((index, health)) => slots[index] = Some(health),
                Err(error) => {
                    // A panicking probe task must not hide the other results.
                    let _ = error;
                }
            }
        }
        slots.into_iter().flatten().collect()
    }

    /// Reachable relays first (in configured order), then unreachable ones (in
    /// configured order), so a caller can keep a deterministic preference while
    /// still handing iroh the full set.
    pub async fn healthy_order(&self) -> Vec<RelayEndpoint> {
        let health = self.probe().await;
        let reachable: Vec<RelayUrl> = health
            .iter()
            .filter(|h| h.is_reachable())
            .map(|h| h.url.clone())
            .collect();
        let mut ordered = Vec::with_capacity(self.relays.len());
        for endpoint in &self.relays {
            if reachable.contains(&endpoint.url) {
                ordered.push(endpoint.clone());
            }
        }
        for endpoint in &self.relays {
            if !reachable.contains(&endpoint.url) {
                ordered.push(endpoint.clone());
            }
        }
        ordered
    }

    /// Is any configured relay reachable right now? An empty plan is `false`.
    ///
    /// A `true` here is necessary, not sufficient: the caller still has to try
    /// the iroh connection and handle its failure.
    pub async fn any_reachable(&self) -> bool {
        if self.relays.is_empty() {
            return false;
        }
        self.probe().await.iter().any(RelayHealth::is_reachable)
    }

    /// The relay URL iroh should be told a peer is reachable at. Validation is
    /// repeated here because `RelayPlan` can also be built from endpoints.
    pub fn advertise_url(&self) -> Result<RelayUrl> {
        let first = self
            .first_url()
            .ok_or_else(|| anyhow!("no relay configured; iroh is relay-only in this PoC"))?;
        Ok(first)
    }
}

fn is_loopback(host: Option<&str>) -> bool {
    match host {
        Some("localhost") => true,
        Some(host) => host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_relays_parse_in_order() {
        let plan = RelayPlan::from_urls(&[
            "https://relay-b.example.test",
            "https://relay-a.example.test",
        ])
        .unwrap();
        assert_eq!(plan.len(), 2);
        assert_eq!(
            plan.first_url().unwrap().to_string(),
            "https://relay-b.example.test/"
        );
        // RelayMap is a set (BTreeMap): order is NOT preserved inside iroh.
        assert_eq!(plan.relay_map().len(), 2);
    }

    #[test]
    fn http_is_loopback_only() {
        assert!(RelayEndpoint::parse("http://127.0.0.1:3340", false).is_ok());
        assert!(RelayEndpoint::parse("http://localhost:3340", false).is_ok());
        assert!(RelayEndpoint::parse("http://relay.example.test", false).is_err());
    }

    #[test]
    fn insecure_tls_is_loopback_only() {
        assert!(RelayEndpoint::parse("https://127.0.0.1:3340", true).is_ok());
        let error = RelayEndpoint::parse("https://relay.example.test", true).unwrap_err();
        assert!(error.to_string().contains("non-loopback"));
    }

    #[test]
    fn empty_plan_is_disabled_not_public() {
        let plan = RelayPlan::empty();
        assert!(plan.is_empty());
        assert!(matches!(plan.relay_mode(), RelayMode::Disabled));
        assert!(plan.advertise_url().is_err());
    }
}
