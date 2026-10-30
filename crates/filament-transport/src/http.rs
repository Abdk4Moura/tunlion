//! One place every HTTP client is built, so TLS trust is decided once.
//!
//! The trust itself lives in `filament_signal::tls`, shared with the signaling
//! websocket and the TURN-over-TLS bridge, so all three accept exactly the same
//! certificates: the OS trust store plus `SSL_CERT_FILE` / `SSL_CERT_DIR`, and
//! the Mozilla roots on Android (where the platform verifier needs a Java VM
//! that a plain executable does not have). See that module for the details.

/// A `reqwest::ClientBuilder` with this platform's TLS trust configured.
///
/// Returns the TLS initialization error if the platform trust store cannot load.
/// TLS uses ring regardless of the process-default rustls provider, without
/// installing or replacing that default.
///
/// The preconfigured backend owns TLS policy, including ALPN. Later reqwest TLS
/// options (roots, identity, versions, SNI, verification, key logging) do not
/// reconfigure it. HTTP version preference methods do not rewrite its fixed
/// `h2`/`http/1.1` ALPN list. Ordinary timeout, DNS, proxy and header options work.
pub fn client_builder() -> Result<reqwest::ClientBuilder, rustls::Error> {
    Ok(reqwest::Client::builder().tls_backend_preconfigured(tls_config()?))
}

fn tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let mut cfg = filament_signal::tls::client_config()?;
    // reqwest preserves preconfigured ALPN. Match its default HTTP/2 + HTTP/1.1
    // configuration rather than silently losing HTTP/2 on desktop.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(cfg)
}

/// The same trust decision as every HTTPS client, with no ALPN: for the
/// TURN-over-TLS bridge (`turn_bridge`), which speaks STUN framing, not HTTP.
pub(crate) fn turn_tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    filament_signal::tls::client_config()
}

#[cfg(test)]
#[path = "http_tls_tests.rs"]
mod tls_tests;
