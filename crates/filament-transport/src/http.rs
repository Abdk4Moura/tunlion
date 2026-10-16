//! One place every HTTP client is built, so TLS trust is decided once.
//!
//! reqwest's rustls backend verifies against the platform's trust store. On
//! Android that verifier needs a Java VM handed to it at startup, which a plain
//! executable (what the Android app wraps) does not have, and it panics on the
//! first HTTPS request. On Android the client therefore carries the Mozilla root
//! set (webpki-roots) instead, the same roots the signaling websocket already
//! uses. Every other platform keeps the platform verifier.

/// A `reqwest::ClientBuilder` with this platform's TLS trust configured.
pub fn client_builder() -> reqwest::ClientBuilder {
    #[cfg(target_os = "android")]
    {
        reqwest::Client::builder().use_preconfigured_tls(android_tls())
    }
    #[cfg(not(target_os = "android"))]
    {
        reqwest::Client::builder()
    }
}

#[cfg(target_os = "android")]
fn android_tls() -> rustls::ClientConfig {
    let roots = rustls::RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}
