//! One place every HTTP client is built, so TLS trust is decided once.
//!
//! reqwest's rustls backend verifies against the platform's trust store. On
//! Android that verifier needs a Java VM handed to it at startup, which a plain
//! executable (what the Android app wraps) does not have, and it panics on the
//! first HTTPS request. On Android the client therefore carries the Mozilla root
//! set (webpki-roots) instead, the same roots the signaling websocket already
//! uses. Every other platform keeps the platform verifier.

/// A `reqwest::ClientBuilder` with this platform's TLS trust configured.
///
/// Panics if the platform verifier cannot initialize its trust store.
/// TLS uses ring regardless of the process-default rustls provider, without
/// installing or replacing that default.
pub fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().tls_backend_preconfigured(tls_config())
}

fn tls_config() -> rustls::ClientConfig {
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("ring supports the default TLS versions");
    #[cfg(target_os = "android")]
    let builder = builder.with_root_certificates(rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    });
    // This is the same verifier (and constructor) used by reqwest 0.13.4.
    // `dangerous` selects a custom verifier API, not relaxed verification.
    #[cfg(not(target_os = "android"))]
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(
            rustls_platform_verifier::Verifier::new(provider)
                .expect("platform TLS verifier initialization failed"),
        ));
    let mut cfg = builder.with_no_client_auth();
    // reqwest preserves preconfigured ALPN. Match its default HTTP/2 + HTTP/1.1
    // configuration rather than silently losing HTTP/2 on desktop.
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    cfg
}

#[cfg(test)]
#[path = "http_tls_tests.rs"]
mod tls_tests;
