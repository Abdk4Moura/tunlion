use super::*;

#[test]
fn provider_isolation_in_fresh_processes() {
    for mode in ["absent", "distinct"] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "http::tls_tests::provider_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("FILAMENT_HTTP_TLS_TEST_PROVIDER", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}

#[test]
#[ignore = "run only by the fresh-process provider/trust regressions"]
fn provider_worker() {
    use rustls::crypto::CryptoProvider;
    assert!(CryptoProvider::get_default().is_none());
    let mode = std::env::var("FILAMENT_HTTP_TLS_TEST_PROVIDER").unwrap();
    if mode.ends_with("distinct") {
        // A valid but distinguishable host policy, without adding another backend.
        let mut host = rustls::crypto::ring::default_provider();
        host.cipher_suites.reverse();
        host.install_default().unwrap();
    }
    if mode.starts_with("empty-") {
        let result = std::panic::catch_unwind(client_builder).expect("factory must not panic");
        let error = match result {
            Ok(_) => panic!("empty platform trust store must fail closed"),
            Err(error) => error,
        };
        assert!(
            matches!(error, rustls::Error::General(ref message)
            if message == "No CA certificates were loaded from the system"),
            "{error:?}"
        );
        match CryptoProvider::get_default() {
            None => assert_eq!(mode, "empty-absent"),
            Some(host) => {
                assert_eq!(mode, "empty-distinct");
                let mut expected = rustls::crypto::ring::default_provider().cipher_suites;
                expected.reverse();
                assert_eq!(
                    host.cipher_suites
                        .iter()
                        .map(|s| s.suite())
                        .collect::<Vec<_>>(),
                    expected.iter().map(|s| s.suite()).collect::<Vec<_>>()
                );
            }
        }
        return;
    }
    let cfg = tls_config().unwrap();
    let suites = |p: &CryptoProvider| {
        p.cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        suites(cfg.crypto_provider()),
        suites(&rustls::crypto::ring::default_provider())
    );
    assert_eq!(cfg.alpn_protocols, [b"h2".to_vec(), b"http/1.1".to_vec()]);
    assert!(cfg.enable_sni);
    let client = client_builder().unwrap().no_proxy().build().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .unwrap();
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut tls = rustls::ServerConnection::new(std::sync::Arc::new(config)).unwrap();
            assert!(
                tls.complete_io(&mut socket).is_err(),
                "untrusted certificate accepted"
            );
        });
        let error = client
            .get(format!("https://localhost:{}/", addr.port()))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .unwrap_err();
        assert!(error.is_connect(), "{error:?}");
        assert!(
            !error.is_timeout(),
            "certificate failure must not be a timeout: {error:?}"
        );
        assert!(certificate_error(&error).is_some(),
            "expected a rustls certificate-validation source, not a connection/reset error: {error:?}");
        #[cfg(any(target_os = "linux", target_os = "android"))]
        assert!(matches!(certificate_error(&error), Some(rustls::CertificateError::UnknownIssuer)),
            "expected untrusted issuer: {error:?}");
        server.join().unwrap();
    });
    match CryptoProvider::get_default() {
        None => assert_eq!(mode, "absent"),
        Some(host) => {
            assert_eq!(mode, "distinct");
            assert_ne!(suites(cfg.crypto_provider()), suites(host));
        }
    }
}

// io::Error may hide its wrapped error from Error::source(), so inspect both
// its payload and the ordinary chain. Do not accept arbitrary connect failures.
fn certificate_error<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a rustls::CertificateError> {
    if let Some(rustls::Error::InvalidCertificate(cert)) = error.downcast_ref::<rustls::Error>() {
        return Some(cert);
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        if let Some(cert) = io.get_ref().and_then(|inner| certificate_error(inner)) {
            return Some(cert);
        }
    }
    error.source().and_then(certificate_error)
}

#[cfg(target_os = "linux")]
#[test]
fn empty_trust_store_returns_error_in_fresh_processes() {
    // Set environment only on child processes, before the platform loader runs.
    // Never mutate the concurrent parent test process's trust or provider state.
    let dir = std::env::temp_dir().join(format!(
        "filament-empty-trust-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir(&dir).unwrap();
    let file = dir.join("empty.pem");
    std::fs::write(&file, "").unwrap();
    let outputs = ["empty-absent", "empty-distinct"].map(|mode| {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "http::tls_tests::provider_worker",
                "--ignored",
                "--nocapture",
            ])
            .env("FILAMENT_HTTP_TLS_TEST_PROVIDER", mode)
            .env("SSL_CERT_FILE", &file)
            .env("SSL_CERT_DIR", &dir)
            .output()
            .unwrap();
        (mode, output)
    });
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(dir).unwrap();
    for (mode, output) in outputs {
        assert!(
            output.status.success(),
            "{mode}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
    }
}

#[test]
fn connection_failures_are_not_certificate_validation() {
    let reset = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
    assert!(certificate_error(&reset).is_none());
    let refused = std::io::Error::from(std::io::ErrorKind::ConnectionRefused);
    assert!(certificate_error(&refused).is_none());
    let invalid = std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
    );
    assert!(matches!(
        certificate_error(&invalid),
        Some(rustls::CertificateError::UnknownIssuer)
    ));
}
