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
#[ignore = "run only by provider_isolation_in_fresh_processes"]
fn provider_worker() {
    use rustls::crypto::CryptoProvider;
    assert!(CryptoProvider::get_default().is_none());
    let mode = std::env::var("FILAMENT_HTTP_TLS_TEST_PROVIDER").unwrap();
    if mode == "distinct" {
        // A valid but distinguishable host policy, without adding another backend.
        let mut host = rustls::crypto::ring::default_provider();
        host.cipher_suites.reverse();
        host.install_default().unwrap();
    }
    let cfg = tls_config();
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
    let client = client_builder().no_proxy().build().unwrap();
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
