use super::*;

fn test_process() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.args(["--ignored", "--nocapture"]);
    command
}

#[tokio::test]
async fn total_timeout_bounds_tls_and_namespace_handshakes() {
    async fn stalled_handshake(tls: bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            if tls {
                // Accept TCP but never send a TLS ServerHello.
                let _socket = socket;
                std::future::pending::<()>().await;
            } else {
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                ws.send(Message::Text("0{}".into())).await.unwrap();
                assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
                // Finish websocket/Engine.IO but never accept the namespace.
                std::future::pending::<()>().await;
                drop(ws);
            }
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let scheme = if tls { "https" } else { "http" };
        let start = std::time::Instant::now();
        let error = match connect(&format!("{scheme}://{addr}"), tx).await {
            Ok(_) => panic!("stalled handshake succeeded"),
            Err(error) => error,
        };
        server.abort();
        assert!(
            error
                .to_string()
                .contains("signaling handshake timed out after 20s"),
            "{error:#}"
        );
        assert!(start.elapsed() >= CONNECT_TIMEOUT);
    }
    // Real local sockets and real time: do not race paused-time auto-advance
    // against network readiness. Both independent 20-second cases run together.
    tokio::join!(stalled_handshake(true), stalled_handshake(false));
}

#[test]
fn provider_isolation_in_fresh_processes() {
    for mode in ["absent", "distinct"] {
        let output = test_process()
            .args(["--exact", "tls_tests::provider_worker"])
            .env("FILAMENT_SIGNAL_TLS_TEST_PROVIDER", mode)
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
    let mode = std::env::var("FILAMENT_SIGNAL_TLS_TEST_PROVIDER").unwrap();
    if mode == "distinct" {
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
    assert!(cfg.enable_sni);
    assert!(
        cfg.alpn_protocols.is_empty(),
        "websocket keeps tungstenite's default ALPN"
    );
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        // Exercise the production connector and both Engine.IO/Socket.IO handshakes
        // over plaintext too: supplying a Rustls connector must not force TLS.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            ws.send(Message::Text("0{}".into())).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
            ws.send(Message::Text("40{}".into())).await.unwrap();
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        connect(&format!("http://{addr}"), tx).await.unwrap();
        server.await.unwrap();

        // A valid localhost identity with an untrusted issuer must fail during TLS,
        // not slip through to the websocket handshake or the total timeout.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let key = rustls::pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
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
            let mut tls = rustls::ServerConnection::new(Arc::new(config)).unwrap();
            assert!(
                tls.complete_io(&mut socket).is_err(),
                "untrusted certificate accepted"
            );
        });
        let (tx, _rx) = mpsc::unbounded_channel();
        let error = match connect(&format!("https://localhost:{}", addr.port()), tx).await {
            Ok(_) => panic!("self-signed certificate accepted"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("UnknownIssuer"), "{error:#}");
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
