//! Trust-store behaviour: what counts as a certificate failure, what
//! `SSL_CERT_FILE` / `SSL_CERT_DIR` load, and an end-to-end signaling connect
//! against a local TLS server whose certificate is signed by a private CA.
//!
//! The end-to-end cases run in fresh child processes, because the trust
//! variables are process-global and the parent test process is concurrent: a
//! test must never set them on itself.

use super::*;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::tungstenite::Message;

fn scratch_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "tunlion-trust-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A private CA and a `localhost` server certificate it signed, as PEM.
struct Pki {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: String,
}

fn pki() -> Pki {
    use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};
    // Validity inside two years around now: well within every platform's
    // policy for a server certificate (macOS caps it at 825 days).
    let year = 1970
        + (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 31_556_952) as i32;
    let (from, to) = (rcgen::date_time_ymd(year - 1, 1, 1), rcgen::date_time_ymd(year + 1, 1, 1));

    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
    ca.distinguished_name.push(DnType::CommonName, "tunlion test inspecting proxy CA");
    ca.not_before = from;
    ca.not_after = to;
    let ca = ca.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    leaf.distinguished_name.push(DnType::CommonName, "localhost");
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.not_before = from;
    leaf.not_after = to;
    let leaf = leaf.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    Pki { ca_pem: ca.pem(), leaf_pem: leaf.pem(), leaf_key_pem: leaf_key.serialize_pem() }
}

// ------------------------------------------------------- classification ---

#[test]
fn certificate_failures_are_found_wherever_they_are_wrapped() {
    let unknown = || rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer);
    // Bare, inside an io::Error payload (tokio-rustls, hyper), and inside
    // tungstenite's boxed TlsError (which hides it from source()).
    assert!(matches!(certificate_error(&unknown()), Some(rustls::CertificateError::UnknownIssuer)));
    let io = std::io::Error::new(std::io::ErrorKind::InvalidData, unknown());
    assert!(matches!(certificate_error(&io), Some(rustls::CertificateError::UnknownIssuer)));
    let ws = tokio_tungstenite::tungstenite::Error::Tls(unknown().into());
    assert!(matches!(certificate_error(&ws), Some(rustls::CertificateError::UnknownIssuer)));
    let ws_io = tokio_tungstenite::tungstenite::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        rustls::Error::InvalidCertificate(rustls::CertificateError::NotValidForName),
    ));
    assert!(matches!(certificate_error(&ws_io), Some(rustls::CertificateError::NotValidForName)));
    // Through an anyhow context chain, the shape the CLI receives.
    let chained = anyhow::Error::new(ws_io).context("websocket connect to wss://x").context("signaling connect to https://x");
    assert!(chained.chain().any(|c| certificate_error(c).is_some()));
    assert!(is_certificate_text(&format!("{chained:#}")), "{chained:#}");

    // Ordinary network failures are not certificate failures.
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::TimedOut,
    ] {
        let e = std::io::Error::from(kind);
        assert!(certificate_error(&e).is_none(), "{kind:?}");
        assert!(!is_certificate_text(&e.to_string()), "{kind:?}");
    }
    let other_tls = rustls::Error::AlertReceived(rustls::AlertDescription::HandshakeFailure);
    assert!(certificate_error(&other_tls).is_none());
    assert!(!is_certificate_text(&other_tls.to_string()));
}

#[test]
fn certificate_text_matches_trust_failures_and_nothing_else() {
    for yes in [
        "websocket connect to wss://x/socket.io/: IO error: invalid peer certificate: UnknownIssuer",
        "GET https://x/api/config: error sending request for url (https://x/api/config): client error (Connect): invalid peer certificate: Expired",
        "loading the TLS trust store: No CA certificates were loaded from the system",
        "no CA certificates were loaded from SSL_CERT_FILE (/nope.pem): No such file or directory (os error 2)",
        UNTRUSTED_LINE,
    ] {
        assert!(is_certificate_text(yes), "{yes}");
    }
    for no in [
        "signaling connect to https://x: failed to lookup address information: Try again",
        "tcp connect to 127.0.0.1:443: Connection refused (os error 111)",
        "signaling handshake timed out after 20s",
        "received fatal alert: HandshakeFailure",
        "peer sent no certificates",
    ] {
        assert!(!is_certificate_text(no), "{no}");
    }
}

#[test]
fn the_sentence_says_which_trust_failure_it_was() {
    assert_eq!(untrusted_line_for("invalid peer certificate: UnknownIssuer"), UNTRUSTED_LINE);
    assert_eq!(untrusted_line_for("No CA certificates were loaded from the system"), NO_TRUST_STORE_LINE);
    assert_eq!(
        untrusted_line_for("no CA certificates were loaded from SSL_CERT_FILE (/x.pem): not found"),
        NO_TRUST_STORE_LINE
    );
    for line in [UNTRUSTED_LINE, NO_TRUST_STORE_LINE] {
        assert!(!line.contains('\u{2014}'), "no em dash: {line}");
        assert!(line.contains("SSL_CERT_FILE"), "names the fix: {line}");
        assert!(is_certificate_text(line), "re-classifies as itself: {line}");
    }
}

// ------------------------------------------------------ SSL_CERT_* loader ---

#[test]
fn env_values_follow_openssl_syntax() {
    assert!(!EnvRoots::from_values(None, None).is_set());
    assert!(!EnvRoots::from_values(Some("".into()), Some("".into())).is_set(), "empty means unset");
    let joined = std::env::join_paths(["/a", "/b"]).unwrap();
    let roots = EnvRoots::from_values(Some("/ca.pem".into()), Some(joined));
    assert_eq!(roots.file.as_deref(), Some(Path::new("/ca.pem")));
    assert_eq!(roots.dirs, [PathBuf::from("/a"), PathBuf::from("/b")]);
}

#[test]
fn env_roots_load_the_file_and_directory_and_fail_closed() {
    let pki = pki();
    let dir = scratch_dir("load");
    let ca_dir = dir.join("ca");
    std::fs::create_dir(&ca_dir).unwrap();
    let file = dir.join("bundle.pem");
    // A bundle with a key and a comment in it: only certificates count.
    std::fs::write(&file, format!("# corporate bundle\n{}{}", pki.leaf_key_pem, pki.ca_pem)).unwrap();
    std::fs::write(ca_dir.join("ca.pem"), &pki.ca_pem).unwrap();
    std::fs::create_dir(ca_dir.join("subdir")).unwrap();

    let from_file = EnvRoots { file: Some(file.clone()), dirs: vec![] }.load().unwrap();
    assert_eq!(from_file.len(), 1);
    let from_dir = EnvRoots { file: None, dirs: vec![ca_dir.clone()] }.load().unwrap();
    assert_eq!(from_dir, from_file, "the same CA, read from the directory");
    let both = EnvRoots { file: Some(file.clone()), dirs: vec![ca_dir.clone()] }.load().unwrap();
    assert_eq!(both.len(), 2);
    assert!(EnvRoots::default().load().unwrap().is_empty(), "unset adds nothing");

    // Set on purpose but loads nothing: an error that names the variable.
    let missing = EnvRoots { file: Some(dir.join("nope.pem")), dirs: vec![] }.load().unwrap_err();
    assert!(missing.to_string().contains("SSL_CERT_FILE"), "{missing}");
    assert!(is_certificate_text(&missing.to_string()), "{missing}");
    let empty = dir.join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let none = EnvRoots { file: Some(empty), dirs: vec![] }.load().unwrap_err();
    assert!(is_certificate_text(&none.to_string()), "{none}");
    let bad_dir = EnvRoots { file: None, dirs: vec![dir.join("no-such-dir")] }.load().unwrap_err();
    assert!(bad_dir.to_string().contains("SSL_CERT_DIR"), "{bad_dir}");

    // The Mozilla verifier accepts the extra root (Android, and Linux's
    // fallback when there is no system store).
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    mozilla_verifier(from_file, provider).unwrap();
    std::fs::remove_dir_all(dir).unwrap();
}

// ----------------------------------------------- end to end, signaling ---

fn test_process() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.args(["--ignored", "--nocapture", "--exact", "tls::trust_tests::trust_worker"]);
    command.env_remove("SSL_CERT_FILE").env_remove("SSL_CERT_DIR");
    command
}

/// The reported case: behind a TLS-inspecting proxy, the signaling client
/// rejected the proxy's certificate even when its CA was configured. Without
/// the CA the connect fails as a certificate error (never a timeout or a
/// network error); with `SSL_CERT_FILE` or `SSL_CERT_DIR` naming the CA, the
/// full websocket, Engine.IO and Socket.IO handshake completes.
#[test]
fn signaling_trusts_a_private_ca_only_when_configured() {
    let pki = pki();
    let dir = scratch_dir("e2e");
    let ca_dir = dir.join("ca");
    std::fs::create_dir(&ca_dir).unwrap();
    std::fs::write(dir.join("leaf.pem"), &pki.leaf_pem).unwrap();
    std::fs::write(dir.join("leaf.key"), &pki.leaf_key_pem).unwrap();
    std::fs::write(ca_dir.join("ca.pem"), &pki.ca_pem).unwrap();

    let run = |mode: &str, env: &[(&str, PathBuf)]| {
        let mut command = test_process();
        command.env("TUNLION_TRUST_TEST_MODE", mode).env("TUNLION_TRUST_TEST_DIR", &dir);
        for (k, v) in env {
            command.env(k, v);
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{mode}: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run("untrusted", &[]);
    run("trusted", &[("SSL_CERT_FILE", ca_dir.join("ca.pem"))]);
    run("trusted", &[("SSL_CERT_DIR", ca_dir.clone())]);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
#[ignore = "run only by signaling_trusts_a_private_ca_only_when_configured"]
fn trust_worker() {
    use rustls::pki_types::{PrivateKeyDer, pem::PemObject};
    let mode = std::env::var("TUNLION_TRUST_TEST_MODE").unwrap();
    let dir = PathBuf::from(std::env::var_os("TUNLION_TRUST_TEST_DIR").unwrap());
    let chain = CertificateDer::pem_file_iter(dir.join("leaf.pem"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(dir.join("leaf.key")).unwrap();
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    rt.block_on(async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            // An untrusting client aborts the handshake; that is the expected
            // end of this server in the untrusted case.
            let Ok(tls) = acceptor.accept(tcp).await else { return false };
            let mut ws = tokio_tungstenite::accept_async(tls).await.unwrap();
            ws.send(Message::Text("0{}".into())).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
            ws.send(Message::Text("40{}".into())).await.unwrap();
            true
        });
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel();
        let started = std::time::Instant::now();
        let result = crate::connect(&format!("https://localhost:{port}"), tx).await;
        match mode.as_str() {
            "untrusted" => {
                let error = match result {
                    Ok(_) => panic!("a certificate from an unconfigured CA was accepted"),
                    Err(error) => error,
                };
                let cert = error.chain().find_map(|c| certificate_error(c));
                assert!(cert.is_some(), "expected a certificate-validation error: {error:#}");
                #[cfg(any(target_os = "linux", target_os = "android"))]
                assert!(matches!(cert, Some(rustls::CertificateError::UnknownIssuer)), "{error:#}");
                assert!(is_certificate_text(&format!("{error:#}")), "{error:#}");
                assert!(started.elapsed() < std::time::Duration::from_secs(10), "failed at the TLS step, not the timeout");
                assert!(!server.await.unwrap(), "the server must not have completed a handshake");
            }
            "trusted" => {
                let client = result.unwrap_or_else(|e| panic!("the configured CA was not trusted: {e:#}"));
                assert!(server.await.unwrap(), "the server completed the Socket.IO handshake");
                drop(client);
            }
            other => panic!("unknown mode {other}"),
        }
    });
}
