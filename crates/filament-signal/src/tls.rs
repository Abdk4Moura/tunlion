//! TLS trust for every client that talks to tunlion's own servers.
//!
//! The signaling websocket, the HTTPS API client and the TURN-over-TLS bridge
//! all build their rustls config here, so a certificate one of them trusts the
//! other two trust as well. Before this the websocket trusted only the
//! compiled-in Mozilla roots while HTTPS used the operating system's store, so
//! behind a TLS-inspecting proxy whose CA is installed on the machine the API
//! calls worked and signaling failed.
//!
//! What is trusted, per platform:
//!
//! * Linux and other non-Apple Unix: the system store, read the way OpenSSL
//!   reads it. `SSL_CERT_FILE` / `SSL_CERT_DIR`, when set, REPLACE the default
//!   locations (as they do for OpenSSL, curl and git), so point them at a
//!   bundle that includes your CA. With neither set and no system store at all
//!   (a minimal container, a static binary on a bare image) the Mozilla roots
//!   are used instead of failing every connection.
//! * macOS and Windows: the OS trust store and its policy, with the
//!   certificates in `SSL_CERT_FILE` / `SSL_CERT_DIR` ADDED to it.
//! * Android: the Mozilla roots plus `SSL_CERT_FILE` / `SSL_CERT_DIR`. The
//!   platform verifier needs a Java VM handed to it at startup, which the
//!   plain executable the Android app wraps does not have.
//!
//! A variable that is set but names nothing loadable is an error, never a
//! silent fallback: someone set it on purpose. Verification itself (chain,
//! hostname, validity) is never relaxed on any platform.
//!
//! The crypto provider is ring, chosen explicitly. This never reads or installs
//! the process-global rustls provider: an embedder may have installed a
//! different one for its own reasons, and a library replacing it would be a
//! side effect nobody asked for.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::CertificateDer;

/// What a person sees when one of tunlion's servers presents a certificate
/// this machine does not trust. Shared so the CLI, the daemon log and
/// `tunlion doctor` say the same thing.
pub const UNTRUSTED_LINE: &str = "The tunlion server's TLS certificate was not trusted. \
A proxy that inspects TLS, or a missing CA? Set SSL_CERT_FILE to your CA bundle.";

/// What a person sees when no trust store could be loaded at all, so no
/// certificate was even looked at: `SSL_CERT_FILE` / `SSL_CERT_DIR` set to
/// something with no certificate in it, or no system store.
pub const NO_TRUST_STORE_LINE: &str = "No CA certificates could be loaded, so no TLS server can be trusted. \
Point SSL_CERT_FILE at a PEM bundle that includes your CA, or unset it to use the system store.";

/// The sentence for a trust failure whose text is `s` (see
/// [`is_certificate_text`]): [`NO_TRUST_STORE_LINE`] when the store itself
/// loaded nothing, [`UNTRUSTED_LINE`] otherwise.
pub fn untrusted_line_for(s: &str) -> &'static str {
    let s = s.to_lowercase();
    if s.contains("no ca certificates were loaded") && !s.contains("invalid peer certificate") {
        NO_TRUST_STORE_LINE
    } else {
        UNTRUSTED_LINE
    }
}

/// The rustls client config for tunlion's servers: ring, the default protocol
/// versions, SNI on, no ALPN (callers that speak HTTP add their own).
///
/// Returns the trust-store error when no trust can be established (for
/// example `SSL_CERT_FILE` names an empty or unreadable file).
pub fn client_config() -> Result<rustls::ClientConfig, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    // `dangerous` selects the custom-verifier API, not relaxed verification:
    // every verifier below is a full WebPKI or OS chain-and-name check.
    Ok(builder
        .dangerous()
        .with_custom_certificate_verifier(server_verifier(provider)?)
        .with_no_client_auth())
}

#[cfg(all(unix, not(target_os = "android"), not(target_vendor = "apple")))]
fn server_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, rustls::Error> {
    // The platform verifier reads SSL_CERT_FILE / SSL_CERT_DIR itself here
    // (rustls-native-certs), with OpenSSL's replace semantics.
    match rustls_platform_verifier::Verifier::new(provider.clone()) {
        Ok(v) => Ok(Arc::new(v)),
        // Explicitly configured trust that loads nothing fails closed.
        Err(e) if EnvRoots::from_env().is_set() => Err(e),
        // No system store at all and nothing configured: the Mozilla roots,
        // the set the signaling client always used.
        Err(_) => mozilla_verifier(Vec::new(), provider),
    }
}

#[cfg(any(target_vendor = "apple", windows))]
fn server_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, rustls::Error> {
    let extra = EnvRoots::from_env().load()?;
    Ok(Arc::new(rustls_platform_verifier::Verifier::new_with_extra_roots(extra, provider)?))
}

#[cfg(target_os = "android")]
fn server_verifier(
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, rustls::Error> {
    mozilla_verifier(EnvRoots::from_env().load()?, provider)
}

/// The Mozilla root set plus `extra`, verified by rustls' WebPKI verifier.
#[cfg(any(all(unix, not(target_vendor = "apple")), test))]
fn mozilla_verifier(
    extra: Vec<CertificateDer<'static>>,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<Arc<dyn rustls::client::danger::ServerCertVerifier>, rustls::Error> {
    let mut roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    for cert in extra {
        roots.add(cert)?;
    }
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
        .build()
        .map_err(|e| rustls::Error::General(format!("building the certificate verifier: {e}")))?;
    Ok(verifier)
}

/// The extra trust named by `SSL_CERT_FILE` and `SSL_CERT_DIR`.
#[derive(Debug, Default)]
struct EnvRoots {
    file: Option<PathBuf>,
    dirs: Vec<PathBuf>,
}

impl EnvRoots {
    fn from_env() -> Self {
        Self::from_values(std::env::var_os("SSL_CERT_FILE"), std::env::var_os("SSL_CERT_DIR"))
    }

    /// Pure half of [`from_env`]: an empty value counts as unset, and
    /// `SSL_CERT_DIR` is a list in the platform's PATH syntax, as for OpenSSL.
    fn from_values(file: Option<std::ffi::OsString>, dirs: Option<std::ffi::OsString>) -> Self {
        Self {
            file: file.filter(|f| !f.is_empty()).map(PathBuf::from),
            dirs: dirs
                .map(|d| std::env::split_paths(&d).filter(|p| !p.as_os_str().is_empty()).collect())
                .unwrap_or_default(),
        }
    }

    fn is_set(&self) -> bool {
        self.file.is_some() || !self.dirs.is_empty()
    }

    /// Every certificate in the file and in the regular files of each
    /// directory. A named path that cannot be read, or a configuration that
    /// yields no certificate at all, is an error naming the variable.
    // Linux reads these through the platform verifier; this loader serves the
    // other platforms, and its tests run everywhere.
    #[cfg_attr(all(unix, not(target_os = "android"), not(target_vendor = "apple")), allow(dead_code))]
    fn load(&self) -> Result<Vec<CertificateDer<'static>>, rustls::Error> {
        if !self.is_set() {
            return Ok(Vec::new());
        }
        let mut certs = Vec::new();
        if let Some(file) = &self.file {
            certs.extend(pem_certs(file).map_err(|e| env_error("SSL_CERT_FILE", file, &e))?);
        }
        for dir in &self.dirs {
            let entries = std::fs::read_dir(dir).map_err(|e| env_error("SSL_CERT_DIR", dir, &e))?;
            for entry in entries {
                let path = entry.map_err(|e| env_error("SSL_CERT_DIR", dir, &e))?.path();
                // OpenSSL's hashed directory is links to PEM files; follow them,
                // skip anything that is not a file (subdirectories, sockets).
                if !path.is_file() {
                    continue;
                }
                certs.extend(pem_certs(&path).map_err(|e| env_error("SSL_CERT_DIR", &path, &e))?);
            }
        }
        if certs.is_empty() {
            return Err(rustls::Error::General(
                "no CA certificates were loaded from SSL_CERT_FILE / SSL_CERT_DIR".to_string(),
            ));
        }
        Ok(certs)
    }
}

fn pem_certs(path: &Path) -> std::io::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    let bytes = std::fs::read(path)?;
    // Non-certificate sections (keys, CRLs, comments) are skipped; a malformed
    // certificate section is an error rather than a silently smaller store.
    CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e:?}")))
}

fn env_error(var: &str, path: &Path, e: &std::io::Error) -> rustls::Error {
    rustls::Error::General(format!(
        "no CA certificates were loaded from {var} ({}): {e}",
        path.display()
    ))
}

/// The certificate-validation failure inside `error`, if that is what it is.
///
/// Walks the source chain, and looks inside `io::Error` payloads too: an
/// `io::Error` can hold the rustls error without exposing it as its
/// `source()`, and both tokio-rustls and hyper wrap TLS failures that way.
/// A reset, a refusal or a timeout is never a certificate failure.
pub fn certificate_error<'a>(
    error: &'a (dyn std::error::Error + 'static),
) -> Option<&'a rustls::CertificateError> {
    if let Some(rustls::Error::InvalidCertificate(cert)) = error.downcast_ref::<rustls::Error>() {
        return Some(cert);
    }
    // tungstenite boxes the rustls error without exposing it as a source.
    if let Some(tokio_tungstenite::tungstenite::error::TlsError::Rustls(inner)) =
        error.downcast_ref::<tokio_tungstenite::tungstenite::error::TlsError>()
    {
        if let rustls::Error::InvalidCertificate(cert) = &**inner {
            return Some(cert);
        }
    }
    if let Some(io) = error.downcast_ref::<std::io::Error>() {
        if let Some(cert) = io.get_ref().and_then(|inner| certificate_error(inner)) {
            return Some(cert);
        }
    }
    error.source().and_then(certificate_error)
}

/// The text of a TLS trust failure: a certificate the server presented and
/// this machine rejected, or a configured trust store that loaded nothing.
/// For errors that only survive as text (a daemon's log line, a probe's
/// recorded error). Case-insensitive; conservative on purpose.
pub fn is_certificate_text(s: &str) -> bool {
    let s = s.to_lowercase();
    const PATTERNS: [&str; 4] = [
        // rustls' Display for Error::InvalidCertificate, every variant.
        "invalid peer certificate",
        // The trust store loaded nothing (platform verifier, and our loader).
        "no ca certificates were loaded",
        // A message that already went through this classification.
        "tls certificate was not trusted",
        "no ca certificates could be loaded",
    ];
    PATTERNS.iter().any(|p| s.contains(p))
}

#[cfg(test)]
#[path = "tls_trust_tests.rs"]
mod trust_tests;
