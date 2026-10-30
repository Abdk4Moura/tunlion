# HTTP and signaling TLS ownership

HTTP and `filament-signal` select ring explicitly and neither read nor install
the process-default rustls provider. Embedders need no provider initialization
for these clients, even if a different provider policy is already installed.
The CLI's provider installation remains for unrelated dependencies; this is not
an audit of WebRTC's internal TLS behavior.

Trust is one decision, `filament_signal::tls::client_config()`, used by the
signaling websocket, every HTTPS client (`http::client_builder`) and the
TURN-over-TLS bridge (`http::turn_tls_config`), so a certificate one of them
accepts the others accept too. Before this, signaling trusted only the Mozilla
roots while HTTPS used the platform verifier, so behind a TLS-inspecting proxy
whose CA was in the OS store the API worked and signaling failed.

* Linux and other non-Apple Unix: `rustls-platform-verifier` 0.7.0 (the
  system store via rustls-native-certs). `SSL_CERT_FILE` / `SSL_CERT_DIR`
  replace the default locations, OpenSSL's semantics. With neither set and no
  system store at all, the Mozilla roots (webpki-roots 1) are used. A set
  variable that loads nothing fails closed.
* macOS and Windows: the platform verifier with the certificates from
  `SSL_CERT_FILE` / `SSL_CERT_DIR` added (`new_with_extra_roots`).
* Android: the Mozilla roots plus `SSL_CERT_FILE` / `SSL_CERT_DIR`, without
  needing a Java VM.
* Certificate/hostname verification and SNI remain enabled. HTTP advertises
  `h2` and `http/1.1`; signaling retains empty ALPN and ordinary plaintext `ws`.
* Signaling's 20-second budget still wraps the entire TCP/TLS, websocket,
  Engine.IO and Socket.IO sequence.

`http::client_builder()` returns `Result<reqwest::ClientBuilder, rustls::Error>`.
Failure to initialize the platform verifier is propagated without panicking or
installing a provider. The only substitution is the Mozilla roots on a Unix
machine with no system store and no `SSL_CERT_*` configuration; verification
itself is never relaxed. Repository
callers handle both factory and reqwest `build()` errors: public-IP discovery
returns `None`, telemetry skips its best-effort request, updates propagate the
error, and configuration fetching retains retries and the TLS error as its cause.
The preconfigured rustls API requires keeping its rustls version aligned with
reqwest; the lockfile currently resolves both to 0.23.45.

## Builder customization limits

The returned builder is not equivalent to an unconfigured reqwest builder.
Timeouts, DNS overrides, proxy policy, headers and HTTP/2 flow-control options
remain available. However, reqwest's preconfigured backend bypasses TLS-policy
construction: later root, identity, TLS-version, SNI, certificate-verification
and key-log settings do not update the supplied rustls config. Do not use them
to customize this helper's TLS policy. Replacing the backend via `tls_backend_*`
also abandons the helper's provider/trust guarantees.

The fixed `h2`/`http/1.1` ALPN list preserves current repository callers' default
HTTP negotiation. Methods such as `http1_only()` or `http2_prior_knowledge()`
can still affect reqwest/hyper's HTTP preference, but do not rewrite that ALPN
list in reqwest 0.13.4's preconfigured branch. This helper does not guarantee
coherent version-forcing customization; no current production caller uses it.

## CI coverage

The existing local-crate CI test loop runs both crates' tests. Each provider
regression launches fresh test processes, first with no provider and then with
a distinguishable, reversed-cipher-order ring provider. They assert the clients'
explicit provider policy and that the ambient provider is unchanged. HTTP
builder construction, HTTP ALPN/SNI, local untrusted HTTPS/WSS rejection and a
successful plaintext signaling handshake are covered. A separate signaling test
checks the total timeout during silent TLS and Socket.IO namespace handshakes.
Linux-only fresh-process cases point the platform loader at an empty CA file
and directory, asserting a recoverable initialization error (not a panic) with
both absent and distinct installed providers. The HTTPS fixture requires a
typed rustls certificate-validation source, specifically `UnknownIssuer` on
Linux/Android; connection resets/refusals are not accepted as certificate errors.

`filament-signal`'s `tls_trust_tests.rs` covers the trust decision end to end:
a local WSS server with a certificate signed by a private CA is refused as a
certificate error without configuration, and completes the full Socket.IO
handshake with `SSL_CERT_FILE` or `SSL_CERT_DIR` naming the CA, each in a fresh
process. It also covers the `SSL_CERT_*` loader and the classification of
certificate failures (`tls::certificate_error`, `tls::is_certificate_text`)
that the CLI turns into exit 13.

The fixtures do not positively validate a publicly trusted WSS chain or
OS-specific trust-store customization/revocation behavior. Android runtime trust
requires device coverage; existing Android compilation gates remain unchanged.
