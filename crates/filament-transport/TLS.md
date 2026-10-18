# HTTP and signaling TLS ownership

HTTP and `filament-signal` select ring explicitly and neither read nor install
the process-default rustls provider. Embedders need no provider initialization
for these clients, even if a different provider policy is already installed.
The CLI's provider installation remains for unrelated dependencies; this is not
an audit of WebRTC's internal TLS behavior.

Trust is unchanged:

* Desktop HTTP uses `rustls-platform-verifier` 0.7.0, the same constructor as
  reqwest 0.13.4. Android HTTP retains Mozilla roots without needing a Java VM.
* Signaling uses the same webpki-roots 0.26.11 root set as
  tokio-tungstenite 0.28.0 (which re-exports the locked 1.0.9 roots).
* Certificate/hostname verification and SNI remain enabled. HTTP advertises
  `h2` and `http/1.1`; signaling retains empty ALPN and ordinary plaintext `ws`.
* Signaling's 20-second budget still wraps the entire TCP/TLS, websocket,
  Engine.IO and Socket.IO sequence.

`http::client_builder()` returns `Result<reqwest::ClientBuilder, rustls::Error>`.
Failure to initialize the platform verifier is propagated without panicking,
installing a provider, or substituting a trust/verification fallback. Repository
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

The fixtures do not positively validate a publicly trusted WSS chain or
OS-specific trust-store customization/revocation behavior. Android runtime trust
requires device coverage; existing Android compilation gates remain unchanged.
No local Rust compilation, tests or binding generation are part of this change.
