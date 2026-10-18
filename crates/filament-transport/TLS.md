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

`http::client_builder()` retains its infallible return type. Failure to initialize
the platform verifier now panics at builder creation rather than being returned
by reqwest's later `build()`. No roots or verification fallback is substituted.
The preconfigured rustls API requires keeping its rustls version aligned with
reqwest; the lockfile currently resolves both to 0.23.45.

## CI coverage

The existing local-crate CI test loop runs both crates' tests. Each provider
regression launches fresh test processes, first with no provider and then with
a distinguishable, reversed-cipher-order ring provider. They assert the clients'
explicit provider policy and that the ambient provider is unchanged. HTTP
builder construction, HTTP ALPN/SNI, local untrusted HTTPS/WSS rejection and a
successful plaintext signaling handshake are covered. A separate signaling test
checks the total timeout during silent TLS and Socket.IO namespace handshakes.

The fixtures do not positively validate a publicly trusted WSS chain or
OS-specific trust-store customization/revocation behavior. Android runtime trust
requires device coverage; existing Android compilation gates remain unchanged.
No local Rust compilation, tests or binding generation are part of this change.
