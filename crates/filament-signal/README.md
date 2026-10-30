# tunlion-signal

A minimal Engine.IO v4 / Socket.IO v5 websocket client on rustls, used by
[tunlion](https://github.com/Abdk4Moura/tunlion) to talk to its signaling
server. It links no system OpenSSL: TLS is rustls with the OS trust store
(Mozilla roots on Android and as the fallback).

The Rust library name is `filament_signal`.

License: MIT
