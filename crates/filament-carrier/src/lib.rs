//! Carriers: how tunlion reaches its own infrastructure through whatever the
//! network allows.
//!
//! A carrier moves bytes between this process and a rendezvous (the signaling
//! server, a TURN server). It never authenticates a peer and never holds a key:
//! TLS to the rendezvous, DTLS and QUIC to the peer, SPAKE2 and device keys all
//! stay above it. Every carrier, and every proxy it passes through, is
//! untrusted. Design: `docs/carriers.md`.
//!
//! The primitive is a STREAM carrier, `dial(host, port) -> TcpStream`. The
//! signaling websocket runs TLS and Engine.IO over it; the TURN bridge
//! (`filament-transport/src/turn_bridge.rs`) runs TURN framing over it and turns
//! that into a loopback datagram port for webrtc-ice. An HTTP CONNECT tunnel
//! through an `http://` proxy is a plain TCP socket once the proxy answers 200,
//! which is why `TcpStream` is enough for the carriers that exist.
//!
//! # When a proxy applies
//!
//! [`select`] uses hyper-util's proxy `Matcher::from_system()`, which is
//! exactly what reqwest's `system-proxy` feature uses for the REST client
//! (`/api/config`, `/api/room`). So the REST calls, signaling and TURN agree on
//! when a proxy applies, by construction: `ALL_PROXY`, `HTTPS_PROXY`,
//! `HTTP_PROXY` and `NO_PROXY` (uppercase first, then lowercase), ignored when
//! `REQUEST_METHOD` is set; on macOS the system HTTP/HTTPS proxy, on Windows the
//! user's Internet Settings. No PAC or WPAD (reqwest has none either).
//!
//! A destination the proxy configuration covers goes through the proxy only,
//! never raced against a direct attempt: that is the rule the REST client
//! applies, and in sandboxes a direct attempt beside a configured proxy is what
//! egress monitoring flags.

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use hyper_util::client::proxy::matcher::Matcher;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// Bound on the CONNECT request and the proxy's answer, after TCP connects.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// A proxy answer head longer than this is not an HTTP proxy talking.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// Socket options a caller wants on the stream it gets back.
#[derive(Clone, Debug, Default)]
pub struct DialOpts {
    /// Kernel send buffer, set before connect (the TURN bridge bounds it so a
    /// stream cannot bufferbloat ICE consent checks; see `turn_bridge.rs`).
    pub send_buffer: Option<u32>,
}

/// A way to get a byte stream to `host:port`.
#[async_trait]
pub trait StreamCarrier: Send + Sync + fmt::Debug {
    /// Short label for routes and doctor: `"direct"` or `"proxy"`.
    fn name(&self) -> &'static str;
    /// What a person reads: `"direct"`, `"proxy 10.0.0.1:3128"`. Never
    /// contains credentials.
    fn describe(&self) -> String;
    /// A stream to `host:port`. TLS, if any, is the caller's, end to end with
    /// the destination: the carrier never terminates it.
    async fn dial(&self, host: &str, port: u16, opts: &DialOpts) -> io::Result<TcpStream>;
}

/// Plain TCP, IPv4 addresses first (many hosts have no route to public IPv6;
/// see `net::prefer_v4`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Direct;

#[async_trait]
impl StreamCarrier for Direct {
    fn name(&self) -> &'static str {
        "direct"
    }
    fn describe(&self) -> String {
        "direct".into()
    }
    async fn dial(&self, host: &str, port: u16, opts: &DialOpts) -> io::Result<TcpStream> {
        let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        addrs.sort_by_key(|a| a.is_ipv6());
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host} has no address"));
        for a in addrs {
            match dial_addr(a, opts).await {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    return Ok(s);
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }
}

async fn dial_addr(a: SocketAddr, opts: &DialOpts) -> io::Result<TcpStream> {
    let sock = if a.is_ipv4() { tokio::net::TcpSocket::new_v4()? } else { tokio::net::TcpSocket::new_v6()? };
    if let Some(n) = opts.send_buffer {
        let _ = sock.set_send_buffer_size(n);
    }
    sock.connect(a).await
}

/// An HTTP CONNECT tunnel through an `http://` proxy. Credentials from the proxy
/// URL go as `Proxy-Authorization: Basic`, as reqwest sends them.
#[derive(Clone)]
pub struct HttpConnect {
    proxy_host: String,
    proxy_port: u16,
    /// The full header value (`Basic ...`), already encoded by the matcher.
    auth: Option<http::HeaderValue>,
}

impl fmt::Debug for HttpConnect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never the credentials.
        f.debug_struct("HttpConnect")
            .field("proxy", &format_args!("{}", self.proxy_addr()))
            .field("auth", &self.auth.is_some())
            .finish()
    }
}

impl HttpConnect {
    pub fn new(proxy_host: impl Into<String>, proxy_port: u16, basic_auth: Option<http::HeaderValue>) -> Self {
        HttpConnect { proxy_host: proxy_host.into(), proxy_port, auth: basic_auth }
    }

    fn proxy_addr(&self) -> String {
        authority(&self.proxy_host, self.proxy_port)
    }
}

#[async_trait]
impl StreamCarrier for HttpConnect {
    fn name(&self) -> &'static str {
        "proxy"
    }
    fn describe(&self) -> String {
        format!("proxy {}", self.proxy_addr())
    }
    async fn dial(&self, host: &str, port: u16, opts: &DialOpts) -> io::Result<TcpStream> {
        let mut s = Direct.dial(&self.proxy_host, self.proxy_port, opts).await.map_err(|e| {
            io::Error::new(e.kind(), format!("cannot reach the proxy at {}: {e}", self.proxy_addr()))
        })?;
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, connect_handshake(&mut s, host, port, self.auth.as_ref())).await {
            Ok(Ok(())) => Ok(s),
            Ok(Err(e)) => Err(io::Error::new(e.kind(), format!("the proxy at {} {e}", self.proxy_addr()))),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("the proxy at {} did not answer CONNECT within {HANDSHAKE_TIMEOUT:?}", self.proxy_addr()),
            )),
        }
    }
}

/// `host:port`, brackets around an IPv6 literal.
fn authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Send `CONNECT host:port` and read the proxy's answer. On `Ok` the stream is
/// the tunnel: no byte past the answer's blank line has been read.
///
/// Errors read as the rest of a sentence that starts "the proxy at X ...".
pub async fn connect_handshake<S: AsyncRead + AsyncWrite + Unpin>(
    s: &mut S,
    host: &str,
    port: u16,
    auth: Option<&http::HeaderValue>,
) -> io::Result<()> {
    let target = authority(host, port);
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nUser-Agent: tunlion\r\n").into_bytes();
    if let Some(a) = auth {
        req.extend_from_slice(b"Proxy-Authorization: ");
        req.extend_from_slice(a.as_bytes());
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"\r\n");
    // A proxy that hangs up can surface as a reset on the write or the read;
    // either way the sentence is the same.
    let hung_up = |e: io::Error| {
        io::Error::new(e.kind(), format!("closed the connection instead of answering CONNECT to {target} ({e})"))
    };
    s.write_all(&req).await.map_err(hung_up)?;
    s.flush().await.map_err(hung_up)?;

    // Byte at a time: the tunnel's first bytes (the far end's TLS ServerHello,
    // a TURN answer) must stay in the socket for the caller.
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "sent an answer head over 16 KiB to CONNECT"));
        }
        let n = s.read(&mut b).await.map_err(hung_up)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("closed the connection instead of answering CONNECT to {target}"),
            ));
        }
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head);
    let status_line = text.lines().next().unwrap_or("").trim().to_string();
    let code = parse_status(&status_line)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("answered CONNECT with {status_line:?}, not HTTP")))?;
    if (200..300).contains(&code) {
        return Ok(());
    }
    let hint = match (code, auth.is_some()) {
        (407, false) => ": put credentials in the proxy URL (http://user:password@host:port)",
        (407, true) => ": it rejected the credentials in the proxy URL",
        (403, _) => ": its policy does not allow that destination",
        _ => "",
    };
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("refused to tunnel to {target} ({status_line}){hint}"),
    ))
}

fn parse_status(line: &str) -> Option<u16> {
    let mut parts = line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse().ok()
}

/// The carrier for one destination, and a note when a configured proxy could
/// not be used.
#[derive(Clone, Debug)]
pub struct Selected {
    pub carrier: Arc<dyn StreamCarrier>,
    /// Set when a proxy matched but has a scheme the carriers cannot speak yet
    /// (`https://`, `socks5://`). The connection then goes direct, as it did
    /// before carriers existed, and doctor says why.
    pub skipped_proxy: Option<String>,
}

impl Selected {
    pub fn direct() -> Self {
        Selected { carrier: Arc::new(Direct), skipped_proxy: None }
    }
    pub fn via_proxy(&self) -> bool {
        self.carrier.name() == "proxy"
    }
}

/// Map a destination's URL scheme to the one the proxy rules are written in:
/// websockets as their HTTP schemes, and TURN streams as `https` (the tunnel is
/// a CONNECT either way, which is what `HTTPS_PROXY` configures).
fn proxy_scheme(scheme: &str) -> &'static str {
    match scheme {
        "http" | "ws" => "http",
        _ => "https",
    }
}

/// The carrier for `scheme://host:port`, from the environment and the OS proxy
/// settings (see the module docs).
pub fn select(scheme: &str, host: &str, port: u16) -> Selected {
    select_with(&Matcher::from_system(), scheme, host, port)
}

/// [`select`] against an explicit matcher, for tests and embedders.
pub fn select_with(matcher: &Matcher, scheme: &str, host: &str, port: u16) -> Selected {
    let uri = format!("{}://{}/", proxy_scheme(scheme), authority(host, port));
    let Ok(dst) = uri.parse::<http::Uri>() else {
        return Selected::direct();
    };
    let Some(icpt) = matcher.intercept(&dst) else {
        return Selected::direct();
    };
    let p = icpt.uri();
    let pscheme = p.scheme_str().unwrap_or("http");
    let Some(phost) = p.host() else {
        return Selected::direct();
    };
    let phost = phost.trim_start_matches('[').trim_end_matches(']').to_string();
    if pscheme != "http" {
        let port = p.port_u16().map(|n| format!(":{n}")).unwrap_or_default();
        return Selected {
            carrier: Arc::new(Direct),
            skipped_proxy: Some(format!(
                "{pscheme}://{phost}{port} is configured, but only http:// proxies carry signaling and relay traffic so far; connecting directly"
            )),
        };
    }
    let pport = p.port_u16().unwrap_or(80);
    Selected {
        carrier: Arc::new(HttpConnect::new(phost, pport, icpt.basic_auth().cloned())),
        skipped_proxy: None,
    }
}

#[cfg(test)]
mod tests;
