//! Local SOCKS5 / HTTP CONNECT mesh proxy and cold-link retry manager.

#[cfg(feature = "forward-server")]
use super::ForwardActivity;
#[cfg(unix)]
use super::bridge_streams;
use super::{
    ForwardRefusal, Mux, WarmOpen, bring_up_to_known, classify_forward_refusal,
    open_stream_verified_reason, pump_initiator, serve_stream,
};
use crate::net;
use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// File (in the config dir, owner-only) holding the local proxy's password.
pub(crate) fn proxy_token_path() -> std::path::PathBuf {
    crate::platform::Paths::config_path("proxy.token")
}

/// The local proxy's password: a random 256-bit token, created on first use
/// and stored owner-only (0600 / owner ACL) so only this user can read it.
/// The proxy opens mesh streams AS THE OWNER, so a listener on 127.0.0.1 with
/// no auth handed that authority to every local account on the machine.
pub(crate) fn proxy_token() -> Result<String> {
    let path = proxy_token_path();
    if let Ok(t) = std::fs::read_to_string(&path) {
        let t = t.trim();
        if t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Ok(t.to_string());
        }
    }
    let mut buf = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut buf)
        .map_err(|_| anyhow!("no system randomness for the proxy token"))?;
    let token = hex::encode(buf);
    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            crate::platform::tighten_new_dir(dir);
        }
    }
    crate::platform::SecretFile::write_str(&path, &token)?;
    // Two proxies starting at once could both mint; whichever landed on disk
    // is the one a user will `cat`, so serve that.
    Ok(std::fs::read_to_string(&path)
        .ok()
        .map(|t| t.trim().to_string())
        .filter(|t| t.len() == 64)
        .unwrap_or(token))
}

/// Username the proxy prints. Only the password is checked; the name is there
/// because SOCKS5 user/pass and HTTP Basic both carry one.
pub(crate) const PROXY_USER: &str = "tunlion";

/// Length-checked, constant-time comparison of a presented password.
fn proxy_password_ok(presented: &[u8], token: &str) -> bool {
    let want = token.as_bytes();
    if presented.len() != want.len() {
        return false;
    }
    presented.iter().zip(want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

/// How to use the proxy, with the password read from its file at use time
/// (never printed: `up` output lands in log files).
pub(crate) fn proxy_usage_lines(bind: &str, port: u16) -> Vec<String> {
    let tok = proxy_token_path();
    vec![
        format!(
            "  auth: username/password required (user `{PROXY_USER}`, password in {}, owner-only)",
            tok.display()
        ),
        format!(
            "  e.g.  curl -x \"socks5h://{PROXY_USER}:$(cat '{}')@{bind}:{port}\" http://<peer>.mesh:8080/",
            tok.display()
        ),
    ]
}

/// True for an address that only this machine can reach.
#[cfg(feature = "forward-server")]
fn bind_is_loopback(bind: &str) -> bool {
    bind.eq_ignore_ascii_case("localhost")
        || bind
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false)
}

/// `tunlion proxy`: a local SOCKS5 proxy that reaches mesh peers by name with NO
/// TUN and NO privilege (Tailscale's userspace-networking model). A SOCKS5 CONNECT
/// to `<peer>.mesh:<port>` opens an L2 stream to that peer's `localhost:<port>` over
/// tunlion (warm via a local daemon, else a self-healing cold link); any other
/// host is dialed directly, so the proxy is a drop-in that only diverts `.mesh`.
/// Pure userspace: no CAP_NET_ADMIN, no sudo, works in containers.
///
/// When `--http-port` is set, also runs an HTTP CONNECT proxy + PAC file endpoint
/// on that port for browser/OS proxy config (Tailscale parity).
#[cfg(feature = "forward-server")]
pub async fn proxy_cmd(
    server: &str,
    bind: &str,
    port: u16,
    http_port: u16,
    relay: bool,
    allow_remote: bool,
) -> Result<()> {
    // A non-loopback bind exposes "open a stream as the owner" (and a plain
    // open relay to anywhere) to the network, guarded only by the token. Make
    // that a deliberate choice, and say so loudly when it is made.
    if !bind_is_loopback(bind) {
        if !allow_remote {
            bail!(
                "tunlion: refusing to bind the proxy to {bind}: anyone who can reach it and learns the token can open mesh streams as you and relay traffic through this machine. Use the default 127.0.0.1, or pass --allow-remote if you really mean it."
            );
        }
        crate::ui::critical(&crate::ui::paint(
            crate::ui::Tone::Warn,
            &format!(
                "WARNING: proxy bound to {bind} (--allow-remote): reachable from the network; the token in {} is the only thing between it and your mesh",
                proxy_token_path().display()
            ),
        ));
    }
    let token: Arc<str> = proxy_token()?.into();
    let listener = match TcpListener::bind((bind, port)).await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            bail!("tunlion: {bind}:{port} is already in use; pick another with --port");
        }
        Err(e) => {
            return Err(
                anyhow::Error::new(e).context(format!("tunlion: failed to bind {bind}:{port}"))
            );
        }
    };
    // `status`, `addr` and `expose` read this to say where the proxy is and how
    // to use it; daemon.log was the only place that said so.
    crate::proxy_state::record(bind, port);
    crate::ui::say(&format!(
        "tunlion: SOCKS5 proxy on {bind}:{port} (no TUN, no sudo)"
    ));
    proxy_serve(server, listener, bind, port, http_port, relay, token).await
}

/// Bind the daemon's automatic SOCKS5 proxy on loopback: `first`, else the next
/// free port in a small window. The listener is returned BOUND, so whatever the
/// caller then prints about it is true. It used to print "started SOCKS5 proxy
/// on 127.0.0.1:1080" and bind afterwards in the background, so a second daemon
/// announced a port the first one held, and its own proxy never existed.
pub async fn bind_auto_proxy(first: u16) -> std::result::Result<(TcpListener, u16), String> {
    let mut last = String::new();
    for port in first..first.saturating_add(10) {
        match TcpListener::bind(("127.0.0.1", port)).await {
            Ok(l) => return Ok((l, port)),
            Err(e) => last = format!("127.0.0.1:{port}: {e}"),
        }
    }
    Err(format!(
        "ports {first}-{} are all taken (last: {last})",
        first.saturating_add(9)
    ))
}

/// Serve the SOCKS5 proxy (and the optional HTTP CONNECT proxy) on an already
/// bound listener. `port` is the SOCKS port the listener holds.
pub async fn proxy_serve(
    server: &str,
    listener: TcpListener,
    bind: &str,
    port: u16,
    http_port: u16,
    relay: bool,
    token: Arc<str>,
) -> Result<()> {
    crate::ui::say(&format!(
        "  point apps here; {}.mesh rides the mesh, everything else connects directly",
        "<peer>"
    ));
    for line in proxy_usage_lines(bind, port) {
        crate::ui::say(&line);
    }
    #[cfg(unix)]
    if !crate::ctl::daemon_present().await {
        crate::ui::say(&crate::ui::paint(
            crate::ui::Tone::Dim,
            "  note: no local daemon; each .mesh connection brings up its own link. `tunlion up` makes them instant.",
        ));
    }
    // Per-peer self-healing cold links, started lazily on first use of a peer (only
    // when the warm daemon path misses), mirroring `forward`'s cold manager.
    let cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    // HTTP CONNECT proxy + PAC file endpoint (optional).
    if http_port > 0 {
        let http_listener = match TcpListener::bind((bind, http_port)).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                bail!(
                    "tunlion: {bind}:{http_port} is already in use; pick another with --http-port"
                );
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("tunlion: failed to bind {bind}:{http_port}")));
            }
        };
        crate::ui::say(&format!(
            "tunlion: HTTP CONNECT proxy on {bind}:{http_port}"
        ));
        crate::ui::say(&format!(
            "  PAC file: http://127.0.0.1:{http_port}/proxy.pac (browsers ask for the same user/password)"
        ));
        crate::ui::say(&format!(
            "  e.g.  curl -x \"http://{PROXY_USER}:$(cat '{}')@127.0.0.1:{http_port}\" https://<peer>.mesh",
            proxy_token_path().display()
        ));
        let cold_http = cold.clone();
        let server_http = server.to_string();
        let token_http = token.clone();
        tokio::spawn(async move {
            loop {
                let sock = match http_listener.accept().await {
                    Ok((s, _)) => s,
                    Err(e) => {
                        crate::ui::status(&format!(
                            "tunlion: HTTP accept paused ({e}), retrying..."
                        ));
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                };
                let _ = sock.set_nodelay(true);
                let (server, cold, token) = (server_http.clone(), cold_http.clone(), token_http.clone());
                tokio::spawn(async move {
                    if let Err(e) = handle_http(sock, &server, port, http_port, relay, cold, &token).await {
                        crate::ui::debug(&format!("tunlion: HTTP proxy connection ended: {e}"));
                    }
                });
            }
        });
    }
    loop {
        let sock = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                crate::ui::status(&format!("tunlion: accept paused ({e}), retrying..."));
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                continue;
            }
        };
        let _ = sock.set_nodelay(true);
        let (server, cold, token) = (server.to_string(), cold.clone(), token.clone());
        tokio::spawn(async move {
            if let Err(e) = handle_socks(sock, &server, relay, cold, &token).await {
                crate::ui::debug(&format!("tunlion: proxy connection ended: {e}"));
            }
        });
    }
}

/// Write a minimal SOCKS5 reply (`code` 0x00 = success) with a zero BND.ADDR/PORT.
async fn socks_reply(sock: &mut TcpStream, code: u8) -> std::io::Result<()> {
    sock.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

/// SOCKS5 greeting + RFC 1929 username/password sub-negotiation. Only method
/// 0x02 is accepted: a client offering no-auth alone gets 0xFF (no acceptable
/// method) and is closed. Returns Ok(()) only for the right password.
async fn socks_authenticate<S: AsyncRead + AsyncWrite + Unpin>(sock: &mut S, token: &str) -> Result<()> {
    // Greeting: VER, NMETHODS, METHODS...
    let mut greet = [0u8; 2];
    sock.read_exact(&mut greet).await?;
    if greet[0] != 0x05 {
        bail!("not a SOCKS5 client");
    }
    let mut methods = vec![0u8; greet[1] as usize];
    sock.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        sock.write_all(&[0x05, 0xFF]).await?;
        bail!("SOCKS5 client offered no username/password auth; the tunlion proxy requires it");
    }
    sock.write_all(&[0x05, 0x02]).await?;
    // RFC 1929: VER(1)=0x01, ULEN, UNAME, PLEN, PASSWD.
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await?;
    if hdr[0] != 0x01 {
        bail!("bad SOCKS5 auth version");
    }
    let mut user = vec![0u8; hdr[1] as usize];
    sock.read_exact(&mut user).await?;
    let mut plen = [0u8; 1];
    sock.read_exact(&mut plen).await?;
    let mut pass = vec![0u8; plen[0] as usize];
    sock.read_exact(&mut pass).await?;
    if !proxy_password_ok(&pass, token) {
        sock.write_all(&[0x01, 0x01]).await?;
        bail!("SOCKS5 auth failed");
    }
    sock.write_all(&[0x01, 0x00]).await?;
    Ok(())
}

/// Handle one SOCKS5 client: username/password handshake, parse the CONNECT
/// target, then route `<peer>.mesh:<port>` over tunlion (warm-first, cold
/// fallback) or dial any other host directly. Errors here only affect this one
/// connection.
async fn handle_socks(
    mut sock: TcpStream,
    server: &str,
    relay: bool,
    cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>>,
    token: &str,
) -> Result<()> {
    socks_authenticate(&mut sock, token).await?;

    // Request: VER, CMD, RSV, ATYP, ADDR, PORT.
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        bail!("bad SOCKS5 request");
    }
    let host = match req[3] {
        0x01 => {
            let mut a = [0u8; 4];
            sock.read_exact(&mut a).await?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        0x04 => {
            let mut a = [0u8; 16];
            sock.read_exact(&mut a).await?;
            std::net::Ipv6Addr::from(a).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut d = vec![0u8; len[0] as usize];
            sock.read_exact(&mut d).await?;
            String::from_utf8_lossy(&d).into_owned()
        }
        _ => {
            socks_reply(&mut sock, 0x08).await?; // address type not supported
            return Ok(());
        }
    };
    let mut pb = [0u8; 2];
    sock.read_exact(&mut pb).await?;
    let dport = u16::from_be_bytes(pb);
    if req[1] != 0x01 {
        socks_reply(&mut sock, 0x07).await?; // only CONNECT
        return Ok(());
    }

    match host.strip_suffix(".mesh") {
        Some(peer) => {
            serve_mesh_connect(sock, ProxyProto::Socks, peer, dport, server, relay, cold).await
        }
        None => {
            // Not a mesh name: behave like a plain SOCKS5 proxy (dial directly), so
            // the user can set tunlion as their one proxy and only .mesh is diverted.
            match TcpStream::connect((host.as_str(), dport)).await {
                Ok(mut up) => {
                    let _ = up.set_nodelay(true);
                    socks_reply(&mut sock, 0x00).await?;
                    let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
                    Ok(())
                }
                Err(_) => {
                    socks_reply(&mut sock, 0x05).await?; // connection refused
                    Ok(())
                }
            }
        }
    }
}

/// Handle one HTTP CONNECT client or PAC file request. Reads the HTTP request,
/// routes CONNECT through the mesh, or serves the PAC file for browser config.
async fn handle_http(
    mut sock: TcpStream,
    server: &str,
    socks_port: u16,
    http_port: u16,
    relay: bool,
    cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>>,
    token: &str,
) -> Result<()> {
    // Read the HTTP request line + headers until empty line.
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1];
    loop {
        sock.read_exact(&mut tmp).await?;
        buf.push(tmp[0]);
        // Check for \r\n\r\n (end of headers).
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 8192 {
            bail!("HTTP request too large");
        }
    }
    let request = String::from_utf8_lossy(&buf);
    let first_line = request.lines().next().unwrap_or("");

    // Parse: METHOD PATH HTTP/1.x
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // Same authority as the SOCKS side, so the same password: HTTP Basic
        // in Proxy-Authorization. A browser answers the 407 with a prompt.
        if !http_proxy_auth_ok(&request, token) {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                      Proxy-Authenticate: Basic realm=\"tunlion\"\r\n\
                      Content-Length: 0\r\n\
                      Connection: close\r\n\
                      \r\n",
                )
                .await;
            return Ok(());
        }
        // HTTP CONNECT proxy: CONNECT host:port HTTP/1.1
        let host_port = path;
        let (host, dport) = if let Some(colon) = host_port.rfind(':') {
            let h = &host_port[..colon];
            let p: u16 = host_port[colon + 1..].parse().unwrap_or(0);
            (h.to_string(), p)
        } else {
            (host_port.to_string(), 80)
        };

        match host.strip_suffix(".mesh") {
            Some(peer) => {
                serve_mesh_connect(sock, ProxyProto::Http, peer, dport, server, relay, cold).await
            }
            None => {
                // Not a mesh name: dial directly.
                match TcpStream::connect((host.as_str(), dport)).await {
                    Ok(mut up) => {
                        let _ = up.set_nodelay(true);
                        let _ = sock
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await;
                        let _ = tokio::io::copy_bidirectional(&mut sock, &mut up).await;
                        Ok(())
                    }
                    Err(_) => {
                        let _ = sock.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n").await;
                        Ok(())
                    }
                }
            }
        }
    } else if path == "/proxy.pac" || path == "/wpad.dat" {
        // Serve PAC file for browser/OS proxy config. The PAC itself holds no
        // secret. Browsers cannot authenticate to SOCKS5, so the HTTP CONNECT
        // proxy (which they can, via the Basic prompt) comes first.
        let pac = format!(
            r#"function FindProxyForURL(url, host) {{
    if (dnsDomainIs(host, ".mesh") || shExpMatch(host, "*.mesh")) {{
        return "PROXY 127.0.0.1:{http_port}; SOCKS5 127.0.0.1:{socks_port}; DIRECT";
    }}
    return "DIRECT";
}}
"#
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\n\
             Content-Type: application/x-ns-proxy-autoconfig\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            pac.len(),
            pac
        );
        let _ = sock.write_all(response.as_bytes()).await;
        Ok(())
    } else {
        // Unknown HTTP request: return 404.
        let response = "HTTP/1.1 404 Not Found\r\n\
                         Content-Length: 0\r\n\
                         Connection: close\r\n\
                         \r\n";
        let _ = sock.write_all(response.as_bytes()).await;
        Ok(())
    }
}

/// Whether the raw request head carries `Proxy-Authorization: Basic` with the
/// proxy password (any username).
fn http_proxy_auth_ok(request: &str, token: &str) -> bool {
    use base64::Engine;
    for line in request.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else { continue };
        if !name.trim().eq_ignore_ascii_case("proxy-authorization") {
            continue;
        }
        let mut parts = value.trim().splitn(2, ' ');
        let (Some(scheme), Some(cred)) = (parts.next(), parts.next()) else { continue };
        if !scheme.eq_ignore_ascii_case("basic") {
            continue;
        }
        let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(cred.trim()) else { continue };
        let pass = match raw.iter().position(|&b| b == b':') {
            Some(i) => &raw[i + 1..],
            None => continue,
        };
        if proxy_password_ok(pass, token) {
            return true;
        }
    }
    false
}

/// How long the daemon lets one overlay dial (the proxy's `.mesh` fallback to an
/// `expose`d port) run before it answers "timed out". A port the peer did not
/// expose can swallow the SYN, and the dial used to have no bound at all.
pub(crate) const OVERLAY_DIAL_BOUND: Duration = Duration::from_secs(3);
/// The daemon's reject reason when `OVERLAY_DIAL_BOUND` runs out.
pub(crate) const OVERLAY_DIAL_TIMED_OUT: &str = "overlay dial timed out";

/// The longest an overlay dial waits after its handshake (see below).
pub(crate) const OVERLAY_SETTLE_MAX: Duration = Duration::from_millis(1500);

/// The daemon's overlay-dial answer when the peer's exposed port accepted the
/// connection and closed it at once: `expose` found nothing listening behind
/// it. The proxy answers SOCKS 0x05 (connection refused).
pub(crate) const OVERLAY_TARGET_CLOSED: &str =
    "overlay dial refused: nothing is listening behind the exposed port there";

/// How long an overlay dial waits, after the handshake, for the peer to close
/// before the connection counts as carried. The close comes about one round
/// trip after the handshake (the peer's `expose` fails its local connect at
/// once), and the handshake itself took about one, so twice it plus a margin,
/// bounded. Pure.
#[cfg_attr(not(l3), allow(dead_code))]
pub(crate) fn overlay_settle_window(handshake: Duration) -> Duration {
    (handshake * 2 + Duration::from_millis(150)).clamp(Duration::from_millis(250), OVERLAY_SETTLE_MAX)
}

/// The budget for the WARM half of a proxy `.mesh` CONNECT: the daemon's L2 open
/// plus its overlay dial must have answered by then: the dial's own bound, its
/// settle wait, and a second for the open. Override with TUNLION_PROXY_WARM_MS.
fn proxy_warm_budget() -> Duration {
    std::env::var("TUNLION_PROXY_WARM_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .map(Duration::from_millis)
        // The dial, then its settle wait (`overlay_settle_window`), then slack.
        .unwrap_or(OVERLAY_DIAL_BOUND + OVERLAY_SETTLE_MAX + Duration::from_secs(1))
}

/// How long a connection accepted by `forward` (or a proxy CONNECT on the cold
/// path) may wait for the peer before it is closed. A forward to a dead peer
/// used to hold every client open with no data and no close for as long as the
/// client cared to wait. Override with TUNLION_FORWARD_CONNECT_SECS.
pub(crate) fn cold_link_bound() -> Duration {
    let secs = std::env::var("TUNLION_FORWARD_CONNECT_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(10);
    Duration::from_secs(secs)
}

/// Why a proxy `.mesh` CONNECT was not carried, as the client is told it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MeshFail {
    /// Something else went wrong (SOCKS 0x01).
    General,
    /// The peer's policy refuses this port: not exposed, tunnels off, no grant
    /// (SOCKS 0x02, connection not allowed by ruleset).
    NotAllowed,
    /// The peer is unknown, offline, or no link came up in time (SOCKS 0x04).
    Unreachable,
    /// The peer answered and nothing listens on the port there (SOCKS 0x05).
    Refused,
    /// The peer's answer did not arrive in time: the overlay dial timed out
    /// while the peer was still answering on its link (SOCKS 0x06).
    TimedOut,
}

impl MeshFail {
    pub(crate) fn socks_rep(self) -> u8 {
        match self {
            MeshFail::General => 0x01,
            MeshFail::NotAllowed => 0x02,
            MeshFail::Unreachable => 0x04,
            MeshFail::Refused => 0x05,
            MeshFail::TimedOut => 0x06,
        }
    }

    pub(super) fn http_status(self) -> &'static str {
        match self {
            MeshFail::NotAllowed => "403 Forbidden",
            MeshFail::TimedOut => "504 Gateway Timeout",
            MeshFail::General | MeshFail::Unreachable | MeshFail::Refused => "502 Bad Gateway",
        }
    }
}

/// The reply for a peer's own refusal of an L2 open (its `l2-close{err}`).
pub(crate) fn mesh_fail_for_refusal(reason: &str) -> MeshFail {
    match classify_forward_refusal(reason) {
        ForwardRefusal::Policy => MeshFail::NotAllowed,
        ForwardRefusal::NothingListening => MeshFail::Refused,
        ForwardRefusal::Transient => MeshFail::General,
    }
}

/// Decide the reply for a `.mesh` CONNECT that neither warm path carried.
/// `l2` is the peer's refusal of the loopback open (None: no warm link to ask
/// through, so nothing was learned). `l3` is the daemon's answer to the overlay
/// dial (None: there was no daemon to ask). `None` means "nothing definitive,
/// try a cold link"; the peer only gets a verdict when it answered.
pub(crate) fn mesh_verdict(l2: Option<&str>, l3: Option<&str>) -> Option<MeshFail> {
    // The peer's exposed port took the connection and closed it: that port IS
    // exposed and nothing listens behind it, whatever the loopback open said
    // (a device without shell is refused there by policy).
    if l3 == Some(OVERLAY_TARGET_CLOSED) {
        return Some(MeshFail::Refused);
    }
    let refusal = mesh_fail_for_refusal(l2?);
    if refusal != MeshFail::General {
        return Some(refusal);
    }
    let dial = l3.map(str::to_ascii_lowercase).unwrap_or_default();
    Some(if dial == OVERLAY_DIAL_TIMED_OUT {
        MeshFail::TimedOut
    } else if dial.contains("refused") || dial.contains("reset") {
        MeshFail::Refused
    } else {
        MeshFail::General
    })
}

/// True when `peer` names a paired device, by name or by the `.mesh` spelling
/// of it (lowercase, anything but letters, digits, '-' and '.' as '-').
fn mesh_peer_known(peer: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '.' { c.to_ascii_lowercase() } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .to_string()
    };
    let want = norm(peer);
    crate::devices_load()
        .iter()
        .any(|(n, _)| n.eq_ignore_ascii_case(peer) || norm(n.as_str()) == want)
}

/// Which proxy protocol is waiting for the CONNECT answer.
#[derive(Clone, Copy)]
pub(super) enum ProxyProto {
    Socks,
    Http,
}

impl ProxyProto {
    pub(super) async fn ok(self, sock: &mut TcpStream) -> std::io::Result<()> {
        match self {
            ProxyProto::Socks => socks_reply(sock, 0x00).await,
            ProxyProto::Http => sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await,
        }
    }

    pub(super) async fn fail(self, sock: &mut TcpStream, f: MeshFail) -> std::io::Result<()> {
        match self {
            ProxyProto::Socks => socks_reply(sock, f.socks_rep()).await,
            ProxyProto::Http => {
                let head = format!(
                    "HTTP/1.1 {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    f.http_status()
                );
                sock.write_all(head.as_bytes()).await
            }
        }
    }
}

/// Wait for a LIVE mux on a cold-link channel (a dead one may stay parked until
/// the manager's ~1 s poll republishes; `is_alive` skips it so nothing opens on
/// a corpse). `None` when the manager is gone.
async fn wait_live_mux(rx: &mut tokio::sync::watch::Receiver<Option<Arc<Mux>>>) -> Option<Arc<Mux>> {
    loop {
        let cur = rx.borrow_and_update().clone();
        match cur {
            Some(m) if m.transport().is_alive() => return Some(m),
            _ => {
                if rx.changed().await.is_err() {
                    return None;
                }
            }
        }
    }
}

/// True when the cold-link channel holds a live link right now.
pub(super) fn cold_link_live(rx: &tokio::sync::watch::Receiver<Option<Arc<Mux>>>) -> bool {
    rx.borrow().as_ref().is_some_and(|m| m.transport().is_alive())
}

/// Route one proxy CONNECT to `<peer>.mesh:<dport>` and answer the client only
/// once the outcome is KNOWN. The proxy used to reply "succeeded" before asking
/// the peer anything, then hold the client open forever when the peer refused
/// (an unexposed port) or never answered (an offline peer). Every path below is
/// bounded and ends in either a bridged stream or a specific failure reply.
async fn serve_mesh_connect(
    mut sock: TcpStream,
    proto: ProxyProto,
    peer: &str,
    dport: u16,
    server: &str,
    relay: bool,
    cold: Arc<Mutex<HashMap<String, tokio::sync::watch::Receiver<Option<Arc<Mux>>>>>>,
) -> Result<()> {
    let started = tokio::time::Instant::now();
    // Read only by the warm (daemon) path, which exists on unix alone.
    let _warm_deadline = started + proxy_warm_budget();
    let peer = peer.to_string();
    if !mesh_peer_known(&peer) {
        crate::ui::debug(&format!("tunlion: proxy: '{peer}.mesh' is not a paired device"));
        proto.fail(&mut sock, MeshFail::Unreachable).await?;
        return Ok(());
    }
    // Warm path: ride the local daemon's live mesh link (instant, no extra
    // presence on the peer). PRIMARY is the L2 loopback open of the peer's
    // 127.0.0.1:dport; FALLBACK is the overlay dial of a port the peer EXPOSED
    // (which the loopback open cannot reach). Both answers are kept: when the
    // peer refused, that refusal IS the reply, and a cold retry would only turn
    // it into a hang.
    #[cfg(unix)]
    if crate::ctl::daemon_present().await {
        let deadline = _warm_deadline;
        let mut l2_refusal: Option<String> = None;
        match tokio::time::timeout_at(deadline, crate::ctl::try_open_reason(&peer, dport)).await {
            Ok(Ok(usock)) => {
                proto.ok(&mut sock).await?;
                return bridge_streams(sock, usock).await.map_err(Into::into);
            }
            Ok(Err(Some(r))) if r.starts_with("refused:") => {
                l2_refusal = Some(r.trim_start_matches("refused:").trim().to_string());
            }
            _ => {}
        }
        let l3 = match tokio::time::timeout_at(deadline, crate::ctl::try_dial_reason(&peer, dport)).await {
            Ok(Ok(usock)) => {
                proto.ok(&mut sock).await?;
                return bridge_streams(sock, usock).await.map_err(Into::into);
            }
            Ok(Err(r)) => r,
            Err(_) => Some(OVERLAY_DIAL_TIMED_OUT.to_string()),
        };
        if let Some(f) = mesh_verdict(l2_refusal.as_deref(), l3.as_deref()) {
            crate::ui::debug(&format!(
                "tunlion: proxy: {peer}.mesh:{dport} not carried ({f:?}; peer said {:?}, overlay said {:?})",
                l2_refusal, l3
            ));
            proto.fail(&mut sock, f).await?;
            return Ok(());
        }
    }
    // Cold fallback (no daemon, or no warm link): a per-peer self-healing link,
    // reused across connections, waited for within the bound.
    let mut rx = {
        let mut map = cold.lock().await;
        if let Some(rx) = map.get(&peer) {
            rx.clone()
        } else {
            let (tx, rx) = tokio::sync::watch::channel::<Option<Arc<Mux>>>(None);
            let (s, pr) = (server.to_string(), peer.clone());
            tokio::spawn(async move { manage_cold_link(s, pr, relay, tx).await });
            map.insert(peer.clone(), rx.clone());
            rx
        }
    };
    let deadline = started + cold_link_bound();
    let mux = match tokio::time::timeout_at(deadline, wait_live_mux(&mut rx)).await {
        Ok(Some(m)) => m,
        _ => {
            proto.fail(&mut sock, MeshFail::Unreachable).await?;
            return Ok(());
        }
    };
    let left = deadline
        .saturating_duration_since(tokio::time::Instant::now())
        .max(Duration::from_secs(2));
    match open_stream_verified_reason(&mux, dport, left).await {
        WarmOpen::Opened(sid, first, pipe) => {
            proto.ok(&mut sock).await?;
            serve_stream(mux, sid, sock, pipe, true, Some(first), None).await;
        }
        WarmOpen::Refused(reason) => proto.fail(&mut sock, mesh_fail_for_refusal(&reason)).await?,
        // No answer at all on a link we held: a zombie to a peer that is gone
        // (killed, cut off), the same verdict the daemon's warm path and
        // `forward` reach. An offline peer is "host unreachable", not a
        // timeout of a peer that is there.
        WarmOpen::Dead(_) => proto.fail(&mut sock, MeshFail::Unreachable).await?,
    }
    Ok(())
}

/// Serve one accepted forward connection over the managed cold link, tolerant of
/// a link blip: wait for a LIVE mux, open a stream and wait for the peer's
/// answer, and on a transient open failure re-wait for the manager's
/// reconnected link. ALL of it within `deadline`: when the peer cannot be
/// reached by then the connection is closed (dropping `sock` sends the FIN) and
/// the forward says so, instead of holding the client open indefinitely.
/// Never propagates errors to the accept loop.
#[cfg(feature = "forward-server")]
pub(super) async fn serve_cold_connection(
    mut rx: tokio::sync::watch::Receiver<Option<Arc<Mux>>>,
    sock: TcpStream,
    rport: u16,
    // #232/#268: `forward`'s user is watching a terminal and needs to know the
    // peer refused, or cannot be reached.
    activity: ForwardActivity,
    deadline: tokio::time::Instant,
) {
    let mut tries = 0u32;
    loop {
        let mux = match tokio::time::timeout_at(deadline, wait_live_mux(&mut rx)).await {
            Ok(Some(m)) => m,
            Ok(None) => return, // manager gone; drop this socket (listener lives on)
            Err(_) => {
                activity.unreachable();
                return;
            }
        };
        let left = deadline
            .saturating_duration_since(tokio::time::Instant::now())
            .max(Duration::from_secs(1));
        match open_stream_verified_reason(&mux, rport, left).await {
            WarmOpen::Opened(sid, first, rx_pipe) => {
                activity.reachable();
                serve_stream(mux.clone(), sid, sock, rx_pipe, true, Some(first), None).await;
                // The acceptor's `l2-close{err}` landed in `close_err` before the
                // pipe was dropped (on_close orders it that way deliberately), so
                // by the time serve_stream returns the reason is already there if
                // there is one. A clean end leaves None and prints nothing.
                if let Some(reason) = mux.take_close_err(sid).await {
                    activity.refused_once(&reason);
                }
                return;
            }
            WarmOpen::Refused(reason) => {
                // The peer answered, so it is reachable; it said no.
                activity.reachable();
                activity.refused_once(&reason);
                return;
            }
            WarmOpen::Dead(_) => {
                tries += 1;
                if tries >= 3 || tokio::time::Instant::now() >= deadline {
                    activity.unreachable();
                    return; // drop sock; accept loop keeps running
                }
                // The link died between the liveness check and the open; loop
                // back to wait for the manager to publish a fresh one.
            }
        }
    }
}

/// Own the cold forward link end to end: establish it, publish it to the accept
/// loop, watch its liveness, and reconnect on loss, narrating each transition so
/// a network blip is visible (mirrors the `up` daemon's lost/recovered UX). Never
/// returns while the watch receiver is live; a send error means the forward
/// command exited, so the manager stops.
pub(super) async fn manage_cold_link(
    server: String,
    peer: String,
    relay: bool,
    tx: tokio::sync::watch::Sender<Option<Arc<Mux>>>,
) {
    let mut backoff_ms = 500u64;
    let mut had_link = false; // distinguishes first bring-up from a recovery
    loop {
        // (Re)establish. Transient states (retrying / reconnecting) update ONE
        // status line in place via ui::status; only real transitions (recovered)
        // print a permanent line via ui::say, which clears the live status line.
        let mux = match bring_up_to_known(&server, &peer, relay, "init").await {
            Ok((t, rx, guard, mut diag)) => {
                guard.forget();
                diag.up("tunnel", "datachannel-or-direct");
                let m = Mux::new(t, crate::host_impl::cli_host());
                tokio::spawn(pump_initiator(rx, m.clone()));
                m
            }
            Err(e) => {
                crate::ui::status(&format!(
                    "tunlion: reaching {peer} failed ({e}), retrying..."
                ));
                tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                backoff_ms = (backoff_ms * 2).min(8000);
                continue;
            }
        };
        backoff_ms = 500;
        if had_link {
            crate::ui::say(&format!("tunlion: link to {peer} recovered"));
        }
        had_link = true;
        if tx.send(Some(mux.clone())).is_err() {
            return; // forward command gone
        }
        // Watch liveness; a dead transport means the link dropped under us.
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if tx.is_closed() {
                return;
            }
            if !mux.transport().is_alive() {
                crate::ui::status(&format!("tunlion: link to {peer} lost, reconnecting..."));
                let _ = tx.send(None);
                break;
            }
        }
    }
}

#[cfg(test)]
mod proxy_auth_tests {
    use super::*;

    const TOKEN: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    async fn run_handshake(client_bytes: Vec<u8>) -> (Result<()>, Vec<u8>) {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&client_bytes).await.unwrap();
        let res = socks_authenticate(&mut server, TOKEN).await;
        drop(server);
        let mut out = Vec::new();
        let _ = client.read_to_end(&mut out).await;
        (res, out)
    }

    fn userpass(user: &[u8], pass: &[u8]) -> Vec<u8> {
        let mut v = vec![0x05, 0x01, 0x02, 0x01, user.len() as u8];
        v.extend_from_slice(user);
        v.push(pass.len() as u8);
        v.extend_from_slice(pass);
        v
    }

    #[tokio::test]
    async fn socks_no_auth_client_is_refused() {
        let (res, out) = run_handshake(vec![0x05, 0x01, 0x00]).await;
        assert!(res.is_err(), "a no-auth-only client must not get through");
        assert_eq!(out, [0x05, 0xFF], "answered with no acceptable method");
    }

    #[tokio::test]
    async fn socks_wrong_password_is_refused() {
        let (res, out) = run_handshake(userpass(b"tunlion", b"not-the-token")).await;
        assert!(res.is_err());
        assert_eq!(out, [0x05, 0x02, 0x01, 0x01]);
        let mut near = TOKEN.as_bytes().to_vec();
        near[63] = b'0';
        let (res, _) = run_handshake(userpass(b"tunlion", &near)).await;
        assert!(res.is_err(), "one byte off is still wrong");
    }

    #[tokio::test]
    async fn socks_right_password_is_accepted() {
        let (res, out) = run_handshake(userpass(b"tunlion", TOKEN.as_bytes())).await;
        assert!(res.is_ok(), "{res:?}");
        assert_eq!(out, [0x05, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn http_basic_auth_is_checked() {
        use base64::Engine;
        let good = base64::engine::general_purpose::STANDARD.encode(format!("tunlion:{TOKEN}"));
        let bad = base64::engine::general_purpose::STANDARD.encode("tunlion:nope");
        let req = |h: &str| format!("CONNECT a.mesh:80 HTTP/1.1\r\nHost: a.mesh:80\r\n{h}\r\n");
        assert!(http_proxy_auth_ok(&req(&format!("Proxy-Authorization: Basic {good}\r\n")), TOKEN));
        assert!(http_proxy_auth_ok(&req(&format!("proxy-authorization: basic {good}\r\n")), TOKEN));
        assert!(!http_proxy_auth_ok(&req(&format!("Proxy-Authorization: Basic {bad}\r\n")), TOKEN));
        assert!(!http_proxy_auth_ok(&req(""), TOKEN), "no header, no entry");
    }

    #[test]
    fn only_loopback_binds_are_local() {
        for b in ["127.0.0.1", "::1", "[::1]", "localhost", "127.0.0.2"] {
            assert!(bind_is_loopback(b), "{b}");
        }
        for b in ["0.0.0.0", "::", "192.168.1.5", "example.com"] {
            assert!(!bind_is_loopback(b), "{b}");
        }
    }
}

