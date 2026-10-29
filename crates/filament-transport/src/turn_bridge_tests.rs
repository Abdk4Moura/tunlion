use super::*;

use std::net::IpAddr;
use tokio::net::TcpListener;
use webrtc::turn;
use webrtc::util::Conn;

const LIVE_URLS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "turn:162.35.114.254:3478",
    "turns:turn.filament.autumated.com:443?transport=tcp",
    "turns:turn.filament.autumated.com:443",
    "turn:turn.cloudflare.com:3478?transport=udp",
    "turn:turn.cloudflare.com:3478?transport=tcp",
    "turns:turn.cloudflare.com:5349?transport=tcp",
    "turn:turn.cloudflare.com:443?transport=udp",
    "turn:turn.cloudflare.com:80?transport=tcp",
    "turns:turn.cloudflare.com:443?transport=tcp",
];

fn up(kind: StreamKind, host: &str, port: u16) -> Option<Upstream> {
    Some(Upstream { kind, host: host.into(), port })
}

#[test]
fn classify_matches_what_webrtc_ice_skips() {
    let got: Vec<Option<Upstream>> = LIVE_URLS.iter().map(|u| classify(u)).collect();
    assert_eq!(
        got,
        vec![
            None,
            None,
            up(StreamKind::Tls, "turn.filament.autumated.com", 443),
            up(StreamKind::Tls, "turn.filament.autumated.com", 443),
            None,
            up(StreamKind::Tcp, "turn.cloudflare.com", 3478),
            up(StreamKind::Tls, "turn.cloudflare.com", 5349),
            None,
            up(StreamKind::Tcp, "turn.cloudflare.com", 80),
            up(StreamKind::Tls, "turn.cloudflare.com", 443),
        ]
    );
    // DTLS TURN is neither; it stays as unusable as it was.
    assert_eq!(classify("turns:example.com:5349?transport=udp"), None);
    assert_eq!(classify("not a url"), None);
}

fn view(elapsed_ms: u64) -> GateView {
    GateView {
        elapsed: Duration::from_millis(elapsed_ms),
        udp_wait: TCP_AFTER,
        tcp_upstreams: 2,
        ..Default::default()
    }
}

#[test]
fn gate_orders_udp_then_tcp_then_tls() {
    // Before the UDP window closes, both stream transports hold.
    assert_eq!(gate(StreamKind::Tcp, &view(0)), Gate::Wait(TCP_AFTER));
    assert_eq!(gate(StreamKind::Tls, &view(500)), Gate::Wait(TCP_AFTER - Duration::from_millis(500)));
    // No UDP relay by then: TCP goes, TLS waits its own window.
    assert_eq!(gate(StreamKind::Tcp, &view(1500)), Gate::Proceed);
    assert_eq!(gate(StreamKind::Tls, &view(1500)), Gate::Wait(TLS_AFTER_TCP));
    assert_eq!(gate(StreamKind::Tls, &view(3000)), Gate::Proceed);
}

#[test]
fn a_udp_relay_suppresses_both_stream_transports() {
    for at in [0, 1500, 10_000] {
        let v = GateView { udp_relay: true, ..view(at) };
        assert_eq!(gate(StreamKind::Tcp, &v), Gate::Suppress, "tcp at {at}");
        assert_eq!(gate(StreamKind::Tls, &v), Gate::Suppress, "tls at {at}");
    }
}

#[test]
fn a_tcp_relay_suppresses_tls_but_not_tcp() {
    let v = GateView { tcp_relay: true, ..view(2000) };
    assert_eq!(gate(StreamKind::Tls, &v), Gate::Suppress);
    assert_eq!(gate(StreamKind::Tcp, &v), Gate::Proceed);
}

#[test]
fn tls_goes_at_once_when_every_tcp_server_failed_or_none_exist() {
    let failed = GateView { tcp_failed: 2, ..view(1600) };
    assert_eq!(gate(StreamKind::Tls, &failed), Gate::Proceed);
    let half = GateView { tcp_failed: 1, ..view(1600) };
    assert!(matches!(gate(StreamKind::Tls, &half), Gate::Wait(_)));
    let none = GateView { tcp_upstreams: 0, ..view(1500) };
    assert_eq!(gate(StreamKind::Tls, &none), Gate::Proceed);
}

#[test]
fn without_a_udp_turn_url_there_is_nothing_to_wait_for() {
    let v = GateView { udp_wait: Duration::ZERO, tcp_upstreams: 1, ..Default::default() };
    assert_eq!(gate(StreamKind::Tcp, &v), Gate::Proceed);
}

#[test]
fn forbidden_response_is_a_403_the_turn_client_parses() {
    use webrtc::stun::error_code::ErrorCodeAttribute;
    use webrtc::stun::message::{Message, Getter, CLASS_ERROR_RESPONSE, METHOD_ALLOCATE, CLASS_REQUEST, MessageType};
    let mut req = Message::new();
    req.typ = MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST);
    req.new_transaction_id().unwrap();
    req.write_header();
    let resp = forbidden_response(&req.raw).expect("a request gets an answer");
    let mut m = Message::new();
    m.raw = resp;
    m.decode().unwrap();
    assert_eq!(m.typ.method, METHOD_ALLOCATE);
    assert_eq!(m.typ.class, CLASS_ERROR_RESPONSE);
    assert_eq!(m.transaction_id, req.transaction_id);
    let mut code = ErrorCodeAttribute::default();
    code.get_from(&m).unwrap();
    assert_eq!(code.code.0, 403);

    // Indications and ChannelData get no answer.
    let mut ind = Message::new();
    ind.typ = MessageType::new(METHOD_ALLOCATE, webrtc::stun::message::CLASS_INDICATION);
    ind.write_header();
    assert!(forbidden_response(&ind.raw).is_none());
    assert!(forbidden_response(&[0x40, 0, 0, 1, 7]).is_none());
}

#[tokio::test]
async fn frames_round_trip_with_channeldata_padding() {
    let (mut a, mut b) = tokio::io::duplex(4096);
    let chan = vec![0x40, 0x00, 0x00, 0x05, 1, 2, 3, 4, 5];
    let mut stun = vec![0x00, 0x01, 0x00, 0x04, 0x21, 0x12, 0xA4, 0x42];
    stun.extend_from_slice(&[9u8; 12]);
    stun.extend_from_slice(&[0, 0, 0, 0]);
    write_frame(&mut a, &chan).await.unwrap();
    write_frame(&mut a, &stun).await.unwrap();
    write_frame(&mut a, &chan).await.unwrap();
    drop(a);
    // On the wire ChannelData is padded to a multiple of four.
    let mut wire = Vec::new();
    {
        let (mut c, mut d) = tokio::io::duplex(4096);
        write_frame(&mut c, &chan).await.unwrap();
        drop(c);
        d.read_to_end(&mut wire).await.unwrap();
    }
    assert_eq!(wire.len(), 12);
    // Read back: exact datagrams, padding stripped.
    assert_eq!(read_frame(&mut b).await.unwrap(), chan);
    assert_eq!(read_frame(&mut b).await.unwrap(), stun);
    assert_eq!(read_frame(&mut b).await.unwrap(), chan);
    assert!(read_frame(&mut b).await.is_err(), "EOF ends the stream");
    let (mut e, mut f) = tokio::io::duplex(64);
    e.write_all(&[0xC0, 0, 0, 0]).await.unwrap();
    assert!(read_frame(&mut f).await.is_err(), "junk is a protocol error");
}

#[tokio::test]
async fn install_rewrites_only_stream_urls_and_dedupes() {
    let servers = vec![RTCIceServer {
        urls: LIVE_URLS.iter().map(|s| s.to_string()).collect(),
        username: "u".into(),
        credential: "c".into(),
    }];
    let (out, bridges) = install(servers).await;
    let bridges = bridges.expect("stream URLs need bridges");
    let urls = &out[0].urls;
    for keep in [
        "stun:stun.l.google.com:19302",
        "turn:162.35.114.254:3478",
        "turn:turn.cloudflare.com:3478?transport=udp",
        "turn:turn.cloudflare.com:443?transport=udp",
    ] {
        assert!(urls.iter().any(|u| u == keep), "{keep} must be untouched: {urls:?}");
    }
    let bridged: Vec<&String> = urls.iter().filter(|u| u.starts_with("turn:127.0.0.1:")).collect();
    // coturn 443 is listed twice upstream; one bridge, one URL.
    assert_eq!(bridged.len(), 5, "{urls:?}");
    assert_eq!(urls.len(), 4 + 5);
    assert!(!urls.iter().any(|u| u.starts_with("turns:")));
    assert_eq!(out[0].username, "u");
    assert_eq!(out[0].credential, "c");
    for u in bridged {
        assert!(is_udp_turn(u), "{u} must be a UDP turn URL to webrtc-ice");
    }
    assert_eq!(bridges.kind_for_port(1), None);
}

#[tokio::test]
async fn install_is_a_no_op_without_stream_urls() {
    let servers = vec![RTCIceServer {
        urls: vec!["turn:1.2.3.4:3478".into(), "stun:1.2.3.4:3478".into()],
        username: "u".into(),
        credential: "c".into(),
    }];
    let (out, bridges) = install(servers.clone()).await;
    assert!(bridges.is_none());
    assert_eq!(out[0].urls, servers[0].urls);
}

// ------------------------------------------- a real TURN allocation, over TCP --

/// The server side of TURN over TCP for the real `turn` crate server: one
/// accepted stream presented as the packet `Conn` the server reads from.
struct StreamConn {
    rd: tokio::sync::Mutex<tokio::io::ReadHalf<tokio::net::TcpStream>>,
    wr: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::TcpStream>>,
    local: SocketAddr,
    peer: SocketAddr,
}

#[async_trait::async_trait]
impl Conn for StreamConn {
    async fn connect(&self, _: SocketAddr) -> webrtc::util::Result<()> {
        Ok(())
    }
    async fn recv(&self, buf: &mut [u8]) -> webrtc::util::Result<usize> {
        Ok(self.recv_from(buf).await?.0)
    }
    async fn recv_from(&self, buf: &mut [u8]) -> webrtc::util::Result<(usize, SocketAddr)> {
        let f = read_frame(&mut *self.rd.lock().await).await?;
        buf[..f.len()].copy_from_slice(&f);
        Ok((f.len(), self.peer))
    }
    async fn send(&self, buf: &[u8]) -> webrtc::util::Result<usize> {
        self.send_to(buf, self.peer).await
    }
    async fn send_to(&self, buf: &[u8], _: SocketAddr) -> webrtc::util::Result<usize> {
        // The server pads ChannelData on a stream; write_frame does exactly that.
        write_frame(&mut *self.wr.lock().await, buf).await?;
        Ok(buf.len())
    }
    fn local_addr(&self) -> webrtc::util::Result<SocketAddr> {
        Ok(self.local)
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.peer)
    }
    async fn close(&self) -> webrtc::util::Result<()> {
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

struct Auth;
impl turn::auth::AuthHandler for Auth {
    fn auth_handle(&self, user: &str, realm: &str, _: SocketAddr) -> Result<Vec<u8>, turn::Error> {
        Ok(turn::auth::generate_auth_key(user, realm, "secret"))
    }
}

/// A real `turn` crate server listening on TCP. Returns its port.
async fn tcp_turn_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut keep = Vec::new();
        loop {
            let (s, peer) = l.accept().await.unwrap();
            let local = s.local_addr().unwrap();
            let (rd, wr) = tokio::io::split(s);
            let conn = Arc::new(StreamConn {
                rd: tokio::sync::Mutex::new(rd),
                wr: tokio::sync::Mutex::new(wr),
                local,
                peer,
            });
            let server = turn::server::Server::new(turn::server::config::ServerConfig {
                conn_configs: vec![turn::server::config::ConnConfig {
                    conn,
                    relay_addr_generator: Box::new(turn::relay::relay_static::RelayAddressGeneratorStatic {
                        relay_address: IpAddr::from([127, 0, 0, 1]),
                        address: "127.0.0.1".into(),
                        net: Arc::new(webrtc::util::vnet::net::Net::new(None)),
                    }),
                }],
                realm: "tunlion.test".into(),
                auth_handler: Arc::new(Auth),
                channel_bind_timeout: Duration::from_secs(0),
                alloc_close_notify: None,
            })
            .await
            .unwrap();
            keep.push(server);
        }
    });
    port
}

fn bridged_port(out: &[RTCIceServer]) -> u16 {
    let u = out
        .iter()
        .flat_map(|s| s.urls.iter())
        .find(|u| u.starts_with("turn:127.0.0.1:"))
        .expect("a bridged url");
    Url::parse_url(u).unwrap().port
}

async fn turn_client(bridge_port: u16) -> turn::client::Client {
    let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let c = turn::client::Client::new(turn::client::ClientConfig {
        stun_serv_addr: String::new(),
        turn_serv_addr: format!("127.0.0.1:{bridge_port}"),
        username: "user".into(),
        password: "secret".into(),
        realm: String::new(),
        software: String::new(),
        rto_in_ms: 0,
        conn,
        vnet: None,
    })
    .await
    .unwrap();
    c.listen().await.unwrap();
    c
}

/// The whole path, with the real webrtc-rs TURN client and server: allocate
/// through the bridge over TCP, then move odd-length datagrams both ways so
/// Send indications AND padded ChannelData cross the stream.
#[tokio::test]
async fn a_real_turn_client_allocates_and_relays_through_the_tcp_bridge() {
    let srv = tcp_turn_server().await;
    let (out, bridges) = install(vec![RTCIceServer {
        urls: vec![format!("turn:127.0.0.1:{srv}?transport=tcp")],
        username: "user".into(),
        credential: "secret".into(),
    }])
    .await;
    let bridges = bridges.unwrap();
    let client = turn_client(bridged_port(&out)).await;
    let relay = tokio::time::timeout(Duration::from_secs(10), client.allocate())
        .await
        .expect("allocation must not hang")
        .expect("allocation over TCP succeeds");
    let relayed = relay.local_addr().unwrap();

    // The candidate's related port is the client's socket: the bridge knows it.
    let client_port = {
        let s = bridges.shared.sources.lock().unwrap();
        assert_eq!(s.len(), 1);
        *s.keys().next().unwrap()
    };
    assert_eq!(bridges.kind_for_port(client_port), Some(StreamKind::Tcp));

    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer_addr = peer.local_addr().unwrap();
    let mut buf = vec![0u8; 2048];
    for i in 0..12u8 {
        let msg: Vec<u8> = (0..(5 + i as usize)).map(|j| i ^ j as u8).collect();
        relay.send_to(&msg, peer_addr).await.unwrap();
        let (n, from) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
            .await
            .expect("relayed datagram reaches the peer")
            .unwrap();
        assert_eq!(&buf[..n], &msg[..], "client->peer #{i}");
        assert_eq!(from.port(), relayed.port());

        let back: Vec<u8> = msg.iter().rev().copied().chain([i]).collect();
        peer.send_to(&back, from).await.unwrap();
        let (n, from_peer) = tokio::time::timeout(Duration::from_secs(5), relay.recv_from(&mut buf))
            .await
            .expect("peer datagram reaches the client")
            .unwrap();
        assert_eq!(&buf[..n], &back[..], "peer->client #{i}");
        assert_eq!(from_peer, peer_addr);
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    client.close().await.unwrap();
}

/// UDP first: with a UDP TURN URL configured, TCP holds for TCP_AFTER and only
/// then allocates.
#[tokio::test]
async fn tcp_waits_for_the_udp_window_before_allocating() {
    let srv = tcp_turn_server().await;
    let (out, _bridges) = install(vec![RTCIceServer {
        urls: vec![
            // Never answers: stands in for a UDP TURN that a firewall drops.
            "turn:192.0.2.1:3478?transport=udp".into(),
            format!("turn:127.0.0.1:{srv}?transport=tcp"),
        ],
        username: "user".into(),
        credential: "secret".into(),
    }])
    .await;
    let client = turn_client(bridged_port(&out)).await;
    let t0 = Instant::now();
    let relay = tokio::time::timeout(Duration::from_secs(10), client.allocate())
        .await
        .expect("allocation must not hang")
        .expect("allocation over TCP succeeds once the UDP window closes");
    let took = t0.elapsed();
    assert!(took >= TCP_AFTER - Duration::from_millis(50), "TCP went before UDP had its chance: {took:?}");
    drop(relay);
    client.close().await.unwrap();
}

/// UDP wins: once a UDP relay candidate is gathered, a TCP allocation is
/// refused at once (a 403, not a 25 s retransmit timeout) and never reaches
/// the server.
#[tokio::test]
async fn a_udp_relay_candidate_refuses_tcp_fast() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let srv = l.local_addr().unwrap().port();
    let (out, bridges) = install(vec![RTCIceServer {
        urls: vec!["turn:192.0.2.1:3478".into(), format!("turn:127.0.0.1:{srv}?transport=tcp")],
        username: "user".into(),
        credential: "secret".into(),
    }])
    .await;
    let bridges = bridges.unwrap();
    bridges.note_candidate(&RTCIceCandidate {
        typ: RTCIceCandidateType::Relay,
        address: "198.51.100.7".into(),
        port: 50000,
        related_address: "0.0.0.0".into(),
        related_port: 1, // not a bridged client: webrtc-ice's own UDP relay
        ..Default::default()
    });
    let client = turn_client(bridged_port(&out)).await;
    let t0 = Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(5), client.allocate())
        .await
        .expect("a refused allocation fails fast");
    assert!(r.is_err(), "TCP must not allocate when UDP relayed");
    assert!(t0.elapsed() < Duration::from_secs(1), "refusal took {:?}", t0.elapsed());
    // Nothing ever dialled the TCP server.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), l.accept()).await.is_err(),
        "the bridge connected upstream although UDP won"
    );
    client.close().await.unwrap();
}

/// A TCP server that refuses connections counts as failed; the client gets a
/// fast 403 instead of a hang.
#[tokio::test]
async fn an_unreachable_tcp_server_fails_fast_and_is_counted() {
    let dead = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    }; // closed again: connect is refused
    let (out, bridges) = install(vec![RTCIceServer {
        urls: vec![format!("turn:127.0.0.1:{dead}?transport=tcp")],
        username: "user".into(),
        credential: "secret".into(),
    }])
    .await;
    let bridges = bridges.unwrap();
    let client = turn_client(bridged_port(&out)).await;
    let r = tokio::time::timeout(Duration::from_secs(8), client.allocate())
        .await
        .expect("must not hang");
    assert!(r.is_err());
    assert_eq!(bridges.shared.view().tcp_failed, 1);
    client.close().await.unwrap();
}

/// The bridge's TCP socket keeps a small send buffer, so a stream slower than
/// its sender drops instead of queueing seconds of data (see STREAM_SNDBUF).
#[tokio::test]
async fn bridge_sockets_have_a_bounded_send_buffer() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let opts = filament_carrier::DialOpts { send_buffer: Some(STREAM_SNDBUF) };
    let s = filament_carrier::StreamCarrier::dial(&filament_carrier::Direct, "127.0.0.1", port, &opts).await.unwrap();
    let size = socket2::SockRef::from(&s).send_buffer_size().unwrap();
    // Linux reports double what was set; nothing reports less than asked.
    assert!(size <= 2 * STREAM_SNDBUF as usize, "send buffer {size} is not bounded");
    assert!(size >= STREAM_SNDBUF as usize / 2, "send buffer {size} is implausibly small");
}

// ------------------------------------------------------- through a proxy --

/// A CONNECT proxy that records each request line and either splices (200) or
/// refuses with `status`.
async fn connect_proxy(status: &'static str) -> (u16, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = lines.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let line = head.lines().next().unwrap().to_string();
                let target = line.split_whitespace().nth(1).unwrap().to_string();
                seen.lock().unwrap().push(line);
                let _ = s.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes()).await;
                if status.starts_with("200") {
                    let mut up = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                }
            });
        }
    });
    (port, lines)
}

/// HTTPS_PROXY is process-global, so the proxy cases run in a fresh process.
#[test]
fn the_bridge_honours_the_proxy_environment_in_a_fresh_process() {
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd.args(["--ignored", "--nocapture", "--exact", "turn_bridge::tests::proxy_worker"]);
    for k in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"] {
        cmd.env_remove(k);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
}

#[test]
#[ignore = "run only by the_bridge_honours_the_proxy_environment_in_a_fresh_process"]
fn proxy_worker() {
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap();
    rt.block_on(async {
        // Through a proxy that tunnels: a real allocation, and the bridge
        // records that the stream rode the proxy.
        let srv = tcp_turn_server().await;
        let (pport, lines) = connect_proxy("200 Connection established").await;
        std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{pport}"));
        let (out, bridges) = install(vec![RTCIceServer {
            urls: vec![format!("turn:127.0.0.1:{srv}?transport=tcp")],
            username: "user".into(),
            credential: "secret".into(),
        }])
        .await;
        let bridges = bridges.unwrap();
        let client = turn_client(bridged_port(&out)).await;
        tokio::time::timeout(Duration::from_secs(10), client.allocate())
            .await
            .expect("allocation must not hang")
            .expect("allocation through the proxy succeeds");
        let client_port = *bridges.shared.sources.lock().unwrap().keys().next().unwrap();
        assert_eq!(bridges.kind_for_port(client_port), Some(StreamKind::Tcp));
        assert_eq!(bridges.carrier_for_port(client_port), Some("proxy"));
        assert_eq!(lines.lock().unwrap().clone(), vec![format!("CONNECT 127.0.0.1:{srv} HTTP/1.1")]);
        client.close().await.unwrap();

        // NO_PROXY: the same server directly, and the proxy never hears of it.
        std::env::set_var("NO_PROXY", "127.0.0.1");
        let (out, bridges) = install(vec![RTCIceServer {
            urls: vec![format!("turn:127.0.0.1:{srv}?transport=tcp")],
            username: "user".into(),
            credential: "secret".into(),
        }])
        .await;
        let bridges = bridges.unwrap();
        let client = turn_client(bridged_port(&out)).await;
        tokio::time::timeout(Duration::from_secs(10), client.allocate()).await.unwrap().unwrap();
        let client_port = *bridges.shared.sources.lock().unwrap().keys().next().unwrap();
        assert_eq!(bridges.carrier_for_port(client_port), Some("direct"));
        assert_eq!(lines.lock().unwrap().len(), 1);
        client.close().await.unwrap();
        std::env::remove_var("NO_PROXY");

        // A proxy that refuses the port (squid allows CONNECT to 443 only): the
        // TCP stream fails at once and counts as failed, so TLS 443 is not kept
        // waiting for it.
        let (rport, _) = connect_proxy("403 Forbidden").await;
        std::env::set_var("HTTPS_PROXY", format!("http://127.0.0.1:{rport}"));
        let (out, bridges) = install(vec![RTCIceServer {
            urls: vec![format!("turn:127.0.0.1:{srv}?transport=tcp")],
            username: "user".into(),
            credential: "secret".into(),
        }])
        .await;
        let bridges = bridges.unwrap();
        let client = turn_client(bridged_port(&out)).await;
        let started = std::time::Instant::now();
        let r = tokio::time::timeout(Duration::from_secs(8), client.allocate()).await.expect("must not hang");
        assert!(r.is_err());
        assert_eq!(bridges.shared.view().tcp_failed, 1);
        assert!(started.elapsed() < Duration::from_secs(3), "refusal took {:?}", started.elapsed());
        client.close().await.unwrap();
    });
}
