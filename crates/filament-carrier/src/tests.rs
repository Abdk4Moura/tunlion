use super::*;
use tokio::net::TcpListener;

fn matcher(https: &str, no: &str) -> Matcher {
    Matcher::builder().https(https.to_string()).no(no.to_string()).build()
}

/// A one-connection CONNECT proxy: records the request head, answers with
/// `answer`, and on a 2xx echoes whatever the client sends next.
async fn fake_proxy(answer: &'static str) -> (u16, tokio::task::JoinHandle<String>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let h = tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read(&mut b).await.unwrap() == 0 {
                break;
            }
            head.push(b[0]);
        }
        s.write_all(answer.as_bytes()).await.unwrap();
        if answer.starts_with("HTTP/1.1 2") {
            let mut buf = [0u8; 64];
            if let Ok(n) = s.read(&mut buf).await {
                let _ = s.write_all(&buf[..n]).await;
            }
        }
        String::from_utf8(head).unwrap()
    });
    (port, h)
}

#[test]
fn https_destinations_use_the_https_proxy_and_no_proxy_bypasses_it() {
    let m = matcher("http://proxy.test:3128", "internal.test,10.0.0.0/8");
    let s = select_with(&m, "wss", "api.example.com", 443);
    assert!(s.via_proxy());
    assert_eq!(s.carrier.describe(), "proxy proxy.test:3128");
    assert!(!select_with(&m, "wss", "sig.internal.test", 443).via_proxy());
    assert!(!select_with(&m, "turns", "10.1.2.3", 443).via_proxy());
    // TURN over TCP and TLS are tunnels, matched as https.
    assert!(select_with(&m, "turn", "turn.example.com", 3478).via_proxy());
}

#[test]
fn ws_follows_http_proxy_not_https_proxy() {
    let m = Matcher::builder().http("http://p.test:8080".to_string()).build();
    assert!(select_with(&m, "ws", "127.0.0.9", 8161).via_proxy());
    assert!(!select_with(&m, "wss", "api.example.com", 443).via_proxy());
}

#[test]
fn no_proxy_configured_is_direct() {
    let m = Matcher::builder().build();
    let s = select_with(&m, "wss", "api.example.com", 443);
    assert!(!s.via_proxy());
    assert!(s.skipped_proxy.is_none());
}

#[test]
fn a_proxy_port_defaults_to_80_like_reqwest() {
    let m = matcher("http://proxy.test", "");
    assert_eq!(select_with(&m, "wss", "a.example", 443).carrier.describe(), "proxy proxy.test:80");
}

#[test]
fn a_socks_or_https_proxy_is_named_and_skipped_not_silently_ignored() {
    for p in ["socks5://127.0.0.1:1080", "https://proxy.test:8443"] {
        let s = select_with(&matcher(p, ""), "wss", "a.example", 443);
        assert!(!s.via_proxy(), "{p}");
        let note = s.skipped_proxy.expect(p);
        assert!(note.contains("only http:// proxies"), "{note}");
    }
}

#[test]
fn credentials_never_appear_in_debug_or_describe() {
    let s = select_with(&matcher("http://alice:s3cret@proxy.test:3128", ""), "wss", "a.example", 443);
    let shown = format!("{:?} {}", s, s.carrier.describe());
    assert!(!shown.contains("s3cret") && !shown.contains("alice"), "{shown}");
}

#[test]
fn ipv6_targets_are_bracketed() {
    assert_eq!(authority("2001:db8::1", 443), "[2001:db8::1]:443");
    assert_eq!(authority("a.example", 443), "a.example:443");
}

#[tokio::test]
async fn connect_tunnels_and_sends_basic_auth() {
    let (port, proxy) = fake_proxy("HTTP/1.1 200 Connection established\r\n\r\n").await;
    let m = matcher(&format!("http://alice:s3cret@127.0.0.1:{port}"), "");
    let sel = select_with(&m, "wss", "sig.example", 443);
    let mut s = sel.carrier.dial("sig.example", 443, &DialOpts::default()).await.unwrap();
    s.write_all(b"ping").await.unwrap();
    let mut got = [0u8; 4];
    s.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"ping", "bytes after the 200 belong to the tunnel");
    let head = proxy.await.unwrap();
    assert!(head.starts_with("CONNECT sig.example:443 HTTP/1.1\r\n"), "{head}");
    assert!(head.contains("Host: sig.example:443\r\n"), "{head}");
    // base64("alice:s3cret")
    assert!(head.contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n"), "{head}");
}

#[tokio::test]
async fn no_credentials_no_auth_header() {
    let (port, proxy) = fake_proxy("HTTP/1.0 200 OK\r\nX: y\r\n\r\n").await;
    let c = HttpConnect::new("127.0.0.1", port, None);
    let mut s = c.dial("10.0.0.1", 443, &DialOpts::default()).await.unwrap();
    s.write_all(b"x").await.unwrap();
    let head = proxy.await.unwrap();
    assert!(!head.contains("Proxy-Authorization"), "{head}");
}

#[tokio::test]
async fn a_407_says_what_to_do() {
    let (port, _proxy) = fake_proxy("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n").await;
    let c = HttpConnect::new("127.0.0.1", port, None);
    let e = c.dial("sig.example", 443, &DialOpts::default()).await.unwrap_err();
    let msg = e.to_string();
    assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
    assert!(msg.contains(&format!("the proxy at 127.0.0.1:{port} refused to tunnel to sig.example:443")), "{msg}");
    assert!(msg.contains("407") && msg.contains("put credentials in the proxy URL"), "{msg}");
}

#[tokio::test]
async fn a_403_names_the_policy() {
    let (port, _proxy) = fake_proxy("HTTP/1.1 403 Forbidden\r\n\r\n").await;
    let e = HttpConnect::new("127.0.0.1", port, None).dial("t.example", 3478, &DialOpts::default()).await.unwrap_err();
    assert!(e.to_string().contains("does not allow that destination"), "{e}");
}

#[tokio::test]
async fn a_proxy_that_hangs_up_or_speaks_garbage_is_an_error_not_a_hang() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (s, _) = l.accept().await.unwrap();
        drop(s);
        let (mut s, _) = l.accept().await.unwrap();
        let _ = s.write_all(b"SSH-2.0-nope\r\n\r\n").await;
    });
    let c = HttpConnect::new("127.0.0.1", port, None);
    let e = c.dial("a.example", 443, &DialOpts::default()).await.unwrap_err();
    assert!(e.to_string().contains("closed the connection"), "{e}");
    let e = c.dial("a.example", 443, &DialOpts::default()).await.unwrap_err();
    assert!(e.to_string().contains("not HTTP"), "{e}");
}

#[tokio::test]
async fn an_unreachable_proxy_is_named() {
    // Bind then drop: nothing listens on that port.
    let port = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let e = HttpConnect::new("127.0.0.1", port, None).dial("a.example", 443, &DialOpts::default()).await.unwrap_err();
    assert!(e.to_string().starts_with(&format!("cannot reach the proxy at 127.0.0.1:{port}")), "{e}");
}
