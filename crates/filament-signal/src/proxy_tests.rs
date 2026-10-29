//! Signaling through an HTTP CONNECT proxy chosen from the environment.
//!
//! The proxy rules are read from process-global environment variables, so the
//! real assertions run in a fresh process (`proxy_worker`), the same pattern as
//! `tls_tests::provider_worker`.

use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn test_process() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.args(["--ignored", "--nocapture"]);
    command
}

#[test]
fn signaling_honours_the_proxy_environment_in_a_fresh_process() {
    let output = test_process()
        .args(["--exact", "proxy_tests::proxy_worker"])
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .env_remove("REQUEST_METHOD")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
}

/// An Engine.IO server that completes the handshake for every connection.
async fn engineio_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
                ws.send(Message::Text("0{}".into())).await.unwrap();
                assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
                ws.send(Message::Text("40{}".into())).await.unwrap();
                while let Some(Ok(_)) = ws.next().await {}
            });
        }
    });
    addr
}

/// A CONNECT proxy: records each request head, answers `status`, and on 200
/// splices to the requested target.
async fn connect_proxy(status: &'static str) -> (std::net::SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let heads = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            let seen = seen.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut b = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if s.read(&mut b).await.unwrap() == 0 {
                        return;
                    }
                    head.push(b[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let target = head.split_whitespace().nth(1).unwrap().to_string();
                seen.lock().unwrap().push(head);
                s.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes()).await.unwrap();
                if status.starts_with("200") {
                    let mut up = tokio::net::TcpStream::connect(target).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut s, &mut up).await;
                }
            });
        }
    });
    (addr, heads)
}

fn set_env(k: &str, v: &str) {
    // SAFETY: this runs alone in its own process (see the caller), before any
    // other thread reads the environment.
    unsafe { std::env::set_var(k, v) }
}

#[test]
#[ignore = "run only by signaling_honours_the_proxy_environment_in_a_fresh_process"]
fn proxy_worker() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let (server, proxy, heads, refusing) = rt.block_on(async {
        let server = engineio_server().await;
        let (proxy, heads) = connect_proxy("200 Connection established").await;
        let (refusing, _) = connect_proxy("407 Proxy Authentication Required").await;
        (server, proxy, heads, refusing)
    });
    // A ws:// server URL follows HTTP_PROXY, like reqwest for http:// URLs.
    set_env("HTTP_PROXY", &format!("http://alice:s3cret@{proxy}"));
    rt.block_on(async {
        let (tx, _rx) = mpsc::unbounded_channel();
        let client = connect(&format!("http://{server}"), tx).await.expect("connect through the proxy");
        assert_eq!(client.carrier(), format!("proxy {proxy}"));
        let h = heads.lock().unwrap().clone();
        assert_eq!(h.len(), 1, "{h:?}");
        assert!(h[0].starts_with(&format!("CONNECT {server} HTTP/1.1\r\n")), "{}", h[0]);
        assert!(h[0].contains("Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n"), "{}", h[0]);
        client.disconnect().await.unwrap();
    });

    // NO_PROXY wins: direct, and the proxy never hears of it.
    set_env("NO_PROXY", "127.0.0.1");
    rt.block_on(async {
        let (tx, _rx) = mpsc::unbounded_channel();
        let client = connect(&format!("http://{server}"), tx).await.expect("direct under NO_PROXY");
        assert_eq!(client.carrier(), "direct");
        assert_eq!(heads.lock().unwrap().len(), 1, "NO_PROXY destination reached the proxy");
        client.disconnect().await.unwrap();
    });

    // A refusing proxy is a clear, prompt error naming the proxy and the code.
    set_env("NO_PROXY", "");
    set_env("HTTP_PROXY", &format!("http://{refusing}"));
    rt.block_on(async {
        let (tx, _rx) = mpsc::unbounded_channel();
        let start = std::time::Instant::now();
        let err = match connect(&format!("http://{server}"), tx).await {
            Ok(_) => panic!("connected through a proxy that refused"),
            Err(e) => format!("{e:#}"),
        };
        assert!(start.elapsed() < std::time::Duration::from_secs(5), "took {:?}", start.elapsed());
        assert!(err.contains(&format!("the proxy at {refusing} refused to tunnel to {server}")), "{err}");
        assert!(err.contains("407") && err.contains("put credentials in the proxy URL"), "{err}");
    });
}
