//! A minimal Socket.IO v5 / Engine.IO v4 client, websocket-only, over rustls.
//!
//! WHY THIS EXISTS. `rust_socketio` depends on `native-tls` unconditionally (not
//! behind a feature), which forced the binary to link the system
//! `libssl`/`libcrypto`, pulled a SECOND `reqwest` major version into the tree,
//! and made a self-contained build impossible. That was recorded as ledger C16
//! and treated as unfixable without forking upstream.
//!
//! It turned out not to need a fork, because tunlion uses almost none of that
//! crate. The client connects with `TransportType::Websocket` and
//! `reconnect(false)`, its handlers only ever pull the first JSON value out of a
//! payload and forward it to one channel, and the only methods called on the
//! client are `emit`, `disconnect` and `clone`. What was actually required was a
//! websocket, the Engine.IO framing bytes, and Socket.IO's `42["name",data]`.
//!
//! SCOPE, deliberately small. Websocket transport only, no HTTP long-polling
//! upgrade dance (tunlion forces websocket anyway, because polling behind
//! Cloudflare produced the reconnect storm documented in `net.rs`). No binary
//! attachments: every payload here is JSON. No automatic reconnect: tunlion
//! keeps `reconnect(false)` on purpose so its own outer loop can re-run
//! join/subscribe/sync, which a silent library-level reconnect would skip.
//!
//! Anything this does not implement is an error rather than a silent no-op, so
//! an unexpected server change surfaces as a failure instead of a hang.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio::sync::{Mutex, mpsc, watch};
use tokio_tungstenite::tungstenite::Message;

pub mod tls;

/// What the read loop delivers upward. One channel for everything, because every
/// call site did the same thing with a per-event callback anyway.
#[derive(Debug, Clone)]
pub enum Incoming {
    /// A Socket.IO event and its first argument.
    Event { name: String, data: Value },
    /// The connection ended. `conn` is the [`Client::id`] of the connection
    /// that ended, so a caller that has already replaced it can tell a late
    /// close of the OLD connection from the loss of the current one. The
    /// reason is for logging only.
    Down { conn: u64, reason: String },
}

/// Connection ids, unique for the life of the process. Zero is never issued.
static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1);

fn next_conn_id() -> u64 {
    NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed)
}

type Writer = Arc<
    Mutex<
        Option<futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >>,
    >,
>;

async fn send_writer_message(
    writer: &Writer,
    mut stopping: watch::Receiver<bool>,
    message: Message,
) -> Result<()> {
    if *stopping.borrow() {
        bail!("signaling connection is stopping");
    }
    tokio::select! {
        biased;
        _ = stopping.changed() => bail!("signaling connection is stopping"),
        result = async {
            let mut sink = writer.lock().await;
            sink.as_mut()
                .ok_or_else(|| anyhow!("signaling connection is closed"))?
                .send(message)
                .await
                .map_err(anyhow::Error::from)
        } => result,
    }
}

/// A handle to a live signaling connection. Cheap to clone; every clone writes
/// to the same socket behind one mutex.
/// Acks the server owes us, by id.
type Pending = Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Vec<Value>>>>>;

#[derive(Clone)]
pub struct Client {
    /// Which connection this handle writes to. Clones share it; every
    /// `connect` gets a new one.
    id: u64,
    writer: Writer,
    /// Ack ids are client-chosen and must be unique per connection; the server
    /// echoes them back on `43`.
    next_ack: Arc<AtomicU64>,
    pending: Pending,
    // Shared among Client clones so shutdown can join the socket reader.
    reader_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    stopping: Arc<Mutex<bool>>,
    stop_tx: watch::Sender<bool>,
}

impl Client {
    /// The id of the connection behind this handle, the same value its
    /// [`Incoming::Down`] carries when it ends.
    ///
    /// LOAD-BEARING for any caller that re-dials. Every connection shares the
    /// caller's event channel, so without the id a close that arrives AFTER a
    /// re-dial (the old socket's read loop ending a moment late) is
    /// indistinguishable from the new connection dropping. Acting on it tears
    /// down the healthy new connection, whose own close then arrives after the
    /// next re-dial, and the cycle sustains itself: the reconnect storm a
    /// daemon fell into after a long SIGSTOP.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Send a Socket.IO event with a single JSON argument.
    pub async fn emit(&self, event: &str, data: Value) -> Result<()> {
        // 42 = Socket.IO EVENT inside Engine.IO MESSAGE, then the argument
        // array. serde_json does the escaping, so an event name or payload
        // containing a quote cannot break framing.
        let frame = format!("42{}", Value::Array(vec![Value::String(event.into()), data]));
        send_writer_message(
            &self.writer,
            self.stop_tx.subscribe(),
            Message::Text(frame.into()),
        )
            .await
            .with_context(|| format!("emit '{event}'"))
    }

    /// Emit an event and wait for the server's acknowledgement.
    ///
    /// LOAD-BEARING, not a convenience. Two callers depend on it: the liveness
    /// heartbeat, whose ack is the only proof a quiet socket is still alive
    /// (without it the watchdog false-reconnects idle links), and the subscribe
    /// roster, whose ack is the deterministic member list that replaced a lossy
    /// one-shot push. Both are documented at their call sites in `net.rs`.
    ///
    /// A timeout yields `Ok(None)` rather than an error: not hearing back is an
    /// ordinary outcome the callers already handle by retrying, and turning it
    /// into an error would make a slow round trip indistinguishable from a dead
    /// socket. The pending entry is always removed, so a late ack cannot leak
    /// the slot or wake a caller that has moved on.
    pub async fn emit_with_ack(
        &self,
        event: &str,
        data: Value,
        timeout: std::time::Duration,
    ) -> Result<Option<Vec<Value>>> {
        let id = self.next_ack.fetch_add(1, Ordering::Relaxed);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        self.pending.lock().await.insert(id, done_tx);
        let frame =
            format!("42{id}{}", Value::Array(vec![Value::String(event.into()), data]));
        if let Err(e) = send_writer_message(
            &self.writer,
            self.stop_tx.subscribe(),
            Message::Text(frame.into()),
        )
        .await
        {
            self.pending.lock().await.remove(&id);
            return Err(e).with_context(|| format!("emit '{event}' with ack"));
        }
        match tokio::time::timeout(timeout, done_rx).await {
            Ok(Ok(args)) => Ok(Some(args)),
            // Sender dropped: the read loop ended, so the socket is gone.
            Ok(Err(_)) => Ok(None),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Ok(None)
            }
        }
    }

    /// A client whose websocket rides a loopback TCP pair with NO signaling
    /// server behind it: emits land in the returned far-end socket, nothing is
    /// ever read back, and no ack ever arrives (`emit_with_ack` times out to
    /// `Ok(None)`, the normal "not heard back" outcome).
    ///
    /// For tests and harnesses that need a real `Client` value to construct
    /// connection state (the CLI's `Conn` holds one) without a network or a
    /// backend. Keep the far end alive for as long as the client is used, or
    /// emits start failing, which every caller already tolerates.
    #[doc(hidden)]
    pub async fn loopback() -> Result<(Client, tokio::net::TcpStream)> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let (dial, accept) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        let dial = dial?;
        let (far, _) = accept?;
        let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
            tokio_tungstenite::MaybeTlsStream::Plain(dial),
            tokio_tungstenite::tungstenite::protocol::Role::Client,
            None,
        )
        .await;
        let (writer, _reader) = ws.split();
        Ok((
            Client {
                id: next_conn_id(),
                writer: Arc::new(Mutex::new(Some(writer))),
                next_ack: Arc::new(AtomicU64::new(1)),
                pending: Arc::new(Mutex::new(HashMap::new())),
                reader_task: Arc::new(Mutex::new(None)),
                stopping: Arc::new(Mutex::new(false)),
                stop_tx: watch::channel(false).0,
            },
            far,
        ))
    }

    /// Close the Socket.IO session and the websocket under it.
    ///
    /// Tries the Socket.IO and websocket close handshake for at most
    /// [`DISCONNECT_GRACE`]. A peer that ignores Close cannot keep this future
    /// alive forever: after the grace period the owned reader is aborted and
    /// joined, and the shared sink is dropped (with a second bounded wait for
    /// concurrent writers). The usual bound is two grace periods plus runtime
    /// scheduling. The handle stays in shared state until the join completes,
    /// so a caller that cancels this future can retry shutdown safely.
    pub async fn disconnect(&self) -> Result<()> {
        *self.stopping.lock().await = true;
        self.stop_tx.send_replace(true);
        // Hold the task slot for the whole operation. Concurrent callers wait
        // here, and a timed-out/cancelled caller leaves the JoinHandle in place.
        let mut reader_task = self.reader_task.lock().await;

        let graceful = tokio::time::timeout(DISCONNECT_GRACE, async {
            let mut writer = self.writer.lock().await;
            if let Some(w) = writer.as_mut() {
                let _ = w.send(Message::Text("41".into())).await; // Socket.IO DISCONNECT
                let _ = w.close().await; // Flush and close the owned websocket sink.
            }
            drop(writer);
            if let Some(task) = reader_task.as_mut() {
                let _ = task.await;
            }
        })
        .await;

        if graceful.is_err() {
            // Dropping the read future releases its split websocket half. Abort
            // and join rather than detach: no task can emit after this returns.
            if let Some(task) = reader_task.as_mut() {
                task.abort();
                let _ = task.await;
            }
            // SplitSink is shared by Client clones; aborting only the reader
            // would otherwise leave its TCP write half alive. Remove it after
            // the graceful future has released the writer mutex.
            let _ = tokio::time::timeout(DISCONNECT_GRACE, async {
                self.writer.lock().await.take();
            })
            .await;
        }
        *reader_task = None;
        Ok(())
    }
}

/// Turn the signaling base URL into the Engine.IO websocket URL.
///
/// `EIO=4&transport=websocket` asks for the websocket transport directly, which
/// Engine.IO v4 permits, instead of opening a polling session and upgrading.
/// Pure, so the URL rewriting is testable without a server.
pub fn ws_url(base: &str) -> Result<String> {
    let trimmed = base.trim_end_matches('/');
    let scheme_swapped = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        trimmed.to_string()
    } else {
        // Default to TLS rather than plaintext: guessing wrong the other way
        // would silently downgrade signaling.
        format!("wss://{trimmed}")
    };
    Ok(format!("{scheme_swapped}/socket.io/?EIO=4&transport=websocket"))
}

/// Split an Engine.IO frame into its packet type digit and the rest.
fn split_packet(s: &str) -> Option<(char, &str)> {
    let mut chars = s.chars();
    let t = chars.next()?;
    Some((t, chars.as_str()))
}

/// Parse a Socket.IO EVENT body (`["name", data]`, possibly preceded by an ack
/// id) into its name and first argument.
///
/// The ack id is skipped rather than rejected: the server is entitled to ask for
/// an acknowledgement, and refusing to parse those frames would drop real
/// events. tunlion never sends acks, which is the existing behaviour.
pub fn parse_event(body: &str) -> Option<(String, Value)> {
    let json_start = body.find('[')?;
    let arr: Value = serde_json::from_str(&body[json_start..]).ok()?;
    let mut items = match arr {
        Value::Array(v) => v,
        _ => return None,
    };
    if items.is_empty() {
        return None;
    }
    let name = match items.remove(0) {
        Value::String(s) => s,
        _ => return None,
    };
    // An event with no argument is legal; hand up Null rather than dropping it.
    let data = if items.is_empty() { Value::Null } else { items.remove(0) };
    Some((name, data))
}

/// Parse a Socket.IO ACK body (`<id>[args...]`) into its id and arguments.
pub fn parse_ack(body: &str) -> Option<(u64, Vec<Value>)> {
    let bracket = body.find('[')?;
    let id: u64 = body[..bracket].parse().ok()?;
    match serde_json::from_str(&body[bracket..]).ok()? {
        Value::Array(v) => Some((id, v)),
        _ => None,
    }
}

/// How long the whole connect sequence may take.
///
/// A TCP connection that is accepted and then goes silent is the dangerous case:
/// without a bound, `connect` waits forever on a handshake that will never
/// arrive, and every caller inherits that hang. rust_socketio bounded this; the
/// replacement has to as well, or a dead server turns into a stuck process
/// instead of an error the caller can retry.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
/// Maximum graceful signaling shutdown time before the owned reader is aborted.
/// Forced sink release gets a second bound of the same length. This is
/// deliberately short: callers may already be in a larger engine shutdown
/// budget, and a peer is not required to answer a websocket Close.
const DISCONNECT_GRACE: std::time::Duration = std::time::Duration::from_millis(500);

/// Connect, complete both handshakes, and start the read loop.
///
/// Returns once the Socket.IO namespace is joined, so a caller that immediately
/// emits cannot race the CONNECT packet. Bounded by `CONNECT_TIMEOUT` end to
/// end, including the TCP/TLS dial.
pub async fn connect(base_url: &str, tx: mpsc::UnboundedSender<Incoming>) -> Result<Client> {
    tokio::time::timeout(CONNECT_TIMEOUT, connect_inner(base_url, tx))
        .await
        .map_err(|_| anyhow!("signaling handshake timed out after {CONNECT_TIMEOUT:?}"))?
}

/// The websocket's TLS config: the trust every client of tunlion's servers
/// shares ([`tls::client_config`]), with tungstenite's default empty ALPN.
fn tls_config() -> Result<rustls::ClientConfig, rustls::Error> {
    tls::client_config()
}

async fn connect_inner(base_url: &str, tx: mpsc::UnboundedSender<Incoming>) -> Result<Client> {
    let url = ws_url(base_url)?;
    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(
        tls_config().context("loading the TLS trust store")?,
    ));
    let (stream, _resp) =
        tokio_tungstenite::connect_async_tls_with_config(&url, None, false, Some(connector))
            .await
            .with_context(|| format!("websocket connect to {url}"))?;
    let (writer, mut reader) = stream.split();
    let writer: Writer = Arc::new(Mutex::new(Some(writer)));
    let (stop_tx, stop_rx) = watch::channel(false);

    // Engine.IO OPEN ('0') must arrive first and carries the session parameters.
    // Anything else here means we are not talking to an Engine.IO v4 endpoint,
    // and continuing would just hang on the next read.
    let first = reader
        .next()
        .await
        .ok_or_else(|| anyhow!("signaling closed before the Engine.IO handshake"))?
        .context("read Engine.IO OPEN")?;
    let text = first.into_text().context("Engine.IO OPEN was not text")?;
    let (kind, _body) = split_packet(&text).ok_or_else(|| anyhow!("empty Engine.IO OPEN"))?;
    if kind != '0' {
        bail!("expected Engine.IO OPEN, got packet type '{kind}'");
    }

    // Socket.IO CONNECT to the default namespace, then wait for its reply.
    writer
        .lock()
        .await
        .as_mut()
        .ok_or_else(|| anyhow!("signaling writer closed"))?
        .send(Message::Text("40".into()))
        .await
        .context("send Socket.IO CONNECT")?;
    loop {
        let msg = reader
            .next()
            .await
            .ok_or_else(|| anyhow!("signaling closed during the Socket.IO handshake"))?
            .context("read Socket.IO CONNECT reply")?;
        let Ok(text) = msg.into_text() else { continue };
        match split_packet(&text) {
            // '4' is Engine.IO MESSAGE; the Socket.IO type is the next digit.
            Some(('4', rest)) => match split_packet(rest) {
                Some(('0', _)) => break,                       // CONNECT accepted
                Some(('4', err)) => bail!("signaling refused the connection: {err}"),
                _ => continue,
            },
            Some(('2', _)) => {
                // A ping can arrive mid-handshake; answer it or the server
                // will time us out while we are still waiting.
                let _ = send_writer_message(
                    &writer,
                    stop_rx.clone(),
                    Message::Text("3".into()),
                )
                .await;
            }
            _ => continue,
        }
    }

    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let id = next_conn_id();
    let reader_task = Arc::new(Mutex::new(None));
    let stopping = Arc::new(Mutex::new(false));
    let client = Client {
        id,
        writer: writer.clone(),
        next_ack: Arc::new(AtomicU64::new(1)),
        pending: pending.clone(),
        reader_task: reader_task.clone(),
        stopping: stopping.clone(),
        stop_tx,
    };
    *reader_task.lock().await = Some(tokio::spawn(read_loop(
        id, reader, writer, tx, pending, stopping, stop_rx,
    )));
    Ok(client)
}

/// Pump packets until the socket ends, then report why exactly once.
async fn read_loop(
    conn: u64,
    mut reader: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    writer: Writer,
    tx: mpsc::UnboundedSender<Incoming>,
    pending: Pending,
    stopping: Arc<Mutex<bool>>,
    stop_rx: watch::Receiver<bool>,
) {
    let reason = loop {
        let Some(next) = reader.next().await else { break "closed".to_string() };
        let msg = match next {
            Ok(m) => m,
            Err(e) => break format!("error: {e}"),
        };
        let text = match msg {
            Message::Text(t) => t.to_string(),
            Message::Close(_) => break "close".to_string(),
            // Ping/Pong at the websocket layer are handled by tungstenite; any
            // binary frame would be a Socket.IO attachment, which this client
            // does not implement and must not silently ignore.
            Message::Binary(_) => break "unsupported binary frame".to_string(),
            _ => continue,
        };
        match split_packet(&text) {
            // Engine.IO PING. Answering keeps the session alive; missing these
            // is what produced the 30s-silence reconnect storm documented in
            // net.rs, so it is the one thing here that must never be skipped.
            Some(('2', _)) => {
                if send_writer_message(&writer, stop_rx.clone(), Message::Text("3".into()))
                    .await
                    .is_err()
                {
                    break "write failed".to_string();
                }
            }
            Some(('1', _)) => break "server closed".to_string(),
            Some(('4', rest)) => match split_packet(rest) {
                Some(('2', body)) => {
                    if let Some((name, data)) = parse_event(body) {
                        let stopping = stopping.lock().await;
                        if *stopping {
                            break "stopped".to_string();
                        }
                        if tx.send(Incoming::Event { name, data }).is_err() {
                            break "receiver gone".to_string();
                        }
                    }
                }
                // ACK: hand the arguments to whoever is waiting on this id.
                Some(('3', body)) => {
                    if let Some((id, args)) = parse_ack(body) {
                        if let Some(waiter) = pending.lock().await.remove(&id) {
                            let _ = waiter.send(args);
                        }
                    }
                }
                Some(('1', _)) => break "server disconnected the namespace".to_string(),
                _ => {}
            },
            _ => {}
        }
    };
    let stopping = stopping.lock().await;
    if !*stopping {
        let _ = tx.send(Incoming::Down { conn, reason });
    }
}

#[cfg(test)]
mod tls_tests;

#[cfg(test)]
mod tests {
    use super::*;

    async fn read_raw_client_frame(socket: &mut tokio::net::TcpStream) -> (u8, Vec<u8>) {
        use tokio::io::AsyncReadExt;

        let mut header = [0; 2];
        socket.read_exact(&mut header).await.unwrap();
        let mut len = (header[1] & 0x7f) as usize;
        if len == 126 {
            let mut extended = [0; 2];
            socket.read_exact(&mut extended).await.unwrap();
            len = u16::from_be_bytes(extended) as usize;
        } else if len == 127 {
            let mut extended = [0; 8];
            socket.read_exact(&mut extended).await.unwrap();
            len = u64::from_be_bytes(extended) as usize;
        }
        assert_ne!(header[1] & 0x80, 0, "client frames must be masked");
        let mut mask = [0; 4];
        socket.read_exact(&mut mask).await.unwrap();
        let mut payload = vec![0; len];
        socket.read_exact(&mut payload).await.unwrap();
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % mask.len()];
        }
        (header[0] & 0x0f, payload)
    }

    async fn send_raw_server_text(socket: &mut tokio::net::TcpStream, text: &str) {
        use tokio::io::AsyncWriteExt;

        let payload = text.as_bytes();
        assert!(payload.len() < 126);
        socket.write_all(&[0x81, payload.len() as u8]).await.unwrap();
        socket.write_all(payload).await.unwrap();
    }

    async fn local_client(
        server_action: impl FnOnce(
                tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
            ) -> tokio::task::JoinHandle<()>
            + Send
            + 'static,
    ) -> (Client, mpsc::UnboundedReceiver<Incoming>, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let url = format!("http://{addr}");
        let client_fut = connect(&url, tx);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            ws.send(Message::Text("0{}".into())).await.unwrap();
            assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "40");
            ws.send(Message::Text("40{}".into())).await.unwrap();
            server_action(ws)
        });
        let client = client_fut.await.unwrap();
        // Let the server finish its handshake and start its scripted behavior.
        let action = server.await.unwrap();
        (client, rx, action)
    }

    async fn reply_to_client_close(mut ws: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>) {
        while let Some(frame) = ws.next().await {
            match frame.unwrap() {
                Message::Close(_) => {
                    let _ = ws.send(Message::Close(None)).await;
                    return;
                }
                _ => {}
            }
        }
    }

    #[tokio::test]
    async fn disconnect_joins_reader_and_suppresses_late_event_and_down() {
        let (client, mut rx, server) = local_client(|mut ws| {
            tokio::spawn(async move {
                // The local stop flag is set before disconnect writes this packet.
                assert_eq!(ws.next().await.unwrap().unwrap().into_text().unwrap(), "41");
                ws.send(Message::Text(r#"42["late",{}]"#.into()))
                    .await
                    .unwrap();
                reply_to_client_close(ws).await;
            })
        })
        .await;
        client.disconnect().await.unwrap();
        assert!(rx.try_recv().is_err(), "local shutdown must not emit Down/event");
        assert!(rx.recv().await.is_none(), "disconnect must await reader exit");
        assert!(server.await.is_ok());
    }

    #[tokio::test]
    async fn concurrent_disconnects_are_idempotent_and_both_join() {
        let (client, mut rx, server) =
            local_client(|ws| tokio::spawn(reply_to_client_close(ws))).await;
        let cloned = client.clone();
        let (a, b) = tokio::join!(client.disconnect(), cloned.disconnect());
        a.unwrap();
        b.unwrap();
        assert!(rx.try_recv().is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn disconnect_terminates_socket_when_peer_ignores_close() {
        let (client, mut rx, server) = local_client(|mut ws| {
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;

                // Read raw TCP frames after the Socket.IO handshake. The
                // tungstenite server API automatically answers Close when
                // polled, which would mask the peer-ignores-close case.
                let socket = ws.get_mut();
                let (opcode, payload) = read_raw_client_frame(socket).await;
                assert_eq!(opcode, 1);
                assert_eq!(payload, b"41");
                // A peer may still send data after Socket.IO DISCONNECT. Local
                // shutdown must suppress it, then finish even if this peer
                // never answers the websocket close handshake.
                send_raw_server_text(socket, r#"42["late",{}]"#).await;
                let (opcode, _) = read_raw_client_frame(socket).await;
                assert_eq!(opcode, 8, "client should send a websocket Close frame");
                let mut byte = [0; 1];
                assert_eq!(socket.read(&mut byte).await.unwrap(), 0, "forced sink drop should close TCP");
            })
        })
        .await;

        let started = std::time::Instant::now();
        client.disconnect().await.unwrap();
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        assert!(rx.try_recv().is_err(), "shutdown must suppress late data");
        assert!(rx.recv().await.is_none(), "reader task must be joined after abort");
        server.abort();
    }

    #[tokio::test]
    async fn remote_close_delivers_down_when_not_locally_stopping() {
        let (client, mut rx, server) = local_client(|mut ws| {
            tokio::spawn(async move {
                ws.send(Message::Close(None)).await.unwrap();
            })
        })
        .await;
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(msg, Incoming::Down { conn, .. } if conn == client.id()));
        client.disconnect().await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn https_becomes_wss_and_keeps_the_engineio_query() {
        let u = ws_url("https://api.example.com").unwrap();
        assert_eq!(u, "wss://api.example.com/socket.io/?EIO=4&transport=websocket");
        assert_eq!(ws_url("https://api.example.com/").unwrap(), u, "trailing slash is the same URL");
    }

    #[test]
    fn http_becomes_ws_and_a_bare_host_defaults_to_tls() {
        assert!(ws_url("http://localhost:5000").unwrap().starts_with("ws://localhost:5000/"));
        // Guessing plaintext for a bare host would silently downgrade signaling.
        assert!(ws_url("api.example.com").unwrap().starts_with("wss://"));
    }

    #[test]
    fn parses_an_event_and_its_first_argument() {
        let (n, d) = parse_event(r#"["welcome",{"sid":"abc"}]"#).unwrap();
        assert_eq!(n, "welcome");
        assert_eq!(d["sid"], "abc");
    }

    /// The server may request an acknowledgement by prefixing an id. Refusing to
    /// parse those would silently drop real events.
    #[test]
    fn an_ack_id_before_the_array_does_not_hide_the_event() {
        let (n, d) = parse_event(r#"17["signal",{"k":1}]"#).unwrap();
        assert_eq!(n, "signal");
        assert_eq!(d["k"], 1);
    }

    #[test]
    fn an_event_with_no_argument_is_kept_not_dropped() {
        let (n, d) = parse_event(r#"["synced"]"#).unwrap();
        assert_eq!(n, "synced");
        assert_eq!(d, Value::Null);
    }

    #[test]
    fn malformed_bodies_are_refused_rather_than_guessed_at() {
        assert!(parse_event("not json").is_none());
        assert!(parse_event("[]").is_none());
        assert!(parse_event(r#"[{"not":"a name"}]"#).is_none());
    }

    /// A re-dialing caller tells a late close of a replaced connection from the
    /// loss of the current one by comparing these ids, so two connections must
    /// never share one.
    #[test]
    fn connection_ids_are_never_reused_or_zero() {
        let ids: Vec<u64> = (0..64).map(|_| next_conn_id()).collect();
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ids.len());
        assert!(ids.iter().all(|&i| i != 0));
    }

    #[test]
    fn packet_types_split_off_the_leading_digit() {
        assert_eq!(split_packet("42[\"a\"]"), Some(('4', "2[\"a\"]")));
        assert_eq!(split_packet("2"), Some(('2', "")));
        assert_eq!(split_packet(""), None);
    }
}
