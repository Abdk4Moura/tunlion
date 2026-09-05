//! A minimal Socket.IO v5 / Engine.IO v4 client, websocket-only, over rustls.
//!
//! WHY THIS EXISTS. `rust_socketio` depends on `native-tls` unconditionally (not
//! behind a feature), which forced the binary to link the system
//! `libssl`/`libcrypto`, pulled a SECOND `reqwest` major version into the tree,
//! and made a self-contained build impossible. That was recorded as ledger C16
//! and treated as unfixable without forking upstream.
//!
//! It turned out not to need a fork, because filament uses almost none of that
//! crate. The client connects with `TransportType::Websocket` and
//! `reconnect(false)`, its handlers only ever pull the first JSON value out of a
//! payload and forward it to one channel, and the only methods called on the
//! client are `emit`, `disconnect` and `clone`. What was actually required was a
//! websocket, the Engine.IO framing bytes, and Socket.IO's `42["name",data]`.
//!
//! SCOPE, deliberately small. Websocket transport only, no HTTP long-polling
//! upgrade dance (filament forces websocket anyway, because polling behind
//! Cloudflare produced the reconnect storm documented in `net.rs`). No binary
//! attachments: every payload here is JSON. No automatic reconnect: filament
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
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::tungstenite::Message;

/// What the read loop delivers upward. One channel for everything, because every
/// call site did the same thing with a per-event callback anyway.
#[derive(Debug, Clone)]
pub enum Incoming {
    /// A Socket.IO event and its first argument.
    Event { name: String, data: Value },
    /// The connection ended. The reason is for logging only.
    Down(String),
}

type Writer = Arc<
    Mutex<
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            Message,
        >,
    >,
>;

/// A handle to a live signaling connection. Cheap to clone; every clone writes
/// to the same socket behind one mutex.
/// Acks the server owes us, by id.
type Pending = Arc<Mutex<HashMap<u64, tokio::sync::oneshot::Sender<Vec<Value>>>>>;

#[derive(Clone)]
pub struct Client {
    writer: Writer,
    /// Ack ids are client-chosen and must be unique per connection; the server
    /// echoes them back on `43`.
    next_ack: Arc<AtomicU64>,
    pending: Pending,
}

impl Client {
    /// Send a Socket.IO event with a single JSON argument.
    pub async fn emit(&self, event: &str, data: Value) -> Result<()> {
        // 42 = Socket.IO EVENT inside Engine.IO MESSAGE, then the argument
        // array. serde_json does the escaping, so an event name or payload
        // containing a quote cannot break framing.
        let frame = format!("42{}", Value::Array(vec![Value::String(event.into()), data]));
        self.writer
            .lock()
            .await
            .send(Message::Text(frame.into()))
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
        if let Err(e) = self.writer.lock().await.send(Message::Text(frame.into())).await {
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

    /// Close the Socket.IO session and the websocket under it.
    ///
    /// Best effort by design: this runs on paths that are already tearing down,
    /// and a peer that has gone away must not turn shutdown into an error.
    pub async fn disconnect(&self) -> Result<()> {
        let mut w = self.writer.lock().await;
        let _ = w.send(Message::Text("41".into())).await; // Socket.IO DISCONNECT
        let _ = w.send(Message::Close(None)).await;
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
/// events. filament never sends acks, which is the existing behaviour.
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

async fn connect_inner(base_url: &str, tx: mpsc::UnboundedSender<Incoming>) -> Result<Client> {
    // Idempotent, and the reason the CLI can skip this for local-only commands:
    // whoever opens TLS first installs the provider, so no call site has to
    // remember to. `.ok()` because "already installed" is the normal case.
    let _ = rustls::crypto::ring::default_provider().install_default();
    let url = ws_url(base_url)?;
    let (stream, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .with_context(|| format!("websocket connect to {url}"))?;
    let (writer, mut reader) = stream.split();
    let writer: Writer = Arc::new(Mutex::new(writer));

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
    writer.lock().await.send(Message::Text("40".into())).await.context("send Socket.IO CONNECT")?;
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
                let _ = writer.lock().await.send(Message::Text("3".into())).await;
            }
            _ => continue,
        }
    }

    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let client = Client {
        writer: writer.clone(),
        next_ack: Arc::new(AtomicU64::new(1)),
        pending: pending.clone(),
    };
    tokio::spawn(read_loop(reader, writer, tx, pending));
    Ok(client)
}

/// Pump packets until the socket ends, then report why exactly once.
async fn read_loop(
    mut reader: futures_util::stream::SplitStream<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
    >,
    writer: Writer,
    tx: mpsc::UnboundedSender<Incoming>,
    pending: Pending,
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
                if writer.lock().await.send(Message::Text("3".into())).await.is_err() {
                    break "write failed".to_string();
                }
            }
            Some(('1', _)) => break "server closed".to_string(),
            Some(('4', rest)) => match split_packet(rest) {
                Some(('2', body)) => {
                    if let Some((name, data)) = parse_event(body) {
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
    let _ = tx.send(Incoming::Down(reason));
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn packet_types_split_off_the_leading_digit() {
        assert_eq!(split_packet("42[\"a\"]"), Some(('4', "2[\"a\"]")));
        assert_eq!(split_packet("2"), Some(('2', "")));
        assert_eq!(split_packet(""), None);
    }
}
