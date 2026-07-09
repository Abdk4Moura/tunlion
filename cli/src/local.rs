//! TCP localhost transport for same-machine peers.
//!
//! This module provides a high-performance IPC transport that bypasses WebRTC/QUIC
//! when both peers are on the same machine. Uses TCP localhost for
//! zero-encryption, high-throughput transfers.

use anyhow::{bail, Result};
use bytes::Bytes;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use crate::net::{Ev, Transport};

const KIND_CONTROL: u8 = 0;
const KIND_DATA: u8 = 1;
const MAX_PAYLOAD: usize = 1024 * 1024; // 1 MiB

/// TCP localhost transport implementing the `Transport` trait.
pub struct LocalTransport {
    stream: Arc<Mutex<TcpStream>>,
    dead: Arc<AtomicBool>,
    last_activity: Arc<AtomicU64>,
}

impl LocalTransport {
    /// Connect to a peer's TCP localhost.
    pub async fn connect(addr: &str) -> Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let stream = Arc::new(Mutex::new(stream));

        Ok(Self {
            stream,
            dead: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(AtomicU64::new(now_ms())),
        })
    }

    /// Create a transport from an accepted TCP stream.
    pub fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream: Arc::new(Mutex::new(stream)),
            dead: Arc::new(AtomicBool::new(false)),
            last_activity: Arc::new(AtomicU64::new(now_ms())),
        }
    }
}

#[async_trait::async_trait]
impl Transport for LocalTransport {
    async fn send_control(&self, msg: &serde_json::Value) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            bail!("transport is dead");
        }
        let payload = serde_json::to_vec(msg)?;
        let len = payload.len() as u32;
        let hdr = [KIND_CONTROL, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        let mut stream = self.stream.lock().await;
        stream.write_all(&hdr).await?;
        stream.write_all(&payload).await?;
        stream.flush().await?;
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    async fn send_frame(&self, sid: u32, payload: &[u8]) -> Result<()> {
        if self.dead.load(Ordering::Relaxed) {
            bail!("transport is dead");
        }
        let len = payload.len() as u32 + 4; // +4 for sid
        let hdr = [KIND_DATA, (len >> 24) as u8, (len >> 16) as u8, (len >> 8) as u8, len as u8];
        let sid_bytes = sid.to_be_bytes();
        let mut stream = self.stream.lock().await;
        stream.write_all(&hdr).await?;
        stream.write_all(&sid_bytes).await?;
        stream.write_all(payload).await?;
        stream.flush().await?;
        self.last_activity.store(now_ms(), Ordering::Relaxed);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut stream = self.stream.lock().await;
        stream.flush().await?;
        Ok(())
    }

    fn max_payload(&self) -> usize {
        MAX_PAYLOAD
    }

    fn is_alive(&self) -> bool {
        !self.dead.load(Ordering::Relaxed)
    }

    fn idle_ms(&self) -> u64 {
        now_ms().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }

    fn remote_addr(&self) -> Option<std::net::SocketAddr> {
        None
    }

    fn local_ip(&self) -> Option<std::net::IpAddr> {
        None
    }
}

/// Start a TCP listener for local peer connections.
pub async fn listen_local() -> Result<(TcpListener, u16)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    Ok((listener, port))
}

/// Get the socket address for a local peer.
pub fn local_socket_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
