//! The framing used between a CLI `exec` and the daemon that carries it over a
//! warm link (the local control socket's `exec` op).
//!
//! The first line of that control connection is still the hand-written JSON
//! request/reply (`control::ReqKind::Exec`). Once the daemon has accepted, both
//! sides exchange binary frames so stdin/stdout/stderr bytes pass through
//! unchanged and the exit status is unambiguous:
//!
//! ```text
//!   u8 kind | u32 BE payload length | payload
//! ```
//!
//! The kinds are deliberately directional: the client sends only STDIN, EOF
//! and SIGNAL; the daemon sends only STDOUT, STDERR, EXIT and CLOSE. A frame
//! with an unknown kind is ignored, not guessed at, so a newer peer cannot make
//! an older one act on a shape it does not understand.
//!
//! This module is platform-neutral on purpose: the Unix control socket is the
//! only current transport, but the framing itself is just bytes and stays
//! reusable if a named-pipe transport is added later.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Client -> daemon: one chunk of the command's stdin.
pub const FRAME_STDIN: u8 = 0x01;
/// Client -> daemon: stdin reached EOF (the payload is empty).
pub const FRAME_STDIN_EOF: u8 = 0x02;
/// Client -> daemon: forward this signal (`HUP`/`INT`/`TERM`) to the remote
/// tree before the stream ends. The payload is the wire name.
pub const FRAME_SIGNAL: u8 = 0x03;

/// Daemon -> client: one chunk of the command's stdout.
pub const FRAME_STDOUT: u8 = 0x11;
/// Daemon -> client: one chunk of the command's stderr.
pub const FRAME_STDERR: u8 = 0x12;
/// Daemon -> client: the remote command exited; payload is 4-byte BE i32.
pub const FRAME_EXIT: u8 = 0x13;
/// Daemon -> client: the session ended without an exit status, or was refused
/// at request time. Payload is a JSON control frame (`l2-close`,
/// `link-revoked`, or our own `{"type":"warm-error","err":...}`).
pub const FRAME_CLOSE: u8 = 0x14;

/// A frame's payload is bounded. stdin chunks are 16 KiB and control frames are
/// tiny; this only stops a corrupt/hostile local peer from making us allocate
/// without limit.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Write one frame. The header and payload go through the same writer so callers
/// cannot accidentally interleave two frames.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    kind: u8,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "exec frame too large",
        ));
    }
    let mut head = [0u8; 5];
    head[0] = kind;
    head[1..].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    w.write_all(&head).await?;
    w.write_all(payload).await?;
    w.flush().await
}

/// Read one frame. `None` is a clean EOF before a header (the other side closed
/// the control connection). A partial header is an error, not a short frame.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; 5];
    let mut got = 0usize;
    while got < head.len() {
        match r.read(&mut head[got..]).await? {
            0 if got == 0 => return Ok(None),
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "exec frame ended inside its header",
                ))
            }
            n => got += n,
        }
    }
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "exec frame length exceeds the bound",
        ));
    }
    let mut payload = vec![0u8; len];
    r.read_exact(&mut payload).await?;
    Ok(Some((head[0], payload)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames_round_trip_byte_exact_and_in_order() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let frames: Vec<(u8, Vec<u8>)> = vec![
            (FRAME_STDIN, b"hello\0world".to_vec()),
            (FRAME_STDOUT, b"\xff\x00binary".to_vec()),
            (FRAME_STDERR, Vec::new()),
            (FRAME_EXIT, 7i32.to_be_bytes().to_vec()),
        ];
        let for_writer = frames.clone();
        let writer = tokio::spawn(async move {
            for (kind, payload) in for_writer {
                write_frame(&mut a, kind, &payload).await.unwrap();
            }
            drop(a);
        });
        for (kind, payload) in frames {
            let got = read_frame(&mut b).await.unwrap().expect("a frame");
            assert_eq!(got.0, kind);
            assert_eq!(got.1, payload);
        }
        assert!(read_frame(&mut b).await.unwrap().is_none());
        writer.await.unwrap();
    }

    #[tokio::test]
    async fn a_partial_header_is_an_error_not_a_frame() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&[FRAME_STDIN, 0, 0]).await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn an_oversized_length_is_refused_without_allocating() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let mut head = [0u8; 9];
        head[0] = FRAME_STDIN;
        head[1..5].copy_from_slice(&(MAX_FRAME as u32 + 1).to_be_bytes());
        a.write_all(&head).await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}
