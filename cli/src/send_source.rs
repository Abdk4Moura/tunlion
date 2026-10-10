//! The local side of `send`: is the source something that can be sent, and
//! what happens when it stops being readable half way.
//!
//! A blind tester sent a mode-000 file: the first run said "ok" and then
//! "lost the receiving peer after 5 attempts; the partial is kept, re-run the
//! same tunlion send to resume" (exit 6, the network blamed, and no re-run can
//! fix a permission), the second stalled silently until it was killed, and an
//! EMPTY mode-000 file reported "ok unread 0 B" (exit 0). The receiver was left
//! holding `unread`, `unread.part` and `unread.part.meta`. A FIFO or
//! `/dev/zero` hung with no output at all. Every one of those is a local input
//! problem, and every one is now said before anything is offered, as one: exit
//! 2, the path, the OS's reason.

use crate::exit_codes::{self, ExitKind};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::Read;

/// The whole-file SHA-256 of a source about to be offered, read in full now.
/// Refuses what is not a regular file and what cannot be read, naming the
/// path and the reason (exit 2: a local input problem, nothing contacted).
pub(crate) fn source_digest(path: &str, meta: &std::fs::Metadata) -> anyhow::Result<String> {
    if !meta.is_file() {
        return Err(not_regular_input(path));
    }
    let mut f = std::fs::File::open(path).map_err(|e| unreadable_input(path, &e))?;
    let (digest, n) = digest_reader(&mut f).map_err(|e| unreadable_input(path, &e))?;
    if n != meta.len() {
        return Err(exit_codes::err(
            ExitKind::Usage,
            format!(
                "cannot send '{path}': it changed size while it was being read ({} bytes, then {n}); \
                 send it again once nothing is writing to it (nothing was sent)",
                meta.len()
            ),
        ));
    }
    Ok(digest)
}

/// SHA-256 of everything `r` yields, and how many bytes that was.
pub(crate) fn digest_reader(r: &mut impl Read) -> std::io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut n = 0u64;
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => {
                h.update(&buf[..k]);
                n += k as u64;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok((h.finalize().iter().map(|b| format!("{b:02x}")).collect(), n))
}

/// A source that cannot be opened or read.
pub(crate) fn unreadable_input(path: &str, e: &std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        return crate::send_cmd::missing_input(path, e);
    }
    exit_codes::err(
        ExitKind::Usage,
        format!("cannot send '{path}': cannot read it: {e} (a local file problem; nothing was sent)"),
    )
}

/// A source that is a FIFO, a device or a socket: it has no size and may never
/// end, so it cannot be offered with the size and digest every offer carries.
pub(crate) fn not_regular_input(path: &str) -> anyhow::Error {
    exit_codes::err(
        ExitKind::Usage,
        format!(
            "cannot send '{path}': it is not a regular file (a named pipe, device or socket), so \
             its size and checksum cannot be known before sending. To send a stream, pipe it to \
             stdin instead: `cat {path} | tunlion send -` (nothing was sent)"
        ),
    )
}

/// A local read of the source failed after the transfer started. Carried in the
/// streaming task's error so the send loop can tell it from a network failure:
/// this one is never retried, the receiver is told to discard what it has, and
/// the send ends as a local input problem.
#[derive(Debug)]
pub(crate) struct SourceRead {
    pub(crate) msg: String,
}

impl std::fmt::Display for SourceRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}
impl std::error::Error for SourceRead {}

/// The error for a read of `path` that failed mid-transfer.
pub(crate) fn source_read(path: &std::path::Path, why: impl std::fmt::Display) -> anyhow::Error {
    anyhow::Error::new(SourceRead {
        msg: format!("could not read '{}' while sending it: {why}", path.display()),
    })
}

/// The message, if `e` is a mid-transfer local read failure.
pub(crate) fn as_source_read(e: &anyhow::Error) -> Option<String> {
    e.chain()
        .find_map(|c| c.downcast_ref::<SourceRead>())
        .map(|s| s.msg.clone())
}

/// Tells the receiver to stop and discard its partial for transfer `id`. An
/// older receiver ignores an unknown control type; it then keeps a partial it
/// can never complete, which is what happened before this message existed.
pub(crate) fn cancel_msg(id: &str, sid: u32, name: &str, reason: &str) -> Value {
    json!({ "type": "file-cancel", "id": id, "sid": sid, "name": name, "reason": reason })
}

/// How a send that ended without a delivery-ack for some file exits. Nothing
/// confirmed at all is "the receiver is gone or never answered" (6); exit 8
/// ("partial") is for when some files were confirmed and others were not.
pub(crate) fn unconfirmed_kind(confirmed: usize, unconfirmed: usize) -> ExitKind {
    if confirmed > 0 && unconfirmed > 0 {
        ExitKind::Partial
    } else {
        ExitKind::Unreachable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tunlion-src-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_readable_file_is_digested_in_full() {
        let d = tmp("ok");
        let p = d.join("a.txt");
        std::fs::write(&p, b"hello").unwrap();
        let meta = std::fs::metadata(&p).unwrap();
        let got = source_digest(p.to_str().unwrap(), &meta).unwrap();
        assert_eq!(got, crate::sha256_hex(b"hello"));
        let _ = std::fs::remove_dir_all(&d);
    }

    /// A directory reaches this only by mistake, but it must be the same clear
    /// refusal as any other non-regular source, never an attempt to read it.
    #[test]
    fn a_non_regular_source_is_refused_as_usage_and_points_at_stdin() {
        let d = tmp("dir");
        let meta = std::fs::metadata(&d).unwrap();
        let e = source_digest(d.to_str().unwrap(), &meta).unwrap_err();
        assert_eq!(exit_codes::classify(&e).code(), 2);
        let m = e.to_string();
        assert!(m.contains("not a regular file") && m.contains("tunlion send -"), "{m}");
        assert!(m.contains(d.to_str().unwrap()), "names the path: {m}");
        let _ = std::fs::remove_dir_all(&d);
    }

    /// The OS's reason travels into the message, and it is exit 2, not a
    /// network failure: the tester's mode-000 file exited 6 blaming the peer.
    #[test]
    fn an_unreadable_source_is_usage_with_the_os_reason() {
        let e = unreadable_input(
            "/tmp/unread",
            &std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        );
        assert_eq!(exit_codes::classify(&e).code(), 2);
        let m = e.to_string();
        assert!(m.contains("/tmp/unread") && m.contains("cannot read it"), "{m}");
        assert!(m.contains("nothing was sent"), "{m}");
        assert!(!m.to_lowercase().contains("peer"), "{m}");
    }

    /// A reader that fails part way, like a file on a failing disk.
    struct Failing(usize);
    impl Read for Failing {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            if self.0 == 0 {
                return Err(std::io::Error::other("I/O error"));
            }
            let n = b.len().min(self.0);
            self.0 -= n;
            Ok(n)
        }
    }

    #[test]
    fn a_read_error_is_an_error_never_a_shorter_digest() {
        assert!(digest_reader(&mut Failing(10)).is_err());
        let (_, n) = digest_reader(&mut std::io::Read::take(std::io::repeat(1), 3_000_000)).unwrap();
        assert_eq!(n, 3_000_000);
    }

    #[test]
    fn a_mid_transfer_read_failure_is_recognised_through_context() {
        let e = source_read(std::path::Path::new("/tmp/x"), "Permission denied").context("stream");
        let m = as_source_read(&e).expect("recognised");
        assert!(m.contains("/tmp/x") && m.contains("Permission denied"), "{m}");
        assert!(as_source_read(&anyhow::anyhow!("channel closed")).is_none());
        let c = cancel_msg("s-1", 1, "a.bin", "gone");
        assert_eq!(c["type"], "file-cancel");
        assert_eq!(c["sid"], 1);
    }

    /// One file, nothing confirmed: the peer is gone (6), not "partial" (8).
    #[test]
    fn unconfirmed_is_6_unless_something_was_confirmed() {
        assert_eq!(unconfirmed_kind(0, 1).code(), 6);
        assert_eq!(unconfirmed_kind(0, 3).code(), 6);
        assert_eq!(unconfirmed_kind(2, 1).code(), 8);
    }

    use anyhow::Context;
}
