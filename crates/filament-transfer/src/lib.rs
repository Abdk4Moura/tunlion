//! Moving and reassembling bytes: the mechanics of a transfer, with no opinion
//! about how the peer was found or authenticated.
//!
//! # Why this is its own module
//!
//! All of this lived inside `main.rs` next to the send/receive event loops, so
//! "reassemble out-of-order chunks" was interleaved with "run a PAKE ceremony",
//! "adopt a peer", and "draw a progress bar". Nothing here depends on any of
//! that. Keeping them together meant a transfer could only ever run on a link
//! the sending PROCESS had just established for itself, which is precisely what
//! blocks reusing a link the daemon already holds.
//!
//! Everything in here is pure or filesystem-local: no transports, no signalling,
//! no UI. That is what makes it testable without a network, and it is why the
//! reassembly functions could finally be given the tests they never had.
//!
//! # Why the tests matter more here than elsewhere
//!
//! This is the path with a measured corruption history. `pwrite_at` exists
//! because a positional write may write FEWER bytes than asked: the original
//! discarded the returned count, so a short write left a hole while the progress
//! counter advanced by the full length. Silent per-file corruption, caught only
//! by the whole-file digest, measured at ~44% on direct-QUIC and ~88% on the
//! DataChannel for large files. The range bookkeeping below is what decides
//! whether a file is complete, so a bug in it means either a truncated file
//! accepted as whole, or a whole file rejected as truncated.

use std::path::PathBuf;

/// Positional write that does not lose bytes.
///
/// `write_at` / `seek_write` may write fewer bytes than requested. The original
/// code discarded the returned count, so a short write left a gap while the
/// received counter advanced by the full length. Loop until the whole buffer
/// lands, and return `Err` on a real failure so the caller can react rather than
/// silently drop bytes.
///
/// Returns the number of iterations it took: 1 is the normal case, more means a
/// short write actually happened. Reporting that is the CALLER's business, which
/// is why this returns it instead of printing. It used to `eprintln!` from in
/// here, which put terminal output inside the byte-writing primitive.
#[cfg(unix)]
pub fn pwrite_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<u32> {
    use std::os::unix::fs::FileExt;
    let mut written = 0usize;
    let mut iters = 0u32;
    while written < buf.len() {
        iters += 1;
        match file.write_at(&buf[written..], offset + written as u64) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "pwrite wrote 0 bytes",
                ))
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(iters)
}

#[cfg(windows)]
pub fn pwrite_at(file: &std::fs::File, buf: &[u8], offset: u64) -> std::io::Result<u32> {
    use std::os::windows::fs::FileExt;
    let mut written = 0usize;
    let mut iters = 0u32;
    while written < buf.len() {
        iters += 1;
        match file.seek_write(&buf[written..], offset + written as u64) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "seek_write wrote 0 bytes",
                ))
            }
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(iters)
}

/// Reduce a remote-supplied filename to a safe single path component.
///
/// Never trust a remote name: basename only, no separators, no control bytes.
pub fn safe_incoming_name(raw: &str) -> String {
    let base = std::path::Path::new(raw)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file.bin".into());
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "file.bin".to_string()
    } else {
        cleaned
    }
}

/// Record `[pos, pos+len)` into a sorted set of disjoint intervals, merging
/// anything it touches. Returns `(newly covered bytes, total covered)`.
///
/// Chunks can arrive out of order and can overlap on a resume, so "how much do
/// we actually have" is not "how many bytes arrived". `delta` is what progress
/// should advance by; counting the raw length instead double-counts a resend and
/// reports a file complete before it is.
pub fn record_range(ranges: &mut Vec<(u64, u64)>, pos: u64, len: usize) -> (u64, u64) {
    let end = pos + len as u64;
    if ranges.is_empty() {
        ranges.push((pos, end));
        let total = len as u64;
        return (total, total);
    }
    // First range whose end >= pos: the earliest one this could touch.
    let mut lo = 0usize;
    let mut hi = ranges.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        if ranges[mid].1 < pos {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut idx = lo;
    let mut new_s = pos;
    let mut new_e = end;
    let mut removed_total: u64 = 0;
    // Merge every overlapping OR adjacent range (adjacent when start <= new_e,
    // so [0,5) and [5,9) become [0,9) rather than staying split forever).
    while idx < ranges.len() && ranges[idx].0 <= new_e {
        let (s, e) = ranges[idx];
        removed_total += e - s;
        new_s = new_s.min(s);
        new_e = new_e.max(e);
        ranges.remove(idx);
    }
    let new_len = new_e - new_s;
    ranges.insert(idx, (new_s, new_e));
    let delta = new_len.saturating_sub(removed_total);
    let total: u64 = ranges.iter().map(|(s, e)| e - s).sum();
    (delta, total)
}

/// `record_range` for callers that only want the running total.
pub fn record_range_total(ranges: &mut Vec<(u64, u64)>, pos: u64, len: usize) -> u64 {
    record_range(ranges, pos, len).1
}

/// True iff the ranges tile `[0, size)` with no gap.
pub fn coverage_complete(ranges: &[(u64, u64)], size: u64) -> bool {
    if size == 0 {
        return true;
    }
    ranges.len() == 1 && ranges[0].0 == 0 && ranges[0].1 == size
}

/// First uncovered byte in `[0, size)`, or `None` when complete. This is the
/// resume point.
pub fn first_gap(ranges: &[(u64, u64)], size: u64) -> Option<u64> {
    if size == 0 {
        return None;
    }
    let mut cursor = 0u64;
    for &(s, e) in ranges {
        if s > cursor {
            return Some(cursor);
        }
        cursor = cursor.max(e);
        if cursor >= size {
            return None;
        }
    }
    if cursor < size {
        Some(cursor)
    } else {
        None
    }
}

/// One file we are sending, and where it has got to.
pub struct Outgoing {
    pub id: String,
    pub sid: u32,
    pub name: String,
    pub size: u64,
    pub head: Option<String>,
    /// sha256 of the WHOLE file, carried in `file-offer` as `full`. The receiver
    /// compares its bytes against this and only accepts (and acks) on a match,
    /// so no transfer can "complete" truncated or corrupt. `None` only when the
    /// digest could not be computed, which degrades to the receiver's size-only
    /// check: bounded, never a hang.
    pub full: Option<String>,
    pub path: PathBuf,
    /// Delete after sending (tar spools, stdin spools).
    pub temp: bool,
    /// Re-offers carry `resume: true` after the first accept.
    pub accepted_once: bool,
    /// The bytes have left this side (stream finished, `file-end` sent). NOT the
    /// same as `done`: a transfer is `sent` once, but is only `done` once the
    /// receiver's whole-file-verified `delivery-ack` lands. The no-ack window
    /// NEVER sets `done`; it re-probes and then fails the send, which is the
    /// silent-data-loss fix.
    pub sent: bool,
    /// The receiver returned a verified `delivery-ack`. This is the only thing
    /// that completes a send, the deterministic "it landed intact" signal. The
    /// one exception is a file with no `full` digest: there is nothing to
    /// verify-and-ack, so it is done on send (the legacy size-only path).
    pub acked: bool,
    /// The receiver refused this file. Distinct from `done`: a declined transfer
    /// has FINISHED without landing, and reporting it as success is what #274
    /// fixed. The send exits non-zero.
    pub declined: bool,
    pub done: bool,
    /// When these bytes started streaming, and how many went out in THIS attempt
    /// (`size - offset`, so a resume counts only its own share).
    ///
    /// Completion throughput is measured from here to the moment the
    /// `delivery-ack` lands, because that is the only instant at which the bytes
    /// are known to be on the far side. Timing to the end of `flush()` instead
    /// measures how fast a socket buffer was filled.
    pub stream_started: Option<std::time::Instant>,
    pub stream_bytes: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- reassembly -------------------------------------------------------
    // These had NO tests, in the one path with a measured corruption history.
    // Every case below is a way a file is declared complete when it is not, or
    // incomplete when it is.

    #[test]
    fn in_order_chunks_accumulate() {
        let mut r = Vec::new();
        assert_eq!(record_range(&mut r, 0, 10), (10, 10));
        assert_eq!(record_range(&mut r, 10, 10), (10, 20));
        assert_eq!(r, vec![(0, 20)], "adjacent ranges must merge");
    }

    #[test]
    fn out_of_order_chunks_leave_a_hole_until_filled() {
        let mut r = Vec::new();
        record_range(&mut r, 10, 10); // [10,20)
        record_range(&mut r, 0, 5); //  [0,5)
        assert_eq!(r, vec![(0, 5), (10, 20)]);
        assert!(!coverage_complete(&r, 20));
        assert_eq!(first_gap(&r, 20), Some(5), "resume must start at the hole");
        record_range(&mut r, 5, 5); // bridges them
        assert_eq!(r, vec![(0, 20)]);
        assert!(coverage_complete(&r, 20));
        assert_eq!(first_gap(&r, 20), None);
    }

    // The double-count bug: a resend must advance progress by ZERO, not by its
    // length, or the file reports complete before it is.
    #[test]
    fn a_duplicate_chunk_covers_nothing_new() {
        let mut r = Vec::new();
        assert_eq!(record_range(&mut r, 0, 10).0, 10);
        assert_eq!(record_range(&mut r, 0, 10).0, 0, "resend adds no coverage");
        assert_eq!(record_range(&mut r, 5, 5).0, 0, "contained resend adds none");
        assert_eq!(r, vec![(0, 10)]);
    }

    #[test]
    fn a_partly_overlapping_chunk_counts_only_the_new_part() {
        let mut r = Vec::new();
        record_range(&mut r, 0, 10);
        assert_eq!(record_range(&mut r, 5, 10).0, 5, "only [10,15) is new");
        assert_eq!(r, vec![(0, 15)]);
    }

    #[test]
    fn one_chunk_can_bridge_many_ranges() {
        let mut r = Vec::new();
        record_range(&mut r, 0, 2);
        record_range(&mut r, 10, 2);
        record_range(&mut r, 20, 2);
        assert_eq!(r.len(), 3);
        let (delta, total) = record_range(&mut r, 0, 22);
        assert_eq!(r, vec![(0, 22)], "all three collapse into one");
        assert_eq!(total, 22);
        assert_eq!(delta, 16, "22 total minus the 6 already held");
    }

    // A gap at the very END is the truncation case the digest exists to catch.
    #[test]
    fn a_trailing_gap_is_not_complete() {
        let r = vec![(0u64, 90u64)];
        assert!(!coverage_complete(&r, 100));
        assert_eq!(first_gap(&r, 100), Some(90));
    }

    // Covering MORE than the file is still not "exactly the file".
    #[test]
    fn overshooting_the_size_is_not_complete() {
        let r = vec![(0u64, 120u64)];
        assert!(!coverage_complete(&r, 100));
    }

    #[test]
    fn a_leading_gap_resumes_at_zero() {
        let r = vec![(10u64, 100u64)];
        assert!(!coverage_complete(&r, 100));
        assert_eq!(first_gap(&r, 100), Some(0));
    }

    #[test]
    fn empty_file_is_complete_and_has_no_gap() {
        assert!(coverage_complete(&[], 0));
        assert_eq!(first_gap(&[], 0), None);
    }

    #[test]
    fn nothing_received_is_incomplete_and_resumes_at_zero() {
        assert!(!coverage_complete(&[], 100));
        assert_eq!(first_gap(&[], 100), Some(0));
    }

    #[test]
    fn record_range_total_agrees_with_record_range() {
        let mut a = Vec::new();
        let mut b = Vec::new();
        for (pos, len) in [(0u64, 10usize), (30, 10), (10, 10), (5, 3)] {
            let (_d, total) = record_range(&mut a, pos, len);
            assert_eq!(record_range_total(&mut b, pos, len), total);
        }
        assert_eq!(a, b);
    }

    // --- untrusted names --------------------------------------------------

    #[test]
    fn remote_names_cannot_escape_the_drop_dir() {
        assert_eq!(safe_incoming_name("../../etc/passwd"), "passwd");
        assert_eq!(safe_incoming_name("/absolute/path.bin"), "path.bin");
        assert_eq!(safe_incoming_name("plain.bin"), "plain.bin");
    }

    #[test]
    fn control_bytes_are_stripped_and_degenerate_names_replaced() {
        assert_eq!(safe_incoming_name("evil\0.bin"), "evil.bin");
        assert_eq!(safe_incoming_name("with\ttab\nand\r.bin"), "withtaband.bin");
        assert_eq!(safe_incoming_name("\0\0\0"), "file.bin");
        assert_eq!(safe_incoming_name(".."), "file.bin");
        assert_eq!(safe_incoming_name("."), "file.bin");
        assert_eq!(safe_incoming_name(""), "file.bin");
    }

    // --- positional write -------------------------------------------------

    #[test]
    fn pwrite_at_lands_every_byte_at_the_right_offset() {
        let dir = std::env::temp_dir().join(format!("fil-pw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.bin");
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        // Write out of order, exactly as chunks arrive.
        pwrite_at(&f, b"world", 5).unwrap();
        pwrite_at(&f, b"hello", 0).unwrap();
        drop(f);
        assert_eq!(std::fs::read(&path).unwrap(), b"helloworld");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
