# Transfer whole-file corruption: structural fix spec (#45)

## Root cause (two bugs, one theme: the coverage map lies about what's on disk)

The receiver reassembles out-of-order chunks by (a) writing each at a byte
position and (b) recording covered byte-ranges. Completion + the whole-file
sha256 gate on "received == size". Two defects let "received == size" be true
while the file on disk has a gap or wrong bytes:

1. **DataChannel drops the offset entirely (the ~88% case).** The `send_frame`
   trait is documented as framing `[u32 sid][u64 abs_offset][payload]`, and the
   QUIC transport (`direct.rs`) does exactly that and decodes the offset back
   (`Some(offset)`). The DataChannel transport (`net.rs`) frames only
   `[u32 sid][payload]` (it ignores the `offset` arg) and the receiver then
   derives position from a naive `inc.received.fetch_add(len)` counter. Any
   duplicate/retransmit over-counts the counter AND shifts every subsequent
   chunk's position forward, leaving an unwritten tail. The sender ALREADY passes
   the correct absolute offset (`send_frame(sid, pos, buf)` in `stream_one`,
   main.rs:10769); the DC transport just throws it away.

2. **QUIC records coverage as INTENT, before the write, and never checks it
   landed (the ~44% case).** `record_range` runs in the event loop BEFORE the
   async `pwrite_at`, so the range is marked "covered" even if the write later
   short-writes or hard-errors (ENOSPC/EIO). The write result was discarded
   (`let _ = pwrite_at(...)`). Partly mitigated already by the write-all
   `pwrite_at` loop on this branch (b3ccf20), but a hard I/O error still leaves a
   lying range.

## The fix (make the coverage map ground truth, and make it the completion gate)

### Part A: `cli/src/net.rs`: DataChannel frames the offset, exactly like QUIC

The trait signature and QUIC already carry the offset; make the DC transport
stop discarding it. This alone makes the DC receive path byte-identical to QUIC.

1. **Send** (`send_frame`, ~line 541):
   - `_offset` → `offset` in the signature.
   - Capacity `Vec::with_capacity(4 + payload.len())` → `4 + 8 + payload.len()`.
   - Between the sid and payload extends, insert:
     `framed.extend_from_slice(&offset.to_be_bytes());`
   Result frame: `[u32 BE sid][u64 BE offset][payload]`.

2. **Receive** (read loop, ~lines 1810-1828):
   - Threshold `if n >= 4` → `if n >= 12` (KEEP `>=`, not `>`: a 12-byte frame is
     an empty-payload FIN and must still be delivered; QUIC uses `>= 12` for the
     same reason).
   - Decode `sid = u32::from_be_bytes(buf[0..4])`,
     `offset = u64::from_be_bytes(buf[4..12])`, payload = `buf[12..n]`.
   - Emit `Ev::Chunk(peer_id, sid, Some(offset), Bytes::copy_from_slice(&buf[12..n]))`.
   - Fix the now-stale comment ("DataChannel frames carry no offset").

   Note: L2 mux + mount + the verify probe all send via `send_frame` with
   `offset = 0` and ignore offset on receive (l2.rs:1607 binds `_offset`); they
   get 8 zero bytes prepended and stripped symmetrically, unaffected. Verify no
   binary bytes are ever written to the data channel OUTSIDE `send_frame` (grep
   for direct `.send`/`write` on the raw DC): the uniform 12-byte header depends
   on it.

### Part B: `cli/src/main.rs` Ev::Chunk handler (~14691): writer records coverage AFTER the bytes land

3. Position for BOTH transports is now the frame offset. Delete the
   `else { pos = inc.received.fetch_add(...) }` branch. An offsetless frame
   (`offset == None`) is now impossible under the new scheme, so REFUSE it: log
   loudly (`dlog!("[recv] REFUSING offsetless chunk sid={sid}: transport must frame offset")`)
   and `continue` WITHOUT writing (do not invent a position). No fallback
   ([[no-external-users-change-freely]]).

4. Remove the event-loop `record_range` block (currently lines ~14713-14716).
   Position assignment becomes just `let pos = off;`.

5. Move coverage recording INTO the `spawn_blocking` writer. Clone
   `Arc<Mutex<ranges>>` and `Arc<AtomicU64>` received into the closure. After
   `pwrite_at(&file, &data, pos)` returns `Ok(())`:
   ```
   let mut r = ranges.lock().unwrap();
   let (_delta, total) = record_range(&mut *r, pos, data_len);
   drop(r);
   received.store(total, Ordering::Relaxed);
   ```
   On `Err(e)`: do NOT record the range (leaves the gap), keep the loud
   `dlog!("[recv] pwrite_at FAILED ...")`. The MaybeComplete emission
   (`prev == 1 && end_seen`) stays after this, unchanged.

   Rationale: `record_range` total = sum of unique bytes. Because the ranges are
   disjoint and within [0,size), `total == size` ⟺ full contiguous coverage.
   With coverage written only after a successful write, `received == size`
   becomes a SOUND completion signal again (the DC counter bug was the only thing
   making it unsound).

### Part C: `cli/src/main.rs` verify_incoming (~15008): permanent contiguity guard

6. Add a helper near `record_range`:
   ```
   /// True iff the recorded ranges tile [0,size) with no gap (one interval).
   fn coverage_complete(ranges: &[(u64, u64)], size: u64) -> bool {
       if size == 0 { return true; }
       ranges.len() == 1 && ranges[0] == (0, size)
   }
   /// First uncovered byte position in [0,size), or None if complete.
   fn first_gap(ranges: &[(u64, u64)], size: u64) -> Option<u64> {
       let mut cursor = 0u64;
       for &(s, e) in ranges {
           if s > cursor { return Some(cursor); }
           cursor = cursor.max(e);
           if cursor >= size { return None; }
       }
       if cursor < size { Some(cursor) } else { None }
   }
   ```
7. In `verify_incoming`, before the hash (before line ~15041), after computing
   `recvd`:
   ```
   {
       let r = inc.ranges.lock().unwrap();
       if !coverage_complete(&r, inc.size) {
           let gap = first_gap(&r, inc.size);
           dlog!("[recv] INCOMPLETE at verify: {} ranges, received {}/{}, first gap at {:?}",
                 r.len(), recvd, inc.size, gap);
           drop(r);
           return protocol::decide_verify(recvd, inc.size, None); // re-fetch, never a false Match
       }
   }
   ```
   This is the permanent guard: any future regression that leaves a gap reports
   WHERE (chunk position), loudly, instead of a bare "digest mismatch".

## Out of scope (do not expand)

- Multi-stream QUIC resume-from-`received` when there is a mid-file gap is a
  separate latent issue (resume asks for one offset, can't fill an interior gap).
  This fix makes such a gap VISIBLE (Part C) rather than silent corruption;
  filling it is a follow-up only if the guard ever fires in a real rig.

## Verification (reviewer holds this)

- `cargo build --manifest-path cli/Cargo.toml` clean; test suite green.
- Re-run the corruption rig on BOTH transports (100MB), contiguity guard armed:
  expect 0% corruption on QUIC AND DataChannel, and the guard silent.
- Safety invariant unchanged throughout: never a false "delivered + verified".
