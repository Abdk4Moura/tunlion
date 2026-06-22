# Design: per-sid QUIC streams for HoL-free L2 multiplexing

Status: PROPOSED (supersedes the app-level credit approach on branch
`feat/l2-credit`, which validation showed cannot prevent head-of-line blocking).

## Problem

`DirectTransport` (cli/src/direct.rs) multiplexes EVERY logical L2 stream (each
`sid`) over ONE authenticated QUIC bidirectional stream, framed
`[1B kind][4B len][payload]` with data payloads further prefixed `[4B sid]`. A
single QUIC stream is an ordered byte stream, so if one logical stream's data is
not drained by the peer application, it blocks the shared stream and every other
logical stream stalls behind it. This is head-of-line (HoL) blocking across
filament's logical streams.

App-level credit (the `feat/l2-credit` attempt) cannot fix this: it throttles how
much each sid SENDS, but the bytes still serialize through one QUIC stream, and
the "consumed" signal (a `write_all` into the kernel send buffer) does not reflect
what the peer app actually read. Validation: a fast stream was still blocked by a
throttled slow stream.

## Goal

Each L2 `sid` rides its OWN QUIC stream. QUIC already gives every stream
independent flow control and no cross-stream HoL, so concurrent heavy streams
(multiple `forward`s, file + ssh) no longer block each other, and NO app-level
credit is needed.

Scope: `DirectTransport` only. The WebRTC `DataChannelTransport` has the same
single-channel HoL but a different fix (multiple SCTP data channels); out of scope
here, tracked separately.

## Wire protocol (NEW, versioned)

This is a BREAKING change to the direct-QUIC wire, so it MUST be negotiated.

- Negotiation: the `transport-offer` already carries a `v` field (currently 1).
  Bump to `v:2` to advertise per-sid-stream support, and have the auth handshake
  confirm it (or carry a capability byte in the auth frame). A connection uses
  per-sid streams ONLY if BOTH sides advertised v2; otherwise it falls back to the
  v1 single-stream framing. This keeps mixed old/new peers working.

- Control stream: the existing authenticated bidi stream (from `authenticate`)
  becomes the dedicated CONTROL stream. `send_control` keeps the v1 framing
  (`[KIND_CONTROL][len][json]`) on it. All `l2-open`/`l2-open-ack`/`l2-close`/
  PTY control still flow here, ordered, exactly as today.

- Data streams: one QUIC bidi stream per `sid`. On first `send_frame(sid, ..)` the
  sender opens a bidi stream and writes a small fixed header `[4B sid]` once, then
  length-framed payloads `[4B len][payload]` (length framing preserves the L2
  message boundaries, including the empty-payload FIN). FIN for the sid =
  `finish()` on that QUIC stream (clean), or `reset()` (RST). The peer's
  accept-loop reads the 4B sid header, registers the stream, and spawns a reader
  that turns each framed payload into `Ev::Chunk(sid, ..)` and the stream end into
  the empty-frame FIN.

## DirectTransport changes (cli/src/direct.rs)

- Struct: replace `send: Arc<Mutex<SendStream>>` with:
  - `control: Arc<Mutex<SendStream>>` (the auth stream, control only),
  - `data: Arc<Mutex<HashMap<u32, Arc<Mutex<SendStream>>>>>` (lazily-opened
    per-sid send streams),
  - keep `conn` (to `open_bi`), `last_activity`, `dead`, the test hooks.
- `send_control`: write framed control to `control`.
- `send_frame(sid, payload)`: get-or-open the sid's `SendStream` via
  `conn.open_bi()` (write the `[4B sid]` header on open), then write `[4B len]
  [payload]`. Empty payload -> write `[4B 0]` then `finish()` the stream (FIN).
  Update `last_activity`. Per-sid `open_bi` is cheap in QUIC.
- Accept loop: a task on `conn.accept_bi()`; for each new stream read `[4B sid]`,
  then loop reading `[4B len][payload]` -> `Ev::Chunk(sid, payload)`; on stream
  end emit the empty FIN. (The control stream is the FIRST stream and is handled
  by the existing reader; data streams are the subsequently-accepted ones.)
- Teardown: dropping/`reset`ing a sid's stream on `l2-close`; connection close
  tears all down (QUIC does this).

## Flow control / backpressure

QUIC per-stream receive windows ARE the per-stream backpressure: a stream whose
reader stalls stops advancing its own window, parking only that stream's
`write_all`. The connection-level window still bounds total memory. No app credit,
no `l2-credit` message, no `wnd` advertisement. (Delete the `feat/l2-credit`
machinery; keep `FILAMENT_L2_WINDOW` only if a connection-level tune is wanted.)

## Test hooks to preserve (currently in `send_frame`)

`freeze_after_bytes`, `frozen`, the `direct_unblock_after_ms` / `direct_flaky`
upgrade-standby hooks, and the `#28` idle-stamp (`last_activity`) must be
re-expressed for per-sid sends (freeze = stop writing + stop stamping on ALL sids;
flaky = carry N bytes then re-freeze). These gate-tests are the regression net for
the resilience ladder, so they must keep passing.

## Risks

- Breaking wire change -> the v2 negotiation + v1 fallback is mandatory and must be
  tested with a mixed old/new pair.
- Most-instrumented file in the tree; the test-hook re-expression is fiddly.
- Per-stream open cost is low but not zero; a connection that opens thousands of
  short streams pays more than the single-stream design. L2 stream counts are
  capped (`MAX_STREAMS_PER_LINK`), so this is bounded.

## Validation plan

- Unit: framing round-trip; sid-header parse; FIN via stream finish.
- Integration (the lab harness from #4): two concurrent streams over one link, one
  to a stalled sink and one to a fast sink; the fast MUST complete promptly while
  the slow is parked (the test that the credit approach FAILED). Plus a single
  big transfer for no-regression, and a mixed v1/v2 pair for fallback.

## Build sequence

1. Add v2 negotiation (offer `v:2` + auth capability) with v1 fallback, no
   behavior change yet.
2. Implement per-sid streams behind the v2 path; keep v1 intact.
3. Re-express the test hooks; keep all gates green.
4. Run the multi-stream HoL lab test; confirm fast-not-blocked-by-slow.
5. Remove the app-credit machinery once v2 is the default and proven.
