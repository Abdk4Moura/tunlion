// net/protocol/wire.js — the tunlion wire CODEC (PROTOCOL layer).
//
// Pure, dependency-free, browser-API-free: framing + control encode/decode +
// the message-type registry. This is the byte-level half of the tunlion
// protocol; it must stay identical to the CLI's framing (CONTRACT.md). Because
// it touches no browser globals it runs under plain `node` — see
// net/protocol/__tests__/wire.test.mjs (the characterization net for the
// consolidation rewrite).
//
// Frame layout (binary data-channel messages), identical to the CLI's
// (crates/filament-transport/src/net.rs, send_frame and the read loop):
//   [ 4-byte BE stream id (sid) ][ 8-byte BE offset ][ payload bytes... ]
// `offset` is where the payload starts in its stream: the file byte offset for
// a transfer (the CLI receiver places and checks bytes by it), the running
// byte count for a PTY stream. An empty payload (12 bytes total) is the
// stream-closed sentinel. The CLI drops anything shorter than 12 bytes, and
// the browser spoke the old 4-byte header until 2026-10: every byte the two
// exchanged was misread, so a browser could not receive a file from the CLI
// or type into a CLI shell.
// Control messages are JSON strings (sent as text, not binary frames).

/** Number of leading bytes carrying the stream id. */
export const SID_BYTES = 4
/** Bytes of the whole frame header: sid + 8-byte offset. */
export const HEADER_BYTES = 12

/**
 * Message-type registry — every `type` string that crosses the data channel as
 * a control message. Grouped by concern; values are the on-the-wire strings and
 * MUST NOT change (cross-impl contract).
 */
export const MSG = {
  // file transfer
  OFFER: 'file-offer',
  ACCEPT: 'file-accept',
  DECLINE: 'file-decline',
  END: 'file-end',
  DELIVERY_ACK: 'delivery-ack', // P4: receiver verified the whole file
  // declared absence (C21)
  BRB: 'brb',
  BACK: 'back',
  // known-device pairing (C12/C20/C27)
  PAIR_KEEP: 'pair-keep',
  PAIR_KEEP_ACK: 'pair-keep-ack',
  PAIR_PROOF: 'pair-proof',
  PAIR_PROOF_ACK: 'pair-proof-ack',
  // periodic link truth (C30)
  STATE: 'state',
  // capability advertisement
  CAPS: 'caps',
  // web-shell PTY over the channel
  PTY_OPEN: 'pty-open',
  PTY_OPEN_ACK: 'pty-open-ack',
  PTY_RESIZE: 'pty-resize',
  PTY_CLOSE: 'pty-close',
  // per-link logical stream teardown (shared with L2)
  L2_CLOSE: 'l2-close',
}

/**
 * Build a binary frame: [4-byte BE sid][8-byte BE offset][payload]. Returns a
 * Uint8Array suitable for RTCDataChannel.send.
 * @param {number} sid
 * @param {Uint8Array} payload
 * @param {number} [offset=0] where the payload starts in its stream
 * @returns {Uint8Array}
 */
export function frame(sid, payload, offset = 0) {
  const body = payload || new Uint8Array(0)
  const out = new Uint8Array(HEADER_BYTES + body.byteLength)
  const v = new DataView(out.buffer)
  v.setUint32(0, sid >>> 0)
  v.setBigUint64(SID_BYTES, BigInt(Math.max(0, Math.floor(offset))))
  out.set(body, HEADER_BYTES)
  return out
}

/**
 * Parse an inbound binary frame. Returns null for a runt (< 12 bytes), matching
 * the CLI's drop-silently behavior. `payload` is a fresh Uint8Array view.
 * @param {ArrayBuffer} buf
 * @returns {{sid: number, offset: number, payload: Uint8Array}|null}
 */
export function parseFrame(buf) {
  if (!buf || buf.byteLength < HEADER_BYTES) return null
  const v = new DataView(buf)
  const sid = v.getUint32(0)
  const offset = Number(v.getBigUint64(SID_BYTES))
  return { sid, offset, payload: new Uint8Array(buf.slice(HEADER_BYTES)) }
}

/** True if a parsed frame is the empty (stream-closed) sentinel. */
export function isCloseFrame(payload) {
  return !payload || payload.byteLength === 0
}

/**
 * Allocate a high-half stream id (top bit set). The CLI's sid router uses the
 * high range for L2/PTY streams and the low range for file transfer.
 * @param {number} n
 * @returns {number}
 */
export function highHalfSid(n) {
  return (0x80000000 | n) >>> 0
}

/** Encode a control message object to its wire string. */
export function encodeControl(obj) {
  return JSON.stringify(obj)
}

/** Decode a control message wire string back to an object. */
export function decodeControl(s) {
  return JSON.parse(s)
}

// The pty-open control frame. `resume_from` rides only on a reattach (a finite
// byte count), so a first open looks exactly as it always did. Pure.
export function ptyOpenMsg(sid, cols, rows, session, resumeFrom) {
  const msg = { type: 'pty-open', sid, cols, rows, session }
  if (Number.isFinite(resumeFrom) && resumeFrom >= 0) msg.resume_from = Math.floor(resumeFrom)
  return msg
}
