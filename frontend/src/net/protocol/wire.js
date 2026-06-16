// net/protocol/wire.js — the filament wire CODEC (PROTOCOL layer).
//
// Pure, dependency-free, browser-API-free: framing + control encode/decode +
// the message-type registry. This is the byte-level half of the filament
// protocol; it must stay identical to the CLI's framing (CONTRACT.md). Because
// it touches no browser globals it runs under plain `node` — see
// net/protocol/__tests__/wire.test.mjs (the characterization net for the
// consolidation rewrite).
//
// Frame layout (binary data-channel messages):
//   [ 4-byte big-endian stream id (sid) ][ payload bytes... ]
// An empty payload (4 bytes total) is the stream-closed sentinel.
// Control messages are JSON strings (sent as text, not binary frames).

/** Number of leading bytes carrying the stream id. */
export const SID_BYTES = 4

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
 * Build a binary frame: [4-byte BE sid][payload]. Returns a Uint8Array suitable
 * for RTCDataChannel.send.
 * @param {number} sid
 * @param {Uint8Array} payload
 * @returns {Uint8Array}
 */
export function frame(sid, payload) {
  const body = payload || new Uint8Array(0)
  const out = new Uint8Array(SID_BYTES + body.byteLength)
  new DataView(out.buffer).setUint32(0, sid >>> 0)
  out.set(body, SID_BYTES)
  return out
}

/**
 * Parse an inbound binary frame. Returns null for a runt (< 4 bytes), matching
 * the receiver's drop-silently behavior. `payload` is a fresh Uint8Array view.
 * @param {ArrayBuffer} buf
 * @returns {{sid: number, payload: Uint8Array}|null}
 */
export function parseFrame(buf) {
  if (!buf || buf.byteLength < SID_BYTES) return null
  const sid = new DataView(buf).getUint32(0)
  return { sid, payload: new Uint8Array(buf.slice(SID_BYTES)) }
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
