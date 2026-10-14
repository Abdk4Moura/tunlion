// Characterization tests for the tunlion wire codec. Plain Node ESM (no deps),
// run with: node frontend/src/net/protocol/__tests__/wire.test.mjs
// These pin the byte-level behavior the consolidation rewrite must preserve.
import {
  SID_BYTES, HEADER_BYTES, MSG, frame, parseFrame, isCloseFrame, highHalfSid,
  encodeControl, decodeControl, ptyOpenMsg,
} from '../wire.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// --- framing: [4-byte BE sid][8-byte BE offset][payload], the CLI's layout ---
eq('SID_BYTES', SID_BYTES, 4)
eq('HEADER_BYTES', HEADER_BYTES, 12)
eq('frame low sid bytes',
  Array.from(frame(0x01020304, new Uint8Array([0xaa, 0xbb]))),
  [0x01, 0x02, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xbb])
eq('frame carries the offset big-endian',
  Array.from(frame(7, new Uint8Array([1]), 0x0102030405)),
  [0, 0, 0, 7, 0, 0, 0, 0x01, 0x02, 0x03, 0x04, 0x05, 1])
// high-half sid must survive the >>>0 (no sign corruption)
eq('frame high-half sid bytes',
  Array.from(frame(highHalfSid(1), new Uint8Array([9]))),
  [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 9])
eq('frame empty payload is 12 bytes',
  Array.from(frame(0x80000001, new Uint8Array(0))),
  [0x80, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0])
eq('highHalfSid(1)', highHalfSid(1), 0x80000001)

// --- parseFrame: inverse of frame, runt -> null ---
{
  const f = frame(0x80000005, new Uint8Array([1, 2, 3]), 65536)
  const p = parseFrame(f.buffer.slice(f.byteOffset, f.byteOffset + f.byteLength))
  eq('parseFrame sid', p && p.sid, 0x80000005)
  eq('parseFrame offset', p && p.offset, 65536)
  eq('parseFrame payload', p && Array.from(p.payload), [1, 2, 3])
}
eq('parseFrame runt (<12) -> null', parseFrame(new Uint8Array([0, 0, 0, 1, 9]).buffer), null)
{
  // A frame exactly as the CLI's send_frame builds it: sid, offset, payload.
  const cli = new Uint8Array([0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0x10, 0, 0xde, 0xad])
  const p = parseFrame(cli.buffer)
  eq('parseFrame CLI frame sid', p && p.sid, 3)
  eq('parseFrame CLI frame offset', p && p.offset, 4096)
  eq('parseFrame CLI frame payload', p && Array.from(p.payload), [0xde, 0xad])
}
{
  const f = frame(0x00000007, new Uint8Array(0))
  const p = parseFrame(f.buffer)
  eq('parseFrame close-frame sid', p && p.sid, 7)
  eq('isCloseFrame on empty payload', isCloseFrame(p && p.payload), true)
  eq('isCloseFrame on non-empty', isCloseFrame(new Uint8Array([1])), false)
}

// --- control codec round-trip + message registry ---
eq('MSG.PTY_OPEN', MSG.PTY_OPEN, 'pty-open')
eq('MSG.DELIVERY_ACK', MSG.DELIVERY_ACK, 'delivery-ack')
eq('MSG.PAIR_PROOF', MSG.PAIR_PROOF, 'pair-proof')
{
  const msg = { type: MSG.PTY_OPEN, sid: 0x80000001, cols: 80, rows: 24, session: 'pty-abc' }
  eq('encode/decode control round-trip', decodeControl(encodeControl(msg)), msg)
}

// --- pty-open: resume_from rides only on a reattach (the CLI's field name) ---
eq('first open carries no resume_from',
  ptyOpenMsg(0x80000001, 80, 24, 's1'),
  { type: 'pty-open', sid: 0x80000001, cols: 80, rows: 24, session: 's1' })
eq('a reattach carries the byte count',
  ptyOpenMsg(0x80000002, 80, 24, 's1', 1234).resume_from, 1234)
eq('a reattach with nothing shown yet still says 0',
  ptyOpenMsg(0x80000002, 80, 24, 's1', 0).resume_from, 0)
eq('junk is never sent as a count',
  ['x', NaN, -1, Infinity, null].map((v) => 'resume_from' in ptyOpenMsg(1, 1, 1, 's', v)),
  [false, false, false, false, false])

console.log(ok ? 'WIRE TESTS PASS' : 'WIRE TESTS FAIL')
process.exit(ok ? 0 : 1)
