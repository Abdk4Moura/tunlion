// Characterization tests for the filament wire codec. Plain Node ESM (no deps),
// run with: node frontend/src/net/protocol/__tests__/wire.test.mjs
// These pin the byte-level behavior the consolidation rewrite must preserve.
import {
  SID_BYTES, MSG, frame, parseFrame, isCloseFrame, highHalfSid,
  encodeControl, decodeControl,
} from '../wire.js'

let ok = true
const eq = (label, got, want) => {
  const g = JSON.stringify(got), w = JSON.stringify(want)
  if (g !== w) { console.log(`  !! ${label}: got ${g} want ${w}`); ok = false }
  else console.log(`  ${label}: OK`)
}

// --- framing: [4-byte BE sid][payload] ---
eq('SID_BYTES', SID_BYTES, 4)
eq('frame low sid bytes',
  Array.from(frame(0x01020304, new Uint8Array([0xaa, 0xbb]))),
  [0x01, 0x02, 0x03, 0x04, 0xaa, 0xbb])
// high-half sid must survive the >>>0 (no sign corruption)
eq('frame high-half sid bytes',
  Array.from(frame(highHalfSid(1), new Uint8Array([9]))),
  [0x80, 0x00, 0x00, 0x01, 9])
eq('frame empty payload is 4 bytes',
  Array.from(frame(0x80000001, new Uint8Array(0))),
  [0x80, 0x00, 0x00, 0x01])
eq('highHalfSid(1)', highHalfSid(1), 0x80000001)

// --- parseFrame: inverse of frame, runt → null ---
{
  const f = frame(0x80000005, new Uint8Array([1, 2, 3]))
  const p = parseFrame(f.buffer.slice(f.byteOffset, f.byteOffset + f.byteLength))
  eq('parseFrame sid', p && p.sid, 0x80000005)
  eq('parseFrame payload', p && Array.from(p.payload), [1, 2, 3])
}
eq('parseFrame runt (<4) → null', parseFrame(new Uint8Array([1, 2]).buffer), null)
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

console.log(ok ? 'WIRE TESTS PASS' : 'WIRE TESTS FAIL')
process.exit(ok ? 0 : 1)
