// Heartbeat scheduling helpers, kept pure so the cost rules are testable
// without workerd.
//
// The hub has one alarm per ping interval. Inside that alarm it may either
// ping every socket at once, or spread the pings over the interval with
// in-memory timers. Spreading was added after the 2026-10-29 load test: at
// 4,000 devices one batch made every pong arrive in one round trip and the
// object closed the population (docs/cf-signaling.md, "Hub load test").
//
// Timers are not free. Cloudflare's Durable Object lifecycle rules say an
// object cannot hibernate while a setTimeout is pending, and duration is
// billed while the object is not eligible to hibernate. A 25 s interval
// spread over 25 one-second timers therefore keeps a single hub awake for the
// whole interval, even when every socket is idle. The load test's own data
// bounds the batch that is safe: 500 and 1,000 connected and stayed up with
// zero drops, 2,000 shed 8%, and 4,000 collapsed. Below a conservative cap we
// send one batch and let the object hibernate between alarms; above it we
// keep the bounded slices. Both paths are one alarm per interval.

/** Most slices any interval may use, whatever the interval or population. */
export const PING_SLICES_MAX = 25;

/** Default population at or below which pings are sent in one batch.
 *  40 is the largest population this branch measured end to end (40/40
 *  connected, 0 drops, 460 s idle). It is deliberately conservative: the
 *  2026-10-29 data only shows that one batch at 1,000 passed and at 2,000
 *  shed 8%, so nothing above 40 is claimed as safe until a bounded burst is
 *  run. FIL_PING_SLICE_AT can raise or lower it without a code change. */
export const PING_SLICE_AT = 40;

export interface PingPlan {
  /** Sockets per slice. */
  batch: number;
  /** Number of slices, 0 when there are no sockets. */
  slices: number;
  /** Delay between slices, 0 when there is only one. */
  delayMs: number;
}

/** How to ping `socketCount` sockets over one `intervalSec` alarm. */
export function pingPlan(
  socketCount: number,
  intervalSec: number,
  sliceAt = PING_SLICE_AT,
  maxSlices = PING_SLICES_MAX,
): PingPlan {
  if (socketCount <= 0) return { batch: 0, slices: 0, delayMs: 0 };
  if (socketCount <= Math.max(0, sliceAt)) return { batch: socketCount, slices: 1, delayMs: 0 };
  const slices = Math.max(1, Math.min(maxSlices, Math.floor(intervalSec)));
  return {
    batch: Math.ceil(socketCount / slices),
    slices,
    delayMs: slices > 1 ? (intervalSec * 1000) / slices : 0,
  };
}
