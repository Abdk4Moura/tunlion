// Every number and rule the Python relay and this port must agree on, in one
// place. Each constant names its Python twin. When backend/signaling.py,
// backend/app.py or backend/config.py changes one of these, change it here
// too; the conformance suite (backend/conformance) runs against both backends
// and is what catches a constant that drifted.

/** _MemRegistry.SESSION_TTL: token/session lifetime, sliding on use. */
export const SESSION_TTL = 24 * 3600;
/** _MemRegistry.SESSION_LIVE_WINDOW: last claim heartbeat that counts as live. */
export const SESSION_LIVE_WINDOW = 120;
/** _MemRegistry.RETIRED_TTL: per-token generation tombstone lifetime. */
export const RETIRED_TTL = 24 * 3600;
/** _MemRegistry.MAX_SESSIONS: token records (capacity, never uid ownership). */
export const MAX_SESSIONS = 50_000;
/** _MemRegistry.MAX_RETIRED_TOTAL: global tombstone cap. */
export const MAX_RETIRED_TOTAL = 200_000;
/** _MemRegistry.PRUNE_INTERVAL (#593): seconds between expired-record sweeps. */
export const PRUNE_INTERVAL = 30;
/** Seconds a refresh may drift from the stored session row before it is
 * written. 6 h turns an always-on daemon's 48 session writes/day into 4. The
 * persisted expiry is `last_write + SESSION_TTL`, and a write is never later
 * than the last claim, so the token can expire up to this much earlier after
 * an eviction, never later. */
export const SESSION_PERSIST_S = 6 * 3600;
/** Most expired rows one prune may delete. Pruning is claim-triggered, so this
 * bounds the session rows per pass, not total rows: the hub also deletes one
 * member and every subscription for each evicted sid, and a sid's subscription
 * count is not globally capped. 64 is a session-row bound, not a total-write
 * or CPU bound. */
export const SESSION_PRUNE_BATCH = 64;
/** Most rows one capacity scan may inspect when no expired row is found. */
export const CAPACITY_SCAN = 64;

function positiveInt(v: unknown, fallback: number): number {
  const s = typeof v === "string" && v.trim() !== "" ? v : typeof v === "number" ? String(v) : "";
  const parsed = parseInt(s, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/** Session refresh spacing. Zero is allowed (write every refresh); negative
 *  and non-finite values fall back, and values at or above SESSION_TTL are
 *  clamped to it because a session must not expire before its next write. */
export function sessionPersistFrom(env: Record<string, unknown>): number {
  const raw = env["FIL_SESSION_PERSIST_S"];
  if (raw === undefined || raw === null || String(raw).trim() === "") return SESSION_PERSIST_S;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) return SESSION_PERSIST_S;
  return Math.min(parsed, SESSION_TTL);
}

export function pruneBatchFrom(env: Record<string, unknown>): number {
  return positiveInt(env["FIL_SESSION_PRUNE_BATCH"], SESSION_PRUNE_BATCH);
}

export function capacityScanFrom(env: Record<string, unknown>): number {
  return positiveInt(env["FIL_CAPACITY_SCAN"], CAPACITY_SCAN);
}

/** register(): PAIR_TTL, unclaimed nameplates evaporate after 10 minutes. */
export const PAIR_TTL = 600;
/** register(): CHAN_RE / MAX_CHANNELS. */
export const CHAN_RE = /^[0-9a-f]{64}$/;
export const MAX_CHANNELS = 64;
/** _NAMEPLATE_RE: v2 nameplates are 3 to 5 digits. */
export const NAMEPLATE_RE = /^[0-9]{3,5}$/;
/** _ID_RE: uid/gen/token-shaped ids. */
export const ID_RE = /^[A-Za-z0-9._:-]{1,128}$/;
/** on_sync: roster digest cap (sorted by sid, then capped). */
export const SYNC_ROSTER_CAP = 32;

/** Limits, with the same env names and defaults as the Python relay. */
export interface Limits {
  sessionClaim: number; // FIL_SESSION_CLAIM_LIMIT (600/min)
  pairClaim: number; // FIL_CLAIM_LIMIT (5/min)
  pairCreate: number; // FIL_PAIR_CREATE_LIMIT (4x claim)
  sessionClose: number; // FIL_CLOSE_LIMIT (120/min)
  window: number; // 60 s for all of them
}

export function limitsFrom(env: Record<string, unknown>): Limits {
  const n = (k: string, d: number) => {
    const v = env[k];
    const parsed = typeof v === "string" && v.trim() !== "" ? parseInt(v, 10) : NaN;
    return Number.isFinite(parsed) ? parsed : d;
  };
  const pairClaim = n("FIL_CLAIM_LIMIT", 5);
  return {
    sessionClaim: n("FIL_SESSION_CLAIM_LIMIT", 600),
    pairClaim,
    pairCreate: n("FIL_PAIR_CREATE_LIMIT", pairClaim * 4),
    sessionClose: n("FIL_CLOSE_LIMIT", 120),
    window: 60,
  };
}

/** Population at or below which the hub sends one batch of pings per alarm
 * instead of spreading them over timers. See heartbeat.ts for why. */
export function pingSliceAt(env: Record<string, unknown>): number {
  const v = env["FIL_PING_SLICE_AT"];
  const parsed = typeof v === "string" && v.trim() !== "" ? parseInt(v, 10) : NaN;
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 40;
}

/** engine.io timing. Production compose sets 25 s / 60 s (FIL_PING_INTERVAL,
 * FIL_PING_TIMEOUT); the app defaults are 5 / 10. This port defaults to the
 * production values because a ping is also a billed inbound message here. */
export function pingFrom(env: Record<string, unknown>): { interval: number; timeout: number } {
  const n = (k: string, d: number) => {
    const v = env[k];
    const parsed = typeof v === "string" ? parseInt(v, 10) : NaN;
    return Number.isFinite(parsed) && parsed > 0 ? parsed : d;
  };
  return { interval: n("FIL_PING_INTERVAL", 25), timeout: n("FIL_PING_TIMEOUT", 60) };
}

/** engine.io Payload.max_decode_packets (FIL_MAX_DECODE_PACKETS, 250). */
export function maxDecodePackets(env: Record<string, unknown>): number {
  const v = env["FIL_MAX_DECODE_PACKETS"];
  const parsed = typeof v === "string" ? parseInt(v, 10) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 250;
}

/** engine.io maxPayload advertised in the OPEN packet (python-engineio default). */
export const MAX_PAYLOAD = 1_000_000;

/** Routing marks. The router sends a request carrying one of these to the
 * Durable Object and everything else to the origin. Python-minted ids are
 * base64url (no '.'), so a "cf." prefix can never collide with one. */
export const CF_EIO_PREFIX = "cf.";
export const CF_TOKEN_PREFIX = "cf.";

export function validId(v: unknown): v is string {
  return typeof v === "string" && ID_RE.test(v);
}
