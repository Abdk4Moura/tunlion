import type { HealthState } from "./health";
import type { SignalHub } from "./hub";

export interface Env {
  HUB: DurableObjectNamespace<SignalHub>;
  HEALTH: DurableObjectNamespace<HealthState>;
  /** Optional: the published up/down flag. With it bound the router reads
   * KV (behind the Cache API) instead of calling HealthState, so the flag
   * costs no Durable Object time; see health.ts. */
  FLAGS?: KVNamespace;

  // Same names as the Python backend's environment (backend/config.py).
  FIL_SECRET?: string;
  FIL_CORS_ORIGINS?: string;
  FIL_SIGNALING?: string;
  FIL_FIREBASE_CONFIG?: string;
  FIL_ICE_SERVERS?: string;
  FIL_TURN_HOST?: string;
  FIL_TURN_SECRET?: string;
  FIL_TURN_TTL?: string;
  FIL_CF_TURN_KEY_ID?: string;
  FIL_CF_TURN_API_TOKEN?: string;
  FIL_CHUNK_SIZE?: string;
  FIL_PING_INTERVAL?: string;
  FIL_PING_TIMEOUT?: string;
  FIL_MAX_DECODE_PACKETS?: string;
  FIL_SESSION_CLAIM_LIMIT?: string;
  FIL_CLAIM_LIMIT?: string;
  FIL_PAIR_CREATE_LIMIT?: string;
  FIL_CLOSE_LIMIT?: string;
  FIL_FORCE_V1?: string;
  FIL_POLL_HOLD_S?: string;
  FIL_POLL_GRACE_S?: string;
  FIL_POLL_TICK_S?: string;
  FILAMENT_TEST_DROP_PUSH?: string;

  // Router.
  /** The primary backend (the VPS), e.g. https://vps-api.example.com. Unset:
   * this Worker IS the backend and the router is a pass-through to the hub. */
  ORIGIN_URL?: string;
  /** "auto" (default): origin while healthy, the hub when it is down.
   *  "cf": always the hub.  "origin": always the origin (failover off). */
  ROUTER_MODE?: string;
  HEALTH_FAIL_N?: string;
  HEALTH_RECOVER_N?: string;
  HEALTH_SUSPECT_EVERY_S?: string;
  HEALTH_DOWN_EVERY_S?: string;
  HEALTH_MIN_DOWN_S?: string;
  HEALTH_PROBE_TIMEOUT_S?: string;
}

/** signaling.origin_allowed(): no Origin is allowed (the bearer token or the
 * protocol still gates the operation), "*" allows all, else an exact list. */
export function originAllowed(origin: string | null, allowed: string | undefined): boolean {
  if (!origin) return true;
  // Unset is the Python default "*"; an empty string is an empty allowlist.
  const a = (allowed ?? "*").trim();
  if (a === "*") return true;
  return a
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
    .includes(origin);
}

export function envInt(v: string | undefined, d: number): number {
  const n = typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : d;
}
