// The stateless REST surface of backend/app.py + backend/config.py, served by
// the Worker itself (no Durable Object request is spent on these).

import { envInt, originAllowed, type Env } from "./shared";
import { networkKey } from "./ip";

const DEFAULT_ICE = [{ urls: "stun:stun.l.google.com:19302" }];
const CF_TURN_RETRY = 60;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";

type Ice = { urls: string | string[]; username?: string; credential?: string };

// config._cf_turn_cache: one per isolate, shared until half the TTL passed.
const cfTurnCache: { servers: Ice[]; until: number } = { servers: [], until: 0 };

function b64(bytes: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

/** config._turn_servers(): coturn use-auth-secret REST credentials. */
async function turnServers(env: Env): Promise<Ice[]> {
  if (!(env.FIL_TURN_HOST && env.FIL_TURN_SECRET)) return [];
  const ttl = envInt(env.FIL_TURN_TTL, 3600);
  const username = String(Math.floor(Date.now() / 1000) + ttl); // username IS the expiry
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.FIL_TURN_SECRET),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const credential = b64(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username)));
  const urls = env.FIL_TURN_HOST.split(",").map((u) => u.trim()).filter(Boolean);
  return [{ urls, username, credential }];
}

/** config._cf_turn_entries(): TURN only, no STUN, no port 53. */
export function cfTurnEntries(iceServers: unknown[]): Ice[] {
  const out: Ice[] = [];
  for (const raw of iceServers) {
    const s = (raw || {}) as Record<string, unknown>;
    let urls = (s.urls || []) as string | string[];
    urls = typeof urls === "string" ? [urls] : urls;
    urls = urls.filter(
      (u) => typeof u === "string" && (u.startsWith("turn:") || u.startsWith("turns:")) && !u.includes(":53?") && !u.endsWith(":53"),
    );
    if (urls.length && s.username && s.credential) {
      out.push({ urls, username: s.username as string, credential: s.credential as string });
    }
  }
  return out;
}

async function cfTurnServers(env: Env): Promise<Ice[]> {
  if (!(env.FIL_CF_TURN_KEY_ID && env.FIL_CF_TURN_API_TOKEN)) return [];
  const now = Date.now() / 1000;
  if (now < cfTurnCache.until) return cfTurnCache.servers;
  const ttl = envInt(env.FIL_TURN_TTL, 3600);
  try {
    const resp = await fetch(
      `https://rtc.live.cloudflare.com/v1/turn/keys/${env.FIL_CF_TURN_KEY_ID}/credentials/generate-ice-servers`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.FIL_CF_TURN_API_TOKEN}`,
          "Content-Type": "application/json",
          "User-Agent": "tunlion-api",
        },
        body: JSON.stringify({ ttl }),
        signal: AbortSignal.timeout(3000),
      },
    );
    if (!resp.ok) throw new Error(`cf turn ${resp.status}`);
    const body = (await resp.json()) as { iceServers?: unknown[] };
    cfTurnCache.servers = cfTurnEntries(body.iceServers || []);
    cfTurnCache.until = now + ttl / 2;
  } catch {
    cfTurnCache.servers = [];
    cfTurnCache.until = now + CF_TURN_RETRY;
  }
  return cfTurnCache.servers;
}

async function iceServers(env: Env): Promise<unknown> {
  if (env.FIL_ICE_SERVERS) {
    try {
      return JSON.parse(env.FIL_ICE_SERVERS);
    } catch {}
  }
  const [turn, cf] = await Promise.all([turnServers(env), cfTurnServers(env)]);
  return [...DEFAULT_ICE, ...turn, ...cf];
}

export async function publicConfig(env: Env): Promise<Record<string, unknown>> {
  let firebase: unknown = null;
  if (env.FIL_FIREBASE_CONFIG) {
    try {
      firebase = JSON.parse(env.FIL_FIREBASE_CONFIG);
    } catch {}
  }
  const want = (env.FIL_SIGNALING || "socketio").toLowerCase();
  const signaling = want !== "firebase" || firebase ? want : "socketio";
  return {
    signaling,
    iceServers: await iceServers(env),
    firebase: signaling === "firebase" ? firebase : null,
    chunkSize: envInt(env.FIL_CHUNK_SIZE, 60 * 1024),
  };
}

async function sha256hex(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function corsFor(request: Request, env: Env): Record<string, string> {
  // flask-cors on /api/*: "*" answers "*"; an allowlist echoes a match.
  const allowed = (env.FIL_CORS_ORIGINS ?? "*").trim();
  if (allowed === "*") return { "access-control-allow-origin": "*" };
  const origin = request.headers.get("origin");
  if (origin && originAllowed(origin, allowed)) return { "access-control-allow-origin": origin, vary: "Origin" };
  return {};
}

function json(body: unknown, request: Request, env: Env, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...corsFor(request, env) },
  });
}

/** The REST endpoints this Worker answers itself; null for anything else. */
export async function restResponse(request: Request, env: Env, clientIp: string): Promise<Response | null> {
  const { pathname } = new URL(request.url);
  const isApi = pathname.startsWith("/api/");
  if (request.method === "OPTIONS" && isApi) {
    return new Response(null, {
      status: 200,
      headers: {
        ...corsFor(request, env),
        "access-control-allow-methods": "DELETE, GET, HEAD, OPTIONS, PATCH, POST, PUT",
        "access-control-allow-headers": request.headers.get("access-control-request-headers") || "",
      },
    });
  }
  const get = request.method === "GET" || request.method === "HEAD";
  if (get && pathname === "/api/config") return json(await publicConfig(env), request, env);
  if (get && pathname === "/api/whoami") return json({ ip: clientIp }, request, env);
  if (get && pathname === "/api/health") return json({ ok: true }, request, env);
  if (get && pathname === "/health") {
    return new Response(JSON.stringify({ ok: true, redis: "not-configured" }), {
      headers: { "content-type": "application/json" },
    });
  }
  if (get && pathname === "/api/room") {
    if (!env.FIL_SECRET) return json({ error: "FIL_SECRET is not set" }, request, env, 503);
    const [network, key] = networkKey(clientIp);
    const room = (await sha256hex(`${env.FIL_SECRET}:${key}`)).slice(0, 12);
    return json({ room, network, scope: "auto" }, request, env);
  }
  if (get && pathname === "/api/room/code") {
    const b = new Uint8Array(6);
    crypto.getRandomValues(b);
    // secrets.choice is uniform; 256 % 31 skews by under 1%, and the code is
    // a convenience room name, not a secret.
    const code = [...b].map((x) => CODE_ALPHABET[x % CODE_ALPHABET.length]).join("");
    return json({ code, room: `code-${code}`, scope: "code" }, request, env);
  }
  if (request.method === "POST" && pathname === "/api/telemetry") {
    const raw = (await request.text()).slice(0, 8192);
    try {
      let events = JSON.parse(raw);
      if (!Array.isArray(events)) events = [events];
      for (const e of events.slice(0, 50)) {
        if (e && typeof e === "object" && typeof e.ev === "string") {
          const { ev, ...rest } = e;
          const kv = Object.fromEntries(Object.entries(rest).slice(0, 12));
          console.log("TEL " + JSON.stringify({ ts: Date.now() / 1000, ev: "web:" + ev.slice(0, 40), ...kv }));
        }
      }
    } catch {}
    return json({ ok: true }, request, env);
  }
  return null;
}

/** Add the /api/* CORS headers to a hub response (session close). */
export function withApiCors(resp: Response, request: Request, env: Env): Response {
  const h = new Headers(resp.headers);
  for (const [k, v] of Object.entries(corsFor(request, env))) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}
