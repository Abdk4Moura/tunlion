// The router Worker on the API hostname.
//
//   ORIGIN_URL unset         -> this Worker is a complete signaling backend
//                               (REST here, sockets in the SignalHub object).
//   ORIGIN_URL set, "auto"   -> proxy to the origin (the VPS) while it is up;
//                               serve everything from Cloudflare while it is
//                               down (HealthState decides, with hysteresis).
//
// Stickiness. Both peers of a room must land on the same backend, because the
// two backends share no state. Three rules give that:
//   1. A NEW engine.io session (no sid) goes where the one global flag says.
//      Every colo reads the same flag (HealthState), cached FLAG_CACHE_MS.
//   2. A request for an EXISTING engine.io session goes to whichever backend
//      minted that sid: hub sids carry the "cf." prefix, Python's never do.
//      A polling session can never be split across backends mid-life.
//   3. On failback the hub closes every transport (after the flag cache has
//      expired everywhere), so its clients reconnect and follow rule 1 to
//      the origin. A straggler that slips onto the hub is swept off on the
//      next cron minute for ten minutes after the flip.
// When the origin is down, sockets on it are already gone, so rule 1 alone
// moves everyone.

import { restResponse, withApiCors } from "./config";
import { FLAG_CACHE_MS, FLAG_COLO_CACHE_S, FLAG_KEY, FLAG_KV_CACHE_S, HealthState } from "./health";
import { SignalHub } from "./hub";
import { CF_EIO_PREFIX, CF_TOKEN_PREFIX } from "./policy";
import type { Env } from "./shared";

export { HealthState, SignalHub };

type Backend = "origin" | "cf";

// Per-isolate cache of the flag (one DO read per isolate per FLAG_CACHE_MS).
let flag = { originUp: true, until: 0 };
let lastReport = 0;
const REPORT_EVERY_MS = 5_000;

/** Statuses that mean "the origin did not answer", not "the app said no".
 * 503 is deliberately absent: the Python app answers 503 for its SPA
 * fallback when the frontend build is absent, a red herring. */
const ORIGIN_DOWN = new Set([502, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530]);

/** Stateless endpoints the Worker can answer identically if the origin fails
 * mid-request (same FIL_SECRET, same TURN secrets). */
const LOCAL_FALLBACK = new Set(["/api/config", "/api/room", "/api/room/code", "/api/whoami", "/api/health", "/health"]);

function health(env: Env) {
  return env.HEALTH.get(env.HEALTH.idFromName("health"));
}

function hub(env: Env) {
  return env.HUB.get(env.HUB.idFromName("hub"));
}

const FLAG_URL = "https://flag.tunlion.internal/" + FLAG_KEY;

/** The one global flag, read cheaply: isolate memory, then (with KV bound)
 * this colo's Cache API, then KV; without KV, HealthState itself. A missing
 * KV value means "up": failover is opt-in by a flip, never by a cold cache. */
async function originUp(env: Env): Promise<boolean> {
  const now = Date.now();
  if (now < flag.until) return flag.originUp;
  try {
    let up: boolean;
    if (env.FLAGS) {
      const cache = caches.default;
      const hit = await cache.match(FLAG_URL);
      if (hit) {
        up = (await hit.text()) !== "0";
      } else {
        const v = await env.FLAGS.get(FLAG_KEY, { cacheTtl: FLAG_KV_CACHE_S });
        up = v !== "0";
        await cache.put(FLAG_URL, new Response(up ? "1" : "0", {
          headers: { "cache-control": `max-age=${FLAG_COLO_CACHE_S}` },
        }));
      }
    } else {
      up = (await health(env).state()).originUp;
    }
    flag = { originUp: up, until: now + FLAG_CACHE_MS };
  } catch {
    flag.until = now + 1_000; // keep the last answer; retry soon
  }
  return flag.originUp;
}

function report(env: Env, ctx: ExecutionContext) {
  const now = Date.now();
  if (now - lastReport < REPORT_EVERY_MS) return;
  lastReport = now;
  ctx.waitUntil(health(env).report().catch(() => {}));
}

function clientIp(request: Request): string {
  return request.headers.get("cf-connecting-ip") || "0.0.0.0";
}

function tag(resp: Response, backend: Backend): Response {
  if (resp.status === 101 || resp.webSocket) return resp;
  const h = new Headers(resp.headers);
  h.set("x-tunlion-backend", backend);
  return new Response(resp.body, { status: resp.status, statusText: resp.statusText, headers: h });
}

/** Serve from Cloudflare: REST in the Worker, sockets and close in the hub. */
async function serveCf(request: Request, env: Env, body?: string): Promise<Response> {
  const url = new URL(request.url);
  const ip = clientIp(request);
  const rest = await restResponse(request, env, ip);
  if (rest) return tag(rest, "cf");
  if (url.pathname.startsWith("/socket.io") || url.pathname === "/api/session/close") {
    const headers = new Headers(request.headers);
    headers.set("x-tunlion-client-ip", ip); // the hub trusts only this header
    const init: RequestInit = { method: request.method, headers };
    if (request.method !== "GET" && request.method !== "HEAD") init.body = body ?? request.body;
    const resp = await hub(env).fetch(new Request(request.url, init));
    if (url.pathname === "/api/session/close") return tag(withApiCors(resp, request, env), "cf");
    return tag(resp, "cf");
  }
  return tag(new Response("not found", { status: 404 }), "cf");
}

async function proxyOrigin(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  body?: string,
): Promise<Response | null> {
  const url = new URL(request.url);
  const target = env.ORIGIN_URL!.replace(/\/$/, "") + url.pathname + url.search;
  const init: RequestInit = { method: request.method, headers: request.headers, redirect: "manual" };
  if (request.method !== "GET" && request.method !== "HEAD") init.body = body ?? request.body;
  try {
    const resp = await fetch(target, init);
    if (ORIGIN_DOWN.has(resp.status)) {
      report(env, ctx);
      return null;
    }
    return tag(resp, "origin");
  } catch {
    report(env, ctx);
    return null;
  }
}

function originUnavailable(): Response {
  return tag(new Response("signaling origin unavailable", { status: 502 }), "origin");
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const mode = (env.ROUTER_MODE || "auto").toLowerCase();

    if (url.pathname === "/__router/status") {
      const st = env.ORIGIN_URL ? await health(env).state() : null;
      return Response.json({ mode, origin: !!env.ORIGIN_URL, health: st });
    }
    if (url.pathname.startsWith("/__hub/")) return new Response("not found", { status: 404 });

    if (!env.ORIGIN_URL || mode === "cf") return serveCf(request, env);

    // Requests that already belong to a backend follow it (rule 2).
    let pinned: Backend | null = null;
    let body: string | undefined;
    if (url.pathname.startsWith("/socket.io")) {
      const sid = url.searchParams.get("sid");
      if (sid) pinned = sid.startsWith(CF_EIO_PREFIX) ? "cf" : "origin";
    } else if (url.pathname === "/api/session/close" && request.method === "POST") {
      body = (await request.text()).slice(0, 4096);
      try {
        const tok = (JSON.parse(body) as { token?: unknown }).token;
        if (typeof tok === "string") pinned = tok.startsWith(CF_TOKEN_PREFIX) ? "cf" : "origin";
      } catch {}
    }
    if (mode === "origin" && pinned !== "cf") pinned = "origin";

    const backend: Backend = pinned ?? ((await originUp(env)) ? "origin" : "cf");
    if (backend === "cf") return serveCf(request, env, body);

    const resp = await proxyOrigin(request, env, ctx, body);
    if (resp) return resp;
    // The origin failed this request. Stateless REST can be answered here
    // identically; a socket stays on the origin until the flag flips (rule 1:
    // splitting a room on one failed request is worse than a short retry).
    if (LOCAL_FALLBACK.has(url.pathname) && (request.method === "GET" || request.method === "HEAD")) {
      return serveCf(request, env);
    }
    if (url.pathname === "/api/session/close") return tag(new Response(null, { status: 204 }), "origin");
    return originUnavailable();
  },

  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    if (!env.ORIGIN_URL) return;
    ctx.waitUntil(health(env).tick());
  },
} satisfies ExportedHandler<Env>;
