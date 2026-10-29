// SignalHub: the Durable Object twin of backend/signaling.py + the engine.io
// and socket.io servers that python-socketio provides on the Python side.
//
// ONE hub, deliberately. The Python relay is a single process (gunicorn -w 1,
// in-memory registry) and its semantics lean on that: a sid's room and its
// presence channels are independent (known-peer crosses rooms), `signal` may
// go to any sid that shares a room OR a channel, pairing nameplates and
// session tokens are global. Splitting by room or channel would need a
// gateway in front of every socket fanning out to several objects, which is
// both a new protocol surface and several billed requests per event. One
// object is the faithful port; docs/cf-signaling.md has the numbers for when
// it would need splitting (it is far past launch traffic).
//
// Layout of this file, top to bottom:
//   transport  engine.io v4 over websocket (hibernatable) and HTTP long-poll,
//              including the polling -> websocket upgrade
//   framing    socket.io v5 CONNECT / EVENT / ACK / DISCONNECT
//   relay      the event handlers, in the same order as register() and with
//              the same names, so a Python change maps to one function here

import { DurableObject } from "cloudflare:workers";
import {
  CF_EIO_PREFIX,
  CF_TOKEN_PREFIX,
  CHAN_RE,
  MAX_CHANNELS,
  MAX_PAYLOAD,
  NAMEPLATE_RE,
  PAIR_TTL,
  SYNC_ROSTER_CAP,
  limitsFrom,
  maxDecodePackets,
  pingFrom,
  validId,
} from "./policy";
import { MemLimiter, ipBucket } from "./ratelimit";
import { Registry, type PeerMeta } from "./registry";
import { originAllowed, type Env } from "./shared";

const SEP = "\x1e"; // engine.io v4 polling payload record separator
const SWEEP_EVERY_MS = 5 * 60 * 1000;
/** Websocket pings go out in at most this many slices per interval (one a second at 25 s). */
const PING_SLICES_MAX = 25;

/** What a hibernatable websocket carries across hibernation (< 2 KiB). */
interface WsAttachment {
  eid: string; // engine.io session id (router routing key)
  sid: string; // socket.io sid: the id every peer sees
  ns: boolean; // socket.io namespace "/" connected
  ip: string;
  probing?: boolean; // upgrade probe in progress (still a polling session)
  legacy?: [string, string]; // #592: token/gen minted for a tokenless CLI claim
}

interface PollSession {
  eid: string;
  sid: string;
  ns: boolean;
  ip: string;
  queue: string[];
  waiter: ((body: string | null) => void) | null; // null: answer 400, the session is gone
  waiterTimer: ReturnType<typeof setTimeout> | null;
  lastSeen: number;
  upgraded: boolean;
  legacy?: [string, string];
  // Polling liveness (signaling.PollWatch): set by the first GET carrying
  // the sid; pollSince is the start of the held GET or the end of the last.
  watched: boolean;
  pollSince: number;
  cycled: boolean; // NOOP already sent for the held GET
  upgrading: boolean; // a websocket probe is open (the client pauses polling)
  awayUntil: number; // ms; the page said it is hidden on purpose (#608 `away`)
}

interface Ctx {
  sid: string;
  ip: string;
}

function rid(bytes = 15): string {
  const b = new Uint8Array(bytes);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function tel(event: string, kv: Record<string, unknown> = {}) {
  // C24: one TEL line per lifecycle event (wrangler tail / Workers Logs).
  console.log("TEL " + JSON.stringify({ ts: Math.round(Date.now()) / 1000, ev: event, ...kv }));
}

export class SignalHub extends DurableObject<Env> {
  private reg: Registry;
  private polls = new Map<string, PollSession>(); // eid -> session
  private pollBySid = new Map<string, string>(); // sid -> eid
  private lastSeen = new Map<string, number>(); // eid -> ms of last inbound packet
  private ping: { interval: number; timeout: number };
  private dropPush: Set<string>;
  private sessionClaimLimiter: MemLimiter;
  private claimLimiter: MemLimiter;
  private createLimiter: MemLimiter;
  private closeLimiter: MemLimiter;
  private nextSweep = 0;
  private pingGen = 0;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.reg = new Registry(ctx.storage.sql, (sid) => this.alive(sid), CF_TOKEN_PREFIX);
    this.ping = pingFrom(env as unknown as Record<string, unknown>);
    const lim = limitsFrom(env as unknown as Record<string, unknown>);
    this.sessionClaimLimiter = new MemLimiter(lim.sessionClaim, lim.window);
    this.claimLimiter = new MemLimiter(lim.pairClaim, lim.window);
    this.createLimiter = new MemLimiter(lim.pairCreate, lim.window);
    this.closeLimiter = new MemLimiter(lim.sessionClose, lim.window);
    this.dropPush = new Set(
      String(env.FILAMENT_TEST_DROP_PUSH || "")
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean),
    );
  }

  // ===================================================================
  // HTTP entry: /socket.io/ (engine.io), /api/session/close, /__hub/*
  // ===================================================================

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const ip = request.headers.get("x-tunlion-client-ip") || "0.0.0.0";
    if (url.pathname === "/api/session/close" && request.method === "POST") {
      return this.sessionClose(request, ip);
    }
    if (url.pathname === "/__hub/drain" && request.method === "POST") {
      return Response.json({ drained: this.drain() });
    }
    if (url.pathname === "/__hub/stats") {
      return Response.json({ ...this.reg.stats(), ...this.connCounts() });
    }
    if (url.pathname.startsWith("/socket.io")) return this.engineio(request, url, ip);
    return new Response("not found", { status: 404 });
  }

  private engineio(request: Request, url: URL, ip: string): Response | Promise<Response> {
    const q = url.searchParams;
    const origin = request.headers.get("origin");
    const cors = this.corsHeaders(origin);
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          "access-control-allow-methods": "OPTIONS, GET, POST",
          "access-control-allow-headers": request.headers.get("access-control-request-headers") || "",
        },
      });
    }
    if (q.get("EIO") !== "4") {
      return this.badRequest("The client is using an unsupported version of the Socket.IO or Engine.IO protocols", cors);
    }
    if (!originAllowed(origin, this.env.FIL_CORS_ORIGINS)) {
      return this.badRequest("Not an accepted origin.", {});
    }
    const transport = q.get("transport");
    const eid = q.get("sid");
    const upgrade = (request.headers.get("upgrade") || "").toLowerCase() === "websocket";
    if (transport === "websocket") {
      if (!upgrade) return this.badRequest("Invalid websocket upgrade", cors);
      return eid ? this.wsUpgrade(eid) : this.wsOpen(ip);
    }
    if (transport !== "polling") return this.badRequest("Invalid transport", cors);
    if (!eid) {
      if (request.method !== "GET") return this.badRequest("Invalid session", cors);
      return this.pollOpen(ip, cors);
    }
    const sess = this.polls.get(eid);
    if (!sess || sess.upgraded) {
      return new Response(JSON.stringify({ code: 1, message: "Session ID unknown" }), {
        status: 400,
        headers: { ...cors, "content-type": "application/json" },
      });
    }
    sess.lastSeen = Date.now();
    this.lastSeen.set(eid, sess.lastSeen);
    if (request.method === "GET") return this.pollGet(sess, cors);
    if (request.method === "POST") return this.pollPost(sess, request, cors);
    return this.badRequest("Invalid method", cors);
  }

  private corsHeaders(origin: string | null): Record<string, string> {
    // python-engineio: an allowed Origin is echoed with credentials.
    if (!origin || !originAllowed(origin, this.env.FIL_CORS_ORIGINS)) return {};
    return { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" };
  }

  private badRequest(message: string, headers: Record<string, string>): Response {
    return new Response(JSON.stringify({ code: 3, message }), {
      status: 400,
      headers: { ...headers, "content-type": "application/json" },
    });
  }

  private openPacket(eid: string, upgrades: string[]): string {
    return (
      "0" +
      JSON.stringify({
        sid: eid,
        upgrades,
        pingTimeout: this.ping.timeout * 1000,
        pingInterval: this.ping.interval * 1000,
        maxPayload: MAX_PAYLOAD,
      })
    );
  }

  // ------------------------------------------------------------- websocket

  private wsOpen(ip: string): Response {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    const eid = CF_EIO_PREFIX + rid();
    const sid = rid();
    this.ctx.acceptWebSocket(server, ["e:" + eid, "s:" + sid]);
    const att: WsAttachment = { eid, sid, ns: false, ip };
    server.serializeAttachment(att);
    this.lastSeen.set(eid, Date.now());
    server.send(this.openPacket(eid, []));
    void this.ensureAlarm();
    return new Response(null, { status: 101, webSocket: client });
  }

  /** polling -> websocket upgrade for an existing polling session. */
  private wsUpgrade(eid: string): Response {
    const sess = this.polls.get(eid);
    if (!sess || sess.upgraded) {
      return new Response(JSON.stringify({ code: 1, message: "Session ID unknown" }), { status: 400 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.ctx.acceptWebSocket(server, ["e:" + eid, "s:" + sess.sid]);
    sess.upgrading = true;
    const att: WsAttachment = { eid, sid: sess.sid, ns: sess.ns, ip: sess.ip, probing: true };
    if (sess.legacy) att.legacy = sess.legacy;
    server.serializeAttachment(att);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer) {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    if (!att) return;
    this.lastSeen.set(att.eid, Date.now());
    if (typeof message !== "string") {
      // No binary attachments in this protocol (the Rust client refuses them
      // too); a binary frame is a protocol error.
      this.closeWs(ws, att, 1003, "binary unsupported");
      return;
    }
    if (att.probing) {
      const sess = this.polls.get(att.eid);
      if (message === "2probe") {
        ws.send("3probe");
        // Release the pending long-poll so the client can pause polling.
        if (sess) this.pollPush(sess, "6");
        return;
      }
      if (message === "5") {
        att.probing = false;
        if (sess) {
          att.ns = sess.ns;
          if (sess.legacy) att.legacy = sess.legacy;
          sess.upgraded = true;
          const queued = sess.queue.splice(0);
          this.endPoll(sess, "6");
          this.polls.delete(att.eid);
          this.pollBySid.delete(att.sid);
          ws.serializeAttachment(att);
          for (const p of queued) ws.send(p);
        } else {
          ws.serializeAttachment(att);
        }
        void this.ensureAlarm();
        return;
      }
      return;
    }
    this.onPacket({ sid: att.sid, ip: att.ip }, message, att.eid);
  }

  async webSocketClose(ws: WebSocket, code: number, _reason: string, _clean: boolean) {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    try {
      ws.close(code === 1005 || code === 1006 ? 1000 : code, "closing");
    } catch {}
    if (att) this.transportGone(att.sid, att.eid, !!att.probing);
  }

  async webSocketError(ws: WebSocket, _err: unknown) {
    const att = ws.deserializeAttachment() as WsAttachment | null;
    if (att) this.transportGone(att.sid, att.eid, !!att.probing);
  }

  private closeWs(ws: WebSocket, att: WsAttachment, code: number, reason: string) {
    try {
      ws.close(code, reason);
    } catch {}
    this.transportGone(att.sid, att.eid, !!att.probing);
  }

  /** The engine.io session ended (close, error, ping timeout). */
  private transportGone(sid: string, eid: string, probing: boolean) {
    if (probing) {
      // A failed upgrade probe leaves the polling session as it was.
      const p = this.polls.get(eid);
      if (p) p.upgrading = false;
      return;
    }
    this.lastSeen.delete(eid);
    if (this.isConnected(sid, eid)) return; // another transport still carries it
    this.onDisconnect(sid);
  }

  // --------------------------------------------------------------- polling

  private pollOpen(ip: string, cors: Record<string, string>): Response {
    const eid = CF_EIO_PREFIX + rid();
    const sid = rid();
    const sess: PollSession = {
      eid, sid, ns: false, ip, queue: [], waiter: null, waiterTimer: null,
      lastSeen: Date.now(), upgraded: false,
      watched: false, pollSince: 0, cycled: false, upgrading: false, awayUntil: 0,
    };
    this.polls.set(eid, sess);
    this.pollBySid.set(sid, eid);
    this.lastSeen.set(eid, sess.lastSeen);
    void this.ensureAlarm();
    return new Response(this.openPacket(eid, ["websocket"]), {
      headers: { ...cors, "content-type": "text/plain; charset=UTF-8" },
    });
  }

  private pollGet(sess: PollSession, cors: Record<string, string>): Response | Promise<Response> {
    const headers = { ...cors, "content-type": "text/plain; charset=UTF-8" };
    if (sess.waiter) {
      // python-engineio treats a second concurrent GET as a protocol error.
      return this.badRequest("Concurrent poll", cors);
    }
    sess.watched = true;
    sess.pollSince = Date.now();
    sess.cycled = false;
    this.armPollTick();
    if (sess.queue.length) return new Response(sess.queue.splice(0).join(SEP), { headers });
    return new Promise<Response>((resolve) => {
      sess.waiter = (body) =>
        resolve(
          body === null
            ? new Response(JSON.stringify({ code: 1, message: "Session ID unknown" }), {
                status: 400,
                headers: { ...cors, "content-type": "application/json" },
              })
            : new Response(body, { headers }),
        );
      // Never hold a poll past one ping interval: the ping tick normally
      // releases it first, this only covers a missed tick.
      sess.waiterTimer = setTimeout(() => this.pollPush(sess, "6"), (this.ping.interval + 5) * 1000);
    });
  }

  private async pollPost(sess: PollSession, request: Request, cors: Record<string, string>): Promise<Response> {
    const headers = { ...cors, "content-type": "text/html; charset=UTF-8" };
    const body = await request.text();
    if (body.length > MAX_PAYLOAD) return this.badRequest("Payload too large", cors);
    const packets = body.split(SEP);
    if (packets.length > maxDecodePackets(this.env as unknown as Record<string, unknown>)) {
      return this.badRequest("Too many packets in payload", cors);
    }
    for (const p of packets) {
      if (!this.polls.has(sess.eid)) break;
      if (p.startsWith("b")) continue; // binary (base64) packets: unsupported, ignored
      this.onPacket({ sid: sess.sid, ip: sess.ip }, p, sess.eid);
    }
    return new Response("OK", { headers });
  }

  private pollPush(sess: PollSession, packet: string) {
    sess.queue.push(packet);
    if (sess.waiter) {
      const w = sess.waiter;
      sess.waiter = null;
      if (sess.waiterTimer) clearTimeout(sess.waiterTimer);
      sess.waiterTimer = null;
      sess.pollSince = Date.now(); // the held GET ends here
      w(sess.queue.splice(0).join(SEP));
    }
  }

  private endPoll(sess: PollSession, last: string) {
    if (sess.waiter) this.pollPush(sess, last);
  }

  // ------------------------------------------------ polling liveness

  // Mirror of signaling.PollWatch + poll_check (fix/polling-liveness): a
  // long-polling client that dies silently leaves no GET behind, while a live
  // one always has one outstanding (engine.io-client re-polls from the last
  // poll's load callback). A GET held HOLD seconds is answered with a NOOP so
  // a live client re-polls at once; a socket with no GET for GRACE seconds is
  // closed as if its ping had timed out. FIL_POLL_GRACE_S=0 turns it off.
  private pollTimer: ReturnType<typeof setTimeout> | null = null;

  private pollCfg() {
    const f = (k: keyof Env, d: number) => {
      const n = parseFloat(String(this.env[k] ?? ""));
      return Number.isFinite(n) ? n : d;
    };
    return {
      hold: f("FIL_POLL_HOLD_S", 2),
      grace: f("FIL_POLL_GRACE_S", 7),
      tick: f("FIL_POLL_TICK_S", 1),
      away: f("FIL_POLL_AWAY_S", 180),
    };
  }

  private armPollTick() {
    const c = this.pollCfg();
    if (this.pollTimer || c.grace <= 0) return;
    this.pollTimer = setTimeout(() => {
      this.pollTimer = null;
      this.pollCheck();
      if (this.polls.size) this.armPollTick();
    }, c.tick * 1000);
  }

  /** poll_check(): one pass of the rule over every watched session. */
  private pollCheck() {
    const { hold, grace } = this.pollCfg();
    const now = Date.now();
    for (const sess of [...this.polls.values()]) {
      if (!sess.watched || sess.upgraded || sess.upgrading) continue;
      const age = (now - sess.pollSince) / 1000;
      if (sess.waiter) {
        if (age >= hold && !sess.cycled) {
          sess.cycled = true;
          this.pollPush(sess, "6");
        }
      } else if (age >= grace) {
        // Hidden on purpose (a file picker, a background tab): the OS may
        // freeze it, and a frozen page cannot poll. The ping timeout still
        // ends it if it never comes back.
        if (sess.awayUntil > now) continue;
        tel("poll-lapsed", { sid: sess.sid, eio: sess.eid.slice(0, 11), idle: Math.round(age * 10) / 10 });
        // No CLOSE packet to a client that is not there; the departure runs
        // as for a ping timeout (peer-left, known-peer-left).
        this.dropPoll(sess);
        this.transportGone(sess.sid, sess.eid, false);
      }
    }
  }

  // ------------------------------------------------------------ addressing

  private wsFor(sid: string): { ws: WebSocket; att: WsAttachment } | null {
    for (const ws of this.ctx.getWebSockets("s:" + sid)) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att && !att.probing) return { ws, att };
    }
    return null;
  }

  private pollFor(sid: string): PollSession | null {
    const eid = this.pollBySid.get(sid);
    const s = eid ? this.polls.get(eid) : undefined;
    return s && !s.upgraded ? s : null;
  }

  private isConnected(sid: string, exceptEid?: string): boolean {
    const p = this.pollFor(sid);
    if (p && p.eid !== exceptEid) return true;
    const w = this.wsFor(sid);
    return !!w && w.att.eid !== exceptEid;
  }

  /** Liveness ground truth (#10): this sid's engine.io transport is open and
   * its socket.io namespace is connected. Every roster filter goes through it. */
  private alive(sid: string): boolean {
    const p = this.pollFor(sid);
    if (p) return p.ns;
    const w = this.wsFor(sid);
    return !!w && w.att.ns;
  }

  private sendRaw(sid: string, packet: string) {
    const p = this.pollFor(sid);
    if (p) {
      this.pollPush(p, packet);
      return;
    }
    const w = this.wsFor(sid);
    if (w) {
      try {
        w.ws.send(packet);
      } catch {}
    }
  }

  /** emit(event, payload, to=sid). */
  private emitTo(sid: string, event: string, data: unknown) {
    this.sendRaw(sid, "42" + JSON.stringify([event, data]));
  }

  /** emit(event, payload, room=room, include_self=False). */
  private emitRoom(room: string, event: string, data: unknown, skip?: string) {
    const packet = "42" + JSON.stringify([event, data]);
    for (const s of this.reg.roomMembers(room)) if (s !== skip) this.sendRaw(s, packet);
  }

  /** _push(): emit, minus any event gate P is configured to swallow. */
  private push(sid: string, event: string, data: unknown) {
    if (this.dropPush.has(event)) return;
    this.emitTo(sid, event, data);
  }

  private pushRoom(room: string, event: string, data: unknown, skip?: string) {
    if (this.dropPush.has(event)) return;
    this.emitRoom(room, event, data, skip);
  }

  private setNs(sid: string, eid: string, ns: boolean) {
    const p = this.polls.get(eid);
    if (p) {
      p.ns = ns;
      return;
    }
    for (const ws of this.ctx.getWebSockets("e:" + eid)) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (att && att.sid === sid) {
        att.ns = ns;
        ws.serializeAttachment(att);
      }
    }
  }

  private getLegacy(sid: string): [string, string] | undefined {
    const p = this.pollFor(sid);
    if (p) return p.legacy;
    return this.wsFor(sid)?.att.legacy;
  }

  private setLegacy(sid: string, v: [string, string] | undefined) {
    const p = this.pollFor(sid);
    if (p) {
      p.legacy = v;
      return;
    }
    const w = this.wsFor(sid);
    if (w && (w.att.legacy?.[0] !== v?.[0] || w.att.legacy?.[1] !== v?.[1])) {
      if (v) w.att.legacy = v;
      else delete w.att.legacy;
      w.ws.serializeAttachment(w.att);
    }
  }

  // ------------------------------------------------------- ping and sweeps

  private async ensureAlarm() {
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null) await this.ctx.storage.setAlarm(Date.now() + this.ping.interval * 1000);
  }

  async alarm() {
    const now = Date.now();
    // Websocket pings are spread over the interval, one slice a second, not
    // sent to every socket at once. python-engineio pings each socket on its
    // own timer, so its pongs arrive spread out; one alarm pinging N sockets
    // brings N pongs back inside one round trip, and the hub load test
    // (docs/cf-signaling.md, "Hub load test") showed that burst closing the
    // whole population with 1013 at 4,000 devices. Each socket is still
    // checked and pinged once per interval. The slices run on in-memory
    // timers, so this is still one alarm (one billed request) per interval.
    const sockets = this.ctx.getWebSockets();
    const slices = Math.max(1, Math.min(PING_SLICES_MAX, Math.floor(this.ping.interval)));
    const per = Math.ceil(sockets.length / slices);
    const gen = ++this.pingGen;
    this.pingSlice(sockets, 0, per);
    for (let k = 1; k < slices && k * per < sockets.length; k++) {
      setTimeout(() => {
        if (gen === this.pingGen) this.pingSlice(sockets, k * per, per);
      }, (k * this.ping.interval * 1000) / slices);
    }
    const deadAfter = (this.ping.interval + this.ping.timeout) * 1000;
    for (const sess of [...this.polls.values()]) {
      if (now - sess.lastSeen > deadAfter && !sess.waiter) {
        tel("ping-timeout", { sid: sess.sid });
        this.dropPoll(sess);
        this.transportGone(sess.sid, sess.eid, false);
        continue;
      }
      this.pollPush(sess, "2");
    }
    if (now >= this.nextSweep) {
      this.nextSweep = now + SWEEP_EVERY_MS;
      this.sweepDead();
    }
    if (sockets.length || this.polls.size) {
      await this.ctx.storage.setAlarm(Date.now() + this.ping.interval * 1000);
    }
  }

  /** Ping-timeout check and ping for sockets[from, from + n). */
  private pingSlice(sockets: WebSocket[], from: number, n: number) {
    const now = Date.now();
    const deadAfter = (this.ping.interval + this.ping.timeout) * 1000;
    for (const ws of sockets.slice(from, from + n)) {
      if (ws.readyState !== WebSocket.OPEN) continue; // closed since the alarm listed it
      const att = ws.deserializeAttachment() as WsAttachment | null;
      if (!att) continue;
      let seen = this.lastSeen.get(att.eid);
      if (seen === undefined) {
        // Woke from hibernation: the heap (and this map) is new. Grant one
        // full window rather than declaring every socket dead.
        seen = now;
        this.lastSeen.set(att.eid, now);
      }
      if (now - seen > deadAfter) {
        tel("ping-timeout", { sid: att.sid });
        this.closeWs(ws, att, 1001, "ping timeout");
        continue;
      }
      if (!att.probing) {
        try {
          ws.send("2");
        } catch {}
      }
    }
  }

  /** End a polling session the way a server restart does: a held GET (and
   * every later one) gets 400 "Session ID unknown", which every client
   * treats as a transport error and reconnects from. An engine.io CLOSE
   * packet would not do: python-socketio takes a server CLOSE as final. */
  private dropPoll(sess: PollSession) {
    if (sess.waiterTimer) clearTimeout(sess.waiterTimer);
    if (sess.waiter) {
      const w = sess.waiter;
      sess.waiter = null;
      w(null);
    }
    this.polls.delete(sess.eid);
    if (this.pollBySid.get(sess.sid) === sess.eid) this.pollBySid.delete(sess.sid);
    this.lastSeen.delete(sess.eid);
  }

  /** Rows whose transport vanished without a close event (a polling session
   * lost with an evicted heap): run the departure they missed. */
  private sweepDead() {
    for (const sid of this.reg.allMemberSids()) if (!this.alive(sid)) this.doLeave(sid);
    for (const sid of this.reg.allSubscribedSids()) if (!this.alive(sid)) this.channelGoodbye(sid);
    this.reg.sweepPairs();
  }

  private connCounts() {
    return { websockets: this.ctx.getWebSockets().length, polling: this.polls.size };
  }

  /** Failback: close every transport WITHOUT a socket.io DISCONNECT, so each
   * client sees "transport close" and reconnects (to the origin, now that the
   * router has flipped). A socket.io 41 would stop socket.io-client from
   * reconnecting at all. Quiet: everyone is leaving, so no peer-left storm. */
  private drain(): number {
    let n = 0;
    for (const ws of this.ctx.getWebSockets()) {
      const att = ws.deserializeAttachment() as WsAttachment | null;
      try {
        ws.close(1012, "failback");
      } catch {}
      if (att) this.quietLeave(att.sid);
      n += 1;
    }
    for (const sess of [...this.polls.values()]) {
      this.dropPoll(sess);
      this.quietLeave(sess.sid);
      n += 1;
    }
    tel("drain", { n });
    return n;
  }

  private quietLeave(sid: string) {
    this.reg.unsubscribeAll(sid);
    this.reg.remove(sid);
  }

  // ===================================================================
  // socket.io framing
  // ===================================================================

  private onPacket(ctx: Ctx, packet: string, eid: string) {
    const t = packet[0];
    if (t === "3" || t === "6") return; // pong / noop: lastSeen already updated
    if (t === "2") {
      this.sendRaw(ctx.sid, "3" + packet.slice(1)); // a v3-style client ping
      return;
    }
    if (t === "1") {
      // engine.io close from the client
      const p = this.polls.get(eid);
      if (p) this.dropPoll(p);
      for (const ws of this.ctx.getWebSockets("e:" + eid)) {
        try {
          ws.close(1000, "client close");
        } catch {}
      }
      this.transportGone(ctx.sid, eid, false);
      return;
    }
    if (t !== "4") return;
    this.onSocketIo(ctx, packet.slice(1), eid);
  }

  private onSocketIo(ctx: Ctx, body: string, eid: string) {
    const t = body[0];
    let rest = body.slice(1);
    // Only the default namespace exists. "/nsp," prefixes are refused.
    if (rest.startsWith("/")) {
      const comma = rest.indexOf(",");
      const nsp = comma === -1 ? rest : rest.slice(0, comma);
      if (nsp !== "/") {
        if (t === "0") this.sendRaw(ctx.sid, `44${nsp},{"message":"Invalid namespace"}`);
        return;
      }
      rest = comma === -1 ? "" : rest.slice(comma + 1);
    }
    if (t === "0") {
      this.setNs(ctx.sid, eid, true);
      this.sendRaw(ctx.sid, "40" + JSON.stringify({ sid: ctx.sid }));
      this.onConnect(ctx);
      return;
    }
    if (t === "1") {
      this.setNs(ctx.sid, eid, false);
      this.onDisconnect(ctx.sid);
      return;
    }
    if (t !== "2") return; // acks from the client and binary events: unused
    if (!this.alive(ctx.sid)) return; // an event before CONNECT
    const bracket = rest.indexOf("[");
    if (bracket === -1) return;
    const idText = rest.slice(0, bracket);
    const ackId = idText === "" ? null : /^\d+$/.test(idText) ? idText : undefined;
    if (ackId === undefined) return;
    let args: unknown;
    try {
      args = JSON.parse(rest.slice(bracket));
    } catch {
      return;
    }
    if (!Array.isArray(args) || typeof args[0] !== "string") return;
    const [event, data] = args as [string, unknown];
    let result: unknown;
    try {
      result = this.dispatch(ctx, event, data);
    } catch (e) {
      // python-socketio logs a handler exception and sends nothing more.
      console.log("handler error", event, String(e));
      return;
    }
    if (ackId !== null) {
      this.sendRaw(ctx.sid, "43" + ackId + JSON.stringify(result === undefined ? [] : [result]));
    }
  }

  private dispatch(ctx: Ctx, event: string, data: unknown): unknown {
    switch (event) {
      case "join":
        return this.onJoin(ctx, data);
      case "pair-create":
        return this.onPairCreate(ctx, data);
      case "pair-claim":
        return this.onPairClaim(ctx, data);
      case "subscribe":
        return this.onSubscribe(ctx, data);
      case "channel-goodbye":
        return this.onChannelGoodbye(ctx, data);
      case "sync":
        return this.onSync(ctx, data);
      case "signal":
        return this.onSignal(ctx, data);
      case "leave":
        return this.doLeave(ctx.sid);
      case "away":
        return this.onAway(ctx, data);
      default:
        return undefined;
    }
  }

  // ===================================================================
  // relay: register() in backend/signaling.py, same names, same order
  // ===================================================================

  private onConnect(ctx: Ctx) {
    tel("connect", { sid: ctx.sid });
  }

  private sessionClaimAllowed(ctx: Ctx, refreshOnly: boolean): boolean {
    const keys = [`sid:${ctx.sid}`];
    if (!refreshOnly) keys.push("ip:" + ipBucket(ctx.ip));
    return this.sessionClaimLimiter.allow(keys);
  }

  /** _claim_session: returns [ok, ownerToken, effectiveGen]. */
  private claimSession(
    ctx: Ctx,
    uid: unknown,
    gen: unknown,
    token: unknown,
    name: string,
    room: string | null = null,
  ): [boolean, string | null, string | null] {
    const sid = ctx.sid;
    const fail: [boolean, null, null] = [false, null, null];
    if (!validId(uid)) {
      tel("session-invalid", { sid });
      this.emitTo(sid, "session-superseded", { reason: "invalid" });
      return fail;
    }
    const legacy = (token === null || token === undefined) && (gen === null || gen === undefined);
    const reuse = legacy ? this.getLegacy(sid) : undefined;
    if (reuse && this.reg.holdsSession(reuse[0], reuse[1], sid)) {
      // #592: the tokenless, generation-less CLI on the SAME socket continues
      // the session the relay already gave it instead of minting one per sync.
      [token, gen] = reuse;
    } else if (gen === null || gen === undefined) {
      if (reuse) this.setLegacy(sid, undefined);
      gen = rid(8); // secrets.token_urlsafe(8): server-assigned generation
    } else if (!validId(gen)) {
      tel("session-invalid", { sid });
      this.emitTo(sid, "session-superseded", { reason: "invalid" });
      return fail;
    }
    if (token !== null && token !== undefined && (typeof token !== "string" || token.length > 512)) {
      tel("session-invalid", { sid });
      this.emitTo(sid, "session-superseded", { reason: "invalid" });
      return fail;
    }
    const refreshOnly =
      room !== null && this.reg.roomOf(sid) === room && this.reg.holdsSession(token, gen, sid);
    if (!this.sessionClaimAllowed(ctx, refreshOnly)) {
      tel("session-claim-rate-limited", { sid, uid });
      this.emitTo(sid, "session-superseded", { reason: "rate-limited" });
      return fail;
    }
    const verdict = this.reg.claimSession(token as string | null | undefined, gen, sid, uid, name);
    const status = verdict.status;
    const ownerToken = verdict.token;
    const effectiveGen = verdict.gen || (gen as string);
    if (status === "retired" || status === "denied" || status === "capacity") {
      const reason = { retired: "stale-generation", denied: "invalid", capacity: "capacity" }[status];
      tel(status === "retired" ? "session-retired" : "session-denied", { sid, uid, status });
      this.emitTo(sid, "session-superseded", { reason });
      return fail;
    }
    if (legacy && ownerToken) this.setLegacy(sid, [ownerToken, effectiveGen]);
    for (const evicted of verdict.evicted) {
      if (!evicted || evicted === sid) continue;
      tel("session-evicted", { sid: evicted, uid });
      this.emitTo(evicted, "session-superseded", { reason: "session-evicted" });
      this.setLegacy(evicted, undefined);
      this.channelGoodbye(evicted);
      this.leaveRoom(evicted);
    }
    const prev = verdict.prev;
    if (prev && prev !== sid) {
      tel("session-supersede", { old: prev, new: sid, uid });
      this.emitTo(prev, "session-superseded", { reason: "newer-generation" });
      this.setLegacy(prev, undefined);
      this.channelGoodbye(prev);
      this.leaveRoom(prev);
    }
    return [true, ownerToken, effectiveGen];
  }

  private livePeers(room: string, exclude: string): PeerMeta[] {
    const { peers, dead } = this.reg.peersIn(room, exclude);
    // A row whose transport is gone missed its departure: run it now so the
    // room hears peer-left (the Python disconnect handler does the same).
    for (const d of dead) this.doLeave(d);
    return peers;
  }

  /** _do_join: leave any prior ROOM only (channels survive), join, announce. */
  private doJoin(ctx: Ctx, room: string, name: string, uid: unknown, gen: string | null, token: string | null) {
    const sid = ctx.sid;
    this.leaveRoom(sid);
    this.reg.add(sid, room, name, (uid as string) ?? null, gen);
    const peers = this.livePeers(room, sid);
    tel("join", { sid, uid, room, peers: peers.length });
    const welcome: Record<string, unknown> = { id: sid, peers, gen };
    if (token) welcome.token = token;
    this.push(sid, "welcome", welcome);
    this.pushRoom(room, "peer-joined", { id: sid, name, uid }, sid);
  }

  private onJoin(ctx: Ctx, raw: unknown) {
    const sid = ctx.sid;
    const data = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
    const room = data.room;
    const rawName = data.name;
    if (typeof rawName !== "string" || !rawName || rawName.length > 128) {
      this.emitTo(sid, "session-superseded", { reason: "invalid" });
      return;
    }
    const name = rawName;
    const uid = data.uid;
    const gen = data.gen;
    const token = data.token;
    if (!room) return;
    const roomKey = String(room);
    const [ok, ownerToken, effectiveGen] = this.claimSession(ctx, uid, gen, token, name);
    if (!ok) return;
    const me = this.reg.meta(sid);
    if (this.reg.roomOf(sid) === roomKey && me && me.name === name && me.uid === uid) {
      // #594: a duplicate join is a roster refresh to the joiner only.
      const peers = this.livePeers(roomKey, sid);
      tel("join-dup", { sid, uid, room: roomKey, peers: peers.length });
      const welcome: Record<string, unknown> = { id: sid, peers, gen: effectiveGen };
      if (ownerToken) welcome.token = ownerToken;
      this.push(sid, "welcome", welcome);
      return;
    }
    this.doJoin(ctx, roomKey, name, uid, effectiveGen, ownerToken);
  }

  private normCode(raw: unknown): string {
    if (typeof raw !== "string") return "";
    return raw.trim().toLowerCase().replace(/\s+/g, "-").replace(/[^a-z0-9-]/g, "").slice(0, 48);
  }

  private limitKeys(ctx: Ctx): string[] {
    return [`sid:${ctx.sid}`, "ip:" + ipBucket(ctx.ip)];
  }

  private onPairCreate(ctx: Ctx, raw: unknown) {
    const sid = ctx.sid;
    if (!this.createLimiter.allow(this.limitKeys(ctx))) {
      this.emitTo(sid, "pair-error", { error: "slow-down" });
      return;
    }
    const data = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    const forceV1 = this.env.FIL_FORCE_V1 === "1";
    if (data.v !== 2 || forceV1) {
      if (forceV1) {
        this.emitTo(sid, "pair-code", { code: "legacy-downgrade-test-000", ttl: 600 });
        return;
      }
      this.emitTo(sid, "pair-error", {
        error: "update-required",
        why: "this server requires v2 (PAKE handshake); update your client",
      });
      return;
    }
    const nameplate = this.normCode(data.nameplate);
    if (!NAMEPLATE_RE.test(nameplate)) {
      this.emitTo(sid, "pair-error", { error: "bad-nameplate" });
      return;
    }
    if (this.reg.pairCreate(nameplate, sid, PAIR_TTL)) {
      tel("pair-create", { sid, nameplate, v: 2, in_room: !!this.reg.roomOf(sid) });
      this.emitTo(sid, "pair-ok", { nameplate, ttl: PAIR_TTL, v: 2 });
      return;
    }
    this.emitTo(sid, "pair-error", { error: "taken" });
  }

  private onPairClaim(ctx: Ctx, raw: unknown) {
    const sid = ctx.sid;
    if (!this.claimLimiter.allow(this.limitKeys(ctx))) {
      this.emitTo(sid, "pair-error", { error: "slow-down" });
      return;
    }
    const data = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    if (data.v !== 2) {
      this.emitTo(sid, "pair-error", {
        error: "update-required",
        why: "this server requires v2 (PAKE handshake); update your client",
      });
      return;
    }
    const code = this.normCode(data.nameplate);
    if (!NAMEPLATE_RE.test(code)) {
      this.emitTo(sid, "pair-error", { error: "invalid", why: "bad-nameplate" });
      return;
    }
    const [existed, peekCreator, creatorAlive] = this.reg.peekPair(code);
    const creator = this.reg.pairClaim(code);
    const room = creator ? this.reg.roomOf(creator) : null;
    if (!room) {
      tel("pair-claim-fail", { sid, code, existed, creator: peekCreator, creator_alive: creatorAlive });
      const why = existed && peekCreator ? "sender-gone" : "unknown";
      this.emitTo(sid, "pair-error", { error: "invalid", why });
      return;
    }
    tel("pair-claim-ok", { sid, code, creator, room });
    this.emitTo(creator as string, "pair-used", { code });
    this.emitTo(sid, "pair-matched", { room });
  }

  /** _do_subscribe: returns [acceptedCount, roster]. */
  private doSubscribe(ctx: Ctx, rawChannels: unknown): [number, Array<PeerMeta & { channel: string }>] {
    const list = Array.isArray(rawChannels) ? rawChannels.slice(0, MAX_CHANNELS) : [];
    const chans = list.filter((c): c is string => typeof c === "string" && CHAN_RE.test(c));
    if (!chans.length) return [0, []];
    const me = this.reg.meta(ctx.sid);
    const roster: Array<PeerMeta & { channel: string }> = [];
    for (const [ch, others] of this.reg.subscribe(ctx.sid, chans)) {
      for (const other of others) {
        const om = this.reg.meta(other);
        if (om) {
          this.emitTo(ctx.sid, "known-peer", { ...om, channel: ch });
          roster.push({ ...om, channel: ch });
        }
        if (me) this.emitTo(other, "known-peer", { ...me, channel: ch });
      }
    }
    return [chans.length, roster];
  }

  private onSubscribe(ctx: Ctx, raw: unknown) {
    const data = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    const [n, roster] = this.doSubscribe(ctx, data.channels);
    return { ok: n > 0, n, peers: roster };
  }

  private onChannelGoodbye(ctx: Ctx, raw: unknown) {
    const data = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    const chans = Array.isArray(data.channels) ? data.channels : [];
    for (const [ch, others] of this.reg.unsubscribe(ctx.sid, chans)) {
      const om = this.reg.meta(ctx.sid);
      if (om) for (const other of others) this.emitTo(other, "known-peer-left", { ...om, channel: ch });
    }
    return { ok: true, n: chans.length };
  }

  private onSync(ctx: Ctx, raw: unknown) {
    const sid = ctx.sid;
    const data = raw && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
    const room = data.room;
    const rawName = data.name;
    const bad = { v: 1, ok: false, room: null, channels: 0, lease: false };
    if (typeof rawName !== "string" || !rawName || rawName.length > 128) return bad;
    const name = rawName;
    const uid = data.uid;
    const gen = data.gen;
    const token = data.token;
    if (!room) return bad;
    const roomKey = String(room);
    const [ok, ownerToken, effectiveGen] = this.claimSession(ctx, uid, gen, token, name, roomKey);
    if (!ok) return { v: 1, ok: false, superseded: true, room: null, channels: 0, lease: false };

    const roomChanged = this.reg.roomOf(sid) !== roomKey;
    if (roomChanged) {
      this.doJoin(ctx, roomKey, name, uid, effectiveGen, ownerToken);
    } else {
      const me = this.reg.meta(sid);
      if (me && me.name !== name) {
        const updated = this.reg.rename(sid, name);
        if (updated) {
          this.emitRoom(roomKey, "peer-updated", updated, sid);
          tel("rename", { sid, uid });
        }
      }
    }
    const [n, chanPeers] = this.doSubscribe(ctx, data.channels);
    tel("sync", { sid, room_changed: roomChanged, channels: n });
    const peers = this.livePeers(roomKey, sid)
      .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
      .slice(0, SYNC_ROSTER_CAP);
    const digest: Record<string, unknown> = {
      v: 1, ok: true, room: roomKey, channels: n, lease: true,
      peers, channel_peers: chanPeers, gen: effectiveGen,
    };
    if (ownerToken) digest.token = ownerToken;
    this.emitTo(sid, "synced", digest);
    return digest;
  }

  private onSignal(ctx: Ctx, raw: unknown) {
    const sid = ctx.sid;
    const data = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
    const to = data.to;
    const payload = data.data;
    const myRoom = this.reg.roomOf(sid);
    if (!to || typeof to !== "string" || !myRoom) return;
    if (this.reg.roomOf(to) !== myRoom && !this.reg.shareChannel(sid, to)) {
      tel("signal-refused", { sid, to });
      return;
    }
    this.emitTo(to, "signal", { from: sid, data: payload ?? null });
  }

  /** on_away (#608): the page behind THIS socket says it is out of sight.
   * Only the session the event arrived on, and only one that has polled;
   * a websocket session accepts and ignores it. on===true lengthens this
   * session's grace to FIL_POLL_AWAY_S; anything else restores it. */
  private onAway(ctx: Ctx, raw: unknown) {
    const p = this.pollFor(ctx.sid);
    if (!p || !p.watched) return;
    const on = !!raw && typeof raw === "object" && (raw as Record<string, unknown>).on === true;
    const { away } = this.pollCfg();
    p.awayUntil = on && away > 0 ? Date.now() + away * 1000 : 0;
    tel("poll-away", { sid: ctx.sid, on });
  }

  private onDisconnect(sid: string) {
    tel("disconnect", { sid });
    this.doLeave(sid);
  }

  private channelGoodbye(sid: string) {
    for (const [ch, others] of this.reg.unsubscribeAll(sid)) {
      for (const other of others) this.emitTo(other, "known-peer-left", { id: sid, channel: ch });
    }
  }

  /** Full departure (leave event, disconnect): channels and room. */
  private doLeave(sid: string) {
    this.setLegacy(sid, undefined);
    this.channelGoodbye(sid);
    this.leaveRoom(sid);
  }

  private leaveRoom(sid: string) {
    const room = this.reg.remove(sid);
    if (!room) return;
    this.emitRoom(room, "peer-left", { id: sid }, sid);
  }

  // ---------------------------------------------------- pagehide beacon

  /** POST /api/session/close: always 204, so it is never a token oracle. */
  private async sessionClose(request: Request, ip: string): Promise<Response> {
    const empty = () => new Response(null, { status: 204 });
    if (!originAllowed(request.headers.get("origin"), this.env.FIL_CORS_ORIGINS)) return empty();
    if (!this.closeLimiter.allow(["ip:" + ipBucket(ip)])) return empty();
    const raw = (await request.text()).slice(0, 2048);
    let body: unknown = {};
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      body = {};
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) body = {};
    const { gen, token } = body as Record<string, unknown>;
    if (typeof gen === "string" && typeof token === "string" && gen && token) {
      this.closeSession(token.slice(0, 512), gen.slice(0, 128));
    }
    return empty();
  }

  /** close_session(): only the token holder's current generation closes. */
  private closeSession(token: string, gen: string): boolean {
    const info = this.reg.takeSession(token, gen);
    if (!info || !info.sid) return false;
    const { sid, room } = info;
    for (const [ch, others] of this.reg.unsubscribeAll(sid)) {
      for (const other of others) this.emitTo(other, "known-peer-left", { id: sid, channel: ch });
    }
    // Python emits to the socket.io room, which still holds the closed sid.
    if (room) {
      this.emitRoom(room, "peer-left", { id: sid });
      this.emitTo(sid, "peer-left", { id: sid });
    }
    this.emitTo(sid, "session-superseded", { reason: "page-closed" });
    tel("session-close", { sid });
    return true;
  }
}
