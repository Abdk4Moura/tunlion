// HealthState: the one place that decides whether the origin (the VPS) is up.
//
// A Durable Object rather than KV because the decision must be the same for
// every colo at once: KV is eventually consistent (up to a minute), and two
// peers of one room reading different answers would land on different
// backends and never see each other. One object, read through a short
// per-isolate cache in the router, gives one answer everywhere within
// FLAG_CACHE_MS.
//
// Hysteresis, as a state machine:
//
//   up --probe fails / router reports a failed proxy--> suspect
//   suspect --FAIL_N consecutive failed probes (SUSPECT_EVERY apart)--> down
//   suspect --a probe succeeds--> up
//   down --RECOVER_N consecutive good probes (DOWN_EVERY apart) and at least
//          MIN_DOWN since going down--> up, then drain the hub DRAIN_DELAY later
//
// Probes run from the minute Cron Trigger (baseline) and from this object's
// own alarm while suspect or down (fast path). Up and healthy, nothing runs
// between cron ticks, so an idle system costs one probe a minute.

import { DurableObject } from "cloudflare:workers";
import { envInt, type Env } from "./shared";

/** The router's per-isolate cache of the flag. */
export const FLAG_CACHE_MS = 5_000;
/** With FLAGS (KV) bound: the router's per-colo Cache API copy, and KV's own
 * edge cache (its minimum). The flag can be this stale anywhere, plus KV's
 * global propagation (typically well under a minute). */
export const FLAG_COLO_CACHE_S = 15;
export const FLAG_KV_CACHE_S = 30;
export const FLAG_KEY = "origin-up";
/** Draining before every router has seen the flip would let a client
 * reconnect through a stale "down" straight back onto the hub. */
function drainDelayMs(env: Env): number {
  return env.FLAGS ? (FLAG_COLO_CACHE_S + FLAG_KV_CACHE_S + 30) * 1000 : FLAG_CACHE_MS + 3_000;
}
/** After a failback, keep sweeping stragglers off the hub for this long. */
const STRAGGLER_WINDOW_MS = 10 * 60_000;

export type Phase = "up" | "suspect" | "down";

export interface HealthView {
  originUp: boolean;
  phase: Phase;
  since: number; // ms epoch of the last up/down flip
  failStreak: number;
  okStreak: number;
  lastProbe: number;
  lastProbeOk: boolean | null;
  lastProbeMs: number | null;
  transitions: Array<{ at: number; to: Phase }>;
}

interface Stored {
  phase: Phase;
  since: number;
  failStreak: number;
  okStreak: number;
  drainAt: number;
  stragglersUntil: number;
  transitions: Array<{ at: number; to: Phase }>;
  // The last probe, kept so /__router/status can show it after an eviction.
  // One small write a minute: 1,440 rows a day of the 100k free.
  lastProbe: number;
  lastProbeOk: boolean | null;
  lastProbeMs: number | null;
  published?: string; // the flag value last written to KV
}

const INITIAL: Stored = {
  phase: "up",
  since: 0,
  failStreak: 0,
  okStreak: 0,
  drainAt: 0,
  stragglersUntil: 0,
  transitions: [],
  lastProbe: 0,
  lastProbeOk: null,
  lastProbeMs: null,
};

function tel(event: string, kv: Record<string, unknown> = {}) {
  console.log("TEL " + JSON.stringify({ ts: Date.now() / 1000, ev: event, ...kv }));
}

export class HealthState extends DurableObject<Env> {
  private s: Stored | null = null;
  private probing: Promise<void> | null = null;

  private get cfg() {
    const e = this.env;
    return {
      failN: envInt(e.HEALTH_FAIL_N, 3),
      recoverN: envInt(e.HEALTH_RECOVER_N, 3),
      suspectEvery: envInt(e.HEALTH_SUSPECT_EVERY_S, 10) * 1000,
      downEvery: envInt(e.HEALTH_DOWN_EVERY_S, 20) * 1000,
      minDown: envInt(e.HEALTH_MIN_DOWN_S, 60) * 1000,
      timeout: envInt(e.HEALTH_PROBE_TIMEOUT_S, 5) * 1000,
    };
  }

  private async load(): Promise<Stored> {
    if (!this.s) this.s = { ...INITIAL, ...((await this.ctx.storage.get<Stored>("s")) || {}) };
    return this.s;
  }

  private async save() {
    if (this.s) await this.ctx.storage.put("s", this.s);
  }

  async state(): Promise<HealthView> {
    const s = await this.load();
    return {
      originUp: s.phase !== "down",
      phase: s.phase,
      since: s.since,
      failStreak: s.failStreak,
      okStreak: s.okStreak,
      lastProbe: s.lastProbe,
      lastProbeOk: s.lastProbeOk,
      lastProbeMs: s.lastProbeMs,
      transitions: s.transitions.slice(-20),
    };
  }

  /** The router saw a proxied request fail. Starts the fast probe loop. */
  async report(): Promise<void> {
    const s = await this.load();
    if (s.phase !== "up") return;
    s.phase = "suspect";
    s.failStreak = 0;
    await this.save();
    tel("health-suspect", { by: "router" });
    await this.armAlarm(500);
  }

  /** Cron entry: one probe, plus straggler sweeping after a failback. */
  async tick(): Promise<void> {
    await this.probeOnce();
    const s = await this.load();
    if (s.phase === "up" && Date.now() < s.stragglersUntil && s.drainAt === 0) {
      await this.drainHub(true);
    }
  }

  async alarm() {
    const s = await this.load();
    if (s.drainAt && Date.now() >= s.drainAt) {
      s.drainAt = 0;
      await this.save();
      await this.drainHub(false);
    }
    if (s.phase !== "up") await this.probeOnce();
    await this.rearm();
  }

  private async armAlarm(inMs: number) {
    const at = Date.now() + inMs;
    const cur = await this.ctx.storage.getAlarm();
    if (cur === null || cur > at) await this.ctx.storage.setAlarm(at);
  }

  private async rearm() {
    const s = await this.load();
    const c = this.cfg;
    const next: number[] = [];
    if (s.phase === "suspect") next.push(c.suspectEvery);
    if (s.phase === "down") next.push(c.downEvery);
    if (s.drainAt) next.push(Math.max(0, s.drainAt - Date.now()));
    if (next.length) await this.ctx.storage.setAlarm(Date.now() + Math.min(...next));
  }

  private async probeOnce(): Promise<void> {
    // Cron and alarm can overlap; one probe at a time keeps streaks honest.
    if (this.probing) return this.probing;
    this.probing = this.doProbe().finally(() => {
      this.probing = null;
    });
    return this.probing;
  }

  private async doProbe(): Promise<void> {
    const origin = this.env.ORIGIN_URL;
    if (!origin) return;
    const c = this.cfg;
    const t0 = Date.now();
    let ok = false;
    try {
      const resp = await fetch(origin.replace(/\/$/, "") + "/health", {
        headers: { "user-agent": "tunlion-router-health" },
        signal: AbortSignal.timeout(c.timeout),
        cf: { cacheTtl: 0 },
      } as RequestInit);
      if (resp.status === 200) {
        const body = (await resp.json().catch(() => null)) as { ok?: unknown } | null;
        ok = !!body && body.ok === true;
      }
    } catch {
      ok = false;
    }
    const now = Date.now();
    const s = await this.load();
    s.lastProbe = now;
    s.lastProbeOk = ok;
    s.lastProbeMs = now - t0;
    if (s.phase === "up" || s.phase === "suspect") {
      if (ok) {
        s.failStreak = 0;
        if (s.phase === "suspect") this.flip(s, "up", now, false);
      } else {
        s.failStreak += 1;
        if (s.failStreak >= c.failN) this.flip(s, "down", now, true);
        else if (s.phase === "up") s.phase = "suspect";
      }
    } else if (ok) {
      s.okStreak += 1;
      if (s.okStreak >= c.recoverN && now - s.since >= c.minDown) {
        this.flip(s, "up", now, true);
        s.drainAt = now + drainDelayMs(this.env);
        s.stragglersUntil = now + STRAGGLER_WINDOW_MS;
      }
    } else {
      s.okStreak = 0;
    }
    await this.save();
    await this.publish(s);
    if (s.phase !== "up" || s.drainAt) await this.rearm();
  }

  /** Write the flag to KV when it differs from what was last published
   * (a handful of writes a day; Free allows 1,000). */
  private async publish(s: Stored) {
    if (!this.env.FLAGS) return;
    const want = s.phase === "down" ? "0" : "1";
    if (s.published === want) return;
    await this.env.FLAGS.put(FLAG_KEY, want);
    s.published = want;
    await this.save();
    tel("health-publish", { originUp: want === "1" });
  }

  private flip(s: Stored, to: Phase, now: number, isFlip: boolean) {
    s.phase = to;
    s.failStreak = 0;
    s.okStreak = 0;
    if (isFlip) {
      s.since = now;
      s.transitions = [...s.transitions, { at: now, to }].slice(-20);
      tel("health-flip", { to });
    }
  }

  private async drainHub(onlyIfConnected: boolean) {
    const hub = this.env.HUB.get(this.env.HUB.idFromName("hub"));
    if (onlyIfConnected) {
      const st = (await (await hub.fetch("https://hub/__hub/stats")).json()) as {
        websockets: number;
        polling: number;
      };
      if (!st.websockets && !st.polling) return;
    }
    const r = (await (await hub.fetch("https://hub/__hub/drain", { method: "POST" })).json()) as { drained: number };
    tel("health-drain", { drained: r.drained, straggler: onlyIfConnected });
  }
}
