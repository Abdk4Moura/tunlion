// Port of backend/ratelimit.py MemLimiter.
//
// The Durable Object is a single instance, so an in-memory sliding window is
// the same budget the single-process Python relay keeps. It resets when the
// object is evicted, exactly as the Python one resets on a restart.

export { ipBucket } from "./ip";

/** Sliding-window limit over several keys at once (ratelimit.MemLimiter).
 * allow(keys) admits only if EVERY key is under its limit, then charges all. */
export class MemLimiter {
  private log = new Map<string, number[]>();
  private ops = 0;
  constructor(
    readonly limit: number,
    readonly window: number,
    readonly maxKeys = 100_000,
  ) {}

  private prune(key: string, now: number): number[] | undefined {
    const q = this.log.get(key);
    if (!q) return undefined;
    while (q.length && now - q[0] > this.window) q.shift();
    return q;
  }

  private sweep(now: number) {
    for (const key of [...this.log.keys()]) {
      const q = this.prune(key, now);
      if (!q || !q.length) this.log.delete(key);
    }
  }

  allow(keys: string[], now = Date.now() / 1000): boolean {
    this.ops += 1;
    if (this.ops % 1024 === 0 || this.log.size > this.maxKeys) this.sweep(now);
    for (const key of keys) {
      const q = this.prune(key, now);
      if (q && q.length >= this.limit) return false;
    }
    for (const key of keys) {
      let q = this.log.get(key);
      if (!q) q = [];
      else this.log.delete(key); // move to end (LRU order)
      q.push(now);
      this.log.set(key, q);
    }
    while (this.log.size > this.maxKeys) {
      const first = this.log.keys().next().value as string;
      this.log.delete(first);
    }
    return true;
  }
}
