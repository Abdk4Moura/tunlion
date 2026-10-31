// Port of backend/signaling.py _MemRegistry onto a Durable Object.
//
// Two layers, for two reasons:
//
//  * Memory is the read path. Every sync touches the session, the room and
//    the channels; reading them from SQLite would spend the Free plan's
//    5M rows-read/day at a few hundred devices. Membership, channels and
//    session records are therefore held in maps, the same structures as the
//    Python class.
//  * SQLite is write-through durability. The hub uses WebSocket hibernation:
//    a hibernated (or evicted) object loses its heap while its websockets stay
//    open, so every map is reloaded from SQLite the first time it is needed
//    after a wake (sessions lazily, one primary-key read per token).
//
// What is deliberately NOT written on every event: the sliding last_seen/exp
// of a claim that is only a refresh (a daemon full-syncs every 30 s). The hot
// value lives in memory and is written through once it has drifted
// FIL_SESSION_PERSIST_S (6 h) from the stored one, which is 4 rows a day for an
// always-on device instead of 48. After an eviction a session can look up to
// that much older than it is: its persisted expiry is never later than the
// last real claim plus SESSION_TTL, but it can be up to 6 h earlier (the
// accepted 18 h floor).
//
// The physical row is separate from token validity. Pruning is claim-triggered
// and batched, so a dead row can remain until a later claim arrives; there is
// no scheduled sweep and no TTL + constant physical-retention claim.
//
// Method names and return shapes follow the Python class one to one, so a
// change on the Python side maps onto the method of the same name here.

import { sessionAlive } from "./liveness";
import {
  CAPACITY_SCAN,
  MAX_RETIRED_TOTAL,
  MAX_SESSIONS,
  PRUNE_INTERVAL,
  RETIRED_TTL,
  SESSION_PERSIST_S,
  SESSION_PRUNE_BATCH,
  SESSION_TTL,
  validId,
} from "./policy";

export interface SqlLike {
  exec(query: string, ...bindings: unknown[]): { toArray(): Record<string, unknown>[] };
}

export type ClaimStatus = "denied" | "retired" | "replace" | "current" | "new" | "capacity";

export interface ClaimVerdict {
  status: ClaimStatus;
  token: string | null;
  gen: string | null;
  prev: string | null;
  evicted: string[];
}

export interface PeerMeta {
  id: string;
  name: string;
  uid: string | null;
}

interface SessionRec {
  sid: string | null;
  gen: string | null;
  uid: string | null;
  name: string | null;
  last_seen: number;
  exp: number;
  stored_last_seen: number; // what SQLite holds, for the write-through slack
}

interface Member {
  room: string;
  name: string;
  uid: string | null;
  gen: string | null;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, sid TEXT, gen TEXT,
     uid TEXT, name TEXT, last_seen REAL NOT NULL, exp REAL NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS sessions_exp ON sessions (exp)`,
  `CREATE TABLE IF NOT EXISTS retired (seq INTEGER PRIMARY KEY AUTOINCREMENT,
     token TEXT NOT NULL, gen TEXT NOT NULL, exp REAL NOT NULL, UNIQUE (token, gen))`,
  `CREATE INDEX IF NOT EXISTS retired_exp ON retired (exp)`,
  `CREATE TABLE IF NOT EXISTS members (sid TEXT PRIMARY KEY, room TEXT NOT NULL,
     name TEXT NOT NULL, uid TEXT, gen TEXT)`,
  `CREATE TABLE IF NOT EXISTS subs (ch TEXT NOT NULL, sid TEXT NOT NULL, PRIMARY KEY (ch, sid))`,
  `CREATE TABLE IF NOT EXISTS pairs (code TEXT PRIMARY KEY, sid TEXT NOT NULL, exp REAL NOT NULL)`,
];

function token24(): string {
  // secrets.token_urlsafe(24): 24 random bytes, base64url, no padding.
  const b = new Uint8Array(24);
  crypto.getRandomValues(b);
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export class Registry {
  // Only records that exist are cached: caching misses would let a client
  // grow the map with made-up tokens.
  private sessions = new Map<string, SessionRec>();
  private sessionCount: number | null = null;
  private retiredCount: number | null = null;
  private nextPrune = 0;
  private members: Map<string, Member> | null = null; // sid -> meta (_m)
  private rooms = new Map<string, Set<string>>(); // room -> sids
  private chans: Map<string, Set<string>> | null = null; // channel -> sids (_chan)
  private sidChans = new Map<string, Set<string>>(); // sid -> channels (_sidchan)
  /** Keyset cursor for the bounded capacity scan, ordered by (exp, rowid). */
  private capacityCursor: { exp: number; rid: number } | null = null;

  constructor(
    private sql: SqlLike,
    /** Ground truth for liveness: is this sid's transport open right now. */
    private alive: (sid: string) => boolean,
    /** Prefix for minted tokens, so the router can tell whose token it is. */
    private tokenPrefix = "",
    private now: () => number = () => Date.now() / 1000,
    /** Capacity bound; tests inject a small value. */
    private maxSessions = MAX_SESSIONS,
    /** Refresh write spacing and prune/scan bounds; see policy.ts. */
    private persistSlack = SESSION_PERSIST_S,
    private pruneBatch = SESSION_PRUNE_BATCH,
    private capacityScan = CAPACITY_SCAN,
  ) {
    for (const q of SCHEMA) this.sql.exec(q);
  }

  private count(table: string): number {
    return (this.sql.exec(`SELECT COUNT(*) AS n FROM ${table}`).toArray()[0] as { n: number }).n;
  }

  // ---------------------------------------------------------------- sessions

  private getSession(token: string): SessionRec | null {
    const cached = this.sessions.get(token);
    if (cached) return cached;
    const row = this.sql.exec("SELECT * FROM sessions WHERE token = ?", token).toArray()[0];
    const rec = row
      ? {
          sid: (row.sid as string | null) ?? null,
          gen: (row.gen as string | null) ?? null,
          uid: (row.uid as string | null) ?? null,
          name: (row.name as string | null) ?? null,
          last_seen: row.last_seen as number,
          exp: row.exp as number,
          stored_last_seen: row.last_seen as number,
        }
      : null;
    if (rec) this.sessions.set(token, rec);
    return rec;
  }

  /** Write the whole record (any change other than a pure refresh). */
  private putSession(token: string, rec: SessionRec, isNew = false) {
    if (isNew) {
      this.sql.exec(
        "INSERT INTO sessions (token, sid, gen, uid, name, last_seen, exp) VALUES (?, ?, ?, ?, ?, ?, ?)",
        token, rec.sid, rec.gen, rec.uid, rec.name, rec.last_seen, rec.exp,
      );
      if (this.sessionCount !== null) this.sessionCount += 1;
    } else {
      this.sql.exec(
        "UPDATE sessions SET sid = ?, gen = ?, uid = ?, name = ?, last_seen = ?, exp = ? WHERE token = ?",
        rec.sid, rec.gen, rec.uid, rec.name, rec.last_seen, rec.exp, token,
      );
    }
    rec.stored_last_seen = rec.last_seen;
    this.sessions.set(token, rec);
  }

  private dropSession(token: string) {
    this.sql.exec("DELETE FROM sessions WHERE token = ?", token);
    this.sessions.delete(token);
    if (this.sessionCount !== null) this.sessionCount = Math.max(0, this.sessionCount - 1);
  }

  /** Slide last_seen/exp; write through only past the configured spacing. */
  private touch(token: string, rec: SessionRec, now: number) {
    rec.last_seen = now;
    rec.exp = now + SESSION_TTL;
    if (now - rec.stored_last_seen >= this.persistSlack) this.putSession(token, rec);
  }

  claimSession(
    token: string | null | undefined,
    gen: unknown,
    sid: string,
    uid: unknown,
    name: string,
  ): ClaimVerdict {
    const denied: ClaimVerdict = { status: "denied", token: null, gen: null, prev: null, evicted: [] };
    if (!validId(uid) || !validId(gen)) return denied;
    if (token !== null && token !== undefined && (typeof token !== "string" || !token || token.length > 512)) {
      return denied;
    }
    const now = this.now();
    // #593: expired records are swept at most every PRUNE_INTERVAL, not on
    // every claim. The claimed token's own expiry is still checked inline.
    let evicted: string[] = [];
    if (now >= this.nextPrune) {
      this.pruneRetired(now);
      evicted = this.pruneSessions(now);
      this.nextPrune = now + PRUNE_INTERVAL;
    }
    let rec = token ? this.getSession(token) : null;
    if (rec && rec.exp <= now) {
      this.dropSession(token as string);
      if (rec.sid && rec.sid !== sid) evicted.push(rec.sid);
      rec = null;
    }
    if (rec && token) {
      if (this.isRetired(token, gen, now)) {
        return { status: "retired", token, gen: rec.gen, prev: rec.sid, evicted };
      }
      const labelsChanged = rec.uid !== uid || rec.name !== name;
      rec.uid = uid;
      rec.name = name;
      if (rec.gen === gen) {
        const prev = rec.sid;
        if (prev !== sid) {
          rec.sid = sid;
          rec.last_seen = now;
          rec.exp = now + SESSION_TTL;
          this.putSession(token, rec);
          return { status: "replace", token, gen, prev, evicted };
        }
        if (labelsChanged) {
          rec.last_seen = now;
          rec.exp = now + SESSION_TTL;
          this.putSession(token, rec);
        } else {
          this.touch(token, rec, now);
        }
        return { status: "current", token, gen, prev: null, evicted };
      }
      const old = rec.gen;
      const prev = rec.sid;
      if (old) this.addRetired(token, old, now);
      rec.gen = gen;
      rec.sid = sid;
      rec.last_seen = now;
      rec.exp = now + SESSION_TTL;
      this.putSession(token, rec);
      return { status: "new", token, gen, prev, evicted };
    }
    // No token, unknown token, or expired token: a fresh independent session.
    const made = this.makeRoom(now);
    if (made === null) return { status: "capacity", token: null, gen: null, prev: null, evicted };
    evicted = evicted.concat(made);
    const issued = this.tokenPrefix + token24();
    this.putSession(
      issued,
      { sid, gen, uid, name, last_seen: now, exp: now + SESSION_TTL, stored_last_seen: now },
      true,
    );
    return { status: "new", token: issued, gen, prev: null, evicted };
  }

  /** Drop expired token records, at most one prune batch; return their sids
   *  for room cleanup. The sessions_exp index orders the candidates, and the
   *  total is not reduced by batching: later claims continue where this one
   *  stopped. If claims stop, the backlog stays (claim-triggered, no sweep). */
  private pruneSessions(now: number): string[] {
    if (this.pruneBatch <= 0) return [];
    const rows = this.sql
      .exec(
        "SELECT token, sid FROM sessions WHERE exp <= ? ORDER BY exp LIMIT ?",
        now,
        this.pruneBatch,
      )
      .toArray() as unknown as { token: string; sid: string | null }[];
    const out: string[] = [];
    for (const r of rows) {
      // A refresh held only in memory may have slid this record past now.
      const hot = this.sessions.get(r.token);
      if (hot && hot.exp > now) continue;
      this.dropSession(r.token);
      if (r.sid) out.push(r.sid);
    }
    return out;
  }

  /** Transport authority, not the stored refresh hint. last_seen is written at
   *  most every persistSlack, so after a hibernation or eviction it can be
   *  hours old while the sid's websocket is still open; judging liveness by it
   *  would let capacity evict a live token. */
  private sessionLive(rec: SessionRec, now: number): boolean {
    return sessionAlive(rec.sid, rec.exp, now, this.alive);
  }

  /** One page of the capacity keyset scan, ordered by (exp, rowid). */
  private capacityRows(limit: number, wrap: boolean): Array<{ rid: number; token: string; sid: string | null; exp: number }> {
    const cols = "rowid AS rid, token, sid, exp FROM sessions";
    if (wrap || !this.capacityCursor) {
      return this.sql
        .exec(`SELECT ${cols} ORDER BY exp, rowid LIMIT ?`, limit)
        .toArray() as unknown as Array<{ rid: number; token: string; sid: string | null; exp: number }>;
    }
    const c = this.capacityCursor;
    // Row-value seek, so a late cursor seeks into sessions_exp instead of
    // re-examining the prefix with an OR predicate.
    return this.sql
      .exec(
        `SELECT ${cols} WHERE (exp, rowid) > (?, ?) ORDER BY exp, rowid LIMIT ?`,
        c.exp,
        c.rid,
        limit,
      )
      .toArray() as unknown as Array<{ rid: number; token: string; sid: string | null; exp: number }>;
  }

  /** Capacity is on TOKEN records only; never evict a live session. Returns
   *  evicted sids, or null when this bounded page has no dead candidate.
   *
   *  An expired row is found directly through sessions_exp, because expiry is
   *  the common dead case and cannot be hidden by a live first page. Otherwise
   *  one keyset page advances a cursor across claims; a page with no dead row
   *  fails closed (capacity) and the next claim continues after it, wrapping
   *  once the end is reached. A closed but unexpired row beyond the page can
   *  therefore delay a new session until cursor progress or expiry: that is an
   *  explicit availability tradeoff, not a promised bound. */
  private makeRoom(now: number): string[] | null {
    if (this.sessionCount === null) this.sessionCount = this.count("sessions");
    if (this.sessionCount < this.maxSessions) return [];
    const expired = this.sql
      .exec("SELECT token, sid FROM sessions WHERE exp <= ? ORDER BY exp LIMIT 1", now)
      .toArray()[0] as { token: string; sid: string | null } | undefined;
    if (expired) {
      const hot = this.sessions.get(expired.token);
      if (!hot || hot.exp <= now) {
        this.dropSession(expired.token);
        return expired.sid ? [expired.sid] : [];
      }
      // The in-memory refresh slid this row past now; fall through to the
      // transport-aware page rather than deleting a live session.
    }
    const limit = Math.max(1, this.capacityScan);
    let rows = this.capacityRows(limit, false);
    if (!rows.length) rows = this.capacityRows(limit, true);
    for (const r of rows) {
      this.capacityCursor = { exp: r.exp, rid: r.rid };
      const rec = this.getSession(r.token);
      if (!rec || this.sessionLive(rec, now)) continue;
      // One new session needs one slot. Delete only that deficit; each later
      // claim frees the next one.
      this.dropSession(r.token);
      return rec.sid ? [rec.sid] : [];
    }
    return null;
  }

  /** Global (token, gen) tombstones: 24h TTL + hard total cap (oldest first). */
  private pruneRetired(now: number) {
    if (this.pruneBatch > 0) {
      // Order by the indexed expiry, with seq only as a stable tie-break.
      // ORDER BY seq alone forced a full scan when nothing was expired.
      this.sql.exec(
        "DELETE FROM retired WHERE seq IN (SELECT seq FROM retired WHERE exp <= ? ORDER BY exp, seq LIMIT ?)",
        now,
        this.pruneBatch,
      );
    }
    this.retiredCount = this.count("retired");
    // Existing path: the hard total cap may still remove its overage in one
    // statement. It normally removes one row on the add that crosses the cap,
    // and bounding it would weaken the tombstone cap, so it stays explicit.
    this.capRetired();
  }

  private capRetired() {
    if (this.retiredCount === null || this.retiredCount < MAX_RETIRED_TOTAL) return;
    const over = this.retiredCount - MAX_RETIRED_TOTAL + 1;
    this.sql.exec("DELETE FROM retired WHERE seq IN (SELECT seq FROM retired ORDER BY seq LIMIT ?)", over);
    this.retiredCount -= over;
  }

  private isRetired(token: string, gen: unknown, now: number): boolean {
    const rows = this.sql
      .exec("SELECT exp FROM retired WHERE token = ? AND gen = ?", token, gen)
      .toArray() as unknown as { exp: number }[];
    if (!rows.length) return false;
    if (rows[0].exp <= now) {
      this.sql.exec("DELETE FROM retired WHERE token = ? AND gen = ?", token, gen);
      return false;
    }
    return true;
  }

  private addRetired(token: string, gen: string, now: number) {
    if (this.retiredCount === null) this.retiredCount = this.count("retired");
    this.capRetired();
    const before = this.retiredCount;
    this.sql.exec("INSERT OR IGNORE INTO retired (token, gen, exp) VALUES (?, ?, ?)", token, gen, now + RETIRED_TTL);
    this.retiredCount = before + 1; // an ignored duplicate overcounts by one: harmless, resynced each prune
  }

  /** #592: true when `sid` already holds TOKEN at `gen` (a claim could only be
   * a refresh). Read-only. */
  holdsSession(token: unknown, gen: unknown, sid: string): boolean {
    if (typeof token !== "string" || !token || !validId(gen)) return false;
    const rec = this.getSession(token);
    if (!rec || rec.exp <= this.now()) return false;
    return rec.gen === gen && rec.sid === sid;
  }

  /** Close the current sid for this token+generation (pagehide beacon). */
  takeSession(token: unknown, gen: unknown): { sid: string | null; room: string | null } | null {
    if (typeof token !== "string" || !token || !validId(gen)) return null;
    const now = this.now();
    const rec = this.getSession(token);
    if (!rec || rec.exp <= now || rec.gen !== gen) return null;
    const sid = rec.sid;
    rec.sid = null;
    rec.gen = null;
    rec.last_seen = now;
    rec.exp = now + SESSION_TTL;
    this.putSession(token, rec);
    this.addRetired(token, gen, now);
    let room: string | null = null;
    if (sid) room = this.remove(sid);
    return { sid, room };
  }

  // -------------------------------------------------------------- membership

  private loadMembers(): Map<string, Member> {
    if (this.members) return this.members;
    const m = new Map<string, Member>();
    for (const r of this.sql.exec("SELECT sid, room, name, uid, gen FROM members").toArray()) {
      const sid = r.sid as string;
      const room = r.room as string;
      m.set(sid, { room, name: r.name as string, uid: (r.uid as string | null) ?? null, gen: (r.gen as string | null) ?? null });
      let set = this.rooms.get(room);
      if (!set) this.rooms.set(room, (set = new Set()));
      set.add(sid);
    }
    this.members = m;
    return m;
  }

  add(sid: string, room: string, name: string, uid: string | null, gen: string | null) {
    const m = this.loadMembers();
    const prev = m.get(sid);
    if (prev) this.rooms.get(prev.room)?.delete(sid);
    m.set(sid, { room, name, uid: uid ?? null, gen: gen ?? null });
    let set = this.rooms.get(room);
    if (!set) this.rooms.set(room, (set = new Set()));
    set.add(sid);
    this.sql.exec(
      "INSERT OR REPLACE INTO members (sid, room, name, uid, gen) VALUES (?, ?, ?, ?, ?)",
      sid, room, name, uid ?? null, gen ?? null,
    );
  }

  roomOf(sid: string): string | null {
    return this.loadMembers().get(sid)?.room ?? null;
  }

  remove(sid: string): string | null {
    const m = this.loadMembers();
    const cur = m.get(sid);
    if (!cur) return null;
    m.delete(sid);
    const set = this.rooms.get(cur.room);
    if (set) {
      set.delete(sid);
      if (!set.size) this.rooms.delete(cur.room);
    }
    this.sql.exec("DELETE FROM members WHERE sid = ?", sid);
    return cur.room;
  }

  rename(sid: string, name: string): PeerMeta | null {
    const cur = this.loadMembers().get(sid);
    if (!cur) return null;
    cur.name = name;
    this.sql.exec("UPDATE members SET name = ? WHERE sid = ?", name, sid);
    return { id: sid, name, uid: cur.uid };
  }

  meta(sid: string): PeerMeta | null {
    const cur = this.loadMembers().get(sid);
    return cur ? { id: sid, name: cur.name, uid: cur.uid } : null;
  }

  /** Live members of a room. Rows whose transport is gone come back as
   * `dead` so the caller can run the departure they missed. */
  peersIn(room: string, exclude?: string): { peers: PeerMeta[]; dead: string[] } {
    const m = this.loadMembers();
    const peers: PeerMeta[] = [];
    const dead: string[] = [];
    for (const sid of this.rooms.get(room) ?? []) {
      if (sid === exclude) continue;
      if (!this.alive(sid)) {
        dead.push(sid);
        continue;
      }
      const v = m.get(sid)!;
      peers.push({ id: sid, name: v.name, uid: v.uid });
    }
    return { peers, dead };
  }

  roomMembers(room: string): string[] {
    this.loadMembers();
    return [...(this.rooms.get(room) ?? [])];
  }

  allMemberSids(): string[] {
    return [...this.loadMembers().keys()];
  }

  // ------------------------------------------------- presence channels (C12)

  private loadSubs(): Map<string, Set<string>> {
    if (this.chans) return this.chans;
    const c = new Map<string, Set<string>>();
    for (const r of this.sql.exec("SELECT ch, sid FROM subs").toArray()) {
      const ch = r.ch as string;
      const sid = r.sid as string;
      let s = c.get(ch);
      if (!s) c.set(ch, (s = new Set()));
      s.add(sid);
      let t = this.sidChans.get(sid);
      if (!t) this.sidChans.set(sid, (t = new Set()));
      t.add(ch);
    }
    this.chans = c;
    return c;
  }

  private unlink(ch: string, sid: string) {
    const c = this.loadSubs();
    const members = c.get(ch);
    if (!members || !members.has(sid)) return;
    members.delete(sid);
    if (!members.size) c.delete(ch);
    const t = this.sidChans.get(sid);
    if (t) {
      t.delete(ch);
      if (!t.size) this.sidChans.delete(sid);
    }
    this.sql.exec("DELETE FROM subs WHERE ch = ? AND sid = ?", ch, sid);
  }

  /** Union-subscribe; returns channel -> other live sids already present. */
  subscribe(sid: string, channels: string[]): Map<string, string[]> {
    const c = this.loadSubs();
    const out = new Map<string, string[]>();
    for (const ch of channels) {
      let members = c.get(ch);
      const others: string[] = [];
      for (const s of [...(members ?? [])]) {
        if (s === sid) continue;
        // lease-filter (#10) + lazy cleanup: dead sids vanish on first look
        if (!this.alive(s)) this.unlink(ch, s);
        else others.push(s);
      }
      out.set(ch, others);
      members = c.get(ch);
      if (!members) c.set(ch, (members = new Set()));
      if (!members.has(sid)) {
        members.add(sid);
        let t = this.sidChans.get(sid);
        if (!t) this.sidChans.set(sid, (t = new Set()));
        t.add(ch);
        this.sql.exec("INSERT OR IGNORE INTO subs (ch, sid) VALUES (?, ?)", ch, sid);
      }
    }
    return out;
  }

  shareChannel(a: string, b: string): boolean {
    this.loadSubs();
    const x = this.sidChans.get(a);
    const y = this.sidChans.get(b);
    if (!x || !y) return false;
    for (const ch of x) if (y.has(ch)) return true;
    return false;
  }

  unsubscribeAll(sid: string): Map<string, string[]> {
    this.loadSubs();
    const chans = [...(this.sidChans.get(sid) ?? [])];
    for (const ch of chans) this.unlink(ch, sid);
    return this.othersOn(chans, sid);
  }

  unsubscribe(sid: string, channels: unknown[]): Map<string, string[]> {
    const chans = channels.filter((c): c is string => typeof c === "string");
    for (const ch of chans) this.unlink(ch, sid);
    return this.othersOn(chans, sid);
  }

  private othersOn(chans: string[], sid: string): Map<string, string[]> {
    const c = this.loadSubs();
    const affected = new Map<string, string[]>();
    for (const ch of chans) {
      const others = [...(c.get(ch) ?? [])].filter((s) => s !== sid && this.alive(s));
      if (others.length) affected.set(ch, others);
    }
    return affected;
  }

  allSubscribedSids(): string[] {
    this.loadSubs();
    return [...this.sidChans.keys()];
  }

  // ------------------------------------------------ one-time nameplates (#11)
  // Rare events; plain SQLite. Python's in-memory twin never expires a code
  // (its Redis twin does, with EX); CONTRACT.md says 10 minutes, as here.

  pairCreate(code: string, sid: string, ttl: number): boolean {
    const now = this.now();
    this.sql.exec("DELETE FROM pairs WHERE code = ? AND exp <= ?", code, now);
    if (this.sql.exec("SELECT 1 FROM pairs WHERE code = ?", code).toArray().length) return false;
    this.sql.exec("INSERT INTO pairs (code, sid, exp) VALUES (?, ?, ?)", code, sid, now + ttl);
    return true;
  }

  /** Telemetry only: [exists, creator, creatorAlive] without consuming. */
  peekPair(code: string): [boolean, string | null, boolean] {
    const r = this.sql.exec("SELECT sid FROM pairs WHERE code = ? AND exp > ?", code, this.now()).toArray()[0];
    const creator = r ? (r.sid as string) : null;
    return [creator !== null, creator, creator !== null && this.alive(creator)];
  }

  /** Atomic consume (a code is claimable once). A dead creator matches nobody. */
  pairClaim(code: string): string | null {
    const r = this.sql.exec("SELECT sid, exp FROM pairs WHERE code = ?", code).toArray()[0];
    if (!r) return null;
    this.sql.exec("DELETE FROM pairs WHERE code = ?", code);
    if ((r.exp as number) <= this.now()) return null;
    const creator = r.sid as string;
    return this.alive(creator) ? creator : null;
  }

  sweepPairs() {
    this.sql.exec("DELETE FROM pairs WHERE exp <= ?", this.now());
  }

  /** Counts for /__hub/stats (no ids). */
  stats(): Record<string, number> {
    return {
      sessions: this.count("sessions"),
      retired: this.count("retired"),
      members: this.loadMembers().size,
      channels: this.loadSubs().size,
      pairs: this.count("pairs"),
    };
  }
}
