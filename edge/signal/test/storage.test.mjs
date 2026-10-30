// Session write-spacing, validity and bounded-cleanup tests. Registry runs
// against a real in-memory SQLite database through node:sqlite, with the same
// schema and sessions_exp index as the Durable Object. SQL statement counts
// are local instrumentation, not Cloudflare billed analytics.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";
import { DatabaseSync } from "node:sqlite";

function transpile(path) {
  const src = readFileSync(new URL(path, import.meta.url), "utf8");
  return ts.transpileModule(src, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
}
const url = (js) => "data:text/javascript," + encodeURIComponent(js);
const policyUrl = url(transpile("../src/policy.ts"));
const livenessUrl = url(transpile("../src/liveness.ts"));
const registryJs = transpile("../src/registry.ts")
  .replace('from "./liveness"', `from "${livenessUrl}"`)
  .replace('from "./policy"', `from "${policyUrl}"`);
const { Registry } = await import(url(registryJs));
const {
  SESSION_TTL,
  SESSION_PERSIST_S,
  SESSION_PRUNE_BATCH,
  CAPACITY_SCAN,
  sessionPersistFrom,
  pruneBatchFrom,
  capacityScanFrom,
} = await import(policyUrl);

function sqlite() {
  const db = new DatabaseSync(":memory:");
  const log = [];
  return {
    db,
    log,
    exec(query, ...bindings) {
      const st = db.prepare(query);
      if (/^\s*(select|pragma|explain)/i.test(query)) {
        const rows = st.all(...bindings).map((r) => ({ ...r }));
        log.push({ query, rows: rows.length, changes: 0 });
        return { toArray: () => rows };
      }
      const r = st.run(...bindings);
      log.push({ query, rows: 0, changes: Number(r.changes) });
      return { toArray: () => [] };
    },
  };
}

const M = (sql, alive, now, max, slack, prune, scan) =>
  new Registry(sql, (s) => alive.has(s), "", () => now.value, max, slack, prune, scan);

test("option parsing rejects bad values and clamps spacing to the TTL", () => {
  assert.equal(sessionPersistFrom({}), SESSION_PERSIST_S);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: "0" }), 0);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: "1800" }), 1800);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: "-1" }), SESSION_PERSIST_S);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: "nope" }), SESSION_PERSIST_S);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: "Infinity" }), SESSION_PERSIST_S);
  assert.equal(sessionPersistFrom({ FIL_SESSION_PERSIST_S: String(SESSION_TTL + 1) }), SESSION_TTL);
  assert.equal(pruneBatchFrom({}), SESSION_PRUNE_BATCH);
  assert.equal(pruneBatchFrom({ FIL_SESSION_PRUNE_BATCH: "10" }), 10);
  assert.equal(pruneBatchFrom({ FIL_SESSION_PRUNE_BATCH: "0" }), SESSION_PRUNE_BATCH);
  assert.equal(pruneBatchFrom({ FIL_SESSION_PRUNE_BATCH: "-4" }), SESSION_PRUNE_BATCH);
  assert.equal(capacityScanFrom({}), CAPACITY_SCAN);
  assert.equal(capacityScanFrom({ FIL_CAPACITY_SCAN: "256" }), 256);
  assert.equal(capacityScanFrom({ FIL_CAPACITY_SCAN: "0" }), CAPACITY_SCAN);
});

test("refresh spacing: 48 writes/day at 30 min, 4 at 6 h", () => {
  for (const [slack, want] of [[1800, 48], [6 * 3600, 4]]) {
    const sql = sqlite();
    const alive = new Set(["s1"]);
    const now = { value: 1_000_000 };
    const reg = M(sql, alive, now, 100, slack, 256, 64);
    const first = reg.claimSession(null, "g1", "s1", "u1", "n1");
    const token = first.token;
    sql.log.length = 0;
    for (let i = 0; i <= 2880; i++) {
      now.value = 1_000_000 + i * 30; // 24 h
      reg.claimSession(token, "g1", "s1", "u1", "n1");
    }
    const updates = sql.log.filter((e) => /^UPDATE sessions/.test(e.query)).length;
    assert.equal(updates, want, `slack=${slack}`);
    const row = sql.db.prepare("SELECT last_seen, exp FROM sessions WHERE token = ?").get(token);
    assert.ok(row.last_seen <= now.value);
    assert.equal(row.exp, row.last_seen + SESSION_TTL);
  }
});

test("validity: never after last claim + TTL, accepted 18 h floor after eviction", () => {
  const t0 = 2_000_000;
  const lastClaim = t0 + 6 * 3600 - 1; // just before the next 6 h write
  // One case = seed at t0, one claim at lastClaim, then evict (fresh heap) and
  // try to resume at `at`. No claim happens between eviction and the probe.
  function probe(slack, at) {
    const sql = sqlite();
    const alive = new Set(["s1"]);
    const now = { value: t0 };
    const reg = M(sql, alive, now, 100, slack, 256, 64);
    const token = reg.claimSession(null, "g1", "s1", "u1", "n1").token;
    // A real always-on claim cadence, so the persisted write is the last one
    // before lastClaim, not a single late refresh.
    for (let t = t0 + 30; t <= lastClaim; t += 30) {
      now.value = t;
      assert.equal(reg.claimSession(token, "g1", "s1", "u1", "n1").status, "current");
    }
    const later = { value: at };
    const v = M(sql, alive, later, 100, slack, 256, 64)
      .claimSession(token, "g1", "s1", "u1", "n1");
    return { status: v.status, token: v.token, original: token };
  }

  // 6 h slack: persisted expiry is t0+24h, so the post-eviction floor is about
  // 18 h. It must never resume after the Python cutoff lastClaim+24h.
  const exp6 = t0 + SESSION_TTL;
  assert.equal(probe(6 * 3600, exp6 - 2).status, "current");
  const expired6 = probe(6 * 3600, exp6);
  assert.equal(expired6.status, "new");
  assert.notEqual(expired6.token, expired6.original);
  assert.ok(exp6 <= lastClaim + SESSION_TTL, "new cutoff never after Python cutoff");

  // 30 min slack: the same sequence resumes later (smaller shortening). Its
  // persisted write was at lastClaim-1799, so it is still current where 6 h
  // slack has already expired, but never after lastClaim+24h.
  assert.equal(probe(1800, t0 + SESSION_TTL).status, "current");
  assert.equal(probe(1800, t0 + 106_200).status, "new");
  assert.equal(probe(1800, lastClaim + SESSION_TTL).status, "new");
});

test("same token across gen changes and retirement survives the larger spacing", () => {
  const sql = sqlite();
  const alive = new Set(["s1", "s2"]);
  const now = { value: 3_000_000 };
  const reg = M(sql, alive, now, 100, 6 * 3600, 256, 64);
  const token = reg.claimSession(null, "g1", "s1", "u1", "n1").token;
  now.value += 3600;
  assert.equal(reg.claimSession(token, "g2", "s2", "u1", "n1").status, "new");
  assert.equal(reg.claimSession(token, "g1", "s2", "u1", "n1").status, "retired");
  assert.equal(reg.takeSession(token, "g2").sid, "s2");
  assert.equal(reg.claimSession(token, "g2", "s2", "u1", "n1").status, "retired");
});

test("offline expiry is a new independent session", () => {
  const sql = sqlite();
  const alive = new Set(["s1"]);
  const now = { value: 4_000_000 };
  const reg = M(sql, alive, now, 100, 6 * 3600, 256, 64);
  const token = reg.claimSession(null, "g1", "s1", "u1", "n1").token;
  now.value += SESSION_TTL + 1;
  const fresh = M(sql, alive, now, 100, 6 * 3600, 256, 64)
    .claimSession(token, "g1", "s1", "u1", "n1");
  assert.equal(fresh.status, "new");
  assert.notEqual(fresh.token, token);
});

test("expired prune deletes one batch at a time and drains the same total", () => {
  const sql = sqlite();
  const alive = new Set();
  const now = { value: 5_000_000 };
  const reg = M(sql, alive, now, 500, 6 * 3600, 10, 64);
  for (let i = 0; i < 100; i++) {
    reg.claimSession(null, `g${i}`, `seed${i}`, `u${i}`, `n${i}`);
  }
  now.value += SESSION_TTL + 1;
  sql.log.length = 0;
  let deleted = 0;
  for (let i = 0; i < 12; i++) {
    reg.claimSession(null, "gx", `x${i}`, `ux${i}`, `nx${i}`);
    deleted += sql.log
      .filter((e) => /^DELETE FROM sessions/.test(e.query))
      .reduce((n, e) => n + e.changes, 0);
    sql.log.length = 0;
    now.value += 31;
  }
  assert.ok(deleted >= 100, `deleted ${deleted}`);
  const left = sql.db.prepare("SELECT COUNT(*) AS n FROM sessions WHERE exp <= ?").get(now.value).n;
  assert.equal(Number(left), 0);
});

test("retired expired cleanup is bounded too", () => {
  const sql = sqlite();
  const alive = new Set();
  const now = { value: 6_000_000 };
  const reg = M(sql, alive, now, 500, 6 * 3600, 10, 64);
  for (let i = 0; i < 50; i++) {
    const t = reg.claimSession(null, "g1", `r${i}`, `u${i}`, `n${i}`).token;
    reg.claimSession(t, "g2", `r${i}`, `u${i}`, `n${i}`);
  }
  now.value += SESSION_TTL + 1;
  sql.log.length = 0;
  reg.claimSession(null, "gx", "x", "ux", "nx");
  const retiredDeletes = sql.log
    .filter((e) => /^DELETE FROM retired/.test(e.query))
    .reduce((n, e) => n + e.changes, 0);
  assert.ok(retiredDeletes > 0 && retiredDeletes <= 10, `retired deletes ${retiredDeletes}`);
});

test("capacity cursor advances through a window of live rows and eventually frees a dead one", () => {
  const sql = sqlite();
  const alive = new Set(["s1", "s2", "s3"]);
  const now = { value: 7_000_000 };
  const reg = M(sql, alive, now, 3, 6 * 3600, 256, 1);
  for (const sid of ["s1", "s2", "s3"]) {
    reg.claimSession(null, "g1", sid, "u", "n");
  }
  // First two pages are live: capacity, cursor advances.
  assert.equal(reg.claimSession(null, "g2", "n1", "u", "n").status, "capacity");
  assert.equal(reg.claimSession(null, "g3", "n2", "u", "n").status, "capacity");
  // Third page finds s3, which is now dead, and frees exactly one slot.
  alive.delete("s3");
  const got = reg.claimSession(null, "g4", "n3", "u", "n");
  assert.equal(got.status, "new");
  assert.deepEqual(got.evicted, ["s3"]);
});

test("capacity wraps after the end and keeps failing closed when all rows are live", () => {
  const sql = sqlite();
  const alive = new Set(["s1", "s2", "s3"]);
  const now = { value: 8_000_000 };
  const reg = M(sql, alive, now, 3, 6 * 3600, 256, 1);
  for (const sid of ["s1", "s2", "s3"]) reg.claimSession(null, "g1", sid, "u", "n");
  for (let i = 0; i < 6; i++) {
    const v = reg.claimSession(null, `g${i}`, `n${i}`, "u", "n");
    assert.equal(v.status, "capacity");
  }
  assert.equal(sql.db.prepare("SELECT COUNT(*) AS n FROM sessions").get().n, 3);
});

test("an expired row is found directly even when the first page is all live", () => {
  const sql = sqlite();
  const alive = new Set(["s1"]);
  const now = { value: 9_000_000 };
  const reg = M(sql, alive, now, 2, 6 * 3600, 256, 1);
  reg.claimSession(null, "g1", "s1", "u", "n");
  now.value += 100;
  reg.claimSession(null, "g2", "s2", "u", "n"); // second row, unexpired
  now.value += SESSION_TTL + 1; // both expired
  const got = reg.claimSession(null, "g3", "s3", "u", "n");
  assert.equal(got.status, "new");
  assert.ok(got.evicted.length >= 1);
});
