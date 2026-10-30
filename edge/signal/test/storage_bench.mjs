// Local SQLite benchmark for the storage defaults. Not part of npm test:
//   node test/storage_bench.mjs [sessions]
// Counts are local statement/row counts, not Cloudflare billed analytics.
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import ts from "typescript";

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

function counted(db) {
  const c = { rowsRead: 0, rowsWritten: 0, statements: 0 };
  return {
    c,
    exec(query, ...bindings) {
      const st = db.prepare(query);
      c.statements += 1;
      if (/^\s*(select|pragma|explain)/i.test(query)) {
        const rows = st.all(...bindings).map((r) => ({ ...r }));
        c.rowsRead += rows.length;
        return { toArray: () => rows };
      }
      const r = st.run(...bindings);
      c.rowsWritten += Number(r.changes);
      return { toArray: () => [] };
    },
  };
}

function seed(n) {
  const db = new DatabaseSync(":memory:");
  db.exec("CREATE TABLE sessions (token TEXT PRIMARY KEY, sid TEXT, gen TEXT, uid TEXT, name TEXT, last_seen REAL NOT NULL, exp REAL NOT NULL)");
  db.exec("CREATE INDEX sessions_exp ON sessions (exp)");
  db.exec("CREATE TABLE retired (seq INTEGER PRIMARY KEY AUTOINCREMENT, token TEXT NOT NULL, gen TEXT NOT NULL, exp REAL NOT NULL, UNIQUE (token, gen))");
  db.exec("CREATE INDEX retired_exp ON retired (exp)");
  db.exec("CREATE TABLE members (sid TEXT PRIMARY KEY, room TEXT NOT NULL, name TEXT NOT NULL, uid TEXT, gen TEXT)");
  db.exec("CREATE TABLE subs (ch TEXT NOT NULL, sid TEXT NOT NULL, PRIMARY KEY (ch, sid))");
  db.exec("CREATE TABLE pairs (code TEXT PRIMARY KEY, sid TEXT NOT NULL, exp REAL NOT NULL)");
  const ins = db.prepare("INSERT INTO sessions (token, sid, gen, uid, name, last_seen, exp) VALUES (?,?,?,?,?,?,?)");
  const mem = db.prepare("INSERT INTO members (sid, room, name, uid, gen) VALUES (?,?,?,?,?)");
  const sub = db.prepare("INSERT INTO subs (ch, sid) VALUES (?,?)");
  db.exec("BEGIN");
  for (let i = 0; i < n; i++) {
    ins.run(`tok${i}`, `sid${i}`, "g", "u", "n", 1_000, 1_000 + 3600);
    mem.run(`sid${i}`, `room${i}`, "n", "u", "g");
    sub.run(`ch${i}`, `sid${i}`);
  }
  db.exec("COMMIT");
  return db;
}

const N = parseInt(process.argv[2] || "50000", 10);
const out = [];
for (const batch of [64, 256, 1024]) {
  const db = seed(N);
  const alive = new Set();
  const now = { value: 1000 + 7200 }; // all seeded rows expired
  const sql = counted(db);
  const reg = new Registry(sql, (s) => alive.has(s), "", () => now.value, N + 10, 6 * 3600, batch, 64);
  sql.c.rowsRead = sql.c.rowsWritten = sql.c.statements = 0;
  const t = performance.now();
  const v = reg.claimSession(null, "gx", "new", "u", "n");
  const pruneWritten = sql.c.rowsWritten;
  const pruneRead = sql.c.rowsRead;
  const pruneStatements = sql.c.statements;
  // What the hub does for each evicted sid, with the same counting wrapper.
  for (const sid of v.evicted) {
    sql.exec("DELETE FROM members WHERE sid = ?", sid);
    sql.exec("DELETE FROM subs WHERE sid = ?", sid);
  }
  const plan = db
    .prepare("EXPLAIN QUERY PLAN SELECT token, sid FROM sessions WHERE exp <= ? ORDER BY exp LIMIT ?")
    .all(now.value, batch)
    .map((r) => r.detail)
    .join("; ");
  out.push({
    kind: "prune", batch, sessions: N, ms: +(performance.now() - t).toFixed(2),
    rowsRead: sql.c.rowsRead, rowsWritten: sql.c.rowsWritten, statements: sql.c.statements,
    pruneRowsRead: pruneRead, pruneRowsWritten: pruneWritten, pruneStatements,
    cascadeRowsWritten: sql.c.rowsWritten - pruneWritten,
    cascadeStatements: sql.c.statements - pruneStatements,
    evicted: v.evicted.length, plan,
  });
  db.close();
}
for (const scan of [16, 64, 256]) {
  const db = seed(N);
  const alive = new Set(Array.from({ length: N }, (_, i) => `sid${i}`));
  const now = { value: 1000 + 1800 }; // unexpired, all live
  const sql = counted(db);
  const reg = new Registry(sql, (s) => alive.has(s), "", () => now.value, N, 6 * 3600, 256, scan);
  sql.c.rowsRead = sql.c.rowsWritten = sql.c.statements = 0;
  const t = performance.now();
  const v = reg.claimSession(null, "gx", "new", "u", "n");
  out.push({
    kind: "capacity", scan, sessions: N, status: v.status, ms: +(performance.now() - t).toFixed(2),
    rowsRead: sql.c.rowsRead, rowsWritten: sql.c.rowsWritten, statements: sql.c.statements,
    evicted: v.evicted.length,
  });
  db.close();
}
for (const scan of [64]) {
  const db = seed(N);
  const alive = new Set(Array.from({ length: N }, (_, i) => (i === 0 ? null : `sid${i}`)).filter(Boolean));
  const now = { value: 1000 + 1800 }; // unexpired, one dead transport
  const sql = counted(db);
  const reg = new Registry(sql, (s) => alive.has(s), "", () => now.value, N, 6 * 3600, 256, scan);
  sql.c.rowsRead = sql.c.rowsWritten = sql.c.statements = 0;
  const t = performance.now();
  const v = reg.claimSession(null, "gx", "new", "u", "n");
  const beforeCascade = sql.c.rowsWritten;
  const beforeStatements = sql.c.statements;
  for (const sid of v.evicted) {
    sql.exec("DELETE FROM members WHERE sid = ?", sid);
    sql.exec("DELETE FROM subs WHERE sid = ?", sid);
  }
  out.push({
    kind: "capacity-dead", scan, sessions: N, status: v.status, ms: +(performance.now() - t).toFixed(2),
    rowsRead: sql.c.rowsRead, rowsWritten: sql.c.rowsWritten, statements: sql.c.statements,
    registryRowsWritten: beforeCascade, cascadeRowsWritten: sql.c.rowsWritten - beforeCascade,
    cascadeStatements: sql.c.statements - beforeStatements, evicted: v.evicted.length,
  });
  db.close();
}
// Late cursor: a fresh Registry only exercises the first page. Compare the
// row-value seek with the old OR predicate near the end of the index.
{
  const db = seed(N);
  const lateExp = 1000 + 3600 - 1;
  const lateRid = N - 50;
  const cols = "rowid AS rid, token, sid, exp FROM sessions";
  const rv = db.prepare(`EXPLAIN QUERY PLAN SELECT ${cols} WHERE (exp, rowid) > (?, ?) ORDER BY exp, rowid LIMIT ?`).all(lateExp, lateRid, 64).map((r) => r.detail).join("; ");
  const or = db.prepare(`EXPLAIN QUERY PLAN SELECT ${cols} WHERE exp > ? OR (exp = ? AND rowid > ?) ORDER BY exp, rowid LIMIT ?`).all(lateExp, lateExp, lateRid, 64).map((r) => r.detail).join("; ");
  const t0 = performance.now();
  const rows = db.prepare(`SELECT ${cols} WHERE (exp, rowid) > (?, ?) ORDER BY exp, rowid LIMIT ?`).all(lateExp, lateRid, 64);
  out.push({ kind: "capacity-late", rowsReturned: rows.length, ms: +(performance.now() - t0).toFixed(2), planRowValue: rv, planOr: or });
  db.close();
}

// Retired steady state: 100k live tombstones, nothing expired. The old
// ORDER BY seq subquery scanned the table; the indexed expiry order should not.
{
  const db = seed(1);
  const ins = db.prepare("INSERT INTO retired (token, gen, exp) VALUES (?,?,?)");
  db.exec("BEGIN");
  for (let i = 0; i < 100000; i++) ins.run(`rtok${i}`, "g", 9_000_000);
  db.exec("COMMIT");
  const oldPlan = db.prepare("EXPLAIN QUERY PLAN SELECT seq FROM retired WHERE exp <= ? ORDER BY seq LIMIT ?").all(5000, 64).map((r) => r.detail).join("; ");
  const newPlan = db.prepare("EXPLAIN QUERY PLAN SELECT seq FROM retired WHERE exp <= ? ORDER BY exp, seq LIMIT ?").all(5000, 64).map((r) => r.detail).join("; ");
  const c = counted(db);
  c.c.rowsRead = 0;
  const t = performance.now();
  const oldRows = c.exec("SELECT seq FROM retired WHERE exp <= ? ORDER BY seq LIMIT ?", 5000, 64).toArray().length;
  const oldMs = +(performance.now() - t).toFixed(2);
  c.c.rowsRead = 0;
  const t2 = performance.now();
  const newRows = c.exec("SELECT seq FROM retired WHERE exp <= ? ORDER BY exp, seq LIMIT ?", 5000, 64).toArray().length;
  out.push({
    kind: "retired-empty", tombstones: 100000, oldRows, oldRowsRead: oldRows === 0 ? c.c.rowsRead : null,
    newRows, newRowsRead: c.c.rowsRead, oldMs, newMs: +(performance.now() - t2).toFixed(2),
    oldPlan, newPlan,
  });
  db.close();
}

for (const line of out) console.log(JSON.stringify(line));
