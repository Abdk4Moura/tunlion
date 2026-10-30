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
  reg.claimSession(null, "gx", "new", "u", "n");
  out.push({
    kind: "prune", batch, sessions: N, ms: +(performance.now() - t).toFixed(2),
    rowsRead: sql.c.rowsRead, rowsWritten: sql.c.rowsWritten, statements: sql.c.statements,
    cascadeRowsIfHubRuns: 2 * Math.min(batch, N),
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
  });
  db.close();
}
for (const line of out) console.log(JSON.stringify(line));
