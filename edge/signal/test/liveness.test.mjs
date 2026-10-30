// Liveness authority tests. The pure predicates are exercised directly, then
// Registry runs against a real in-memory SQLite database through node:sqlite
// (Node 22) so the capacity path uses the same session rows and indexes as the
// Durable Object.
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
function dataUrl(js) {
  return "data:text/javascript," + encodeURIComponent(js);
}

const policyUrl = dataUrl(transpile("../src/policy.ts"));
const livenessUrl = dataUrl(transpile("../src/liveness.ts"));
const registryJs = transpile("../src/registry.ts")
  .replace('from "./liveness"', `from "${livenessUrl}"`)
  .replace('from "./policy"', `from "${policyUrl}"`);
const { wsAlive, pollAlive, sessionAlive } = await import(livenessUrl);
const { Registry } = await import(dataUrl(registryJs));

test("websocket authority requires OPEN, attachment, no probe, namespace", () => {
  assert.equal(wsAlive(true, true, false, true), true);
  assert.equal(wsAlive(false, true, false, true), false);
  assert.equal(wsAlive(true, false, false, true), false);
  assert.equal(wsAlive(true, true, true, true), false);
  assert.equal(wsAlive(true, true, false, false), false);
});

test("polling authority is the engine.io dead window, not just ns", () => {
  const dead = 85_000;
  assert.equal(pollAlive(true, 1_000, 1_000 + dead, dead), true);
  assert.equal(pollAlive(true, 1_000, 1_001 + dead, dead), false);
  assert.equal(pollAlive(false, 1_000, 1_000, dead), false);
  assert.equal(pollAlive(true, NaN, 1_000, dead), false);
});

test("session authority is sid + unexpired + transport", () => {
  const alive = new Set(["s1"]);
  assert.equal(sessionAlive("s1", 10, 9, (s) => alive.has(s)), true);
  assert.equal(sessionAlive("s1", 9, 9, (s) => alive.has(s)), false);
  assert.equal(sessionAlive(null, 10, 9, (s) => alive.has(s)), false);
  alive.delete("s1");
  assert.equal(sessionAlive("s1", 10, 9, (s) => alive.has(s)), false);
});

function sqlite() {
  const db = new DatabaseSync(":memory:");
  return {
    db,
    exec(query, ...bindings) {
      const st = db.prepare(query);
      if (/^\s*(select|pragma|explain)/i.test(query)) {
        const rows = st.all(...bindings).map((r) => ({ ...r }));
        return { toArray: () => rows };
      }
      st.run(...bindings);
      return { toArray: () => [] };
    },
  };
}

test("capacity keeps a live token even when its stored last_seen is hours old", () => {
  const sql = sqlite();
  const alive = new Set(["s1"]);
  let now = 1_000_000;
  const make = () => new Registry(sql, (s) => alive.has(s), "", () => now, 1);

  const first = make().claimSession(null, "g1", "s1", "u1", "n1");
  assert.equal(first.status, "new");
  assert.ok(first.token);

  // A fresh heap reads the persisted row, where last_seen is one hour old.
  // The websocket is still open, so the token is live and must not be evicted.
  now += 3600;
  const second = make().claimSession(null, "g2", "s2", "u2", "n2");
  assert.equal(second.status, "capacity");

  // The transport closes: the same stale row is now evictable.
  alive.delete("s1");
  const third = make().claimSession(null, "g3", "s3", "u3", "n3");
  assert.equal(third.status, "new");
  assert.deepEqual(third.evicted, ["s1"]);
});

test("an expired token is evictable even if its sid still looks open", () => {
  const sql = sqlite();
  const alive = new Set(["s1"]);
  let now = 1_000_000;
  const make = () => new Registry(sql, (s) => alive.has(s), "", () => now, 1);
  assert.equal(make().claimSession(null, "g1", "s1", "u1", "n1").status, "new");

  now += 25 * 3600;
  const next = make().claimSession(null, "g2", "s2", "u2", "n2");
  assert.equal(next.status, "new");
  assert.deepEqual(next.evicted, ["s1"]);
});

test("reconnect replaces, close retires, and an old generation cannot return", () => {
  const sql = sqlite();
  const alive = new Set(["s1"]);
  let now = 1_000_000;
  const make = () => new Registry(sql, (s) => alive.has(s), "", () => now, 10);
  const reg = make();
  const first = reg.claimSession(null, "g1", "s1", "u1", "n1");
  const token = first.token;
  alive.add("s2");
  const replace = reg.claimSession(token, "g1", "s2", "u1", "n1");
  assert.equal(replace.status, "replace");
  assert.equal(replace.prev, "s1");

  const closed = reg.takeSession(token, "g1");
  assert.equal(closed.sid, "s2");
  assert.equal(reg.claimSession(token, "g1", "s3", "u1", "n1").status, "retired");

  const nextGen = reg.claimSession(token, "g2", "s4", "u1", "n1");
  assert.equal(nextGen.status, "new");
  assert.equal(reg.claimSession(token, "g1", "s5", "u1", "n1").status, "retired");
});
