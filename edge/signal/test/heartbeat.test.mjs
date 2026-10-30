// The heartbeat plan decides whether an alarm sends one batch or schedules
// timers (which make a Durable Object non-hibernatable). Pure module, so no
// workerd is needed: transpile it with the TypeScript compiler already in
// devDependencies, as ip.test.mjs does.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";

function load(path) {
  const src = readFileSync(new URL(path, import.meta.url), "utf8");
  const js = ts.transpileModule(src, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  return import("data:text/javascript," + encodeURIComponent(js));
}

const { PING_SLICE_AT, PING_SLICES_MAX, pingPlan } = await load("../src/heartbeat.ts");
const { pingSliceAt } = await load("../src/policy.ts");

test("no sockets: no slices and no timer", () => {
  assert.deepEqual(pingPlan(0, 25, 512), { batch: 0, slices: 0, delayMs: 0 });
});

test("default cap sends one batch at or below 40", () => {
  assert.equal(PING_SLICE_AT, 40);
  for (const n of [1, 20, 40]) {
    assert.deepEqual(pingPlan(n, 25), { batch: n, slices: 1, delayMs: 0 }, `n=${n}`);
  }
});

test("one above the cap returns to bounded slices", () => {
  const p = pingPlan(41, 25);
  assert.equal(p.slices, PING_SLICES_MAX);
  assert.equal(p.batch, 2);
  assert.equal(p.delayMs, 1000);
  assert.ok(p.batch * p.slices >= 41);
});

test("4,000 sockets keep the load-test slicing shape", () => {
  assert.deepEqual(pingPlan(4000, 25), { batch: 160, slices: 25, delayMs: 1000 });
});

test("slice count never exceeds the interval's whole seconds or the hard maximum", () => {
  const p = pingPlan(2000, 10);
  assert.equal(p.slices, 10);
  assert.equal(p.batch, 200);
  assert.equal(p.delayMs, 1000);
  assert.ok(pingPlan(1_000_000, 600).slices <= PING_SLICES_MAX);
});

test("a configured cap is honoured and a bad value falls back", () => {
  assert.deepEqual(pingPlan(64, 25, 64), { batch: 64, slices: 1, delayMs: 0 });
  assert.equal(pingPlan(65, 25, 64).slices, 25);
  assert.equal(pingPlan(1, 25, 0).slices, 25);
  assert.equal(pingSliceAt({ FIL_PING_SLICE_AT: "64" }), 64);
  assert.equal(pingSliceAt({ FIL_PING_SLICE_AT: "0" }), 0);
  assert.equal(pingSliceAt({ FIL_PING_SLICE_AT: "-1" }), 40);
  assert.equal(pingSliceAt({ FIL_PING_SLICE_AT: "nope" }), 40);
  assert.equal(pingSliceAt({}), 40);
});

test("every plan covers every socket exactly once", () => {
  for (const n of [0, 1, 513, 999, 4000]) {
    const p = pingPlan(n, 25);
    if (n === 0) assert.equal(p.batch, 0);
    else assert.ok(p.batch * p.slices >= n);
  }
});
