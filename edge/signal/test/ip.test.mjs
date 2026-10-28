// Vectors generated with CPython's ipaddress through the exact expressions in
// backend/ratelimit.py (ip_bucket) and backend/app.py (_network_key).
// src/ip.ts has no imports, so it is transpiled here with the TypeScript
// compiler already in devDependencies; no bundler or TS-enabled node needed.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import ts from "typescript";

const src = readFileSync(new URL("../src/ip.ts", import.meta.url), "utf8");
const js = ts.transpileModule(src, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText;
const { ipBucket, networkKey } = await import("data:text/javascript," + encodeURIComponent(js));

const VECTORS = [
  ["1.2.3.4", "v4:1.2.3.4", ["ipv4", "1.2.3.4"]],
  ["162.35.114.254", "v4:162.35.114.254", ["ipv4", "162.35.114.254"]],
  ["2001:db8::1", "v6:2001:db8::/64", ["ipv6", "2001:db8::"]],
  ["2001:0db8:0000:0001:0000:0000:0000:0001", "v6:2001:db8:0:1::/64", ["ipv6", "2001:db8:0:1::"]],
  ["2a06:98c0:3600::103", "v6:2a06:98c0:3600::/64", ["ipv6", "2a06:98c0:3600::"]],
  ["fe80::1:2:3:4", "v6:fe80::/64", ["ipv6", "fe80::"]],
  ["::1", "v6:::/64", ["ipv6", "::"]],
  ["::", "v6:::/64", ["ipv6", "::"]],
  ["::ffff:1.2.3.4", "v4:1.2.3.4", ["ipv6", "::"]],
  ["2001:db8:0:0:1:0:0:1", "v6:2001:db8::/64", ["ipv6", "2001:db8::"]],
  ["2001:0:0:1::", "v6:2001:0:0:1::/64", ["ipv6", "2001:0:0:1::"]],
  ["1:0:0:0:1:0:0:0", "v6:1::/64", ["ipv6", "1::"]],
  ["01.2.3.4", "raw:01.2.3.4", ["raw", "01.2.3.4"]],
  ["not-an-ip", "raw:not-an-ip", ["raw", "not-an-ip"]],
  ["2001:db8::ffff:1.2.3.4", "v6:2001:db8::/64", ["ipv6", "2001:db8::"]],
  ["abcd:ef01:2345:6789:abcd:ef01:2345:6789", "v6:abcd:ef01:2345:6789::/64", ["ipv6", "abcd:ef01:2345:6789::"]],
];

for (const [ip, bucket, key] of VECTORS) {
  test(`ip ${ip}`, () => {
    assert.equal(ipBucket(ip), bucket);
    assert.deepEqual(networkKey(ip), key);
  });
}
