// Addresses, exactly as Python's ipaddress prints them: ratelimit.ip_bucket()
// and app._network_key(). Byte-for-byte agreement matters: /api/room hashes
// the network key, so both backends must produce the same string or a
// failover moves every device into a different "nearby" room.
// No imports, so test/ip.test.ts can load it under plain node.

/** The unit a per-IP limit counts: full IPv4 address, IPv6 /64 prefix. */
export function ipBucket(ip: string): string {
  const s = (ip || "").trim();
  const v4 = parseIPv4(s);
  if (v4) return `v4:${v4.join(".")}`;
  const v6 = parseIPv6(s);
  if (!v6) return `raw:${ip}`;
  // IPv4-mapped (::ffff:a.b.c.d) counts as that IPv4 address.
  if (v6.slice(0, 5).every((h) => h === 0) && v6[5] === 0xffff) {
    return `v4:${v6[6] >> 8}.${v6[6] & 255}.${v6[7] >> 8}.${v6[7] & 255}`;
  }
  return `v6:${formatIPv6([...v6.slice(0, 4), 0, 0, 0, 0])}/64`;
}

export function parseIPv4(s: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const parts = m.slice(1).map((p) => {
    // Python's ipaddress refuses leading zeros ("01").
    if (p.length > 1 && p.startsWith("0")) return NaN;
    return Number(p);
  });
  return parts.every((p) => Number.isInteger(p) && p >= 0 && p <= 255) ? parts : null;
}

/** Parse an IPv6 literal to 8 hextets, or null. Accepts an embedded IPv4 tail. */
export function parseIPv6(s: string): number[] | null {
  if (!s || s.includes("%") || !s.includes(":")) return null;
  let text = s;
  const lastColon = s.lastIndexOf(":");
  const maybeV4 = s.slice(lastColon + 1);
  if (maybeV4.includes(".")) {
    const v4 = parseIPv4(maybeV4);
    if (!v4) return null;
    const hi = ((v4[0] << 8) | v4[1]).toString(16);
    const lo = ((v4[2] << 8) | v4[3]).toString(16);
    text = s.slice(0, lastColon + 1) + hi + ":" + lo;
  }
  const dbl = text.split("::");
  if (dbl.length > 2) return null;
  const groups = (g: string) => (g === "" ? [] : g.split(":"));
  const left = groups(dbl[0]);
  const right = dbl.length === 2 ? groups(dbl[1]) : [];
  if (![...left, ...right].every((g) => /^[0-9a-fA-F]{1,4}$/.test(g))) return null;
  const l = left.map((g) => parseInt(g, 16));
  const r = right.map((g) => parseInt(g, 16));
  if (dbl.length === 2) {
    if (l.length + r.length > 7) return null;
    return [...l, ...new Array(8 - l.length - r.length).fill(0), ...r];
  }
  return l.length === 8 ? l : null;
}

/** Python ipaddress str(): lowercase hex, the LEFTMOST LONGEST run of two or
 * more zero hextets collapsed to "::". Matching it byte for byte matters:
 * /api/room hashes this string, so both backends must agree on it. */
export function formatIPv6(h: number[]): string {
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  h.forEach((x, i) => {
    if (x === 0) {
      curLen += 1;
      if (curStart === -1) curStart = i;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curLen = 0;
      curStart = -1;
    }
  });
  const hex = h.map((x) => x.toString(16));
  if (bestLen > 1) {
    const left = hex.slice(0, bestStart).join(":");
    const right = hex.slice(bestStart + bestLen).join(":");
    return `${left}::${right}`;
  }
  return hex.join(":");
}

/** app._network_key(): IPv4 by address, IPv6 by /64, else raw. */
export function networkKey(ip: string): [string, string] {
  const v4 = parseIPv4(ip);
  if (v4) return ["ipv4", v4.join(".")];
  const v6 = parseIPv6(ip);
  if (v6) return ["ipv6", formatIPv6([...v6.slice(0, 4), 0, 0, 0, 0])];
  return ["raw", ip];
}
