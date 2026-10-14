#!/usr/bin/env python3
"""Merge cli.jsonl and browser.jsonl into matrix.json and matrix.md."""
import json, sys, pathlib
out = pathlib.Path(sys.argv[1]); sha = sys.argv[2] if len(sys.argv) > 2 else "?"
rows = []
for name in ("cli.jsonl", "browser.jsonl"):
    p = out / name
    if p.exists():
        rows += [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
(out / "matrix.json").write_text(json.dumps({"binary": sha, "cells": rows}, indent=1))
count = {r: sum(1 for x in rows if x["result"] == r) for r in ("pass", "fail", "n/a")}
md = [f"# Launch matrix", "", f"Binary sha256 `{sha}`. {count['pass']} pass, {count['fail']} fail, {count['n/a']} n/a.", "",
      "| Cell | Pair | Feature | Result | Seconds | Evidence |", "|---|---|---|---|---|---|"]
for r in rows:
    md.append(f"| {r['cell']} | {r['pair']} | {r['feature']} | {'**FAIL**' if r['result']=='fail' else r['result']} | {r['seconds']} | {r['evidence']} |")
(out / "matrix.md").write_text("\n".join(md) + "\n")
print("\n".join(md))
