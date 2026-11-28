#!/usr/bin/env python3
"""Fold an explore campaign's coverage back into the repo, so the next
campaign starts where this one stopped instead of re-covering the same cases.

    python3 -I fuzz/chaos/absorb.py chaos-results/<job>/out

- seen.json: the union of every behaviour any absorbed campaign reached.
  explore loads it, so a schedule is kept only for a behaviour no campaign
  has seen before.
- corpus-grown/: each kept schedule, named by a hash of its content, so the
  same schedule absorbed twice is one file. explore seeds from these.

Then commit fuzz/chaos/seen.json and fuzz/chaos/corpus-grown/.
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _norm(sched) -> bytes:
    return (json.dumps(sched, indent=2, sort_keys=True) + "\n").encode()


def absorb(out: Path, here: Path = HERE) -> tuple[int, int, int]:
    seen_path = here / "seen.json"
    try:
        seen = set(json.loads(seen_path.read_text()))
    except FileNotFoundError:
        seen = set()
    before = len(seen)
    camp = out / "seen.json"
    if not camp.is_file():
        raise SystemExit(f"{camp}: missing (not an explore campaign, or one from before seen.json)")
    seen |= set(json.loads(camp.read_text()))
    seen_path.write_text(json.dumps(sorted(seen), indent=0) + "\n")
    dest = here / "corpus-grown"
    dest.mkdir(exist_ok=True)
    have = {hashlib.sha256(_norm(json.loads(p.read_text()))).hexdigest() for p in dest.glob("*.json")}
    added = 0
    for p in sorted((out / "corpus-grown").glob("*.json")):
        sched = json.loads(p.read_text())
        body = _norm(sched)
        h = hashlib.sha256(body).hexdigest()
        if h in have:
            continue
        (dest / f"g-{h[:12]}.json").write_bytes(body)
        have.add(h)
        added += 1
    return before, len(seen), added


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    before, after, added = absorb(Path(sys.argv[1]))
    print(f"behaviours: {before} -> {after} (+{after - before}); schedules added to corpus-grown: {added}")
