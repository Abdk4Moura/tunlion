"""Plan, run and judge the sharded gate jobs in .github/workflows/gates.yml.

The DATA lives in the workflow (the GATE_SCRIPTS and CORE_SHARDS tables), so the
artifact registry checker still finds every gate path in a workflow file. This
file is only the logic, in three subcommands:

  plan        decide what this run executes and emit the job matrices. Full mode
              runs everything; quick mode (a push to a branch) runs only what the
              changed paths touch. Either way it refuses a table that does not
              cover what it must: a core id missing from every shard, an id in
              two shards, a gate script that is not executable.
  run-bundle  run some gate scripts one after another on this runner, each under
              its own bound, and count PASS lines against the EXPECT for it.
  verdict     the one final job: every planned bundle and shard must have
              reported, every script must have passed exactly EXPECT gates, every
              core id must have run in some shard, and the deterministic-core
              ratchet must hold over the shard logs put back together.

Why a count and not the exit code: `bad` only increments a counter in these
scripts, so a script that dies early or skips a branch can still exit zero. The
EXPECT number is what makes green mean "the gates ran AND passed" (#249).

Run with `python3 scripts/ci_gates.py <subcommand>`; it reads its inputs from the
environment the workflow sets, and needs nothing beyond the standard library.
"""

from __future__ import annotations

import fnmatch
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GATES_SH = "cli/tests/gates.sh"
RATCHET = "cli/tests/gates-ratchet.sh"
# What a quick (push) run treats as able to change a gate's outcome at all.
RELEVANT = ["cli/*", "backend/*", "crates/*", "scripts/ci_gates.py", ".github/workflows/gates.yml"]
FAMILIES = {
    # suite: the Gate Suite counted PASS lines only.
    "suite": re.compile(r"^PASS:", re.M),
    # revoke: the Revoke Gates job counted KNOWN-RED as well, so a tracked
    # failure keeps its slot and can never make the total look short.
    "revoke": re.compile(r"^(PASS|KNOWN-RED):", re.M),
}


def die(msg: str) -> None:
    print(f"::error::{msg}")
    sys.exit(1)


def table_rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            rows.append(line.split())
    return rows


def gate_scripts() -> list[dict]:
    """GATE_SCRIPTS: path family expect bound bundle needs areas."""
    out = []
    seen = set()
    for row in table_rows(os.environ.get("GATE_SCRIPTS", "")):
        if len(row) != 7:
            die(f"GATE_SCRIPTS row needs 7 columns, got {len(row)}: {' '.join(row)}")
        path, family, expect, bound, bundle, needs, areas = row
        if family not in FAMILIES:
            die(f"{path}: unknown family {family}")
        if path in seen:
            die(f"{path} is listed twice in GATE_SCRIPTS")
        seen.add(path)
        out.append({
            "path": path,
            "family": family,
            "expect": int(expect),
            "bound": int(bound),
            "bundle": bundle,
            "needs": [] if needs == "-" else needs.split(","),
            "areas": [] if areas == "-" else areas.split(","),
        })
    if not out:
        die("GATE_SCRIPTS is empty")
    return out


def core_shards() -> tuple[dict[str, list[str]], list[str]]:
    """CORE_SHARDS: `<shard>: <gate ids>` lines, plus one `areas:` line."""
    shards: dict[str, list[str]] = {}
    areas: list[str] = []
    for line in os.environ.get("CORE_SHARDS", "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "areas":
            areas = rest.split()
            continue
        if name in shards:
            die(f"core shard {name} is defined twice")
        shards[name] = rest.split()
    if "unit" not in shards or shards["unit"] != ["0"]:
        die("CORE_SHARDS must define `unit: 0` (gate 0 runs cargo test on its own runner)")
    return shards, areas


def list_gates() -> list[str]:
    out = subprocess.run(["bash", GATES_SH, "--list-gates"], cwd=ROOT,
                         check=True, capture_output=True, text=True).stdout
    ids = out.split()
    if not ids:
        die("gates.sh --list-gates printed nothing")
    return ids


def check_core_cover(shards: dict[str, list[str]]) -> None:
    ids = list_gates()
    where: dict[str, list[str]] = {}
    for name, gates in shards.items():
        for g in gates:
            where.setdefault(g, []).append(name)
    missing = [g for g in ids if g not in where]
    unknown = [g for g in where if g not in ids]
    twice = {g: s for g, s in where.items() if len(s) > 1}
    if missing:
        die(f"core gate(s) {missing} are in gates.sh but in no shard of CORE_SHARDS")
    if unknown:
        die(f"CORE_SHARDS names {unknown}, which gates.sh does not define")
    if twice:
        die(f"core gate(s) listed in more than one shard: {twice}")
    for name, gates in shards.items():
        if "14b" in gates and "14" not in gates:
            die(f"shard {name}: gate 14b reuses gate 14's pairing and needs it in the same shard")


def changed_files() -> list[str] | None:
    """The files a push changed, or None when that cannot be known."""
    path = os.environ.get("CHANGED_FILES_FILE")
    if not path or not Path(path).exists():
        return None
    files = [f.strip() for f in Path(path).read_text().splitlines() if f.strip()]
    return files or None


def touches(files: list[str], patterns: list[str]) -> bool:
    for f in files:
        for p in patterns:
            if any(ch in p for ch in "*?["):
                if fnmatch.fnmatch(f, p):
                    return True
            elif p in f:
                return True
    return False


def cmd_plan() -> None:
    mode = os.environ.get("MODE", "full")
    scripts = gate_scripts()
    shards, core_areas = core_shards()
    check_core_cover(shards)
    for s in scripts:
        p = ROOT / s["path"]
        if not p.is_file():
            die(f"{s['path']} is in GATE_SCRIPTS but does not exist")
        if not os.access(p, os.X_OK):
            # Same precheck the old Gate Suite loop carried: a 0644 script runs
            # under `bash x` locally and hides the missing bit.
            die(f"{s['path']} is not executable (git update-index --chmod=+x)")

    files = changed_files() if mode == "quick" else None
    if mode == "quick" and os.environ.get("OPEN_PR"):
        # The pull request's own run is the full suite, and it starts on the
        # same push. A quick run beside it would only compete with it for
        # runners (the account runs 20 jobs at a time), so it stands down.
        print(f"quick mode: this branch has an open pull request ({os.environ['OPEN_PR']}), "
              "whose full run covers this push; running nothing here")
        files = []
    elif mode == "quick" and files is None:
        print("quick mode, but the changed files are unknown: running everything")
        mode = "full"

    if mode == "full":
        sel_scripts = scripts
        sel_core = True
    else:
        if files:
            print("changed files:\n  " + "\n  ".join(files))
        gate_lib = touches(files, ["cli/tests/lib/fixture.sh"])
        sel_scripts = []
        for s in scripts:
            text = (ROOT / s["path"]).read_text(errors="replace")
            hit = s["path"] in files or touches(files, s["areas"])
            if gate_lib and "lib/fixture.sh" in text:
                hit = True
            if hit:
                sel_scripts.append(s)
        sel_core = touches(files, [GATES_SH, RATCHET] + core_areas)
    # Gate 0 (the unit tests and the pair-code tests) runs whenever anything the
    # gates can see changed: it is the cheapest signal there is and needs no
    # binary. A push that touched none of it (docs, the frontend) runs nothing.
    run_unit = mode == "full" or touches(files, RELEVANT)

    bundles: dict[str, list[dict]] = {}
    for s in sel_scripts:
        bundles.setdefault(s["bundle"], []).append(s)
    suite_matrix = {"include": [
        {
            "bundle": b,
            "scripts": " ".join(x["path"] for x in ss),
            "fuse": str(any("fuse" in x["needs"] for x in ss)).lower(),
            "tcpdump": str(any("tcpdump" in x["needs"] for x in ss)).lower(),
        }
        for b, ss in sorted(bundles.items())
    ]}
    core_matrix = {"include": [
        {"shard": name, "gates": " ".join(g)}
        for name, g in shards.items() if name != "unit" and sel_core
    ]}
    expected = {
        "mode": mode,
        "unit": run_unit,
        "scripts": [s["path"] for s in sel_scripts],
        "core_shards": [c["shard"] for c in core_matrix["include"]],
    }
    print(f"mode={mode}: {len(sel_scripts)} gate script(s) in {len(bundles)} bundle(s), "
          f"{len(core_matrix['include'])} core shard(s), unit shard: {'yes' if run_unit else 'no'}")
    need_plain = bool(sel_scripts)
    need_hooks = bool(core_matrix["include"])
    build_matrix = {"include": (
        ([{"variant": "plain", "features": ""}] if need_plain else [])
        + ([{"variant": "hooks", "features": "--features test-hooks"}] if need_hooks else [])
    )}
    outputs = {
        "suite_matrix": json.dumps(suite_matrix),
        "core_matrix": json.dumps(core_matrix),
        "build_matrix": json.dumps(build_matrix),
        "has_suite": str(need_plain).lower(),
        "has_core": str(need_hooks).lower(),
        "has_build": str(need_plain or need_hooks).lower(),
        "has_unit": str(run_unit).lower(),
        "expected": json.dumps(expected),
    }
    gh_out = os.environ.get("GITHUB_OUTPUT")
    for k, v in outputs.items():
        print(f"{k}={v}")
    if gh_out:
        with open(gh_out, "a") as f:
            for k, v in outputs.items():
                f.write(f"{k}={v}\n")


def run_one(s: dict, log_dir: Path) -> dict:
    path, bound = s["path"], s["bound"]
    print(f"::group::{path}")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    # CI checks out the MERGE ref (pull/N/merge) by default, so "CI ran sha X"
    # is a false premise unless it is printed.
    print(f"gate tree: {head} ({path})")
    res = {"path": path, "family": s["family"], "expect": s["expect"], "got": 0,
           "code": None, "seconds": 0, "ok": False}
    if not os.access(ROOT / path, os.X_OK):
        print(f"MISSING or not executable: {path}")
        print("::endgroup::")
        print(f"::error::{path} is missing or not executable")
        return res
    log = log_dir / (Path(path).name + ".log")
    t0 = time.monotonic()
    # Output goes to a FILE that this loop tails, not to a pipe: a daemon a gate
    # leaves behind can hold a pipe open forever after the gate itself exits,
    # and a reader waiting for EOF would then wait with it. The old loop's
    # `out="$(timeout ...)"` had exactly that exposure.
    with open(log, "wb") as out:
        proc = subprocess.Popen(["timeout", str(bound), "bash", path], cwd=ROOT,
                                stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
        with open(log, "rb") as tail:
            while True:
                code = proc.poll()
                chunk = tail.read()
                if chunk:
                    sys.stdout.write(chunk.decode("utf-8", "replace"))
                    sys.stdout.flush()
                if code is not None:
                    rest = tail.read()
                    if rest:
                        sys.stdout.write(rest.decode("utf-8", "replace"))
                    break
                time.sleep(0.5)
    res["seconds"] = round(time.monotonic() - t0)
    res["code"] = code
    text = log.read_text(errors="replace")
    got = len(FAMILIES[s["family"]].findall(text))
    res["got"] = got
    print("::endgroup::")
    want = s["expect"]
    if code == 124:
        print(f"::error::{path} HUNG: killed by the {bound}s per-gate timeout, so the output above is partial")
    elif code != 0:
        print(f"::error::{path} exited {code}")
    elif got != want:
        print(f"::error::{path} passed {got} gates but {want} were expected; a gate did not run")
    else:
        res["ok"] = True
        print(f"{path}: {got}/{want} gates passed in {res['seconds']}s")
    return res


def cmd_run_bundle() -> None:
    bundle = os.environ["BUNDLE"]
    wanted = os.environ["BUNDLE_SCRIPTS"].split()
    by_path = {s["path"]: s for s in gate_scripts()}
    out_dir = ROOT / "gate-results"
    log_dir = out_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for p in wanted:
        if p not in by_path:
            die(f"bundle {bundle} names {p}, which is not in GATE_SCRIPTS")
        results.append(run_one(by_path[p], log_dir))
    (out_dir / f"result-{bundle}.json").write_text(json.dumps(results, indent=1))
    if not all(r["ok"] for r in results):
        sys.exit(1)


def cmd_verdict() -> None:
    expected = json.loads(os.environ["EXPECTED"])
    results_dir = Path(os.environ.get("RESULTS_DIR", "gate-results"))
    core_dir = Path(os.environ.get("CORE_DIR", "core-logs"))
    scripts = {s["path"]: s for s in gate_scripts()}
    shards, _ = core_shards()
    bad = 0

    # --- gate scripts: every planned script reported, and passed EXPECT ---
    got: dict[str, dict] = {}
    for f in sorted(results_dir.glob("**/result-*.json")):
        for r in json.loads(f.read_text()):
            if r["path"] in got:
                print(f"::error::{r['path']} reported by more than one bundle")
                bad += 1
            got[r["path"]] = r
    print(f"== gate scripts ({len(expected['scripts'])} planned, mode {expected['mode']})")
    for fam in ("suite", "revoke"):
        for p in expected["scripts"]:
            if scripts[p]["family"] != fam:
                continue
            r = got.get(p)
            if r is None:
                print(f"  NO RESULT  {p} (its bundle did not report: cancelled, crashed, or never ran)")
                bad += 1
            elif r["expect"] != scripts[p]["expect"]:
                print(f"  MISMATCH   {p} ran against EXPECT {r['expect']}, the table says {scripts[p]['expect']}")
                bad += 1
            elif not r["ok"]:
                print(f"  FAILED     {p}: exit {r['code']}, {r['got']}/{r['expect']} gates")
                bad += 1
            else:
                print(f"  ok         {p}: {r['got']}/{r['expect']} in {r['seconds']}s [{fam}]")
    if expected["mode"] == "full" and set(expected["scripts"]) != set(scripts):
        print("::error::a full run did not plan every gate script")
        bad += 1

    # --- the deterministic core: every shard reported, every id ran, ratchet ---
    unit_log = core_dir / "core-unit.log"
    if not expected["unit"]:
        if expected["scripts"] or expected["core_shards"]:
            die("plan skipped gate 0 but planned other gates; that is not a plan this file makes")
        print("gates verdict: this push touched nothing the gates can see; nothing ran")
        return
    logs = [unit_log] + [core_dir / f"core-{s}.log" for s in expected["core_shards"]]
    present = []
    for lg in logs:
        if lg.is_file():
            present.append(lg)
        else:
            print(f"::error::core shard log {lg.name} is missing: that shard did not report")
            bad += 1
    ran: list[str] = []
    for lg in present:
        m = re.findall(r"^gates shard ran:(.*)$", lg.read_text(errors="replace"), re.M)
        if not m:
            print(f"::error::{lg.name} has no 'gates shard ran:' line: gates.sh did not reach its summary")
            bad += 1
            continue
        ran += m[-1].split()
    want_ids = shards["unit"] + [g for s in expected["core_shards"] for g in shards[s]]
    not_run = [g for g in want_ids if g not in ran]
    if not_run:
        print(f"::error::core gate(s) {not_run} were planned but never ran in any shard")
        bad += 1
    if expected["core_shards"]:
        if sorted(expected["core_shards"]) != sorted(s for s in shards if s != "unit"):
            print("::error::core shards are all or nothing; the ratchet needs every one")
            bad += 1
        all_ids = list_gates()
        missing = [g for g in all_ids if g not in ran]
        if missing:
            print(f"::error::gates.sh defines {missing} but no shard ran them")
            bad += 1
        combined = core_dir / "combined.log"
        with open(combined, "wb") as out:
            for lg in present:
                out.write(lg.read_bytes())
        print(f"== deterministic core ratchet over {len(present)} shard log(s)")
        rc = subprocess.run(["bash", RATCHET, str(combined)], cwd=ROOT).returncode
        if rc != 0:
            bad += 1
    else:
        # No core shard this run (quick mode, nothing in the core touched). Gate
        # 0 still ran, and the two ratchet entries it owns must still hold.
        text = unit_log.read_text(errors="replace") if unit_log.is_file() else ""
        for want in ("unit tests", "pair-code variance/security tests"):
            if re.search(rf"^PASS:.*{re.escape(want)}", text, re.M):
                print(f"  ok         {want}")
            else:
                print(f"  FAILED     {want}")
                bad += 1
    if bad:
        die(f"gates verdict: {bad} problem(s) above")
    print("gates verdict: every planned gate ran and held")


def main() -> None:
    # Line-buffered, so this file's own lines and the ratchet's (a child
    # process writing to the same log) come out in the order they happened.
    sys.stdout.reconfigure(line_buffering=True)
    cmds ={"plan": cmd_plan, "run-bundle": cmd_run_bundle, "verdict": cmd_verdict}
    if len(sys.argv) != 2 or sys.argv[1] not in cmds:
        print(f"usage: ci_gates.py {{{'|'.join(cmds)}}}", file=sys.stderr)
        sys.exit(2)
    cmds[sys.argv[1]]()


if __name__ == "__main__":
    main()
