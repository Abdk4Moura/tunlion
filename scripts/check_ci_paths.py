#!/usr/bin/env python3
"""Enforce the CI path policy: a browser-only change never runs the Rust jobs,
a CLI change always does, and no required check is left pending.

Run with no arguments to check .github/workflows; `--self-test` checks the
checker and the classifier in scripts/ci_changes.py against fixed examples.

Policy:
  (a) Every job that runs cargo or rustup, in a workflow that a browser-only
      change would start, is gated by the shared `changes` job in the fail-open
      shape (`!cancelled()` and `needs.changes.outputs.rust != 'false'`), or is
      dispatch-only. A workflow whose trigger path filter already excludes a
      browser-only change needs no gate.
  (b) A workflow that provides a required check has no trigger path filter (a
      workflow that never starts leaves its required check pending forever),
      and a required check that comes from a matrix job is gated per STEP: a
      matrix job skipped at job level reports one check under its literal,
      unexpanded name, so the required names would never report.
  (c) browser-gates.yml still runs for frontend changes and not for CLI-only
      ones; pake-wasm.yml still runs for the browser's copy of the handshake
      and for its Rust source.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
sys.path.insert(0, str(ROOT / "scripts"))
from ci_changes import is_browser_only, needs_rust  # noqa: E402

# Branch protection on main (gh api repos/Abdk4Moura/tunlion/branches/main/protection).
# Keep in sync when protection changes; a name here with no job behind it fails.
REQUIRED_CHECKS = [
    "cargo test (linux)",
    "cargo test (windows)",
    "build (x86_64-unknown-linux-musl)",
    "build (aarch64-apple-darwin)",
    "build (x86_64-pc-windows-msvc)",
    "establishment-proof",
]

BROWSER_DIFF = ["frontend/src/ui/Tunlion.jsx", "frontend/src/lib/wire.js", "docs/design-ux-from-jobs.md"]
CLI_DIFF = ["cli/src/main.rs"]
PAKE_DIFF = ["frontend/src/pake/filament_pake_bg.wasm"]
PAIR_SRC_DIFF = ["crates/filament-pair/src/lib.rs"]

GATE_OUTPUT = "needs.changes.outputs.rust != 'false'"
RUST_STEP = re.compile(r"(^|[\s;|&(])(cargo|rustup)\s")


def _glob_re(pat: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pat):
        if pat.startswith("**", i):
            out += ".*"
            i += 2
            if i < len(pat) and pat[i] == "/":
                i += 1
        elif pat[i] == "*":
            out += "[^/]*"
            i += 1
        elif pat[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pat[i])
            i += 1
    return re.compile(out + r"\Z")


def _match(pat: str, path: str) -> bool:
    return bool(_glob_re(pat).match(path))


def triggers(on, event: str, diff: list[str]) -> bool:
    """Would a `push` (to a branch) or `pull_request` with `diff` start this workflow?"""
    if isinstance(on, str):
        on = {on: None}
    elif isinstance(on, list):
        on = {e: None for e in on}
    if event not in on:
        return False
    cfg = on[event] or {}
    if event == "push" and "tags" in cfg and "branches" not in cfg:
        return False  # tag pushes only: not a code change
    if "paths" in cfg:
        return any(_match(p, f) for p in cfg["paths"] for f in diff)
    if "paths-ignore" in cfg:
        return not all(any(_match(p, f) for p in cfg["paths-ignore"]) for f in diff)
    return True


def _on(doc: dict):
    # PyYAML reads the bare key `on` as boolean True.
    return doc.get("on", doc.get(True))


def _is_rust_job(job: dict) -> bool:
    for st in job.get("steps") or []:
        if RUST_STEP.search(str(st.get("run", ""))) or "rust-toolchain" in str(st.get("uses", "")):
            return True
    return False


def _needs(job: dict) -> list[str]:
    n = job.get("needs") or []
    return [n] if isinstance(n, str) else list(n)


def _job_gated(job: dict) -> bool:
    cond = str(job.get("if", ""))
    return "changes" in _needs(job) and "!cancelled()" in cond and GATE_OUTPUT in cond


def _steps_gated(job: dict) -> bool:
    if "changes" not in _needs(job) or "!cancelled()" not in str(job.get("if", "")):
        return False
    for st in job.get("steps") or []:
        cond = str(st.get("if", ""))
        if "needs.changes.outputs.rust == 'false'" in cond:
            continue  # the "skipped" note step
        if GATE_OUTPUT not in cond:
            return False
    return True


def _dispatch_only(job: dict) -> bool:
    return str(job.get("if", "")).strip() in (
        "github.event_name == 'workflow_dispatch'",
        "${{ github.event_name == 'workflow_dispatch' }}",
    )


def _name_re(name: str) -> re.Pattern:
    parts = re.split(r"\$\{\{[^}]*\}\}", name)
    return re.compile(".+?".join(re.escape(p) for p in parts) + r"\Z")


def check(workflows: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    found_required = {c: False for c in REQUIRED_CHECKS}
    for fname, doc in sorted(workflows.items()):
        on = _on(doc) or {}
        jobs = doc.get("jobs") or {}
        browser_starts = [e for e in ("push", "pull_request") if triggers(on, e, BROWSER_DIFF)]
        for jid, job in jobs.items():
            if not isinstance(job, dict) or "uses" in job:
                continue
            name = str(job.get("name", jid))
            required = [c for c in REQUIRED_CHECKS if _name_re(name).match(c)]
            for c in required:
                found_required[c] = True
            if required:
                for e in ("push", "pull_request"):
                    cfg = on.get(e) if isinstance(on, dict) else None
                    if isinstance(cfg, dict) and ("paths" in cfg or "paths-ignore" in cfg):
                        errors.append(f"{fname}:{jid}: provides required check(s) {required} but its {e} trigger has a path filter (the check would stay pending)")
                if _is_rust_job(job) and "matrix" in (job.get("strategy") or {}) and not _steps_gated(job) and browser_starts:
                    errors.append(f"{fname}:{jid}: required matrix job must be gated per step, not per job (a job-level skip reports the unexpanded name)")
            if not _is_rust_job(job) or not browser_starts:
                continue
            if _dispatch_only(job) or _job_gated(job) or _steps_gated(job):
                continue
            errors.append(
                f"{fname}:{jid}: runs cargo/rustup and starts on a browser-only {'/'.join(browser_starts)}, "
                f"but is not gated by `needs: changes` with `if: ${{{{ !cancelled() && {GATE_OUTPUT} }}}}`"
            )
    for c, ok in found_required.items():
        if not ok:
            errors.append(f"required check {c!r} has no job behind it")
    if "changes.yml" not in workflows:
        errors.append("changes.yml (the shared change detection) is missing")
    bg, pw = workflows.get("browser-gates.yml"), workflows.get("pake-wasm.yml")
    if bg is None or not triggers(_on(bg), "pull_request", BROWSER_DIFF[:1]):
        errors.append("browser-gates.yml no longer runs for a frontend change")
    elif triggers(_on(bg), "pull_request", CLI_DIFF):
        errors.append("browser-gates.yml runs for a CLI-only change")
    if pw is None or not (triggers(_on(pw), "pull_request", PAKE_DIFF) and triggers(_on(pw), "pull_request", PAIR_SRC_DIFF)):
        errors.append("pake-wasm.yml no longer runs for the browser handshake or its Rust source")
    return errors


def load() -> dict[str, dict]:
    return {p.name: yaml.safe_load(p.read_text()) for p in sorted(WORKFLOWS.glob("*.yml"))}


def self_test() -> int:
    fails = []

    def expect(cond, what):
        if not cond:
            fails.append(what)

    # Classifier.
    expect(needs_rust(BROWSER_DIFF) == (False, needs_rust(BROWSER_DIFF)[1]), "frontend+docs diff must skip Rust")
    expect(needs_rust(["frontend/src/App.jsx", "README.md"])[0] is False, "frontend + root README must skip Rust")
    expect(needs_rust(CLI_DIFF)[0] is True, "a CLI diff must run Rust")
    expect(needs_rust(PAKE_DIFF)[0] is True, "the browser's wasm handshake must run Rust")
    expect(needs_rust(["cli/skills/tunlion/SKILL.md"])[0] is True, "markdown compiled into the CLI must run Rust")
    expect(needs_rust([".github/workflows/browser-gates.yml"])[0] is True, "a workflow change must run everything")
    expect(needs_rust(["frontend/src/App.jsx", "Cargo.lock"])[0] is True, "a mixed diff must run Rust")
    expect(needs_rust([])[0] is True, "an empty or unknown diff must run Rust (fail open)")
    expect(is_browser_only("frontend/package.json"), "frontend deps are browser-only")
    expect(not is_browser_only("scripts/ci_changes.py"), "scripts are not browser-only")

    # Checker, on the real workflows.
    real = load()
    errs = check(real)
    expect(not errs, "the real workflows pass: " + "; ".join(errs))

    # Checker, on a deliberately broken copy: an ungated cargo job must be caught.
    import copy

    broken = copy.deepcopy(real)
    broken["test.yml"]["jobs"]["test"].pop("if", None)
    expect(any("test.yml:test" in e for e in check(broken)), "an ungated cargo job is reported")
    broken = copy.deepcopy(real)
    _on(broken["test.yml"])["pull_request"] = {"paths": ["cli/**"]}
    expect(any("path filter" in e for e in check(broken)), "a path filter on a required check is reported")
    broken = copy.deepcopy(real)
    broken["test.yml"]["jobs"]["cross-build"]["if"] = "${{ !cancelled() && " + GATE_OUTPUT + " }}"
    for st in broken["test.yml"]["jobs"]["cross-build"]["steps"]:
        st.pop("if", None)
    expect(any("per step" in e for e in check(broken)), "a job-level gate on a required matrix job is reported")
    broken = copy.deepcopy(real)
    _on(broken["browser-gates.yml"])["pull_request"] = {"paths": ["cli/**"]}
    expect(any("browser-gates" in e for e in check(broken)), "browser-gates losing its frontend trigger is reported")

    for f in fails:
        print(f"FAIL: {f}")
    print(f"self-test: {'ok' if not fails else f'{len(fails)} failed'}")
    return 1 if fails else 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    errors = check(load())
    for e in errors:
        print(f"::error::{e}")
    print(f"CI path policy: {'ok' if not errors else f'{len(errors)} violation(s)'}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
