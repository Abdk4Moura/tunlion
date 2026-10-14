#!/usr/bin/env python3
"""Decide whether a CI run needs the Rust/CLI jobs.

A browser-only change (the web app, docs, prose) cannot change what the CLI
builds or how it behaves, so the cargo tests, cross-builds and gate suites have
nothing to say about it. Running them anyway costs about an hour of runner time
per push and delays the browser checks that do matter.

The rule is deliberately narrow, and FAILS OPEN: the Rust jobs are skipped only
when every changed path is provably outside the CLI's inputs. Any doubt (an
unknown event, a missing commit, a git error, an empty diff, a path this file
does not recognise) means "run everything". A skipped required check counts as
passed on GitHub, so a wrong "skip" would wave a broken CLI through; a wrong
"run" only costs minutes.

Writes `rust=true|false` to $GITHUB_OUTPUT and prints the reasoning.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

# frontend/src/pake/** is the wasm build of crates/filament-pair: it is the
# CLI's handshake compiled for the browser, so a change there must run the CLI
# side too (pake-wasm.yml checks it matches its source).
_RUST_INSIDE_FRONTEND = ("frontend/src/pake/",)

# Markdown inside these trees can be compiled in (cli/skills/tunlion/SKILL.md is
# include_str!'d and packaged), so prose there is not "just docs".
_CODE_TREES = ("cli/", "crates/", "pake/", "backend/", "proofs/", "scripts/", ".github/")


def is_browser_only(path: str) -> bool:
    """True when `path` cannot affect the CLI build, its tests or its gates."""
    p = path.strip().lstrip("./")
    if not p:
        return False
    if p.startswith(_RUST_INSIDE_FRONTEND):
        return False
    if p.startswith("frontend/"):
        return True
    if p.startswith("docs/"):
        return True
    if p.endswith(".md") and not p.startswith(_CODE_TREES):
        return True
    return False


def needs_rust(paths: list[str]) -> tuple[bool, str]:
    """(run the Rust jobs?, why). An empty list is treated as unknown: run."""
    paths = [p for p in (x.strip() for x in paths) if p]
    if not paths:
        return True, "no changed paths could be listed; running everything"
    rust = [p for p in paths if not is_browser_only(p)]
    if rust:
        shown = ", ".join(rust[:5]) + (" ..." if len(rust) > 5 else "")
        return True, f"{len(rust)} of {len(paths)} changed paths touch the CLI's inputs: {shown}"
    return False, f"all {len(paths)} changed paths are browser-only or docs"


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def _has_commit(sha: str) -> bool:
    if not sha or set(sha) == {"0"}:
        return False
    try:
        _git("cat-file", "-e", f"{sha}^{{commit}}")
        return True
    except subprocess.CalledProcessError:
        return False


def changed_paths() -> tuple[list[str] | None, str]:
    """The paths this run is about, or (None, why) when that cannot be known."""
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    payload_path = os.environ.get("GITHUB_EVENT_PATH", "")
    try:
        payload = json.load(open(payload_path)) if payload_path else {}
    except (OSError, ValueError):
        return None, "event payload unreadable"
    if event in ("pull_request", "pull_request_target"):
        pr = payload.get("pull_request") or {}
        base = (pr.get("base") or {}).get("sha", "")
        head = (pr.get("head") or {}).get("sha", "")
        if not (_has_commit(base) and _has_commit(head)):
            return None, "pull request base or head commit is not in the checkout"
        # Three dots: what the PR changes relative to where it branched, not
        # what landed on the base since.
        return _git("diff", "--name-only", f"{base}...{head}").splitlines(), f"{event} {base[:8]}...{head[:8]}"
    if event == "push":
        before, after = payload.get("before", ""), payload.get("after", "")
        if not (_has_commit(before) and _has_commit(after)):
            return None, "push has no usable 'before' commit (new branch or force push)"
        return _git("diff", "--name-only", before, after).splitlines(), f"push {before[:8]}..{after[:8]}"
    return None, f"event '{event or 'unknown'}' always runs everything"


def main() -> int:
    try:
        paths, source = changed_paths()
        if paths is None:
            rust, why = True, source
        else:
            rust, why = needs_rust(paths)
            why = f"{source}: {why}"
            for p in paths:
                print(f"  {'browser' if is_browser_only(p) else 'cli    '}  {p}")
    except Exception as e:  # fail open: an error must never skip tests
        rust, why = True, f"could not classify the change ({e!r}); running everything"
    print(f"rust={'true' if rust else 'false'}: {why}")
    out = os.environ.get("GITHUB_OUTPUT")
    if out:
        with open(out, "a") as f:
            f.write(f"rust={'true' if rust else 'false'}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
