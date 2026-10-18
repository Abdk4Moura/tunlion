#!/usr/bin/env python3
"""Checks the `tl` alias packaging without building Rust.

Covers the files a release consumes:
  - Homebrew formula template AND the rendered in-repo Formula
  - the npm manifest and launcher
  - the Windows portable ZIP's managed tl.cmd and its installer fallback
  - the winget manifest's deliberate single command alias

Run: python3 packaging/check-package-shape.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TL_MARKER = "@rem Tunlion tl launcher. Managed by scripts/install.ps1."

errors: list[str] = []


def read(rel: str) -> str:
    path = ROOT / rel
    if not path.is_file():
        errors.append(f"{rel}: missing")
        return ""
    return path.read_text(encoding="utf-8")


def require(rel: str, text: str, needle: str) -> None:
    if needle not in text:
        errors.append(f"{rel}: missing {needle!r}")


def main() -> int:
    # ------------------------------------------------------------- Homebrew
    for rel in ("packaging/brew/tunlion.rb.tmpl", "Formula/tunlion.rb"):
        formula = read(rel)
        require(rel, formula, 'bin.install "tunlion"')
        require(rel, formula, 'bin.install_symlink "tunlion" => "tl"')
        require(rel, formula, 'shell_output("#{bin}/tunlion --version")')
        require(rel, formula, 'shell_output("#{bin}/tl --version")')

    # ------------------------------------------------------------------ npm
    rel = "packaging/npm/package.json"
    raw = read(rel)
    try:
        pkg = json.loads(raw)
    except json.JSONDecodeError as exc:
        errors.append(f"{rel}: invalid JSON: {exc}")
        pkg = {}
    bins = pkg.get("bin") or {}
    if bins.get("tunlion") != "bin/tunlion.js":
        errors.append(f"{rel}: bin.tunlion must be bin/tunlion.js")
    if bins.get("tl") != bins.get("tunlion"):
        errors.append(f"{rel}: bin.tl must map to the same launcher as bin.tunlion")
    launcher = read("packaging/npm/bin/tunlion.js")
    if not launcher.startswith("#!/usr/bin/env node\n"):
        errors.append("packaging/npm/bin/tunlion.js: missing node shebang")
    if "bin/" not in (pkg.get("files") or []):
        errors.append(f"{rel}: files must include bin/")
    if "test/package.test.js" not in ((pkg.get("scripts") or {}).get("test") or ""):
        errors.append(f"{rel}: test script must run test/package.test.js")

    # ------------------------------------------------------ Windows portable
    rel = "packaging/windows/tl.cmd"
    tl = read(rel)
    expected_tl = (
        f"{TL_MARKER}\n"
        "@echo off\n"
        '"%~dp0tunlion.exe" %*\n'
        "exit /b %errorlevel%\n"
    )
    if tl != expected_tl:
        errors.append(f"{rel}: managed launcher content changed; update the installer fallback too")

    rel = "scripts/install.ps1"
    installer = read(rel)
    require(rel, installer, f"$TlMarker = '{TL_MARKER}'")
    require(rel, installer, "$TlLauncherContent = @'")
    require(rel, installer, 'Join-Path $extract \'tl.cmd\'')
    require(rel, installer, "Test-TlLauncherOwned")
    start = installer.find("$TlLauncherContent = @'")
    end = installer.find("\n'@", start)
    if start < 0 or end < 0:
        errors.append(f"{rel}: could not read the tl.cmd fallback here-string")
    else:
        fallback = installer[start:end].split("\n", 1)[1] + "\n"
        if fallback != expected_tl:
            errors.append(f"{rel}: embedded tl.cmd fallback diverges from {rel.replace('scripts/install.ps1', 'packaging/windows/tl.cmd')}")

    rel = ".github/workflows/cli-release.yml"
    release = read(rel)
    require(rel, release, "packaging/windows/tl.cmd")
    require(rel, release, "Copy-Item -LiteralPath $tl -Destination out/")

    # --------------------------------------------------------------- winget
    rel = "packaging/winget/Abdk4Moura.Tunlion.installer.yaml.tmpl"
    winget = read(rel)
    aliases = [line.strip() for line in winget.splitlines() if line.strip().startswith("PortableCommandAlias:")]
    if aliases != ["PortableCommandAlias: tunlion"]:
        errors.append(f"{rel}: must expose exactly the canonical tunlion alias, got {aliases}")

    # ------------------------------------------------------------ user docs
    readme = read("README.md")
    for needle in ("`tl`", "winget", "release ZIP"):
        require("README.md", readme, needle)

    if errors:
        for err in errors:
            print(f"check-package-shape: FAIL: {err}", file=sys.stderr)
        return 1
    print("check-package-shape: PASS: brew, npm, Windows ZIP/installer and winget alias shape")
    return 0


if __name__ == "__main__":
    sys.exit(main())
