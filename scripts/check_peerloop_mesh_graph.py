#!/usr/bin/env python3
"""Prove mesh reachability using a single selected root, never the workspace.

Graph-only: no compilation, tests, binding generation or lockfile updates.
Keep normal/build edges; lockfile membership is not dependency reachability.
"""

import argparse
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PROFILES = {
    "minimal": ["--no-default-features"],
    "default": [],
    "mesh": ["--no-default-features", "--features", "filament-peerloop/mesh"],
}
TARGETS = (None, "aarch64-linux-android", "x86_64-linux-android")
COMMON = {"filament-peerloop", "filament-id", "filament-cap",
          "filament-signal", "filament-transport"}


def check_graph(graph, mesh):
    packages = set()
    peerloop_features = set()
    for line in graph.splitlines():
        match = re.fullmatch(r"(\S+) v.+ \[([^\]]*)\](?: \(\*\))?", line)
        if not match:
            raise RuntimeError(f"Unexpected cargo tree output: {line}")
        name, features = match.groups()
        packages.add(name)
        if name == "filament-peerloop":
            peerloop_features.update(filter(None, features.split(",")))
    if not COMMON <= packages:
        raise RuntimeError(f"Missing common packages: {COMMON - packages}")
    if "filament-cli" in packages:
        raise RuntimeError("CLI must not be selected for an exclusion proof")
    if ("mesh" in peerloop_features) != mesh:
        raise RuntimeError(f"Wrong peerloop features: {sorted(peerloop_features)}")
    if ("filament-overlay" in packages) != mesh:
        raise RuntimeError(f"Overlay reachability must match mesh={mesh}")
    return len(packages)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    args = parser.parse_args()
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
    for target in TARGETS:
        for profile, flags in PROFILES.items():
            command = [
                "cargo", "tree", "--locked", "--color", "never",
                "-p", "filament-peerloop", "--edges", "normal,build",
                "--prefix", "none", "--format", "{p} [{f}]", *flags,
            ]
            if target:
                command += ["--target", target]
            graph = subprocess.check_output(command, cwd=ROOT, text=True)
            label = f"{target or 'host'}-{profile}"
            if args.output_dir:
                (args.output_dir / f"{label}.txt").write_text(graph)
            try:
                count = check_graph(graph, mesh=profile != "minimal")
            except RuntimeError as error:
                raise RuntimeError(f"{label}: {error}\n{graph}") from error
            print(f"PASS: {label}: {count} packages; mesh={profile != 'minimal'}")


if __name__ == "__main__":
    main()
