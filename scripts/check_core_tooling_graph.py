#!/usr/bin/env python3
"""Check selected-root UniFFI graphs without compiling or generating bindings.

Do not use a workspace-wide graph: other roots can unify tooling features into
the library. The lockfile records available packages, not compile exclusion.
Normal + build edges deliberately retain legitimate proc-macro dependencies.
"""

from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
ANDROID_TARGETS = ("aarch64-linux-android", "x86_64-linux-android")
TOOLING_PACKAGES = {"cargo_metadata", "uniffi_bindgen", "clap"}
TOOLING_FEATURES = {"bindgen", "cli", "cargo-metadata"}


def check_graph(target, cli):
    command = [
        "cargo", "tree", "--locked", "--color", "never",
        "-p", "tunlion-core", "--edges", "normal,build",
        "--prefix", "none", "--format", "{p} [{f}]",
    ]
    if target:
        command += ["--target", target]
    if cli:
        command += ["--features", "tunlion-core/cli"]
    graph = subprocess.check_output(command, cwd=ROOT, text=True)
    packages = set()
    uniffi_features = set()
    for line in graph.splitlines():
        match = re.fullmatch(r"(\S+) v.+ \[([^\]]*)\](?: \(\*\))?", line)
        if not match:
            raise RuntimeError(f"Unexpected cargo tree output: {line}")
        name, features = match.groups()
        packages.add(name)
        if name == "uniffi":
            uniffi_features.update(filter(None, features.split(",")))
    label = f"{target or 'host'} {'cli' if cli else 'library'}"
    required = {"tunlion-core", "uniffi", "uniffi_core", "uniffi_macros"}
    if not required <= packages:
        raise RuntimeError(f"{label}: missing scaffolding packages: {required - packages}")
    if cli:
        if not TOOLING_PACKAGES <= packages or not TOOLING_FEATURES <= uniffi_features:
            raise RuntimeError(f"{label}: missing bindgen tooling or metadata discovery")
    elif TOOLING_PACKAGES & packages or TOOLING_FEATURES & uniffi_features:
        raise RuntimeError(
            f"{label}: leaked tooling: {TOOLING_PACKAGES & packages}, "
            f"features: {TOOLING_FEATURES & uniffi_features}"
        )
    print(f"PASS: {label}: {len(packages)} packages; UniFFI features {sorted(uniffi_features)}")


if __name__ == "__main__":
    for android_target in ANDROID_TARGETS:
        check_graph(android_target, cli=False)
        check_graph(android_target, cli=True)
    # Match the existing Kotlin generator's host build as well.
    check_graph(None, cli=True)
