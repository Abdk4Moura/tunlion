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
# The shipped Core is a receive/transfer/shell-client engine. Desktop server
# sectors and mesh/fleet route state must not be selected by this library root,
# even when another workspace member or a host tooling build enables them.
REDUCED_PEERLOOP_FEATURES = {"dispatch"}
FORBIDDEN_PEERLOOP_FEATURES = {
    "mesh",
    "fleet",
    "mount-server",
    "mount-daemon",
    "forward-server",
    "exec-server",
    "pty-server",
    "ssh-sign",
    "ssh-bootstrap",
}
FORBIDDEN_REDUCED_PACKAGES = {"filament-overlay", "filament-fleet", "filament-cli"}
# `authkeys-managed` is now optional behind `ssh-bootstrap`, which the reduced
# Core does not enable. The reduced graph has nothing inert to allow here.
INERT_REDUCED_PACKAGES = set()


def check_fleet_graph():
    """The optional desktop fleet composition is reachable, not selected by Android."""
    command = [
        "cargo", "tree", "--locked", "--color", "never",
        "-p", "tunlion-core", "--edges", "normal,build",
        "--prefix", "none", "--format", "{p} [{f}]",
        "--features", "tunlion-core/fleet",
    ]
    graph = subprocess.check_output(command, cwd=ROOT, text=True)
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
    required_features = {"dispatch", "mesh", "fleet"}
    required_packages = {"filament-overlay", "filament-fleet"}
    if not required_features <= peerloop_features:
        raise RuntimeError(
            "host fleet: missing peerloop features: "
            f"{required_features - peerloop_features}"
        )
    if not required_packages <= packages:
        raise RuntimeError(
            f"host fleet: missing packages: {required_packages - packages}"
        )
    print(
        f"PASS: host fleet: {len(packages)} packages; "
        f"peerloop features {sorted(peerloop_features)}"
    )


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
    peerloop_features = set()
    for line in graph.splitlines():
        match = re.fullmatch(r"(\S+) v.+ \[([^\]]*)\](?: \(\*\))?", line)
        if not match:
            raise RuntimeError(f"Unexpected cargo tree output: {line}")
        name, features = match.groups()
        packages.add(name)
        if name == "uniffi":
            uniffi_features.update(filter(None, features.split(",")))
        if name == "filament-peerloop":
            peerloop_features.update(filter(None, features.split(",")))
    label = f"{target or 'host'} {'cli' if cli else 'library'}"
    required = {"tunlion-core", "uniffi", "uniffi_core", "uniffi_macros"}
    if not required <= packages:
        raise RuntimeError(f"{label}: missing scaffolding packages: {required - packages}")
    if not REDUCED_PEERLOOP_FEATURES <= peerloop_features:
        raise RuntimeError(
            f"{label}: the Core must select the real receive dispatch; "
            f"peerloop features are {sorted(peerloop_features)}"
        )
    leaked_features = FORBIDDEN_PEERLOOP_FEATURES & peerloop_features
    leaked_packages = FORBIDDEN_REDUCED_PACKAGES & packages
    if leaked_features or leaked_packages:
        raise RuntimeError(
            f"{label}: reduced Core selected desktop/mesh sectors: "
            f"features {sorted(leaked_features)}, packages {sorted(leaked_packages)}"
        )
    if INERT_REDUCED_PACKAGES - packages:
        raise RuntimeError(
            f"{label}: expected inert packages are absent; update the allow-list: "
            f"{INERT_REDUCED_PACKAGES - packages}"
        )
    if cli:
        if not TOOLING_PACKAGES <= packages or not TOOLING_FEATURES <= uniffi_features:
            raise RuntimeError(f"{label}: missing bindgen tooling or metadata discovery")
    elif TOOLING_PACKAGES & packages or TOOLING_FEATURES & uniffi_features:
        raise RuntimeError(
            f"{label}: leaked tooling: {TOOLING_PACKAGES & packages}, "
            f"features: {TOOLING_FEATURES & uniffi_features}"
        )
    print(
        f"PASS: {label}: {len(packages)} packages; "
        f"UniFFI features {sorted(uniffi_features)}; "
        f"peerloop features {sorted(peerloop_features)}; "
        f"inert {sorted(INERT_REDUCED_PACKAGES & packages)}"
    )


if __name__ == "__main__":
    for android_target in ANDROID_TARGETS:
        check_graph(android_target, cli=False)
        check_graph(android_target, cli=True)
    # Match the existing Kotlin generator's host build as well.
    check_graph(None, cli=True)
    check_fleet_graph()
