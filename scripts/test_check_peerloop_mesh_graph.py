#!/usr/bin/env python3
"""Regression tests for the graph gate (no Cargo invocation)."""

import unittest

from check_peerloop_mesh_graph import COMMON, check_graph


def graph(mesh):
    lines = [f"{name} v0.1.0 []" for name in sorted(COMMON)]
    if mesh:
        lines = [line.replace("tunlion-peerloop v0.1.0 []",
                              "tunlion-peerloop v0.1.0 [default,mesh]")
                 for line in lines]
        lines.append("tunlion-overlay v0.1.0 (/checkout/overlay) []")
    return "\n".join(lines)


class MeshGraphTests(unittest.TestCase):
    def test_expected_profiles(self):
        for mesh in (False, True):
            self.assertEqual(check_graph(graph(mesh), mesh), len(COMMON) + mesh)

    def test_overlay_leak_even_without_mesh_feature(self):
        with self.assertRaisesRegex(RuntimeError, "Overlay reachability"):
            check_graph(graph(False) + "\ntunlion-overlay v0.1.0 []", False)

    def test_missing_overlay_even_with_mesh_feature(self):
        with self.assertRaisesRegex(RuntimeError, "Overlay reachability"):
            check_graph(graph(True).split("\ntunlion-overlay")[0], True)

    def test_unified_mesh_is_not_a_minimal_proof(self):
        with self.assertRaisesRegex(RuntimeError, "Wrong peerloop features"):
            check_graph(graph(True), False)

    def test_common_package_must_remain(self):
        with self.assertRaisesRegex(RuntimeError, "Missing common packages"):
            check_graph("tunlion-peerloop v0.1.0 []", False)

    def test_cli_is_not_an_isolated_root(self):
        with self.assertRaisesRegex(RuntimeError, "CLI must not"):
            check_graph(graph(True) + "\ntunlion v0.1.0 []", True)

    def test_unknown_format_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, "Unexpected cargo tree"):
            check_graph("unexpected", False)


if __name__ == "__main__":
    unittest.main()
