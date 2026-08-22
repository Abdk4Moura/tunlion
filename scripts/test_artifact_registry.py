import datetime as dt
import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("check_artifact_registry.py")
SPEC = importlib.util.spec_from_file_location("artifact_registry", MODULE_PATH)
registry_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(registry_module)


class RegistryValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "gate.sh").write_text("#!/bin/sh\n./consumer.sh\n")
        (self.root / "consumer.sh").write_text("#!/bin/sh\n")
        # A `required` artifact must be referenced by some workflow (#249),
        # so the fixture tree needs CI that actually runs the gate it declares.
        wf = self.root / ".github" / "workflows"
        wf.mkdir(parents=True)
        (wf / "ci.yml").write_text("jobs:\n  t:\n    steps:\n      - run: sh gate.sh\n")
        self.today = dt.date(2026, 8, 4)

    def tearDown(self):
        self.temp.cleanup()

    def registry(self, artifacts):
        retired = [
            {
                "path": path,
                "disposition": "retired",
                "reason": "retired",
                "reference": "PR #1",
            }
            for path in sorted(registry_module.RETIRED_TOMBSTONES)
        ]
        return {"version": 1, "artifacts": artifacts + retired, "verdict_debt": []}

    def test_required_artifact_no_workflow_references_is_rejected(self):
        """The check that would have caught #247 and #249 must be able to fail.

        A `required` entry whose entrypoint is spelled perfectly but which no
        workflow invokes is the exact shape that let cli/tests/gates.sh sit
        marked required for months while nothing ran it.
        """
        (self.root / ".github" / "workflows" / "ci.yml").write_text(
            "jobs:\n  t:\n    steps:\n      - run: echo nothing\n"
        )
        registry = self.registry(
            [
                {
                    "path": "gate.sh",
                    "disposition": "required",
                    "entrypoint": "sh gate.sh",
                    "matrix": [{"platform": "linux", "topology": "unit"}],
                }
            ]
        )
        errors = registry_module.validate(
            registry, self.root, {"gate.sh"}, self.today
        )
        self.assertTrue(
            any("no workflow references it" in e for e in errors),
            f"expected the unwired-required error, got: {errors}",
        )

    def test_ratchet_entry_that_became_wired_is_rejected(self):
        """The ratchet may only shrink, so a line that is no longer true errors."""
        path = sorted(registry_module.UNWIRED_REQUIRED)[0]
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\n")
        (self.root / ".github" / "workflows" / "ci.yml").write_text(
            f"jobs:\n  t:\n    steps:\n      - run: sh {path}\n"
        )
        registry = self.registry(
            [
                {
                    "path": path,
                    "disposition": "required",
                    "entrypoint": f"sh {path}",
                    "matrix": [{"platform": "linux", "topology": "unit"}],
                }
            ]
        )
        errors = registry_module.validate(registry, self.root, {path}, self.today)
        self.assertTrue(
            any("the ratchet may only shrink" in e for e in errors),
            f"expected the stale-ratchet error, got: {errors}",
        )

    def test_valid_required_and_support(self):
        registry = self.registry(
            [
                {
                    "path": "gate.sh",
                    "disposition": "required",
                    "entrypoint": "sh gate.sh",
                    "matrix": [{"platform": "linux", "topology": "unit"}],
                },
                {
                    "path": "consumer.sh",
                    "disposition": "support",
                    "invoked_by": ["gate.sh"],
                },
            ]
        )
        self.assertEqual(
            registry_module.validate(
                registry, self.root, {"gate.sh", "consumer.sh"}, self.today
            ),
            [],
        )

    def test_unregistered_artifact_fails(self):
        errors = registry_module.validate(
            self.registry([]), self.root, {"gate.sh"}, self.today
        )
        self.assertIn("gate.sh: executable artifact is unregistered", errors)

    def test_unknown_disposition_fails(self):
        errors = registry_module.validate(
            self.registry([{"path": "gate.sh", "disposition": "maybe"}]),
            self.root,
            {"gate.sh"},
            self.today,
        )
        self.assertTrue(any("unknown disposition" in error for error in errors))

    def test_required_entrypoint_must_name_artifact(self):
        errors = registry_module.validate(
            self.registry(
                [
                    {
                        "path": "gate.sh",
                        "disposition": "required",
                        "entrypoint": "echo gate.sh",
                        "matrix": [{"platform": "linux", "topology": "unit"}],
                    }
                ]
            ),
            self.root,
            {"gate.sh"},
            self.today,
        )
        self.assertTrue(any("entrypoint must execute" in error for error in errors))

    def test_required_entrypoint_ignores_shell_comments(self):
        errors = registry_module.validate(
            self.registry(
                [
                    {
                        "path": "gate.sh",
                        "disposition": "required",
                        "entrypoint": "true # bash gate.sh",
                        "matrix": [{"platform": "linux", "topology": "unit"}],
                    }
                ]
            ),
            self.root,
            {"gate.sh"},
            self.today,
        )
        self.assertTrue(any("entrypoint must execute" in error for error in errors))

    def test_incomplete_diagnostic_fails(self):
        errors = registry_module.validate(
            self.registry(
                [{"path": "gate.sh", "disposition": "diagnostic", "owner": "owner"}]
            ),
            self.root,
            {"gate.sh"},
            self.today,
        )
        self.assertTrue(any("incomplete schema" in error for error in errors))

    def test_expired_diagnostic_fails(self):
        errors = registry_module.validate(
            self.registry(
                [
                    {
                        "path": "gate.sh",
                        "disposition": "diagnostic",
                        "issue": "https://github.com/Abdk4Moura/filament/issues/133",
                        "owner": "chief-ux",
                        "expires": "2026-08-03",
                    }
                ]
            ),
            self.root,
            {"gate.sh"},
            self.today,
        )
        self.assertTrue(any("expired on 2026-08-03" in error for error in errors))

    def test_retired_artifact_must_be_absent(self):
        retired_path = next(iter(registry_module.RETIRED_TOMBSTONES))
        retired_file = self.root / retired_path
        retired_file.parent.mkdir(parents=True)
        retired_file.write_text("#!/bin/sh\n")
        errors = registry_module.validate(
            self.registry([]),
            self.root,
            set(),
            self.today,
        )
        self.assertIn(f"{retired_path}: retired artifact still exists", errors)

    def test_retired_reference_cannot_escape_repository(self):
        registry = self.registry([])
        registry["artifacts"][0]["reference"] = "/etc/passwd"
        errors = registry_module.validate(registry, self.root, set(), self.today)
        self.assertTrue(any("durable reference" in error for error in errors))

    def test_support_requires_active_consumer(self):
        (self.root / "missing.sh").write_text("#!/bin/sh\nconsumer.sh\n")
        errors = registry_module.validate(
            self.registry(
                [
                    {
                        "path": "consumer.sh",
                        "disposition": "support",
                        "invoked_by": ["missing.sh"],
                    }
                ]
            ),
            self.root,
            {"consumer.sh"},
            self.today,
        )
        self.assertTrue(any("support consumer is not an active artifact" in error for error in errors))

    def test_support_comment_is_not_an_invocation(self):
        (self.root / "gate.sh").write_text("#!/bin/sh\ntrue # consumer.sh\n")
        errors = registry_module.validate(
            self.registry(
                [
                    {
                        "path": "gate.sh",
                        "disposition": "required",
                        "entrypoint": "sh gate.sh",
                        "matrix": [{"platform": "linux", "topology": "unit"}],
                    },
                    {
                        "path": "consumer.sh",
                        "disposition": "support",
                        "invoked_by": ["gate.sh"],
                    },
                ]
            ),
            self.root,
            {"gate.sh", "consumer.sh"},
            self.today,
        )
        self.assertTrue(any("declared caller does not reference" in error for error in errors))

    def test_verdict_debt_names_a_real_test(self):
        source = self.root / "tests.rs"
        source.write_text("#[test]\nfn real() {}\nfn missing() {}\n")
        registry = self.registry([])
        registry["verdict_debt"] = [
            {
                "path": "tests.rs",
                "test": "missing",
                "platforms": ["linux"],
                "behavior": "skip",
            }
        ]
        errors = registry_module.validate(registry, self.root, set(), self.today)
        self.assertTrue(any("attributed test does not exist" in error for error in errors))

    def test_discovery_is_recursive_and_uses_mode_or_shebang(self):
        (self.root / "cli/tests/nested").mkdir(parents=True)
        shebang = self.root / "cli/tests/nested/gate.sh"
        shebang.write_text("#!/bin/sh\n")
        executable = self.root / "cli/tests/tool.bin"
        executable.write_text("not a script\n")
        executable.chmod(0o755)
        (self.root / "outside.sh").write_text("#!/bin/sh\n")
        subprocess.run(["git", "init", "-q"], cwd=self.root, check=True)
        subprocess.run(["git", "add", "."], cwd=self.root, check=True)
        self.assertEqual(
            registry_module.tracked_artifacts(self.root),
            {"cli/tests/nested/gate.sh", "cli/tests/tool.bin"},
        )


if __name__ == "__main__":
    unittest.main()
