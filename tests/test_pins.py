import json
import tempfile
import unittest
from pathlib import Path

from tools.check_pins import check_pins


class DependencyPinsTests(unittest.TestCase):
    def check_project(self, declarations: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text("[project]\n" + declarations, encoding="utf-8")
            check_pins(path)

    def test_exact_versions_extras_and_markers(self) -> None:
        self.check_project(
            'dependencies = ["example[cli] == 1.2.3"]\n'
            "[project.optional-dependencies]\n"
            "gpu = [\"accelerator==2.0+build1; sys_platform == 'linux'\"]"
        )

    def test_floating_and_invalid_declarations_fail(self) -> None:
        for entry in (
            "example",
            "example>=1.0",
            "example==1.*",
            "example==1,==2",
            "example @ https://example.invalid/tip.whl",
            "example>=1; sys_platform == 'never'",
            "not a requirement",
        ):
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.check_project("dependencies = " + json.dumps([entry]))

    def test_checks_optional_and_dynamic_runtime_dependencies(self) -> None:
        for declarations in (
            '[project.optional-dependencies]\ngpu = ["example~=2.0"]',
            'dynamic = ["dependencies"]',
            'dynamic = ["optional-dependencies"]',
        ):
            with self.subTest(declarations=declarations), self.assertRaises(ValueError):
                self.check_project(declarations)
