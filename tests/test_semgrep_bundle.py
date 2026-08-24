from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class SemgrepBundleValidationTests(unittest.TestCase):
    BUNDLED_VERSION = "1.174.0"

    def test_self_contained_runtime_with_java_rules_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime, rules = self._make_runtime(Path(temp_dir))

            result = self._validate(runtime, rules)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"Validated Semgrep {self.BUNDLED_VERSION}", result.stdout)

    def test_external_cli_fallback_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            runtime, rules = self._make_runtime(Path(temp_dir))
            cli = runtime / "secflow-semgrep"
            cli.write_text("#!/bin/sh\nexec pysemgrep \"$@\"\n", encoding="utf-8")
            cli.chmod(0o755)

            result = self._validate(runtime, rules)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("isolated CLI cannot start", result.stderr)

    def test_external_symbolic_link_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as external_dir:
            runtime, rules = self._make_runtime(Path(temp_dir))
            external = Path(external_dir) / "external-runtime"
            external.write_text("external", encoding="utf-8")
            (runtime / "external-runtime").symlink_to(external)

            result = self._validate(runtime, rules)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("outside its root", result.stderr)

    @staticmethod
    def _make_runtime(root: Path) -> tuple[Path, Path]:
        runtime = root / "semgrep"
        runtime.mkdir(parents=True)
        metadata = runtime / "_internal" / "semgrep-1.174.0.dist-info" / "METADATA"
        metadata.parent.mkdir(parents=True)
        metadata.write_text(
            "Metadata-Version: 2.1\nName: semgrep\nVersion: 1.174.0\n",
            encoding="utf-8",
        )
        cli = runtime / "secflow-semgrep"
        cli.write_text(
            "#!/bin/sh\n"
            "if [ \"${1:-}\" = \"--version\" ]; then\n"
            "  printf '%s\\n' '1.174.0'\n"
            "  exit 0\n"
            "fi\n"
            "output=''\n"
            "while [ \"$#\" -gt 0 ]; do\n"
            "  if [ \"$1\" = \"--json-output\" ]; then shift; output=$1; fi\n"
            "  shift\n"
            "done\n"
            "printf '%s\\n' '{\"version\":\"1.174.0\",\"results\":[{\"check_id\":\"secflow.java.command-injection\"}]}' > \"$output\"\n",
            encoding="utf-8",
        )
        cli.chmod(0o755)
        rules = root / "java-security.yml"
        rules.write_text("rules: []\n", encoding="utf-8")
        return runtime, rules

    @staticmethod
    def _validate(runtime: Path, rules: Path) -> subprocess.CompletedProcess[str]:
        root = Path(__file__).parents[1]
        env = dict(os.environ)
        env["PYTHON_BIN"] = sys.executable
        return subprocess.run(
            ["bash", str(root / "scripts" / "validate_semgrep_runtime.sh"), str(runtime), str(rules)],
            cwd=root,
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )


if __name__ == "__main__":
    unittest.main()
