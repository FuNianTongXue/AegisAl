from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from scripts.validate_security_truth_manifest import check_sealed_truth_manifest, validate_manifest_report


ROOT = Path(__file__).resolve().parents[1]


def sha(value: str) -> str:
    return value * 64


def sealed_manifest() -> dict[str, object]:
    return {
        "methodology": {
            "qualification_eligible": True,
            "negative_label_scope": "cwe_complete",
            "cwe_complete_negative_labels": True,
            "seal_status": "sealed",
            "leakage_policy": "labels stay sealed until rules freeze before evaluation",
            "case_label_scope": "cwe_complete",
        },
        "cases": [
            {
                "id": "case-pos-1",
                "partition": "qualification",
                "language": "go",
                "vulnerable": True,
                "cwes": ["CWE-89"],
                "code_hash": sha("a"),
                "source_path": "pos/sql.go",
                "label_evidence": "request parameter reaches SQL query text",
                "label_scope": "cwe_complete",
            },
            {
                "id": "case-pos-2",
                "partition": "qualification",
                "language": "python",
                "vulnerable": True,
                "cwes": ["CWE-79"],
                "content_sha256": sha("b"),
                "file": "pos/xss.py",
                "evidence": "request parameter reaches HTML response",
                "label_scope": "cwe_complete",
            },
            {
                "id": "case-neg-1",
                "partition": "qualification",
                "language": "go",
                "vulnerable": False,
                "cwes": ["CWE-89"],
                "code_hash": sha("c"),
                "source_path": "neg/sql.go",
                "label_evidence": "SQL identifier is selected from a fixed allowlist",
                "label_scope": "cwe_complete",
            },
            {
                "id": "case-neg-2",
                "partition": "qualification",
                "language": "python",
                "vulnerable": False,
                "cwes": ["CWE-79"],
                "files": [{"path": "neg/xss.py", "sha256": sha("d")}],
                "label_evidence": "HTML output is escaped before response write",
                "label_scope": "cwe_complete",
            },
        ],
    }


class SecurityTruthManifestTests(unittest.TestCase):
    def test_accepts_sealed_cwe_complete_manifest(self) -> None:
        report = validate_manifest_report(
            sealed_manifest(),
            min_positive_cases=2,
            min_negative_cases=2,
        )

        self.assertTrue(report["passed"])
        self.assertEqual(report["summary"]["positive_cases"], 2)
        self.assertEqual(report["summary"]["negative_cases"], 2)
        self.assertEqual(report["summary"]["languages"], ["go", "python"])

    def test_rejects_incomplete_or_unsealed_truth_claims(self) -> None:
        manifest = sealed_manifest()
        manifest["methodology"] = {
            **manifest["methodology"],  # type: ignore[arg-type]
            "negative_label_scope": "external_rule_specific",
            "cwe_complete_negative_labels": False,
            "seal_status": "open",
        }
        manifest["cases"][0] = {  # type: ignore[index]
            **manifest["cases"][0],  # type: ignore[index]
            "language": "",
            "label_scope": "external_rule_specific",
            "code_hash": "not-a-sha",
        }

        failures = check_sealed_truth_manifest(
            manifest,
            min_positive_cases=2,
            min_negative_cases=2,
        )

        self.assertTrue(any("negative_label_scope" in failure for failure in failures))
        self.assertTrue(any("cwe_complete_negative_labels" in failure for failure in failures))
        self.assertTrue(any("seal_status" in failure for failure in failures))
        self.assertTrue(any("language" in failure for failure in failures))
        self.assertTrue(any("invalid SHA-256" in failure for failure in failures))
        self.assertTrue(any("label_scope" in failure for failure in failures))

    def test_rejects_forbidden_case_and_source_material_reuse(self) -> None:
        manifest = sealed_manifest()
        forbidden = {
            "cases": [
                {"id": "case-pos-1", "code_hash": sha("f")},
                {"id": "other", "code_hash": sha("d")},
            ]
        }

        failures = check_sealed_truth_manifest(
            manifest,
            forbidden_manifests=[forbidden],
            min_positive_cases=2,
            min_negative_cases=2,
        )

        self.assertTrue(any("forbidden case ids" in failure for failure in failures))
        self.assertTrue(any("forbidden source material" in failure for failure in failures))

    def test_existing_go_external_manifest_is_not_sealed_truth(self) -> None:
        manifest = json.loads((ROOT / "config/evaluation/go-external-random-598x2-2026-07-24-v2.json").read_text())

        failures = check_sealed_truth_manifest(manifest)

        self.assertTrue(any("negative_label_scope" in failure for failure in failures))
        self.assertTrue(any("qualification_eligible" in failure for failure in failures))
        self.assertTrue(any("seal_status" in failure for failure in failures))
        self.assertTrue(any("language" in failure for failure in failures))

    def test_cli_writes_audit_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            manifest_path = temp / "sealed.json"
            output_path = temp / "report.json"
            manifest_path.write_text(json.dumps(sealed_manifest()), encoding="utf-8")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "validate_security_truth_manifest.py"),
                    "--manifest",
                    str(manifest_path),
                    "--min-positive-cases",
                    "2",
                    "--min-negative-cases",
                    "2",
                    "--output",
                    str(output_path),
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            report = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(len(report["manifest_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
