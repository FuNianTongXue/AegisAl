from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.task_agent import compact_language_result
from scripts.attribute_github_multilang_parse_errors import build_report, summarize_parse_error_name_coverage
from scripts.evaluate_github_multilang import scan_project


class FakeTaskAgentGraph:
    def __init__(self, *, adaptive_upload: bool) -> None:
        self.adaptive_upload = adaptive_upload

    def invoke(self, **_: object) -> dict[str, object]:
        parse_error_names = [f"src/file_{index}.c" for index in range(101)]
        parse_error_details = [
            {
                "file_name": file_name,
                "language": "c",
                "parser_mode": "native",
                "parser_error_nodes": 1,
                "raw_parse_error": True,
                "recovered_parse_error": False,
            }
            for file_name in parse_error_names
        ]
        return {
            "result": {
                "languages": ["c"],
                "total_files": 101,
                "dependency_count": 0,
                "total_findings": 0,
                "total_review_findings": 0,
                "language_results": {
                    "c": {
                        "syntax_summary": {
                            "parse_error_files": 101,
                            "raw_parse_error_files": 101,
                            "recovered_parse_error_files": 0,
                            "parse_error_file_names": parse_error_names,
                        },
                        "parse_error_file_details": parse_error_details,
                        "findings": [],
                        "review_findings": [],
                    }
                },
            }
        }


class GithubMultilangEvaluationTests(unittest.TestCase):
    def test_scan_project_preserves_all_parse_error_file_names(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "scripts.evaluate_github_multilang.TaskAgentGraph",
            FakeTaskAgentGraph,
        ), patch(
            "scripts.evaluate_github_multilang.collect_workspace_inventory",
            return_value={"manifest_files": [], "unsupported_files": [], "skipped_files": 0},
        ):
            result = scan_project(
                Path(temp_dir),
                {"slug": "owner/repo", "language": "C"},
                scan_timeout=1,
            )

        self.assertEqual(result["parse_errors"], 101)
        self.assertEqual(len(result["parse_error_file_names"]), 101)
        self.assertEqual(result["parse_error_file_names_count"], 101)
        self.assertFalse(result["parse_error_file_names_truncated"])
        self.assertEqual(result["parse_error_file_details_count"], 101)
        self.assertEqual(result["parse_error_file_details"][0]["parser_mode"], "native")

    def test_compact_language_result_keeps_only_parse_error_details(self) -> None:
        compact = compact_language_result(
            "c",
            {
                "syntax_summary": {"parse_error_files": 1},
                "files": [
                    {
                        "file_name": "src/bad.c",
                        "language": "c",
                        "syntax": {
                            "file": "src/bad.c",
                            "language": "c",
                            "parse_error": True,
                            "parser_mode": "native",
                            "parser_error_nodes": 2,
                            "raw_parse_error": True,
                            "recovered_parse_error": False,
                        },
                    },
                    {
                        "file_name": "src/good.c",
                        "language": "c",
                        "syntax": {
                            "file": "src/good.c",
                            "language": "c",
                            "parse_error": False,
                            "parser_mode": "native",
                        },
                    },
                ],
            },
            ["src/bad.c", "src/good.c"],
            [],
        )

        self.assertEqual(
            compact["parse_error_file_details"],
            [
                {
                    "file_name": "src/bad.c",
                    "language": "c",
                    "parser_mode": "native",
                    "parser_error_nodes": 2,
                    "raw_parse_error": True,
                    "recovered_parse_error": False,
                }
            ],
        )

    def test_scan_project_restores_semgrep_timeout_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "scripts.evaluate_github_multilang.TaskAgentGraph",
            FakeTaskAgentGraph,
        ), patch(
            "scripts.evaluate_github_multilang.collect_workspace_inventory",
            return_value={"manifest_files": [], "unsupported_files": [], "skipped_files": 0},
        ), patch.dict(
            os.environ,
            {"SECFLOW_SEMGREP_TIMEOUT_SECONDS": "240"},
        ):
            scan_project(
                Path(temp_dir),
                {"slug": "owner/repo", "language": "C"},
                scan_timeout=1,
            )

            self.assertEqual(os.environ["SECFLOW_SEMGREP_TIMEOUT_SECONDS"], "240")

    def test_parse_error_attribution_reports_legacy_name_truncation(self) -> None:
        result = {
            "projects": [
                {
                    "slug": "owner/a",
                    "status": "completed",
                    "expected_language": "C",
                    "parse_errors": 3,
                    "parse_error_file_names": ["a.c", "b.c"],
                },
                {
                    "slug": "owner/b",
                    "status": "completed",
                    "expected_language": "Go",
                    "parse_errors": 0,
                    "parse_error_file_names": [],
                },
            ]
        }

        summary, by_language, truncated_projects = summarize_parse_error_name_coverage(result)

        self.assertEqual(summary["parse_errors"], 3)
        self.assertEqual(summary["recorded_parse_error_file_names"], 2)
        self.assertEqual(summary["recorded_parse_error_file_details"], 0)
        self.assertEqual(summary["unrecorded_parse_error_file_names"], 1)
        self.assertFalse(summary["complete_per_file_attribution_possible"])
        self.assertFalse(summary["complete_parse_error_detail_coverage"])
        self.assertEqual(by_language["C"]["projects_with_truncated_parse_error_names"], 1)
        self.assertEqual(truncated_projects[0]["slug"], "owner/a")

    def test_parse_error_attribution_reports_detail_coverage(self) -> None:
        result = {
            "projects": [
                {
                    "slug": "owner/a",
                    "status": "completed",
                    "expected_language": "C",
                    "parse_errors": 1,
                    "parse_error_file_names": ["a.c"],
                    "parse_error_file_details": [
                        {
                            "file_name": "a.c",
                            "language": "c",
                            "parser_mode": "native",
                            "parser_error_nodes": 1,
                        }
                    ],
                }
            ]
        }

        summary, by_language, truncated_projects = summarize_parse_error_name_coverage(result)

        self.assertEqual(summary["recorded_detail_coverage_rate"], 1.0)
        self.assertTrue(summary["complete_per_file_attribution_possible"])
        self.assertTrue(summary["complete_parse_error_detail_coverage"])
        self.assertEqual(by_language["C"]["recorded_detail_coverage_rate"], 1.0)
        self.assertEqual(truncated_projects, [])

    def test_parse_error_attribution_folds_parser_delta_evidence(self) -> None:
        result = {
            "projects": [
                {
                    "slug": "owner/a",
                    "status": "completed",
                    "expected_language": "C",
                    "parse_errors": 1,
                    "parse_error_file_names": ["a.c"],
                }
            ]
        }
        delta = {
            "delta_revision": "delta",
            "metric_scope": "parser_recovery_delta_on_recorded_revision4_parse_errors",
            "summary": {
                "candidate_files": 1,
                "analyzed_files": 1,
                "source_stub_files": 0,
                "newly_recovered_files": 0,
                "still_parse_error_files": 1,
                "recovery_rate_on_analyzed_files": 0.0,
            },
            "projects": [
                {
                    "slug": "owner/a",
                    "files": [
                        {
                            "file_name": "a.c",
                            "current_parse_error": True,
                            "parser_mode": "native",
                            "parser_error_classes": ["syntactically_incomplete_source"],
                        }
                    ],
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            delta_path = Path(temp_dir) / "delta.json"
            delta_path.write_text(json.dumps(delta), encoding="utf-8")
            report = build_report(
                result,
                result_path=Path(temp_dir) / "result.json",
                parser_delta_paths=[delta_path],
            )

        evidence = report["parser_delta_evidence"][0]
        self.assertEqual(evidence["still_parse_error_files"], 1)
        self.assertEqual(evidence["error_class_counts"], {"syntactically_incomplete_source": 1})
        self.assertEqual(evidence["remaining_files"][0]["file_name"], "a.c")


if __name__ == "__main__":
    unittest.main()
