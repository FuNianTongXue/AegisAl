from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.evaluate_parser_recovery_delta import build_sample_plan, evaluate_project, parser_error_diagnostics, summarize


class ParserRecoveryDeltaTests(unittest.TestCase):
    def test_build_sample_plan_filters_by_slug_language_and_limits_files(self) -> None:
        manifest = {
            "projects": [
                {"slug": "demo/c", "ref": "a" * 40, "language": "C"},
                {"slug": "demo/cpp", "ref": "b" * 40, "language": "C++"},
            ]
        }
        previous = {
            "projects": [
                {
                    "slug": "demo/c",
                    "expected_language": "C",
                    "evaluator_revision": "old",
                    "parse_errors": 3,
                    "raw_parse_errors": 4,
                    "recovered_parse_errors": 1,
                    "parse_error_file_names": ["a.c", "b.c", "b.c"],
                },
                {
                    "slug": "demo/cpp",
                    "expected_language": "C++",
                    "parse_error_file_names": ["a.cpp"],
                },
            ]
        }

        plan = build_sample_plan(
            manifest,
            previous,
            slugs={"demo/c"},
            languages={"C"},
            limit=1,
            max_files_per_project=2,
        )

        self.assertEqual(len(plan), 1)
        self.assertEqual(plan[0]["slug"], "demo/c")
        self.assertEqual(plan[0]["ref"], "a" * 40)
        self.assertEqual(plan[0]["files"], ["a.c"])
        self.assertEqual(plan[0]["previous_parse_errors"], 3)
        self.assertEqual(plan[0]["previous_recovered_parse_errors"], 1)

    def test_summarize_counts_recovered_and_unavailable_files(self) -> None:
        summary = summarize(
            [
                {
                    "candidate_files": 3,
                    "analyzed_files": 2,
                    "source_stub_files": 1,
                    "newly_recovered_files": 1,
                    "still_parse_error_files": 1,
                    "unavailable_files": 1,
                    "files": [{"parser_error_classes": ["compiler_extension"]}],
                },
                {
                    "candidate_files": 1,
                    "analyzed_files": 0,
                    "source_stub_files": 0,
                    "newly_recovered_files": 0,
                    "still_parse_error_files": 0,
                    "unavailable_files": 1,
                    "files": [],
                },
            ]
        )

        self.assertEqual(summary["projects"], 2)
        self.assertEqual(summary["candidate_files"], 4)
        self.assertEqual(summary["analyzed_files"], 2)
        self.assertEqual(summary["source_stub_files"], 1)
        self.assertEqual(summary["newly_recovered_files"], 1)
        self.assertEqual(summary["unavailable_files"], 2)
        self.assertEqual(summary["recovery_rate_on_analyzed_files"], 0.5)
        self.assertEqual(summary["failed_projects"], 1)
        self.assertEqual(summary["error_class_counts"], {"compiler_extension": 1})

    def test_evaluate_project_applies_compile_database_definitions(self) -> None:
        source = """
int run(
#ifdef FEATURE_ENABLED
    int value
#else
    void
#endif
) { return 0; }
"""
        compile_database = """
[
  {
    "directory": "/work/project",
    "file": "/work/project/src/feature.c",
    "arguments": ["clang", "-DFEATURE_ENABLED=1", "-c", "src/feature.c"]
  }
]
"""
        with (
            patch(
                "scripts.evaluate_parser_recovery_delta.fetch_project_compile_databases",
                return_value=[{"file_name": "compile_commands.json", "content": compile_database}],
            ),
            patch("scripts.evaluate_parser_recovery_delta.fetch_pinned_file", return_value=source),
        ):
            result = evaluate_project(
                {
                    "slug": "demo/project",
                    "ref": "a" * 40,
                    "expected_language": "C",
                    "files": ["src/feature.c"],
                },
                cache_dir=Path("/tmp/secflow-test-cache"),
                timeout=1,
            )

        self.assertEqual(result["compile_database_files"], ["compile_commands.json"])
        self.assertEqual(result["compile_definition_entries"], 1)
        self.assertEqual(result["newly_recovered_files"], 1)
        self.assertEqual(result["files"][0]["parser_mode"], "preprocessor-defs")
        self.assertEqual(result["files"][0]["preprocessor_definition_count"], 1)

    def test_evaluate_project_skips_archive_materialized_source_stubs(self) -> None:
        with (
            patch("scripts.evaluate_parser_recovery_delta.fetch_project_compile_databases", return_value=[]),
            patch("scripts.evaluate_parser_recovery_delta.fetch_project_cmake_files", return_value=[]),
            patch("scripts.evaluate_parser_recovery_delta.fetch_pinned_file", return_value="../../real/target.cc"),
        ):
            result = evaluate_project(
                {
                    "slug": "demo/project",
                    "ref": "a" * 40,
                    "expected_language": "C++",
                    "files": ["src/alias.cc"],
                },
                cache_dir=Path("/tmp/secflow-test-cache"),
                timeout=1,
            )

        self.assertEqual(result["candidate_files"], 1)
        self.assertEqual(result["analyzed_files"], 0)
        self.assertEqual(result["source_stub_files"], 1)
        self.assertEqual(result["newly_recovered_files"], 0)
        self.assertEqual(result["still_parse_error_files"], 0)
        self.assertEqual(result["unavailable_files"], 0)
        self.assertEqual(result["files"][0]["status"], "skipped_source_stub")
        self.assertEqual(result["files"][0]["stub_target"], "../../real/target.cc")

    def test_parser_error_diagnostics_classifies_remaining_errors(self) -> None:
        diagnostics = parser_error_diagnostics(
            "driver.c",
            "int run(void) { __asm mov eax, eax; return 0; }\n",
        )

        self.assertTrue(diagnostics)
        self.assertEqual(diagnostics[0]["classification"], "compiler_extension")
        self.assertGreaterEqual(diagnostics[0]["line"], 1)
        self.assertIn("__asm", diagnostics[0]["snippet"])
        self.assertIn("start_point", diagnostics[0])
        self.assertIn("end_point", diagnostics[0])

    def test_parser_error_diagnostics_reports_missing_syntax_nodes(self) -> None:
        diagnostics = parser_error_diagnostics(
            "driver.c",
            "struct packet_header {\n    unsigned char packet[8]\n};\n",
        )

        self.assertTrue(diagnostics)
        self.assertEqual(diagnostics[0]["node_type"], ";")
        self.assertTrue(diagnostics[0]["missing"])
        self.assertEqual(diagnostics[0]["classification"], "syntactically_incomplete_source")
        self.assertEqual(diagnostics[0]["start_point"][0], 2)


if __name__ == "__main__":
    unittest.main()
