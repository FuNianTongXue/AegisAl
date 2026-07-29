from __future__ import annotations

import json
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from app.project_adaptive_scan import (
    PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION,
    apply_overlay_classification,
    empty_project_overlay,
    load_project_adaptive_scan_skill,
    project_adaptive_skill_metadata,
    project_overlay_rule_file,
    validate_project_overlay,
)
from app.reports import build_agent_task_markdown_report
from app.task_agent import TaskAgentGraph
from app.semgrep_tool import SemgrepTool


def scan_result() -> dict:
    return {
        "status": "completed",
        "mode": "test",
        "syntax_summary": {
            "languages": ["python"],
            "parsed_files": 1,
            "parse_error_files": 0,
            "ast_node_count": 10,
            "cfg_node_count": 2,
            "cfg_edge_count": 1,
            "dfg_edge_count": 1,
        },
        "findings": [
            {
                "id": "primary-1",
                "rule_id": "secflow.python.primary",
                "title": "primary finding",
                "severity": "HIGH",
                "file_name": "app.py",
                "line": 2,
                "description": "request value reaches a reviewed sink",
            }
        ],
        "finding_count": 1,
        "review_findings": [
            {
                "id": "review-1",
                "rule_id": "secflow.python.review",
                "title": "review candidate",
                "severity": "MEDIUM",
                "file_name": "app.py",
                "line": 3,
                "description": "candidate source to sink path",
            }
        ],
        "review_finding_count": 1,
        "diagnostics": [],
    }


class ProjectAdaptiveScanTests(unittest.TestCase):
    def test_packaged_skill_and_prompt_metadata_are_auditable(self) -> None:
        skill = load_project_adaptive_scan_skill()
        metadata = project_adaptive_skill_metadata()

        self.assertIn("Evaluation Isolation", skill)
        self.assertEqual(metadata["name"], "secflow-project-adaptive-scan")
        self.assertEqual(metadata["prompt_version"], PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION)
        self.assertEqual(len(metadata["sha256"]), 64)

    def test_overlay_rejects_unreferenced_actions(self) -> None:
        request = {
            "project_profile": {"languages": ["python"]},
            "evidence": {
                "evidence_ids": ["review:python:review-1"],
                "findings": [],
                "review_findings": [{"finding_id": "review-1"}],
            },
        }
        overlay = validate_project_overlay(
            {
                "decision": "apply_overlay",
                "confidence": 0.99,
                "taint_rules": [
                    {
                        "id": "unreferenced",
                        "language": "python",
                        "sources": ["$REQ.get(...)"],
                        "sinks": ["$DB.execute(...)"],
                        "evidence_ids": ["missing:evidence"],
                    }
                ],
                "promote_review_finding_ids": ["missing-review"],
            },
            request,
        )

        self.assertEqual(overlay["decision"], "no_change")
        self.assertEqual(overlay["taint_rules"], [])
        self.assertEqual(overlay["promote_review_finding_ids"], [])
        self.assertFalse(overlay["global_rule_changes"])

    def test_overlay_rule_file_and_classification_are_project_scoped(self) -> None:
        request = {
            "project_profile": {"languages": ["python"]},
            "evidence": {
                "evidence_ids": ["review:python:review-1", "finding:python:primary-1"],
                "findings": [{"finding_id": "primary-1"}],
                "review_findings": [{"finding_id": "review-1"}],
            },
        }
        overlay = validate_project_overlay(
            {
                "decision": "apply_overlay",
                "reason": "project wrapper evidence",
                "confidence": 0.95,
                "taint_rules": [
                    {
                        "id": "custom-wrapper-flow",
                        "language": "python",
                        "message": "custom wrapper taint flow",
                        "sources": ["$REQ.get(...)"],
                        "sinks": ["$DB.execute(...)"],
                        "sanitizers": ["sanitize(...)"],
                        "evidence_ids": ["review:python:review-1"],
                    }
                ],
                "promote_review_finding_ids": ["review-1"],
                "demote_finding_ids": ["primary-1"],
            },
            request,
        )

        with project_overlay_rule_file(overlay, "python") as path:
            self.assertIsNotNone(path)
            payload = json.loads(Path(str(path)).read_text(encoding="utf-8"))
            rule = payload["rules"][0]
            self.assertEqual(rule["id"], "secflow.project.custom-wrapper-flow")
            self.assertEqual(rule["metadata"]["secflow_scope"], "project-task-only")
            self.assertEqual(rule["pattern-sources"], [{"pattern": "$REQ.get(...)"}])

        adapted = apply_overlay_classification(scan_result(), overlay)
        self.assertEqual([item["id"] for item in adapted["findings"]], ["review-1"])
        self.assertEqual([item["id"] for item in adapted["review_findings"]], ["primary-1"])
        self.assertEqual(adapted["finding_count"], 1)
        self.assertEqual(adapted["project_overlay"]["fingerprint"], overlay["fingerprint"])

    def test_adaptive_upload_rescans_once_and_stops_on_no_change(self) -> None:
        scanner_calls: list[list[str]] = []
        synthesis_calls: list[dict] = []

        def scanner(_language, _attachments, _dependency_scan, rules, _cancelled):
            scanner_calls.append(list(rules))
            if len(scanner_calls) == 2:
                overlay_paths = [Path(value) for value in rules if Path(value).suffix == ".json"]
                self.assertEqual(len(overlay_paths), 1)
                payload = json.loads(overlay_paths[0].read_text(encoding="utf-8"))
                self.assertEqual(payload["rules"][0]["id"], "secflow.project.custom-wrapper-flow")
            return scan_result()

        def synthesizer(request):
            synthesis_calls.append(request)
            if len(synthesis_calls) > 1:
                return {"status": "no_change", "reason": "stable", "overlay": empty_project_overlay("stable")}
            candidate = {
                "decision": "apply_overlay",
                "reason": "restore reviewed project flow",
                "confidence": 0.95,
                "taint_rules": [
                    {
                        "id": "custom-wrapper-flow",
                        "language": "python",
                        "message": "custom wrapper taint flow",
                        "sources": ["$REQ.get(...)"],
                        "sinks": ["$DB.execute(...)"],
                        "evidence_ids": ["review:python:review-1"],
                    }
                ],
                "promote_review_finding_ids": ["review-1"],
                "demote_finding_ids": ["primary-1"],
            }
            return {
                "status": "ready",
                "reason": "ready",
                "overlay": validate_project_overlay(candidate, request),
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("value = request.get('id')\ndb.execute(value)\n", encoding="utf-8")
            state = TaskAgentGraph(
                language_scanner=scanner,
                overlay_synthesizer=synthesizer,
                adaptive_upload=True,
            ).invoke(
                task_id="upload-adaptive-1",
                objective="scan uploaded project",
                workspace_path=str(root),
                user_id="analyst",
            )

        self.assertEqual(len(scanner_calls), 2)
        self.assertEqual(len(synthesis_calls), 2)
        self.assertEqual(state["result"]["scan_mode"], "adaptive_upload")
        self.assertEqual(state["adaptation"]["iterations"], 1)
        self.assertEqual(state["adaptation"]["status"], "no_change")
        self.assertEqual(len(state["adaptation"]["overlays"]), 1)
        self.assertEqual(
            [item["id"] for item in state["language_results"]["python"]["findings"]],
            ["review-1"],
        )
        report = build_agent_task_markdown_report(
            {
                "workspace_name": "demo",
                "workspace_path": "/tmp/demo",
                "workspace_type": "directory",
                "objective": "scan uploaded project",
                "events": [],
                "result": state["result"],
            }
        )
        self.assertIn("## 7. 项目自适应与回归审计", report)
        self.assertIn(PROJECT_ADAPTIVE_SCAN_PROMPT_VERSION, report)
        self.assertIn(state["adaptation"]["overlays"][0]["fingerprint"], report)

    def test_overlay_parser_definition_reaches_tree_sitter_rescan(self) -> None:
        source = """
int run(
#ifdef PROJECT_FEATURE
    int value
#else
    void
#endif
) { return 0; }
"""
        with patch.dict("os.environ", {"SECFLOW_SEMGREP_DISABLE_CLI": "1"}):
            result = SemgrepTool().analyze(
                [{"file_name": "feature.c", "content": source}],
                {
                    "files": [],
                    "dependencies": [],
                    "project_preprocessor_definitions": {"PROJECT_FEATURE": "1"},
                },
                [],
                language_hint="c",
            )

        syntax = result["files"][0]["syntax"]
        self.assertFalse(syntax["parse_error"])
        self.assertEqual(syntax["parser_mode"], "preprocessor-defs")
        self.assertEqual(syntax["preprocessor_definition_count"], 1)

    def test_evaluation_task_never_invokes_overlay_synthesizer(self) -> None:
        scanner_calls = 0

        def scanner(_language, _attachments, _dependency_scan, _rules, _cancelled):
            nonlocal scanner_calls
            scanner_calls += 1
            return scan_result()

        def forbidden_synthesizer(_request):
            raise AssertionError("evaluation task must not invoke the model")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("print('baseline')\n", encoding="utf-8")
            state = TaskAgentGraph(
                language_scanner=scanner,
                overlay_synthesizer=forbidden_synthesizer,
                adaptive_upload=True,
            ).invoke(
                task_id="evaluation-fixed-corpus",
                objective="run frozen baseline",
                workspace_path=str(root),
                user_id="evaluation",
            )

        self.assertEqual(scanner_calls, 1)
        self.assertEqual(state["result"]["scan_mode"], "frozen_evaluation")
        self.assertEqual(state["adaptation"]["attempts"], 0)
        self.assertEqual(state["adaptation"]["termination_reason"], "frozen_evaluation")


if __name__ == "__main__":
    unittest.main()
