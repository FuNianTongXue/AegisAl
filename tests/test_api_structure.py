from __future__ import annotations

import importlib
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.routes import application


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class ApiStructureTests(unittest.TestCase):
    def test_implementations_live_in_their_domain_packages(self) -> None:
        root = Path(__file__).resolve().parents[1] / "app"
        expected = {
            "agent": {"project_adaptive_scan.py", "task_agent.py", "task_store.py"},
            "api/routes": {"application.py"},
            "langgraph": {
                "assistant_graph.py",
                "collector_graph.py",
                "component_catalog_graph.py",
                "component_query_graph.py",
                "report_graph.py",
                "sbom_graph.py",
            },
            "mcp": {
                "component_query.py",
                "report_charts.py",
                "report_markdown.py",
                "report_mermaid.py",
                "report_pdf.py",
                "report_word.py",
                "sbom.py",
            },
        }

        for package, file_names in expected.items():
            package_path = root / package
            self.assertTrue((package_path / "__init__.py").is_file(), package)
            self.assertTrue(file_names.issubset({path.name for path in package_path.glob("*.py")}), package)

    def test_legacy_modules_alias_the_canonical_module_objects(self) -> None:
        aliases = {
            "app.main": "app.api.routes.application",
            "app.graph": "app.langgraph.assistant_graph",
            "app.collector_graph": "app.langgraph.collector_graph",
            "app.component_query_subgraph": "app.langgraph.component_query_graph",
            "app.report_subgraph": "app.langgraph.report_graph",
            "app.component_mcp": "app.mcp.component_query",
            "app.report_mcp": "app.mcp.report_charts",
            "app.task_agent": "app.agent.task_agent",
            "app.task_store": "app.agent.task_store",
            "app.project_adaptive_scan": "app.agent.project_adaptive_scan",
        }

        for legacy_name, canonical_name in aliases.items():
            self.assertIs(importlib.import_module(legacy_name), importlib.import_module(canonical_name))

    def test_openapi_exposes_clear_routes_and_hides_legacy_aliases(self) -> None:
        paths = application.app.openapi()["paths"]
        canonical_paths = {
            "/api/assistant/questions",
            "/api/assistant/questions/stream",
            "/api/assistant/conversations",
            "/api/assistant/conversations/{session_id}",
            "/api/assistant/conversations/{session_id}/archive",
            "/api/agent/tasks",
            "/api/agent/tasks/graph",
            "/api/agent/tasks/{task_id}",
            "/api/agent/tasks/{task_id}/events",
            "/api/langgraph/assistant",
            "/api/langgraph/collectors",
            "/api/system/runtime",
            "/api/reports/actions",
            "/api/reports/actions/resume",
            "/api/assistant/interrupts/resume",
            "/api/assistant/workspace-actions",
            "/api/components/vulnerabilities/query",
            "/api/mcp/tools/component-query",
            "/api/mcp/tools/report-charts",
            "/api/mcp/tools/reports",
            "/api/mcp/tools/project-sbom",
        }
        legacy_paths = {
            "/api/ask",
            "/api/ask/stream",
            "/api/tasks",
            "/api/tasks/graph",
            "/api/tasks/{task_id}",
            "/api/graph",
            "/api/collector-graph",
            "/api/runtime",
            "/api/report-actions",
            "/api/report-actions/resume",
            "/api/memory/conversations",
            "/api/memory/conversations/{session_id}",
        }

        self.assertTrue(canonical_paths.issubset(paths))
        self.assertTrue(legacy_paths.isdisjoint(paths))

    def test_canonical_and_legacy_http_routes_remain_available(self) -> None:
        with (
            patch.object(application, "trial_manager", AlwaysUsableTrial()),
            TestClient(application.app) as client,
        ):
            for path in (
                "/api/langgraph/assistant",
                "/api/graph",
                "/api/langgraph/collectors",
                "/api/collector-graph",
                "/api/system/runtime",
                "/api/runtime",
            ):
                response = client.get(path)
                self.assertEqual(response.status_code, 200, f"{path}: {response.text}")
                self.assertEqual(response.json()["status"], "success")


if __name__ == "__main__":
    unittest.main()
