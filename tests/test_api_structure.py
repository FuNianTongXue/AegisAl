from __future__ import annotations

import importlib
import json
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
    def test_openapi_uses_current_public_brand(self) -> None:
        self.assertEqual(application.app.openapi()["info"]["title"], "AegisAl")
        documented = json.loads(
            (Path(__file__).resolve().parents[1] / "docs" / "openapi.json").read_text(encoding="utf-8")
        )
        self.assertEqual(documented["info"]["title"], "AegisAl")

    def test_vulnerability_read_routes_forward_requested_language(self) -> None:
        localized = {
            "vulnerability_count": 1,
            "severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "recent_records": [
                {
                    "id": "CVE-2026-1234",
                    "title": "繁體中文漏洞標題",
                    "summary": "繁體中文漏洞描述。",
                    "content_language": "zh-Hant",
                    "translation_status": "translated",
                }
            ],
            "response_language": "zh-Hant",
            "catalog_translation": {"status": "completed", "target_language": "zh-Hant"},
            "translation_status": "completed",
            "translation_progress": 100,
            "translation_count": 1,
            "translation_ready_count": 1,
        }
        with patch.object(application.intelligence_service, "dashboard", return_value=localized) as dashboard:
            dashboard_response = application.dashboard(response_language="zh-Hant")
            records_response = application.vulnerabilities(response_language="zh-Hant")

        self.assertEqual(dashboard.call_count, 2)
        self.assertEqual(
            [call.kwargs["response_language"] for call in dashboard.call_args_list],
            ["zh-Hant", "zh-Hant"],
        )
        self.assertEqual(dashboard_response.data["recent_records"][0]["content_language"], "zh-Hant")
        self.assertEqual(records_response.data["records"][0]["summary"], "繁體中文漏洞描述。")
        self.assertEqual(records_response.data["response_language"], "zh-Hant")
        self.assertEqual(records_response.data["translation_count"], 1)
        self.assertEqual(records_response.data["translation_ready_count"], 1)

    def test_vulnerability_search_forwards_cve_to_full_catalog_query(self) -> None:
        result = {
            "records": [
                {
                    "id": "CVE-2026-98765",
                    "title": "目标漏洞",
                    "summary": "目标漏洞描述。",
                    "severity": "CRITICAL",
                    "content_language": "zh-Hans",
                    "translation_status": "translated",
                }
            ],
            "catalog_translation": {
                "status": "completed",
                "record_count": 1,
                "ready_records": 1,
            },
        }
        with patch.object(application.intelligence_service, "query", return_value=result) as query:
            response = application.vulnerabilities(
                query=" CVE-2026-98765 ",
                response_language="zh-Hans",
            )

        query.assert_called_once_with(
            "CVE-2026-98765",
            limit=50,
            response_language="zh-Hans",
        )
        self.assertEqual(response.data["records"][0]["id"], "CVE-2026-98765")
        self.assertEqual(response.data["stats"]["critical"], 1)
        self.assertEqual(response.data["translation_progress"], 100)

    def test_implementations_live_in_their_domain_packages(self) -> None:
        root = Path(__file__).resolve().parents[1] / "app"
        expected = {
            "agent": {"project_adaptive_scan.py", "task_agent.py", "task_store.py", "task_worker.py"},
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
                "code_scan.py",
                "code_scan_client.py",
                "component_query.py",
                "report_charts.py",
                "report_excel.py",
                "report_markdown.py",
                "report_mermaid.py",
                "report_pdf.py",
                "report_template.py",
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
            "/api/assistant/short-term-sessions/{session_id}",
            "/api/agent/tasks",
            "/api/agent/tasks/graph",
            "/api/agent/tasks/{task_id}",
            "/api/agent/tasks/{task_id}/events",
            "/api/langgraph/assistant",
            "/api/langgraph/collectors",
            "/api/system/runtime",
            "/api/system/capabilities",
            "/api/reports/actions",
            "/api/reports/actions/resume",
            "/api/assistant/interrupts/resume",
            "/api/assistant/workspace-actions",
            "/api/components/vulnerabilities/query",
            "/api/mcp/tools/component-query",
            "/api/mcp/tools/code-scan",
            "/api/mcp/tools/license-scan",
            "/api/mcp/tools/report-charts",
            "/api/mcp/tools/reports",
            "/api/mcp/tools/project-sbom",
            "/api/mcp/tools/translation",
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

    def test_capability_catalog_is_read_from_runtime_registries(self) -> None:
        with (
            patch.object(application, "trial_manager", AlwaysUsableTrial()),
            TestClient(application.app) as client,
        ):
            response = client.get("/api/system/capabilities")

        self.assertEqual(response.status_code, 200, response.text)
        catalog = response.json()["data"]
        self.assertEqual(catalog["schema_version"], "secflow.client-capabilities/v1")
        self.assertEqual(catalog["summary"]["agent_count"], len(catalog["agents"]))
        self.assertEqual(catalog["summary"]["mcp_server_count"], len(catalog["mcp_servers"]))
        self.assertEqual(catalog["summary"]["skill_count"], len(catalog["skills"]))
        server_ids = {item["id"] for item in catalog["mcp_servers"]}
        self.assertIn("report-template", server_ids)
        self.assertIn("report-excel", server_ids)
        self.assertTrue(any(item["id"] == "secflow-report-generation" for item in catalog["skills"]))


if __name__ == "__main__":
    unittest.main()
