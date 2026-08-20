from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import patch

from app.api.routes import application
from app.composition import SecFlowRuntime


class ApplicationPluginRuntimeTests(unittest.TestCase):
    def test_application_lifecycle_boots_and_closes_plugin_runtime(self) -> None:
        events: list[str] = []
        with (
            patch.dict(os.environ, {"SECFLOW_DISABLE_BATCH_SCHEDULER": "0"}),
            patch.object(
                application,
                "secflow_runtime",
                side_effect=lambda: events.append("runtime.boot"),
            ),
            patch.object(
                application,
                "shutdown_secflow_runtime",
                side_effect=lambda: events.append("runtime.shutdown"),
            ),
            patch.object(
                application.report_store,
                "sanitize_existing_reports",
                side_effect=lambda: events.append("reports.sanitize"),
            ),
            patch.object(
                application.task_agent_service,
                "start",
                side_effect=lambda: events.append("tasks.start"),
            ),
            patch.object(
                application.task_agent_service,
                "shutdown",
                side_effect=lambda: events.append("tasks.shutdown"),
            ),
            patch.object(
                application.intelligence_service,
                "start_batch_scheduler",
                side_effect=lambda: events.append("scheduler.start"),
            ),
            patch.object(
                application.intelligence_service,
                "stop_batch_scheduler",
                side_effect=lambda: events.append("scheduler.stop"),
            ),
        ):
            application.startup_batch_jobs()
            application.shutdown_batch_jobs()

        self.assertEqual(
            events,
            [
                "runtime.boot",
                "reports.sanitize",
                "tasks.start",
                "scheduler.start",
                "scheduler.stop",
                "tasks.shutdown",
                "runtime.shutdown",
            ],
        )

    def test_shutdown_releases_runtime_when_task_shutdown_fails(self) -> None:
        with (
            patch.object(application.intelligence_service, "stop_batch_scheduler"),
            patch.object(
                application.task_agent_service,
                "shutdown",
                side_effect=RuntimeError("task shutdown failed"),
            ),
            patch.object(application, "shutdown_secflow_runtime") as shutdown_runtime,
        ):
            with self.assertRaisesRegex(RuntimeError, "task shutdown failed"):
                application.shutdown_batch_jobs()

        shutdown_runtime.assert_called_once_with()

    def test_mcp_description_routes_read_isolated_servers_from_registry(self) -> None:
        runtime = SecFlowRuntime()
        cases = (
            (
                application.component_query_mcp_tools,
                "servers",
                ["component-detail", "excel", "d3-sankey"],
            ),
            (application.code_scan_mcp_tools, "server", ["code-scan"]),
            (application.license_scan_mcp_tools, "server", ["license-scan"]),
            (application.project_sbom_mcp_tools, "servers", ["sbom-excel"]),
            (application.translation_mcp_tools, "server", ["translation"]),
            (
                application.report_chart_mcp_tools,
                "servers",
                list(application.REPORT_MCP_SERVER_IDS),
            ),
        )
        try:
            with patch.object(application, "secflow_runtime", return_value=runtime):
                for endpoint, result_key, expected_ids in cases:
                    payload = asyncio.run(endpoint()).data
                    self.assertEqual(payload["transport"], "stdio")
                    self.assertEqual(payload["isolation"], "host-managed-child-process")
                    raw_servers = payload[result_key]
                    servers = raw_servers if isinstance(raw_servers, list) else [raw_servers]
                    self.assertEqual([item["id"] for item in servers], expected_ids)
                    for server in servers:
                        self.assertEqual(server["transport"], "stdio")
                        self.assertEqual(server["isolation"], "host-managed-child-process")
                        self.assertEqual(server["plugin_id"], "secflow.mcp")
                        self.assertTrue(server["tools"])
                        namespace = server["id"].replace("-", "_").replace(".", "_")
                        self.assertTrue(
                            all(
                                tool["id"].startswith(f"mcp__{namespace}__")
                                for tool in server["tools"]
                            )
                        )
        finally:
            runtime.close()

        self.assertFalse(hasattr(application, "component_mcp_specs"))
        self.assertFalse(hasattr(application, "code_scan_mcp_spec"))
        self.assertFalse(hasattr(application, "report_mcp_specs"))


if __name__ == "__main__":
    unittest.main()
