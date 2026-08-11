from __future__ import annotations

import asyncio
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.agent.task_agent import TaskAgentGraph, TaskAgentService
from app.agent.task_store import AgentTaskStore
from app.api.routes import application
from app.mcp.code_scan import _parent_process_is_alive, _watch_parent, code_scan_mcp_spec
from app.mcp.code_scan_client import CodeScanMCPClient, _server_environment
from app.mcp.license_scan import identify_workspace_licenses, invoke_license_scan_mcp, license_scan_mcp_spec
from app.reports import ReportStore
from app.semgrep_tool import semgrep_rule_paths_for_language


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class ForbiddenCodeScanClient:
    enabled = True

    def scan_language(self, **_kwargs):
        raise AssertionError("frozen evaluation must not call the Code Scan MCP")

    def shutdown(self) -> None:
        return None


def completed_scan_result(language: str = "python") -> dict:
    return {
        "status": "completed",
        "mode": "test",
        "syntax_summary": {
            "languages": [language],
            "parsed_files": 1,
            "parse_error_files": 0,
            "ast_node_count": 3,
            "cfg_node_count": 1,
            "cfg_edge_count": 0,
            "dfg_edge_count": 0,
        },
        "files": [],
        "findings": [],
        "finding_count": 0,
        "review_findings": [],
        "review_finding_count": 0,
        "diagnostics": [],
    }


class CodeScanMCPTests(unittest.TestCase):
    def test_parent_watch_exits_when_parent_is_no_longer_alive(self) -> None:
        with (
            patch("app.mcp.code_scan._parent_process_is_alive", return_value=False),
            patch("app.mcp.code_scan.os._exit", side_effect=SystemExit(0)) as exit_process,
        ):
            with self.assertRaises(SystemExit):
                _watch_parent(43210)

        exit_process.assert_called_once_with(0)

    def test_posix_parent_check_accepts_alive_non_direct_parent(self) -> None:
        with (
            patch("app.mcp.code_scan.sys.platform", "darwin"),
            patch("app.mcp.code_scan.os.getppid", return_value=1),
            patch("app.mcp.code_scan.os.kill") as signal_parent,
        ):
            self.assertTrue(_parent_process_is_alive(43210))

        signal_parent.assert_called_once_with(43210, 0)

    def test_frozen_server_environment_resets_pyinstaller_parent_state(self) -> None:
        inherited = {
            "_PYI_ARCHIVE_FILE": "/Applications/SecFlow.app/backend/secflow-backend",
            "_PYI_PARENT_PROCESS_LEVEL": "1",
            "PYINSTALLER_STRICT_UNPACK_MODE": "1",
            "PYTHONPATH": "/Applications/SecFlow.app/backend/_internal",
        }
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(os.environ, inherited, clear=True),
            patch.object(__import__("sys"), "frozen", True, create=True),
        ):
            environment = _server_environment("capability-token", runtime_path=Path(temp_dir))

        self.assertEqual(environment["PYINSTALLER_RESET_ENVIRONMENT"], "1")
        self.assertNotIn("_PYI_ARCHIVE_FILE", environment)
        self.assertNotIn("_PYI_PARENT_PROCESS_LEVEL", environment)
        self.assertNotIn("PYINSTALLER_STRICT_UNPACK_MODE", environment)
        self.assertNotIn("PYTHONPATH", environment)

    def test_public_mcp_spec_uses_sse_without_exposing_capability_token(self) -> None:
        spec = asyncio.run(code_scan_mcp_spec())
        license_spec = asyncio.run(license_scan_mcp_spec())
        scan_tool = next(item for item in spec["tools"] if item["name"] == "scan_language")
        license_tool = next(item for item in license_spec["tools"] if item["name"] == "identify_project_licenses")

        self.assertEqual(spec["transport"], "sse")
        self.assertEqual(spec["endpoint"], "loopback-managed")
        self.assertNotIn("capability_token", scan_tool["input_schema"]["properties"])
        self.assertNotIn("capability_token", scan_tool["input_schema"].get("required") or [])
        self.assertNotIn("identify_project_licenses", {item["name"] for item in spec["tools"]})
        self.assertEqual(license_spec["name"], "SecFlow License MCP")
        self.assertEqual(set(license_tool["input_schema"]["properties"]), {"workspace_path"})

    def test_license_identification_combines_spdx_manifest_and_license_file_evidence(self) -> None:
        registry = [
            {
                "id": "mit",
                "spdx_id": "MIT",
                "name": "MIT License",
                "approved": True,
                "_links": {"html": {"href": "https://opensource.org/license/mit"}},
            },
            {
                "id": "apache-2-0",
                "spdx_id": "Apache-2.0",
                "name": "Apache License 2.0",
                "approved": True,
                "_links": {"html": {"href": "https://opensource.org/license/apache-2-0"}},
            },
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text('{"name":"demo","license":"MIT"}', encoding="utf-8")
            (root / "NOTICE").write_text(
                "SPDX-License-Identifier: Apache-2.0\n",
                encoding="utf-8",
            )
            (root / "LICENSE").write_text(
                'Permission is hereby granted, free of charge, to any person obtaining a copy.\n'
                'THE SOFTWARE IS PROVIDED "AS IS".\n',
                encoding="utf-8",
            )
            scan = identify_workspace_licenses(root, registry_fetcher=lambda: registry)

        self.assertEqual(scan["coverage_status"], "complete")
        self.assertEqual({item["spdx_id"] for item in scan["licenses"]}, {"MIT", "Apache-2.0"})
        mit = next(item for item in scan["licenses"] if item["spdx_id"] == "MIT")
        self.assertEqual(set(mit["source_files"]), {"LICENSE", "package.json"})
        self.assertTrue(mit["osi"]["listed"])
        self.assertEqual(mit["osi"]["approval_status"], "approved")

    def test_license_identification_keeps_local_results_when_osi_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text('{"name":"demo","license":"MIT"}', encoding="utf-8")

            def unavailable_registry() -> list[dict]:
                raise TimeoutError("registry timeout")

            scan = identify_workspace_licenses(root, registry_fetcher=unavailable_registry)

        self.assertEqual(scan["coverage_status"], "partial")
        self.assertEqual(scan["registry"]["status"], "unavailable")
        self.assertEqual([item["spdx_id"] for item in scan["licenses"]], ["MIT"])
        self.assertFalse(scan["licenses"][0]["osi"]["listed"])

    def test_sse_client_runs_the_engine_in_an_independent_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            client = CodeScanMCPClient(startup_timeout=10)
            try:
                result = client.scan_language(
                    workspace_path=str(root),
                    language="python",
                    source_paths=["app.py"],
                    manifest_files=[],
                    dependency_scan={"files": [], "dependencies": [], "dependency_count": 0},
                    rule_paths=semgrep_rule_paths_for_language("python"),
                    complete_scan=True,
                    cancelled=lambda: False,
                )
            finally:
                client.shutdown()

        audit = result["_scan_mcp"]
        self.assertEqual(audit["transport"], "sse")
        self.assertNotEqual(audit["process_id"], os.getpid())
        self.assertEqual(len(audit["input_sha256"]), 64)
        self.assertEqual(len(audit["output_sha256"]), 64)
        self.assertEqual(result["syntax_summary"]["parsed_files"], 1)

    def test_independent_license_mcp_identifies_project_license_without_code_scan_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "package.json").write_text('{"name":"demo","license":"MIT"}', encoding="utf-8")
            result = invoke_license_scan_mcp({"workspace_path": str(root)})

        audit = result["_license_mcp"]
        self.assertEqual(audit["tool"], "identify_project_licenses")
        self.assertEqual(audit["transport"], "in-process")
        self.assertEqual(audit["process_id"], os.getpid())
        self.assertIn(result["coverage_status"], {"complete", "partial"})
        self.assertEqual([item["spdx_id"] for item in result["licenses"]], ["MIT"])

    def test_agent_capability_allowlist_blocks_cross_boundary_tools(self) -> None:
        code_agent_client = CodeScanMCPClient()
        self.addCleanup(code_agent_client.shutdown)

        self.assertFalse(hasattr(code_agent_client, "identify_project_licenses"))
        with self.assertRaisesRegex(ValueError, "supported tool allowlist"):
            CodeScanMCPClient(allowed_tools={"identify_project_licenses"})

    def test_cancel_active_scan_terminates_mcp_process_and_removes_private_runtime(self) -> None:
        client = CodeScanMCPClient(startup_timeout=10)
        endpoint, _token = client._ensure_server()
        process = client._process
        runtime_path = client._runtime_path
        log_path = client._log_path

        self.assertTrue(endpoint.startswith("http://127.0.0.1:"))
        self.assertIsNotNone(process)
        self.assertIsNotNone(runtime_path)
        self.assertTrue(runtime_path.is_dir())
        client.cancel_active_scan()

        self.assertIsNotNone(process.poll())
        self.assertFalse(runtime_path.exists())
        self.assertFalse(log_path.exists())
        self.assertIsNone(client._process)

    def test_frozen_runtime_allows_for_onefile_mcp_cold_start(self) -> None:
        with patch.object(sys, "frozen", True, create=True):
            client = CodeScanMCPClient()
        self.addCleanup(client.shutdown)

        self.assertEqual(client._startup_timeout, 60.0)

    def test_mcp_startup_timeout_can_be_configured_without_limiting_scan_duration(self) -> None:
        with patch.dict(os.environ, {"SECFLOW_CODE_SCAN_MCP_STARTUP_TIMEOUT_SECONDS": "75"}):
            client = CodeScanMCPClient()
        self.addCleanup(client.shutdown)

        self.assertEqual(client._startup_timeout, 75.0)
        self.assertGreater(client._sse_read_timeout, client._startup_timeout)

    def test_frozen_evaluation_keeps_the_existing_in_process_engine_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            graph = TaskAgentGraph(code_scan_client=ForbiddenCodeScanClient())
            with patch("app.task_agent.semgrep_tool.analyze", return_value=completed_scan_result()):
                state = graph.invoke(
                    task_id="evaluation-frozen-sse-isolation",
                    objective="run frozen evaluation",
                    workspace_path=str(root),
                    user_id="evaluation",
                )
            graph.shutdown()

        self.assertFalse(state["result"]["scan_mcp"]["enabled"])
        self.assertEqual(state["result"]["scan_mcp"]["transport"], "in-process")

    def test_user_api_scan_report_and_download_flow_records_sse_mcp_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "code-scan-mcp-e2e-test-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "uploaded-project"
            root.mkdir()
            sources = {
                "App.java": "// SPDX-License-Identifier: Apache-2.0\nclass App { String run(String value) { return value; } }\n",
                "app.py": "def run(value):\n    return value\n",
                "app.go": "package demo\nfunc run(value string) string { return value }\n",
                "app.c": "const char *run(const char *value) { return value; }\n",
                "app.cpp": "const char *run(const char *value) { return value; }\n",
                "App.cs": "class App { string Run(string value) { return value; } }\n",
                "app.rs": "fn run(value: &str) -> &str { value }\n",
                "app.sol": "pragma solidity ^0.8.0; contract App { function run(uint value) public pure returns (uint) { return value; } }\n",
            }
            for file_name, content in sources.items():
                (root / file_name).write_text(content, encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
            (root / "package.json").write_text('{"name":"uploaded-project","license":"MIT"}\n', encoding="utf-8")
            (root / "LICENSE").write_text(
                'Permission is hereby granted, free of charge, to any person obtaining a copy.\n'
                'THE SOFTWARE IS PROVIDED "AS IS".\n',
                encoding="utf-8",
            )
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                code_scan_client=CodeScanMCPClient(startup_timeout=10),
                overlay_synthesizer=lambda _request: {
                    "status": "no_change",
                    "reason": "integration test keeps the baseline result",
                    "overlay": {},
                },
                adaptive_upload=True,
            )
            reports = ReportStore(Path(temp_dir) / "reports")
            try:
                with (
                    patch.object(application, "task_agent_service", service),
                    patch.object(application, "report_store", reports),
                    patch.object(application, "trial_manager", AlwaysUsableTrial()),
                    patch.object(
                        application,
                        "plan_assistant_intent",
                        return_value={"intent": "project_scan", "reason": "authorized workspace scan"},
                    ),
                    TestClient(application.app) as client,
                ):
                    created = client.post(
                        "/api/assistant/workspace-actions",
                        json={
                            "objective": "扫描我上传的代码项目",
                            "workspace_path": str(root),
                            "user_id": "analyst",
                            "session_id": "code-scan-mcp-e2e",
                            "response_language": "zh-Hans",
                        },
                    )
                    self.assertEqual(created.status_code, 200, created.text)
                    task_id = created.json()["data"]["task"]["id"]
                    task = self._wait_for_task(client, task_id)
                    generated = client.post(
                        f"/api/tasks/{task_id}/report-decision",
                        params={"user_id": "analyst"},
                        json={"generate": True},
                    )
                    downloaded = client.post(
                        f"/api/tasks/{task_id}/report-download-decision",
                        params={"user_id": "analyst"},
                        json={"confirm": True, "format": "html"},
                    )
                    report_content = reports.get_report(generated.json()["data"]["report"]["id"])["content"]
            finally:
                service.shutdown(wait=True)

        self.assertEqual(task["status"], "completed")
        self.assertTrue(task["result"]["scan_mcp"]["enabled"])
        self.assertEqual(task["result"]["scan_mcp"]["transport"], "sse")
        self.assertEqual(
            task["result"]["languages"],
            ["java", "python", "go", "c", "cpp", "csharp", "rust", "solidity"],
        )
        self.assertEqual(task["result"]["scan_mcp"]["invocation_count"], 8)
        self.assertEqual(task["result"]["license_count"], 1)
        self.assertEqual(
            {item["spdx_id"] for item in task["result"]["licenses"]},
            {"MIT"},
        )
        self.assertIn(task["result"]["license_scan"]["coverage_status"], {"complete", "partial"})
        self.assertEqual(set(task["result"]["scan_mcp"]["tools"]), {"scan_language"})
        self.assertTrue(task["result"]["license_mcp"]["enabled"])
        self.assertEqual(task["result"]["license_mcp"]["server"], "SecFlow License MCP")
        self.assertEqual(task["result"]["license_mcp"]["invocation_count"], 1)
        self.assertNotEqual(task["result"]["scan_mcp"]["invocations"][0]["process_id"], os.getpid())
        self.assertEqual(
            {
                item["language"]
                for item in task["result"]["scan_mcp"]["invocations"]
                if item.get("tool") == "scan_language"
            },
            {"java", "python", "go", "c", "cpp", "csharp", "rust", "solidity"},
        )
        self.assertEqual(len({item["process_id"] for item in task["result"]["scan_mcp"]["invocations"]}), 1)
        license_audit = task["result"]["license_mcp"]["invocations"][0]
        self.assertEqual(license_audit["agent_id"], "sbom_agent")
        completed_nodes = {
            event["node"]
            for event in task["events"]
            if event["type"] in {
                "node.completed",
                "adaptation.skipped",
                "verification.completed",
                "task.completed",
            }
        }
        self.assertTrue(
            {
                "inspect_workspace",
                "scan_dependencies",
                "identify_project_licenses",
                "profile_project",
                "scan_java",
                "scan_python",
                "scan_go",
                "scan_c",
                "scan_cpp",
                "scan_csharp",
                "scan_rust",
                "scan_solidity",
                "fuse_analysis_evidence",
                "synthesize_project_overlay",
                "verify_results",
                "compose_result",
            }.issubset(completed_nodes)
        )
        self.assertEqual(generated.status_code, 200, generated.text)
        self.assertEqual(downloaded.status_code, 200, downloaded.text)
        self.assertEqual(downloaded.json()["data"]["artifact"]["media_type"], "text/html; charset=utf-8")
        self.assertIn("### 5.1 项目许可识别", report_content)
        self.assertIn("MIT", report_content)

    @staticmethod
    def _wait_for_task(client: TestClient, task_id: str) -> dict:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            response = client.get(f"/api/tasks/{task_id}", params={"user_id": "analyst"})
            task = response.json()["data"]
            if task["status"] in {"completed", "failed", "cancelled"}:
                return task
            time.sleep(0.05)
        raise AssertionError("SSE MCP task did not finish")


if __name__ == "__main__":
    unittest.main()
