from __future__ import annotations

import os
import sqlite3
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

os.environ.setdefault("SECFLOW_DISABLE_BATCH_SCHEDULER", "1")

from fastapi.testclient import TestClient

import app.main as main_module
from app.language_support import language_for_file
from app.memory import LongTermMemoryService
from app.reports import ReportStore, build_agent_task_markdown_report, build_scan_result_json
from app.secure_storage import encrypt_json_to_text, is_encrypted_text
from app.task_agent import (
    TaskAgentGraph,
    TaskAgentService,
    agent_task_report_metrics,
    agent_task_report_ready,
    collect_workspace_inventory,
    compact_task_finding,
    read_workspace_attachments,
    remember_project_submission,
    task_assistant_context,
    task_finding_fingerprint,
)
from app.task_store import AgentTaskStore


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class TaskReportReadinessTests(unittest.TestCase):
    def test_same_rule_findings_keep_distinct_stable_evidence_fingerprints(self) -> None:
        first = {
            "finding_fingerprint": "legacy-collision",
            "rule_id": "secflow.java.unsafe-deserialization",
            "path": "src/App.java",
            "line": 30,
            "source": {"file": "src/App.java", "kind": "source", "snippet": "parseYaml(yamlText)"},
            "sink": {"file": "src/App.java", "kind": "sink", "snippet": "yaml.load(yamlText)"},
        }
        second = {
            "finding_fingerprint": "legacy-collision",
            "rule_id": "secflow.java.unsafe-deserialization",
            "path": "src/App.java",
            "line": 40,
            "source": {"file": "src/App.java", "kind": "source", "snippet": "parseJson(jsonText)"},
            "sink": {"file": "src/App.java", "kind": "sink", "snippet": "mapper.readValue(jsonText)"},
        }
        moved = {**first, "line": 130, "source": {**first["source"], "line": 127}, "sink": {**first["sink"], "line": 130}}
        task = {
            "id": "task-two-paths",
            "status": "completed",
            "result": {
                "total_findings": 2,
                "language_results": {"java": {"findings": [first, second]}},
            },
        }

        context = task_assistant_context(task)

        self.assertEqual(len(context["findings"]), 2)
        self.assertTrue(all(item["engine_finding_fingerprint"] == "legacy-collision" for item in context["findings"]))
        self.assertNotEqual(task_finding_fingerprint(first), task_finding_fingerprint(second))
        self.assertEqual(task_finding_fingerprint(first), task_finding_fingerprint(moved))

    def test_report_readiness_requires_terminal_plan_and_completion_event(self) -> None:
        task = {
            "status": "completed",
            "result": {"summary": "done"},
            "plan": [{"id": "scan", "status": "running"}],
            "events": [{"type": "task.completed", "status": "completed"}],
        }
        self.assertFalse(agent_task_report_ready(task))

        task["plan"][0]["status"] = "completed"
        self.assertTrue(agent_task_report_ready(task))

    def test_report_readiness_rejects_degraded_language_scan(self) -> None:
        task = {
            "status": "completed",
            "result": {
                "summary": "scan returned fallback data",
                "languages": ["python"],
                "language_results": {
                    "python": {
                        "status": "warning",
                        "mode": "internal-fallback",
                        "file_count": 1,
                        "diagnostics": ["静态分析 CLI 未返回 JSON"],
                    }
                },
            },
            "plan": [{"id": "scan", "status": "completed"}],
            "events": [{"type": "task.completed", "status": "completed"}],
        }

        self.assertFalse(agent_task_report_ready(task))

    def test_report_events_do_not_replace_scan_current_node(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-report-current-node-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.json")
            store.create(
                {
                    "id": "task-current-node",
                    "user_id": "analyst",
                    "status": "completed",
                    "current_node": "compose_result",
                    "events": [],
                }
            )
            store.add_event(
                "task-current-node",
                event_type="report.generated",
                node="report_capability_subgraph",
                status="completed",
                message="报告已生成",
            )

            self.assertEqual(store.get("task-current-node")["current_node"], "compose_result")


class ProjectMemoryAndLicenseReportTests(unittest.TestCase):
    def test_project_submission_is_persisted_only_for_the_owning_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "project-memory-user-isolation-key"},
        ):
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            with patch("app.memory.memory_service", service):
                remember_project_submission(
                    {
                        "id": "task-a",
                        "objective": "完整扫描支付服务",
                        "workspace_path": "/tmp/payments-a",
                        "workspace_name": "payments-a",
                        "user_id": "user-a",
                        "session_id": "session-a",
                        "run_number": 1,
                    }
                )
                remember_project_submission(
                    {
                        "id": "task-b",
                        "objective": "完整扫描结算服务",
                        "workspace_path": "/tmp/settlement-b",
                        "workspace_name": "settlement-b",
                        "user_id": "user-b",
                        "session_id": "session-b",
                        "run_number": 1,
                    }
                )

            user_a = service.get_history("user-a")
            user_b = service.get_history("user-b")

        self.assertEqual(len(user_a), 1)
        self.assertEqual(len(user_b), 1)
        self.assertEqual(user_a[0]["sessionId"], "session-a")
        self.assertEqual(user_a[0]["answerPayload"]["mode"], "project_submission")
        self.assertIn("payments-a", user_a[0]["answer"])
        self.assertNotIn("settlement-b", user_a[0]["answer"])
        self.assertIn("settlement-b", user_b[0]["answer"])

    def test_code_scan_report_and_canonical_json_include_project_license_facts(self) -> None:
        license_fact = {
            "spdx_id": "Apache-2.0",
            "name": "Apache License 2.0",
            "confidence": 0.95,
            "source_files": ["LICENSE"],
            "detection_methods": ["license-text-signature"],
            "osi": {
                "listed": True,
                "approval_status": "approved",
                "official_url": "https://opensource.org/license/apache-2-0",
            },
        }
        task = {
            "id": "task-license-report",
            "workspace_name": "payments",
            "workspace_path": "/tmp/payments",
            "workspace_type": "directory",
            "objective": "扫描支付项目",
            "events": [],
            "result": {
                "languages": [],
                "language_results": {},
                "licenses": [license_fact],
                "license_count": 1,
                "license_scan": {
                    "coverage_status": "complete",
                    "license_count": 1,
                    "licenses": [license_fact],
                    "registry": {"status": "completed"},
                },
            },
        }

        report = build_agent_task_markdown_report(task)
        scan_json = build_scan_result_json(task, source_kind="agent_task")

        self.assertIn("### 5.1 项目许可识别", report)
        self.assertIn("Apache-2.0", report)
        self.assertIn("不构成法律意见", report)
        self.assertEqual(scan_json["counts"]["licenses"], 1)
        self.assertEqual(scan_json["facts"]["licenses"][0]["spdx_id"], "Apache-2.0")


def fake_language_scanner(language, attachments, _dependency_scan, rules, cancelled):
    if cancelled():
        raise RuntimeError("cancelled")
    source_files = [
        item for item in attachments
        if language_for_file(str(item.get("file_name") or "")) == language
    ]
    finding = {
        "id": f"finding-{language}",
        "rule_id": f"secflow.{language}.test",
        "title": f"{language} test finding",
        "severity": "HIGH",
        "file_name": source_files[0]["file_name"] if source_files else "",
        "line": 1,
        "description": "test finding",
    }
    count = len(source_files)
    return {
        "status": "completed",
        "mode": "test",
        "syntax_summary": {
            "languages": [language],
            "parsed_files": count,
            "parse_error_files": 0,
            "ast_node_count": count * 10,
            "cfg_node_count": count * 2,
            "cfg_edge_count": count,
            "dfg_edge_count": count,
        },
        "findings": [finding] if source_files else [],
        "finding_count": 1 if source_files else 0,
        "diagnostics": [],
        "rules": rules,
    }


class TaskAgentTests(unittest.TestCase):
    def test_task_service_marks_degraded_language_scan_failed_and_disables_report(self) -> None:
        def degraded_scanner(language, attachments, dependency_scan, rules, cancelled):
            return {
                "status": "warning",
                "mode": "internal-fallback",
                "syntax_summary": {"languages": [language], "parsed_files": 0},
                "findings": [],
                "finding_count": 0,
                "diagnostics": ["静态分析 CLI 未返回 JSON"],
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("print('scan me')\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=degraded_scanner,
            )
            try:
                task = service.create(
                    objective="scan uploaded project",
                    workspace_path=str(root),
                    user_id="analyst",
                )
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    task = service.get(task["id"])
                    if task["status"] in {"completed", "failed", "cancelled"}:
                        break
                    time.sleep(0.01)
            finally:
                service.shutdown(wait=True)

        self.assertEqual(task["status"], "failed")
        self.assertFalse(task["report_ready"])
        self.assertEqual(task["report_decision"], "unavailable")
        self.assertTrue(any(event["type"] == "verification.failed" for event in task["events"]))
        self.assertNotIn("task.completed", {event["type"] for event in task["events"]})

    def test_compact_finding_uses_enriched_file_and_risk_line(self) -> None:
        finding = compact_task_finding(
            {"id": "f1", "title": "risk", "file": "src/app.c", "risk_line": 42},
            1,
        )

        self.assertEqual(finding["file_name"], "src/app.c")
        self.assertEqual(finding["line"], 42)

    def test_compact_finding_keeps_taint_path_separate_from_file_location(self) -> None:
        taint_path = [
            {"kind": "source", "file": "app.py", "line": 7},
            {"kind": "sink", "file": "app.py", "line": 8},
        ]
        finding = compact_task_finding(
            {
                "id": "f1",
                "title": "command injection",
                "scenario": "command_execution",
                "path": taint_path,
                "source": taint_path[0],
                "sink": taint_path[1],
            },
            1,
        )

        self.assertEqual(finding["file_name"], "app.py")
        self.assertEqual(finding["path"], "app.py")
        self.assertEqual(finding["taint_path"], taint_path)
        self.assertEqual(finding["scenario"], "command_execution")

    def test_compact_finding_preserves_long_taint_path_as_structured_nodes(self) -> None:
        taint_path = [
            {
                "kind": "source" if index == 0 else "sink" if index == 39 else "propagation",
                "file": "src/flow.py",
                "line": index + 1,
                "label": f"taint-node-{index}",
                "snippet": f"value_{index} = transform(value_{index - 1})" if index else "value_0 = request.args['q']",
            }
            for index in range(40)
        ]
        self.assertGreater(len(str(taint_path)), 1_600)

        finding = compact_task_finding(
            {
                "id": "long-flow",
                "title": "long flow",
                "path": taint_path,
                "source": taint_path[0],
                "sink": taint_path[-1],
            },
            1,
        )

        self.assertIsInstance(finding["taint_path"], list)
        self.assertEqual(len(finding["taint_path"]), 40)
        self.assertEqual(finding["taint_path"][-1]["label"], "taint-node-39")
        self.assertEqual(finding["taint_path"][-1]["snippet"], "value_39 = transform(value_38)")

    def test_agent_report_renders_severity_levels_in_chinese(self) -> None:
        content = build_agent_task_markdown_report(
            {
                "workspace_name": "demo",
                "workspace_path": "/tmp/demo",
                "workspace_type": "directory",
                "objective": "scan project",
                "languages": ["python"],
                "events": [],
                "result": {
                    "languages": ["python"],
                    "total_files": 1,
                    "dependency_count": 0,
                    "total_findings": 1,
                    "language_results": {
                        "python": {
                            "file_count": 1,
                            "finding_count": 1,
                            "files": ["app.py"],
                            "rule_files": ["python-security.yml"],
                            "syntax_summary": {},
                            "findings": [
                                {
                                    "title": "命令注入",
                                    "severity": "HIGH",
                                    "file_name": "app.py",
                                    "line": 8,
                                    "vulnerable_snippet": "os.system(command)",
                                    "remediation": "使用参数化进程调用并校验命令参数。",
                                    "fixed_snippet": "subprocess.run([allowed_command], check=True)",
                                }
                            ],
                        }
                    },
                },
            }
        )

        self.assertIn("| 高危 | 1 |", content)
        self.assertNotIn("扫描文件与规则", content)
        self.assertNotIn("扫描模式", content)
        self.assertIn("- 严重等级：高危", content)
        self.assertNotIn("- 严重等级：HIGH", content)
        self.assertIn("证据代码片段", content)
        self.assertIn("- 修复方案：使用参数化进程调用并校验命令参数。", content)
        self.assertIn("可核验修复代码", content)

    def test_graph_routes_each_language_to_its_rules_and_syntax_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self._write_multilanguage_workspace(root)
            calls: list[tuple[str, list[str]]] = []

            def scanner(language, attachments, dependency_scan, rules, cancelled):
                calls.append((language, [Path(item).name for item in rules]))
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            graph = TaskAgentGraph(language_scanner=scanner)
            state = graph.invoke(
                task_id="task-test",
                objective="scan project",
                workspace_path=str(root),
                user_id="analyst",
            )

        self.assertEqual(state["languages"], ["java", "python", "go", "c", "cpp", "rust", "solidity"])
        self.assertEqual(
            calls,
            [
                ("java", ["java-security.yml"]),
                ("python", ["python-security.yml"]),
                ("go", ["go-security.yml", "go-security-recall.yml"]),
                ("c", ["c-cpp-security.yml"]),
                ("cpp", ["c-cpp-security.yml"]),
                ("rust", ["rust-security.yml"]),
                ("solidity", ["solidity-security.yml"]),
            ],
        )
        self.assertEqual(state["result"]["total_findings"], 7)
        self.assertEqual({step["status"] for step in state["plan"]}, {"completed"})
        self.assertTrue(all(item["syntax_summary"]["parsed_files"] == 1 for item in state["language_results"].values()))

    def test_inventory_does_not_follow_workspace_symlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside = Path(outside_dir) / "outside.py"
            outside.write_text("print('outside')\n", encoding="utf-8")
            (root / "inside.py").write_text("print('inside')\n", encoding="utf-8")
            try:
                os.symlink(outside, root / "linked.py")
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")

            inventory = collect_workspace_inventory(root)

        self.assertEqual(inventory["files_by_language"]["python"], ["inside.py"])

    def test_inventory_and_attachment_reader_skip_materialized_symlink_source_stubs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "apps" / "frameworks" / "sherpa-mnn" / "c-api-examples" / "asr-microphone-example").mkdir(
                parents=True
            )
            stub = root / "apps" / "frameworks" / "sherpa-mnn" / "c-api-examples" / "asr-microphone-example" / "alsa.cc"
            stub.write_text("../../sherpa-onnx/csrc/alsa.cc", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "main.cc").write_text("int main() { return 0; }\n", encoding="utf-8")

            inventory = collect_workspace_inventory(root)
            attachments = read_workspace_attachments(root, [str(stub.relative_to(root)), "src/main.cc"])

        self.assertEqual(inventory["files_by_language"]["cpp"], ["src/main.cc"])
        self.assertEqual(inventory["skipped_files"], 1)
        self.assertEqual([item["file_name"] for item in attachments], ["src/main.cc"])

    def test_single_file_inventory_skips_materialized_symlink_source_stub(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            stub = Path(temp_dir) / "alsa.cc"
            stub.write_text("../../sherpa-onnx/csrc/alsa.cc", encoding="utf-8")

            inventory = collect_workspace_inventory(stub)
            attachments = read_workspace_attachments(stub, ["alsa.cc"])

        self.assertEqual(inventory["files_by_language"], {})
        self.assertEqual(inventory["skipped_files"], 1)
        self.assertEqual(attachments, [])

    def test_go_mod_is_reserved_before_source_file_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.task_agent.MAX_WORKSPACE_FILES", 3):
            root = Path(temp_dir)
            (root / "000.go").write_text("package demo\n", encoding="utf-8")
            (root / "001.go").write_text("package demo\n", encoding="utf-8")
            (root / "002.go").write_text("package demo\n", encoding="utf-8")
            (root / "go.mod").write_text(
                "module example.com/demo\nrequire github.com/gin-gonic/gin v1.10.1\n",
                encoding="utf-8",
            )

            inventory = collect_workspace_inventory(root)

        self.assertEqual(inventory["manifest_files"], ["go.mod"])
        self.assertEqual(inventory["files_by_language"]["go"], ["000.go", "001.go"])
        self.assertEqual(inventory["skipped_files"], 1)

    def test_requirements_is_reserved_before_python_source_file_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.task_agent.MAX_WORKSPACE_FILES", 2):
            root = Path(temp_dir)
            (root / "000.py").write_text("import requests\n", encoding="utf-8")
            (root / "001.py").write_text("import requests\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")

            inventory = collect_workspace_inventory(root)

        self.assertEqual(inventory["manifest_files"], ["requirements.txt"])
        self.assertEqual(inventory["files_by_language"]["python"], ["000.py"])
        self.assertEqual(inventory["skipped_files"], 1)

    def test_user_upload_scans_files_after_300_while_evaluation_remains_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            core = root / "core" / "src" / "main" / "java"
            payment = root / "zz-payment" / "src" / "main" / "java"
            core.mkdir(parents=True)
            payment.mkdir(parents=True)
            for index in range(304):
                (core / f"Core{index:03d}.java").write_text(
                    f"class Core{index:03d} {{}}\n",
                    encoding="utf-8",
                )
            (payment / "Payment.java").write_text("class Payment {}\n", encoding="utf-8")

            upload_files: list[str] = []
            evaluation_files: list[str] = []

            def upload_scanner(language, attachments, dependency_scan, rules, cancelled):
                upload_files.extend(str(item.get("file_name") or "") for item in attachments)
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            def evaluation_scanner(language, attachments, dependency_scan, rules, cancelled):
                evaluation_files.extend(str(item.get("file_name") or "") for item in attachments)
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            upload = TaskAgentGraph(
                language_scanner=upload_scanner,
                overlay_synthesizer=lambda _request: {"status": "no_change", "reason": "stable", "overlay": {}},
                adaptive_upload=True,
            ).invoke(
                task_id="task-complete-upload",
                objective="scan uploaded project",
                workspace_path=str(root),
                user_id="analyst",
            )
            evaluation = TaskAgentGraph(
                language_scanner=evaluation_scanner,
                adaptive_upload=True,
            ).invoke(
                task_id="evaluation-frozen-project",
                objective="scan frozen evaluation project",
                workspace_path=str(root),
                user_id="evaluation",
            )

        payment_path = "zz-payment/src/main/java/Payment.java"
        self.assertEqual(upload["result"]["total_files"], 305)
        self.assertIn(payment_path, upload_files)
        self.assertEqual(upload["result"]["coverage"]["skipped_files"], 0)
        self.assertFalse(upload["result"]["coverage"]["limits_applied"])
        self.assertEqual(evaluation["result"]["total_files"], 300)
        self.assertNotIn(payment_path, evaluation_files)
        self.assertEqual(evaluation["result"]["coverage"]["skipped_files"], 5)
        self.assertTrue(evaluation["result"]["coverage"]["limits_applied"])

    def test_manifest_budget_cannot_starve_source_files(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch("app.task_agent.MAX_WORKSPACE_FILES", 3),
            patch("app.task_agent.MAX_WORKSPACE_MANIFEST_FILES", 1),
        ):
            root = Path(temp_dir)
            (root / "module-a").mkdir()
            (root / "module-b").mkdir()
            (root / "module-a" / "go.mod").write_text("module example.test/a\n", encoding="utf-8")
            (root / "module-b" / "go.mod").write_text("module example.test/b\n", encoding="utf-8")
            (root / "main.go").write_text("package main\n", encoding="utf-8")
            (root / "server.go").write_text("package main\n", encoding="utf-8")

            inventory = collect_workspace_inventory(root)

        self.assertEqual(len(inventory["manifest_files"]), 1)
        self.assertEqual(inventory["files_by_language"]["go"], ["main.go", "server.go"])
        self.assertEqual(inventory["skipped_files"], 1)

    def test_cpp_translation_units_are_reserved_before_headers_and_set_header_language(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.task_agent.MAX_WORKSPACE_FILES", 2):
            root = Path(temp_dir)
            (root / "000.h").write_text("template<class T> class Box {};\n", encoding="utf-8")
            (root / "001.h").write_text("template<class T> class Other {};\n", encoding="utf-8")
            (root / "main.cpp").write_text('#include "000.h"\nint main() { return 0; }\n', encoding="utf-8")

            inventory = collect_workspace_inventory(root)

        self.assertEqual(inventory["files_by_language"]["cpp"], ["main.cpp", "000.h"])
        self.assertNotIn("c", inventory["files_by_language"])
        self.assertEqual(inventory["skipped_files"], 1)

    def test_build_compile_commands_is_reserved_without_scanning_build_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "build").mkdir()
            (root / "src").mkdir()
            (root / "build" / "compile_commands.json").write_text("[]\n", encoding="utf-8")
            (root / "build" / "generated.c").write_text("int generated(void) { return 0; }\n", encoding="utf-8")
            (root / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")

            inventory = collect_workspace_inventory(root)

        self.assertIn("build/compile_commands.json", inventory["manifest_files"])
        self.assertEqual(inventory["files_by_language"]["c"], ["src/main.c"])
        self.assertNotIn("build/generated.c", inventory["files_by_language"]["c"])

    def test_go_task_resolves_go_mod_before_static_language_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "go.mod").write_text(
                """
                module example.com/secflow/demo
                go 1.24
                require github.com/gin-gonic/gin v1.10.1
                """,
                encoding="utf-8",
            )
            (root / "go.sum").write_text(
                "github.com/obsolete/dependency v9.9.9 h1:old\n",
                encoding="utf-8",
            )
            (root / "main.go").write_text(
                """
                package main
                import (
                    "example.com/secflow/demo/internal/app"
                    "github.com/gin-gonic/gin/binding"
                )
                """,
                encoding="utf-8",
            )
            scanner_inputs: list[dict] = []
            events: list[dict] = []

            def scanner(language, attachments, dependency_scan, rules, cancelled):
                scanner_inputs.append(dependency_scan)
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            def event_sink(_task_id, event_type, node, status, message, data):
                events.append(
                    {"type": event_type, "node": node, "status": status, "message": message, "data": data or {}}
                )

            state = TaskAgentGraph(language_scanner=scanner, event_sink=event_sink).invoke(
                task_id="task-go-mod-first",
                objective="scan go project",
                workspace_path=str(root),
                user_id="analyst",
            )

        self.assertEqual(state["languages"], ["go"])
        self.assertEqual(state["plan"][1]["title"], "优先解析 go.mod 并识别依赖组件")
        self.assertEqual(state["dependency_scan"]["strategy"], "go_mod_first")
        self.assertEqual(state["dependency_scan"]["go_mod_files"], ["go.mod"])
        self.assertEqual(scanner_inputs[0]["dependencies"][0]["name"], "github.com/gin-gonic/gin")
        self.assertEqual(scanner_inputs[0]["dependencies"][0]["version"], "v1.10.1")
        dependency_done_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "node.completed" and event["node"] == "scan_dependencies"
        )
        go_scan_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "node.started" and event["node"] == "scan_go"
        )
        self.assertLess(dependency_done_index, go_scan_index)
        self.assertIn("优先解析 go.mod", events[dependency_done_index]["message"])

    def test_python_task_resolves_requirements_before_static_language_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
            (root / "pyproject.toml").write_text(
                '[project]\ndependencies = ["requests==9.9.9", "Flask==3.1.1"]\n',
                encoding="utf-8",
            )
            (root / "app.py").write_text("import requests\nimport flask\n", encoding="utf-8")
            scanner_inputs: list[dict] = []
            events: list[dict] = []

            def scanner(language, attachments, dependency_scan, rules, cancelled):
                scanner_inputs.append(dependency_scan)
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            def event_sink(_task_id, event_type, node, status, message, data):
                events.append(
                    {"type": event_type, "node": node, "status": status, "message": message, "data": data or {}}
                )

            state = TaskAgentGraph(language_scanner=scanner, event_sink=event_sink).invoke(
                task_id="task-python-requirements-first",
                objective="scan python project",
                workspace_path=str(root),
                user_id="analyst",
            )

        dependencies = {item["name"].lower(): item for item in scanner_inputs[0]["dependencies"]}
        self.assertEqual(state["languages"], ["python"])
        self.assertEqual(state["plan"][1]["title"], "优先解析 requirements.txt 并识别依赖组件")
        self.assertEqual(state["dependency_scan"]["strategy"], "requirements_first")
        self.assertEqual(state["dependency_scan"]["requirements_files"], ["requirements.txt"])
        self.assertEqual(dependencies["requests"]["version"], "2.32.4")
        self.assertEqual(dependencies["requests"]["source_file"], "requirements.txt")
        self.assertNotIn("9.9.9", str(scanner_inputs[0]["dependencies"]))
        dependency_done_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "node.completed" and event["node"] == "scan_dependencies"
        )
        python_scan_index = next(
            index
            for index, event in enumerate(events)
            if event["type"] == "node.started" and event["node"] == "scan_python"
        )
        self.assertLess(dependency_done_index, python_scan_index)
        self.assertIn("优先解析 requirements.txt", events[dependency_done_index]["message"])

    def test_overlay_node_event_does_not_publish_skill_or_prompt_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            events: list[dict] = []

            def event_sink(_task_id, event_type, node, status, message, data):
                events.append({"type": event_type, "node": node, "data": data or {}})

            TaskAgentGraph(
                language_scanner=fake_language_scanner,
                overlay_synthesizer=lambda _request: {
                    "status": "no_change",
                    "reason": "test",
                    "overlay": {},
                },
                event_sink=event_sink,
                adaptive_upload=True,
            ).invoke(
                task_id="task-private-skill-event",
                objective="scan python project",
                workspace_path=str(root),
                user_id="analyst",
            )

        started = next(
            event
            for event in events
            if event["type"] == "node.started" and event["node"] == "synthesize_project_overlay"
        )
        self.assertEqual(set(started["data"]), {"iteration", "max_iterations"})
        self.assertNotIn("skill", str(started["data"]).lower())
        self.assertNotIn("prompt", str(started["data"]).lower())

    def test_long_language_scan_emits_throttled_progress_heartbeats(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch("app.task_agent.SCAN_HEARTBEAT_INTERVAL_SECONDS", 0.01):
            root = Path(temp_dir)
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            events: list[dict] = []

            def scanner(language, attachments, dependency_scan, rules, cancelled):
                time.sleep(0.05)
                return fake_language_scanner(language, attachments, dependency_scan, rules, cancelled)

            TaskAgentGraph(
                language_scanner=scanner,
                event_sink=lambda _task_id, event_type, node, status, message, data: events.append(
                    {"type": event_type, "node": node, "status": status, "message": message, "data": data or {}}
                ),
            ).invoke(
                task_id="task-progress",
                objective="scan project",
                workspace_path=str(root),
                user_id="analyst",
            )

        progress = [event for event in events if event["type"] == "node.progress"]
        self.assertGreaterEqual(len(progress), 1)
        self.assertEqual(progress[0]["node"], "scan_python")
        self.assertEqual(progress[0]["data"]["total_files"], 1)
        self.assertTrue(progress[0]["data"]["heartbeat"])

    def test_single_file_scope_does_not_scan_sibling_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "selected.py"
            selected.write_text("def selected(value):\n    return value\n", encoding="utf-8")
            (root / "sibling.py").write_text("def sibling(value):\n    return value\n", encoding="utf-8")

            inventory = collect_workspace_inventory(selected)
            graph = TaskAgentGraph(language_scanner=fake_language_scanner)
            state = graph.invoke(
                task_id="task-single-file",
                objective="scan selected file only",
                workspace_path=str(selected),
                user_id="analyst",
            )

        self.assertEqual(inventory["files_by_language"], {"python": ["selected.py"]})
        self.assertEqual(state["result"]["total_files"], 1)
        self.assertEqual(state["result"]["language_results"]["python"]["files"], ["selected.py"])
        self.assertEqual(
            state["result"]["language_results"]["python"]["findings"][0]["file_name"],
            "selected.py",
        )

    def test_single_manifest_scope_only_parses_that_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            selected = root / "requirements.txt"
            selected.write_text("requests==2.32.4\n", encoding="utf-8")
            (root / "sibling.py").write_text("print('not selected')\n", encoding="utf-8")

            graph = TaskAgentGraph(language_scanner=fake_language_scanner)
            state = graph.invoke(
                task_id="task-single-manifest",
                objective="scan selected manifest only",
                workspace_path=str(selected),
                user_id="analyst",
            )

        self.assertEqual(state["languages"], [])
        self.assertEqual(state["result"]["total_files"], 0)
        self.assertEqual(state["result"]["dependency_count"], 1)
        self.assertEqual(state["result"]["dependencies"][0]["name"], "requests")
        self.assertEqual(state["result"]["dependencies"][0]["source_file"], "requirements.txt")

    def test_task_store_encrypts_task_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-test-master-key"},
        ):
            path = Path(temp_dir) / "tasks.json"
            store = AgentTaskStore(path)
            store.create(
                {
                    "id": "task-1",
                    "user_id": "analyst",
                    "objective": "inspect secret project",
                    "status": "queued",
                    "events": [],
                }
            )

            with closing(sqlite3.connect(store.path)) as connection:
                raw = str(connection.execute("SELECT payload FROM tasks WHERE id = 'task-1'").fetchone()[0])
                journal_mode = str(connection.execute("PRAGMA journal_mode").fetchone()[0])
            loaded = store.get("task-1")

        self.assertTrue(is_encrypted_text(raw))
        self.assertNotIn("inspect secret project", raw)
        self.assertEqual(journal_mode.casefold(), "wal")
        self.assertEqual(loaded["objective"], "inspect secret project")

    def test_task_store_migrates_encrypted_legacy_json_into_separate_event_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-migration-key"},
        ):
            path = Path(temp_dir) / "tasks.json"
            path.write_text(
                encrypt_json_to_text(
                    {
                        "version": 1,
                        "tasks": [
                            {
                                "id": "legacy-task",
                                "user_id": "analyst",
                                "objective": "legacy sensitive objective",
                                "status": "completed",
                                "archived": False,
                                "events": [
                                    {
                                        "sequence": 7,
                                        "type": "task.completed",
                                        "node": "compose_result",
                                        "status": "completed",
                                        "message": "legacy sensitive event",
                                        "data": {},
                                        "time": "2026-07-31T00:00:00+00:00",
                                    }
                                ],
                            }
                        ],
                    },
                    "secflow-agent-tasks",
                    compact=True,
                ),
                encoding="utf-8",
            )

            store = AgentTaskStore(path)
            loaded = store.get("legacy-task")
            resumed_events = store.events("legacy-task", after=6)
            with closing(sqlite3.connect(store.path)) as connection:
                task_payload = str(connection.execute("SELECT payload FROM tasks").fetchone()[0])
                event_payload = str(connection.execute("SELECT payload FROM task_events").fetchone()[0])

        self.assertEqual(loaded["events"][0]["sequence"], 7)
        self.assertEqual(resumed_events[0]["type"], "task.completed")
        self.assertTrue(is_encrypted_text(task_payload))
        self.assertTrue(is_encrypted_text(event_payload))
        self.assertNotIn("legacy sensitive objective", task_payload)
        self.assertNotIn("legacy sensitive event", event_payload)

    def test_task_store_leases_one_durable_job_and_recovers_expired_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-job-lease-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.sqlite3")
            store.create(
                {
                    "id": "task-leased",
                    "user_id": "analyst",
                    "status": "queued",
                    "created_at": "2026-08-01T08:00:00+08:00",
                    "updated_at": "2026-08-01T08:00:00+08:00",
                    "events": [],
                }
            )
            store.enqueue("task-leased")

            first = store.claim("worker-a", lease_seconds=30)
            blocked = store.claim("worker-b", lease_seconds=30)
            renewed = store.renew_lease("task-leased", "worker-a", lease_seconds=30)
            with closing(sqlite3.connect(store.path)) as connection:
                connection.execute(
                    "UPDATE task_jobs SET lease_expires_at = 0 WHERE task_id = 'task-leased'"
                )
                connection.commit()
            recovered = store.claim("worker-b", lease_seconds=30)
            completed = store.finish_job("task-leased", "worker-b", state="completed")

        self.assertEqual(first["lease_owner"], "worker-a")
        self.assertIsNone(blocked)
        self.assertTrue(renewed)
        self.assertTrue(recovered["recovered"])
        self.assertEqual(recovered["attempts"], 2)
        self.assertEqual(completed["state"], "completed")

    def test_task_store_requeues_active_legacy_task_without_a_job(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-job-reconcile-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.sqlite3")
            store.create(
                {
                    "id": "task-orphaned",
                    "user_id": "analyst",
                    "status": "running",
                    "report_ready": False,
                    "created_at": "2026-08-01T08:00:00+08:00",
                    "updated_at": "2026-08-01T08:00:00+08:00",
                    "events": [],
                }
            )

            recovered = store.reconcile_pending_jobs()
            task = store.get("task-orphaned")
            job = store.job("task-orphaned")
            has_runnable_jobs = store.has_runnable_jobs()

        self.assertEqual(recovered, ["task-orphaned"])
        self.assertEqual(task["status"], "queued")
        self.assertEqual(job["state"], "queued")
        self.assertTrue(has_runnable_jobs)

    def test_task_store_finishes_expired_cancellation_and_clears_partial_data(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-job-expired-cancel-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.sqlite3")
            store.create(
                {
                    "id": "task-expired-cancel",
                    "user_id": "analyst",
                    "status": "cancelling",
                    "languages": ["python"],
                    "plan": [{"node": "scan_python", "status": "running"}],
                    "result": {"finding_count": 3},
                    "report_ready": True,
                    "report": {"id": "stale"},
                    "created_at": "2026-08-02T08:00:00+08:00",
                    "updated_at": "2026-08-02T08:00:00+08:00",
                    "events": [],
                }
            )
            store.enqueue("task-expired-cancel")
            store.claim("dead-worker", lease_seconds=30)
            with closing(sqlite3.connect(store.path)) as connection:
                connection.execute(
                    "UPDATE task_jobs SET lease_expires_at = 0 WHERE task_id = 'task-expired-cancel'"
                )
                connection.commit()

            recovered = store.reconcile_pending_jobs()
            task = store.get("task-expired-cancel")
            job = store.job("task-expired-cancel")

        self.assertEqual(recovered, [])
        self.assertEqual(task["status"], "cancelled")
        self.assertIsNone(task["result"])
        self.assertEqual(task["languages"], [])
        self.assertEqual(task["plan"], [])
        self.assertFalse(task["report_ready"])
        self.assertIsNone(task["report"])
        self.assertEqual(job["state"], "cancelled")

    def test_external_service_starts_dedicated_workers_with_an_empty_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-external-worker-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.sqlite3")
            service = TaskAgentService(store, max_workers=2, execution_mode="external")
            with patch("app.agent.task_worker.TaskWorkerProcessSupervisor") as supervisor_type:
                supervisor = supervisor_type.return_value
                supervisor.snapshot.return_value = {
                    "mode": "external-process",
                    "configured_workers": 2,
                    "running_workers": 2,
                    "store_path": str(store.path),
                }

                service.start()
                service.start()
                status = service.execution_status()
                service.shutdown(wait=True)

            supervisor_type.assert_called_once_with(store_path=store.path, worker_count=2)
            supervisor.start.assert_called_once_with()
            supervisor.stop.assert_called_once_with(wait=True)

        self.assertEqual(status["mode"], "external-process")
        self.assertEqual(status["running_workers"], 2)

    def test_task_store_filters_archived_tasks_and_deletes_permanently(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-archive-store-key"},
        ):
            path = Path(temp_dir) / "tasks.json"
            store = AgentTaskStore(path)
            store.create({"id": "active", "user_id": "analyst", "archived": False})
            store.create({"id": "archived", "user_id": "analyst", "archived": True})

            self.assertEqual([item["id"] for item in store.list("analyst")], ["active"])
            self.assertEqual(
                [item["id"] for item in store.list("analyst", archived=True)],
                ["archived"],
            )
            removed = store.delete("archived")

            self.assertEqual(removed["id"], "archived")
            with self.assertRaises(KeyError):
                store.get("archived")
            with closing(sqlite3.connect(store.path)) as connection:
                task_row = connection.execute("SELECT id FROM tasks WHERE id = 'archived'").fetchone()
                event_rows = connection.execute(
                    "SELECT COUNT(*) FROM task_events WHERE task_id = 'archived'"
                ).fetchone()[0]
            self.assertIsNone(task_row)
            self.assertEqual(event_rows, 0)

    def test_task_api_runs_persistent_task_and_streams_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "task-agent-api-test-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=fake_language_scanner,
            )
            with (
                patch.object(main_module, "task_agent_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                created = client.post(
                    "/api/tasks",
                    json={
                        "objective": "scan python workspace",
                        "workspace_path": str(root),
                        "user_id": "analyst",
                    },
                )
                self.assertEqual(created.status_code, 202, created.text)
                task_id = created.json()["data"]["id"]
                task = self._wait_for_task(client, task_id)
                events = client.get(
                    f"/api/tasks/{task_id}/events",
                    params={"user_id": "analyst"},
                )
                last_sequence = max(int(event["sequence"]) for event in task["events"])
                resumed_events = client.get(
                    f"/api/tasks/{task_id}/events",
                    params={"user_id": "analyst", "after": 0},
                    headers={"Last-Event-ID": str(last_sequence - 1)},
                )

            service.shutdown(wait=True)
            persisted = AgentTaskStore(Path(temp_dir) / "tasks.json").get(task_id)

        self.assertEqual(task["status"], "completed")
        self.assertEqual(task["languages"], ["python"])
        self.assertEqual(task["result"]["total_findings"], 1)
        self.assertEqual(task["report_decision"], "pending")
        self.assertIn("event: languages.detected", events.text)
        self.assertIn("event: task.completed", events.text)
        self.assertIn(f"id: {last_sequence}", resumed_events.text)
        self.assertNotIn(f"id: {last_sequence - 1}\n", resumed_events.text)
        self.assertEqual(persisted["status"], "completed")

    def test_task_action_creates_a_new_rescan_with_an_immutable_baseline_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "task-rescan-api-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=fake_language_scanner,
            )
            try:
                with (
                    patch.object(main_module, "task_agent_service", service),
                    patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                    patch.object(
                        main_module,
                        "plan_assistant_intent",
                        return_value={"intent": "project_rescan", "reason": "重新扫描并比较。"},
                    ),
                    TestClient(main_module.app) as client,
                ):
                    baseline_id = self._create_and_wait(client, root)
                    response = client.post(
                        f"/api/assistant/tasks/{baseline_id}/actions",
                        json={
                            "objective": "重新扫描这个项目并与上一次结果比较",
                            "user_id": "analyst",
                            "session_id": "scan-session",
                            "response_language": "zh-Hans",
                        },
                    )
                    self.assertEqual(response.status_code, 200, response.text)
                    rescanned_id = response.json()["data"]["task"]["id"]
                    rescanned = self._wait_for_task(client, rescanned_id)
                    baseline = client.get(
                        f"/api/tasks/{baseline_id}", params={"user_id": "analyst"}
                    ).json()["data"]
            finally:
                service.shutdown(wait=True)

        self.assertNotEqual(rescanned_id, baseline_id)
        self.assertEqual(rescanned["baseline_task_id"], baseline_id)
        self.assertEqual(rescanned["run_number"], 2)
        self.assertEqual(rescanned["result"]["result_diff"]["counts"], {
            "new": 0,
            "resolved": 0,
            "unchanged": 1,
            "changed": 0,
        })
        self.assertNotIn("result_diff", baseline["result"])
        self.assertTrue(rescanned["result"]["ruleset_fingerprint"])
        self.assertTrue(rescanned["result"]["engine_fingerprint"])

    def test_task_follow_up_injects_canonical_finding_json_from_the_task_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "task-follow-up-api-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=fake_language_scanner,
            )
            observed: dict = {}

            def invoke(_question, top_k=5, **kwargs):
                observed["top_k"] = top_k
                observed.update(kwargs)
                return {
                    "mode": "scan_result_follow_up",
                    "summary": "已根据扫描证据补充修复方案。",
                    "records": [],
                    "fields": {},
                    "trace": [],
                    "generated_at": "2026-07-29T01:00:00+00:00",
                }

            try:
                with (
                    patch.object(main_module, "task_agent_service", service),
                    patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                    patch.object(
                        main_module,
                        "plan_assistant_intent",
                        return_value={"intent": "scan_result_follow_up", "reason": "补充扫描修复。"},
                    ),
                    patch.object(main_module.knowledge_graph, "invoke", side_effect=invoke),
                    TestClient(main_module.app) as client,
                ):
                    task_id = self._create_and_wait(client, root)
                    response = client.post(
                        f"/api/assistant/tasks/{task_id}/actions",
                        json={
                            "objective": "补充刚才风险的修复代码和验证方法",
                            "user_id": "analyst",
                            "session_id": "scan-session",
                            "response_language": "zh-Hans",
                        },
                    )
            finally:
                service.shutdown(wait=True)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["kind"], "assistant")
        context = observed["task_context"]
        self.assertEqual(context["task_id"], task_id)
        self.assertEqual(context["metrics"]["total_findings"], 1)
        self.assertEqual(context["findings"][0]["path"], "app.py")
        self.assertEqual(context["findings"][0]["message"], "test finding")
        self.assertEqual(len(context["findings"][0]["finding_fingerprint"]), 64)

    def test_task_report_decision_skips_or_generates_an_idempotent_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "task-agent-report-test-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=fake_language_scanner,
            )
            reports = ReportStore(Path(temp_dir) / "reports")
            with (
                patch.object(main_module, "task_agent_service", service),
                patch.object(main_module, "report_store", reports),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                skipped_task_id = self._create_and_wait(client, root, require_dependencies=True)
                skipped = client.post(
                    f"/api/tasks/{skipped_task_id}/report-decision",
                    params={"user_id": "analyst"},
                    json={"generate": False},
                )
                self.assertEqual(skipped.status_code, 200, skipped.text)
                self.assertEqual(skipped.json()["data"]["report_decision"], "declined")
                self.assertEqual(reports.list_reports(), [])

                generated_task_id = self._create_and_wait(client, root, require_dependencies=True)
                unauthorized = client.post(
                    f"/api/tasks/{generated_task_id}/report-decision",
                    params={"user_id": "another-user"},
                    json={"generate": True},
                )
                self.assertEqual(unauthorized.status_code, 404)

                generated = client.post(
                    f"/api/tasks/{generated_task_id}/report-decision",
                    params={"user_id": "analyst"},
                    json={"generate": True},
                )
                repeated = client.post(
                    f"/api/tasks/{generated_task_id}/report-decision",
                    params={"user_id": "analyst"},
                    json={"generate": True},
                )
                downloaded = client.post(
                    f"/api/tasks/{generated_task_id}/report-download-decision",
                    params={"user_id": "analyst"},
                    json={"confirm": True, "format": "all"},
                )

            service.shutdown(wait=True)

            generated_task = generated.json()["data"]
            repeated_task = repeated.json()["data"]
            saved_reports = reports.list_reports()
            report_detail = reports.get_report(generated_task["report"]["id"])
            report_json = reports.get_report_json(generated_task["report"]["id"])

        self.assertEqual(generated.status_code, 200, generated.text)
        self.assertEqual(repeated.status_code, 200, repeated.text)
        self.assertEqual(downloaded.status_code, 200, downloaded.text)
        self.assertEqual(downloaded.json()["data"]["artifact"]["media_type"], "application/zip")
        self.assertTrue(downloaded.json()["data"]["artifact"]["file_name"].endswith(".zip"))
        self.assertEqual(generated_task["report_decision"], "generated")
        self.assertEqual(generated_task["report_orchestration"]["final_agent"], "report_agent")
        report_event_nodes = {
            str(event.get("node") or "")
            for event in generated_task.get("events") or []
            if str(event.get("type") or "").startswith("report.")
        }
        self.assertIn("supervisor_agent", report_event_nodes)
        self.assertIn("report_agent", report_event_nodes)
        self.assertIn("report.sarif_mcp", report_event_nodes)
        self.assertIn("report.pdf_mcp", report_event_nodes)
        self.assertIn("report.persist", report_event_nodes)
        self.assertEqual(repeated_task["report"]["id"], generated_task["report"]["id"])
        self.assertEqual(len(saved_reports), 1)
        self.assertEqual(set(saved_reports[0]["available_formats"]), {"md", "html", "docx", "xlsx", "pdf"})
        self.assertIn("requests", report_detail["content"])
        self.assertIn("requirements.txt", report_detail["content"])
        self.assertIn("app.py:1", report_detail["content"])
        self.assertIn("| MCP 调用状态 | 已完成", report_detail["content"])
        self.assertIn("1 | def run(value):", report_detail["content"])
        self.assertEqual(report_detail["metadata"]["report_mcp"]["status"], "completed")
        self.assertTrue(report_detail["metadata"]["report_mcp"]["output_sha256"])
        self.assertEqual(report_detail["metadata"]["report_schema_version"], 5)
        self.assertEqual(report_json["source"]["counts"]["dependencies"], 1)
        self.assertEqual(report_json["source"]["counts"]["code_findings"], 1)
        self.assertIn(
            "1 | def run(value):",
            report_json["source"]["facts"]["code_findings"][0]["vulnerable_snippet"],
        )
        self.assertGreaterEqual(len(report_json["report"]["sections"]), 8)
        self.assertTrue(all(section["content"].strip() for section in report_json["report"]["sections"]))
        self.assertTrue(any(event.get("type") == "report.mcp.completed" for event in generated_task["events"]))

    def test_task_api_archives_restores_and_deletes_terminal_task(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_STORAGE_MASTER_KEY": "task-agent-archive-api-key",
                "SECFLOW_DISABLE_BATCH_SCHEDULER": "1",
            },
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.4\n", encoding="utf-8")
            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=fake_language_scanner,
            )
            try:
                with (
                    patch.object(main_module, "task_agent_service", service),
                    patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                    TestClient(main_module.app) as client,
                ):
                    task_id = self._create_and_wait(client, root)
                    unauthorized = client.post(
                        f"/api/tasks/{task_id}/archive",
                        params={"user_id": "another-user"},
                        json={"archived": True},
                    )
                    archived = client.post(
                        f"/api/tasks/{task_id}/archive",
                        params={"user_id": "analyst"},
                        json={"archived": True},
                    )
                    current = client.get("/api/tasks", params={"user_id": "analyst"})
                    archive = client.get(
                        "/api/tasks",
                        params={"user_id": "analyst", "archived": "true"},
                    )
                    restored = client.post(
                        f"/api/tasks/{task_id}/archive",
                        params={"user_id": "analyst"},
                        json={"archived": False},
                    )
                    deleted = client.delete(
                        f"/api/tasks/{task_id}",
                        params={"user_id": "analyst"},
                    )
                    missing = client.get(
                        f"/api/tasks/{task_id}",
                        params={"user_id": "analyst"},
                    )
            finally:
                service.shutdown(wait=True)

        self.assertEqual(unauthorized.status_code, 404)
        self.assertEqual(archived.status_code, 200, archived.text)
        self.assertTrue(archived.json()["data"]["archived"])
        self.assertIsNotNone(archived.json()["data"]["archived_at"])
        self.assertNotIn(task_id, {item["id"] for item in current.json()["data"]})
        self.assertIn(task_id, {item["id"] for item in archive.json()["data"]})
        self.assertFalse(restored.json()["data"]["archived"])
        self.assertEqual(deleted.json()["data"], {"id": task_id, "deleted": True})
        self.assertEqual(missing.status_code, 404)

    def test_task_api_rejects_archive_and_delete_while_running(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-active-mutation-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.json")
            store.create(
                {
                    "id": "task-running",
                    "user_id": "analyst",
                    "status": "running",
                    "archived": False,
                    "events": [],
                }
            )
            service = TaskAgentService(store, max_workers=1, language_scanner=fake_language_scanner)
            store.update("task-running", status="running")
            with (
                patch.object(main_module, "task_agent_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                archived = client.post(
                    "/api/tasks/task-running/archive",
                    params={"user_id": "analyst"},
                    json={"archived": True},
                )
                deleted = client.delete(
                    "/api/tasks/task-running",
                    params={"user_id": "analyst"},
                )
            service.shutdown(wait=True)

        self.assertEqual(archived.status_code, 409)
        self.assertEqual(deleted.status_code, 409)

    def test_report_decision_rejects_unfinished_task(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-pending-report-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.json")
            store.create(
                {
                    "id": "task-pending",
                    "user_id": "analyst",
                    "status": "running",
                    "result": None,
                    "events": [],
                }
            )
            service = TaskAgentService(store, max_workers=1, language_scanner=fake_language_scanner)
            with self.assertRaisesRegex(ValueError, "扫描尚未完成"):
                service.decide_report("task-pending", generate=False, report_store=ReportStore(Path(temp_dir) / "reports"))
            service.shutdown(wait=True)

    def test_full_scan_matches_dependency_vulnerabilities_into_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pom.xml").write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.demo</groupId>
  <artifactId>log4shell-demo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            (root / "App.java").write_text("class App {}\n", encoding="utf-8")
            events: list[dict] = []
            matched_payloads: list[dict] = []

            def event_sink(_task_id, event_type, node, status, message, data):
                events.append(
                    {"type": event_type, "node": node, "status": status, "message": message, "data": data or {}}
                )

            matching = {
                "vulnerability_count": 1,
                "matched_component_count": 1,
                "coverage_status": "complete",
                "errors": [],
                "records": [
                    {
                        "id": "CVE-2021-44228",
                        "aliases": ["CVE-2021-44228"],
                        "severity": "CRITICAL",
                        "cvss_score": 10.0,
                        "summary": "Apache Log4j2 JNDI 远程代码执行（Log4Shell）。",
                        "known_exploited": True,
                        "affected_versions": [">= 2.0.0, < 2.15.0"],
                        "fixed_versions": ["2.15.0"],
                        "matched_dependencies": [
                            {
                                "ecosystem": "Maven",
                                "name": "org.apache.logging.log4j:log4j-core",
                                "version": "2.14.1",
                                "source_file": "pom.xml",
                            }
                        ],
                    }
                ],
            }

            def fake_match(sbom, dependency_scan, **_kwargs):
                matched_payloads.append(dependency_scan)
                enriched = dict(sbom)
                enriched["vulnerabilities"] = [{"id": "CVE-2021-44228"}]
                return enriched, matching

            with patch("app.agent.task_agent.match_sbom_vulnerabilities", side_effect=fake_match):
                state = TaskAgentGraph(language_scanner=fake_language_scanner, event_sink=event_sink).invoke(
                    task_id="task-vuln-match",
                    objective="scan java project",
                    workspace_path=str(root),
                    user_id="analyst",
                )

        result = state["result"]
        self.assertEqual(result["vulnerability_count"], 1)
        self.assertEqual(
            result["vulnerability_severities"],
            {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        )
        self.assertIn("命中 1 个组件已知漏洞", result["summary"])
        self.assertIn("严重 1", result["summary"])
        self.assertEqual(result["vulnerabilities"][0]["id"], "CVE-2021-44228")
        self.assertEqual(
            result["vulnerabilities"][0]["matched_dependencies"][0]["name"],
            "org.apache.logging.log4j:log4j-core",
        )
        self.assertNotIn("records", result["vulnerability_matching"])
        self.assertEqual(
            result["vulnerability_matching"]["coverage_status"],
            "complete",
        )
        self.assertTrue(any(item.get("id") == "vulnerabilities" for item in state["plan"]))
        self.assertEqual(
            matched_payloads[0]["dependencies"][0]["name"],
            "org.apache.logging.log4j:log4j-core",
        )
        matched_events = [event for event in events if event["type"] == "vulnerability.matched"]
        self.assertEqual(len(matched_events), 1)
        self.assertIn("命中 1 个已知漏洞", matched_events[0]["message"])

    def test_full_scan_continues_when_vulnerability_matching_degrades(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "pom.xml").write_text(
                """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""",
                encoding="utf-8",
            )
            (root / "App.java").write_text("class App {}\n", encoding="utf-8")
            events: list[dict] = []

            def event_sink(_task_id, event_type, node, status, message, data):
                events.append(
                    {"type": event_type, "node": node, "status": status, "message": message, "data": data or {}}
                )

            with patch(
                "app.agent.task_agent.match_sbom_vulnerabilities",
                side_effect=RuntimeError("catalog offline"),
            ):
                state = TaskAgentGraph(language_scanner=fake_language_scanner, event_sink=event_sink).invoke(
                    task_id="task-vuln-degraded",
                    objective="scan java project",
                    workspace_path=str(root),
                    user_id="analyst",
                )

        result = state["result"]
        self.assertEqual(result["vulnerability_count"], 0)
        self.assertEqual(result["vulnerability_matching"]["coverage_status"], "failed")
        self.assertNotIn("组件已知漏洞", result["summary"])
        self.assertEqual(result["dependency_count"], 1)
        failed_events = [event for event in events if event["type"] == "vulnerability.failed"]
        self.assertEqual(len(failed_events), 1)
        self.assertIn("降级", failed_events[0]["message"])

    def test_agent_task_report_metrics_counts_dependency_vulnerabilities(self) -> None:
        task = {
            "result": {
                "total_files": 12,
                "dependency_count": 3,
                "total_findings": 2,
                "vulnerability_count": 2,
                "vulnerability_severities": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 0, "LOW": 0},
                "language_results": {
                    "java": {"findings": [{"severity": "HIGH"}, {"severity": "MEDIUM"}]},
                },
            }
        }

        metrics = agent_task_report_metrics(task)

        self.assertEqual(metrics["dependency_vulnerabilities"], 2)
        self.assertEqual(metrics["code_findings"], 2)
        self.assertEqual(metrics["severity"], {"CRITICAL": 1, "HIGH": 2, "MEDIUM": 1, "LOW": 0})
        self.assertEqual(metrics["high_risk"], 3)
        self.assertEqual(metrics["total_risks"], 4)

    def test_running_task_can_be_cancelled(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-cancel-test-key"},
        ):
            root = Path(temp_dir) / "workspace"
            root.mkdir()
            (root / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")

            def slow_scanner(language, attachments, dependency_scan, rules, cancelled):
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and not cancelled():
                    time.sleep(0.02)
                return fake_language_scanner(language, attachments, dependency_scan, rules, lambda: False)

            service = TaskAgentService(
                AgentTaskStore(Path(temp_dir) / "tasks.json"),
                max_workers=1,
                language_scanner=slow_scanner,
            )
            task = service.create(objective="cancel scan", workspace_path=str(root), user_id="analyst")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                task = service.get(task["id"])
                if task.get("current_node") == "scan_python":
                    break
                time.sleep(0.02)
            self.assertEqual(
                task.get("current_node"),
                "scan_python",
                "扫描未在 10 秒内进入 scan_python，取消前提不成立。",
            )
            service.store.update(
                task["id"],
                result={"finding_count": 12, "dependencies": [{"name": "stale"}]},
                report={"id": "stale-report"},
                report_interrupt={"interrupt_id": "stale-interrupt"},
                report_thread_id="stale-thread",
                report_download_artifact={"id": "stale-download"},
                workspace_fingerprint="stale-workspace",
                ruleset_fingerprint="stale-rules",
                engine_fingerprint="stale-engine",
            )
            with patch.object(service.graph, "cancel_active_scan", wraps=service.graph.cancel_active_scan) as stop_engine:
                cancelling = service.cancel(task["id"])
                # cancel() 返回前工作线程可能已完成停止，cancelling/cancelled 均为合法的已受理状态。
                self.assertIn(cancelling["status"], {"cancelling", "cancelled"})
                self.assertIsNone(cancelling["result"])
                self.assertEqual(cancelling["languages"], [])
                self.assertEqual(cancelling["plan"], [])
                stop_engine.assert_called()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                task = service.get(task["id"])
                if task["status"] == "cancelled":
                    break
                time.sleep(0.02)
            service.shutdown(wait=True)
            # 状态落库先于终态事件，关停后必须重新读取，避免用轮询时的旧快照断言事件流。
            task = service.get(task["id"])

        self.assertEqual(task["status"], "cancelled")
        self.assertIsNone(task["result"])
        self.assertEqual(task["languages"], [])
        self.assertEqual(task["plan"], [])
        self.assertIsNone(task["report"])
        self.assertIsNone(task["report_interrupt"])
        self.assertIsNone(task["report_thread_id"])
        self.assertIsNone(task["report_download_artifact"])
        self.assertIsNone(task["workspace_fingerprint"])
        self.assertIsNone(task["ruleset_fingerprint"])
        self.assertIsNone(task["engine_fingerprint"])
        self.assertTrue(any(event["type"] == "task.cancelled" for event in task["events"]))
        node_cancelled_events = [
            event
            for event in task["events"]
            if event["type"] == "node.cancelled" and event["status"] == "cancelled"
        ]
        self.assertTrue(node_cancelled_events, "取消时应为在途节点补齐 node.cancelled 终态事件。")
        self.assertEqual(node_cancelled_events[-1]["node"], "scan_python")
        event_types = [event["type"] for event in task["events"]]
        self.assertLess(
            event_types.index("node.cancelled"),
            event_types.index("task.cancelled"),
            "node.cancelled 应先于 task.cancelled 记录，保证前端先收到节点终态。",
        )

    def test_worker_cannot_overwrite_cancelling_state_when_starting(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "task-agent-start-cancel-race-key"},
        ):
            store = AgentTaskStore(Path(temp_dir) / "tasks.json")
            store.create(
                {
                    "id": "task-cancel-before-worker-start",
                    "objective": "scan project",
                    "workspace_path": temp_dir,
                    "workspace_name": "project",
                    "user_id": "analyst",
                    "status": "cancelling",
                    "current_node": "queued",
                    "languages": ["python"],
                    "plan": [{"node": "scan_python", "status": "pending"}],
                    "result": {"finding_count": 4},
                    "report_ready": True,
                    "report_decision": "pending",
                    "report": {"id": "stale-report"},
                    "events": [],
                    "created_at": "2026-08-02T00:00:00+08:00",
                    "updated_at": "2026-08-02T00:00:00+08:00",
                }
            )
            graph = Mock()
            graph.invoke.side_effect = AssertionError("cancelled task must not enter the graph")
            service = TaskAgentService(store, graph=graph, execution_mode="worker")

            service._run("task-cancel-before-worker-start")
            task = store.get("task-cancel-before-worker-start")

        self.assertEqual(task["status"], "cancelled")
        self.assertIsNone(task["result"])
        self.assertEqual(task["languages"], [])
        self.assertEqual(task["plan"], [])
        self.assertFalse(task["report_ready"])
        self.assertIsNone(task["report"])
        graph.invoke.assert_not_called()
        graph.cancel_active_scan.assert_called_once_with()

    @staticmethod
    def _wait_for_task(client: TestClient, task_id: str) -> dict:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            response = client.get(f"/api/tasks/{task_id}", params={"user_id": "analyst"})
            task = response.json()["data"]
            if task["status"] in {"completed", "failed", "cancelled"}:
                return task
            time.sleep(0.03)
        raise AssertionError("task did not finish")

    @classmethod
    def _create_and_wait(cls, client: TestClient, root: Path, *, require_dependencies: bool = False) -> str:
        response = client.post(
            "/api/tasks",
            json={
                "objective": "scan python workspace",
                "workspace_path": str(root),
                "user_id": "analyst",
            },
        )
        if response.status_code != 202:
            raise AssertionError(response.text)
        task_id = response.json()["data"]["id"]
        task = cls._wait_for_task(client, task_id)
        if task.get("report_decision") != "pending":
            raise AssertionError(task)
        if require_dependencies and not task.get("result", {}).get("dependencies"):
            raise AssertionError("dependency details were not persisted")
        return task_id

    @staticmethod
    def _write_multilanguage_workspace(root: Path) -> None:
        files = {
            "src/App.java": "class App { String run(String value) { return value; } }\n",
            "src/app.py": "def run(value):\n    return value\n",
            "src/app.go": "package main\nfunc run(value string) string { return value }\n",
            "src/app.c": "int run(int value) { return value; }\n",
            "src/app.cpp": "int run(int value) { return value; }\n",
            "src/app.rs": "fn run(value: i32) -> i32 { value }\n",
            "src/App.sol": "pragma solidity ^0.8.20; contract App {}\n",
            "requirements.txt": "requests==2.32.4\n",
        }
        for relative, content in files.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
