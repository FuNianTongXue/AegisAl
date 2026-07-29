from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("SECFLOW_DISABLE_BATCH_SCHEDULER", "1")

from fastapi.testclient import TestClient

import app.main as main_module
from app.language_support import language_for_file
from app.reports import ReportStore, build_agent_task_markdown_report
from app.secure_storage import is_encrypted_text
from app.task_agent import (
    TaskAgentGraph,
    TaskAgentService,
    agent_task_report_ready,
    collect_workspace_inventory,
    compact_task_finding,
    read_workspace_attachments,
)
from app.task_store import AgentTaskStore


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class TaskReportReadinessTests(unittest.TestCase):
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
    def test_compact_finding_uses_enriched_file_and_risk_line(self) -> None:
        finding = compact_task_finding(
            {"id": "f1", "title": "risk", "file": "src/app.c", "risk_line": 42},
            1,
        )

        self.assertEqual(finding["file_name"], "src/app.c")
        self.assertEqual(finding["line"], 42)

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

            raw = path.read_text(encoding="utf-8")
            loaded = store.get("task-1")

        self.assertTrue(is_encrypted_text(raw))
        self.assertNotIn("inspect secret project", raw)
        self.assertEqual(loaded["objective"], "inspect secret project")

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
            self.assertNotIn("archived", path.read_text(encoding="utf-8"))

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

            service.shutdown(wait=True)
            persisted = AgentTaskStore(Path(temp_dir) / "tasks.json").get(task_id)

        self.assertEqual(task["status"], "completed")
        self.assertEqual(task["languages"], ["python"])
        self.assertEqual(task["result"]["total_findings"], 1)
        self.assertEqual(task["report_decision"], "pending")
        self.assertIn("event: languages.detected", events.text)
        self.assertIn("event: task.completed", events.text)
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
                    json={"confirm": True, "format": "html"},
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
        self.assertEqual(downloaded.json()["data"]["artifact"]["media_type"], "text/html; charset=utf-8")
        self.assertEqual(generated_task["report_decision"], "generated")
        self.assertEqual(repeated_task["report"]["id"], generated_task["report"]["id"])
        self.assertEqual(len(saved_reports), 1)
        self.assertEqual(set(saved_reports[0]["available_formats"]), {"md", "html", "docx", "pdf"})
        self.assertIn("requests", report_detail["content"])
        self.assertIn("requirements.txt", report_detail["content"])
        self.assertIn("app.py:1", report_detail["content"])
        self.assertIn("| MCP 调用状态 | 已完成", report_detail["content"])
        self.assertIn("1 | def run(value):", report_detail["content"])
        self.assertEqual(report_detail["metadata"]["report_mcp"]["status"], "completed")
        self.assertTrue(report_detail["metadata"]["report_mcp"]["output_sha256"])
        self.assertEqual(report_detail["metadata"]["report_schema_version"], 4)
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
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                task = service.get(task["id"])
                if task.get("current_node") == "scan_python":
                    break
                time.sleep(0.02)
            service.cancel(task["id"])
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                task = service.get(task["id"])
                if task["status"] == "cancelled":
                    break
                time.sleep(0.02)
            service.shutdown(wait=True)

        self.assertEqual(task["status"], "cancelled")
        self.assertTrue(any(event["type"] == "task.cancelled" for event in task["events"]))

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
