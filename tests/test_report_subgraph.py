from __future__ import annotations

import os
import asyncio
import base64
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.report_mcp import invoke_report_chart_mcp, report_mcp_specs
from app.mcp.report_mermaid import _image_font, build_report_mermaid
from app.mcp.report_sarif import build_scan_sarif
from app.report_subgraph import ReportCapabilitySubgraph
from app.reports import ReportStore, build_scan_result_json, report_artifact_store
from app.task_agent import TaskAgentGraph, agent_task_report_metrics


REPORT_BODY = """# Demo vulnerability report

- Generated at: 2026-07-26T00:00:00+00:00

## 1. Executive summary

- Severity: HIGH
- Risk location: demo.py:10

## 2. Method and limitations

Verified scan facts only.
"""


class ReportSubgraphTests(unittest.TestCase):
    def test_sarif_mermaid_and_jpeg_preserve_every_long_taint_path_node(self) -> None:
        path = [
            {
                "kind": "source" if index == 0 else "sink" if index == 31 else "propagation",
                "file": "src/long_flow.py",
                "line": index + 10,
                "label": f"ordered-node-{index}",
                "snippet": f"value_{index} = step_{index}(value_{index - 1})" if index else "value_0 = request.args['input']",
            }
            for index in range(32)
        ]
        scan_json = build_scan_result_json(
            {
                "static_analysis": {
                    "findings": [
                        {
                            "id": "long-taint-flow",
                            "rule_id": "python.long-taint-flow",
                            "title": "Long taint flow",
                            "severity": "HIGH",
                            "file_name": "src/long_flow.py",
                            "line": 41,
                            "taint_path": path,
                            "vulnerable_snippet": "dangerous(value_31)",
                            "remediation": "Validate the input and use a safe API.",
                        }
                    ]
                }
            },
            source_kind="assistant_scan",
            language="zh-Hans",
        )

        sarif = build_scan_sarif(scan_json).model_dump()
        locations = sarif["sarif"]["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
        self.assertEqual(len(locations), 32)
        self.assertEqual([item["executionOrder"] for item in locations], list(range(1, 33)))
        self.assertEqual(locations[-1]["location"]["message"]["text"], "ordered-node-31")
        self.assertEqual(
            locations[-1]["location"]["physicalLocation"]["region"]["snippet"]["text"],
            "value_31 = step_31(value_30)",
        )

        mermaid = build_report_mermaid(scan_json, sarif=sarif, language="zh-Hans")
        diagram = mermaid.diagrams[0]
        self.assertEqual(mermaid.taint_path_count, 1)
        self.assertEqual(mermaid.taint_node_count, 32)
        self.assertEqual(diagram.node_count, 32)
        self.assertEqual(diagram.source.count("[\""), 32)
        self.assertIn("ordered-node-0", diagram.source)
        self.assertIn("ordered-node-31", diagram.source)
        self.assertIn("value_31 = step_31(value_30)", diagram.source)
        self.assertTrue(base64.b64decode(diagram.image_base64).startswith(b"\xff\xd8\xff"))
        self.assertGreater(diagram.height, 32 * 100)

    def test_report_agent_uses_completed_task_scan_json_for_generation_interrupt(self) -> None:
        graph = KnowledgeSecurityGraph()
        report_subgraph = Mock()
        report_subgraph.start.return_value = {
            "status": "interrupted",
            "thread_id": "report-thread-1",
            "summary": "等待确认生成报告。",
            "interrupt": {
                "interrupt_id": "interrupt-report-1",
                "kind": "report_generation_confirmation",
                "action": "generate",
                "question": "是否生成报告？",
                "options": ["confirm", "cancel"],
            },
            "artifacts": [],
        }
        graph._report_subgraph = report_subgraph
        task = {
            "id": "task-report-1",
            "status": "completed",
            "workspace_name": "demo",
            "result": {"total_findings": 1, "language_results": {}},
        }

        outcome = graph._run_report_subgraph(
            {
                "question": "基于本次扫描事实生成报告",
                "user_id": "analyst",
                "session_id": "session-1",
                "response_language": "zh-Hans",
                "intent": "report_operation",
                "task_context": {"report_task": task},
                "answer": {},
                "trace": [],
            }
        )

        payload = report_subgraph.start.call_args.args[0]
        self.assertEqual(payload["source_kind"], "agent_task")
        self.assertEqual(payload["scan_data"]["task"]["id"], task["id"])
        self.assertEqual(payload["scan_data"]["report_metrics"]["code_findings"], 1)
        self.assertEqual(outcome["answer"]["interrupt"]["kind"], "report_generation_confirmation")

    def test_mermaid_renderer_prefers_available_macos_cjk_font(self) -> None:
        candidates = [
            Path("/System/Library/Fonts/PingFang.ttc"),
            Path("/System/Library/Fonts/LanguageSupport/PingFang.ttc"),
            *sorted(Path("/System/Library/AssetsV2/com_apple_MobileAsset_Font8").glob("*.asset/AssetData/PingFang.ttc")),
            Path("/System/Library/Fonts/STHeiti Light.ttc"),
        ]
        expected = next((path for path in candidates if path.is_file()), None)
        if expected is None:
            self.skipTest("macOS CJK system font is not available")

        font = _image_font(20)

        self.assertEqual(Path(str(font.path)), expected)

    def test_report_mcp_catalog_exposes_format_specific_servers(self) -> None:
        specs = asyncio.run(report_mcp_specs())
        tools = {item["id"]: [tool["name"] for tool in item["tools"]] for item in specs}
        self.assertEqual(tools["report-sarif"], ["build_scan_sarif"])
        self.assertEqual(tools["report-template"], ["resolve_report_template"])
        self.assertEqual(tools["report-mermaid"], ["build_report_mermaid"])
        self.assertEqual(tools["report-markdown"], ["render_markdown_report"])
        self.assertEqual(tools["report-word"], ["render_word_report"])
        self.assertEqual(tools["report-excel"], ["render_excel_report"])
        self.assertEqual(tools["report-pdf"], ["render_pdf_report"])

    def test_scan_json_rejects_code_finding_without_verifiable_evidence(self) -> None:
        with self.assertRaisesRegex(ValueError, "verifiable evidence snippet"):
            build_scan_result_json(
                {
                    "question": "scan demo",
                    "static_analysis": {
                        "findings": [
                            {
                                "id": "finding-without-evidence",
                                "title": "Missing evidence",
                                "file": "demo.py",
                                "risk_line": 10,
                            }
                        ]
                    },
                },
                source_kind="assistant_scan",
            )

    def test_real_uploaded_project_preserves_dependency_and_multiline_code_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_SEMGREP_DISABLE_CLI": "0"},
        ):
            workspace = Path(temp_dir) / "uploaded-command-demo"
            workspace.mkdir()
            (workspace / "app.py").write_text(
                "import os\n"
                "from flask import request\n\n"
                "def run():\n"
                "    command = request.args.get(\"cmd\")\n"
                "    os.system(command)\n",
                encoding="utf-8",
            )
            (workspace / "requirements.txt").write_text(
                "Flask==2.2.5\nrequests==2.32.4\n",
                encoding="utf-8",
            )
            state = TaskAgentGraph(adaptive_upload=False).invoke(
                task_id="uploaded-project-report",
                objective="以普通用户上传方式扫描项目并生成报告",
                workspace_path=str(workspace),
                user_id="analyst",
            )
            task = {
                "id": "uploaded-project-report",
                "objective": "以普通用户上传方式扫描项目并生成报告",
                "workspace_path": str(workspace),
                "workspace_name": workspace.name,
                "workspace_type": "directory",
                "languages": state["languages"],
                "events": [],
                "result": state["result"],
            }
            store = ReportStore(Path(temp_dir) / "reports")
            graph = ReportCapabilitySubgraph()
            started = graph.start(
                {
                    "action": "generate",
                    "user_id": "analyst",
                    "session_id": "real-upload-report",
                    "response_language": "zh-Hans",
                    "source_kind": "agent_task",
                    "scan_data": {"task": task, "report_metrics": agent_task_report_metrics(task)},
                    "report_store_root": str(store.root),
                }
            )
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="real-upload-report",
            )
            report_id = generated["report"]["id"]
            report_json = store.get_report_json(report_id)
            html_path, _, _ = store.resolve_download(report_id, "html")
            pdf_path, _, _ = store.resolve_download(report_id, "pdf")

            self.assertEqual(generated["interrupt"]["kind"], "report_download_confirmation")
            self.assertEqual(report_json["source"]["counts"]["dependencies"], 2)
            self.assertEqual(report_json["source"]["counts"]["code_findings"], 1)
            report_finding = report_json["source"]["facts"]["code_findings"][0]
            snippet = report_finding["vulnerable_snippet"]
            snippet_lines = report_finding["snippet_lines"]
            remediation = report_finding["remediation"]
            self.assertEqual(report_finding["file_name"], "app.py")
            self.assertEqual(report_finding["path"], "app.py")
            self.assertIn("subprocess.run", report_finding["fixed_snippet"])
            self.assertNotIn("ProcessBuilder", report_finding["fixed_snippet"])
            self.assertIn("command = request.args.get", snippet)
            self.assertIn("\n", snippet)
            self.assertIn("os.system(command)", snippet)
            self.assertTrue(any(item["is_risk"] for item in snippet_lines))
            self.assertTrue(remediation)
            self.assertEqual(generated["report_charts"]["code_blocks"][0]["lines"], snippet_lines)
            html_report = html_path.read_text(encoding="utf-8")
            self.assertIn("<pre", html_report)
            self.assertIn("os.system(command)", html_report)
            self.assertIn("white-space: pre-wrap", html_report)
            self.assertIn('class="code-row risk"', html_report)
            self.assertIn('class="code-line-number"', html_report)
            self.assertIn('class="code-source"', html_report)
            self.assertIn("修复方案", html_report)
            self.assertGreater(pdf_path.stat().st_size, 10_000)

    def test_scan_json_and_report_mcp_normalize_large_line_numbers_and_long_source(self) -> None:
        long_source = 'return response.withHeader("X-Audit-Context", "' + ("a" * 420) + '");'
        scan_json = build_scan_result_json(
            {
                "question": "scan demo",
                "static_analysis": {
                    "findings": [
                        {
                            "id": "finding-long-line",
                            "title": "Long evidence line",
                            "file": "src/main/java/example/payment/PaymentController.java",
                            "risk_line": 10000,
                            "line_start": 9998,
                            "line_end": 10100,
                            "vulnerable_snippet": "prepare();\nvalidate();\n" + long_source + "\ncommit();",
                        }
                    ]
                },
            },
            source_kind="assistant_scan",
        )

        finding = scan_json["facts"]["code_findings"][0]
        self.assertEqual(finding["line_start"], 9998)
        self.assertEqual(finding["line_end"], 10001)
        self.assertEqual([item["number"] for item in finding["snippet_lines"]], [9998, 9999, 10000, 10001])
        self.assertEqual([item["number"] for item in finding["snippet_lines"] if item["is_risk"]], [10000])
        self.assertEqual(finding["snippet_lines"][2]["text"], long_source)
        self.assertTrue(finding["remediation"])

        rendered = invoke_report_chart_mcp({"report_json": scan_json})
        block = rendered["code_blocks"][0]
        self.assertEqual(block["finding_id"], "finding-long-line")
        self.assertEqual(block["line_start"], 9998)
        self.assertEqual(block["line_end"], 10001)
        self.assertEqual(block["risk_line"], 10000)
        self.assertEqual(block["lines"], finding["snippet_lines"])

    def test_chart_mcp_uses_only_completed_scan_facts(self) -> None:
        result = invoke_report_chart_mcp(
            {
                "source_kind": "assistant_scan",
                "scan_data": {
                    "records": [
                        {
                            "id": "CVE-2026-0001",
                            "severity": "HIGH",
                            "components": [{"name": "demo-lib"}],
                        }
                    ],
                    "static_analysis": {
                        "findings": [
                            {
                                "id": "finding-1",
                                "title": "Command injection",
                                "scenario": "command_execution",
                                "severity": "CRITICAL",
                                "sink": {"file": "demo.py", "line": 10},
                            }
                        ]
                    },
                },
            }
        )

        self.assertEqual(result["renderer"], "d3-report-charts")
        self.assertEqual(result["fact_count"], 2)
        severity = {item["severity"]: item["value"] for item in result["severity_ring"]}
        self.assertEqual(severity["CRITICAL"], 1)
        self.assertEqual(severity["HIGH"], 1)
        self.assertEqual(len(result["sankey_links"]), 2)

    def test_generate_then_download_requires_two_native_interrupts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ReportStore(Path(temp_dir) / "reports")
            graph = ReportCapabilitySubgraph()
            scan_data = {
                "question": "scan demo",
                "dependency_scan": {
                    "files": [{"file_name": "demo.py", "kind": "code"}],
                    "dependencies": [],
                },
                "records": [],
                "static_analysis": {
                    "finding_count": 1,
                    "findings": [
                        {
                            "id": "finding-1",
                            "title": "Command injection",
                            "scenario": "command_execution",
                            "severity": "HIGH",
                            "sink": {"file": "demo.py", "line": 10, "snippet": "run(value)"},
                            "path": [
                                {
                                    "kind": "source",
                                    "file": "demo.py",
                                    "line": 4,
                                    "label": "HTTP request parameter",
                                    "snippet": "value = request.args['cmd']",
                                },
                                {
                                    "kind": "call",
                                    "file": "demo.py",
                                    "line": 7,
                                    "label": "value propagated to helper",
                                    "snippet": "dispatch(value)",
                                },
                                {
                                    "kind": "sink",
                                    "file": "demo.py",
                                    "line": 10,
                                    "label": "command execution sink",
                                    "snippet": "run(value)",
                                },
                            ],
                        }
                    ],
                },
                "summary": "One verified code finding.",
                "fields": {},
                "report_metrics": {
                    "language": "en",
                    "code_findings": 1,
                    "dependency_vulnerabilities": 0,
                    "severity": {"HIGH": 1},
                },
                "input_fingerprint": "test-report-flow",
            }
            started = graph.start(
                {
                    "action": "generate",
                    "user_id": "analyst",
                    "session_id": "session-1",
                    "response_language": "en",
                    "source_kind": "assistant_scan",
                    "scan_data": scan_data,
                    "report_store_root": str(store.root),
                }
            )
            self.assertEqual(started["status"], "interrupted")
            self.assertEqual(started["interrupt"]["kind"], "report_generation_confirmation")
            with self.assertRaises(KeyError):
                graph.resume(
                    started["thread_id"],
                    decision="confirm",
                    user_id="another-user",
                    session_id="session-1",
                )

            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="session-1",
            )
            self.assertEqual(generated["status"], "interrupted")
            self.assertEqual(generated["interrupt"]["kind"], "report_download_confirmation")
            report = store.get_report(generated["report"]["id"])
            report_json = store.get_report_json(generated["report"]["id"])
            self.assertEqual(report["metadata"]["chart_mcp"], "build_scan_report_charts")
            self.assertEqual(report["metadata"]["report_charts"]["fact_count"], 1)
            self.assertEqual(generated["report_mcp"]["status"], "completed")
            self.assertEqual(
                [item["tool"] for item in generated["report_mcps"]],
                [
                    "translate_json_payload",
                    "build_scan_sarif",
                    "build_scan_report_charts",
                    "resolve_report_template",
                    "build_report_mermaid",
                    "render_markdown_report",
                    "render_word_report",
                    "render_excel_report",
                    "render_pdf_report",
                ],
            )
            completed_audits = [item for item in generated["report_mcps"] if item["status"] == "completed"]
            self.assertEqual(len(completed_audits), 9)
            source_hash = report_json["audit"]["source_payload_sha256"]
            self.assertTrue(all(item.get("input_sha256") == source_hash for item in completed_audits))
            self.assertEqual(report["metadata"]["report_mcp"]["status"], "completed")
            self.assertEqual(len(report["metadata"]["report_mcps"]), 9)
            self.assertIn("| MCP status | completed", report["content"])
            self.assertIn("run(value)", report["content"])
            self.assertEqual(report_json["$schema"], "secflow.report-document/v1")
            self.assertEqual(report_json["source"]["$schema"], "secflow.scan-results/v1")
            self.assertEqual(report_json["template"]["id"], "security")
            self.assertEqual(report_json["qa"]["status"], "passed")
            self.assertEqual(report_json["qa"]["score"], 100)
            self.assertEqual(report_json["statistics"]["counts"]["code_findings"], 1)
            self.assertEqual(len(report_json["findings"]), 1)
            self.assertEqual(report_json["source"]["counts"]["code_findings"], 1)
            self.assertEqual(
                report_json["source"]["facts"]["code_findings"][0]["vulnerable_snippet"],
                "run(value)",
            )
            self.assertTrue(report_json["audit"]["source_payload_sha256"])
            self.assertTrue(report_json["audit"]["report_blocks_sha256"])
            self.assertTrue(report_json["audit"]["sarif_sha256"])
            self.assertTrue(report_json["audit"]["visuals_sha256"])
            thread_locations = report_json["sarif"]["sarif"]["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
            self.assertEqual([item["executionOrder"] for item in thread_locations], [1, 2, 3])
            self.assertEqual([item["kinds"][0] for item in thread_locations], ["source", "propagation", "sink"])
            self.assertEqual(
                [item["location"]["physicalLocation"]["region"]["snippet"]["text"] for item in thread_locations],
                ["value = request.args['cmd']", "dispatch(value)", "run(value)"],
            )
            taint_diagram = report_json["visuals"]["diagrams"][0]
            self.assertEqual(report_json["visuals"]["taint_path_count"], 1)
            self.assertEqual(report_json["visuals"]["taint_node_count"], 3)
            self.assertEqual(taint_diagram["node_count"], 3)
            self.assertIn("value = request.args['cmd']", taint_diagram["source"])
            self.assertIn("dispatch(value)", taint_diagram["source"])
            self.assertIn("run(value)", taint_diagram["source"])
            self.assertEqual(taint_diagram["image_media_type"], "image/jpeg")
            self.assertTrue(any(
                block.get("type") == "diagram" and block.get("sha256") == taint_diagram["image_sha256"]
                for section in report_json["report"]["sections"]
                for block in section.get("blocks") or []
            ))
            self.assertIn("html_renderer_json", report["render_pipeline"])
            self.assertIn("report_sarif_mcp_json", report["render_pipeline"])
            self.assertIn("report_mermaid_mcp_json", report["render_pipeline"])
            self.assertIn("report_markdown_mcp_json", report["render_pipeline"])
            self.assertIn("report_word_mcp_docx", report["render_pipeline"])
            self.assertIn("report_excel_mcp_xlsx", report["render_pipeline"])
            self.assertIn("report_pdf_mcp_pdf", report["render_pipeline"])
            self.assertIn("data:image/jpeg;base64,", report["content"])
            self.assertNotIn("```mermaid", report["content"])
            self.assertNotIn("flowchart LR", report["content"])
            self.assertEqual(set(report["available_formats"]), {"md", "html", "docx", "xlsx", "pdf"})
            html_path, _, _ = store.resolve_download(report["id"], "html")
            html_content = html_path.read_text(encoding="utf-8")
            self.assertIn('class="mermaid-diagram"', html_content)
            self.assertIn("data:image/jpeg;base64,", html_content)
            self.assertNotIn("flowchart LR", html_content)
            docx_path, _, docx_type = store.resolve_download(report["id"], "docx")
            self.assertTrue(docx_path.read_bytes().startswith(b"PK"))
            with zipfile.ZipFile(io.BytesIO(docx_path.read_bytes())) as bundle:
                styles_xml = bundle.read("word/styles.xml").decode("utf-8")
                font_table_xml = bundle.read("word/fontTable.xml").decode("utf-8")
                document_xml = bundle.read("word/document.xml").decode("utf-8")
                media_entries = [name for name in bundle.namelist() if name.startswith("word/media/")]
            self.assertGreaterEqual(len(media_entries), 1)
            self.assertIn('w:eastAsia="PingFang SC"', styles_xml)
            self.assertIn('w:name="PingFang SC"', font_table_xml)
            self.assertIn('w:altName w:val="Arial Unicode MS"', font_table_xml)
            self.assertIn('w:name="SF Pro Text"', font_table_xml)
            self.assertIn('w:altName w:val="Arial"', font_table_xml)
            self.assertIn("w:cantSplit", document_xml)
            self.assertIn("w:tblHeader", document_xml)
            self.assertIn('w:eastAsia="zh-CN"', document_xml)
            self.assertIn('w:hint="eastAsia"', document_xml)
            self.assertIn('w:ascii="Arial Unicode MS"', document_xml)
            self.assertEqual(
                docx_type,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
            xlsx_path, _, xlsx_type = store.resolve_download(report["id"], "xlsx")
            self.assertTrue(xlsx_path.read_bytes().startswith(b"PK"))
            with zipfile.ZipFile(io.BytesIO(xlsx_path.read_bytes())) as workbook:
                workbook_names = set(workbook.namelist())
                shared_strings = workbook.read("xl/sharedStrings.xml").decode("utf-8")
            self.assertIn("[Content_Types].xml", workbook_names)
            self.assertIn("xl/workbook.xml", workbook_names)
            self.assertIn("高危", shared_strings)
            self.assertNotIn(">HIGH<", shared_strings)
            self.assertEqual(
                xlsx_type,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            pdf_path, _, _ = store.resolve_download(report["id"], "pdf")
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))
            self.assertIn(b"/Subtype /Image", pdf_path.read_bytes())
            bundle_artifact = store.prepare_download_artifact(
                [report["id"]],
                ["md", "html", "docx", "xlsx", "pdf"],
                user_id="analyst",
            )
            bundle_path, _, _ = report_artifact_store.resolve(bundle_artifact["id"])
            with zipfile.ZipFile(bundle_path) as bundle:
                bundle_names = bundle.namelist()
                self.assertEqual(sum(name.endswith(".json") for name in bundle_names), 2)
                self.assertTrue(any(name.endswith(".sarif.json") for name in bundle_names))

            downloaded = graph.resume(
                started["thread_id"],
                decision="confirm",
                report_format="pdf",
                user_id="analyst",
                session_id="session-1",
            )
            self.assertEqual(downloaded["status"], "completed")
            self.assertEqual(downloaded["artifacts"][0]["media_type"], "application/pdf")
            artifact_path, _, _ = report_artifact_store.resolve(downloaded["artifacts"][0]["id"])
            self.assertTrue(artifact_path.read_bytes().startswith(b"%PDF"))

    def test_cancel_generation_does_not_write_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ReportStore(Path(temp_dir) / "reports")
            graph = ReportCapabilitySubgraph()
            started = graph.start(
                {
                    "action": "generate",
                    "user_id": "analyst",
                    "session_id": "session-2",
                    "source_kind": "assistant_scan",
                    "scan_data": {"question": "scan", "static_analysis": {"findings": []}},
                    "report_store_root": str(store.root),
                }
            )
            cancelled = graph.resume(
                started["thread_id"],
                decision="cancel",
                user_id="analyst",
                session_id="session-2",
            )
            self.assertEqual(cancelled["status"], "cancelled")
            self.assertEqual(store.list_reports(), [])

    def test_mcp_failure_is_visible_and_blocks_report_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "app.report_subgraph.invoke_report_chart_mcp",
            side_effect=RuntimeError("renderer unavailable"),
        ):
            store = ReportStore(Path(temp_dir) / "reports")
            graph = ReportCapabilitySubgraph()
            started = graph.start(
                {
                    "action": "generate",
                    "user_id": "analyst",
                    "session_id": "session-mcp-failure",
                    "source_kind": "assistant_scan",
                    "scan_data": {"question": "scan", "static_analysis": {"findings": []}},
                    "report_store_root": str(store.root),
                }
            )
            failed = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="session-mcp-failure",
            )

        self.assertEqual(failed["status"], "failed")
        self.assertEqual(failed["report_mcp"]["status"], "failed")
        self.assertIn("renderer unavailable", failed["error"])
        self.assertEqual(failed["report"], {})
        self.assertEqual(store.list_reports(), [])

    def test_mermaid_image_failure_never_falls_back_to_raw_relationship_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "app.report_subgraph.invoke_report_mermaid_mcp",
            side_effect=RuntimeError("mermaid image renderer unavailable"),
        ):
            store = ReportStore(Path(temp_dir) / "reports")
            graph = ReportCapabilitySubgraph()
            started = graph.start(
                {
                    "action": "generate",
                    "user_id": "analyst",
                    "session_id": "session-mermaid-failure",
                    "source_kind": "assistant_scan",
                    "scan_data": {"question": "scan", "static_analysis": {"findings": []}},
                    "report_store_root": str(store.root),
                }
            )
            failed = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="session-mermaid-failure",
            )

        self.assertEqual(failed["status"], "failed")
        self.assertIn("mermaid image renderer unavailable", failed["error"])
        self.assertEqual(failed["report"], {})
        self.assertEqual(store.list_reports(), [])

    def test_download_all_builds_auditable_zip_after_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ReportStore(Path(temp_dir) / "reports")
            for index in range(2):
                store.save_markdown(
                    f"Demo report {index}",
                    REPORT_BODY,
                    mode="agent_static_scan",
                    vulnerability_count=0,
                    finding_count=1,
                    metadata={"user_id": "analyst", "language": "en"},
                    input_fingerprint=f"bundle-{index}",
                )
            graph = ReportCapabilitySubgraph()
            started = graph.start(
                {
                    "action": "download_all",
                    "formats": ["md", "html", "pdf"],
                    "user_id": "analyst",
                    "session_id": "session-3",
                    "report_store_root": str(store.root),
                }
            )
            self.assertEqual(started["interrupt"]["kind"], "report_download_confirmation")
            completed = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="session-3",
            )
            artifact = completed["artifacts"][0]
            path, _, media_type = report_artifact_store.resolve(artifact["id"])
            self.assertEqual(media_type, "application/zip")
            with zipfile.ZipFile(path) as bundle:
                names = bundle.namelist()
            self.assertEqual(len(names), 8)
            self.assertEqual(sum(name.endswith(".json") for name in names), 2)
            self.assertTrue(any(name.endswith(".pdf") for name in names))

    def test_download_interrupt_supports_cancel_single_formats_and_all_formats(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            store = ReportStore(Path(temp_dir) / "reports")
            report = store.save_markdown(
                "Demo report",
                REPORT_BODY,
                mode="agent_static_scan",
                vulnerability_count=0,
                finding_count=1,
                metadata={"user_id": "analyst", "language": "en"},
                input_fingerprint="interrupt-formats",
            )

            cancelled_graph = ReportCapabilitySubgraph()
            cancelled = cancelled_graph.start(
                {
                    "action": "download_report",
                    "report_ids": [report["id"]],
                    "user_id": "analyst",
                    "session_id": "download-cancel",
                    "report_store_root": str(store.root),
                }
            )
            self.assertEqual(cancelled["interrupt"]["kind"], "report_download_confirmation")
            declined = cancelled_graph.resume(
                cancelled["thread_id"],
                decision="cancel",
                user_id="analyst",
                session_id="download-cancel",
            )
            self.assertEqual(declined["status"], "cancelled")
            self.assertEqual(declined["artifacts"], [])

            for report_format, media_type in (
                ("md", "text/markdown; charset=utf-8"),
                ("html", "text/html; charset=utf-8"),
                ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
                ("pdf", "application/pdf"),
            ):
                with self.subTest(report_format=report_format):
                    graph = ReportCapabilitySubgraph()
                    started = graph.start(
                        {
                            "action": "download_report",
                            "report_ids": [report["id"]],
                            "user_id": "analyst",
                            "session_id": f"download-{report_format}",
                            "report_store_root": str(store.root),
                        }
                    )
                    completed = graph.resume(
                        started["thread_id"],
                        decision="confirm",
                        report_format=report_format,
                        user_id="analyst",
                        session_id=f"download-{report_format}",
                    )
                    self.assertEqual(completed["status"], "completed")
                    self.assertEqual(completed["artifacts"][0]["media_type"], media_type)

            all_formats_graph = ReportCapabilitySubgraph()
            all_formats = all_formats_graph.start(
                {
                    "action": "download_report_all_formats",
                    "report_ids": [report["id"]],
                    "user_id": "analyst",
                    "session_id": "download-all-formats",
                    "report_store_root": str(store.root),
                }
            )
            completed = all_formats_graph.resume(
                all_formats["thread_id"],
                decision="confirm",
                user_id="analyst",
                session_id="download-all-formats",
            )
            artifact_path, _, media_type = report_artifact_store.resolve(completed["artifacts"][0]["id"])
            self.assertEqual(media_type, "application/zip")
            with zipfile.ZipFile(artifact_path) as bundle:
                self.assertEqual(
                    {Path(name).suffix for name in bundle.namelist()},
                    {".md", ".html", ".docx", ".xlsx", ".pdf", ".json"},
                )
                self.assertEqual(sum(name.endswith(".json") for name in bundle.namelist()), 1)

            selectable_all_graph = ReportCapabilitySubgraph()
            selectable_all = selectable_all_graph.start(
                {
                    "action": "download_report",
                    "report_ids": [report["id"]],
                    "user_id": "analyst",
                    "session_id": "download-selectable-all-formats",
                    "report_store_root": str(store.root),
                }
            )
            selectable_completed = selectable_all_graph.resume(
                selectable_all["thread_id"],
                decision="confirm",
                report_format="all",
                user_id="analyst",
                session_id="download-selectable-all-formats",
            )
            selectable_path, selectable_name, selectable_media_type = report_artifact_store.resolve(
                selectable_completed["artifacts"][0]["id"]
            )
            self.assertTrue(selectable_name.endswith(".zip"))
            self.assertEqual(selectable_media_type, "application/zip")
            with zipfile.ZipFile(selectable_path) as selectable_bundle:
                self.assertEqual(
                    {Path(name).suffix for name in selectable_bundle.namelist()},
                    {".md", ".html", ".docx", ".xlsx", ".pdf", ".json"},
                )

            natural_language_graph = ReportCapabilitySubgraph()
            natural = natural_language_graph.start(
                {
                    "question": f"下载当前报告全部格式 {report['id']}",
                    "user_id": "analyst",
                    "session_id": "download-natural-all-formats",
                    "report_store_root": str(store.root),
                }
            )
            self.assertEqual(natural["interrupt"]["action"], "download_report_all_formats")
            self.assertFalse(natural["interrupt"]["allow_format_selection"])
            self.assertEqual(set(natural["interrupt"]["formats"]), {"md", "html", "docx", "xlsx", "pdf"})


if __name__ == "__main__":
    unittest.main()
