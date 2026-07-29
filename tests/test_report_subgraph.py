from __future__ import annotations

import os
import asyncio
import io
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from app.report_mcp import invoke_report_chart_mcp, report_mcp_specs
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
    def test_report_mcp_catalog_exposes_format_specific_servers(self) -> None:
        specs = asyncio.run(report_mcp_specs())
        tools = {item["id"]: [tool["name"] for tool in item["tools"]] for item in specs}
        self.assertEqual(tools["report-mermaid"], ["build_report_mermaid"])
        self.assertEqual(tools["report-markdown"], ["render_markdown_report"])
        self.assertEqual(tools["report-word"], ["render_word_report"])
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
            snippet = report_json["source"]["facts"]["code_findings"][0]["vulnerable_snippet"]
            snippet_lines = report_json["source"]["facts"]["code_findings"][0]["snippet_lines"]
            remediation = report_json["source"]["facts"]["code_findings"][0]["remediation"]
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
                    "build_scan_report_charts",
                    "build_report_mermaid",
                    "render_markdown_report",
                    "render_word_report",
                    "render_pdf_report",
                ],
            )
            completed_audits = [item for item in generated["report_mcps"] if item["status"] == "completed"]
            self.assertEqual(len(completed_audits), 5)
            source_hash = report_json["audit"]["source_payload_sha256"]
            self.assertTrue(all(item.get("input_sha256") == source_hash for item in completed_audits))
            self.assertEqual(report["metadata"]["report_mcp"]["status"], "completed")
            self.assertEqual(len(report["metadata"]["report_mcps"]), 5)
            self.assertIn("| MCP status | completed", report["content"])
            self.assertIn("run(value)", report["content"])
            self.assertEqual(report_json["$schema"], "secflow.report-document/v1")
            self.assertEqual(report_json["source"]["$schema"], "secflow.scan-results/v1")
            self.assertEqual(report_json["source"]["counts"]["code_findings"], 1)
            self.assertEqual(
                report_json["source"]["facts"]["code_findings"][0]["vulnerable_snippet"],
                "run(value)",
            )
            self.assertTrue(report_json["audit"]["source_payload_sha256"])
            self.assertIn("html_renderer_json", report["render_pipeline"])
            self.assertIn("report_mermaid_mcp_json", report["render_pipeline"])
            self.assertIn("report_markdown_mcp_json", report["render_pipeline"])
            self.assertIn("report_word_mcp_docx", report["render_pipeline"])
            self.assertIn("report_pdf_mcp_pdf", report["render_pipeline"])
            self.assertEqual(set(report["available_formats"]), {"md", "html", "docx", "pdf"})
            docx_path, _, docx_type = store.resolve_download(report["id"], "docx")
            self.assertTrue(docx_path.read_bytes().startswith(b"PK"))
            with zipfile.ZipFile(io.BytesIO(docx_path.read_bytes())) as bundle:
                styles_xml = bundle.read("word/styles.xml").decode("utf-8")
                font_table_xml = bundle.read("word/fontTable.xml").decode("utf-8")
            self.assertIn('w:eastAsia="PingFang SC"', styles_xml)
            self.assertIn('w:name="PingFang SC"', font_table_xml)
            self.assertIn('w:altName w:val="Arial Unicode MS"', font_table_xml)
            self.assertIn('w:name="SF Pro Text"', font_table_xml)
            self.assertIn('w:altName w:val="Arial"', font_table_xml)
            self.assertEqual(
                docx_type,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            )
            pdf_path, _, _ = store.resolve_download(report["id"], "pdf")
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))

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
            self.assertEqual(len(names), 6)
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
                    {".md", ".html", ".docx", ".pdf"},
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
            self.assertEqual(set(natural["interrupt"]["formats"]), {"md", "html", "docx", "pdf"})


if __name__ == "__main__":
    unittest.main()
