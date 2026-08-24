from __future__ import annotations

import json
import os
import sqlite3
import unittest
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from xml.etree import ElementTree

from fastapi.testclient import TestClient
from langgraph.checkpoint.sqlite import SqliteSaver
from app.agent import assistant_intent
from app.api.routes import application
from app.langgraph.checkpoints import InterruptStateConflictError
from app.langgraph.sbom_graph import ProjectSBOMSubgraph, project_sbom_subgraph
from app.mcp.sbom import SBOMArtifactStore, _china_datetime, build_sbom_workbook
from app.sbom import build_cyclonedx_sbom, canonical_sbom_json, localized_intelligence_source, match_sbom_vulnerabilities


POM = """<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>example</groupId><artifactId>payments</artifactId><version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>"""


def fake_match_result() -> dict:
    return {
        "records": [
            {
                "id": "CVE-2021-44228",
                "title": "Log4Shell",
                "summary": "JNDI lookup injection in vulnerable Log4j versions.",
                "severity": "CRITICAL",
                "cvss_score": 10.0,
                "matched_dependencies": [
                    {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1"}
                ],
                "components": [],
                "fixed_versions": ["2.17.1"],
                "affected_versions": ["<= 2.14.1"],
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
                "aliases": [],
                "provenance": ["osv"],
                "published_at": "2021-12-10T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }
        ],
        "source_status": [{"id": "osv", "status": "success", "count": 1, "message": "查询完成"}],
    }


def fake_artifact() -> dict:
    return {
        "id": "sbom-xlsx-20260728000000-abcdef123456",
        "kind": "excel",
        "file_name": "AegisAl-payments-SBOM.xlsx",
        "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "download_path": "/api/assistant/artifacts/sbom-xlsx-20260728000000-abcdef123456",
        "sha256": "a" * 64,
        "size": 4096,
        "generated_at": "2026-07-28T00:00:00+00:00",
    }


def fake_license_scan(_workspace_path: str) -> dict:
    return {
        "schema_version": 1,
        "coverage_status": "complete",
        "license_count": 1,
        "licenses": [
            {
                "spdx_id": "Apache-2.0",
                "name": "Apache License 2.0",
                "confidence": 0.95,
                "source_files": ["LICENSE"],
                "detection_methods": ["license-text-signature"],
                "declarations": [],
                "osi": {
                    "listed": True,
                    "approved": True,
                    "approval_status": "approved",
                    "official_url": "https://opensource.org/license/apache-2-0",
                },
            }
        ],
        "registry": {"status": "completed", "url": "https://opensource.org/api/licenses"},
        "_license_mcp": {
            "server": "AegisAl License MCP",
            "tool": "identify_project_licenses",
            "transport": "in-process",
        },
    }


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class SBOMDocumentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scan = {
            "files": [{"file_name": "pom.xml", "kind": "pom"}],
            "dependencies": [
                {
                    "ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                    "version": "2.14.1",
                    "source_file": "pom.xml",
                    "source_type": "pom",
                    "declaration": "org.apache.logging.log4j:log4j-core:2.14.1",
                    "confidence": "high",
                },
                {
                    "ecosystem": "npm",
                    "name": "left-pad",
                    "version": "",
                    "source_file": "package.json",
                    "source_type": "solidity_manifest",
                    "declaration": "left-pad",
                    "confidence": "high",
                },
            ],
            "dependency_count": 2,
            "rejected_files": [],
        }

    def test_cyclonedx_json_preserves_source_facts_and_purls(self) -> None:
        sbom = build_cyclonedx_sbom(
            self.scan,
            project_name="payments",
            workspace_path="/private/project",
            license_scan=fake_license_scan(""),
        )

        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertEqual(sbom["specVersion"], "1.6")
        self.assertEqual(len(sbom["components"]), 2)
        maven = next(item for item in sbom["components"] if item.get("group"))
        self.assertEqual(maven["group"], "org.apache.logging.log4j")
        self.assertEqual(maven["name"], "log4j-core")
        self.assertEqual(maven["purl"], "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
        self.assertEqual(sbom["metadata"]["component"]["licenses"][0]["license"]["id"], "Apache-2.0")
        self.assertTrue(
            any(item["name"] == "secflow:licenseAnalysisSha256" for item in sbom["metadata"]["properties"])
        )
        self.assertNotIn("/private/project", canonical_sbom_json(sbom))

    def test_dependency_extraction_layers_source_imports_without_manifests(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "app.py").write_text("import requests\n", encoding="utf-8")

            state = ProjectSBOMSubgraph._extract_dependencies({"workspace_path": str(root), "trace": []})

        scan = state["dependency_scan"]
        # SBOM 口径不变：无清单即无声明组件。
        self.assertEqual(scan["dependency_count"], 0)
        self.assertEqual(scan["dependencies"], [])
        # 源码 import 进入独立的 inferred 观察层，版本未知、不纳入 SBOM。
        self.assertEqual(scan["inferred_count"], 1)
        self.assertEqual(scan["inferred_dependencies"][0]["name"], "requests")
        self.assertEqual(scan["inferred_dependencies"][0]["layer"], "inferred")
        self.assertEqual(scan["inventory"]["manifest_files"], 0)
        self.assertEqual(scan["inventory"]["source_files"], 1)
        self.assertTrue(any("未发现支持的依赖清单" in item for item in scan["warnings"]))
        self.assertTrue(any("未纳入 SBOM" in item for item in scan["warnings"]))

    def test_vulnerability_matching_attaches_findings_to_component_bom_refs(self) -> None:
        sbom = build_cyclonedx_sbom(
            self.scan,
            project_name="payments",
            license_scan=fake_license_scan(""),
        )
        with patch("app.sbom.intelligence_service.query_dependencies", return_value=fake_match_result()):
            enriched, matching = match_sbom_vulnerabilities(sbom, self.scan)

        self.assertEqual(matching["coverage_status"], "complete")
        self.assertEqual(matching["unresolved_version_count"], 1)
        self.assertEqual(matching["vulnerability_count"], 1)
        self.assertEqual(len(enriched["vulnerabilities"][0]["affects"]), 1)
        localized_summary = matching["records"][0]["summary_zh"]
        localized_description = enriched["vulnerabilities"][0]["description"]
        for localized in (localized_summary, localized_description):
            self.assertRegex(localized, r"[\u3400-\u9fff]")
            self.assertIn("JNDI", localized)
            self.assertIn("Log4j", localized)
            self.assertNotIn("JNDI lookup injection in vulnerable Log4j versions.", localized)
        self.assertNotEqual(localized_summary, matching["records"][0]["summary"])
        self.assertEqual(enriched["vulnerabilities"][0]["source"]["name"], "OSV 开源漏洞数据库")
        self.assertEqual(
            next(
                item["value"]
                for item in enriched["vulnerabilities"][0]["properties"]
                if item["name"] == "secflow:sourceOriginal"
            ),
            "osv",
        )
        self.assertEqual(
            next(
                item["value"]
                for item in enriched["vulnerabilities"][0]["properties"]
                if item["name"] == "secflow:descriptionLanguage"
            ),
            "zh-Hans",
        )

    def test_workbook_has_required_sheets_wrapping_filters_and_audit_json(self) -> None:
        sbom = build_cyclonedx_sbom(
            self.scan,
            project_name="payments",
            license_scan=fake_license_scan(""),
        )
        with patch("app.sbom.intelligence_service.query_dependencies", return_value=fake_match_result()):
            sbom, matching = match_sbom_vulnerabilities(sbom, self.scan)
        content = build_sbom_workbook(sbom, matching)

        self.assertTrue(content.startswith(b"PK\x03\x04"))
        with zipfile.ZipFile(BytesIO(content)) as archive:
            self.assertIn("xl/worksheets/sheet1.xml", archive.namelist())
            workbook_xml = ElementTree.fromstring(archive.read("xl/workbook.xml"))
            namespace = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            sheet_names = [item.attrib["name"] for item in workbook_xml.findall("m:sheets/m:sheet", namespace)]
            self.assertEqual(sheet_names, ["摘要", "SBOM 组件", "项目许可", "漏洞匹配", "来源与审计"])
            summary_xml = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
            component_xml = archive.read("xl/worksheets/sheet2.xml").decode("utf-8")
            styles_xml = archive.read("xl/styles.xml").decode("utf-8")
            shared_strings = archive.read("xl/sharedStrings.xml").decode("utf-8")
            shared_root = ElementTree.fromstring(shared_strings)
            shared_values = ["".join(item.itertext()) for item in shared_root.findall("m:si", namespace)]
            license_root = ElementTree.fromstring(archive.read("xl/worksheets/sheet3.xml"))
            license_string_indexes = [
                int(value.text or "0")
                for cell in license_root.findall(".//m:c[@t='s']", namespace)
                for value in cell.findall("m:v", namespace)
            ]
            license_sheet_text = "\n".join(shared_values[index] for index in license_string_indexes)
            vulnerability_root = ElementTree.fromstring(archive.read("xl/worksheets/sheet4.xml"))
            vulnerability_string_indexes = [
                int(value.text or "0")
                for cell in vulnerability_root.findall(".//m:c[@t='s']", namespace)
                for value in cell.findall("m:v", namespace)
            ]
            vulnerability_sheet_text = "\n".join(shared_values[index] for index in vulnerability_string_indexes)
            self.assertIn("COUNTA('SBOM 组件'!A2:A1048576)", summary_xml)
            self.assertIn('<pane ySplit="1"', component_xml)
            self.assertIn('wrapText="1"', styles_xml)
            self.assertIn("SBOM JSON SHA-256", shared_strings)
            self.assertIn("CVE-2021-44228", shared_strings)
            self.assertIn("SPDX 标识", license_sheet_text)
            self.assertIn("Apache-2.0", license_sheet_text)
            self.assertIn("风险等级", vulnerability_sheet_text)
            self.assertIn("严重", vulnerability_sheet_text)
            self.assertNotIn("CRITICAL", vulnerability_sheet_text)
            self.assertIn("JNDI", vulnerability_sheet_text)
            self.assertIn("Log4j", vulnerability_sheet_text)
            self.assertIn("OSV 开源漏洞数据库", vulnerability_sheet_text)
            self.assertNotIn("JNDI lookup injection in vulnerable Log4j versions.", vulnerability_sheet_text)
            self.assertNotIn("AegisAl vulnerability intelligence", vulnerability_sheet_text)
            self.assertNotIn("T00:00:00Z", vulnerability_sheet_text)
            self.assertIn('formatCode="yyyy:mm:dd:hh:mm"', styles_xml)
            self.assertIn("JNDI lookup injection in vulnerable Log4j versions.", shared_strings)

    def test_workbook_uses_current_brand_for_table_objects(self) -> None:
        sbom = build_cyclonedx_sbom(
            self.scan,
            project_name="payments",
            license_scan=fake_license_scan(""),
        )
        with patch("app.sbom.intelligence_service.query_dependencies", return_value=fake_match_result()):
            sbom, matching = match_sbom_vulnerabilities(sbom, self.scan)

        with zipfile.ZipFile(BytesIO(build_sbom_workbook(sbom, matching))) as archive:
            table_names = [
                ElementTree.fromstring(archive.read(path)).attrib["name"]
                for path in sorted(name for name in archive.namelist() if name.startswith("xl/tables/table"))
            ]

        self.assertEqual(
            table_names,
            ["AegisAlSBOMComponents", "AegisAlProjectLicenses", "AegisAlSBOMVulnerabilities"],
        )

    def test_workbook_dates_are_converted_to_china_time(self) -> None:
        self.assertEqual(_china_datetime("2021-12-10T00:00:00Z"), datetime(2021, 12, 10, 8, 0))
        self.assertEqual(_china_datetime("2026-07-29T08:30:00-04:00"), datetime(2026, 7, 29, 20, 30))
        self.assertIsNone(_china_datetime("not-a-time"))

    def test_intelligence_source_labels_are_chinese(self) -> None:
        self.assertEqual(localized_intelligence_source("SecFlow vulnerability intelligence"), "神盾漏洞情报库")
        self.assertEqual(localized_intelligence_source("SecFlow vulnerability intelligence / 漏洞情报"), "神盾漏洞情报库")
        self.assertEqual(localized_intelligence_source("nvd; github_advisory"), "美国国家漏洞数据库（NVD）；GitHub 安全公告数据库")


class SBOMSubgraphTests(unittest.TestCase):
    def test_three_interrupts_preserve_fixed_project_facts_and_desktop_hint(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            graph = ProjectSBOMSubgraph(license_scanner=fake_license_scan)
            with (
                patch("app.langgraph.sbom_graph.match_sbom_vulnerabilities") as matcher,
                patch("app.langgraph.sbom_graph.call_mcp_tool", return_value={}),
                patch("app.langgraph.sbom_graph.publish_mcp_workbook", return_value=fake_artifact()) as excel,
            ):
                matcher.side_effect = lambda sbom, _scan, response_language: (
                    {**sbom, "vulnerabilities": [{"id": "CVE-2021-44228", "affects": []}]},
                    {"coverage_status": "complete", "vulnerability_count": 1, "matched_component_count": 1},
                )
                started = graph.start(
                    {
                        "question": "导出项目依赖资产清单并下载到桌面",
                        "workspace_path": directory,
                        "user_id": "sbom-user",
                        "session_id": "sbom-session",
                        "destination_hint": "desktop",
                    }
                )
                matched = graph.resume(started["thread_id"], decision="confirm", user_id="sbom-user", session_id="sbom-session")
                generated = graph.resume(started["thread_id"], decision="confirm", user_id="sbom-user", session_id="sbom-session")
                inspected = graph.inspect(started["thread_id"], user_id="sbom-user")
                with self.assertRaises(KeyError):
                    graph.inspect(started["thread_id"], user_id="another-user")
                completed = graph.resume(started["thread_id"], decision="confirm", user_id="sbom-user", session_id="sbom-session")

        self.assertEqual(started["interrupt"]["kind"], "sbom_vulnerability_match_confirmation")
        self.assertEqual(matched["interrupt"]["kind"], "sbom_excel_generation_confirmation")
        self.assertEqual(generated["interrupt"]["kind"], "sbom_excel_download_confirmation")
        self.assertEqual(inspected["interrupt"]["kind"], "sbom_excel_download_confirmation")
        self.assertEqual(inspected["matching"]["vulnerability_count"], 1)
        self.assertEqual(generated["interrupt"]["destination_hint"], "desktop")
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(matcher.call_count, 1)
        self.assertEqual(excel.call_count, 1)

    def test_declining_vulnerability_matching_still_allows_excel_generation(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            graph = ProjectSBOMSubgraph(license_scanner=fake_license_scan)
            with (
                patch("app.langgraph.sbom_graph.call_mcp_tool", return_value={}),
                patch("app.langgraph.sbom_graph.publish_mcp_workbook", return_value=fake_artifact()),
            ):
                started = graph.start(
                    {"question": "导出 SBOM", "workspace_path": directory, "user_id": "u", "session_id": "s"}
                )
                generation = graph.resume(started["thread_id"], decision="cancel", user_id="u", session_id="s")
                download = graph.resume(started["thread_id"], decision="confirm", user_id="u", session_id="s")

        self.assertEqual(generation["interrupt"]["kind"], "sbom_excel_generation_confirmation")
        self.assertEqual(download["interrupt"]["kind"], "sbom_excel_download_confirmation")
        self.assertEqual(download["fields"]["是否匹配漏洞"], "否")

    def test_resume_enforces_user_and_session_ownership(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            graph = ProjectSBOMSubgraph(license_scanner=fake_license_scan)
            started = graph.start(
                {"question": "导出 SBOM", "workspace_path": directory, "user_id": "u", "session_id": "s"}
            )
            with self.assertRaises(KeyError):
                graph.resume(started["thread_id"], decision="cancel", user_id="other", session_id="s")

    def test_pending_interrupt_survives_backend_restart(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            checkpoint_path = Path(directory, "sbom-checkpoints.sqlite3")
            first_connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
            first_graph = ProjectSBOMSubgraph(checkpointer=SqliteSaver(first_connection), license_scanner=fake_license_scan)
            started = first_graph.start(
                {"question": "导出 SBOM", "workspace_path": directory, "user_id": "u", "session_id": "s"}
            )
            first_connection.close()

            second_connection = sqlite3.connect(checkpoint_path, check_same_thread=False)
            second_graph = ProjectSBOMSubgraph(checkpointer=SqliteSaver(second_connection), license_scanner=fake_license_scan)
            resumed = second_graph.resume(
                started["thread_id"],
                decision="cancel",
                user_id="u",
                session_id="s",
                interrupt_id=started["interrupt"]["interrupt_id"],
            )
            second_connection.close()

        self.assertEqual(resumed["status"], "interrupted")
        self.assertEqual(resumed["interrupt"]["kind"], "sbom_excel_generation_confirmation")

    def test_resume_rejects_an_old_interrupt_card(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            graph = ProjectSBOMSubgraph(license_scanner=fake_license_scan)
            started = graph.start(
                {"question": "导出 SBOM", "workspace_path": directory, "user_id": "u", "session_id": "s"}
            )
            with self.assertRaises(InterruptStateConflictError):
                graph.resume(
                    started["thread_id"],
                    decision="cancel",
                    user_id="u",
                    session_id="s",
                    interrupt_id="stale-interrupt-id",
                )


class SBOMIntentAndAPITests(unittest.TestCase):
    def test_semantic_fallback_understands_project_inventory_without_literal_sbom(self) -> None:
        with patch.object(assistant_intent, "chat_readiness_error", return_value="model unavailable"):
            plan = assistant_intent.plan_assistant_intent(
                "把这个仓库的软件组件资产清单生成 Excel 并下载到桌面",
                workspace_available=True,
            )

        self.assertEqual(plan["intent"], "project_sbom_export")
        self.assertEqual(plan["destination_hint"], "desktop")
        self.assertEqual(plan["skill"]["name"], "secflow-project-sbom")

    def test_workspace_action_keeps_non_sbom_objectives_on_existing_scan_service(self) -> None:
        fake_task = {"id": "task-1", "workspace_name": "payments", "status": "queued"}
        with (
            patch.object(application, "trial_manager", AlwaysUsableTrial()),
            patch.object(application, "plan_assistant_intent", return_value={"intent": "project_scan", "planner": "llm"}),
            patch.object(application.task_agent_service, "create", return_value=fake_task) as create,
            TestClient(application.app) as client,
        ):
            response = client.post(
                "/api/assistant/workspace-actions",
                json={
                    "objective": "完整扫描这个项目",
                    "workspace_path": "/tmp/payments",
                    "user_id": "u",
                    "session_id": "s",
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["kind"], "agent_task")
        create.assert_called_once()

    def test_workspace_action_routes_semantic_sbom_plan_into_assistant_subgraph(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            plan = {
                "intent": "project_sbom_export",
                "reason": "用户需要项目组件资产工作簿。",
                "confidence": 0.98,
                "destination_hint": "desktop",
                "planner": "llm",
                "skill": assistant_intent.sbom_skill_metadata(),
            }
            with (
                patch.object(application, "trial_manager", AlwaysUsableTrial()),
                patch.object(application, "plan_assistant_intent", return_value=plan),
                patch.object(application.task_agent_service, "create") as create,
                TestClient(application.app) as client,
            ):
                response = client.post(
                    "/api/assistant/workspace-actions",
                    json={
                        "objective": "把这个项目的供应链资产做成 Excel 并放到桌面",
                        "workspace_path": directory,
                        "user_id": "workspace-user",
                        "session_id": "workspace-session",
                    },
                )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()["data"]
        self.assertEqual(data["kind"], "assistant")
        self.assertEqual(data["answer"]["mode"], "project_sbom_export")
        self.assertEqual(data["answer"]["interrupt"]["kind"], "sbom_vulnerability_match_confirmation")
        self.assertEqual(data["answer"]["fields"]["下载目标"], "桌面")
        create.assert_not_called()

    def test_generic_resume_api_routes_sbom_thread(self) -> None:
        with TemporaryDirectory() as directory:
            Path(directory, "pom.xml").write_text(POM, encoding="utf-8")
            started = project_sbom_subgraph.start(
                {
                    "question": "导出 SBOM",
                    "workspace_path": directory,
                    "user_id": "api-user",
                    "session_id": "api-session",
                }
            )
            with (
                patch.dict(os.environ, {"SECFLOW_DISABLE_BATCH_SCHEDULER": "1"}),
                patch.object(application, "trial_manager", AlwaysUsableTrial()),
                TestClient(application.app) as client,
            ):
                response = client.post(
                    "/api/assistant/interrupts/resume",
                    json={
                        "thread_id": started["thread_id"],
                        "interrupt_id": started["interrupt"]["interrupt_id"],
                        "decision": "cancel",
                        "user_id": "api-user",
                        "session_id": "api-session",
                    },
                )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["answer"]["mode"], "project_sbom_export")
        self.assertEqual(response.json()["data"]["interrupt"]["kind"], "sbom_excel_generation_confirmation")

    def test_expired_legacy_interrupt_is_cleared_without_a_404(self) -> None:
        with (
            patch.dict(os.environ, {"SECFLOW_DISABLE_BATCH_SCHEDULER": "1"}),
            patch.object(application, "trial_manager", AlwaysUsableTrial()),
            patch.object(application.memory_service, "update_interrupt_exchange", return_value=True) as update,
            TestClient(application.app) as client,
        ):
            response = client.post(
                "/api/assistant/interrupts/resume",
                json={
                    "thread_id": "sbom-legacy-without-checkpoint",
                    "interrupt_id": "legacy-interrupt",
                    "decision": "confirm",
                    "user_id": "u",
                    "session_id": "s",
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["status"], "expired")
        self.assertIsNone(response.json()["data"]["answer"]["interrupt"])
        update.assert_called_once()

    def test_sbom_artifact_download_endpoint_returns_generated_workbook(self) -> None:
        with TemporaryDirectory() as directory:
            store = SBOMArtifactStore(Path(directory))
            content = build_sbom_workbook(
                build_cyclonedx_sbom({"files": [], "dependencies": []}, project_name="payments"),
                {},
            )
            artifact = store.save(
                content,
                file_name="AegisAl-payments-SBOM.xlsx",
                generated_at="2026-07-28T00:00:00+00:00",
            )
            with (
                patch.object(application, "trial_manager", AlwaysUsableTrial()),
                patch.object(application, "sbom_artifact_store", store),
                TestClient(application.app) as client,
            ):
                response = client.get(artifact.download_path)

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.content, content)
        self.assertEqual(
            response.headers["content-type"],
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertIn(".xlsx", response.headers["content-disposition"])

    def test_skill_explicitly_isolates_frozen_evaluation(self) -> None:
        text = Path("app/resources/skills/secflow-project-sbom/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Do not modify scanner rules", text)
        self.assertIn("frozen evaluation manifests", text)
        self.assertIn("Simplified Chinese description", text)


if __name__ == "__main__":
    unittest.main()
