from __future__ import annotations

import asyncio
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.component_mcp as component_mcp_module
import app.component_query_subgraph as component_subgraph_module
import app.graph as graph_module
import app.main as main_module
import app.mcp.protocol as mcp_protocol_module
from app.catalog_translation import CATALOG_TRANSLATION_VERSION
from app.component_mcp import ComponentArtifactStore, component_mcp_specs
from app.mcp.component_query import build_component_vulnerability_detail
from app.component_query_subgraph import looks_like_component_query, parse_component_query
from app.graph import KnowledgeSecurityGraph
from app.vulnerability_export import build_component_vulnerability_workbook


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class FakeComponentService:
    def __init__(self) -> None:
        self.export_calls = 0
        self.record = {
            "id": "CVE-2026-10001",
            "title": "Demo package command injection",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "summary": "Untrusted input reaches a command execution sink.",
            "affected_versions": ["< 2.4.1"],
            "fixed_versions": ["2.4.1"],
            "aliases": [],
            "cwes": ["CWE-78"],
            "components": [
                {
                    "name": "demo",
                    "ecosystem": "PyPI",
                    "affected": ["< 2.4.1"],
                    "fixed": ["2.4.1"],
                }
            ],
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-10001"],
            "published_at": "2026-07-01T00:00:00+00:00",
            "updated_at": "2026-07-20T00:00:00+00:00",
        }
        self.graph = {
            "query": "demo@2.3.0",
            "nodes": [
                {
                    "id": "vulnerability:cve-2026-10001",
                    "label": "CVE-2026-10001",
                    "type": "vulnerability",
                    "metadata": {"severity": "HIGH"},
                },
                {
                    "id": "component:pypi:demo",
                    "label": "demo",
                    "type": "component",
                    "metadata": {"ecosystem": "PyPI"},
                },
                {
                    "id": "fix:pypi:demo:2.4.1",
                    "label": "2.4.1",
                    "type": "fix",
                    "metadata": {},
                },
            ],
            "edges": [
                {
                    "id": "edge-1",
                    "source": "vulnerability:cve-2026-10001",
                    "target": "component:pypi:demo",
                    "type": "AFFECTS",
                    "label": "影响组件",
                },
                {
                    "id": "edge-2",
                    "source": "component:pypi:demo",
                    "target": "fix:pypi:demo:2.4.1",
                    "type": "FIXED_BY",
                    "label": "修复版本",
                },
            ],
            "node_count": 3,
            "edge_count": 2,
        }

    def query_component_vulnerabilities(self, *_args, **_kwargs) -> dict:
        return {
            "status": "success",
            "query": "demo@2.3.0",
            "component": {"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            "records": [self.record],
            "total": 1,
            "preview_limit": 80,
            "truncated": False,
            "ecosystems": ["pypi"],
            "graph": self.graph,
            "generated_at": "2026-07-26T00:00:00+00:00",
        }

    def export_component_vulnerabilities(self, *_args, **_kwargs) -> tuple[bytes, dict]:
        self.export_calls += 1
        content = build_component_vulnerability_workbook(
            [self.record],
            component_name="demo",
            version="2.3.0",
            ecosystem="PyPI",
            generated_at="2026-07-26T00:00:00+00:00",
        )
        return content, {
            "name": "demo",
            "version": "2.3.0",
            "ecosystem": "PyPI",
            "generated_at": "2026-07-26T00:00:00+00:00",
            "total": 1,
        }


class ComponentQuerySubgraphTests(unittest.TestCase):
    def test_detail_mcp_derives_cvss_score_from_verified_vector_and_deduplicates_ranges(self) -> None:
        payload = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10001",
                    "severity": "HIGH",
                    "cvss_score": 8.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "affected_versions": ["PyPI / demo: >= 1.0, < 2.4.1"],
                    "fixed_versions": ["PyPI / demo: 2.4.1"],
                    "components": [
                        {
                            "name": "demo",
                            "ecosystem": "PyPI",
                            "affected": [">= 1.0, < 2.4.1"],
                            "fixed": ["2.4.1"],
                        }
                    ],
                }
            ],
        )

        vulnerability = payload.vulnerabilities[0]
        self.assertEqual(vulnerability.cvss.score, 9.8)
        self.assertEqual(vulnerability.cvss.rating, "严重")
        self.assertEqual(vulnerability.affected_versions, [">= 1.0, < 2.4.1"])
        self.assertEqual(vulnerability.fixed_versions, ["2.4.1"])
        self.assertEqual(vulnerability.remediation, "建议升级到已确认修复版本：2.4.1")

        vector_only = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10002",
                    "severity": "MEDIUM",
                    "cvss_score": 8.1,
                    "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H",
                }
            ],
        ).vulnerabilities[0]
        self.assertEqual(vector_only.cvss.score, 5.9)
        self.assertEqual(vector_only.cvss.rating, "中危")

    def test_detail_mcp_projects_only_accepted_catalog_translation(self) -> None:
        record = {
            "id": "CVE-2026-10003",
            "title": "English vulnerability title",
            "summary": "Remote attackers can execute arbitrary code.",
            "title_original": "English vulnerability title",
            "summary_original": "Remote attackers can execute arbitrary code.",
            "title_zh": "远程代码执行漏洞",
            "summary_zh": "远程攻击者可能执行任意代码。",
            "catalog_translation": {
                "version": CATALOG_TRANSLATION_VERSION,
                "status": "translated",
                "target_language": "zh-Hans",
            },
        }
        with patch(
            "app.intelligence.translation_agent.translate_json",
            side_effect=AssertionError("Component Detail MCP must not call the Host TranslationAgent"),
        ) as translator:
            detail = build_component_vulnerability_detail(
                component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
                records=[record],
                response_language="zh-Hans",
            ).vulnerabilities[0]

        self.assertEqual(detail.title, "远程代码执行漏洞")
        self.assertEqual(detail.description, "远程攻击者可能执行任意代码。")
        translator.assert_not_called()

    def test_detail_mcp_fails_closed_when_chinese_translation_is_pending(self) -> None:
        english = "Remote attackers can execute arbitrary code."
        pending = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10004",
                    "title": "English vulnerability title",
                    "summary": english,
                    "content_language": "unknown",
                    "translation_status": "pending",
                }
            ],
            response_language="zh-Hans",
        ).vulnerabilities[0]
        stale = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10007",
                    "summary_original": english,
                    "summary_zh": "这是不再可信的旧版译文。",
                    "catalog_translation": {
                        "version": CATALOG_TRANSLATION_VERSION - 1,
                        "status": "translated",
                    },
                }
            ],
            response_language="zh-Hans",
        ).vulnerabilities[0]

        self.assertEqual(
            pending.description,
            "中文漏洞描述暂不可用。请根据漏洞编号、影响版本和修复版本核验风险。",
        )
        self.assertNotIn(english, pending.description)
        self.assertNotIn("不再可信", stale.description)

    def test_detail_mcp_uses_english_original_and_traditional_public_projection(self) -> None:
        english = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10005",
                    "title_original": "English vulnerability title",
                    "summary_original": "Remote code execution is possible.",
                }
            ],
            response_language="en",
        ).vulnerabilities[0]
        traditional = build_component_vulnerability_detail(
            component={"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"},
            records=[
                {
                    "id": "CVE-2026-10006",
                    "title": "遠程程式碼執行漏洞",
                    "summary": "遠程攻擊者可能執行任意程式碼。",
                    "content_language": "zh-Hant",
                    "translation_status": "translated",
                }
            ],
            response_language="zh-Hant",
        ).vulnerabilities[0]

        self.assertEqual(english.title, "English vulnerability title")
        self.assertEqual(english.description, "Remote code execution is possible.")
        self.assertEqual(traditional.title, "遠程程式碼執行漏洞")
        self.assertEqual(traditional.description, "遠程攻擊者可能執行任意程式碼。")

    def test_parser_supports_maven_and_scoped_npm_coordinates(self) -> None:
        self.assertEqual(
            parse_component_query("查询 Maven org.apache.logging.log4j:log4j-core 2.14.1 的组件漏洞"),
            {
                "name": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
                "ecosystem": "Maven",
                "include_realtime": True,
            },
        )
        self.assertEqual(parse_component_query("检查 @scope/demo@1.2.3 是否有漏洞")["name"], "@scope/demo")
        self.assertFalse(looks_like_component_query("CVE-2021-44228"))

    def test_main_graph_routes_component_query_through_mcp_subgraph_without_llm(self) -> None:
        fake = FakeComponentService()
        with (
            TemporaryDirectory() as directory,
            patch.object(component_subgraph_module, "intelligence_service", fake),
            patch.object(component_mcp_module, "intelligence_service", fake),
            patch.object(component_mcp_module, "artifact_store", ComponentArtifactStore(Path(directory))),
            patch.object(
                mcp_protocol_module,
                "component_artifact_store",
                component_mcp_module.artifact_store,
            ),
            patch.object(
                graph_module.memory_service,
                "build_context",
                return_value={"enabled": True, "stats": {}, "injectedMessages": []},
            ),
            patch.object(graph_module.memory_service, "add_exchange", return_value=None),
            patch.object(
                graph_module,
                "active_model_from_env",
                side_effect=AssertionError("component query must not call the chat model"),
            ),
        ):
            result = KnowledgeSecurityGraph().invoke("查询 PyPI demo 2.3.0 组件漏洞")
            artifact_path = component_mcp_module.artifact_store.resolve(result["artifacts"][0]["id"])
            artifact_content = artifact_path.read_bytes()

        self.assertEqual(result["mode"], "component_vulnerability_query")
        self.assertEqual(fake.export_calls, 0, "Excel MCP must reuse the verified query records")
        self.assertNotIn("records", result)
        self.assertIn("CVE-2026-10001", result["summary"])
        detail = result["component_detail"]
        self.assertEqual(detail["schema_version"], 1)
        self.assertEqual(detail["renderer"], "component-vulnerability-detail")
        self.assertEqual(detail["component"], {"name": "demo", "version": "2.3.0", "ecosystem": "PyPI"})
        self.assertEqual(detail["vulnerabilities"][0]["id"], "CVE-2026-10001")
        self.assertEqual(detail["vulnerabilities"][0]["severity_label"], "高危")
        self.assertEqual(detail["vulnerabilities"][0]["cvss"]["score"], 8.1)
        self.assertEqual(detail["vulnerabilities"][0]["cvss"]["metrics"][0]["value"], "网络")
        self.assertEqual(
            detail["vulnerabilities"][0]["reference_links"][0]["url"],
            "https://nvd.nist.gov/vuln/detail/CVE-2026-10001",
        )
        self.assertEqual(detail["vulnerabilities"][0]["reference_links"][0]["title"], "NVD 漏洞详情")
        self.assertEqual(len(result["chart_data"]["sankey"]["nodes"]), 3)
        self.assertEqual(
            [(item["from"], item["to"]) for item in result["chart_data"]["sankey"]["links"]],
            [
                ("component:pypi:demo", "vulnerability:cve-2026-10001"),
                ("vulnerability:cve-2026-10001", "fix:pypi:demo:2.4.1"),
            ],
        )
        self.assertEqual(
            {item["type"]: item["column"] for item in result["chart_data"]["sankey"]["nodes"]},
            {"component": 0, "vulnerability": 1, "fix": 2},
        )
        self.assertTrue(artifact_content.startswith(b"PK\x03\x04"))
        self.assertEqual(
            [item["node"] for item in result["trace"]][2:8],
            [
                "component_query.parse_coordinates",
                "component_query.query_vulnerabilities",
                "component_query.component_detail_mcp",
                "component_query.excel_mcp",
                "component_query.d3_sankey_mcp",
                "component_query.compose_result",
            ],
        )

    def test_incomplete_component_query_returns_concrete_version_guidance(self) -> None:
        with (
            patch.object(
                graph_module.memory_service,
                "build_context",
                return_value={"enabled": True, "stats": {}, "injectedMessages": []},
            ),
            patch.object(graph_module.memory_service, "add_exchange", return_value=None),
            patch.object(
                graph_module,
                "plan_assistant_intent",
                return_value={
                    "intent": "component_vulnerability_query",
                    "reason": "用户询问单个组件风险，但尚未提供版本。",
                    "confidence": 0.9,
                    "date_filter": {},
                    "filters": {},
                    "planner": "llm",
                    "skill": {},
                },
            ),
        ):
            result = KnowledgeSecurityGraph().invoke("查询 log4j 组件漏洞")

        self.assertEqual(result["mode"], "component_vulnerability_query")
        self.assertIn("明确版本", result["summary"])
        self.assertEqual(result["artifacts"], [])

    def test_mcp_specs_and_artifact_download_endpoint_are_auditable(self) -> None:
        specs = asyncio.run(component_mcp_specs())
        self.assertEqual([item["id"] for item in specs], ["component-detail", "excel", "d3-sankey"])
        self.assertEqual(specs[0]["tools"][0]["name"], "build_component_vulnerability_detail")
        self.assertEqual(specs[1]["tools"][0]["name"], "export_component_vulnerabilities")
        self.assertEqual(specs[1]["tools"][1]["name"], "export_component_vulnerability_catalog")
        self.assertEqual(specs[2]["tools"][0]["name"], "build_component_sankey")

        fake = FakeComponentService()
        with TemporaryDirectory() as directory:
            store = ComponentArtifactStore(Path(directory))
            content, metadata = fake.export_component_vulnerabilities()
            artifact = store.save(
                content,
                file_name="SecFlow-PyPI-demo-2.3.0-vulnerabilities.xlsx",
                generated_at=metadata["generated_at"],
            )
            with (
                patch.dict(os.environ, {"SECFLOW_DISABLE_BATCH_SCHEDULER": "1"}),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                patch.object(main_module, "component_artifact_store", store),
                TestClient(main_module.app) as client,
            ):
                response = client.get(artifact.download_path)
                tools_response = client.get("/api/mcp/component-query")

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.content.startswith(b"PK\x03\x04"))
        self.assertEqual(tools_response.status_code, 200)
        self.assertEqual(len(tools_response.json()["data"]["servers"]), 3)


if __name__ == "__main__":
    unittest.main()
