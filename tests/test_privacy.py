from __future__ import annotations

import unittest
from unittest.mock import patch

from app.collectors import (
    _github_version_facts,
    _nvd_affected_versions,
    _nvd_fixed_versions,
    _nvd_modern_components,
)
from app.graph import (
    ASSISTANT_IDENTITY,
    KnowledgeSecurityGraph,
    build_vulnerability_card,
    empty_knowledge_graph,
    merge_translated_card,
    normalize_knowledge_graph,
)
from app.privacy import public_answer_payload, sanitize_public_text, severity_cn


class KnowledgeAnswerPrivacyTests(unittest.TestCase):
    def test_punctuation_only_question_skips_model_and_returns_immediately(self) -> None:
        graph = KnowledgeSecurityGraph()
        state = {
            "question": "？",
            "intent": "security_knowledge",
            "records": [],
            "knowledge_graph": empty_knowledge_graph(),
            "memory_context": {},
            "llm_result": {},
            "llm_error": "",
            "vulnerability_card": {},
            "trace": [],
        }

        state = graph._classify_query(state)
        with patch("app.graph.active_model_from_env", side_effect=AssertionError("punctuation must not call model")):
            state = graph._call_llm(state)
        state = graph._compose_answer(state)

        self.assertEqual(state["intent"], "clarification")
        self.assertEqual(state["llm_result"]["status"], "skipped")
        self.assertIn("请输入需要分析的具体安全问题", state["answer"]["summary"])

    def test_public_text_hides_static_analysis_engine_name(self) -> None:
        payload = public_answer_payload(
            {
                "mode": "security_knowledge",
                "summary": "Semgrep analysis completed",
                "trace": [{"node": "run_static_path_analysis", "message": "semgrep returned one path"}],
            }
        )

        self.assertNotIn("semgrep", str(payload).lower())
        self.assertIn("静态代码路径分析", payload["summary"])

    def test_public_text_preserves_reference_url_while_hiding_source_label(self) -> None:
        text = sanitize_public_text("NVD 查询完成：https://nvd.nist.gov/vuln/detail/CVE-2026-55576")
        self.assertNotIn("NVD 查询", text)
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-55576", text)

    def test_public_text_does_not_replace_rag_inside_normal_words(self) -> None:
        text = sanitize_public_text("ActiveRecord::Tenanted::Storage::DiskService and paragraph")

        self.assertEqual(text, "ActiveRecord::Tenanted::Storage::DiskService and paragraph")
        self.assertEqual(sanitize_public_text("RAG 查询完成"), "内部安全知识 查询完成")

    def test_public_payload_removes_intelligence_provenance(self) -> None:
        payload = public_answer_payload(
            {
                "mode": "vulnerability_lookup",
                "summary": "NVD 与 GitHub Advisory 检索完成",
                "sources": [{"source": "NVD", "url": "https://example.test"}],
                "records": [{"id": "CVE-2026-0001", "collection": "cve", "references": ["https://example.test"], "provenance": ["NVD"]}],
                "fields": {"数据来源": "NVD", "漏洞链接": "https://example.test"},
                "vulnerability_card": {"严重等级": "HIGH"},
            }
        )
        self.assertNotIn("sources", payload)
        self.assertNotIn("records", payload)
        self.assertEqual(payload["fields"], {})
        self.assertEqual(payload["vulnerability_card"]["严重等级"], "高危")
        self.assertNotIn("NVD", payload["summary"])
        self.assertNotIn("GitHub Advisory", payload["summary"])

    def test_severity_is_chinese(self) -> None:
        self.assertEqual(severity_cn("critical"), "严重")
        self.assertEqual(severity_cn("HIGH"), "高危")
        self.assertEqual(severity_cn("medium"), "中危")
        self.assertEqual(severity_cn("low"), "低危")
        self.assertEqual(severity_cn("info"), "提示")
        self.assertEqual(severity_cn("none"), "无风险")

    def test_empty_card_stays_empty_for_non_vulnerability_answer(self) -> None:
        payload = public_answer_payload({"mode": "security_knowledge", "vulnerability_card": {}})
        self.assertEqual(payload["vulnerability_card"], {})

    def test_empty_knowledge_graph_has_client_contract_fields(self) -> None:
        graph = empty_knowledge_graph()
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["node_count"], 0)
        self.assertEqual(graph["edge_count"], 0)

    def test_malformed_knowledge_graph_is_normalized_for_client(self) -> None:
        graph = normalize_knowledge_graph({})
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])
        self.assertEqual(graph["node_count"], 0)
        self.assertEqual(graph["edge_count"], 0)

    def test_public_payload_preserves_knowledge_graph_edge_source(self) -> None:
        payload = public_answer_payload(
            {
                "mode": "security_knowledge",
                "records": [
                    {
                        "id": "CVE-2026-0001",
                        "source": "NVD",
                        "references": ["https://example.test"],
                    }
                ],
                "knowledge_graph": {
                    "nodes": [
                        {"id": "CVE-2026-0001", "label": "CVE-2026-0001", "type": "vulnerability"}
                    ],
                    "edges": [
                        {
                            "id": "edge-1",
                            "source": "CVE-2026-0001",
                            "target": "package:demo",
                            "type": "affects",
                            "label": "影响",
                        }
                    ],
                    "node_count": 1,
                    "edge_count": 1,
                },
            }
        )

        self.assertEqual(payload["knowledge_graph"]["edges"][0]["source"], "CVE-2026-0001")
        self.assertEqual(payload["knowledge_graph"]["edges"][0]["target"], "package:demo")
        self.assertNotIn("source", payload["records"][0])
        self.assertNotIn("references", payload["records"][0])

    def test_nvd_wildcard_is_not_exposed_as_all_versions(self) -> None:
        cve = {
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                    "versionEndExcluding": "3.8.0",
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        versions = _nvd_affected_versions(cve)
        self.assertEqual(versions, ["acme widget < 3.8.0"])
        self.assertNotIn("*", versions[0])
        self.assertNotIn("所有版本", versions[0])

    def test_nvd_affected_data_returns_affected_fixed_and_component_facts(self) -> None:
        cve = {
            "descriptions": [
                {
                    "lang": "en",
                    "value": (
                        "JLine remote-telnet is affected. This issue is fixed in versions "
                        "3.30.14, 4.0.16, and 4.2.1."
                    ),
                }
            ],
            "affected": [
                {
                    "source": "security-advisories@example.test",
                    "affectedData": [
                        {
                            "vendor": "jline",
                            "product": "jline3",
                            "versions": [
                                {"version": "< 3.30.14", "status": "affected"},
                                {"version": ">= 4.0.0, < 4.0.16", "status": "affected"},
                                {"version": ">= 4.1.0, < 4.2.1", "status": "affected"},
                            ],
                        }
                    ],
                }
            ],
        }

        self.assertEqual(
            _nvd_affected_versions(cve),
            [
                "jline jline3 < 3.30.14",
                "jline jline3 >= 4.0.0, < 4.0.16",
                "jline jline3 >= 4.1.0, < 4.2.1",
            ],
        )
        self.assertEqual(
            _nvd_fixed_versions(cve),
            ["jline jline3 3.30.14", "jline jline3 4.0.16", "jline jline3 4.2.1"],
        )
        self.assertEqual(
            _nvd_modern_components(cve),
            [
                {
                    "name": "jline3",
                    "ecosystem": "jline",
                    "affected": ["< 3.30.14", ">= 4.0.0, < 4.0.16", ">= 4.1.0, < 4.2.1"],
                    "fixed": ["3.30.14", "4.0.16", "4.2.1"],
                }
            ],
        )

    def test_cve5_container_range_uses_confirmed_unaffected_boundary_as_fix(self) -> None:
        cve = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "acme",
                            "product": "widget",
                            "defaultStatus": "unaffected",
                            "versions": [
                                {
                                    "version": "1.0.0",
                                    "lessThan": "2.4.1",
                                    "versionType": "semver",
                                    "status": "affected",
                                }
                            ],
                        }
                    ]
                }
            }
        }

        self.assertEqual(_nvd_affected_versions(cve), ["acme widget >= 1.0.0, < 2.4.1"])
        self.assertEqual(_nvd_fixed_versions(cve), ["acme widget 2.4.1"])
        self.assertEqual(_nvd_modern_components(cve)[0]["fixed"], ["2.4.1"])

    def test_partial_patch_is_not_reported_as_confirmed_fixed_version(self) -> None:
        cve = {
            "descriptions": [
                {
                    "lang": "en",
                    "value": "This vulnerability was partially patched in 5.0.7 and remains under review.",
                }
            ],
            "affected": [
                {
                    "affectedData": [
                        {
                            "vendor": "example",
                            "product": "plugin",
                            "versions": [{"version": "<= 5.0.7", "status": "affected"}],
                        }
                    ]
                }
            ],
        }

        self.assertEqual(_nvd_fixed_versions(cve), [])

    def test_package_url_sets_component_ecosystem(self) -> None:
        cve = {
            "affected": [
                {
                    "affectedData": [
                        {
                            "vendor": "OpenClaw",
                            "product": "OpenClaw",
                            "packageURL": "pkg:npm/openclaw",
                            "defaultStatus": "unaffected",
                            "versions": [
                                {"version": "0", "lessThan": "2026.6.6", "status": "affected"},
                                {"version": "2026.6.6", "status": "unaffected"},
                            ],
                        }
                    ]
                }
            ]
        }

        self.assertEqual(
            _nvd_modern_components(cve),
            [
                {
                    "name": "OpenClaw",
                    "ecosystem": "npm",
                    "affected": ["< 2026.6.6"],
                    "fixed": ["2026.6.6"],
                }
            ],
        )

    def test_non_vulnerability_question_goes_directly_to_llm(self) -> None:
        graph = KnowledgeSecurityGraph()
        with (
            patch("app.graph.memory_service.build_context", return_value={"enabled": True, "stats": {}, "injectedMessages": []}),
            patch("app.graph.memory_service.add_exchange"),
            patch("app.graph.intelligence_service.query") as query_intelligence,
            patch(
                "app.graph.active_model_from_env",
                return_value={
                    "provider": "deepseek",
                    "model": "test-model",
                    "endpoint": "https://example.test/v1",
                    "apiKey": "test-key",
                },
            ),
            patch(
                "app.graph.diagnose_chat_completion",
                return_value={"status": "success", "answer": "这是大模型直接生成的回答。", "latency_ms": 10},
            ),
        ):
            result = graph.invoke("帮我写一份项目周报", top_k=5, user_id="direct-user", session_id="direct-session")

        query_intelligence.assert_not_called()
        self.assertEqual(result["mode"], "llm_direct")
        self.assertEqual(result["summary"], "这是大模型直接生成的回答。")
        self.assertNotIn("query_intelligence", [item["node"] for item in result["trace"]])
        self.assertIn("call_llm", [item["node"] for item in result["trace"]])

    def test_identity_question_returns_xiao_an_without_calling_model(self) -> None:
        graph = KnowledgeSecurityGraph()
        with (
            patch("app.graph.memory_service.build_context", return_value={"enabled": True, "stats": {}, "injectedMessages": []}),
            patch("app.graph.memory_service.add_exchange"),
            patch("app.graph.intelligence_service.query") as query_intelligence,
            patch("app.graph.active_model_from_env", side_effect=AssertionError("identity must not call model")),
        ):
            result = graph.invoke("你是谁？", user_id="identity-user", session_id="identity-session")

        query_intelligence.assert_not_called()
        self.assertEqual(result["mode"], "identity")
        self.assertEqual(result["summary"], ASSISTANT_IDENTITY)

    def test_fixed_version_cannot_be_invented_by_translation(self) -> None:
        record = {
            "id": "CVE-2026-0001",
            "title": "Example issue",
            "summary": "Example description",
            "severity": "HIGH",
            "affected_versions": ["acme widget < 3.8.0"],
            "fixed_versions": [],
        }
        fallback = build_vulnerability_card(record)
        translated = merge_translated_card({"修复版本": "99.0.0"}, fallback, record)
        self.assertEqual(translated["修复版本"], "未明确")

    def test_vulnerability_card_includes_component_ranges_and_vulnerable_code_snippet(self) -> None:
        record = {
            "id": "CVE-2026-0002",
            "title": "Example dependency issue",
            "summary": "Example description",
            "severity": "HIGH",
            "affected_versions": ["pip / demo: < 2.4.1"],
            "fixed_versions": ["pip / demo: 2.4.1"],
            "code_snippets": ["def vulnerable_render(value):\n    return template.render(value)"],
            "fixed_code_snippets": ["def safe_render(value):\n    return template.render(escape(value))"],
            "reference_links": [
                "https://github.com/advisories/GHSA-1111-2222-3333",
                "https://nvd.nist.gov/vuln/detail/CVE-2026-0002",
            ],
            "components": [
                {
                    "name": "demo",
                    "ecosystem": "pip",
                    "affected": ["< 2.4.1"],
                    "fixed": ["2.4.1"],
                }
            ],
        }
        card = build_vulnerability_card(record)
        self.assertIn("pip / demo", card["组件版本范围"])
        self.assertIn("影响 < 2.4.1", card["组件版本范围"])
        self.assertIn("def vulnerable_render", card["代码片段"])
        self.assertIn("template.render", card["代码片段"])
        self.assertIn("def safe_render", card["修复代码片段"])
        self.assertIn("escape(value)", card["修复代码片段"])
        self.assertNotIn("payload", card["代码片段"].lower())
        self.assertIn("https://github.com/advisories/GHSA-1111-2222-3333", card["参考链接"])
        self.assertIn("https://nvd.nist.gov/vuln/detail/CVE-2026-0002", card["参考链接"])

    def test_vulnerability_card_description_is_chinese_when_source_summary_is_english(self) -> None:
        card = build_vulnerability_card(
            {
                "id": "CVE-2026-0005",
                "title": "Example remote code execution",
                "summary": "Example remote code execution in demo package.",
                "severity": "HIGH",
                "cvss_score": 8.8,
                "affected_versions": ["Maven / demo: < 1.2.3"],
                "fixed_versions": ["Maven / demo: 1.2.3"],
                "components": [
                    {
                        "name": "demo",
                        "ecosystem": "Maven",
                        "affected": ["< 1.2.3"],
                        "fixed": ["1.2.3"],
                    }
                ],
            }
        )
        self.assertRegex(card["漏洞描述"], r"[\u3400-\u9fff]")
        self.assertNotIn("Example remote code execution", card["漏洞描述"])
        self.assertEqual(card["CVSS评分"], 8.8)
        self.assertEqual(card["严重等级"], "高危")
        self.assertIn("Maven / demo", card["组件版本范围"])

    def test_vulnerability_lookup_uses_offline_translation_without_chat_model(self) -> None:
        graph = KnowledgeSecurityGraph()
        record = {
            "id": "CVE-2026-55576",
            "title": "Workflow expression injection",
            "summary": "A pull request title can reach a shell command.",
            "severity": "HIGH",
            "cvss_score": 8.8,
            "aliases": ["CVE-2026-55576"],
            "affected_versions": [],
            "fixed_versions": [],
            "components": [],
            "reference_links": ["https://example.test/CVE-2026-55576"],
        }
        state = {
            "intent": "vulnerability_lookup",
            "records": [record],
            "trace": [],
            "llm_result": {},
        }

        with patch(
            "app.langgraph.assistant_graph.active_model_from_env",
            side_effect=AssertionError("vulnerability localization must not call a chat model"),
        ):
            skipped = graph._call_llm(state)
        translated = graph._translate_vulnerability_card(skipped)

        self.assertEqual(skipped["llm_result"]["status"], "skipped")
        self.assertRegex(translated["vulnerability_card"]["漏洞描述"], r"[\u3400-\u9fff]")
        self.assertNotIn("A pull request title", translated["vulnerability_card"]["漏洞描述"])
        self.assertIn("Translation MCP", translated["trace"][-1]["message"])

    def test_vulnerability_card_does_not_invent_code_snippet(self) -> None:
        card = build_vulnerability_card(
            {
                "id": "CVE-2026-0003",
                "title": "Example issue",
                "summary": "Example description",
                "severity": "HIGH",
                "affected_versions": [],
                "fixed_versions": [],
                "components": [],
            }
        )
        self.assertEqual(card["代码片段"], "未在漏洞记录中找到可核验代码片段")
        self.assertEqual(card["修复代码片段"], "未在漏洞记录中找到可核验修复代码片段")

    def test_vulnerability_card_reference_links_are_preserved_without_labels(self) -> None:
        payload = public_answer_payload(
            {
                "mode": "vulnerability_lookup",
                "summary": "",
                "vulnerability_card": {
                    "严重等级": "HIGH",
                    "参考链接": "NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-0004\nGitHub Advisory: https://github.com/advisories/GHSA-1111-2222-3333",
                },
            }
        )
        self.assertEqual(payload["vulnerability_card"]["严重等级"], "高危")
        self.assertEqual(
            payload["vulnerability_card"]["参考链接"],
            "https://nvd.nist.gov/vuln/detail/CVE-2026-0004\nhttps://github.com/advisories/GHSA-1111-2222-3333",
        )
        self.assertNotIn("NVD:", payload["vulnerability_card"]["参考链接"])
        self.assertNotIn("GitHub Advisory", payload["vulnerability_card"]["参考链接"])

    def test_github_fixed_version_is_kept_as_fact(self) -> None:
        affected, fixed = _github_version_facts(
            {
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "demo"},
                        "vulnerable_version_range": "< 2.4.1",
                        "first_patched_version": {"identifier": "2.4.1"},
                    }
                ]
            }
        )
        self.assertEqual(affected, ["pip / demo: < 2.4.1"])
        self.assertEqual(fixed, ["pip / demo: 2.4.1"])

        affected, fixed = _github_version_facts(
            {
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "demo"},
                        "vulnerable_version_range": "< 3.0.0",
                        "first_patched_version": "3.0.0",
                    }
                ]
            }
        )
        self.assertEqual(fixed, ["npm / demo: 3.0.0"])


if __name__ == "__main__":
    unittest.main()
