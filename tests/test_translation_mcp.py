from __future__ import annotations

import asyncio
import re
import unittest
from unittest.mock import patch

from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.langgraph.report_graph import ReportCapabilitySubgraph
from app.mcp.offline_translation import OfflineTranslationUnavailable
from app.mcp.translation import _translation_cache, translate_json_payload, translation_mcp_spec
from app.reports import build_scan_result_json, validate_scan_result_json


def _complete_local_translation(texts, *, target_language: str) -> list[str]:
    sentence = "這是完整的繁體中文翻譯。" if target_language == "zh-Hant" else "这是完整的简体中文翻译。"
    anchors = (
        ("execute arbitrary code", "執行任意程式碼" if target_language == "zh-Hant" else "执行任意代码"),
        ("arbitrary code execution", "執行任意程式碼" if target_language == "zh-Hant" else "执行任意代码"),
        ("remote code execution", "遠端程式碼執行" if target_language == "zh-Hant" else "远程代码执行"),
        ("buffer overflow", "緩衝區溢位" if target_language == "zh-Hant" else "缓冲区溢出"),
        ("integer overflow", "整數溢位" if target_language == "zh-Hant" else "整数溢出"),
        ("denial of service", "拒絕服務" if target_language == "zh-Hant" else "拒绝服务"),
        ("information disclosure", "資訊洩露" if target_language == "zh-Hant" else "信息泄露"),
        ("prototype pollution", "原型污染"),
        ("out-of-bounds read", "越界讀取" if target_language == "zh-Hant" else "越界读取"),
        ("command injection", "命令注入"),
        ("sql injection", "SQL 注入"),
    )
    translated: list[str] = []
    for value in texts:
        source = str(value)
        boundary = r"\s,;:，；。.!?()\[\]{}"
        leading = re.match(rf"^[{boundary}]*", source).group(0)
        trailing = re.search(rf"[{boundary}]*$", source).group(0)
        sentence_count = max(1, len(re.findall(r"[.!?]+(?:\s|$)", source.strip())))
        existing_cjk = list(dict.fromkeys(re.findall(r"[\u3400-\u9fff]+", source)))
        placeholders = list(
            dict.fromkeys(
                re.findall(r"X\d+X|https://secflow\.invalid/entity/\d+", source)
            )
        )
        preserved_entities = [
            entity for entity in ("Nginx", "OpenSSL", "PostgreSQL") if entity in source
        ]
        meaning = [translated_term for phrase, translated_term in anchors if phrase in source.casefold()]
        prefix = " ".join(
            (*existing_cjk, *placeholders, *preserved_entities, *dict.fromkeys(meaning))
        )
        body = " ".join([sentence] * sentence_count)
        translated.append(f"{leading}{prefix} {body}{trailing}" if prefix else f"{leading}{body}{trailing}")
    return translated


class TranslationMCPContractTests(unittest.TestCase):
    def setUp(self) -> None:
        _translation_cache.clear()

    def assert_free_offline_contract(self, result) -> None:
        self.assertTrue(result.offline)
        self.assertFalse(result.network_used)
        self.assertFalse(result.requires_api_key)
        self.assertFalse(result.model_used)
        self.assertEqual(result.provider_calls, 0)
        self.assertEqual(result.billable_tokens, 0)
        self.assertEqual(result.token_usage, 0)

    def test_translates_visible_json_without_user_model_or_provider_usage(self) -> None:
        payload = {
            "summary": "Command injection found",
            "fields": {"Risk": "needs remediation"},
            "finding": {
                "id": "CVE-2026-1234",
                "file_name": "src/app.py",
                "version": "1.2.3",
                "url": "https://example.test/CVE-2026-1234",
                "title": "Command injection",
                "vulnerable_snippet": "os.system(command)",
            },
        }

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ) as engine:
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertGreater(engine.call_count, 0)
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.translated_fields, 3)
        self.assertRegex(result.payload["summary"], r"[\u3400-\u9fff]")
        self.assertRegex(result.payload["fields"]["Risk"], r"[\u3400-\u9fff]")
        self.assertRegex(result.payload["finding"]["title"], r"[\u3400-\u9fff]")
        for key in ("id", "file_name", "version", "url", "vulnerable_snippet"):
            self.assertEqual(result.payload["finding"][key], payload["finding"][key])
        self.assert_free_offline_contract(result)

    def test_preserves_all_security_evidence_segments_exactly(self) -> None:
        code_block = '```python\nos.system(user_input)\n```'
        evidence = (
            "The component Nginx before 1.2.3 has command injection in CVE-2026-1234 and "
            "GHSA-abcd-efgh-ijkl; see https://example.test/advisory at commit deadbee, "
            "Unix path /opt/secflow/app.py and Windows path "
            "C:\\Program Files\\SecFlow\\app.exe; exploit:\n"
            f"{code_block}"
        )

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ):
            result = translate_json_payload({"summary": evidence}, target_language="zh-Hans")

        translated = result.payload["summary"]
        self.assertEqual(result.translation_status, "translated")
        for segment in (
            "Nginx",
            "1.2.3",
            "CVE-2026-1234",
            "GHSA-abcd-efgh-ijkl",
            "https://example.test/advisory",
            "deadbee",
            "/opt/secflow/app.py",
            "C:\\Program Files\\SecFlow\\app.exe",
            code_block,
        ):
            self.assertIn(segment, translated)
        self.assert_free_offline_contract(result)

    def test_mixed_chinese_and_english_still_translates_english_prose(self) -> None:
        source = "已确认 component Nginx issue allows remote attackers to execute arbitrary code."

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ) as engine:
            result = translate_json_payload({"summary": source}, target_language="zh-Hans")

        self.assertGreater(engine.call_count, 0)
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.unresolved_fields, 0)
        self.assertIn("Nginx", result.payload["summary"])
        self.assertNotIn("remote attackers", result.payload["summary"])

    def test_truncated_long_translation_is_rejected(self) -> None:
        source = "Remote attackers can execute arbitrary code. " * 12

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            return_value=["截断译文。"],
        ) as engine:
            result = translate_json_payload({"summary": source}, target_language="zh-Hans")

        self.assertGreaterEqual(engine.call_count, 2)
        self.assertEqual(result.payload["summary"], source)
        self.assertEqual(result.translation_status, "fallback")
        self.assertEqual(result.translated_fields, 0)
        self.assertEqual(result.unresolved_fields, 1)

    def test_complete_long_repeated_translation_is_accepted(self) -> None:
        source = ("Remote attackers can execute arbitrary code. " * 140).strip()
        self.assertGreater(len(source), 4_000)

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ):
            result = translate_json_payload({"summary": source}, target_language="zh-Hans")

        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.candidate_fields, 1)
        self.assertEqual(result.translated_fields, 1)
        self.assertEqual(result.unresolved_fields, 0)
        self.assertNotIn("Remote attackers", result.payload["summary"])
        self.assertGreaterEqual(result.payload["summary"].count("翻译"), 140)

    def test_simplified_and_traditional_have_separate_results_and_cache_entries(self) -> None:
        payload = {"summary": "Remote code execution vulnerability."}

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ) as engine:
            simplified = translate_json_payload(payload, target_language="zh-Hans")
            traditional = translate_json_payload(payload, target_language="zh-Hant")

        self.assertEqual(engine.call_count, 2)
        self.assertIn("简体", simplified.payload["summary"])
        self.assertIn("繁體", traditional.payload["summary"])
        self.assertNotEqual(simplified.payload["summary"], traditional.payload["summary"])
        self.assertEqual(traditional.translation_status, "translated")

    def test_chinese_to_english_is_explicitly_unsupported(self) -> None:
        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch"
        ) as engine:
            result = translate_json_payload(
                {"summary": "存在远程代码执行漏洞。"},
                target_language="en",
            )

        engine.assert_not_called()
        self.assertEqual(result.translation_status, "unsupported")
        self.assertEqual(result.unresolved_fields, 1)
        self.assertTrue(result.errors)
        self.assert_free_offline_contract(result)

    def test_english_target_passthrough_does_not_load_offline_model(self) -> None:
        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch"
        ) as engine:
            result = translate_json_payload(
                {"summary": "Already English."},
                target_language="en",
            )

        engine.assert_not_called()
        self.assertEqual(result.translation_status, "passthrough")
        self.assertFalse(result.offline_model_used)
        self.assertFalse(result.resource_verified)
        self.assertEqual(result.model_sha256, "")
        self.assert_free_offline_contract(result)

    def test_localized_payload_with_machine_string_value_is_passthrough(self) -> None:
        payload = {
            "summary": "请输入组件名称和明确版本。",
            "fields": {"确认漏洞数量": "0"},
        }

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=lambda texts, *, target_language: list(texts),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translation_status, "passthrough")
        self.assertEqual(result.unresolved_fields, 0)
        self.assert_free_offline_contract(result)

    def test_unsupported_target_returns_auditable_result(self) -> None:
        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch"
        ) as engine:
            result = translate_json_payload(
                {"summary": "Command injection found."},
                target_language="fr",
            )

        engine.assert_not_called()
        self.assertEqual(result.translation_status, "unsupported")
        self.assertEqual(result.target_language, "fr")
        self.assertTrue(result.errors)
        self.assert_free_offline_contract(result)

    def test_offline_runtime_unavailable_preserves_original(self) -> None:
        payload = {"summary": "general advisory text."}

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=OfflineTranslationUnavailable("offline language pack unavailable"),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translation_status, "unavailable")
        self.assertEqual(result.translated_fields, 0)
        self.assertEqual(result.unresolved_fields, 1)
        self.assertIn("offline language pack unavailable", result.errors)
        self.assert_free_offline_contract(result)

    def test_repeated_payloads_reuse_local_translation_cache(self) -> None:
        payload = {"summary": "Unique local cache probe text."}

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ) as engine:
            first = translate_json_payload(payload, target_language="zh-Hans")
            calls_after_first = engine.call_count
            second = translate_json_payload(payload, target_language="zh-Hans")

        self.assertGreater(calls_after_first, 0)
        self.assertEqual(engine.call_count, calls_after_first)
        self.assertEqual(first.payload, second.payload)
        self.assertEqual(second.translation_status, "translated")

    def test_retry_can_be_disabled_for_bulk_translation(self) -> None:
        def echo(texts, *, target_language: str) -> list[str]:
            del target_language
            return list(texts)

        payload = {"summary": "general advisory text."}
        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=echo,
        ) as engine:
            result = translate_json_payload(
                payload,
                target_language="zh-Hans",
                retry_untranslated_fields=False,
            )

        self.assertEqual(engine.call_count, 1)
        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translation_status, "fallback")
        self.assertEqual(result.unresolved_fields, 1)

    def test_partial_glossary_translation_with_residual_english_is_rejected(self) -> None:
        def echo(texts, *, target_language: str) -> list[str]:
            del target_language
            return list(texts)

        for source in (
            "Command injection found.",
            "Keep command injection.",
            "Package command injection.",
            "Command injection Unexpected Behavior.",
        ):
            with self.subTest(source=source), patch(
                "app.mcp.translation.offline_translation_engine.translate_batch",
                side_effect=echo,
            ):
                payload = {"summary": source}
                result = translate_json_payload(
                    payload,
                    target_language="zh-Hans",
                    retry_untranslated_fields=False,
                )

                self.assertEqual(result.payload, payload)
                self.assertEqual(result.translation_status, "fallback")
                self.assertEqual(result.unresolved_fields, 1)

    def test_protected_chart_payload_is_not_sent_to_offline_engine(self) -> None:
        payload = {
            "summary": "Command injection found.",
            "chart_data": {
                "risk_bars": [{"label": "AlmaLinux:8", "description": "Do not translate"}]
            },
        }

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ) as engine:
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["chart_data"], payload["chart_data"])
        self.assertEqual(result.candidate_fields, 1)
        sent_text = " ".join(
            str(item)
            for call in engine.call_args_list
            for item in call.args[0]
        )
        self.assertNotIn("Do not translate", sent_text)

    def test_scan_json_is_rehashed_and_facts_are_rebuilt_after_translation(self) -> None:
        scan_json = build_scan_result_json(
            {
                "question": "Scan this project",
                "static_analysis": {
                    "findings": [
                        {
                            "id": "finding-1",
                            "title": "Command injection",
                            "severity": "HIGH",
                            "file_name": "src/app.py",
                            "line": 9,
                            "vulnerable_snippet": "os.system(command)",
                            "remediation": "Use a safe process API.",
                            "taint_path": [
                                {
                                    "kind": "sink",
                                    "file": "src/app.py",
                                    "line": 9,
                                    "label": "Command execution sink",
                                    "snippet": "os.system(command)",
                                }
                            ],
                        }
                    ]
                },
            },
            source_kind="assistant_scan",
            language="en",
        )
        original_hash = scan_json["audit"]["payload_sha256"]

        with patch(
            "app.mcp.translation.offline_translation_engine.translate_batch",
            side_effect=_complete_local_translation,
        ):
            result = translate_json_payload(
                scan_json,
                target_language="zh-Hans",
                content_scope="report_source",
            )

        translated = validate_scan_result_json(result.payload)
        payload_finding = translated["payload"]["static_analysis"]["findings"][0]
        fact_finding = translated["facts"]["code_findings"][0]
        self.assertEqual(translated["language"], "zh-Hans")
        self.assertNotEqual(translated["audit"]["payload_sha256"], original_hash)
        self.assertEqual(fact_finding["title"], payload_finding["title"])
        self.assertEqual(fact_finding["vulnerable_snippet"], "os.system(command)")
        self.assertEqual(fact_finding["snippet_lines"][0]["text"], "os.system(command)")
        self.assertEqual(translated["counts"]["code_findings"], 1)

    def test_graphs_place_translation_after_structured_json(self) -> None:
        assistant = KnowledgeSecurityGraph.graph_spec()
        report = ReportCapabilitySubgraph.graph_spec()
        self.assertIn("translation_agent", {node["id"] for node in assistant["nodes"]})
        self.assertIn(
            ("compose_answer", "translation_agent"),
            {(edge["source"], edge["target"]) for edge in assistant["edges"]},
        )
        self.assertIn("translation_agent", {node["id"] for node in report["nodes"]})
        self.assertIn(
            ("build_scan_result_json", "translation_agent"),
            {(edge["source"], edge["target"]) for edge in report["edges"]},
        )

    def test_mcp_catalog_exposes_structured_offline_contract(self) -> None:
        spec = asyncio.run(translation_mcp_spec())
        self.assertEqual(spec["id"], "translation")
        self.assertEqual([tool["name"] for tool in spec["tools"]], ["translate_json_payload"])
        output_schema = spec["tools"][0]["output_schema"]
        properties = output_schema["properties"]
        for field in (
            "network_used",
            "requires_api_key",
            "provider_calls",
            "billable_tokens",
            "token_usage",
            "model_used",
            "offline_model_used",
            "resource_verified",
        ):
            self.assertIn(field, properties)


class BundledTranslationModelSmokeTests(unittest.TestCase):
    def setUp(self) -> None:
        _translation_cache.clear()

    def test_real_model_translates_pure_english_to_simplified_and_traditional(self) -> None:
        payload = {
            "summary": "Remote code execution vulnerability allows arbitrary code execution."
        }

        simplified = translate_json_payload(payload, target_language="zh-Hans")
        traditional = translate_json_payload(payload, target_language="zh-Hant")

        self.assertEqual(simplified.translation_status, "translated")
        self.assertEqual(traditional.translation_status, "translated")
        self.assertRegex(simplified.payload["summary"], r"[\u3400-\u9fff]")
        self.assertRegex(traditional.payload["summary"], r"[\u3400-\u9fff]")
        self.assertNotIn("Remote code execution", simplified.payload["summary"])
        self.assertNotEqual(simplified.payload["summary"], traditional.payload["summary"])
        for result in (simplified, traditional):
            self.assertTrue(result.resource_verified)
            self.assertTrue(result.offline_model_used)
            self.assertEqual(len(result.model_sha256), 64)
            self.assertFalse(result.network_used)
            self.assertFalse(result.requires_api_key)
            self.assertEqual(result.provider_calls, 0)
            self.assertEqual(result.billable_tokens, 0)
            self.assertEqual(result.token_usage, 0)

    def test_real_model_translates_mixed_chinese_and_preserves_nginx(self) -> None:
        source = "该 Nginx issue allows remote attackers to execute arbitrary code."

        result = translate_json_payload({"summary": source}, target_language="zh-Hans")

        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.unresolved_fields, 0)
        self.assertIn("Nginx", result.payload["summary"])
        self.assertNotIn("remote attackers", result.payload["summary"])
        self.assertNotIn("execute arbitrary code", result.payload["summary"])

    def test_real_model_preserves_security_advisory_evidence(self) -> None:
        source = (
            "Nginx before 1.2.3 is vulnerable; see CVE-2026-1234 at "
            "https://example.test/advisory and commit deadbee."
        )

        result = translate_json_payload({"summary": source}, target_language="zh-Hans")

        self.assertEqual(result.translation_status, "translated")
        for segment in (
            "Nginx",
            "1.2.3",
            "CVE-2026-1234",
            "https://example.test/advisory",
            "deadbee",
        ):
            self.assertIn(segment, result.payload["summary"])
        self.assertIn("受影响版本早于 1.2.3", result.payload["summary"])
        self.assertIn("提交 deadbee", result.payload["summary"])

    def test_real_model_preserves_core_security_meaning(self) -> None:
        cases = (
            (
                "Remote attackers can execute arbitrary code in Nginx before 1.2.3.",
                "执行任意代码",
                {"Nginx"},
            ),
            ("Buffer overflow allows remote attackers to execute code.", "缓冲区溢出", set()),
            ("Integer overflow causes memory corruption.", "整数溢出", set()),
            ("Denial of service vulnerability in Nginx.", "拒绝服务", {"Nginx"}),
            ("Information disclosure affects OpenSSL.", "信息泄露", {"OpenSSL"}),
            ("Prototype pollution allows attackers to modify objects.", "原型污染", set()),
            ("Out-of-bounds read in Nginx.", "越界读取", {"Nginx"}),
        )

        for source, expected_term, allowed_latin in cases:
            with self.subTest(source=source):
                _translation_cache.clear()
                result = translate_json_payload({"summary": source}, target_language="zh-Hans")
                translated = result.payload["summary"]

                self.assertEqual(result.translation_status, "translated")
                self.assertIn(expected_term, translated)
                latin_words = set(re.findall(r"[A-Za-z]{2,}", translated))
                self.assertLessEqual(latin_words, allowed_latin)


if __name__ == "__main__":
    unittest.main()
