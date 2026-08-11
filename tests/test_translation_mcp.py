from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import patch

from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.langgraph.report_graph import ReportCapabilitySubgraph
from app.mcp.translation import _translation_cache, translate_json_payload, translation_mcp_spec
from app.reports import build_scan_result_json, validate_scan_result_json


class TranslationMCPTests(unittest.TestCase):
    def setUp(self) -> None:
        # 模块级翻译缓存跨用例隔离：各用例自行控制模型桩的调用预期。
        _translation_cache.clear()

    def test_translates_visible_json_and_preserves_machine_evidence(self) -> None:
        payload = {
            "summary": "Command injection found",
            "fields": {"Risk": "Needs remediation"},
            "finding": {
                "id": "CVE-2026-1234",
                "file_name": "src/app.py",
                "version": "1.2.3",
                "url": "https://example.test/CVE-2026-1234",
                "title": "Command injection",
                "vulnerable_snippet": "os.system(command)",
            },
        }

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=_translated_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        translated = result.payload
        self.assertEqual(translated["summary"], "译：Command injection found")
        self.assertEqual(translated["fields"]["Risk"], "译：Needs remediation")
        self.assertEqual(translated["finding"]["title"], "译：Command injection")
        self.assertEqual(translated["finding"]["id"], "CVE-2026-1234")
        self.assertEqual(translated["finding"]["file_name"], "src/app.py")
        self.assertEqual(translated["finding"]["version"], "1.2.3")
        self.assertEqual(translated["finding"]["url"], "https://example.test/CVE-2026-1234")
        self.assertEqual(translated["finding"]["vulnerable_snippet"], "os.system(command)")
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.translated_fields, 3)

    def test_translation_calls_raise_max_tokens_for_batch_safety(self) -> None:
        # 聊天配置 2048 会截断批量翻译 JSON；翻译调用必须独立提高输出预算。
        seen_models = []

        def capturing_completion(model, messages, **_kwargs):
            seen_models.append(dict(model))
            return _translated_completion(model, messages)

        with (
            patch(
                "app.mcp.translation.active_model_from_env",
                return_value={"id": "model-a", "model": "deepseek-chat", "maxTokens": 2048},
            ),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=capturing_completion),
        ):
            translate_json_payload({"summary": "Unique maxTokens probe text 甲"}, target_language="zh-Hans")

        self.assertTrue(seen_models)
        self.assertTrue(all(int(model.get("maxTokens") or 0) >= 8192 for model in seen_models))

    def test_repeated_payloads_reuse_cached_translations(self) -> None:
        payload = {"summary": "Cache probe unique text 乙"}

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-cache"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=_translated_completion) as completion,
        ):
            first = translate_json_payload(payload, target_language="zh-Hans")
            calls_after_first = completion.call_count
            second = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(first.payload["summary"], "译：Cache probe unique text 乙")
        self.assertEqual(second.payload["summary"], "译：Cache probe unique text 乙")
        self.assertGreater(calls_after_first, 0)
        self.assertEqual(completion.call_count, calls_after_first)  # 第二次命中缓存，零模型调用
        self.assertEqual(second.translation_status, "translated")

    def test_report_scan_json_is_rehashed_and_rebuilds_translated_facts(self) -> None:
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

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=_translated_completion),
        ):
            result = translate_json_payload(scan_json, target_language="zh-Hans", content_scope="report_source")

        translated = validate_scan_result_json(result.payload)
        payload_finding = translated["payload"]["static_analysis"]["findings"][0]
        fact_finding = translated["facts"]["code_findings"][0]
        self.assertEqual(translated["language"], "zh-Hans")
        self.assertNotEqual(translated["audit"]["payload_sha256"], original_hash)
        self.assertEqual(payload_finding["title"], "译：Command injection")
        self.assertEqual(fact_finding["title"], payload_finding["title"])
        self.assertEqual(fact_finding["vulnerable_snippet"], "os.system(command)")
        self.assertEqual(fact_finding["snippet_lines"][0]["text"], "os.system(command)")
        self.assertEqual(translated["counts"]["code_findings"], 1)

    def test_rejects_translated_field_when_a_protected_token_is_removed(self) -> None:
        def unsafe_completion(_model, messages, **_kwargs):
            request = json.loads(messages[-1]["content"])
            return {
                "status": "success",
                "answer": json.dumps(
                    {"items": [{"id": request["items"][0]["id"], "text": "漏洞需要立即修复"}]},
                    ensure_ascii=False,
                ),
            }

        payload = {"summary": "CVE-2026-1234 affects demo 1.2.3; see https://example.test/advisory"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=unsafe_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translated_fields, 0)

    def test_retries_without_json_mode_when_endpoint_rejects_structured_output(self) -> None:
        calls: list[bool] = []

        def rejecting_completion(_model, messages, **kwargs):
            json_mode = bool(kwargs.get("json_mode"))
            calls.append(json_mode)
            if json_mode:
                return {"status": "failed", "message": "HTTP 400: response_format is not supported"}
            request = json.loads(messages[-1]["content"])
            return {
                "status": "success",
                "answer": json.dumps(
                    {
                        "items": [
                            {"id": item["id"], "text": f"译：{item['text']}"}
                            for item in request["items"]
                        ]
                    },
                    ensure_ascii=False,
                ),
            }

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=rejecting_completion),
        ):
            result = translate_json_payload({"summary": "Command injection found"}, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "译：Command injection found")
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(calls, [True, False])

    def test_plain_text_fallback_translates_fields_left_in_english(self) -> None:
        def echoing_completion(_model, messages, **_kwargs):
            user_content = messages[-1]["content"]
            if user_content.startswith("{"):
                request = json.loads(user_content)
                return {
                    "status": "success",
                    "answer": json.dumps(
                        {"items": [{"id": item["id"], "text": item["text"]} for item in request["items"]]},
                        ensure_ascii=False,
                    ),
                }
            return {"status": "success", "answer": f"译：{user_content}"}

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=echoing_completion),
        ):
            result = translate_json_payload({"summary": "Command injection found"}, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "译：Command injection found")
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.translated_fields, 1)

    def test_bulk_export_can_disable_per_field_retry_amplification(self) -> None:
        calls = 0

        def echoing_completion(_model, messages, **_kwargs):
            nonlocal calls
            calls += 1
            request = json.loads(messages[-1]["content"])
            return {
                "status": "success",
                "answer": json.dumps(
                    {"items": [{"id": item["id"], "text": item["text"]} for item in request["items"]]},
                    ensure_ascii=False,
                ),
            }

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=echoing_completion),
        ):
            result = translate_json_payload(
                {"summary": "Command injection found"},
                target_language="zh-Hans",
                retry_untranslated_fields=False,
            )

        self.assertEqual(result.payload["summary"], "Command injection found")
        self.assertEqual(result.batch_count, 1)
        self.assertEqual(calls, 1)

    def test_chart_payload_is_not_sent_to_translation_model(self) -> None:
        payload = {
            "summary": "Command injection found",
            "chart_data": {"risk_bars": [{"label": "AlmaLinux:8", "description": "Do not translate"}]},
        }
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=_translated_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["chart_data"], payload["chart_data"])
        self.assertEqual(result.candidate_fields, 1)

    def test_preserves_original_when_translation_model_completely_fails(self) -> None:
        payload = {"summary": "Command injection found"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch(
                "app.mcp.translation.diagnose_chat_completion",
                return_value={"status": "failed", "message": "HTTP 500"},
            ),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translation_status, "fallback")
        self.assertTrue(result.errors)

    def test_translation_accepted_when_inline_code_backticks_are_dropped(self) -> None:
        # 中文译文常保留标识符但去掉反引号：这种译文不应被保护段校验误杀。
        def dropping_backticks_completion(_model, messages, **kwargs):
            if kwargs.get("json_mode"):
                return {"status": "failed", "message": "force plain fallback"}
            content = messages[-1]["content"]
            if content.startswith("{"):
                return {"status": "failed", "message": "force plain fallback"}
            return {"status": "success", "answer": "在 1.2.3 中将 email_verified 设为 false 即可修复"}

        payload = {"summary": "Set `email_verified` to false in 1.2.3 to remediate"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=dropping_backticks_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "在 1.2.3 中将 email_verified 设为 false 即可修复")
        self.assertEqual(result.translated_fields, 1)

    def test_overlong_text_is_split_into_chunks_and_joined(self) -> None:
        from app.mcp.translation import _LONG_TEXT_CHARS

        long_text = "Paragraph one about the vulnerability. " * 150 + "\n\n" + "Paragraph two with impact details. " * 150
        self.assertGreater(len(long_text), _LONG_TEXT_CHARS)
        plain_calls: list[str] = []

        def chunk_completion(_model, messages, **_kwargs):
            content = messages[-1]["content"]
            if content.startswith("{"):
                # 批次模式原样回显，逼迫走逐字段兜底。
                request = json.loads(content)
                return {
                    "status": "success",
                    "answer": json.dumps(
                        {"items": [{"id": item["id"], "text": item["text"]} for item in request["items"]]},
                        ensure_ascii=False,
                    ),
                }
            plain_calls.append(content)
            return {"status": "success", "answer": f"译：{content[:40]}"}

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=chunk_completion),
        ):
            result = translate_json_payload({"summary": long_text}, target_language="zh-Hans")

        self.assertGreaterEqual(len(plain_calls), 2)  # 超长文本被切成多块分别翻译
        self.assertEqual(result.translation_status, "translated")
        self.assertEqual(result.translated_fields, 1)
        self.assertIn("译：", result.payload["summary"])

    def test_untranslated_fields_get_a_second_fallback_round(self) -> None:
        # 首轮兜底失败（返回英文）的字段，第二轮全新尝试应被重新拾取。
        plain_attempts: list[str] = []

        def flaky_completion(_model, messages, **_kwargs):
            content = messages[-1]["content"]
            if content.startswith("{"):
                request = json.loads(content)
                return {
                    "status": "success",
                    "answer": json.dumps(
                        {"items": [{"id": item["id"], "text": item["text"]} for item in request["items"]]},
                        ensure_ascii=False,
                    ),
                }
            plain_attempts.append(content)
            if len(plain_attempts) == 1:
                return {"status": "success", "answer": content}  # 第一轮仍回英文
            return {"status": "success", "answer": f"译：{content}"}

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=flaky_completion),
        ):
            result = translate_json_payload({"summary": "Second round probe text zebra"}, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "译：Second round probe text zebra")
        self.assertEqual(result.translated_fields, 1)
        self.assertEqual(len(plain_attempts), 2)

    def test_soft_slash_phrases_do_not_block_translation(self) -> None:
        # no-code/low-code 是自然语言斜杠短语而非机器路径：译成中文不应被误判弃译。
        def soft_path_completion(_model, messages, **_kwargs):
            request = json.loads(messages[-1]["content"])
            return {
                "status": "success",
                "answer": json.dumps(
                    {
                        "items": [
                            {
                                "id": request["items"][0]["id"],
                                "text": "NocoBase 是一个无代码/低代码平台；详见 https://example.test/advisory",
                            }
                        ]
                    },
                    ensure_ascii=False,
                ),
            }

        payload = {"summary": "NocoBase is a no-code/low-code platform; see https://example.test/advisory"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=soft_path_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "NocoBase 是一个无代码/低代码平台；详见 https://example.test/advisory")
        self.assertEqual(result.translated_fields, 1)

    def test_real_machine_paths_are_still_protected(self) -> None:
        # @scope/pkg、conf/conf.json 等真机器标识被译文丢弃时仍必须拒收。
        def dropping_paths_completion(_model, messages, **_kwargs):
            content = messages[-1]["content"]
            if content.startswith("{"):
                request = json.loads(content)
                return {
                    "status": "success",
                    "answer": json.dumps(
                        {"items": [{"id": item["id"], "text": "在 1.2.3 中通过配置逃逸"} for item in request["items"]]},
                        ensure_ascii=False,
                    ),
                }
            return {"status": "success", "answer": "在 1.2.3 中通过配置逃逸"}

        payload = {"summary": "Escape via conf/conf.json in @scope/pkg before 1.2.3"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=dropping_paths_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload, payload)
        self.assertEqual(result.translated_fields, 0)

    def test_fenced_code_blocks_are_masked_translated_and_restored(self) -> None:
        # PoC 公告：代码块不发给模型，叙述文字译成中文后代码块逐字回填。
        code_block = "```javascript\nconst payload = \"x) else if a==a (echo y\";\n// VULNERABLE comment stays English\n```"
        seen_user_texts: list[str] = []

        def poc_completion(_model, messages, **_kwargs):
            content = messages[-1]["content"]
            seen_user_texts.append(content)
            if content.startswith("{"):
                request = json.loads(content)
                answers = {}
                for item in request["items"]:
                    answers[item["id"]] = "该漏洞允许命令注入。详见 [[SEC-BLOCK-1]] 中的利用方式。"
                return {"status": "success", "answer": json.dumps({"items": [{"id": k, "text": v} for k, v in answers.items()]}, ensure_ascii=False)}
            return {"status": "success", "answer": "该漏洞允许命令注入。详见 [[SEC-BLOCK-1]] 中的利用方式。"}

        payload = {"summary": f"Command injection via shell option. Exploit:\n\n{code_block}"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=poc_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        translated = result.payload["summary"]
        self.assertIn("该漏洞允许命令注入", translated)
        self.assertIn(code_block, translated)  # 代码块逐字还原，注释不被翻译
        self.assertNotIn("[[SEC-BLOCK-1]]", translated)
        self.assertEqual(result.translated_fields, 1)
        self.assertTrue(all("VULNERABLE comment" not in text for text in seen_user_texts))  # 代码未发给模型

    def test_trailing_sentence_period_does_not_block_version_match(self) -> None:
        # 版本号段被正则并入句尾英文句号（5.0.0-beta.3.），中文句号结尾不应判失败。
        def period_completion(_model, messages, **_kwargs):
            request = json.loads(messages[-1]["content"])
            return {
                "status": "success",
                "answer": json.dumps(
                    {"items": [{"id": request["items"][0]["id"], "text": "5.0.0-beta.3 之前的版本受影响。请尽快升级。"}]},
                    ensure_ascii=False,
                ),
            }

        payload = {"summary": "Versions before 5.0.0-beta.3. Upgrade immediately"}
        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=period_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "5.0.0-beta.3 之前的版本受影响。请尽快升级。")
        self.assertEqual(result.translated_fields, 1)

    def test_whitespace_only_echo_is_neither_counted_nor_cached(self) -> None:
        # 模型"回显原文但裁掉尾部空白"不算翻译：不得计数、不得入缓存，
        # 否则逐字段兜底会被缓存里的英文原文短路，报告永远残留英文。
        payload = {"summary": "Advisory text with trailing whitespace probe "}
        plain_calls = 0

        def echo_strip_completion(_model, messages, **_kwargs):
            nonlocal plain_calls
            content = messages[-1]["content"]
            if content.startswith("{"):
                request = json.loads(content)
                return {
                    "status": "success",
                    "answer": json.dumps(
                        {"items": [{"id": item["id"], "text": item["text"].strip()} for item in request["items"]]},
                        ensure_ascii=False,
                    ),
                }
            plain_calls += 1
            return {"status": "success", "answer": "译：Advisory text with trailing whitespace probe"}

        with (
            patch("app.mcp.translation.active_model_from_env", return_value={"id": "model-a"}),
            patch("app.mcp.translation.diagnose_chat_completion", side_effect=echo_strip_completion),
        ):
            result = translate_json_payload(payload, target_language="zh-Hans")

        self.assertEqual(result.payload["summary"], "译：Advisory text with trailing whitespace probe")
        self.assertEqual(result.translated_fields, 1)
        self.assertEqual(plain_calls, 1)

    def test_graph_specs_place_translation_after_structured_json(self) -> None:
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

    def test_mcp_catalog_exposes_structured_translation_tool(self) -> None:
        spec = asyncio.run(translation_mcp_spec())
        self.assertEqual(spec["id"], "translation")
        self.assertEqual([tool["name"] for tool in spec["tools"]], ["translate_json_payload"])


def _translated_completion(_model, messages, **_kwargs):
    request = json.loads(messages[-1]["content"])
    return {
        "status": "success",
        "answer": json.dumps(
            {
                "items": [
                    {"id": item["id"], "text": f"译：{item['text']}"}
                    for item in request["items"]
                ]
            },
            ensure_ascii=False,
        ),
    }


if __name__ == "__main__":
    unittest.main()
