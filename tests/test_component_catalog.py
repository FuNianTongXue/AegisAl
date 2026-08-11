from __future__ import annotations

import json
import os
import unittest
import zipfile
from datetime import date
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.agent import assistant_intent
from app.api.routes import application
from app.intelligence import RealtimeIntelligenceService
from app.langgraph import assistant_graph
from app.langgraph.component_catalog_graph import (
    ComponentVulnerabilityCatalogSubgraph,
    _catalog_chart_data,
    _catalog_summary,
    component_catalog_outcome_answer,
    component_vulnerability_catalog_subgraph,
)


TODAY = date(2026, 7, 28)


def _record(
    identifier: str,
    published_at: str,
    *,
    severity: str = "HIGH",
    components: list[dict] | None = None,
) -> dict:
    return {
        "id": identifier,
        "title": f"{identifier} title",
        "summary": f"{identifier} summary",
        "severity": severity,
        "cvss_score": 8.1,
        "aliases": [],
        "cwes": ["CWE-79"],
        "affected_versions": ["< 2.0.0"],
        "fixed_versions": ["2.0.0"],
        "components": components or [],
        "references": [f"https://example.test/{identifier}"],
        "published_at": published_at,
        "updated_at": published_at,
    }


def _catalog_result() -> dict:
    record = _record(
        "CVE-2026-7001",
        "2026-07-24T00:00:00+00:00",
        components=[
            {
                "ecosystem": "npm",
                "name": "demo-package",
                "affected": ["< 2.0.0"],
                "fixed": ["2.0.0"],
            }
        ],
    )
    return {
        "status": "success",
        "start_date": "2026-07-01",
        "end_date": "2026-07-28",
        "records": [record],
        "total": 1,
        "component_count": 1,
        "severity": {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
        "ecosystem_counts": {"npm": 1},
        "filters": {"ecosystems": ["npm"], "severities": ["HIGH"], "component_names": []},
        "truncated": False,
        "graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "generated_at": "2026-07-28T00:00:00+00:00",
        "result_sha256": "1" * 64,
    }


def _artifact() -> dict:
    return {
        "id": "component-xlsx-20260728000000-abcdef123456",
        "kind": "excel",
        "file_name": "SecFlow-component-vulnerabilities-2026-07-01-to-2026-07-28.xlsx",
        "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "download_path": "/api/assistant/artifacts/component-xlsx-20260728000000-abcdef123456",
        "sha256": "a" * 64,
        "size": 1024,
        "generated_at": "2026-07-28T00:00:00+00:00",
    }


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class AssistantIntentPlannerTests(unittest.TestCase):
    def _fallback_plan(self, question: str) -> dict:
        with patch.object(assistant_intent, "chat_readiness_error", return_value="model unavailable"):
            return assistant_intent.plan_assistant_intent(question, today=TODAY)

    def test_current_and_explicit_month_catalog_intents(self) -> None:
        latest = self._fallback_plan("最新年月组件漏洞清单")
        explicit = self._fallback_plan("2026 年 7 月组件漏洞清单")

        self.assertEqual(latest["intent"], "component_vulnerability_catalog")
        self.assertEqual(latest["date_filter"]["start_date"], "2026-07-01")
        self.assertEqual(latest["date_filter"]["end_date"], "2026-07-28")
        self.assertEqual(explicit["date_filter"]["start_date"], "2026-07-01")
        self.assertEqual(explicit["date_filter"]["end_date"], "2026-07-28")

    def test_relative_time_and_explicit_filters_are_authoritative(self) -> None:
        plan = self._fallback_plan("上月 npm 高危组件漏洞列表")

        self.assertEqual(plan["intent"], "component_vulnerability_catalog")
        self.assertEqual(plan["date_filter"]["start_date"], "2026-06-01")
        self.assertEqual(plan["date_filter"]["end_date"], "2026-06-30")
        self.assertEqual(plan["filters"]["ecosystems"], ["npm"])
        self.assertEqual(plan["filters"]["severities"], ["HIGH"])

    def test_llm_inferred_severity_filter_is_stripped_without_explicit_keywords(self) -> None:
        candidate = {
            "intent": "component_vulnerability_catalog",
            "reason": "用户查询本月组件漏洞",
            "confidence": 0.9,
            "time_scope": {"kind": "current_month"},
            "filters": {"ecosystems": [], "severities": ["HIGH", "CRITICAL"], "component_names": []},
            "destination_hint": "unspecified",
        }
        plan = assistant_intent.validate_intent_plan(candidate, "查询本月需要优先处置的组件漏洞", today=TODAY)
        self.assertEqual(plan["filters"]["severities"], [])

        explicit = assistant_intent.validate_intent_plan(
            {**candidate, "filters": {"ecosystems": [], "severities": ["HIGH"], "component_names": []}},
            "查询本月高危组件漏洞",
            today=TODAY,
        )
        self.assertEqual(explicit["filters"]["severities"], ["HIGH"])

    def test_concrete_component_version_stays_on_single_component_path(self) -> None:
        plan = self._fallback_plan("检查 Maven org.example:demo 1.2.3 是否存在漏洞")
        self.assertEqual(plan["intent"], "component_vulnerability_query")
        self.assertEqual(plan["skill"]["name"], "secflow-component-vulnerability-query")
        self.assertEqual(plan["skill"]["prompt_version"], "secflow-assistant-intent-v9")

    def test_project_scan_rescan_and_follow_up_are_distinct_capabilities(self) -> None:
        active_task = {
            "id": "task-baseline",
            "status": "completed",
            "workspace_name": "demo",
            "result": {"total_findings": 3},
        }

        scan = assistant_intent.heuristic_intent_plan(
            "完整扫描这个项目并执行跨方法污点分析",
            today=TODAY,
            workspace_available=True,
        )
        rescan = assistant_intent.heuristic_intent_plan(
            "重新扫描这个项目并与上一次结果比较",
            today=TODAY,
            active_task={"available": True, **active_task},
        )
        follow_up = assistant_intent.heuristic_intent_plan(
            "补充刚才三条风险的修复代码和验证方法",
            today=TODAY,
            active_task={"available": True, **active_task},
        )

        self.assertEqual(scan["intent"], "project_scan")
        self.assertEqual(rescan["intent"], "project_rescan")
        self.assertEqual(follow_up["intent"], "scan_result_follow_up")
        self.assertEqual(rescan["skill"]["name"], "secflow-project-scan")

    def test_explicit_scan_execution_intent_survives_missing_workspace(self) -> None:
        scan = assistant_intent.heuristic_intent_plan(
            "我想做代码漏洞的扫描",
            today=TODAY,
            workspace_available=False,
        )
        conceptual = assistant_intent.heuristic_intent_plan(
            "代码扫描是什么",
            today=TODAY,
            workspace_available=False,
        )

        self.assertEqual(scan["intent"], "project_scan")
        self.assertEqual(conceptual["intent"], "llm_direct")

    def test_component_catalog_scan_wording_does_not_become_project_scan(self) -> None:
        plan = assistant_intent.heuristic_intent_plan(
            "请扫描本月最新组件漏洞清单",
            today=TODAY,
            workspace_available=False,
        )

        self.assertEqual(plan["intent"], "component_vulnerability_catalog")

    def test_invalid_model_capability_falls_back_to_validated_semantics(self) -> None:
        with (
            patch.object(assistant_intent, "active_model_from_env", return_value={"provider": "test", "model": "planner"}),
            patch.object(assistant_intent, "chat_readiness_error", return_value=None),
            patch.object(
                assistant_intent,
                "diagnose_chat_completion",
                return_value={"status": "success", "answer": json.dumps({"intent": "delete_database"})},
            ),
        ):
            plan = assistant_intent.plan_assistant_intent("近 30 天组件漏洞清单", today=TODAY)

        self.assertEqual(plan["planner"], "deterministic-fallback")
        self.assertEqual(plan["intent"], "component_vulnerability_catalog")
        self.assertEqual(plan["date_filter"]["start_date"], "2026-06-29")

    def test_valid_model_plan_cannot_override_explicit_user_dates_or_filters(self) -> None:
        candidate = {
            "intent": "component_vulnerability_catalog",
            "reason": "用户需要时间范围组件漏洞目录。",
            "confidence": 0.96,
            "time_scope": {
                "kind": "date_range",
                "start_date": "2026-01-01",
                "end_date": "2026-01-31",
            },
            "filters": {"ecosystems": ["PyPI"], "severities": ["CRITICAL"], "component_names": []},
        }
        with (
            patch.object(assistant_intent, "active_model_from_env", return_value={"provider": "test", "model": "planner"}),
            patch.object(assistant_intent, "chat_readiness_error", return_value=None),
            patch.object(
                assistant_intent,
                "diagnose_chat_completion",
                return_value={"status": "success", "answer": json.dumps(candidate, ensure_ascii=False)},
            ),
        ):
            plan = assistant_intent.plan_assistant_intent("2026 年 7 月 npm 高危组件漏洞清单", today=TODAY)

        self.assertEqual(plan["planner"], "llm")
        self.assertEqual(plan["date_filter"]["start_date"], "2026-07-01")
        self.assertEqual(plan["date_filter"]["end_date"], "2026-07-28")
        self.assertEqual(plan["filters"]["ecosystems"], ["npm"])
        self.assertEqual(plan["filters"]["severities"], ["HIGH"])


class ComponentCatalogServiceTests(unittest.TestCase):
    def test_range_and_component_filters_are_applied_to_fixed_result(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            service._catalog.upsert(  # noqa: SLF001 - isolated public service contract fixture.
                [
                    _record(
                        "CVE-2026-7001",
                        "2026-07-24T00:00:00+00:00",
                        components=[
                            {"ecosystem": "npm", "name": "demo-package", "affected": ["< 2"], "fixed": ["2"]},
                            {"ecosystem": "Maven", "name": "other", "affected": ["< 4"], "fixed": ["4"]},
                        ],
                    ),
                    _record(
                        "CVE-2026-7002",
                        "2026-07-01T00:00:00+00:00",
                        severity="MEDIUM",
                        components=[{"ecosystem": "npm", "name": "medium-package", "affected": ["< 1"], "fixed": []}],
                    ),
                    _record("CVE-2026-7003", "2026-07-15T00:00:00+00:00", severity="CRITICAL"),
                    _record(
                        "CVE-2026-6001",
                        "2026-06-30T23:59:59+00:00",
                        components=[{"ecosystem": "npm", "name": "old-package", "affected": ["< 1"], "fixed": []}],
                    ),
                ]
            )
            result = service.query_component_vulnerability_catalog(
                "2026-07-01",
                "2026-07-28",
                ecosystems=["npm"],
                severities=["HIGH"],
                include_realtime=False,
            )

            self.assertEqual(result["total"], 1)
            self.assertEqual(result["records"][0]["id"], "CVE-2026-7001")
            self.assertEqual(result["records"][0]["components"], [
                {"ecosystem": "npm", "name": "demo-package", "affected": ["< 2"], "fixed": ["2"]}
            ])
            self.assertEqual(result["component_count"], 1)
            self.assertEqual(len(result["result_sha256"]), 64)

            content, metadata = service.export_component_vulnerability_catalog(
                result["records"],
                start_date=result["start_date"],
                end_date=result["end_date"],
                filters=result["filters"],
                generated_at=result["generated_at"],
            )

        self.assertEqual(metadata["total"], 1)
        with zipfile.ZipFile(BytesIO(content)) as archive:
            workbook_xml = archive.read("xl/workbook.xml").decode("utf-8")
            shared_strings = archive.read("xl/sharedStrings.xml").decode("utf-8")
        for sheet_name in ("目录摘要", "漏洞明细", "组件版本范围", "参考链接"):
            self.assertIn(sheet_name, workbook_xml)
        self.assertIn("结果指纹", shared_strings)
        self.assertIn(result["result_sha256"], shared_strings)
        self.assertIn("组件范围记录", shared_strings)
        self.assertIn("高危", shared_strings)
        self.assertNotIn(">HIGH<", shared_strings)

    def test_report_translation_is_written_back_and_reused_by_next_query(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            source = _record(
                "CVE-2026-7099",
                "2026-07-24T00:00:00+00:00",
                components=[{"ecosystem": "npm", "name": "persist-demo", "affected": ["< 2"], "fixed": ["2"]}],
            )
            prepared = {
                **source,
                "title_original": source["title"],
                "summary_original": source["summary"],
                "catalog_translation": {
                    "version": 1,
                    "target_language": "zh-Hans",
                    "status": "pending",
                    "source_title": source["title"],
                    "source_summary": source["summary"],
                },
            }
            with patch(
                "app.intelligence.translate_records_for_storage",
                return_value=([prepared], {"pending_records": 1}),
            ):
                service._catalog.upsert([source])  # noqa: SLF001 - isolated persistence fixture.

            persisted = service.persist_component_summary_translations(
                [
                    {
                        "id": source["id"],
                        "source_summary": source["summary"],
                        "summary_zh": "该组件存在高危漏洞，攻击者可能触发远程代码执行。",
                    }
                ]
            )
            result = service.query_component_vulnerability_catalog(
                "2026-07-01",
                "2026-07-28",
                include_realtime=False,
            )

        self.assertEqual(persisted, 1)
        self.assertEqual(result["records"][0]["summary"], "该组件存在高危漏洞，攻击者可能触发远程代码执行。")
        self.assertEqual(result["catalog_translation"]["status"], "completed")


class ComponentCatalogSubgraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.payload = {
            "question": "2026 年 7 月 npm 高危组件漏洞清单",
            "user_id": "catalog-user",
            "session_id": "catalog-session",
            "date_filter": {"start_date": "2026-07-01", "end_date": "2026-07-28"},
            "filters": {"ecosystems": ["npm"], "severities": ["HIGH"], "component_names": []},
            "intent_plan": {"planner": "llm"},
        }

    def test_two_interrupts_preserve_one_query_result_and_artifact(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()) as query,
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()) as excel,
        ):
            started = graph.start(self.payload)
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )
            completed = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        self.assertEqual(started["interrupt"]["kind"], "component_excel_generation_confirmation")
        self.assertEqual(generated["interrupt"]["kind"], "component_excel_download_confirmation")
        self.assertEqual(generated["interrupt"]["artifact_ids"], [_artifact()["id"]])
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["artifacts"], [_artifact()])
        self.assertEqual(query.call_count, 1)
        self.assertEqual(excel.call_count, 1)

    def test_catalog_preview_and_chart_severity_are_localized_for_chinese(self) -> None:
        catalog = {
            **_catalog_result(),
            "records": [
                {
                    **_catalog_result()["records"][0],
                    "severity": "MEDIUM",
                }
            ],
            "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 1, "LOW": 0, "UNKNOWN": 0},
        }

        summary = _catalog_summary(catalog, "zh-Hans")
        chart = _catalog_chart_data(catalog, {}, "zh-Hans")

        self.assertIn("| 中危 |", summary)
        labels = {item["key"]: item["label"] for item in chart["severity_ring"]}
        self.assertEqual(labels["CRITICAL"], "严重")
        self.assertEqual(labels["MEDIUM"], "中危")
        self.assertEqual(labels["UNKNOWN"], "未知")

    def test_excel_reuses_stored_translation_without_report_time_model_call(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        catalog = _catalog_result()
        catalog["records"][0]["summary"] = "演示包存在高危缓冲区溢出漏洞。"
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=catalog),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()) as excel,
        ):
            started = graph.start({**self.payload, "response_language": "zh-Hans"})
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        self.assertEqual(generated["interrupt"]["kind"], "component_excel_download_confirmation")
        translate.assert_not_called()
        excel_records = excel.call_args[0][0]["records"]
        self.assertEqual(excel_records[0]["summary"], "演示包存在高危缓冲区溢出漏洞。")
        self.assertEqual(excel_records[0]["id"], "CVE-2026-7001")
        translation_traces = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertTrue(any("预先存储" in item["message"] for item in translation_traces))

    def test_excel_keeps_verified_original_while_storage_translation_is_pending(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()) as excel,
        ):
            started = graph.start({**self.payload, "response_language": "zh-Hans"})
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        self.assertEqual(generated["interrupt"]["kind"], "component_excel_download_confirmation")
        translate.assert_not_called()
        excel_records = excel.call_args[0][0]["records"]
        self.assertEqual(excel_records[0]["summary"], "CVE-2026-7001 summary")
        warning = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertEqual(warning[0]["status"], "warning")
        self.assertIn("未重复调用翻译模型", warning[0]["message"])

    def test_excel_skips_translation_for_non_chinese_language(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()),
        ):
            started = graph.start({**self.payload, "response_language": "en"})
            graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        translate.assert_not_called()

    def test_large_excel_export_never_fans_out_translation_calls(self) -> None:
        records = [
            _record(f"CVE-2026-7{index:03d}", "2026-07-24T00:00:00+00:00")
            for index in range(25)
        ]
        catalog = {**_catalog_result(), "records": records, "total": 25}

        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=catalog),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()) as excel,
        ):
            started = graph.start({**self.payload, "response_language": "zh-Hans"})
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        translate.assert_not_called()
        excel_records = excel.call_args[0][0]["records"]
        self.assertEqual(len(excel_records), 25)
        self.assertTrue(all(str(item["summary"]).endswith("summary") for item in excel_records))
        translation_traces = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertTrue(any("25 条" in item["message"] for item in translation_traces))
        self.assertTrue(any(item["status"] == "warning" for item in translation_traces))

    def test_generation_and_download_can_be_cancelled_independently(self) -> None:
        generation_graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
        ):
            started = generation_graph.start(self.payload)
            cancelled = generation_graph.resume(
                started["thread_id"],
                decision="cancel",
                user_id="catalog-user",
                session_id="catalog-session",
            )
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["artifacts"], [])

        download_graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
            patch("app.langgraph.component_catalog_graph.invoke_catalog_excel_mcp", return_value=_artifact()),
        ):
            started = download_graph.start(self.payload)
            generated = download_graph.resume(
                started["thread_id"], decision="confirm", user_id="catalog-user", session_id="catalog-session"
            )
            cancelled = download_graph.resume(
                started["thread_id"], decision="cancel", user_id="catalog-user", session_id="catalog-session"
            )
        self.assertEqual(generated["status"], "interrupted")
        self.assertEqual(cancelled["status"], "cancelled")
        self.assertEqual(cancelled["artifacts"], [_artifact()])

    def test_resume_enforces_user_and_session_ownership(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
        ):
            started = graph.start(self.payload)
            with self.assertRaises(KeyError):
                graph.resume(
                    started["thread_id"], decision="cancel", user_id="other-user", session_id="catalog-session"
                )
            graph.resume(
                started["thread_id"], decision="cancel", user_id="catalog-user", session_id="catalog-session"
            )

    def test_generic_resume_api_routes_component_catalog_thread(self) -> None:
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.invoke_sankey_mcp", return_value={"nodes": [], "links": []}),
        ):
            started = component_vulnerability_catalog_subgraph.start(self.payload)
            with (
                patch.dict(os.environ, {"SECFLOW_DISABLE_BATCH_SCHEDULER": "1"}),
                patch.object(application, "trial_manager", AlwaysUsableTrial()),
                patch("app.agent.assistant_service.translate_assistant_answer") as translate_answer,
                TestClient(application.app) as client,
            ):
                response = client.post(
                    "/api/assistant/interrupts/resume",
                    json={
                        "thread_id": started["thread_id"],
                        "decision": "cancel",
                        "user_id": "catalog-user",
                        "session_id": "catalog-session",
                    },
                )

        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()["data"]
        self.assertEqual(data["status"], "cancelled")
        self.assertEqual(data["answer"]["mode"], "component_vulnerability_catalog")
        translate_answer.assert_not_called()

    def test_outcome_answer_exposes_preview_before_export(self) -> None:
        answer = component_catalog_outcome_answer(
            {
                "summary": "- CVE-2026-7001 | HIGH | demo-package",
                "fields": {"漏洞数量": "1"},
                "chart_data": {},
                "artifacts": [],
                "interrupt": {"kind": "component_excel_generation_confirmation"},
                "trace": [],
            }
        )
        self.assertIn("CVE-2026-7001", answer["summary"])
        self.assertEqual(answer["artifacts"], [])


class MainAssistantCatalogRoutingTests(unittest.TestCase):
    def test_main_graph_routes_semantic_catalog_plan_without_affecting_scan_paths(self) -> None:
        planned = {
            "intent": "component_vulnerability_catalog",
            "reason": "用户需要按时间列出多个组件漏洞。",
            "confidence": 0.98,
            "date_filter": {"start_date": "2026-07-01", "end_date": "2026-07-28"},
            "filters": {"ecosystems": ["npm"], "severities": ["HIGH"], "component_names": []},
            "planner": "llm",
            "skill": {"prompt_version": "secflow-assistant-intent-v2", "sha256": "f" * 64},
        }
        outcome = {
            "status": "interrupted",
            "thread_id": "component-catalog-test",
            "interrupt": {"kind": "component_excel_generation_confirmation", "question": "是否生成 Excel？"},
            "summary": "- CVE-2026-7001 | HIGH | demo-package",
            "fields": {"漏洞数量": "1"},
            "chart_data": {},
            "artifacts": [],
            "error": "",
            "trace": [],
        }
        with (
            patch.object(assistant_graph, "plan_assistant_intent", return_value=planned),
            patch.object(component_vulnerability_catalog_subgraph, "start", return_value=outcome),
            patch.object(
                assistant_graph.memory_service,
                "build_context",
                return_value={"enabled": True, "stats": {}, "injectedMessages": []},
            ),
            patch.object(assistant_graph.memory_service, "add_exchange", return_value=None),
        ):
            result = assistant_graph.KnowledgeSecurityGraph().invoke("本月 npm 高危组件漏洞清单")

        self.assertEqual(result["mode"], "component_vulnerability_catalog")
        self.assertEqual(result["interrupt"]["kind"], "component_excel_generation_confirmation")


if __name__ == "__main__":
    unittest.main()
