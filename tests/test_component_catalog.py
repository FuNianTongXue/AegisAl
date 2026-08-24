from __future__ import annotations

import json
import os
import tracemalloc
import unittest
import zipfile
from datetime import date
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.agent import assistant_intent
from app.agent.translation_policy import host_localization_attestation_is_publishable
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
from app.vulnerability_export import build_component_vulnerability_catalog_workbook_stream


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
        "file_name": "AegisAl-component-vulnerabilities-2026-07-01-to-2026-07-28.xlsx",
        "media_type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "download_path": "/api/assistant/artifacts/component-xlsx-20260728000000-abcdef123456",
        "sha256": "a" * 64,
        "size": 1024,
        "generated_at": "2026-07-28T00:00:00+00:00",
    }


def _translation_agent_audit(**overrides: object) -> dict:
    audit = {
        "server": "AegisAl Translation MCP",
        "tool": "translate_json_payload",
        "transport": "stdio",
        "status": "completed",
        "translation_status": "translated",
        "target_language": "zh-Hans",
        "unresolved_fields": 0,
        "offline": True,
        "network_used": False,
        "requires_api_key": False,
        "model_used": False,
        "offline_model_used": True,
        "resource_verified": True,
        "offline_contract_valid": True,
        "runtime_contract_valid": True,
        "provider_calls": 0,
        "billable_tokens": 0,
        "token_usage": 0,
        "input_sha256": "1" * 64,
        "output_sha256": "2" * 64,
        "model_sha256": "3" * 64,
    }
    audit.update(overrides)
    return audit


def _catalog_mcp_call(*, tool_id: str, arguments: dict, **_kwargs) -> dict:
    if tool_id == "mcp__d3_sankey__build_component_sankey":
        return {"nodes": [], "links": []}
    if tool_id == "mcp__excel__export_component_vulnerability_catalog":
        return {"file_name": _artifact()["file_name"], "test_arguments": arguments}
    raise AssertionError(f"Unexpected MCP tool: {tool_id}")


def _mcp_arguments(mock, tool_id: str) -> dict:
    for call in mock.call_args_list:
        if call.kwargs.get("tool_id") == tool_id:
            return dict(call.kwargs.get("arguments") or {})
    raise AssertionError(f"MCP tool was not called: {tool_id}")


def _workbook_xml_text(content: bytes) -> str:
    with zipfile.ZipFile(BytesIO(content)) as archive:
        return "".join(
            archive.read(name).decode("utf-8")
            for name in archive.namelist()
            if name.endswith(".xml")
        )


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
    def test_catalog_indexes_alias_cleanup_by_canonical_id(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            with service._catalog._connect() as connection:  # noqa: SLF001
                indexes = {
                    str(row[1])
                    for row in connection.execute("PRAGMA index_list(vulnerability_aliases)").fetchall()
                }
                plan = connection.execute(
                    "EXPLAIN QUERY PLAN DELETE FROM vulnerability_aliases WHERE canonical_id = ?",
                    ("CVE-2026-0001",),
                ).fetchall()

        self.assertIn("idx_vulnerability_aliases_cid", indexes)
        self.assertTrue(any("idx_vulnerability_aliases_cid" in str(row[3]) for row in plan))

    def test_range_query_filters_before_decrypting_visible_records(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            records = [
                _record(
                    f"CVE-2026-{8000 + index}",
                    f"2026-07-{24 - index:02d}T00:00:00+00:00",
                    severity="HIGH",
                    components=[
                        {
                            "ecosystem": "npm",
                            "name": f"demo-package-{index}",
                            "affected": ["< 2"],
                            "fixed": ["2"],
                        }
                    ],
                )
                for index in range(8)
            ]
            records.extend(
                _record(
                    f"CVE-2026-{8100 + index}",
                    f"2026-07-{15 - index:02d}T00:00:00+00:00",
                    severity="HIGH" if index < 4 else "MEDIUM",
                    components=[
                        {
                            "ecosystem": "PyPI" if index < 4 else "npm",
                            "name": "unrelated" if index < 4 else f"demo-package-medium-{index}",
                            "affected": ["< 1"],
                            "fixed": ["1"],
                        }
                    ],
                )
                for index in range(7)
            )
            service._catalog.upsert(records, translate=False)  # noqa: SLF001
            decode_record = service._catalog._decode_record  # noqa: SLF001

            with (
                patch.object(service._catalog, "_decode_record", wraps=decode_record) as decode,
                patch(
                    "app.intelligence.translation_agent.translate_json",
                    side_effect=AssertionError("catalog previews must not synchronously translate graph summaries"),
                ) as translate,
            ):
                result = service.query_component_vulnerability_catalog(
                    "2026-07-01",
                    "2026-07-28",
                    ecosystems=["npm"],
                    severities=["HIGH"],
                    component_names=["demo-package"],
                    include_realtime=False,
                    limit=2,
                )

        self.assertEqual(result["total"], 8)
        self.assertEqual(len(result["records"]), 2)
        self.assertTrue(result["truncated"])
        self.assertLessEqual(decode.call_count, 2)
        translate.assert_not_called()
        self.assertTrue(all(record["severity"] == "HIGH" for record in result["records"]))
        self.assertTrue(all(record["components"][0]["ecosystem"] == "npm" for record in result["records"]))

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
        workbook_text = _workbook_xml_text(content)
        for sheet_name in ("目录摘要", "漏洞明细", "组件版本范围", "参考链接"):
            self.assertIn(sheet_name, workbook_xml)
        self.assertIn("结果指纹", workbook_text)
        self.assertIn(result["result_sha256"], workbook_text)
        self.assertIn("组件范围记录", workbook_text)
        self.assertIn("高危", workbook_text)
        self.assertNotIn(">HIGH<", workbook_text)

    def test_catalog_export_streams_filtered_records_in_bounded_batches(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            service._catalog.upsert(  # noqa: SLF001 - isolated persistence fixture.
                [
                    _record(
                        "CVE-2026-7201",
                        "2026-07-24T00:00:00+00:00",
                        components=[
                            {"ecosystem": "npm", "name": "stream-demo", "affected": ["< 2"], "fixed": ["2"]},
                            {"ecosystem": "Maven", "name": "other", "affected": ["< 4"], "fixed": ["4"]},
                        ],
                    ),
                    _record(
                        "CVE-2026-7202",
                        "2026-07-23T00:00:00+00:00",
                        severity="MEDIUM",
                        components=[{"ecosystem": "npm", "name": "stream-demo", "affected": ["< 1"], "fixed": []}],
                    ),
                ],
                translate=False,
            )
            decode_record = service._catalog._decode_record  # noqa: SLF001
            with patch.object(service._catalog, "_decode_record", wraps=decode_record) as decode:
                records, metadata = service.stream_component_vulnerability_catalog(
                    "2026-07-01",
                    "2026-07-28",
                    ecosystems=["npm"],
                    severities=["HIGH"],
                    component_names=["stream-demo"],
                    response_language="en",
                    batch_size=1,
                )
                self.assertNotIsInstance(records, list)
                exported = list(records)

        self.assertEqual(metadata["total"], 1)
        self.assertEqual(decode.call_count, 1)
        self.assertEqual([record["id"] for record in exported], ["CVE-2026-7201"])
        self.assertEqual(
            exported[0]["components"],
            [{"ecosystem": "npm", "name": "stream-demo", "affected": ["< 2"], "fixed": ["2"]}],
        )
        self.assertNotIn("provenance", exported[0])

    def test_streaming_workbook_rejects_count_mismatch(self) -> None:
        with self.assertRaisesRegex(ValueError, "预期 2 条，实际 1 条"):
            build_component_vulnerability_catalog_workbook_stream(
                iter([_catalog_result()["records"][0]]),
                start_date="2026-07-01",
                end_date="2026-07-28",
                filters=_catalog_result()["filters"],
                generated_at="2026-07-28T00:00:00+00:00",
                expected_total=2,
            )

    def test_streaming_workbook_keeps_10k_records_within_bounded_memory(self) -> None:
        def records():
            for index in range(10_001):
                yield {
                    **_record(
                        f"CVE-2026-{80_000 + index}",
                        "2026-07-24T00:00:00+00:00",
                        components=[
                            {
                                "ecosystem": "npm",
                                "name": f"package-{index}",
                                "affected": ["< 2"],
                                "fixed": ["2"],
                            }
                        ],
                    ),
                    "reference_links": [],
                }

        tracemalloc.start()
        try:
            content, metadata = build_component_vulnerability_catalog_workbook_stream(
                records(),
                start_date="2026-07-01",
                end_date="2026-07-28",
                filters={"ecosystems": ["npm"], "severities": ["HIGH"], "component_names": []},
                generated_at="2026-07-28T00:00:00+00:00",
                expected_total=10_001,
            )
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(metadata["total"], 10_001)
        self.assertLess(peak, 96 * 1024 * 1024)
        with zipfile.ZipFile(BytesIO(content)) as archive:
            self.assertIsNone(archive.testzip())

    def test_report_summary_writeback_falls_back_to_source_until_catalog_translation_is_complete(self) -> None:
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
                        "translation_audit": _translation_agent_audit(),
                    }
                ]
            )
            stored = service._catalog.find_by_identifier(source["id"])[0]  # noqa: SLF001
            result = service.query_component_vulnerability_catalog(
                "2026-07-01",
                "2026-07-28",
                include_realtime=False,
            )

        self.assertEqual(persisted, 1)
        self.assertEqual(
            stored["catalog_translation"]["translation_agent"],
            _translation_agent_audit(),
        )
        self.assertEqual(result["records"][0]["summary"], source["summary"])
        self.assertEqual(result["catalog_translation"]["status"], "pending")

    def test_report_summary_writeback_rejects_missing_or_unsafe_translation_audit(self) -> None:
        with TemporaryDirectory() as directory:
            service = RealtimeIntelligenceService(Path(directory) / "catalog.sqlite3")
            source = _record(
                "CVE-2026-7100",
                "2026-07-24T00:00:00+00:00",
                components=[{"ecosystem": "npm", "name": "audit-demo", "affected": ["< 2"], "fixed": ["2"]}],
            )
            prepared = {
                **source,
                "title_original": source["title"],
                "summary_original": source["summary"],
                "catalog_translation": {
                    "version": 3,
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
                service._catalog.upsert([source])  # noqa: SLF001

            base = {
                "id": source["id"],
                "source_summary": source["summary"],
                "summary_zh": "该组件存在高危漏洞。",
            }
            missing = service.persist_component_summary_translations([base])
            unsafe = service.persist_component_summary_translations(
                [{**base, "translation_audit": _translation_agent_audit(network_used=True)}]
            )
            token_billed = service.persist_component_summary_translations(
                [{**base, "translation_audit": _translation_agent_audit(token_usage=1)}]
            )
            stored = service._catalog.find_by_identifier(source["id"])[0]  # noqa: SLF001

        self.assertEqual((missing, unsafe, token_billed), (0, 0, 0))
        self.assertNotIn("summary_zh", stored)


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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()) as excel,
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
        self.assertEqual(started["records"][0]["id"], "CVE-2026-7001")
        self.assertEqual(started["total"], 1)
        self.assertEqual(query.call_args_list[0].kwargs["limit"], 200)
        self.assertFalse(query.call_args_list[0].kwargs["include_realtime"])

    def test_excel_mcp_receives_query_contract_without_materialized_records(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        preview = {**_catalog_result(), "total": 3, "truncated": True}
        with (
            patch(
                "app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog",
                return_value=preview,
            ) as query,
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call) as mcp,
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()),
        ):
            started = graph.start({**self.payload, "top_k": 5})
            graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        self.assertEqual(query.call_count, 1)
        self.assertEqual(query.call_args_list[0].kwargs["limit"], 200)
        arguments = _mcp_arguments(mcp, "mcp__excel__export_component_vulnerability_catalog")
        self.assertNotIn("records", arguments)
        self.assertEqual(arguments["expected_total"], 3)
        self.assertEqual(arguments["expected_result_sha256"], "1" * 64)
        self.assertEqual(arguments["filters"], preview["filters"])

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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call) as mcp,
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()) as excel,
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
        excel_arguments = _mcp_arguments(
            mcp, "mcp__excel__export_component_vulnerability_catalog"
        )
        self.assertNotIn("records", excel_arguments)
        self.assertEqual(excel_arguments["response_language"], "zh-Hans")
        translation_traces = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertTrue(any("预先存储" in item["message"] for item in translation_traces))

    def test_excel_keeps_verified_original_while_storage_translation_is_pending(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call) as mcp,
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()) as excel,
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
        excel_arguments = _mcp_arguments(
            mcp, "mcp__excel__export_component_vulnerability_catalog"
        )
        self.assertNotIn("records", excel_arguments)
        self.assertEqual(excel_arguments["expected_total"], 1)
        warning = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertEqual(warning[0]["status"], "warning")
        self.assertIn("未重复执行离线翻译", warning[0]["message"])

    def test_excel_skips_translation_for_non_chinese_language(self) -> None:
        graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()),
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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call) as mcp,
            patch("app.mcp.translation.invoke_translation_mcp") as translate,
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()) as excel,
        ):
            started = graph.start({**self.payload, "response_language": "zh-Hans"})
            generated = graph.resume(
                started["thread_id"],
                decision="confirm",
                user_id="catalog-user",
                session_id="catalog-session",
            )

        translate.assert_not_called()
        excel_arguments = _mcp_arguments(
            mcp, "mcp__excel__export_component_vulnerability_catalog"
        )
        self.assertNotIn("records", excel_arguments)
        self.assertEqual(excel_arguments["expected_total"], 25)
        translation_traces = [item for item in generated["trace"] if item["node"] == "component_catalog.translation_cache"]
        self.assertTrue(any("25 条" in item["message"] for item in translation_traces))
        self.assertTrue(any(item["status"] == "warning" for item in translation_traces))
        self.assertEqual(len(started["records"]), 25)

    def test_generation_and_download_can_be_cancelled_independently(self) -> None:
        generation_graph = ComponentVulnerabilityCatalogSubgraph()
        with (
            patch("app.langgraph.component_catalog_graph.intelligence_service.query_component_vulnerability_catalog", return_value=_catalog_result()),
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
            patch("app.langgraph.component_catalog_graph.publish_mcp_workbook", return_value=_artifact()),
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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
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
            patch("app.langgraph.component_catalog_graph.call_mcp_tool", side_effect=_catalog_mcp_call),
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
                "summary": "已核验组件漏洞目录。\n- CVE-2026-7001 | HIGH | demo-package",
                "fields": {"漏洞数量": "1"},
                "chart_data": {},
                "artifacts": [],
                "interrupt": {"kind": "component_excel_generation_confirmation"},
                "trace": [],
            }
        )
        self.assertIn("CVE-2026-7001", answer["summary"])
        self.assertEqual(answer["artifacts"], [])
        self.assertEqual(answer["translation"]["translation_status"], "host-localized")

    def test_outcome_answer_keeps_all_public_translated_record_fields(self) -> None:
        record = {
            **_catalog_result()["records"][0],
            "title": "演示组件漏洞",
            "summary": "演示组件存在输入校验漏洞。",
            "title_original": "Demo component vulnerability",
            "summary_original": "The demo component has an input validation issue.",
            "reference_links": ["https://example.test/CVE-2026-7001"],
            "translation_audit": {"internal": True},
        }
        answer = component_catalog_outcome_answer(
            {
                "summary": "已核验组件漏洞目录。",
                "fields": {"漏洞数量": "1"},
                "records": [record],
                "total": 1,
                "chart_data": {},
                "artifacts": [],
                "trace": [],
            }
        )

        self.assertEqual(answer["total"], 1)
        self.assertEqual(answer["records"][0]["title"], "演示组件漏洞")
        for field in (
            "aliases",
            "cwes",
            "affected_versions",
            "fixed_versions",
            "components",
            "reference_links",
        ):
            self.assertIn(field, answer["records"][0])
        self.assertNotIn("references", answer["records"][0])
        self.assertNotIn("translation_audit", answer["records"][0])

    def test_outcome_answer_does_not_attest_unlocalized_preview(self) -> None:
        answer = component_catalog_outcome_answer(
            {
                "summary": "Component catalog preview is ready.",
                "fields": {"漏洞数量": "1"},
                "chart_data": {},
                "artifacts": [],
                "interrupt": {"kind": "component_excel_generation_confirmation"},
                "trace": [],
            }
        )

        self.assertNotIn("translation", answer)


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
            "summary": "已核验组件漏洞目录。\n- CVE-2026-7001 | 高危 | demo-package",
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
            patch.object(
                assistant_graph.translation_agent,
                "translate_json",
                side_effect=AssertionError("host-localized catalog previews must bypass Translation MCP"),
            ),
        ):
            result = assistant_graph.KnowledgeSecurityGraph().invoke("本月 npm 高危组件漏洞清单")

        self.assertEqual(result["mode"], "component_vulnerability_catalog")
        self.assertEqual(result["interrupt"]["kind"], "component_excel_generation_confirmation")
        self.assertEqual(result["translation"]["translation_status"], "host-localized")
        self.assertTrue(host_localization_attestation_is_publishable(result, "zh-Hans"))


if __name__ == "__main__":
    unittest.main()
