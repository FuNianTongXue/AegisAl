from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

import app.main as main_module
from app.api.routes.application import _assistant_content_chunks
from app.graph import KnowledgeSecurityGraph, add_trace
from app.langgraph.assistant_graph import build_task_scan_follow_up_answer, llm_token_usage, system_prompt
from app.memory import LongTermMemoryService


class AlwaysUsableTrial:
    @staticmethod
    def status() -> dict:
        return {"usable": True}


class RecordingPostgresResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class RecordingPostgresConnection:
    def __init__(self, rows):
        self.rows = list(rows)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, statement, parameters=()):
        self.calls.append((str(statement), parameters))
        row = self.rows.pop(0) if self.rows else None
        return RecordingPostgresResult(row)


class FakeKnowledgeGraph:
    def invoke(self, _question, _top_k, **kwargs):
        sink = kwargs["event_sink"]
        trace = [
            {
                "node": "classify_query",
                "status": "completed",
                "message": "已识别问题意图。",
                "time": "2026-07-22T10:00:00+00:00",
            },
            {
                "node": "compose_answer",
                "status": "completed",
                "message": "已生成最终回答。",
                "time": "2026-07-22T10:00:01+00:00",
            },
        ]
        for item in trace:
            sink(item)
        return {
            "mode": "llm_direct",
            "summary": "测试回答",
            "fields": {},
            "vulnerability_card": {},
            "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "chart_data": {},
            "confidence": 0.82,
            "trace": trace,
            "generated_at": "2026-07-22T10:00:01+00:00",
        }


class FakeStreamingKnowledgeGraph(FakeKnowledgeGraph):
    def invoke(self, _question, _top_k, **kwargs):
        kwargs["content_sink"]("UNVERIFIED ENGLISH ")
        kwargs["content_sink"]("BODY")
        return {
            "mode": "llm_direct",
            "summary": "实时回答",
            "fields": {},
            "trace": [],
            "generated_at": "2026-07-22T10:00:01+00:00",
        }


class FakeLiveTraceKnowledgeGraph(FakeKnowledgeGraph):
    def invoke(self, _question, _top_k, **kwargs):
        trace = [
            {
                "id": "catalog-query",
                "node": "query_intelligence",
                "status": "running",
                "message": "正在查询公开漏洞事实。Authorization: Bearer live-secret-token-123456",
                "time": "2026-07-22T10:00:00+00:00",
                "reasoning": "SECRET_CHAIN_OF_THOUGHT",
                "presentation": {
                    "kind": "prompt_diff",
                    "title": "系统提示词变更",
                    "before": "SECRET_SYSTEM_PROMPT_BEFORE",
                    "after": "SECRET_SYSTEM_PROMPT_AFTER",
                },
            },
            {
                "id": "catalog-query",
                "node": "query_intelligence",
                "status": "completed",
                "message": "漏洞事实查询完成。",
                "time": "2026-07-22T10:00:01+00:00",
                "duration_ms": 1000,
                "presentation": {
                    "kind": "tool_call",
                    "title": "查询漏洞事实",
                    "tool_name": "catalog_query",
                    "state": "completed",
                    "input": {
                        "query": "CVE-2026-0001",
                        "api_key": "sk-supersecretvalue",
                        "system_prompt": "SECRET_TOOL_PROMPT",
                    },
                    "output": {"matches": 1},
                    "error": "",
                },
            },
        ]
        for item in trace:
            kwargs["event_sink"](item)
        return {
            "mode": "llm_direct",
            "summary": "实时状态回答",
            "fields": {},
            # Include a duplicate terminal item to verify both result and SSE
            # projection use stable identity de-duplication.
            "trace": [*trace, dict(trace[-1])],
            "generated_at": "2026-07-22T10:00:01+00:00",
        }


class AssistantStreamTests(unittest.TestCase):
    def test_information_graph_persistence_returns_short_term_exchange_id(self) -> None:
        graph = KnowledgeSecurityGraph.__new__(KnowledgeSecurityGraph)
        state = {
            "question": "解释这条安全资讯",
            "user_id": "tester",
            "session_id": "information:article-1",
            "response_language": "zh-Hans",
            "intent": "security_knowledge",
            "answer": {
                "mode": "security_knowledge",
                "summary": "这是译后的资讯说明。",
                "fields": {},
                "trace": [],
            },
            "trace": [],
        }

        with patch(
            "app.langgraph.assistant_graph.memory_service.add_short_term_exchange",
            return_value={"id": "short-0013"},
        ) as remember:
            persisted = graph._persist_memory(state)
            result = graph._final_answer(persisted)

        remember.assert_called_once()
        self.assertEqual(persisted["exchange_id"], "short-0013")
        self.assertEqual(result["session_id"], "information:article-1")
        self.assertEqual(result["exchange_id"], "short-0013")

    def test_system_prompt_uses_shanghai_date_across_utc_day_boundary(self) -> None:
        prompt = system_prompt(
            "zh-Hans",
            now=datetime(2026, 8, 1, 16, 30, tzinfo=timezone.utc),
        )

        self.assertIn("系统当前日期为 2026年08月02日", prompt)
        self.assertIn("当前时间为 00:30:00", prompt)
        self.assertIn("Asia/Shanghai", prompt)

    def test_non_component_answer_omits_empty_component_detail(self) -> None:
        graph = KnowledgeSecurityGraph()
        state = {
            "intent": "vulnerability_lookup",
            "response_language": "zh-Hans",
            "records": [],
            "llm_result": {"status": "success", "answer": "CVE 查询完成。"},
            "llm_error": "",
            "memory_context": {},
            "vulnerability_card": {},
            "knowledge_graph": {},
            "component_detail": {},
            "evidence_sources": [],
            "artifacts": [],
            "trace": [],
        }

        result = graph._compose_answer(state)["answer"]

        self.assertNotIn("component_detail", result)
        self.assertEqual(result["summary"], "CVE 查询完成。")

    def test_conversation_endpoints_list_and_restore_only_the_requested_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange(
                "tester",
                "保留这个问题",
                {
                    "mode": "llm_direct",
                    "summary": "保留这个回答",
                    "fields": {},
                    "evidence_sources": [{"id": "nvd", "status": "success", "count": 2}],
                    "token_usage": 4128,
                    "confidence": 0.91,
                    "trace": [
                        {
                            "node": "call_llm",
                            "status": "completed",
                            "message": "模型调用完成。",
                            "time": "2026-07-28T10:00:01+00:00",
                        }
                    ],
                    "generated_at": "2026-07-28T10:00:02+00:00",
                },
                session_id="session-1",
            )
            service.add_exchange("other", "不能看到的问题", {"summary": "不能看到的回答"}, session_id="session-2")
            with (
                patch.object(main_module, "memory_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                listing = client.get("/api/assistant/conversations", params={"user_id": "tester"})
                detail = client.get(
                    "/api/assistant/conversations/session-1",
                    params={"user_id": "tester"},
                )
                hidden = client.get(
                    "/api/assistant/conversations/session-2",
                    params={"user_id": "tester"},
                )
                archived = client.post(
                    "/api/assistant/conversations/session-1/archive",
                    params={"user_id": "tester"},
                    json={"archived": True},
                )
                active_listing = client.get("/api/assistant/conversations", params={"user_id": "tester"})
                archived_listing = client.get(
                    "/api/assistant/conversations",
                    params={"user_id": "tester", "archived": True},
                )
                unauthorized_delete = client.delete(
                    "/api/assistant/conversations/session-1",
                    params={"user_id": "other"},
                )
                deleted = client.delete(
                    "/api/assistant/conversations/session-1",
                    params={"user_id": "tester"},
                )
                legacy_listing = client.get("/api/memory/conversations", params={"user_id": "tester"})

            self.assertEqual(listing.status_code, 200, listing.text)
            self.assertEqual([item["id"] for item in listing.json()["data"]], ["session-1"])
            self.assertEqual(detail.status_code, 200, detail.text)
            self.assertEqual(detail.json()["data"]["exchanges"][0]["answer"], "保留这个回答")
            restored_payload = detail.json()["data"]["exchanges"][0]["answer_payload"]
            self.assertEqual(restored_payload["token_usage"], 4128)
            self.assertEqual(restored_payload["trace"][0]["node"], "call_llm")
            self.assertEqual(restored_payload["evidence_sources"][0]["id"], "nvd")
            self.assertEqual(hidden.status_code, 404, hidden.text)
            self.assertEqual(archived.status_code, 200, archived.text)
            self.assertTrue(archived.json()["data"]["archived"])
            self.assertEqual(active_listing.json()["data"], [])
            self.assertEqual([item["id"] for item in archived_listing.json()["data"]], ["session-1"])
            self.assertEqual(unauthorized_delete.status_code, 404, unauthorized_delete.text)
            self.assertEqual(deleted.status_code, 200, deleted.text)
            self.assertTrue(deleted.json()["data"]["deleted"])
            self.assertEqual(legacy_listing.status_code, 200, legacy_listing.text)
            self.assertEqual(legacy_listing.json()["data"], [])

    def test_translated_table_edits_are_isolated_and_survive_conversation_reload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            memory_path = Path(temp_dir) / "memory.json"
            service = LongTermMemoryService(memory_path)
            service.local_only = True
            original_tables = [{
                "id": "translated-findings",
                "title": "翻译后的漏洞记录",
                "columns": [
                    {"key": "id", "label": "漏洞编号", "editable": False},
                    {"key": "title", "label": "标题"},
                ],
                "rows": [{"id": "CVE-2026-4242", "title": "原中文标题"}],
            }]
            stored = service.add_exchange(
                "tester",
                "返回漏洞记录",
                {
                    "mode": "component_vulnerability_catalog",
                    "summary": "已返回翻译后的漏洞记录。",
                    "tables": original_tables,
                    "translation": {"status": "completed", "proof": "original-proof"},
                },
                session_id="translated-session",
            )
            edited_tables = [{
                **original_tables[0],
                "type": "records-table",
                "rows": [{"id": "CVE-2026-4242", "title": "修订后的中文标题"}],
                "edited": True,
            }]
            path = (
                f"/api/assistant/conversations/translated-session/exchanges/"
                f"{stored['id']}/table-edits"
            )
            with (
                patch.object(main_module, "memory_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                saved = client.patch(path, params={"user_id": "tester"}, json={"tables": edited_tables})
                wrong_user = client.patch(path, params={"user_id": "other"}, json={"tables": edited_tables})
                wrong_session = client.patch(
                    path.replace("translated-session", "other-session"),
                    params={"user_id": "tester"},
                    json={"tables": edited_tables},
                )
                missing = client.patch(
                    path.replace(str(stored["id"]), "msg-9999"),
                    params={"user_id": "tester"},
                    json={"tables": edited_tables},
                )

            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()["data"]["tables"], edited_tables)
            self.assertEqual(wrong_user.status_code, 404, wrong_user.text)
            self.assertEqual(wrong_session.status_code, 404, wrong_session.text)
            self.assertEqual(missing.status_code, 404, missing.text)

            reopened = LongTermMemoryService(memory_path)
            reopened.local_only = True
            payload = reopened.get_conversation("tester", "translated-session")["exchanges"][0]["answer_payload"]
            self.assertEqual(payload["structured_data_edits"], edited_tables)
            self.assertEqual(payload["tables"], original_tables)
            self.assertEqual(payload["translation"], {"status": "completed", "proof": "original-proof"})

    def test_local_exchange_ids_remain_unique_after_history_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.max_history = 2
            stored = [
                service.add_exchange(
                    "tester",
                    f"第 {index} 轮",
                    {
                        "summary": f"回答 {index}",
                        "tables": [{
                            "id": "findings",
                            "columns": [{"key": "title", "label": "标题"}],
                            "rows": [{"title": f"记录 {index}"}],
                        }],
                    },
                    session_id="rolling-session",
                )
                for index in range(4)
            ]

            self.assertEqual(
                [entry["id"] for entry in stored],
                ["msg-0001", "msg-0002", "msg-0003", "msg-0004"],
            )
            conversation = service.get_conversation("tester", "rolling-session")
            self.assertEqual(
                [entry["id"] for entry in conversation["exchanges"]],
                ["msg-0003", "msg-0004"],
            )
            edits = [{
                "id": "findings",
                "columns": [{"key": "title", "label": "标题"}],
                "rows": [{"title": "窗口滚动后仍可保存"}],
            }]
            self.assertEqual(
                service.update_exchange_table_edits(
                    "tester",
                    "rolling-session",
                    stored[-1]["id"],
                    edits,
                ),
                edits,
            )

    def test_postgres_table_edit_uses_one_atomic_jsonb_update(self) -> None:
        service = LongTermMemoryService()
        connection = RecordingPostgresConnection([{"id": 42}])
        edits = [{
            "id": "findings",
            "columns": [{"key": "title", "label": "标题"}],
            "rows": [{"title": "并发安全修改"}],
        }]

        with patch.object(service, "_pg_connect", return_value=connection):
            saved = service._pg_update_exchange_table_edits(
                "tester",
                "translated-session",
                "msg-42",
                edits,
            )

        self.assertEqual(saved, edits)
        self.assertEqual(len(connection.calls), 1)
        statement, parameters = connection.calls[0]
        normalized_sql = " ".join(statement.lower().split())
        self.assertIn("set answer_payload = jsonb_set(", normalized_sql)
        self.assertIn("'{structured_data_edits}'", normalized_sql)
        self.assertIn("returning id", normalized_sql)
        self.assertNotIn("select id, answer_payload", normalized_sql)
        self.assertEqual(json.loads(parameters[0]), edits)
        self.assertEqual(parameters[1:], (42, "tester", "translated-session"))

    def test_postgres_interrupt_update_preserves_current_table_edits_atomically(self) -> None:
        service = LongTermMemoryService()
        connection = RecordingPostgresConnection([
            {"id": 42, "question": "继续生成制品"},
            {"id": 42},
            None,
        ])
        resumed_answer = {
            "mode": "project_sbom_export",
            "summary": "确认流程已继续",
            "interrupt": {
                "thread_id": "sbom-thread-1",
                "interrupt_id": "interrupt-2",
            },
            "translation": {"status": "completed", "proof": "new-proof"},
        }

        with patch.object(service, "_pg_connect", return_value=connection):
            updated = service._pg_update_interrupt_exchange(
                "tester",
                "translated-session",
                "sbom-thread-1",
                resumed_answer,
            )

        self.assertTrue(updated)
        self.assertEqual(len(connection.calls), 3)
        statement, parameters = connection.calls[1]
        normalized_sql = " ".join(statement.lower().split())
        self.assertIn("answer_payload = case", normalized_sql)
        self.assertIn("then jsonb_set(", normalized_sql)
        self.assertIn("exchange.answer_payload -> 'structured_data_edits'", normalized_sql)
        self.assertIn("returning id", normalized_sql)
        self.assertIs(parameters[4], True)
        self.assertNotIn("structured_data_edits", json.loads(parameters[5]))

        explicit_edits = [{
            "id": "replacement",
            "columns": [{"key": "title", "label": "标题"}],
            "rows": [{"title": "显式替换"}],
        }]
        explicit_connection = RecordingPostgresConnection([
            {"id": 42, "question": "继续生成制品"},
            {"id": 42},
            None,
        ])
        with patch.object(service, "_pg_connect", return_value=explicit_connection):
            service._pg_update_interrupt_exchange(
                "tester",
                "translated-session",
                "sbom-thread-1",
                {**resumed_answer, "structured_data_edits": explicit_edits},
            )
        explicit_parameters = explicit_connection.calls[1][1]
        self.assertIs(explicit_parameters[4], False)
        self.assertEqual(
            json.loads(explicit_parameters[5])["structured_data_edits"],
            explicit_edits,
        )

    def test_short_term_consultation_can_be_cleared_without_creating_conversation_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.add_short_term_exchange(
                "tester",
                "information:isolated",
                "第一轮咨询",
                {"summary": "第一轮回答"},
            )
            with (
                patch.object(main_module, "memory_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                listing = client.get("/api/assistant/conversations", params={"user_id": "tester"})
                cleared = client.delete(
                    "/api/assistant/short-term-sessions/information:isolated",
                    params={"user_id": "tester"},
                )
                rejected = client.delete(
                    "/api/assistant/short-term-sessions/persistent-session",
                    params={"user_id": "tester"},
                )

            self.assertEqual(listing.status_code, 200, listing.text)
            self.assertEqual(listing.json()["data"], [])
            self.assertEqual(cleared.status_code, 200, cleared.text)
            self.assertEqual(cleared.json()["data"]["cleared_turn_count"], 1)
            self.assertEqual(rejected.status_code, 422, rejected.text)

    def test_short_term_table_edits_save_in_process_and_ids_do_not_repeat(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.recent_limit = 2
            stored = [
                service.add_short_term_exchange(
                    "tester",
                    "information:editable",
                    f"咨询 {index}",
                    {
                        "summary": f"回答 {index}",
                        "tables": [{
                            "id": "information-records",
                            "columns": [{"key": "title", "label": "标题"}],
                            "rows": [{"title": f"译文 {index}"}],
                        }],
                    },
                )
                for index in range(3)
            ]
            edits = [{
                "id": "information-records",
                "type": "records-table",
                "columns": [{"key": "title", "label": "标题"}],
                "rows": [{"title": "用户修订后的译文"}],
                "edited": True,
            }]
            path = (
                "/api/assistant/conversations/information:editable/exchanges/"
                f"{stored[-1]['id']}/table-edits"
            )
            with (
                patch.object(main_module, "memory_service", service),
                patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
                TestClient(main_module.app) as client,
            ):
                saved = client.patch(path, params={"user_id": "tester"}, json={"tables": edits})
                wrong_user = client.patch(path, params={"user_id": "other"}, json={"tables": edits})

            self.assertEqual([entry["id"] for entry in stored], ["short-0001", "short-0002", "short-0003"])
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()["data"]["tables"], edits)
            self.assertEqual(wrong_user.status_code, 404, wrong_user.text)
            recent = service.build_short_term_context(
                "tester",
                "information:editable",
                "继续咨询",
            )["recentHistory"]
            self.assertEqual(recent[-1]["answerPayload"]["structured_data_edits"], edits)

            service.clear_short_term_session("tester", "information:editable")
            after_clear = service.add_short_term_exchange(
                "tester",
                "information:editable",
                "重新咨询",
                {"summary": "重新回答"},
            )
            self.assertEqual(after_clear["id"], "short-0004")

    def test_interrupt_resume_replaces_the_original_history_answer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange(
                "tester",
                "导出项目 SBOM",
                {
                    "mode": "project_sbom_export",
                    "summary": "是否匹配漏洞？",
                    "interrupt": {
                        "thread_id": "sbom-thread-1",
                        "interrupt_id": "interrupt-1",
                        "kind": "sbom_vulnerability_match_confirmation",
                    },
                    "structured_data_edits": [{
                        "id": "translated-sbom-records",
                        "columns": [{"key": "title", "label": "标题"}],
                        "rows": [{"title": "用户修订后的译文"}],
                        "edited": True,
                    }],
                    "translation": {"status": "completed", "proof": "original-proof"},
                },
                session_id="session-1",
            )

            updated = service.update_interrupt_exchange(
                "tester",
                "session-1",
                "sbom-thread-1",
                {
                    "mode": "project_sbom_export",
                    "summary": "是否生成 Excel？",
                    "interrupt": {
                        "thread_id": "sbom-thread-1",
                        "interrupt_id": "interrupt-2",
                        "kind": "sbom_excel_generation_confirmation",
                    },
                    "translation": {"status": "completed", "proof": "resumed-proof"},
                },
            )
            conversation = service.get_conversation("tester", "session-1")

        self.assertTrue(updated)
        self.assertEqual(conversation["turn_count"], 1)
        payload = conversation["exchanges"][0]["answer_payload"]
        self.assertEqual(payload["summary"], "是否生成 Excel？")
        self.assertEqual(payload["interrupt"]["interrupt_id"], "interrupt-2")
        self.assertEqual(
            payload["structured_data_edits"][0]["rows"],
            [{"title": "用户修订后的译文"}],
        )
        self.assertEqual(payload["translation"]["proof"], "resumed-proof")

    def test_add_trace_notifies_sink_without_exposing_callback(self) -> None:
        events = []
        state = {"trace": [], "event_sink": events.append}

        result = add_trace(state, "classify_query", "已识别问题意图。")

        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["node"], "classify_query")
        self.assertNotIn("event_sink", events[0])
        self.assertEqual(result["trace"], events)

    def test_sink_failure_does_not_interrupt_graph(self) -> None:
        def fail(_item):
            raise RuntimeError("client disconnected")

        state = add_trace({"trace": [], "event_sink": fail}, "compose_answer", "已生成最终回答。")

        self.assertEqual(state["trace"][0]["status"], "completed")

    def test_final_answer_contains_trace_from_last_graph_node(self) -> None:
        state = {
            "answer": {"mode": "llm_direct", "summary": "ok", "trace": []},
            "trace": [{"node": "persist_memory", "status": "completed", "message": "done", "time": "now"}],
        }

        answer = KnowledgeSecurityGraph._final_answer(state)

        self.assertEqual(answer["trace"][0]["node"], "persist_memory")

    def test_stream_endpoint_sends_trace_before_result(self) -> None:
        with (
            patch.object(main_module, "knowledge_graph", FakeKnowledgeGraph()),
            patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
            TestClient(main_module.app) as client,
        ):
            response = client.post(
                "/api/ask/stream",
                json={
                    "question": "测试问题",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "session-1",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["content-type"].split(";")[0], "text/event-stream")
        self.assertEqual(response.text.count("event: trace"), 2)
        self.assertNotIn('"node": "supervisor_agent"', response.text)
        self.assertNotIn('"node": "conversation_agent"', response.text)
        self.assertNotIn('"node": "result_aggregator_agent"', response.text)
        self.assertEqual(response.text.count("event: content"), 1)
        self.assertLess(response.text.index("event: trace"), response.text.index("event: result"))
        self.assertLess(response.text.index("event: content"), response.text.index("event: result"))
        content_data = response.text.split("event: content\ndata: ", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(json.loads(content_data)["delta"], "测试回答")
        result_data = response.text.split("event: result\ndata: ", 1)[1].split("\n\n", 1)[0]
        result = json.loads(result_data)
        self.assertEqual(result["summary"], "测试回答")
        self.assertEqual(result["orchestration"]["architecture"], "direct-model")
        self.assertFalse(result["orchestration"]["agentic"])

    def test_stream_endpoint_publishes_only_final_accepted_content(self) -> None:
        with (
            patch.object(main_module, "knowledge_graph", FakeStreamingKnowledgeGraph()),
            patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
            TestClient(main_module.app) as client,
        ):
            response = client.post(
                "/api/ask/stream",
                json={
                    "question": "测试真实流",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "session-stream",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.text.count("event: content"), 1)
        self.assertEqual(response.text.count('"delta": "实时回答"'), 1)
        self.assertNotIn("UNVERIFIED ENGLISH", response.text)
        self.assertNotIn("BODY", response.text)

    def test_stream_endpoint_publishes_live_public_trace_without_final_replay(self) -> None:
        with (
            patch.object(main_module, "knowledge_graph", FakeLiveTraceKnowledgeGraph()),
            patch.object(main_module, "trial_manager", AlwaysUsableTrial()),
            TestClient(main_module.app) as client,
        ):
            response = client.post(
                "/api/ask/stream",
                json={
                    "question": "查询并解释这个漏洞",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "session-live-trace",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        trace_events = [
            json.loads(block.split("data: ", 1)[1])
            for block in response.text.split("\n\n")
            if block.startswith("event: trace\n")
        ]
        self.assertEqual([item["status"] for item in trace_events], ["running", "completed"])
        self.assertNotIn("reasoning", trace_events[0])
        self.assertNotIn("presentation", trace_events[0])
        self.assertEqual(trace_events[1]["presentation"]["kind"], "tool_call")
        self.assertEqual(trace_events[1]["presentation"]["input"]["api_key"], "[REDACTED]")
        self.assertNotIn("system_prompt", trace_events[1]["presentation"]["input"])
        self.assertNotIn("SECRET_", response.text)
        self.assertNotIn("live-secret-token", response.text)
        result_data = response.text.split("event: result\ndata: ", 1)[1].split("\n\n", 1)[0]
        result = json.loads(result_data)
        self.assertEqual(len(result["trace"]), 2)
        self.assertEqual([item["status"] for item in result["trace"]], ["running", "completed"])

    def test_answer_content_chunks_preserve_markdown_exactly(self) -> None:
        answer = "# 漏洞摘要\n\n第一段。第二段。\n\n```java\nreturn value;\n```"
        chunks = _assistant_content_chunks(answer, limit=24)

        self.assertGreater(len(chunks), 1)
        self.assertEqual("".join(chunks), answer)

    def test_system_prompt_uses_adaptive_security_answer_structure(self) -> None:
        prompt = system_prompt("zh-Hans")

        self.assertIn("不要仅凭关键词把意图固定到某个节点", prompt)
        self.assertIn("只保留与当前问题相关且有事实支撑的章节", prompt)
        self.assertIn("NVD、GitHub Advisory、OSV、CISA", prompt)
        self.assertIn("不要输出模型的私有推理过程", prompt)
        self.assertIn("禁止生成 PoC、利用载荷或攻击步骤", prompt)
        self.assertIn("不承担跨语言翻译", prompt)
        self.assertIn("模型不得执行该翻译", prompt)

    def test_llm_token_usage_normalizes_supported_provider_shapes(self) -> None:
        self.assertEqual(llm_token_usage({"data": {"usage": {"total_tokens": 4128}}}), 4128)
        self.assertEqual(
            llm_token_usage({"data": {"usage": {"input_tokens": 1200, "output_tokens": 328}}}),
            1528,
        )
        self.assertEqual(llm_token_usage({"data": {"usage": {"prompt_tokens": 7, "completion_tokens": 5}}}), 12)
        self.assertEqual(llm_token_usage({"data": {"usage": {"total_tokens": "invalid"}}}), 0)

    def test_task_follow_up_fallback_uses_persisted_finding_evidence(self) -> None:
        answer = build_task_scan_follow_up_answer(
            {
                "task_id": "task-1",
                "run_number": 2,
                "result_diff": {"counts": {"new": 0, "resolved": 0, "unchanged": 1, "changed": 0}},
                "findings": [
                    {
                        "title": "命令注入",
                        "severity": "HIGH",
                        "path": "app.py",
                        "line": 8,
                        "rule_id": "secflow.python.command-injection",
                        "message": "外部输入进入命令执行函数。",
                        "source": {"kind": "request", "line": 7},
                        "sink": {"kind": "os.system", "line": 8},
                        "taint_path": ["request.args", "os.system"],
                        "vulnerable_snippet": "os.system(command)",
                        "remediation": "改用参数数组调用，并对命令和值执行白名单校验。",
                        "fixed_snippet": "subprocess.run([allowed_command], check=True)",
                    }
                ],
            },
            "zh-Hans",
        )

        self.assertIn("任务 `task-1` 第 2 轮", answer)
        self.assertIn("未变化 1", answer)
        self.assertIn("`app.py:8`", answer)
        self.assertIn("os.system(command)", answer)
        self.assertIn("改用参数数组调用", answer)
        self.assertIn("subprocess.run", answer)
        self.assertIn("Source", answer)
        self.assertIn("使用相同项目、规则集和分析引擎重新扫描", answer)

    def test_task_follow_up_fallback_does_not_invent_missing_fix_code(self) -> None:
        answer = build_task_scan_follow_up_answer(
            {
                "task_id": "task-2",
                "findings": [{"title": "待复核风险", "severity": "MEDIUM", "path": "src/app.java", "line": 4}],
            },
            "zh-Hans",
        )

        self.assertIn("没有可核验修复代码", answer)
        self.assertNotIn("请检查 LLM API Key", answer)


if __name__ == "__main__":
    unittest.main()
