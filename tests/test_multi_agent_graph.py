from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from app.langgraph.multi_agent_graph import AssistantMultiAgentSupervisor
from app.agent.translation_policy import (
    host_localization_attestation_is_publishable,
    issue_host_localization_attestation,
    issue_stored_translation_attestation,
    partial_catalog_translation_is_publishable,
    partial_catalog_translation_status,
)
from app.memory import LongTermMemoryService


class FakeRuntimeGraph:
    def __init__(self, *, stored_translation: bool = False, host_localization: bool = False) -> None:
        self.calls: list[dict] = []
        self.stored_translation = stored_translation
        self.host_localization = host_localization

    def invoke(self, question, top_k, **kwargs):
        self.calls.append({"question": question, "top_k": top_k, **kwargs})
        answer = {
            "mode": "test",
            "summary": "专业 Agent 返回结果",
            "fields": {},
            "artifacts": [],
            "trace": [],
            "generated_at": "2026-07-31T08:00:00+08:00",
        }
        if self.stored_translation:
            answer["translation"] = issue_stored_translation_attestation(
                answer,
                target_language="zh-Hans",
                record_count=1,
                source="test-catalog",
            )
        elif self.host_localization:
            answer["mode"] = "component_vulnerability_catalog"
            answer["translation"] = issue_host_localization_attestation(
                answer,
                target_language="zh-Hans",
                source="component-catalog-preview",
            )
        return answer

    @staticmethod
    def graph_spec() -> dict:
        return {"name": "fake-knowledge", "nodes": [], "edges": []}


def planner(intent: str):
    def plan(_question, **_kwargs):
        return {
            "intent": intent,
            "reason": f"route to {intent}",
            "confidence": 0.99,
            "filters": {},
            "date_filter": {},
            "destination_hint": "unspecified",
        }

    return plan


class MultiAgentSupervisorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.supervisor = AssistantMultiAgentSupervisor()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.memory = LongTermMemoryService(Path(self.temp_dir.name) / "memory.json")
        self.memory.local_only = True

    def invoke(self, *, intent: str, graph=None, **kwargs):
        return self.supervisor.invoke(
            question=kwargs.pop("question", "执行测试任务"),
            top_k=5,
            user_id="user-a",
            session_id="session-a",
            response_language="zh-Hans",
            attachments=kwargs.pop("attachments", []),
            runtime_graph=graph or FakeRuntimeGraph(),
            memory=self.memory,
            planner=planner(intent),
            **kwargs,
        )

    def test_graph_spec_declares_real_agent_and_evaluation_boundaries(self) -> None:
        spec = self.supervisor.graph_spec(knowledge_graph=FakeRuntimeGraph())
        agents = {agent["id"]: agent for agent in spec["agents"]}

        self.assertEqual(spec["architecture"], "supervisor-specialists")
        self.assertIn("code_scan_agent", agents)
        self.assertIn("report_agent", agents)
        self.assertFalse(agents["code_scan_agent"]["can_mutate_global_analysis"])
        self.assertNotIn("license_scan_mcp", agents["code_scan_agent"]["tool_allowlist"])
        self.assertIn("license_scan_mcp", agents["sbom_agent"]["tool_allowlist"])
        self.assertTrue(spec["policies"]["frozen_evaluation_isolated"])

    def test_sbom_follow_up_uses_user_owned_snapshot_without_runtime_tool_call(self) -> None:
        self.memory.remember_sbom_operation(
            "user-a",
            "session-a",
            {
                "thread_id": "sbom-follow-up-regression",
                "project_name": "payments",
                "status": "interrupted",
                "component_count": 8,
                "components": [],
                "match_requested": True,
                "matching": {"coverage_status": "complete", "vulnerability_count": 0, "records": []},
                "license_analysis": {"coverage_status": "complete", "licenses": []},
                "interrupt": {
                    "kind": "sbom_excel_download_confirmation",
                    "question": "SBOM Excel 已生成，是否选择目录并下载？",
                },
                "artifacts": [],
            },
        )
        graph = FakeRuntimeGraph()
        answer = self.supervisor.invoke(
            question="存在哪些漏洞",
            top_k=5,
            user_id="user-a",
            session_id="session-a",
            response_language="zh-Hans",
            attachments=[],
            runtime_graph=graph,
            memory=self.memory,
            planner=lambda question, **kwargs: __import__(
                "app.agent.assistant_intent", fromlist=["heuristic_intent_plan"]
            ).heuristic_intent_plan(question, recent_sbom_operation=kwargs.get("recent_sbom_operation")),
        )

        self.assertEqual(answer["mode"], "sbom_result_follow_up")
        self.assertIn("共 8 个组件", answer["summary"])
        self.assertIn("当前命中 0 个漏洞", answer["summary"])
        self.assertIn("本次只读查询未确认或取消", answer["summary"])
        self.assertEqual(answer["orchestration"]["final_agent"], "sbom_agent")
        self.assertEqual(graph.calls, [])

    def test_sbom_snapshot_is_user_isolated_and_recovers_in_a_new_session(self) -> None:
        self.memory.remember_sbom_operation(
            "user-a",
            "old-session",
            {
                "thread_id": "sbom-new-session-regression",
                "project_name": "ledger",
                "component_count": 3,
                "match_requested": True,
                "matching": {"coverage_status": "complete", "vulnerability_count": 0, "records": []},
            },
        )

        self.assertEqual(
            self.memory.latest_sbom_operation("user-a", session_id="new-session")["projectName"],
            "ledger",
        )
        self.assertIsNone(self.memory.latest_sbom_operation("user-b", session_id="new-session"))

    def test_component_request_has_explicit_supervisor_handoffs(self) -> None:
        graph = FakeRuntimeGraph()
        answer = self.invoke(intent="component_vulnerability_query", graph=graph)

        orchestration = answer["orchestration"]
        self.assertEqual(orchestration["final_agent"], "component_agent")
        self.assertEqual(
            [item["target_agent"] for item in orchestration["handoffs"]],
            ["component_agent", "result_aggregator_agent", "translation_agent"],
        )
        self.assertIn("translation_agent", orchestration["visited_agents"])
        self.assertEqual(graph.calls[0]["intent_plan"]["intent"], "component_vulnerability_query")

    def test_stored_catalog_translation_bypasses_outer_translation_agent(self) -> None:
        graph = FakeRuntimeGraph(stored_translation=True)
        answer = self.invoke(intent="vulnerability_lookup", graph=graph)

        orchestration = answer["orchestration"]
        self.assertNotIn("translation_agent", orchestration["visited_agents"])
        self.assertEqual(
            [item["target_agent"] for item in orchestration["handoffs"]],
            ["intelligence_agent", "result_aggregator_agent"],
        )
        self.assertEqual(answer["translation"]["translation_status"], "stored")

    def test_host_localized_catalog_preview_bypasses_outer_translation_agent(self) -> None:
        graph = FakeRuntimeGraph(host_localization=True)
        answer = self.invoke(intent="component_vulnerability_catalog", graph=graph)

        orchestration = answer["orchestration"]
        self.assertNotIn("translation_agent", orchestration["visited_agents"])
        self.assertEqual(
            [item["target_agent"] for item in orchestration["handoffs"]],
            ["component_agent", "result_aggregator_agent"],
        )
        self.assertEqual(answer["translation"]["translation_status"], "host-localized")

    def test_sanitized_partial_catalog_bypasses_outer_translation_agent(self) -> None:
        records = [
            {
                "id": "CVE-2026-8101",
                "severity": "HIGH",
                "title": "已翻译漏洞标题",
                "summary": "已翻译漏洞描述。",
                "content_language": "zh-Hans",
                "translation_status": "translated",
            },
            {
                "id": "CVE-2026-8102",
                "severity": "MEDIUM",
                "title": "中文标题暂不可用",
                "summary": "中文翻译暂不可用，请稍后重试。",
                "content_language": "zh-Hans",
                "translation_status": "pending",
            },
        ]
        audit = {
            "status": "partial",
            "translation_status": "fallback",
            "target_language": "zh-Hans",
            "candidate_fields": 4,
            "translated_fields": 2,
            "unresolved_fields": 2,
            "offline_contract_valid": True,
            "runtime_contract_valid": True,
            "transport": "stdio",
            "offline": True,
            "network_used": False,
            "requires_api_key": False,
            "model_used": False,
            "provider_calls": 0,
            "billable_tokens": 0,
            "token_usage": 0,
        }
        answer = {
            "mode": "component_vulnerability_catalog",
            "summary": "组件漏洞目录已完成部分离线翻译。",
            "fields": {"漏洞数量": "2"},
            "records": records,
            "trace": [],
        }
        answer["translation"] = partial_catalog_translation_status(
            audit,
            target_language="zh-Hans",
            record_count=2,
            ready_records=1,
        )
        supervisor = AssistantMultiAgentSupervisor.__new__(AssistantMultiAgentSupervisor)
        supervisor._result_aggregator_agent = Mock()
        supervisor._result_aggregator_agent.aggregate.side_effect = lambda value: dict(value)
        state = {
            "answer": answer,
            "response_language": "zh-Hans",
            "current_agent": "component_agent",
            "visited_agents": ["component_agent"],
            "handoffs": [],
            "trace": [],
        }

        result = supervisor._result_aggregator(state)

        aggregated = result["answer"]
        self.assertTrue(partial_catalog_translation_is_publishable(aggregated, "zh-Hans"))
        self.assertTrue(AssistantMultiAgentSupervisor._answer_uses_stored_translation(result))
        self.assertNotIn(
            "translation_agent",
            [item["target_agent"] for item in result["handoffs"]],
        )
        self.assertEqual(len(aggregated["records"]), 2)
        self.assertEqual(aggregated["translation"]["publication_status"], "partial")

    def test_user_table_edits_do_not_invalidate_the_original_translation_proof(self) -> None:
        answer = {
            "mode": "component_vulnerability_catalog",
            "summary": "已返回翻译后的漏洞记录。",
            "tables": [{"id": "translated-findings", "rows": [{"id": "CVE-1", "title": "原译文"}]}],
        }
        answer["translation"] = issue_host_localization_attestation(
            answer,
            target_language="zh-Hans",
            source="component-catalog-preview",
        )
        answer["session_id"] = "translated-session"
        answer["exchange_id"] = "msg-42"
        answer["structured_data_edits"] = [{
            "id": "translated-findings",
            "rows": [{"id": "CVE-1", "title": "用户修订译文"}],
        }]

        self.assertTrue(host_localization_attestation_is_publishable(answer, "zh-Hans"))

    def test_report_agent_forces_report_subgraph_intent(self) -> None:
        graph = FakeRuntimeGraph()
        answer = self.invoke(
            intent="llm_direct",
            graph=graph,
            question="请下载刚才生成的 PDF 报告",
        )

        self.assertEqual(answer["orchestration"]["final_agent"], "report_agent")
        self.assertEqual(graph.calls[0]["intent_plan"]["intent"], "report_operation")

    def test_explicit_report_request_skips_external_intent_planner(self) -> None:
        graph = FakeRuntimeGraph()
        planner = Mock(side_effect=AssertionError("report routing must not wait for the external planner"))

        answer = self.supervisor.invoke(
            question="基于已完成扫描生成正式 PDF 报告",
            top_k=5,
            user_id="user-a",
            session_id="session-a",
            response_language="zh-Hans",
            attachments=[],
            runtime_graph=graph,
            memory=self.memory,
            planner=planner,
        )

        planner.assert_not_called()
        self.assertEqual(answer["orchestration"]["final_agent"], "report_agent")
        self.assertEqual(graph.calls[0]["intent_plan"]["intent"], "report_operation")
        self.assertEqual(graph.calls[0]["intent_plan"]["planner"], "deterministic-report-route")

    def test_scan_intent_wins_when_report_is_only_a_post_scan_step(self) -> None:
        task_service = Mock()
        task_service.create.return_value = {
            "id": "task-scan-before-report",
            "workspace_name": "payments",
            "status": "queued",
        }

        answer = self.invoke(
            intent="project_scan",
            question="完整扫描代码和跨方法污点，完成后等我确认是否生成报告",
            workspace_path=self.temp_dir.name,
            task_service=task_service,
            allow_task_creation=True,
        )

        self.assertEqual(answer["orchestration"]["final_agent"], "code_scan_agent")
        self.assertEqual(answer["agent_task"]["id"], "task-scan-before-report")
        task_service.create.assert_called_once()

    def test_standalone_scan_cannot_create_local_task(self) -> None:
        graph = FakeRuntimeGraph()
        task_service = Mock()
        answer = self.invoke(
            intent="project_scan",
            graph=graph,
            task_service=task_service,
            allow_workspace_recovery=False,
            allow_task_creation=False,
        )

        self.assertEqual(answer["orchestration"]["final_agent"], "code_scan_agent")
        task_service.create.assert_not_called()
        self.assertEqual(len(graph.calls), 1)

    def test_general_question_with_workspace_does_not_start_scan(self) -> None:
        graph = FakeRuntimeGraph()
        task_service = Mock()
        answer = self.invoke(
            intent="llm_direct",
            graph=graph,
            workspace_path=self.temp_dir.name,
            task_service=task_service,
            allow_task_creation=True,
        )

        self.assertEqual(answer["orchestration"]["final_agent"], "conversation_agent")
        task_service.create.assert_not_called()
        task_service.rescan.assert_not_called()

    def test_rescan_handoff_uses_baseline_task(self) -> None:
        task_service = Mock()
        task_service.rescan.return_value = {
            "id": "task-rescan",
            "workspace_name": "payments",
            "status": "queued",
        }
        active_task = {
            "id": "task-baseline",
            "workspace_path": self.temp_dir.name,
            "workspace_name": "payments",
            "status": "completed",
        }
        answer = self.invoke(
            intent="project_rescan",
            workspace_path=self.temp_dir.name,
            active_task=active_task,
            task_service=task_service,
            allow_task_creation=True,
        )

        self.assertEqual(answer["agent_task"]["id"], "task-rescan")
        task_service.rescan.assert_called_once_with(
            "task-baseline",
            objective="执行测试任务",
            user_id="user-a",
            session_id="session-a",
        )
        task_service.create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
