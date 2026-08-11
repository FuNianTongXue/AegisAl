from __future__ import annotations

import json
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from app import assistant_app
from app.agent.assistant_intent import heuristic_intent_plan
from app.agent.assistant_service import (
    invoke_assistant_question,
    invoke_assistant_task_action,
    invoke_assistant_workspace_action,
)
from app.api.routes import assistant as assistant_routes
from app.models import AskRequest, AssistantTaskActionRequest, AssistantWorkspaceActionRequest
from app.langgraph.assistant_graph import KnowledgeSecurityGraph


class FakeKnowledgeGraph:
    @staticmethod
    def graph_spec() -> dict:
        return {"name": "standalone-test", "nodes": [], "edges": []}

    def invoke(self, _question, _top_k, **kwargs):
        sink = kwargs.get("event_sink")
        trace = {
            "node": "compose_answer",
            "status": "completed",
            "message": "已生成最终回答。",
            "time": "2026-07-29T10:00:00+00:00",
        }
        if sink is not None:
            sink(trace)
        return {
            "mode": "llm_direct",
            "summary": "独立智能问答响应",
            "fields": {},
            "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "confidence": 1.0,
            "trace": [trace],
            "generated_at": "2026-07-29T10:00:00+00:00",
        }


class StandaloneAssistantModuleTests(unittest.TestCase):
    def test_pretranslated_catalog_answer_routes_directly_to_memory(self) -> None:
        route = KnowledgeSecurityGraph._route_after_compose(
            {
                "intent": "vulnerability_lookup",
                "response_language": "zh-Hans",
                "records": [{"id": "CVE-2026-7788"}],
                "catalog_translation_ready": True,
                "attachments": [],
            }
        )

        self.assertEqual(route, "persist_memory")

    def test_plain_question_bypasses_multi_agent_supervisor(self) -> None:
        graph = FakeKnowledgeGraph()
        with (
            patch(
                "app.agent.assistant_service.plan_assistant_intent",
                return_value={"intent": "llm_direct", "reason": "普通问答", "confidence": 1.0},
            ),
            patch(
                "app.langgraph.multi_agent_graph.assistant_multi_agent_supervisor.invoke",
                side_effect=AssertionError("plain questions must not enter the multi-agent supervisor"),
            ),
        ):
            result = invoke_assistant_question(
                AskRequest(
                    question="今天是几月几号",
                    user_id="tester",
                    session_id="plain-question",
                ),
                graph=graph,
            )

        self.assertEqual(result["summary"], "独立智能问答响应")
        self.assertEqual(result["orchestration"]["architecture"], "direct-model")
        self.assertFalse(result["orchestration"]["agentic"])
        self.assertEqual(result["orchestration"]["visited_agents"], [])

    def test_agent_intent_still_uses_multi_agent_supervisor(self) -> None:
        supervisor_answer = {
            "mode": "project_scan",
            "summary": "已交给扫描 Agent",
            "orchestration": {"architecture": "supervisor-specialists", "agentic": True},
        }
        with (
            patch(
                "app.agent.assistant_service.plan_assistant_intent",
                return_value={"intent": "project_scan", "reason": "执行项目扫描", "confidence": 1.0},
            ),
            patch(
                "app.langgraph.multi_agent_graph.assistant_multi_agent_supervisor.invoke",
                return_value=supervisor_answer,
            ) as invoke,
        ):
            result = invoke_assistant_question(
                AskRequest(question="扫描这个项目", user_id="tester", session_id="agent-question"),
                graph=FakeKnowledgeGraph(),
                allow_workspace_recovery=True,
            )

        self.assertTrue(result["orchestration"]["agentic"])
        self.assertEqual(invoke.call_args.kwargs["intent_plan"]["intent"], "project_scan")

    def test_catalog_quick_action_skips_the_planner_model_and_keeps_explicit_risk_filters(self) -> None:
        supervisor_answer = {
            "mode": "component_vulnerability_catalog",
            "summary": "已返回本月高风险组件漏洞。",
            "orchestration": {"architecture": "supervisor-specialists", "agentic": True},
        }
        with (
            patch(
                "app.agent.assistant_service.plan_assistant_intent",
                side_effect=AssertionError("a fixed quick action must not call the planner model"),
            ),
            patch(
                "app.langgraph.multi_agent_graph.assistant_multi_agent_supervisor.invoke",
                return_value=supervisor_answer,
            ) as invoke,
        ):
            result = invoke_assistant_question(
                AskRequest(
                    question="查询本月严重和高危组件漏洞",
                    intent_hint="component_vulnerability_catalog",
                    user_id="tester",
                    session_id="catalog-quick-action",
                ),
                graph=FakeKnowledgeGraph(),
            )

        plan = invoke.call_args.kwargs["intent_plan"]
        self.assertEqual(result["mode"], "component_vulnerability_catalog")
        self.assertEqual(plan["intent"], "component_vulnerability_catalog")
        self.assertEqual(plan["planner"], "deterministic-quick-action")
        self.assertEqual(plan["filters"]["severities"], ["CRITICAL", "HIGH"])
        self.assertEqual(plan["date_filter"]["kind"], "current_month")

    def test_information_recent_high_lookup_uses_only_the_local_translated_catalog(self) -> None:
        catalog_result = {
            "total": 12,
            "records": [
                {
                    "id": "CVE-2026-9999",
                    "severity": "HIGH",
                    "title": "已翻译的高危漏洞",
                    "components": [{"name": "demo"}],
                }
            ],
            "source_status": [],
        }
        with (
            patch(
                "app.agent.assistant_service.plan_assistant_intent",
                side_effect=AssertionError("信息中心快速查询不得调用规划模型"),
            ),
            patch(
                "app.agent.assistant_service.intelligence_service.query_component_vulnerability_catalog",
                return_value=catalog_result,
            ) as query,
        ):
            result = invoke_assistant_question(
                AskRequest(
                    question="查询近期高危漏洞",
                    intent_hint="recent_high_vulnerability_lookup",
                    top_k=5,
                    user_id="tester",
                    session_id="information-fast-query",
                ),
                graph=FakeKnowledgeGraph(),
            )

        self.assertEqual(result["mode"], "recent_high_vulnerability_lookup")
        self.assertEqual(result["orchestration"]["architecture"], "deterministic-local-query")
        self.assertIn("已翻译的高危漏洞", result["summary"])
        self.assertEqual(query.call_args.kwargs["severities"], ["HIGH"])
        self.assertFalse(query.call_args.kwargs["include_realtime"])
        self.assertEqual(query.call_args.kwargs["limit"], 5)

    def test_recent_high_free_text_uses_deterministic_catalog_planning(self) -> None:
        plan = heuristic_intent_plan("查询近期高危漏洞")

        self.assertEqual(plan["intent"], "component_vulnerability_catalog")
        self.assertEqual(plan["time_scope"], {"kind": "recent_days", "days": 7})
        self.assertEqual(plan["filters"]["severities"], ["HIGH"])

    def test_scan_fallback_understands_natural_project_security_review_phrasings(self) -> None:
        questions = [
            "麻烦把这个项目从依赖到源码完整检查一遍，尤其确认用户输入能否进入命令执行。",
            "看看这个仓库有没有安全风险，并分析依赖和数据流。",
            "请审查当前代码库的外部输入是否会流向危险执行点。",
        ]

        for question in questions:
            with self.subTest(question=question):
                plan = heuristic_intent_plan(question, workspace_available=True)
                self.assertEqual(plan["intent"], "project_scan")

        architecture = heuristic_intent_plan("介绍一下这个项目的架构", workspace_available=True)
        self.assertEqual(architecture["intent"], "llm_direct")

        scan_then_report = heuristic_intent_plan(
            "请完整扫描代码和跨方法污点，完成后询问我是否生成报告",
            workspace_available=True,
        )
        self.assertEqual(scan_then_report["intent"], "project_scan")

        completed_scan_report = heuristic_intent_plan(
            "基于已完成扫描事实生成 PDF 报告",
            workspace_available=True,
        )
        self.assertEqual(completed_scan_report["intent"], "llm_direct")

    def test_attached_project_vulnerability_question_always_routes_to_scan(self) -> None:
        question = "这个项目存在哪些漏洞"
        fallback = heuristic_intent_plan(question, workspace_available=True)

        self.assertEqual(fallback["intent"], "project_scan")
        with patch(
            "app.agent.assistant_intent.active_model_from_env",
            side_effect=AssertionError("deterministic project scan must not wait for an LLM"),
        ):
            from app.agent.assistant_intent import plan_assistant_intent

            plan = plan_assistant_intent(question, workspace_available=True)

        self.assertEqual(plan["intent"], "project_scan")
        self.assertEqual(plan["planner"], "deterministic-workspace-security-route")

    def test_explicit_sbom_scan_type_directive_never_routes_to_code_scan(self) -> None:
        objectives = [
            "请仅执行SBOM扫描和许可证识别（不包含代码漏洞扫描）：扫描这个项目",
            "请仅执行SBOM扫描和许可证识别（不包含代码漏洞扫描）：检查项目安全",
        ]
        for objective in objectives:
            with self.subTest(objective=objective):
                plan = heuristic_intent_plan(objective, workspace_available=True)
                self.assertEqual(plan["intent"], "project_sbom_export")
                self.assertEqual(plan["scan_type_directive"], "sbom")
                with patch(
                    "app.agent.assistant_intent.active_model_from_env",
                    side_effect=AssertionError("explicit SBOM scan type must not wait for an LLM"),
                ):
                    from app.agent.assistant_intent import plan_assistant_intent

                    planned = plan_assistant_intent(objective, workspace_available=True)

                self.assertEqual(planned["intent"], "project_sbom_export")
                self.assertEqual(planned["planner"], "deterministic-workspace-sbom-route")

    def test_explicit_code_and_full_scan_type_directives_stay_on_code_scan(self) -> None:
        cases = {
            "请仅执行代码安全扫描（不包含SBOM）：扫描这个项目": "code",
            "请执行完整安全扫描（代码安全扫描 + SBOM生成 + 许可证识别）：扫描这个项目": "full",
        }
        for objective, directive in cases.items():
            with self.subTest(objective=objective):
                plan = heuristic_intent_plan(objective, workspace_available=True)
                self.assertEqual(plan["intent"], "project_scan")
                self.assertEqual(plan["scan_type_directive"], directive)

    def test_sbom_keyword_adjacent_to_cjk_text_is_still_detected(self) -> None:
        plan = heuristic_intent_plan("帮我执行SBOM扫描并导出依赖清单", workspace_available=True)

        self.assertEqual(plan["intent"], "project_sbom_export")

    def test_workspace_vulnerability_question_hands_off_to_code_scan_agent(self) -> None:
        task_service = Mock()
        task_service.create.return_value = {
            "id": "task-kafka-scan",
            "objective": "这个项目存在哪些漏洞",
            "workspace_path": "/tmp/kafka",
            "workspace_name": "kafka",
            "status": "queued",
        }
        with TemporaryDirectory() as workspace:
            result = invoke_assistant_workspace_action(
                AssistantWorkspaceActionRequest(
                    objective="这个项目存在哪些漏洞",
                    workspace_path=workspace,
                    user_id="tester",
                    session_id="session-kafka",
                ),
                graph=FakeKnowledgeGraph(),
                task_service=task_service,
            )

        self.assertEqual(result["kind"], "agent_task")
        self.assertEqual(result["intent_plan"]["intent"], "project_scan")
        self.assertEqual(result["orchestration"]["final_agent"], "code_scan_agent")
        task_service.create.assert_called_once_with(
            objective="这个项目存在哪些漏洞",
            workspace_path=workspace,
            user_id="tester",
            session_id="session-kafka",
        )

    def test_scan_fallback_understands_natural_rescan_comparison_phrasings(self) -> None:
        active_task = {"available": True, "id": "task-baseline", "status": "completed"}
        questions = [
            "再帮我完整检查一次这个项目，并和上一次扫描结果比较一下",
            "重新审查这个仓库，看看和之前结果有什么差异",
            "Please compare this project with the previous scan",
        ]

        for question in questions:
            with self.subTest(question=question):
                plan = heuristic_intent_plan(
                    question,
                    workspace_available=True,
                    active_task=active_task,
                )
                self.assertEqual(plan["intent"], "project_rescan")

        first_scan = heuristic_intent_plan(
            "再帮我完整检查一次这个项目",
            workspace_available=True,
            active_task=None,
        )
        self.assertEqual(first_scan["intent"], "project_scan")

    def test_task_report_request_skips_planner_and_passes_owned_scan_task(self) -> None:
        planner = Mock(side_effect=AssertionError("explicit report requests must not wait for the LLM planner"))
        task = {
            "id": "task-report-1",
            "workspace_path": "/tmp/demo",
            "workspace_name": "demo",
            "user_id": "tester",
            "status": "completed",
            "result": {"total_findings": 1},
        }
        supervisor_answer = {
            "mode": "report_operation",
            "summary": "是否生成报告？",
            "interrupt": {"kind": "report_generation_confirmation"},
            "orchestration": {},
        }
        with patch(
            "app.langgraph.multi_agent_graph.assistant_multi_agent_supervisor.invoke",
            return_value=supervisor_answer,
        ) as invoke:
            result = invoke_assistant_task_action(
                AssistantTaskActionRequest(
                    objective="基于本次扫描事实生成正式报告",
                    user_id="tester",
                    session_id="session-report",
                    response_language="zh-Hans",
                ),
                task=task,
                graph=object(),
                task_service=object(),
                planner=planner,
            )

        planner.assert_not_called()
        self.assertEqual(result["answer"]["interrupt"]["kind"], "report_generation_confirmation")
        self.assertEqual(invoke.call_args.kwargs["intent_plan"]["intent"], "report_operation")
        self.assertEqual(invoke.call_args.kwargs["task_context"]["report_task"]["id"], task["id"])

    def test_standalone_app_exposes_only_assistant_contract(self) -> None:
        paths = set(assistant_app.app.openapi()["paths"])

        self.assertIn("/api/assistant/questions", paths)
        self.assertIn("/api/assistant/questions/stream", paths)
        self.assertIn("/api/assistant/interrupts/resume", paths)
        self.assertIn("/api/assistant/conversations", paths)
        self.assertNotIn("/api/agent/tasks", paths)
        self.assertNotIn("/api/subscriptions", paths)

    def test_question_and_graph_use_the_standalone_router(self) -> None:
        with patch.object(assistant_routes, "knowledge_graph", FakeKnowledgeGraph()), TestClient(
            assistant_app.app
        ) as client:
            graph = client.get("/api/assistant/graph")
            response = client.post(
                "/api/assistant/questions",
                json={
                    "question": "介绍一下当前能力",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "standalone-session",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(graph.status_code, 200, graph.text)
        graph_data = graph.json()["data"]
        self.assertEqual(graph_data["name"], "SecFlow Multi-Agent Supervisor")
        self.assertEqual(graph_data["architecture"], "supervisor-specialists")
        self.assertEqual(graph_data["subgraphs"][0]["name"], "standalone-test")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["summary"], "独立智能问答响应")
        self.assertEqual(
            response.json()["data"]["orchestration"]["schema_version"],
            "secflow.direct-model/v1",
        )
        self.assertFalse(response.json()["data"]["orchestration"]["agentic"])

    def test_stream_preserves_trace_content_and_result_order(self) -> None:
        with patch.object(assistant_routes, "knowledge_graph", FakeKnowledgeGraph()), TestClient(
            assistant_app.app
        ) as client:
            response = client.post(
                "/api/assistant/questions/stream",
                json={
                    "question": "流式回答",
                    "top_k": 5,
                    "user_id": "tester",
                    "session_id": "standalone-stream",
                    "response_language": "zh-Hans",
                    "attachments": [],
                },
            )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertLess(response.text.index("event: trace"), response.text.index("event: content"))
        self.assertLess(response.text.index("event: content"), response.text.index("event: result"))
        content = response.text.split("event: content\ndata: ", 1)[1].split("\n\n", 1)[0]
        self.assertEqual(json.loads(content)["delta"], "独立智能问答响应")


if __name__ == "__main__":
    unittest.main()
