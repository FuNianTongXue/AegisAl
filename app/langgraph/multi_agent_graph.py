from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - packaged fallback
    END = "__end__"
    StateGraph = None

from app.agent.assistant_intent import heuristic_intent_plan
from app.agent.contracts import AgentExecution, AgentHandoff, AgentManifest
from app.agent.specialist_agents import (
    AssistantAgentContext,
    CodeScanAgent,
    GraphSpecialistAgent,
    ProjectContextAgent,
    SBOMAgent,
)
from app.agent.translation_agent import translation_agent
from app.dependencies import BUILD_MANIFEST_SOURCE_TYPES, CODE_EXTENSIONS, attachment_kind
from app.langgraph.report_graph import looks_like_report_request
from app.privacy import public_answer_payload, sanitize_public_text
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


class MultiAgentState(TypedDict, total=False):
    question: str
    top_k: int
    user_id: str
    session_id: str
    response_language: str
    attachments: list[dict[str, Any]]
    workspace_path: str
    task_context: dict[str, Any]
    active_task: dict[str, Any]
    intent_plan: dict[str, Any]
    sbom_context: dict[str, Any]
    target_agent: str
    current_agent: str
    visited_agents: list[str]
    handoffs: list[dict[str, str]]
    trace: list[dict[str, Any]]
    answer: dict[str, Any]
    runtime_graph: Any
    memory: Any
    task_service: Any
    planner: Any
    event_sink: Any
    content_sink: Any
    allow_workspace_recovery: bool
    allow_task_creation: bool


SUPERVISOR_MANIFEST = AgentManifest(
    agent_id="supervisor_agent",
    label="Supervisor Agent",
    description="理解用户目标、制定能力计划并向最小权限专业 Agent 交接。",
    capabilities=("semantic_planning", "agent_handoff", "termination"),
    tool_allowlist=("plan_assistant_intent", "handoff"),
)
PROJECT_CONTEXT_MANIFEST = AgentManifest(
    agent_id="project_context_agent",
    label="Project Context Agent",
    description="恢复并验证当前用户授权的本机源码工作区。",
    capabilities=("workspace_recovery", "project_memory"),
    tool_allowlist=("encrypted_project_links", "agent_task_store"),
)
CODE_SCAN_MANIFEST = AgentManifest(
    agent_id="code_scan_agent",
    label="Code Scan Agent",
    description="创建完整项目扫描任务并调用扫描任务图和 Code Scan MCP。",
    capabilities=("project_scan", "project_rescan", "scan_result_follow_up"),
    tool_allowlist=("task_agent_graph", "code_scan_sse_mcp"),
    can_start_tasks=True,
)
COMPONENT_MANIFEST = AgentManifest(
    agent_id="component_agent",
    label="Component Intelligence Agent",
    description="核验单组件版本或生成时间范围组件漏洞目录。",
    capabilities=("component_vulnerability_query", "component_vulnerability_catalog"),
    tool_allowlist=("component_detail_mcp", "component_excel_mcp", "d3_sankey_mcp"),
)
SBOM_MANIFEST = AgentManifest(
    agent_id="sbom_agent",
    label="SBOM Agent",
    description="生成项目 SBOM、识别许可证并匹配依赖组件漏洞。",
    capabilities=("project_sbom_export", "license_inventory"),
    tool_allowlist=("sbom_graph", "license_scan_mcp", "sbom_excel_mcp"),
)
INTELLIGENCE_MANIFEST = AgentManifest(
    agent_id="intelligence_agent",
    label="Vulnerability Intelligence Agent",
    description="查询并整理漏洞事实、年份范围和安全知识。",
    capabilities=("vulnerability_lookup", "vulnerability_year_lookup", "security_knowledge"),
    tool_allowlist=("intelligence_query", "knowledge_graph"),
)
REPORT_MANIFEST = AgentManifest(
    agent_id="report_agent",
    label="Report Agent",
    description="从固定扫描 JSON 生成人工确认的多格式报告。",
    capabilities=("report_generate", "report_download"),
    tool_allowlist=("report_graph", "chart_mcp", "mermaid_mcp", "markdown_mcp", "word_mcp", "pdf_mcp"),
)
CONVERSATION_MANIFEST = AgentManifest(
    agent_id="conversation_agent",
    label="Security Conversation Agent",
    description="处理无需执行项目工具的安全问答、澄清和身份说明。",
    capabilities=("llm_direct", "identity", "clarification"),
    tool_allowlist=("configured_llm", "long_term_memory"),
)
RESULT_AGGREGATOR_MANIFEST = AgentManifest(
    agent_id="result_aggregator_agent",
    label="Result Aggregator Agent",
    description="合并专业 Agent 结果、审计交接并生成统一客户响应。",
    capabilities=("result_merge", "audit_finalize"),
    tool_allowlist=("public_payload_filter",),
)
TRANSLATION_MANIFEST = AgentManifest(
    agent_id="translation_agent",
    label="Translation Agent",
    description="将专业 Agent 的结构化 JSON 交给翻译 MCP，生成客户端目标语言回复。",
    capabilities=("json_translation", "response_localization"),
    tool_allowlist=("translation_mcp",),
)

AGENT_MANIFESTS = (
    SUPERVISOR_MANIFEST,
    PROJECT_CONTEXT_MANIFEST,
    CODE_SCAN_MANIFEST,
    COMPONENT_MANIFEST,
    SBOM_MANIFEST,
    INTELLIGENCE_MANIFEST,
    REPORT_MANIFEST,
    CONVERSATION_MANIFEST,
    RESULT_AGGREGATOR_MANIFEST,
    TRANSLATION_MANIFEST,
)


class AssistantMultiAgentSupervisor:
    """Supervisor-and-specialists orchestration over existing capability subgraphs."""

    def __init__(self) -> None:
        self._project_context_agent = ProjectContextAgent(PROJECT_CONTEXT_MANIFEST)
        self._agents = {
            "code_scan_agent": CodeScanAgent(CODE_SCAN_MANIFEST),
            "component_agent": GraphSpecialistAgent(COMPONENT_MANIFEST),
            "sbom_agent": SBOMAgent(SBOM_MANIFEST),
            "intelligence_agent": GraphSpecialistAgent(INTELLIGENCE_MANIFEST),
            "report_agent": GraphSpecialistAgent(REPORT_MANIFEST, force_intent="report_operation"),
            "conversation_agent": GraphSpecialistAgent(CONVERSATION_MANIFEST),
        }
        self._graph = self._build_graph()

    def invoke(
        self,
        *,
        question: str,
        top_k: int,
        user_id: str,
        session_id: str,
        response_language: str,
        attachments: list[dict[str, Any]],
        runtime_graph: Any,
        memory: Any,
        planner: Callable[..., dict[str, Any]],
        event_sink: Any = None,
        content_sink: Any = None,
        workspace_path: str = "",
        task_context: dict[str, Any] | None = None,
        active_task: dict[str, Any] | None = None,
        intent_plan: dict[str, Any] | None = None,
        task_service: Any = None,
        allow_workspace_recovery: bool = False,
        allow_task_creation: bool = False,
    ) -> dict[str, Any]:
        state: MultiAgentState = {
            "question": question,
            "top_k": top_k,
            "user_id": user_id or "default",
            "session_id": session_id or "default",
            "response_language": response_language or "zh-Hans",
            "attachments": list(attachments),
            "workspace_path": str(workspace_path or ""),
            "task_context": dict(task_context or {}),
            "active_task": dict(active_task or {}),
            "intent_plan": dict(intent_plan or {}),
            "sbom_context": {},
            "target_agent": "",
            "current_agent": "",
            "visited_agents": [],
            "handoffs": [],
            "trace": [],
            "answer": {},
            "runtime_graph": runtime_graph,
            "memory": memory,
            "task_service": task_service,
            "planner": planner,
            "event_sink": event_sink,
            "content_sink": content_sink,
            "allow_workspace_recovery": bool(allow_workspace_recovery),
            "allow_task_creation": bool(allow_task_creation),
        }
        if self._graph is not None:
            final = self._graph.invoke(state)
        else:  # pragma: no cover - dependency fallback for packaged diagnostics.
            final = self._invoke_fallback(state)
        return public_answer_payload(dict(final.get("answer") or {}))

    def graph_spec(self, *, knowledge_graph: Any = None, task_graph: Any = None) -> dict[str, Any]:
        subgraphs: list[dict[str, Any]] = []
        if knowledge_graph is not None:
            subgraphs.append(knowledge_graph.graph_spec())
        if task_graph is not None:
            subgraphs.append(task_graph.graph_spec())
        return {
            "name": "SecFlow Multi-Agent Supervisor",
            "architecture": "supervisor-specialists",
            "schema_version": "secflow.multi-agent/v1",
            "agents": [manifest.as_dict() for manifest in AGENT_MANIFESTS],
            "nodes": [
                {"id": manifest.agent_id, "label": manifest.label, "type": "agent"}
                for manifest in AGENT_MANIFESTS
            ]
            + [{"id": "final_output", "label": "已本地化输出", "type": "output"}],
            "edges": [
                {"source": "supervisor_agent", "target": target, "label": "语义交接"}
                for target in (
                    "project_context_agent",
                    "code_scan_agent",
                    "component_agent",
                    "sbom_agent",
                    "intelligence_agent",
                    "report_agent",
                    "conversation_agent",
                )
            ]
            + [
                {"source": "project_context_agent", "target": "code_scan_agent", "label": "源码已验证"},
                {"source": "project_context_agent", "target": "sbom_agent", "label": "源码已验证"},
            ]
            + [
                {"source": target, "target": "result_aggregator_agent", "label": "结构化结果"}
                for target in (
                    "project_context_agent",
                    "code_scan_agent",
                    "component_agent",
                    "sbom_agent",
                    "intelligence_agent",
                    "report_agent",
                    "conversation_agent",
                )
            ]
            + [
                {"source": "result_aggregator_agent", "target": "translation_agent", "label": "统一 JSON 翻译"},
                {"source": "result_aggregator_agent", "target": "final_output", "label": "复用情报库入库译文"},
            ],
            "subgraphs": subgraphs,
            "policies": {
                "online_global_rule_mutation": False,
                "project_overlay_scope": "task-only",
                "frozen_evaluation_isolated": True,
                "maximum_handoffs": 3,
            },
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(MultiAgentState)
        graph.add_node("supervisor_agent", self._supervisor)
        graph.add_node("project_context_agent", self._project_context)
        for agent_id in self._agents:
            graph.add_node(agent_id, self._specialist_node(agent_id))
        graph.add_node("result_aggregator_agent", self._result_aggregator)
        graph.add_node("translation_agent", self._translation)
        graph.set_entry_point("supervisor_agent")
        graph.add_conditional_edges(
            "supervisor_agent",
            lambda state: state["target_agent"],
            {
                "project_context_agent": "project_context_agent",
                **{agent_id: agent_id for agent_id in self._agents},
            },
        )
        graph.add_conditional_edges(
            "project_context_agent",
            lambda state: state["target_agent"],
            {
                "code_scan_agent": "code_scan_agent",
                "sbom_agent": "sbom_agent",
                "result_aggregator_agent": "result_aggregator_agent",
            },
        )
        for agent_id in self._agents:
            graph.add_edge(agent_id, "result_aggregator_agent")
        graph.add_conditional_edges(
            "result_aggregator_agent",
            lambda state: "end" if self._answer_uses_stored_translation(state) else "translation_agent",
            {"translation_agent": "translation_agent", "end": END},
        )
        graph.add_edge("translation_agent", END)
        return graph.compile()

    def _supervisor(self, state: MultiAgentState) -> MultiAgentState:
        try:
            state["sbom_context"] = dict(
                state["memory"].latest_sbom_operation(
                    state["user_id"],
                    session_id=state["session_id"],
                )
                or {}
            )
        except Exception:  # noqa: BLE001 - non-SBOM routes remain available if local memory fails.
            state["sbom_context"] = {}
        plan = dict(state.get("intent_plan") or {})
        if not plan and looks_like_report_request(state["question"]):
            execution_hint = heuristic_intent_plan(
                state["question"],
                workspace_available=bool(state.get("workspace_path")),
                active_task=state.get("active_task") or None,
                recent_sbom_operation=state.get("sbom_context") or None,
            )
            if execution_hint.get("intent") in {"project_scan", "project_rescan", "project_sbom_export"}:
                plan = {**execution_hint, "planner": "deterministic-execution-precedence"}
        execution_intent = str(plan.get("intent") or "")
        if looks_like_report_request(state["question"]) and execution_intent not in {
            "project_scan",
            "project_rescan",
            "project_sbom_export",
        }:
            plan = {
                **plan,
                "intent": "report_operation",
                "reason": "用户请求报告生成或下载。",
                "confidence": 1.0,
                "planner": "deterministic-report-route",
            }
        elif not plan:
            planner = state["planner"]
            try:
                plan = planner(
                    state["question"],
                    workspace_available=bool(state.get("workspace_path")),
                    active_task=state.get("active_task") or None,
                    recent_sbom_operation=state.get("sbom_context") or None,
                    user_id=state["user_id"],
                )
            except Exception as exc:  # noqa: BLE001 - deterministic routing remains available.
                plan = heuristic_intent_plan(
                    state["question"],
                    workspace_available=bool(state.get("workspace_path")),
                    active_task=state.get("active_task") or None,
                    recent_sbom_operation=state.get("sbom_context") or None,
                )
                plan["planner"] = "deterministic-fallback"
                plan["planner_error"] = sanitize_public_text(str(exc))
        state["intent_plan"] = plan
        target = self._target_agent(state)
        state["target_agent"] = target
        self._visit(state, "supervisor_agent")
        self._trace(state, "supervisor_agent", "已完成任务规划并选择专业 Agent。")
        self._handoff(state, "supervisor_agent", target, str(plan.get("reason") or "按能力边界交接。"))
        return state

    def _project_context(self, state: MultiAgentState) -> MultiAgentState:
        context = self._context(state)
        execution = self._project_context_agent.invoke(context)
        self._visit(state, execution.agent_id)
        resolution = dict(execution.metadata.get("resolution") or {})
        status = str(resolution.get("status") or "unavailable")
        self._trace(
            state,
            execution.agent_id,
            {
                "available": "已验证当前用户项目源码工作区可访问。",
                "stale": "历史项目源码目录当前不可访问。",
                "ambiguous": "存在多个候选项目，需要用户重新选择。",
            }.get(status, "未找到可验证的源码工作区关联。"),
            "completed" if status == "available" else "warning",
        )
        if execution.answer is not None:
            state["answer"] = execution.answer
            state["target_agent"] = "result_aggregator_agent"
            self._handoff(state, execution.agent_id, "result_aggregator_agent", "需要用户补充源码范围。")
            return state
        state["workspace_path"] = str(resolution.get("workspace_path") or "")
        state["target_agent"] = execution.next_agent
        self._handoff(state, execution.agent_id, execution.next_agent, "源码工作区验证通过。")
        return state

    def _specialist_node(self, agent_id: str):
        def invoke(state: MultiAgentState) -> MultiAgentState:
            execution = self._agents[agent_id].invoke(self._context(state))
            state["answer"] = dict(execution.answer or {})
            state["current_agent"] = agent_id
            self._visit(state, agent_id)
            status = "warning" if execution.status == "failed" else "completed"
            self._trace(state, agent_id, self._agent_completion_message(agent_id, execution), status)
            self._handoff(state, agent_id, "result_aggregator_agent", "专业能力执行完成。")
            return state

        return invoke

    def _result_aggregator(self, state: MultiAgentState) -> MultiAgentState:
        self._visit(state, "result_aggregator_agent")
        answer = public_answer_payload(dict(state.get("answer") or {}))
        if not self._translation_audit_is_stored(answer, state.get("response_language", "zh-Hans")):
            self._handoff(
                state,
                "result_aggregator_agent",
                "translation_agent",
                "结构化结果已完成审计，进入统一语言输出节点。",
            )
        agent_trace = list(state.get("trace") or [])
        answer_trace = list(answer.get("trace") or [])
        answer["trace"] = [*agent_trace, *answer_trace]
        answer["orchestration"] = {
            "schema_version": "secflow.multi-agent/v1",
            "architecture": "supervisor-specialists",
            "agentic": True,
            "supervisor": "supervisor_agent",
            "final_agent": str(state.get("current_agent") or "project_context_agent"),
            "visited_agents": list(state.get("visited_agents") or []),
            "handoffs": list(state.get("handoffs") or []),
            "policy": {
                "online_global_rule_mutation": False,
                "project_overlay_scope": "task-only",
                "frozen_evaluation_isolated": True,
            },
        }
        state["answer"] = answer
        self._trace(state, "result_aggregator_agent", "已完成结构化结果合并与审计。")
        # Include the final aggregator event after it has been emitted.
        answer["trace"] = [*state.get("trace", []), *answer_trace]
        return state

    @staticmethod
    def _translation_audit_is_stored(answer: dict[str, Any], target_language: Any) -> bool:
        audit = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
        return (
            audit.get("status") == "completed"
            and audit.get("target_language") == str(target_language or "zh-Hans")
            and audit.get("storage_stage") == "before-persist"
        )

    @classmethod
    def _answer_uses_stored_translation(cls, state: MultiAgentState) -> bool:
        return cls._translation_audit_is_stored(
            dict(state.get("answer") or {}),
            state.get("response_language", "zh-Hans"),
        )

    def _translation(self, state: MultiAgentState) -> MultiAgentState:
        self._visit(state, "translation_agent")
        answer = dict(state.get("answer") or {})
        existing_trace = list(answer.get("trace") or [])
        existing = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
        target_language = str(state.get("response_language") or "zh-Hans")
        if existing.get("status") == "completed" and existing.get("target_language") == target_language:
            self._trace(state, "translation_agent", "已复用问答子图完成的 Translation MCP JSON 翻译。")
        else:
            try:
                result = translation_agent.translate_json(
                    answer,
                    target_language=target_language,
                    user_id=str(state.get("user_id") or "default"),
                    session_id=str(state.get("session_id") or "default"),
                    content_scope="multi_agent_response",
                )
                answer = public_answer_payload(result.payload)
                answer["translation"] = dict(result.audit)
                state["answer"] = answer
                self._trace(
                    state,
                    "translation_agent",
                    (
                        "Translation Agent 已调用翻译 MCP 处理汇总 JSON："
                        f"目标语言 {result.audit['target_language']}，"
                        f"翻译 {result.audit['translated_fields']} 个字段。"
                    ),
                    presentation=tool_call_presentation(
                        "translate_json_payload",
                        state="completed",
                        title="Translation MCP",
                        input_summary={
                            "content_scope": "multi_agent_response",
                            "target_language": result.audit["target_language"],
                            "candidate_fields": result.audit["candidate_fields"],
                        },
                        output={
                            "translated_fields": result.audit["translated_fields"],
                            "translation_status": result.audit["translation_status"],
                            "output_sha256": result.audit["output_sha256"],
                        },
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - do not discard a verified specialist result.
                message = sanitize_public_text(str(exc)).strip() or "翻译 MCP 未返回可用结果"
                answer["translation"] = {
                    "server": "SecFlow Translation MCP",
                    "tool": "translate_json_payload",
                    "status": "failed",
                    "target_language": target_language,
                    "error": message,
                }
                state["answer"] = public_answer_payload(answer)
                self._trace(
                    state,
                    "translation_agent",
                    f"Translation Agent 调用失败，已保留专业 Agent 结构化结果：{message}",
                    "warning",
                    presentation=tool_call_presentation(
                        "translate_json_payload",
                        state="error",
                        title="Translation MCP",
                        input_summary={"content_scope": "multi_agent_response"},
                        error=message,
                    ),
                )
        answer = dict(state.get("answer") or answer)
        orchestration = answer.get("orchestration") if isinstance(answer.get("orchestration"), dict) else {}
        orchestration["visited_agents"] = list(state.get("visited_agents") or [])
        orchestration["handoffs"] = list(state.get("handoffs") or [])
        orchestration["translation_agent"] = "translation_agent"
        answer["orchestration"] = orchestration
        answer["trace"] = _merge_trace_items(existing_trace, list(state.get("trace") or []))
        state["answer"] = answer
        return state

    def _invoke_fallback(self, state: MultiAgentState) -> MultiAgentState:
        state = self._supervisor(state)
        if state["target_agent"] == "project_context_agent":
            state = self._project_context(state)
        if state["target_agent"] in self._agents:
            state = self._specialist_node(state["target_agent"])(state)
        state = self._result_aggregator(state)
        return state if self._answer_uses_stored_translation(state) else self._translation(state)

    def _target_agent(self, state: MultiAgentState) -> str:
        intent = str((state.get("intent_plan") or {}).get("intent") or "llm_direct")
        workspace = bool(state.get("workspace_path"))
        direct_source = self._has_direct_source_attachment(state.get("attachments") or [])
        if intent in {"project_scan", "project_rescan"}:
            if not workspace and not direct_source and state.get("allow_workspace_recovery"):
                return "project_context_agent"
            return "code_scan_agent"
        if intent == "scan_result_follow_up":
            return "code_scan_agent"
        if intent == "project_sbom_export":
            if not workspace and state.get("allow_workspace_recovery"):
                return "project_context_agent"
            return "sbom_agent"
        if intent == "sbom_result_follow_up":
            return "sbom_agent"
        if intent in {"component_vulnerability_query", "component_vulnerability_catalog"}:
            return "component_agent"
        if intent == "report_operation":
            return "report_agent"
        if intent in {"vulnerability_lookup", "vulnerability_year_lookup"}:
            return "intelligence_agent"
        return "conversation_agent"

    def _context(self, state: MultiAgentState) -> AssistantAgentContext:
        return AssistantAgentContext(
            question=state["question"],
            top_k=state["top_k"],
            user_id=state["user_id"],
            session_id=state["session_id"],
            response_language=state["response_language"],
            attachments=list(state.get("attachments") or []),
            workspace_path=str(state.get("workspace_path") or ""),
            task_context=dict(state.get("task_context") or {}),
            active_task=dict(state.get("active_task") or {}),
            intent_plan=dict(state.get("intent_plan") or {}),
            sbom_context=dict(state.get("sbom_context") or {}),
            runtime_graph=state["runtime_graph"],
            memory=state["memory"],
            task_service=state.get("task_service"),
            allow_task_creation=bool(state.get("allow_task_creation")),
            event_sink=state.get("event_sink"),
            content_sink=state.get("content_sink"),
            artifact_names=[
                str(item.get("file_name") or "")
                for item in state.get("attachments") or []
                if isinstance(item, dict)
            ],
        )

    @staticmethod
    def _has_direct_source_attachment(attachments: list[dict[str, Any]]) -> bool:
        for item in attachments:
            name = str(item.get("file_name") or "")
            if attachment_kind(name) in BUILD_MANIFEST_SOURCE_TYPES:
                return True
            if Path(name).suffix.lower() in CODE_EXTENSIONS:
                return True
        return False

    @staticmethod
    def _agent_completion_message(agent_id: str, execution: AgentExecution) -> str:
        labels = {manifest.agent_id: manifest.label for manifest in AGENT_MANIFESTS}
        if execution.status == "waiting":
            return f"{labels.get(agent_id, agent_id)} 已进入人工确认阶段。"
        if execution.status == "failed":
            return f"{labels.get(agent_id, agent_id)} 执行失败。"
        return f"{labels.get(agent_id, agent_id)} 已完成。"

    def _handoff(self, state: MultiAgentState, source: str, target: str, reason: str) -> None:
        handoff = AgentHandoff(
            source_agent=source,
            target_agent=target,
            reason=sanitize_public_text(reason),
            intent=str((state.get("intent_plan") or {}).get("intent") or "llm_direct"),
        ).as_dict()
        state["handoffs"] = [*state.get("handoffs", []), handoff]

    @staticmethod
    def _visit(state: MultiAgentState, agent_id: str) -> None:
        visited = list(state.get("visited_agents") or [])
        if agent_id not in visited:
            visited.append(agent_id)
        state["visited_agents"] = visited

    @staticmethod
    def _trace(
        state: MultiAgentState,
        node: str,
        message: str,
        status: str = "completed",
        presentation: dict[str, Any] | None = None,
    ) -> None:
        item = {"node": node, "status": status, "message": sanitize_public_text(message), "time": now_iso()}
        if presentation:
            item["presentation"] = presentation
        state["trace"] = [*state.get("trace", []), item]
        sink = state.get("event_sink")
        if sink is not None:
            try:
                sink(dict(item))
            except Exception:  # noqa: BLE001 - UI streaming must not break execution.
                pass


def _merge_trace_items(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for group in groups:
        for item in group:
            identity = (
                str(item.get("node") or ""),
                str(item.get("time") or item.get("started_at") or ""),
                str(item.get("message") or ""),
            )
            if identity in seen:
                continue
            seen.add(identity)
            output.append(item)
    return output


assistant_multi_agent_supervisor = AssistantMultiAgentSupervisor()


__all__ = [
    "AGENT_MANIFESTS",
    "AssistantMultiAgentSupervisor",
    "assistant_multi_agent_supervisor",
]
