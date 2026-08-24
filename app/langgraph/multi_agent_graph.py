from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - packaged fallback
    END = "__end__"
    StateGraph = None

from app.agent.assistant_intent import heuristic_intent_plan
from app.agent.contracts import AgentExecution, AgentHandoff
from app.agent.plugins import (
    AGENT_MANIFESTS,
    AGENT_REGISTRY,
    AgentRegistry,
)
from app.agent.specialist_agents import AssistantAgentContext
from app.agent.translation_policy import (
    catalog_partial_translation_audit_is_recoverable,
    fail_closed_translation_payload,
    failed_translation_audit,
    host_localization_attestation_is_publishable,
    issue_host_localization_attestation,
    issue_partial_catalog_translation_attestation,
    issue_stored_translation_attestation,
    partial_catalog_translation_attestation_is_publishable,
    partial_catalog_translation_is_publishable,
    partial_catalog_translation_status,
    stored_translation_attestation_is_publishable,
    translation_audit_is_publishable,
    translation_unavailable_message,
)
from app.catalog_translation import partial_catalog_summary, recover_partial_catalog_records
from app.composition import secflow_runtime
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
    emoji_mode: str
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
    stored_translation_verified: bool


class AssistantMultiAgentSupervisor:
    """Supervisor-and-specialists orchestration over existing capability subgraphs."""

    def __init__(self, agent_registry: AgentRegistry | None = None) -> None:
        self._agent_registry = agent_registry
        self._agents: dict[str, Any] = {}
        self._definitions = ()
        self._manifests = AGENT_MANIFESTS
        self._project_context_agent: Any = None
        self._result_aggregator_agent: Any = None
        self._translation_agent: Any = None
        self._graph = None
        if agent_registry is not None:
            self._configure(agent_registry)

    def _configure(self, registry: AgentRegistry) -> None:
        self._definitions = registry.definitions()
        self._manifests = tuple(definition.manifest for definition in self._definitions)
        self._project_context_agent = registry.instantiate("project_context_agent")
        self._result_aggregator_agent = registry.instantiate("result_aggregator_agent")
        self._translation_agent = registry.instantiate("translation_agent")
        self._agents = {
            definition.agent_id: definition.instantiate()
            for definition in self._definitions
            if definition.role == "specialist"
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
        emoji_mode: str = "moderate",
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
        if self._agent_registry is None:
            with secflow_runtime().pin() as snapshot:
                registry = AgentRegistry(snapshot.registries.get(AGENT_REGISTRY, {}))
                return AssistantMultiAgentSupervisor(registry).invoke(
                    question=question,
                    top_k=top_k,
                    user_id=user_id,
                    session_id=session_id,
                    response_language=response_language,
                    emoji_mode=emoji_mode,
                    attachments=attachments,
                    runtime_graph=runtime_graph,
                    memory=memory,
                    planner=planner,
                    event_sink=event_sink,
                    content_sink=content_sink,
                    workspace_path=workspace_path,
                    task_context=task_context,
                    active_task=active_task,
                    intent_plan=intent_plan,
                    task_service=task_service,
                    allow_workspace_recovery=allow_workspace_recovery,
                    allow_task_creation=allow_task_creation,
                )
        state: MultiAgentState = {
            "question": question,
            "top_k": top_k,
            "user_id": user_id or "default",
            "session_id": session_id or "default",
            "response_language": response_language or "zh-Hans",
            "emoji_mode": emoji_mode if emoji_mode in {"off", "moderate", "active"} else "moderate",
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
            "stored_translation_verified": False,
        }
        if self._graph is not None:
            final = self._graph.invoke(state)
        else:  # pragma: no cover - dependency fallback for packaged diagnostics.
            final = self._invoke_fallback(state)
        return public_answer_payload(dict(final.get("answer") or {}))

    def graph_spec(self, *, knowledge_graph: Any = None, task_graph: Any = None) -> dict[str, Any]:
        if self._agent_registry is None:
            with secflow_runtime().pin() as snapshot:
                registry = AgentRegistry(snapshot.registries.get(AGENT_REGISTRY, {}))
                return AssistantMultiAgentSupervisor(registry).graph_spec(
                    knowledge_graph=knowledge_graph,
                    task_graph=task_graph,
                )
        subgraphs: list[dict[str, Any]] = []
        if knowledge_graph is not None:
            subgraphs.append(knowledge_graph.graph_spec())
        if task_graph is not None:
            subgraphs.append(task_graph.graph_spec())
        return {
            "name": "AegisAl Multi-Agent Supervisor",
            "architecture": "supervisor-specialists",
            "schema_version": "secflow.multi-agent/v1",
            "agents": [
                definition.as_dict()
                for definition in self._definitions
            ],
            "nodes": [
                {"id": manifest.agent_id, "label": manifest.label, "type": "agent"}
                for manifest in self._manifests
            ]
            + [{"id": "final_output", "label": "已本地化输出", "type": "output"}],
            "edges": [
                {"source": "supervisor_agent", "target": target, "label": "语义交接"}
                for target in ("project_context_agent", *self._agents)
            ]
            + [
                {
                    "source": "project_context_agent",
                    "target": definition.agent_id,
                    "label": "源码已验证",
                }
                for definition in self._definitions
                if definition.role == "specialist" and definition.requires_workspace
            ]
            + [
                {"source": target, "target": "result_aggregator_agent", "label": "结构化结果"}
                for target in ("project_context_agent", *self._agents)
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
                **{
                    definition.agent_id: definition.agent_id
                    for definition in self._definitions
                    if definition.role == "specialist" and definition.requires_workspace
                },
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
        state["target_agent"] = self._target_agent(state)
        self._handoff(
            state,
            execution.agent_id,
            state["target_agent"],
            "源码工作区验证通过。",
        )
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
        answer = self._result_aggregator_agent.aggregate(dict(state.get("answer") or {}))
        target_language = str(state.get("response_language") or "zh-Hans")
        stored_audit = answer.get("translation") if isinstance(answer.get("translation"), dict) else {}
        stored_translation_verified = stored_translation_attestation_is_publishable(answer, target_language)
        host_localization_verified = host_localization_attestation_is_publishable(answer, target_language)
        partial_catalog_verified = partial_catalog_translation_attestation_is_publishable(
            answer,
            target_language,
        )
        sanitized_partial_catalog_verified = partial_catalog_translation_is_publishable(
            answer,
            target_language,
        )
        localization_verified = (
            stored_translation_verified
            or host_localization_verified
            or partial_catalog_verified
            or sanitized_partial_catalog_verified
        )
        state["stored_translation_verified"] = localization_verified
        if not localization_verified:
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
        if stored_translation_verified:
            answer["translation"] = issue_stored_translation_attestation(
                answer,
                target_language=target_language,
                record_count=int(stored_audit["record_count"]),
                source=str(stored_audit.get("source") or "vulnerability-catalog"),
            )
        elif host_localization_verified:
            answer["translation"] = issue_host_localization_attestation(
                answer,
                target_language=target_language,
                source=str(stored_audit.get("source") or "host-rendered-response"),
            )
        elif partial_catalog_verified:
            answer["translation"] = issue_partial_catalog_translation_attestation(
                answer,
                target_language=target_language,
                catalog_status=stored_audit,
                source=str(stored_audit.get("source") or "component-vulnerability-catalog"),
            )
        elif sanitized_partial_catalog_verified:
            answer["translation"] = partial_catalog_translation_status(
                stored_audit,
                target_language=target_language,
                record_count=int(stored_audit["record_count"]),
                ready_records=int(stored_audit["ready_records"]),
                source=str(stored_audit.get("source") or "component-vulnerability-catalog"),
            )
        return state

    @staticmethod
    def _translation_audit_is_stored(answer: dict[str, Any], target_language: Any) -> bool:
        return stored_translation_attestation_is_publishable(
            answer,
            target_language,
        ) or host_localization_attestation_is_publishable(
            answer,
            target_language,
        ) or partial_catalog_translation_attestation_is_publishable(
            answer,
            target_language,
        ) or partial_catalog_translation_is_publishable(answer, target_language)

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
        target_language = str(state.get("response_language") or "zh-Hans")
        translation_blocked = False
        try:
            result = self._translation_agent.translate_json(
                answer,
                target_language=target_language,
                user_id=str(state.get("user_id") or "default"),
                session_id=str(state.get("session_id") or "default"),
                content_scope="multi_agent_response",
            )
            audit = dict(result.audit)
            translation_completed = translation_audit_is_publishable(audit)
            translation_partial = (
                answer.get("mode") == "component_vulnerability_catalog"
                and isinstance(answer.get("records"), list)
                and bool(answer["records"])
                and catalog_partial_translation_audit_is_recoverable(
                    audit,
                    target_language,
                )
            )
            if translation_completed:
                answer = public_answer_payload(result.payload)
                answer["translation"] = audit
            elif translation_partial:
                candidate_records = (
                    result.payload.get("records")
                    if isinstance(result.payload.get("records"), list)
                    else []
                )
                records = recover_partial_catalog_records(
                    answer["records"],
                    candidate_records,
                    target_language=target_language,
                )
                ready_records = sum(
                    record.get("translation_status") == "translated"
                    for record in records
                )
                answer["summary"] = partial_catalog_summary(
                    result.payload.get("summary"),
                    answer.get("summary"),
                    target_language=target_language,
                )
                answer["records"] = records
                answer["trace"] = []
                answer["translation"] = partial_catalog_translation_status(
                    audit,
                    target_language=target_language,
                    record_count=len(records),
                    ready_records=ready_records,
                )
                answer = public_answer_payload(answer)
                existing_trace = []
                state["trace"] = []
            else:
                translation_blocked = True
                existing_trace = []
                state["trace"] = []
                answer = public_answer_payload(
                    fail_closed_translation_payload(
                        result.payload,
                        target_language=target_language,
                        audit=audit,
                    )
                )
            state["answer"] = answer
            self._trace(
                state,
                "translation_agent",
                (
                    "Translation Agent 已调用翻译 MCP 处理汇总 JSON："
                    f"目标语言 {result.audit['target_language']}，"
                    f"翻译 {result.audit['translated_fields']} 个字段。"
                ) if translation_completed else (
                    "Translation Agent 返回部分离线译文；已保留核验记录，待补译字段使用中文占位。"
                    if translation_partial
                    else translation_unavailable_message(target_language)
                ),
                "completed" if translation_completed else "warning",
                presentation=tool_call_presentation(
                    "translate_json_payload",
                    state="completed" if (translation_completed or translation_partial) else "error",
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
                    error="" if (translation_completed or translation_partial) else "翻译结果不可用。",
                ),
            )
        except Exception as exc:  # noqa: BLE001 - do not discard a verified specialist result.
            translation_blocked = True
            existing_trace = []
            state["trace"] = []
            message = sanitize_public_text(str(exc)).strip() or "翻译 MCP 未返回可用结果"
            answer = public_answer_payload(
                fail_closed_translation_payload(
                    answer,
                    target_language=target_language,
                    audit=failed_translation_audit(target_language, message),
                )
            )
            state["answer"] = answer
            self._trace(
                state,
                "translation_agent",
                translation_unavailable_message(target_language),
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
        orchestration = (
            {}
            if translation_blocked
            else answer.get("orchestration") if isinstance(answer.get("orchestration"), dict) else {}
        )
        orchestration["visited_agents"] = list(state.get("visited_agents") or [])
        if not translation_blocked:
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
        definition = self._agent_registry.route(intent) if self._agent_registry is not None else None
        if definition is None:
            definition = self._agent_registry.definition("conversation_agent")
        needs_workspace_now = intent in {"project_scan", "project_rescan", "project_sbom_export"}
        direct_workspace = definition.agent_id == "code_scan_agent" and direct_source
        if (
            definition.requires_workspace
            and needs_workspace_now
            and not workspace
            and not direct_workspace
            and state.get("allow_workspace_recovery")
        ):
            return "project_context_agent"
        return definition.agent_id

    def _context(self, state: MultiAgentState) -> AssistantAgentContext:
        return AssistantAgentContext(
            question=state["question"],
            top_k=state["top_k"],
            user_id=state["user_id"],
            session_id=state["session_id"],
            response_language=state["response_language"],
            emoji_mode=state.get("emoji_mode", "moderate"),
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

    def _agent_completion_message(self, agent_id: str, execution: AgentExecution) -> str:
        labels = {manifest.agent_id: manifest.label for manifest in self._manifests}
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
