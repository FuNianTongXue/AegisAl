from __future__ import annotations

from datetime import date
from time import perf_counter
from typing import Any

from app.agent.assistant_intent import (
    assistant_intent_skill_metadata,
    heuristic_intent_plan,
    infer_explicit_filters,
    infer_time_scope,
    plan_assistant_intent,
    resolve_catalog_date_range,
)
from app.agent.translation_agent import translate_answer_json
from app.agent.translation_policy import (
    fail_closed_translation_payload,
    failed_translation_audit,
    translation_audit_is_publishable,
    translation_unavailable_message,
)
from app.langgraph.checkpoints import InterruptStateExpiredError
from app.langgraph.component_catalog_graph import (
    component_catalog_outcome_answer,
    component_vulnerability_catalog_subgraph,
)
from app.intelligence import intelligence_service
from app.langgraph.report_graph import looks_like_report_request, report_capability_subgraph, report_outcome_answer
from app.langgraph.sbom_graph import project_sbom_subgraph, sbom_outcome_answer
from app.memory import LongTermMemoryService, memory_service
from app.models import (
    AssistantInterruptResumeRequest,
    AssistantTaskActionRequest,
    AssistantWorkspaceActionRequest,
    AskRequest,
)
from app.privacy import public_answer_payload, sanitize_public_text
from app.storage import now_iso


def invoke_assistant_question(
    payload: AskRequest,
    *,
    graph: Any,
    event_sink: Any = None,
    content_sink: Any = None,
    allow_workspace_recovery: bool = False,
) -> dict[str, Any]:
    if payload.intent_hint == "recent_high_vulnerability_lookup":
        result = _invoke_recent_high_vulnerability_lookup(payload, event_sink=event_sink)
        if str(payload.session_id or "").startswith("information:"):
            memory_service.add_short_term_exchange(
                payload.user_id,
                payload.session_id,
                payload.question,
                result,
            )
        return result

    from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor

    if payload.intent_hint == "component_vulnerability_catalog":
        # The empty-state vulnerability card is an explicit product action, not
        # free-form text.  Route it deterministically so a planner-model timeout
        # cannot make a known-safe click fail or add an unnecessary model call.
        today = date.today()
        plan = heuristic_intent_plan(payload.question, today=today)
        time_scope = infer_time_scope(payload.question, today=today)
        plan = {
            **plan,
            "intent": "component_vulnerability_catalog",
            "planner": "deterministic-quick-action",
            "reason": "用户点击了本月高风险组件漏洞快捷入口。",
            "confidence": 1.0,
            "time_scope": time_scope,
            "date_filter": resolve_catalog_date_range(payload.question, time_scope, today=today),
            "filters": infer_explicit_filters(payload.question),
            "skill": assistant_intent_skill_metadata(),
        }
    elif payload.intent_hint == "information_consultation":
        # The Information Center already provides an explicit, isolated chat
        # surface. Use deterministic semantic rules here so ordinary questions
        # do not spend an extra model call on the planner before answering.
        plan = heuristic_intent_plan(payload.question, today=date.today())
        plan = {
            **plan,
            "planner": "deterministic-information-consultation",
            "reason": str(plan.get("reason") or "信息中心短期咨询。"),
        }
    else:
        plan = plan_assistant_intent(
            payload.question,
            user_id=payload.user_id,
            session_id=payload.session_id,
        )
    if _is_direct_model_question(payload, plan):
        answer = graph.invoke(
            payload.question,
            payload.top_k,
            user_id=payload.user_id,
            session_id=payload.session_id,
            response_language=payload.response_language,
            attachments=[attachment.model_dump() for attachment in payload.attachments],
            intent_plan=plan,
            event_sink=event_sink,
            content_sink=content_sink,
        )
        direct_answer = dict(answer or {})
        direct_answer["orchestration"] = {
            "schema_version": "secflow.direct-model/v1",
            "architecture": "direct-model",
            "agentic": False,
            "visited_agents": [],
            "handoffs": [],
        }
        return public_answer_payload(direct_answer)

    task_service = None
    if allow_workspace_recovery:
        from app.agent.task_agent import task_agent_service

        task_service = task_agent_service
    return assistant_multi_agent_supervisor.invoke(
        question=payload.question,
        top_k=payload.top_k,
        user_id=payload.user_id,
        session_id=payload.session_id,
        response_language=payload.response_language,
        attachments=[attachment.model_dump() for attachment in payload.attachments],
        runtime_graph=graph,
        memory=memory_service,
        planner=plan_assistant_intent,
        intent_plan=plan,
        event_sink=event_sink,
        content_sink=content_sink,
        task_service=task_service,
        allow_workspace_recovery=allow_workspace_recovery,
        allow_task_creation=allow_workspace_recovery,
    )


def _invoke_recent_high_vulnerability_lookup(
    payload: AskRequest,
    *,
    event_sink: Any = None,
) -> dict[str, Any]:
    """Serve the Information Center from the translated local catalog."""

    today = date.today()
    time_scope = infer_time_scope(payload.question, today=today)
    if str(time_scope.get("kind") or "") in {"", "unspecified", "latest"}:
        time_scope = {"kind": "recent_days", "days": 7}
    date_filter = resolve_catalog_date_range(payload.question, time_scope, today=today)
    filters = infer_explicit_filters(payload.question)
    severities = list(filters.get("severities") or ["CRITICAL", "HIGH"])
    started = perf_counter()
    running_trace = {
        "node": "query_recent_high_vulnerabilities",
        "title": "查询近期高危漏洞",
        "status": "running",
        "message": "正在读取本地已翻译漏洞目录。",
        "time": now_iso(),
        "tool_name": "Local Catalog",
    }
    if event_sink is not None:
        event_sink(running_trace)
    try:
        result = intelligence_service.query_component_vulnerability_catalog(
            str(date_filter.get("start_date") or ""),
            str(date_filter.get("end_date") or ""),
            ecosystems=list(filters.get("ecosystems") or []),
            severities=severities,
            component_names=list(filters.get("component_names") or []),
            include_realtime=False,
            limit=max(1, min(int(payload.top_k or 5), 20)),
            response_language=payload.response_language,
        )
        elapsed_ms = max(0, round((perf_counter() - started) * 1000))
        completed_trace = {
            **running_trace,
            "status": "completed" if result.get("records") else "warning",
            "message": f"本地目录查询完成，命中 {int(result.get('total') or 0)} 条，耗时 {elapsed_ms}ms。",
            "time": now_iso(),
            "duration_ms": elapsed_ms,
            "presentation": {
                "kind": "tool_call",
                "title": "Local vulnerability catalog query",
                "tool_name": "query_recent_high_vulnerabilities",
                "state": "completed",
                "input": {"date_filter": date_filter, "severities": severities},
                "output": {
                    "matched_records": int(result.get("total") or 0),
                    "returned_records": len(result.get("records") or []),
                    "elapsed_ms": elapsed_ms,
                },
            },
        }
        if event_sink is not None:
            event_sink(completed_trace)
        answer = {
            "mode": "recent_high_vulnerability_lookup",
            "summary": _recent_high_vulnerability_summary(result, date_filter, payload.response_language),
            "records": list(result.get("records") or []),
            "fields": {
                "查询开始日期": str(date_filter.get("start_date") or ""),
                "查询结束日期": str(date_filter.get("end_date") or ""),
                "风险等级": "、".join(_severity_label_zh(value) for value in severities),
                "命中漏洞": str(int(result.get("total") or 0)),
                "展示数量": str(len(result.get("records") or [])),
                "数据路径": "本地已翻译漏洞目录",
            },
            "vulnerability_card": {},
            "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "chart_data": {},
            "artifacts": [],
            "evidence_sources": list(result.get("source_status") or []),
            "confidence": 0.97 if result.get("records") else 0.62,
            "trace": [completed_trace],
            "translation": {
                "server": "SecFlow Vulnerability Catalog",
                "tool": "translate_before_persist",
                "transport": "local-catalog",
                "status": "completed",
                "target_language": payload.response_language,
                "storage_stage": "before-persist",
            },
            "elapsed_ms": elapsed_ms,
            "generated_at": now_iso(),
            "orchestration": {
                "schema_version": "secflow.local-catalog/v1",
                "architecture": "deterministic-local-query",
                "agentic": False,
                "visited_agents": [],
                "handoffs": [],
            },
        }
        return public_answer_payload(answer)
    except Exception as exc:  # noqa: BLE001 - preserve a useful local error envelope.
        message = sanitize_public_text(str(exc)).strip() or "本地漏洞目录查询失败。"
        elapsed_ms = max(0, round((perf_counter() - started) * 1000))
        failed_trace = {
            **running_trace,
            "status": "warning",
            "message": message,
            "time": now_iso(),
            "duration_ms": elapsed_ms,
        }
        if event_sink is not None:
            event_sink(failed_trace)
        return public_answer_payload(
            {
                "mode": "recent_high_vulnerability_lookup",
                "summary": f"暂时无法读取本地漏洞目录：{message}",
                "records": [],
                "fields": {},
                "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
                "confidence": 0.3,
                "trace": [failed_trace],
                "elapsed_ms": elapsed_ms,
                "generated_at": now_iso(),
            }
        )


def _recent_high_vulnerability_summary(
    result: dict[str, Any],
    date_filter: dict[str, Any],
    response_language: str,
) -> str:
    records = [record for record in result.get("records") or [] if isinstance(record, dict)]
    if not records:
        return (
            f"未在 {date_filter.get('start_date')} 至 {date_filter.get('end_date')} "
            "的本地已翻译目录中找到匹配的高危漏洞。"
        )
    lines = [
        f"已查询 {date_filter.get('start_date')} 至 {date_filter.get('end_date')} 的本地漏洞目录，"
        f"共命中 {int(result.get('total') or 0)} 条，以下展示最新 {len(records)} 条："
    ]
    use_zh = str(response_language or "").strip().lower() in {"zh", "zh-cn", "zh-hans", "zh_hans"}
    for record in records:
        components = [
            str(component.get("name") or "").strip()
            for component in record.get("components") or []
            if isinstance(component, dict) and str(component.get("name") or "").strip()
        ]
        description = str(record.get("title") or record.get("summary") or "").strip()
        if use_zh and description and not any("\u4e00" <= char <= "\u9fff" for char in description):
            description = "描述正在后台补译"
        lines.append(
            f"- {record.get('id') or '未标明编号'} | {_severity_label_zh(record.get('severity'))} | "
            f"{'、'.join(dict.fromkeys(components)) or '组件待核验'} | {description or '未提供描述'}"
        )
    lines.append("结果来自本机持续更新、翻译后存储的漏洞目录，已复用本地离线译文，本次未重复执行离线翻译。")
    return "\n".join(lines)


def _severity_label_zh(value: Any) -> str:
    return {
        "CRITICAL": "严重",
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危",
        "UNKNOWN": "未知",
    }.get(str(value or "UNKNOWN").strip().upper(), str(value or "未知"))


def _is_direct_model_question(payload: AskRequest, plan: dict[str, Any]) -> bool:
    if payload.attachments or looks_like_report_request(payload.question):
        return False
    if str(plan.get("intent") or "") != "llm_direct":
        return False
    fallback = heuristic_intent_plan(payload.question)
    return str(fallback.get("intent") or "") == "llm_direct"


def invoke_assistant_workspace_action(
    payload: AssistantWorkspaceActionRequest,
    *,
    graph: Any,
    task_service: Any,
    planner: Any = plan_assistant_intent,
) -> dict[str, Any]:
    from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor

    plan = planner(
        payload.objective,
        workspace_available=True,
        user_id=payload.user_id,
        session_id=payload.session_id,
    )
    answer = assistant_multi_agent_supervisor.invoke(
        question=payload.objective,
        top_k=8,
        user_id=payload.user_id,
        session_id=payload.session_id,
        response_language=payload.response_language,
        attachments=[],
        workspace_path=payload.workspace_path,
        runtime_graph=graph,
        memory=memory_service,
        planner=planner,
        intent_plan=plan,
        task_service=task_service,
        allow_workspace_recovery=False,
        allow_task_creation=True,
    )
    task = answer.get("agent_task") if isinstance(answer.get("agent_task"), dict) else None
    return {
        "kind": "agent_task" if task else "assistant",
        "answer": None if task else answer,
        "task": task,
        "intent_plan": plan,
        "orchestration": answer.get("orchestration") or {},
    }


def invoke_assistant_task_action(
    payload: AssistantTaskActionRequest,
    *,
    task: dict[str, Any],
    graph: Any,
    task_service: Any,
    planner: Any = plan_assistant_intent,
) -> dict[str, Any]:
    from app.agent.task_agent import agent_task_report_metrics, task_assistant_context
    from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor

    report_request = looks_like_report_request(payload.objective)
    if report_request:
        plan = {
            "intent": "report_operation",
            "reason": "用户请求基于活动扫描任务生成或下载报告。",
            "confidence": 1.0,
            "planner": "deterministic-report-route",
        }
    else:
        plan = planner(
            payload.objective,
            workspace_available=bool(task.get("workspace_path")),
            active_task=task,
            user_id=payload.user_id,
            session_id=payload.session_id,
        )
    if report_request:
        task_context = {
            "report_task": task,
            "report_metrics": agent_task_report_metrics(task),
        }
    elif plan.get("intent") == "scan_result_follow_up":
        task_context = task_assistant_context(task)
    else:
        task_context = {}
    answer = assistant_multi_agent_supervisor.invoke(
        question=payload.objective,
        top_k=8,
        user_id=payload.user_id,
        session_id=payload.session_id,
        response_language=payload.response_language,
        attachments=[],
        workspace_path=str(task.get("workspace_path") or ""),
        task_context=task_context,
        active_task=task,
        runtime_graph=graph,
        memory=memory_service,
        planner=planner,
        intent_plan=plan,
        task_service=task_service,
        allow_workspace_recovery=False,
        allow_task_creation=True,
    )
    rescanned = answer.get("agent_task") if isinstance(answer.get("agent_task"), dict) else None
    return {
        "kind": "agent_task" if rescanned else "assistant",
        "answer": None if rescanned else answer,
        "task": rescanned,
        "intent_plan": plan,
        "orchestration": answer.get("orchestration") or {},
    }


def assistant_content_chunks(text: str, *, limit: int = 96) -> list[str]:
    """Split final model text into stable SSE increments without changing Markdown."""

    if not text:
        return []
    chunks: list[str] = []
    cursor = 0
    while cursor < len(text):
        end = min(len(text), cursor + max(16, limit))
        if end < len(text):
            boundary = max(
                text.rfind("\n", cursor, end),
                text.rfind("。", cursor, end),
                text.rfind(" ", cursor, end),
            )
            if boundary >= cursor + 24:
                end = boundary + 1
        chunks.append(text[cursor:end])
        cursor = end
    return chunks


def translate_assistant_answer(
    answer: dict[str, Any],
    *,
    response_language: str,
    user_id: str,
    session_id: str,
    content_scope: str,
) -> dict[str, Any]:
    try:
        translated = translate_answer_json(
            answer,
            target_language=response_language,
            user_id=user_id,
            session_id=session_id,
            content_scope=content_scope,
        )
        trace = list(translated.get("trace") or [])
        audit = translated.get("translation") if isinstance(translated.get("translation"), dict) else {}
        translation_completed = translation_audit_is_publishable(audit)
        if not translation_completed:
            translated = fail_closed_translation_payload(
                translated,
                target_language=response_language,
                audit=audit,
            )
            audit = dict(translated["translation"])
            trace = []
        trace.append(
            {
                "node": "translation_agent",
                "status": "completed" if translation_completed else "warning",
                "message": (
                    "Translation Agent 已调用翻译 MCP 处理结构化回复："
                    f"目标语言 {audit.get('target_language') or response_language}，"
                    f"翻译 {int(audit.get('translated_fields') or 0)} 个字段，"
                    f"状态为 {audit.get('status') or 'failed'}。"
                ) if translation_completed else translation_unavailable_message(response_language),
                "time": now_iso(),
            }
        )
        translated["trace"] = trace
        return public_answer_payload(translated)
    except Exception as exc:  # noqa: BLE001 - preserve an already verified operation result.
        message = sanitize_public_text(str(exc)).strip() or "翻译 MCP 未返回可用结果"
        fallback = fail_closed_translation_payload(
            answer,
            target_language=response_language,
            audit=failed_translation_audit(response_language, message),
        )
        fallback["trace"] = [
            {
                "node": "translation_agent",
                "status": "warning",
                "message": str(fallback.get("summary") or ""),
                "time": now_iso(),
            },
        ]
        return public_answer_payload(fallback)


def resume_assistant_operation(
    payload: AssistantInterruptResumeRequest,
    *,
    memory: LongTermMemoryService,
) -> dict[str, Any]:
    if payload.thread_id.startswith("component-catalog-"):
        outcome = component_vulnerability_catalog_subgraph.resume(
            payload.thread_id,
            decision=payload.decision,
            user_id=payload.user_id,
            session_id=payload.session_id,
            interrupt_id=payload.interrupt_id,
        )
        answer = component_catalog_outcome_answer(outcome)
    elif payload.thread_id.startswith("sbom-"):
        outcome = project_sbom_subgraph.resume(
            payload.thread_id,
            decision=payload.decision,
            user_id=payload.user_id,
            session_id=payload.session_id,
            interrupt_id=payload.interrupt_id,
        )
        operation_context = dict(outcome.pop("_operation_context", {}) or {})
        if operation_context:
            memory.remember_sbom_operation(payload.user_id, payload.session_id, operation_context)
        answer = sbom_outcome_answer(outcome)
    elif payload.thread_id.startswith("report-"):
        outcome = report_capability_subgraph.resume(
            payload.thread_id,
            decision=payload.decision,
            user_id=payload.user_id,
            session_id=payload.session_id,
            report_format=payload.format or "",
            interrupt_id=payload.interrupt_id,
        )
        answer = report_outcome_answer(outcome)
    else:
        raise KeyError(payload.thread_id)
    response_language = str(outcome.get("response_language") or payload.response_language)
    localized_catalog_answer = payload.thread_id.startswith("component-catalog-") and response_language.strip().lower() in {
        "zh",
        "zh-cn",
        "zh-hans",
        "zh_hans",
    }
    if localized_catalog_answer:
        # The catalog subgraph already composes Chinese UI text and returns
        # stored description translations. Re-translating the full Sankey and
        # artifact payload here previously added minutes after every confirm.
        answer = public_answer_payload(answer)
    else:
        answer = translate_assistant_answer(
            answer,
            response_language=response_language,
            user_id=payload.user_id,
            session_id=payload.session_id,
            content_scope="assistant_interrupt_resume",
        )
    memory.update_interrupt_exchange(
        payload.user_id,
        payload.session_id,
        payload.thread_id,
        answer,
    )
    if payload.thread_id.startswith("sbom-") and outcome.get("artifacts"):
        memory.attach_project_artifacts(
            payload.user_id,
            payload.session_id,
            list(outcome.get("artifacts") or []),
        )
    return {**outcome, "answer": answer}


def expired_assistant_operation(
    payload: AssistantInterruptResumeRequest,
    *,
    memory: LongTermMemoryService,
) -> dict[str, Any]:
    summary = "该确认来自已结束的本地服务进程，原 LangGraph 状态已失效。请重新提交当前操作。"
    mode = "project_sbom_export" if payload.thread_id.startswith("sbom-") else "llm_direct"
    answer = public_answer_payload(
        {
            "mode": mode,
            "summary": summary,
            "fields": {},
            "artifacts": [],
            "interrupt": None,
            "confidence": 1.0,
            "trace": [],
            "generated_at": now_iso(),
        }
    )
    answer = translate_assistant_answer(
        answer,
        response_language=payload.response_language,
        user_id=payload.user_id,
        session_id=payload.session_id,
        content_scope="assistant_interrupt_expired",
    )
    memory.update_interrupt_exchange(
        payload.user_id,
        payload.session_id,
        payload.thread_id,
        answer,
    )
    return {
        "status": "expired",
        "thread_id": payload.thread_id,
        "interrupt": None,
        "summary": summary,
        "report": None,
        "artifacts": [],
        "error": "",
        "answer": answer,
    }


__all__ = [
    "InterruptStateExpiredError",
    "assistant_content_chunks",
    "expired_assistant_operation",
    "heuristic_intent_plan",
    "invoke_assistant_question",
    "invoke_assistant_task_action",
    "invoke_assistant_workspace_action",
    "resume_assistant_operation",
    "translate_assistant_answer",
]
