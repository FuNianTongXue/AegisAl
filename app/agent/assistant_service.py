from __future__ import annotations

import json
import re
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
    partial_translation_audit_is_publishable,
    partial_translation_payload,
    translation_audit_is_publishable,
    translation_partial_message,
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
from app.settings import normalize_language
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


_LOCAL_GREETINGS = {
    "zh-Hans": "你好！我是小安，您的信息安全专家助手。需要我帮你分析漏洞、代码风险、依赖或项目安全吗？",
    "zh-Hant": "你好！我是小安，您的資訊安全專家助手。需要我協助分析漏洞、程式碼風險、相依套件或專案安全嗎？",
    "en": "Hello! I'm Xiao An, your information security assistant. How can I help with vulnerabilities, code risk, dependencies, or project security?",
    "ja": "こんにちは。情報セキュリティ専門アシスタントの小安です。脆弱性、コードリスク、依存関係、プロジェクトの安全性を分析できます。",
    "ko": "안녕하세요. 정보 보안 전문 어시스턴트 샤오안입니다. 취약점, 코드 위험, 종속성 또는 프로젝트 보안 분석을 도와드릴 수 있습니다.",
}

_PUBLIC_TRACE_STATUSES = {
    "pending",
    "running",
    "started",
    "completed",
    "success",
    "warning",
    "failed",
    "error",
    "cancelled",
    "awaiting-approval",
}
_PRIVATE_TRACE_DETAIL_KEY = re.compile(
    r"(?:system[-_ ]?prompt|prompt|messages?|reasoning|thought|chain[-_ ]?of[-_ ]?thought|scratchpad)",
    flags=re.IGNORECASE,
)
_TRACE_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|authorization|password|secret|token)"
    r"(\s*[:=]\s*[\"']?)([^\"'\s,;&}]+)",
)
_TRACE_BEARER_TOKEN = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_TRACE_API_TOKEN = re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b")


def invoke_assistant_question(
    payload: AskRequest,
    *,
    graph: Any,
    event_sink: Any = None,
    content_sink: Any = None,
    allow_workspace_recovery: bool = False,
) -> dict[str, Any]:
    if _is_local_greeting(payload.question):
        result = _local_greeting_answer(payload.response_language, payload.emoji_mode)
        result["session_id"] = payload.session_id
        if str(payload.session_id or "").startswith("information:"):
            stored = memory_service.add_short_term_exchange(
                payload.user_id,
                payload.session_id,
                payload.question,
                result,
            )
            if isinstance(stored, dict) and stored.get("id"):
                result["exchange_id"] = str(stored["id"])
        else:
            stored = memory_service.add_exchange(
                payload.user_id,
                payload.question,
                result,
                session_id=payload.session_id,
            )
            if isinstance(stored, dict) and stored.get("id"):
                result["exchange_id"] = str(stored["id"])
        return result

    if payload.intent_hint == "recent_high_vulnerability_lookup":
        result = _invoke_recent_high_vulnerability_lookup(payload, event_sink=event_sink)
        if str(payload.session_id or "").startswith("information:"):
            stored = memory_service.add_short_term_exchange(
                payload.user_id,
                payload.session_id,
                payload.question,
                result,
            )
            if isinstance(stored, dict) and stored.get("id"):
                result["exchange_id"] = str(stored["id"])
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
            emoji_mode=payload.emoji_mode,
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
        emoji_mode=payload.emoji_mode,
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


def _is_local_greeting(question: Any) -> bool:
    normalized = re.sub(r"[\s，。！？、,.!?：:；;‘’'\"“”]", "", str(question or "")).casefold()
    return normalized in {
        "你好", "您好", "你们好", "大家好", "嗨", "哈喽", "哈啰", "在吗", "早上好", "下午好", "晚上好",
        "hello", "hi", "hey", "goodmorning", "goodafternoon", "goodevening",
    }


def _local_greeting_answer(response_language: str, emoji_mode: str = "moderate") -> dict[str, Any]:
    language = normalize_language(response_language)
    summary = _LOCAL_GREETINGS.get(language, _LOCAL_GREETINGS["en"])
    if emoji_mode in {"moderate", "active"}:
        summary = f"{summary} 👋"
    return public_answer_payload(
        {
            "mode": "greeting",
            "summary": summary,
            "fields": {},
            "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
            "evidence_sources": [],
            "artifacts": [],
            "confidence": 1.0,
            "token_usage": 0,
            "trace": [
                {
                    "node": "local_greeting",
                    "status": "completed",
                    "message": "已使用本地问候响应，无需调用模型或翻译。",
                    "time": now_iso(),
                }
            ],
            "generated_at": now_iso(),
            "orchestration": {
                "schema_version": "secflow.local-response/v1",
                "architecture": "local-deterministic",
                "agentic": False,
                "visited_agents": [],
                "handoffs": [],
            },
        }
    )


def public_stream_trace_event(item: Any) -> dict[str, Any] | None:
    """Project an internal trace entry onto the bounded public SSE contract."""

    if not isinstance(item, dict):
        return None
    node = _bounded_public_trace_text(item.get("node"), 200)
    if not node:
        return None
    status = str(item.get("status") or "completed").strip().lower()
    if status not in _PUBLIC_TRACE_STATUSES:
        status = "completed"
    event: dict[str, Any] = {"node": node, "status": status}
    for key, limit in (
        ("id", 240),
        ("title", 240),
        ("message", 1_200),
        ("started_at", 80),
        ("completed_at", 80),
        ("time", 80),
        ("tool_name", 200),
    ):
        value = _bounded_public_trace_text(item.get(key), limit)
        if value:
            event[key] = value
    try:
        duration_ms = max(0, int(float(item.get("duration_ms") or 0)))
    except (TypeError, ValueError, OverflowError):
        duration_ms = 0
    if duration_ms:
        event["duration_ms"] = duration_ms

    presentation = item.get("presentation")
    if isinstance(presentation, dict) and presentation.get("kind") == "tool_call":
        raw_input = presentation.get("input")
        input_summary = {
            str(key): value
            for key, value in list(raw_input.items())[:24]
            if not _PRIVATE_TRACE_DETAIL_KEY.search(str(key))
        } if isinstance(raw_input, dict) else {}
        presentation_state = str(presentation.get("state") or status).strip().lower()
        if presentation_state in {"failed", "warning"}:
            presentation_state = "error"
        elif presentation_state not in {"completed", "running", "awaiting-approval", "error"}:
            presentation_state = "completed"
        event["presentation"] = tool_call_presentation(
            str(presentation.get("tool_name") or item.get("tool_name") or item.get("title") or node),
            state=presentation_state,
            title=str(presentation.get("title") or item.get("title") or ""),
            input_summary=input_summary,
            output=presentation.get("output"),
            error=presentation.get("error"),
        )

    # Apply the same provenance scrubber used by final answers. Arbitrary trace
    # fields were never copied, so prompt diffs and model reasoning stay private.
    projected = public_answer_payload({"trace": [event]}).get("trace")
    return projected[0] if isinstance(projected, list) and projected else None


def public_stream_trace_items(value: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in value if isinstance(value, list) else []:
        event = public_stream_trace_event(item)
        if event is None:
            continue
        identity = public_stream_trace_identity(event)
        if identity in seen:
            continue
        seen.add(identity)
        output.append(event)
    return output


def public_stream_trace_identity(item: dict[str, Any]) -> str:
    return json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _bounded_public_trace_text(value: Any, limit: int) -> str:
    text = sanitize_public_text(value).strip()
    text = _TRACE_BEARER_TOKEN.sub(r"\1[REDACTED]", text)
    text = _TRACE_SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    text = _TRACE_API_TOKEN.sub("[REDACTED]", text)
    if len(text) <= limit:
        return text
    cut_at = max(0, limit - 1)
    prefix = text[:cut_at].rstrip()
    if prefix and cut_at < len(text) and prefix[-1].isalnum() and text[cut_at].isalnum():
        boundary = max(prefix.rfind(" "), prefix.rfind("\n"), prefix.rfind("\t"))
        if boundary >= cut_at // 2:
            prefix = prefix[:boundary].rstrip()
    return prefix + "…"


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
                "server": "AegisAl Vulnerability Catalog",
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
        translation_partial = partial_translation_audit_is_publishable(audit)
        if translation_partial:
            translated = partial_translation_payload(
                translated,
                target_language=response_language,
                audit=audit,
                verified_source=answer,
            )
            audit = dict(translated["translation"])
        elif not translation_completed:
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
                ) if translation_completed else (
                    translation_partial_message(response_language)
                    if translation_partial
                    else translation_unavailable_message(response_language)
                ),
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
