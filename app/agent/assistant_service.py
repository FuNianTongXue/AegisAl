from __future__ import annotations

from typing import Any

from app.langgraph.checkpoints import InterruptStateExpiredError
from app.langgraph.component_catalog_graph import (
    component_catalog_outcome_answer,
    component_vulnerability_catalog_subgraph,
)
from app.langgraph.report_graph import report_capability_subgraph, report_outcome_answer
from app.langgraph.sbom_graph import project_sbom_subgraph, sbom_outcome_answer
from app.memory import LongTermMemoryService
from app.models import AssistantInterruptResumeRequest, AskRequest
from app.privacy import public_answer_payload
from app.storage import now_iso


def invoke_assistant_question(payload: AskRequest, *, graph: Any) -> dict[str, Any]:
    return public_answer_payload(
        graph.invoke(
            payload.question,
            payload.top_k,
            user_id=payload.user_id,
            session_id=payload.session_id,
            response_language=payload.response_language,
            attachments=[attachment.model_dump() for attachment in payload.attachments],
        )
    )


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
    memory.update_interrupt_exchange(
        payload.user_id,
        payload.session_id,
        payload.thread_id,
        answer,
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
    "invoke_assistant_question",
    "resume_assistant_operation",
]
