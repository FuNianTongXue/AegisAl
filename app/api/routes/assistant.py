from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse, StreamingResponse

from app.agent.assistant_service import (
    InterruptStateExpiredError,
    assistant_content_chunks,
    expired_assistant_operation,
    invoke_assistant_question,
    resume_assistant_operation,
)
from app.langgraph.assistant_graph import knowledge_graph
from app.langgraph.checkpoints import InterruptStateConflictError
from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor
from app.assistant_artifacts import component_artifact_store, sbom_artifact_store
from app.memory import memory_service
from app.models import (
    ApiResponse,
    AskRequest,
    AssistantConversationArchiveRequest,
    AssistantInterruptResumeRequest,
)
from app.privacy import sanitize_public_text
from app.reports import report_artifact_store


router = APIRouter(prefix="/api/assistant", tags=["assistant"])


def _ok(data: Any = None, message: str = "ok") -> ApiResponse:
    return ApiResponse(status="success", message=message, data=data)


@router.get("/graph", response_model=ApiResponse)
def assistant_graph() -> ApiResponse:
    return _ok(
        assistant_multi_agent_supervisor.graph_spec(knowledge_graph=knowledge_graph),
        "Assistant multi-agent LangGraph loaded.",
    )


@router.post("/questions", response_model=ApiResponse)
def ask(payload: AskRequest) -> ApiResponse:
    return _ok(
        invoke_assistant_question(payload, graph=knowledge_graph),
        "Assistant response generated.",
    )


@router.post("/questions/stream")
async def ask_stream(payload: AskRequest) -> StreamingResponse:
    async def stream():
        queue: asyncio.Queue[tuple[str, dict[str, Any]]] = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def emit_trace(item: dict[str, Any]) -> None:
            del item

        def emit_content(delta: str) -> None:
            del delta

        def run_graph() -> None:
            try:
                result = invoke_assistant_question(
                    payload,
                    graph=knowledge_graph,
                    event_sink=emit_trace,
                    content_sink=emit_content,
                )
                final_trace = result.get("trace") if isinstance(result.get("trace"), list) else []
                for item in final_trace:
                    if isinstance(item, dict):
                        loop.call_soon_threadsafe(queue.put_nowait, ("trace", dict(item)))
                for delta in assistant_content_chunks(str(result.get("summary") or "")):
                    loop.call_soon_threadsafe(queue.put_nowait, ("content", {"delta": delta}))
                loop.call_soon_threadsafe(queue.put_nowait, ("result", result))
            except Exception as exc:  # noqa: BLE001
                message = sanitize_public_text(str(exc)).strip() or "Assistant response generation failed."
                loop.call_soon_threadsafe(queue.put_nowait, ("error", {"message": message}))

        worker = asyncio.create_task(asyncio.to_thread(run_graph))
        try:
            while True:
                try:
                    event_name, data = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"event: {event_name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n"
                if event_name in {"result", "error"}:
                    break
        finally:
            if not worker.done():
                worker.cancel()

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


@router.get("/artifacts/{artifact_id}")
def download_artifact(
    artifact_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
) -> FileResponse:
    path: Path
    try:
        path = component_artifact_store.resolve(artifact_id, user_id=user_id)
        file_name = str(
            component_artifact_store.metadata(artifact_id, user_id=user_id).get("file_name")
            or "SecFlow-component-vulnerabilities.xlsx"
        )
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    except KeyError:
        try:
            path = sbom_artifact_store.resolve(artifact_id, user_id=user_id)
            file_name = str(
                sbom_artifact_store.metadata(artifact_id, user_id=user_id).get("file_name")
                or "SecFlow-project-SBOM.xlsx"
            )
            media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        except KeyError as exc:
            try:
                path, file_name, media_type = report_artifact_store.resolve(
                    artifact_id,
                    user_id=user_id,
                )
            except KeyError:
                raise HTTPException(status_code=404, detail=f"Unknown assistant artifact: {artifact_id}") from exc
    return FileResponse(path, media_type=media_type, filename=file_name, headers={"Cache-Control": "no-store"})


@router.post("/interrupts/resume", response_model=ApiResponse)
def resume_interrupt(payload: AssistantInterruptResumeRequest) -> ApiResponse:
    try:
        outcome = resume_assistant_operation(payload, memory=memory_service)
    except InterruptStateExpiredError:
        return _ok(
            expired_assistant_operation(payload, memory=memory_service),
            "Expired assistant interrupt cleared.",
        )
    except InterruptStateConflictError as exc:
        raise HTTPException(status_code=409, detail="该确认卡片已失效，流程已进入下一阶段，请刷新当前对话。") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="该确认卡片不属于当前会话或已失效，请切换到发起任务的对话后重试。") from exc
    return _ok(outcome, "Assistant interrupt resumed.")


@router.get("/conversations", response_model=ApiResponse)
def list_conversations(
    user_id: str = Query(default="default", min_length=1, max_length=120),
    limit: int = Query(default=30, ge=1, le=100),
    archived: bool = False,
) -> ApiResponse:
    return _ok(memory_service.list_conversations(user_id, limit=limit, archived=archived), "Conversations loaded.")


@router.get("/conversations/{session_id}", response_model=ApiResponse)
def conversation_detail(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
) -> ApiResponse:
    _validate_session_id(session_id)
    try:
        return _ok(memory_service.get_conversation(user_id, session_id), "Conversation loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc


@router.post("/conversations/{session_id}/archive", response_model=ApiResponse)
def archive_conversation(
    session_id: str,
    payload: AssistantConversationArchiveRequest,
    user_id: str = Query(default="default", min_length=1, max_length=120),
) -> ApiResponse:
    _validate_session_id(session_id)
    try:
        conversation = memory_service.archive_conversation(user_id, session_id, payload.archived)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc
    return _ok(conversation, "Conversation archived." if payload.archived else "Conversation restored.")


@router.delete("/conversations/{session_id}", response_model=ApiResponse)
def delete_conversation(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
) -> ApiResponse:
    _validate_session_id(session_id)
    try:
        return _ok(memory_service.delete_conversation(user_id, session_id), "Conversation deleted.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc


@router.delete("/short-term-sessions/{session_id}", response_model=ApiResponse)
def clear_short_term_session(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
) -> ApiResponse:
    _validate_session_id(session_id)
    if not session_id.startswith("information:"):
        raise HTTPException(status_code=422, detail="Invalid short-term consultation session.")
    return _ok(
        memory_service.clear_short_term_session(user_id, session_id),
        "Short-term consultation cleared.",
    )


def _validate_session_id(session_id: str) -> None:
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
