from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import date
from pathlib import Path
from urllib.parse import quote
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import ValidationError

from app.collectors import collector_graph, collector_service
from app.assistant_artifacts import component_artifact_store, sbom_artifact_store
from app.langgraph.assistant_graph import knowledge_graph, runtime_status
from app.information import information_service, load_information_image, load_information_source_image
from app.llm import list_llm_models, llm_public_config, save_llm_config, test_llm_config
from app.intelligence import intelligence_service
from app.memory import memory_service
from app.model_usage import model_usage_service
from app.models import (
    AgentTaskArchiveRequest,
    AgentTaskCreateRequest,
    AgentTaskReportDecisionRequest,
    AgentTaskReportDownloadDecisionRequest,
    AssistantInterruptResumeRequest,
    AssistantTaskActionRequest,
    AssistantWorkspaceActionRequest,
    AssistantConversationArchiveRequest,
    AssistantStructuredDataEditRequest,
    ApiResponse,
    AppPreferenceSettingsUpdate,
    AskRequest,
    AvatarUploadRequest,
    CollectorConfigUpdate,
    ComponentVulnerabilityRequest,
    DashboardRefreshRequest,
    InformationSourceUpdate,
    InformationSourcesUpdate,
    IntelligenceQueryRequest,
    LegalDocumentUpdate,
    LLMConfigRequest,
    LLMModelsRequest,
    MemoryClearRequest,
    ReportDeleteRequest,
    ReportActionRequest,
    ReportActionResumeRequest,
    SubscriptionCancelRequest,
    SubscriptionCheckoutRequest,
    SubscriptionPaymentEvent,
    UserProfileSettingsUpdate,
    VulnerabilityComponentExportRequest,
)
from app.privacy import public_answer_payload, sanitize_public_text
from app.capabilities import built_in_capability_catalog
from app.composition import secflow_runtime, shutdown_secflow_runtime
from app.mcp.protocol import MCP_PLUGIN_ID, MCP_SERVER_REGISTRY, MCPServerDefinition
from app.langgraph.report_graph import report_capability_subgraph, report_outcome_answer
from app.langgraph.component_catalog_graph import (
    component_catalog_outcome_answer,
    component_vulnerability_catalog_subgraph,
)
from app.langgraph.sbom_graph import project_sbom_subgraph, sbom_outcome_answer
from app.langgraph.checkpoints import InterruptStateConflictError, InterruptStateExpiredError
from app.agent.assistant_intent import plan_assistant_intent
from app.agent.assistant_service import (
    assistant_content_chunks as _assistant_content_chunks,
    invoke_assistant_question,
    invoke_assistant_task_action,
    invoke_assistant_workspace_action,
    public_stream_trace_event,
    public_stream_trace_identity,
    public_stream_trace_items,
    resume_assistant_operation,
    translate_assistant_answer,
)
from app.reports import report_artifact_store, report_store
from app.settings import (
    APP_VERSION,
    avatar_response,
    delete_profile_avatar,
    get_legal_document,
    get_legal_documents,
    get_preference_settings,
    get_profile_settings,
    public_settings_snapshot,
    save_profile_avatar,
    update_legal_document,
    update_preference_settings,
    update_profile_settings,
)
from app.agent.task_agent import task_agent_service
from app.storage import now_iso
from app.trial import trial_manager
from app.subscriptions import SubscriptionServiceError, subscription_service


MACOS_API_CONTRACT_VERSION = "2026-07-subscriptions-v1"
MCP_LOCAL_TRANSPORT = "stdio"
MCP_LOCAL_ISOLATION = "host-managed-child-process"
COMPONENT_MCP_SERVER_IDS = ("component-detail", "excel", "d3-sankey")
REPORT_MCP_SERVER_IDS = (
    "translation",
    "report-template",
    "report-chart",
    "report-sarif",
    "report-mermaid",
    "report-markdown",
    "report-word",
    "report-excel",
    "report-pdf",
)

app = FastAPI(
    title="AegisAl",
    version=APP_VERSION,
    description="A source-available LangGraph security agent by ShenSiQi.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:1420",
        "http://localhost:1420",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "tauri://localhost",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type", "Last-Event-ID", "X-Request-ID"],
)
@app.middleware("http")
async def enforce_trial_period(request: Request, call_next):
    request_id = str(request.headers.get("X-Request-ID") or uuid4())[:120]
    trial_exempt = request.url.path == "/api/trial/status" or request.url.path.startswith("/api/subscriptions")
    if request.url.path.startswith("/api/") and not trial_exempt:
        trial = trial_manager.status()
        if not trial["usable"]:
            return JSONResponse(
                status_code=403,
                content={
                    "status": "error",
                    "message": trial["message"],
                    "data": {"trial": trial},
                },
                headers={"Cache-Control": "no-store", "X-Request-ID": request_id},
            )
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


@app.on_event("startup")
def startup_batch_jobs() -> None:
    secflow_runtime()
    report_store.sanitize_existing_reports()
    task_agent_service.start()
    if os.getenv("SECFLOW_DISABLE_BATCH_SCHEDULER", "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    intelligence_service.start_batch_scheduler()


@app.on_event("shutdown")
def shutdown_batch_jobs() -> None:
    try:
        intelligence_service.stop_batch_scheduler()
    finally:
        try:
            task_agent_service.shutdown()
        finally:
            shutdown_secflow_runtime()


def ok(data=None, message: str = "ok") -> ApiResponse:
    return ApiResponse(status="success", message=message, data=data)


def _registered_mcp_server_specs(server_ids: tuple[str, ...]) -> list[dict[str, object]]:
    runtime = secflow_runtime()
    with runtime.pin(MCP_PLUGIN_ID) as snapshot:
        registry = snapshot.registries.get(MCP_SERVER_REGISTRY, {})
        specs: list[dict[str, object]] = []
        for server_id in server_ids:
            entry = registry.get(server_id)
            if entry is None or not isinstance(entry.value, MCPServerDefinition):
                raise RuntimeError(f"Registered MCP server is unavailable: {server_id}")
            specs.append(entry.value.as_dict())
        return specs


@app.get("/")
def root():
    return {
        "service": "aegisal",
        "client": "AegisAl Tauri Desktop",
        "api_docs": "/docs",
    }


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "aegisal",
        "contract_version": MACOS_API_CONTRACT_VERSION,
        "author": "ShenSiQi",
        "startup_token": os.getenv("SECFLOW_BACKEND_STARTUP_TOKEN", ""),
        "task_execution": task_agent_service.execution_status(),
    }


@app.get("/api/trial/status", response_model=ApiResponse)
def trial_status():
    return ok(trial_manager.status(), "Trial status loaded.")


@app.get("/api/config", response_model=ApiResponse)
def config(user_id: str = "default"):
    snapshot = collector_service.snapshot()
    snapshot["runtime"] = runtime_status(user_id)
    return ok(snapshot, "Configuration loaded.")


@app.get("/api/settings", response_model=ApiResponse)
def settings_snapshot(user_id: str = "default"):
    return ok(public_settings_snapshot(user_id), "Settings loaded.")


@app.get("/api/settings/profile", response_model=ApiResponse)
def settings_profile(user_id: str = "default"):
    return ok(get_profile_settings(user_id), "Profile settings loaded.")


@app.patch("/api/settings/profile", response_model=ApiResponse)
def update_settings_profile(payload: UserProfileSettingsUpdate, user_id: str = "default"):
    return ok(update_profile_settings(payload.model_dump(), user_id), "Profile settings saved.")


@app.post("/api/settings/profile/avatar", response_model=ApiResponse)
def upload_settings_profile_avatar(payload: AvatarUploadRequest, user_id: str = "default"):
    try:
        return ok(
            save_profile_avatar(
                payload.file_name,
                payload.content_base64,
                payload.content_type or "",
                user_id,
            ),
            "Profile avatar uploaded.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/settings/profile/avatar", response_model=ApiResponse)
def remove_settings_profile_avatar(user_id: str = "default"):
    return ok(delete_profile_avatar(user_id), "Profile avatar removed.")


@app.get("/api/settings/profile/avatar")
def settings_profile_avatar(user_id: str = "default"):
    try:
        return avatar_response(user_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Profile avatar not found.") from exc


@app.get("/api/settings/preferences", response_model=ApiResponse)
def settings_preferences():
    return ok(get_preference_settings(), "Preference settings loaded.")


@app.patch("/api/settings/preferences", response_model=ApiResponse)
def update_settings_preferences(payload: AppPreferenceSettingsUpdate):
    return ok(update_preference_settings(payload.model_dump()), "Preference settings saved.")


@app.get("/api/settings/legal", response_model=ApiResponse)
def settings_legal_documents():
    return ok(get_legal_documents(), "Legal documents loaded.")


@app.get("/api/settings/legal/{document_id}", response_model=ApiResponse)
def settings_legal_document(document_id: str):
    try:
        return ok(get_legal_document(document_id), "Legal document loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown legal document: {document_id}") from exc


@app.patch("/api/settings/legal/{document_id}", response_model=ApiResponse)
def update_settings_legal_document(document_id: str, payload: LegalDocumentUpdate):
    try:
        return ok(
            update_legal_document(document_id, payload.model_dump(exclude_unset=True)),
            "Legal document saved.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown legal document: {document_id}") from exc


@app.get("/api/subscriptions/plans", response_model=ApiResponse)
def subscription_plans():
    return ok(subscription_service.plans(), "Subscription plans loaded.")


@app.get("/api/subscriptions/current", response_model=ApiResponse)
def current_subscription(user_id: str = "local-user"):
    try:
        return ok(subscription_service.current(user_id), "Current subscription loaded.")
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.get("/api/subscriptions/usage", response_model=ApiResponse)
def subscription_usage(user_id: str = "local-user"):
    try:
        return ok(subscription_service.usage(user_id), "Subscription usage loaded.")
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.get("/api/subscriptions/orders", response_model=ApiResponse)
def subscription_orders(user_id: str = "local-user", limit: int = 50):
    try:
        return ok(subscription_service.orders(user_id, limit), "Subscription orders loaded.")
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/subscriptions/checkout", response_model=ApiResponse)
def subscription_checkout(payload: SubscriptionCheckoutRequest):
    try:
        result = subscription_service.checkout(
            user_id=payload.user_id,
            plan_id=payload.plan_id,
            payment_method=payload.payment_method,
            idempotency_key=payload.idempotency_key,
        )
        return ok(result, result["message"])
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/subscriptions/cancel", response_model=ApiResponse)
def cancel_subscription(payload: SubscriptionCancelRequest):
    try:
        return ok(
            subscription_service.cancel(payload.user_id, payload.reason),
            "已取消自动续费，当前权益可使用至本周期结束。",
        )
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.post("/api/subscriptions/payment-events", response_model=ApiResponse)
async def subscription_payment_event(request: Request):
    raw_body = await request.body()
    try:
        payload_digest = subscription_service.verify_webhook_signature(
            raw_body,
            request.headers.get("X-SecFlow-Signature"),
        )
        event = SubscriptionPaymentEvent.model_validate_json(raw_body)
        result = subscription_service.process_payment_event(event.model_dump(), payload_digest)
        message = "Payment event already processed." if result["duplicate"] else "Payment event processed."
        return ok(result, message)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail="支付事件格式无效") from exc
    except SubscriptionServiceError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@app.patch("/api/config/{collector_id}", response_model=ApiResponse)
def update_config(collector_id: str, payload: CollectorConfigUpdate):
    try:
        return ok(collector_service.update_config(collector_id, payload), "Collector configuration saved.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.post("/api/config/{collector_id}/test", response_model=ApiResponse)
def test_config(collector_id: str):
    try:
        result = collector_service.test_config(collector_id)
        return ok(result, result.get("message", "Collector test finished."))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.post("/api/collect/{collector_id}", response_model=ApiResponse)
def collect(collector_id: str):
    try:
        result = collector_service.collect(collector_id)
        return ok(result, result.get("message", "Collection finished."))
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown collector: {collector_id}") from exc


@app.get("/api/vulnerabilities", response_model=ApiResponse)
def vulnerabilities(
    query: str = Query(default="", max_length=160),
    response_language: str = Query(default="zh-Hans", max_length=24),
):
    try:
        clean_query = " ".join(query.split()) if isinstance(query, str) else ""
        if clean_query:
            result = intelligence_service.query(
                clean_query,
                limit=50,
                response_language=response_language,
            )
            records = list(result.get("records") or [])
            severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for record in records:
                severity = str(record.get("severity") or "").upper()
                if severity in severity_counts:
                    severity_counts[severity] += 1
            translation = dict(result.get("catalog_translation") or {})
            ready_count = int(translation.get("ready_records") or 0)
            total_count = len(records)
            translation_progress = 100 if not total_count else int((ready_count / total_count) * 100)
            return ok(
                {
                    "records": records,
                    "stats": {
                        "total": total_count,
                        "critical": severity_counts["CRITICAL"],
                        "high": severity_counts["HIGH"],
                        "medium": severity_counts["MEDIUM"],
                        "low": severity_counts["LOW"],
                    },
                    "query": clean_query,
                    "response_language": response_language,
                    "catalog_translation": translation,
                    "translation_status": str(translation.get("status") or "pending"),
                    "translation_progress": translation_progress,
                    "translation_count": total_count,
                    "translation_ready_count": ready_count,
                },
                "Matching vulnerability records loaded.",
            )
        snapshot = intelligence_service.dashboard(response_language=response_language)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    severity = dict(snapshot.get("severity") or {})
    return ok(
        {
            "records": list(snapshot.get("recent_records") or []),
            "stats": {
                "total": int(snapshot.get("vulnerability_count") or 0),
                "critical": int(severity.get("CRITICAL") or 0),
                "high": int(severity.get("HIGH") or 0),
                "medium": int(severity.get("MEDIUM") or 0),
                "low": int(severity.get("LOW") or 0),
            },
            "response_language": str(snapshot.get("response_language") or response_language),
            "catalog_translation": dict(snapshot.get("catalog_translation") or {}),
            "translation_status": str(snapshot.get("translation_status") or "pending"),
            "translation_progress": int(snapshot.get("translation_progress") or 0),
            "translation_count": int(snapshot.get("translation_count") or 0),
            "translation_ready_count": int(snapshot.get("translation_ready_count") or 0),
        },
        "Localized vulnerability records loaded.",
    )


@app.get("/api/dashboard", response_model=ApiResponse)
def dashboard(
    start_date: date | None = None,
    end_date: date | None = None,
    response_language: str = Query(default="zh-Hans", max_length=24),
    refresh: bool = Query(default=False),
):
    try:
        return ok(
            intelligence_service.dashboard(
                start_date=start_date,
                end_date=end_date,
                response_language=response_language,
                force_refresh=refresh,
            ),
            "Dashboard batch snapshot loaded.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/dashboard/refresh", response_model=ApiResponse)
def refresh_dashboard(payload: DashboardRefreshRequest | None = None):
    payload = payload or DashboardRefreshRequest()
    try:
        result = intelligence_service.refresh_dashboard_batch(
            start_date=payload.start_date,
            end_date=payload.end_date,
        )
        return ok(result, "Dashboard batch snapshot refreshed.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/intelligence/sources", response_model=ApiResponse)
def intelligence_sources():
    return ok(intelligence_service.sources_status(), "Intelligence query sources loaded.")


@app.get("/api/intelligence/recent", response_model=ApiResponse)
def recent_intelligence():
    return ok(intelligence_service.recent(), "Recent intelligence queries loaded.")


@app.get("/api/information", response_model=ApiResponse)
def information(
    query: str = "",
    category: str = "全部",
    sort: str = "latest",
    limit: int = 80,
    refresh: bool = False,
    response_language: str = Query(default="zh-Hans", max_length=24),
):
    try:
        return ok(
            information_service.snapshot(
                query=query,
                category=category,
                sort=sort,
                limit=max(1, min(limit, 200)),
                refresh=refresh,
                response_language=response_language,
            ),
            "Public security information loaded from source feeds.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/information/refresh", response_model=ApiResponse)
def refresh_information(
    response_language: str = Query(default="zh-Hans", max_length=24),
):
    try:
        return ok(
            information_service.request_refresh(
                force=True,
                response_language=response_language,
            ),
            "Public security information refresh started.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/information/images/{item_id}")
def information_image(item_id: str):
    try:
        result = load_information_image(item_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Information item not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return Response(
        content=result.data,
        media_type=result.content_type,
        headers={
            "Cache-Control": "public, max-age=86400, stale-if-error=604800",
            "ETag": f'"{result.etag}"',
            "X-SecFlow-Image-Kind": result.kind,
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get("/api/information/source-images/{source_id}")
def information_source_image(source_id: str):
    try:
        result = load_information_source_image(source_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Information source not found.") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return Response(
        content=result.data,
        media_type=result.content_type,
        headers={
            "Cache-Control": "public, max-age=86400, stale-if-error=604800",
            "ETag": f'"{result.etag}"',
            "X-SecFlow-Image-Kind": "source",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.patch("/api/information/sources/{source_id}", response_model=ApiResponse)
def update_information_source(source_id: str, payload: InformationSourceUpdate):
    try:
        return ok(
            information_service.set_source_enabled(source_id, payload.enabled),
            "Information source subscription updated.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown information source: {source_id}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.patch("/api/information/sources", response_model=ApiResponse)
def update_information_sources(payload: InformationSourcesUpdate):
    try:
        return ok(
            information_service.set_sources_enabled(payload.source_ids, payload.enabled),
            "Information source subscriptions updated.",
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown information source: {exc.args[0]}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/information/sources/{source_id}/test", response_model=ApiResponse)
def test_information_source(source_id: str):
    try:
        return ok(information_service.test_source(source_id), "Information source connection tested.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown information source: {source_id}") from exc


@app.post("/api/intelligence/query", response_model=ApiResponse)
def query_intelligence(payload: IntelligenceQueryRequest):
    try:
        result = intelligence_service.query(
            payload.query,
            limit=payload.limit,
            sources=payload.sources,
            response_language=payload.response_language or "zh-Hans",
        )
        return ok(result, "API intelligence query and graph enrichment completed.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/intelligence/components/query", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/components/vulnerabilities/query", response_model=ApiResponse)
def query_component_vulnerabilities(payload: ComponentVulnerabilityRequest):
    try:
        result = intelligence_service.query_component_vulnerabilities(
            payload.name,
            payload.version,
            ecosystem=payload.ecosystem or "",
            include_realtime=payload.include_realtime,
        )
        return ok(result, "Component vulnerability query completed.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/intelligence/components/export", include_in_schema=False)
@app.post("/api/components/vulnerabilities/export")
def export_component_vulnerabilities(payload: ComponentVulnerabilityRequest):
    try:
        content, metadata = intelligence_service.export_component_vulnerabilities(
            payload.name,
            payload.version,
            ecosystem=payload.ecosystem or "",
            include_realtime=payload.include_realtime,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    stem_parts = ["secflow", metadata.get("ecosystem") or "auto", metadata["name"], metadata["version"], "vulnerabilities"]
    stem = "-".join(re.sub(r"[^A-Za-z0-9._-]+", "-", str(part)).strip("-") or "component" for part in stem_parts)
    filename = f"{stem[:180]}.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename={quote(filename)}; filename*=UTF-8''{quote(filename)}",
            "X-SecFlow-Record-Count": str(metadata["total"]),
            "Cache-Control": "no-store",
        },
    )


@app.get("/api/mcp/component-query", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/mcp/tools/component-query", response_model=ApiResponse)
async def component_query_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "servers": _registered_mcp_server_specs(COMPONENT_MCP_SERVER_IDS),
        },
        "Component query MCP tools loaded.",
    )


@app.get("/api/mcp/tools/code-scan", response_model=ApiResponse)
async def code_scan_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "server": _registered_mcp_server_specs(("code-scan",))[0],
        },
        "Independent Code Scan MCP stdio tools loaded.",
    )


@app.get("/api/mcp/tools/license-scan", response_model=ApiResponse)
async def license_scan_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "server": _registered_mcp_server_specs(("license-scan",))[0],
        },
        "Independent License MCP tools loaded.",
    )


@app.get("/api/mcp/tools/project-sbom", response_model=ApiResponse)
async def project_sbom_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "servers": _registered_mcp_server_specs(("sbom-excel",)),
        },
        "Project SBOM MCP tools loaded.",
    )


@app.get("/api/mcp/tools/translation", response_model=ApiResponse)
async def translation_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "server": _registered_mcp_server_specs(("translation",))[0],
        },
        "Translation MCP tools loaded.",
    )


@app.get("/api/mcp/report-charts", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/mcp/tools/report-charts", response_model=ApiResponse)
@app.get("/api/mcp/tools/reports", response_model=ApiResponse)
async def report_chart_mcp_tools():
    return ok(
        {
            "transport": MCP_LOCAL_TRANSPORT,
            "isolation": MCP_LOCAL_ISOLATION,
            "servers": _registered_mcp_server_specs(REPORT_MCP_SERVER_IDS),
        },
        "Report template, chart, Mermaid, Markdown, Word, Excel, and PDF MCP tools loaded.",
    )


@app.get("/api/system/capabilities", response_model=ApiResponse)
async def system_capabilities():
    return ok(await built_in_capability_catalog(), "Built-in Agent, MCP and Skill capabilities loaded.")


@app.get("/api/assistant/artifacts/{artifact_id}")
def download_assistant_artifact(
    artifact_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    try:
        path = component_artifact_store.resolve(artifact_id, user_id=user_id)
        file_name = str(
            component_artifact_store.metadata(artifact_id, user_id=user_id).get("file_name")
            or "AegisAl-component-vulnerabilities.xlsx"
        )
        media_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    except KeyError:
        try:
            path = sbom_artifact_store.resolve(artifact_id, user_id=user_id)
            file_name = str(
                sbom_artifact_store.metadata(artifact_id, user_id=user_id).get("file_name")
                or "AegisAl-project-SBOM.xlsx"
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
    return FileResponse(
        path,
        media_type=media_type,
        filename=file_name,
        headers={"Cache-Control": "no-store"},
    )


@app.post("/api/intelligence/vulnerabilities/export", include_in_schema=False)
@app.post("/api/vulnerabilities/components/export")
def export_vulnerability_components(payload: VulnerabilityComponentExportRequest):
    try:
        content, metadata = intelligence_service.export_vulnerability_components(payload.identifier)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", str(metadata["identifier"])).strip("-") or "vulnerability"
    filename = f"AegisAl-{stem[:120]}-component-ranges.xlsx"
    return Response(
        content=content,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f"attachment; filename={quote(filename)}; filename*=UTF-8''{quote(filename)}",
            "X-SecFlow-Record-Count": str(metadata["total"]),
            "X-SecFlow-Component-Count": str(metadata["component_count"]),
            "Cache-Control": "no-store",
        },
    )


@app.post("/api/knowledge-graph/query", response_model=ApiResponse)
def query_knowledge_graph(payload: IntelligenceQueryRequest):
    try:
        result = intelligence_service.query(
            payload.query,
            limit=payload.limit,
            sources=payload.sources,
            response_language=payload.response_language or "zh-Hans",
        )
        return ok(result["graph"], "Knowledge graph enriched from upstream API intelligence.")
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/ask", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/assistant/questions", response_model=ApiResponse)
def ask(payload: AskRequest):
    return ok(
        invoke_assistant_question(
            payload,
            graph=knowledge_graph,
            allow_workspace_recovery=True,
        ),
        "Assistant response generated.",
    )


@app.post("/api/ask/stream", include_in_schema=False)
@app.post("/api/assistant/questions/stream")
async def ask_stream(payload: AskRequest):
    async def stream():
        queue: asyncio.Queue[tuple[str, dict]] = asyncio.Queue()
        loop = asyncio.get_running_loop()
        emitted_trace: set[str] = set()

        def enqueue(event_name: str, data: dict) -> None:
            try:
                loop.call_soon_threadsafe(queue.put_nowait, (event_name, data))
            except RuntimeError:
                # The client may disconnect while the worker thread is finishing.
                pass

        def emit_trace(item: dict) -> None:
            event = public_stream_trace_event(item)
            if event is None:
                return
            identity = public_stream_trace_identity(event)
            if identity in emitted_trace:
                return
            emitted_trace.add(identity)
            enqueue("trace", event)

        def emit_content(delta: str) -> None:
            # Model deltas are untrusted until translation/publication policy has
            # accepted the complete answer. Only final accepted chunks are sent.
            del delta

        def run_graph() -> None:
            try:
                result = invoke_assistant_question(
                    payload,
                    graph=knowledge_graph,
                    event_sink=emit_trace,
                    content_sink=emit_content,
                    allow_workspace_recovery=True,
                )
                result = dict(result)
                final_trace = public_stream_trace_items(result.get("trace"))
                result["trace"] = final_trace
                for item in final_trace:
                    emit_trace(item)
                for delta in _assistant_content_chunks(str(result.get("summary") or "")):
                    enqueue("content", {"delta": delta})
                enqueue("result", result)
            except Exception as exc:  # noqa: BLE001 - stream failures must be delivered to the client.
                message = sanitize_public_text(str(exc)).strip() or "Assistant response generation failed."
                enqueue("error", {"message": message})

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


@app.get("/api/tasks/graph", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/agent/tasks/graph", response_model=ApiResponse)
def task_agent_graph():
    return ok(task_agent_service.graph.graph_spec(), "Task agent graph loaded.")


@app.post("/api/tasks", response_model=ApiResponse, status_code=202, include_in_schema=False)
@app.post("/api/agent/tasks", response_model=ApiResponse, status_code=202)
def create_agent_task(payload: AgentTaskCreateRequest):
    try:
        return ok(
            task_agent_service.create(
                objective=payload.objective,
                workspace_path=payload.workspace_path,
                user_id=payload.user_id,
            ),
            "Agent task created.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/assistant/workspace-actions", response_model=ApiResponse)
def start_assistant_workspace_action(payload: AssistantWorkspaceActionRequest):
    """Route an authorized workspace objective by semantic intent before starting a scan."""

    try:
        result = invoke_assistant_workspace_action(
            payload,
            graph=knowledge_graph,
            task_service=task_agent_service,
            planner=plan_assistant_intent,
        )
        return ok(
            result,
            "Workspace action delegated to the multi-agent supervisor.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/assistant/tasks/{task_id}/actions", response_model=ApiResponse)
def start_assistant_task_action(task_id: str, payload: AssistantTaskActionRequest):
    """Route a follow-up or user-level rescan against persisted task evidence."""

    task = _owned_agent_task(task_id, payload.user_id)
    try:
        return ok(
            invoke_assistant_task_action(
                payload,
                task=task,
                graph=knowledge_graph,
                task_service=task_agent_service,
                planner=plan_assistant_intent,
            ),
            "Task action delegated to the multi-agent supervisor.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.get("/api/tasks", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/agent/tasks", response_model=ApiResponse)
def agent_tasks(user_id: str = "default", limit: int = 30, archived: bool = False):
    return ok(
        task_agent_service.list(user_id, max(1, min(limit, 100)), archived=archived),
        "Agent tasks loaded.",
    )


@app.get("/api/tasks/{task_id}", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/agent/tasks/{task_id}", response_model=ApiResponse)
def agent_task(task_id: str, user_id: str = "default"):
    return ok(_owned_agent_task(task_id, user_id), "Agent task loaded.")


@app.post("/api/tasks/{task_id}/cancel", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/agent/tasks/{task_id}/cancel", response_model=ApiResponse)
def cancel_agent_task(task_id: str, user_id: str = "default"):
    _owned_agent_task(task_id, user_id)
    return ok(task_agent_service.cancel(task_id), "Agent task cancellation requested.")


@app.post("/api/tasks/{task_id}/resume", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/agent/tasks/{task_id}/resume", response_model=ApiResponse)
def resume_agent_task(task_id: str, user_id: str = "default"):
    _owned_agent_task(task_id, user_id)
    return ok(task_agent_service.resume(task_id), "Agent task resumed.")


@app.post("/api/tasks/{task_id}/archive", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/agent/tasks/{task_id}/archive", response_model=ApiResponse)
def archive_agent_task(
    task_id: str,
    payload: AgentTaskArchiveRequest,
    user_id: str = "default",
):
    _owned_agent_task(task_id, user_id)
    try:
        task = task_agent_service.archive(task_id, archived=payload.archived)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    message = "Agent task archived." if payload.archived else "Agent task restored."
    return ok(task, message)


@app.delete("/api/tasks/{task_id}", response_model=ApiResponse, include_in_schema=False)
@app.delete("/api/agent/tasks/{task_id}", response_model=ApiResponse)
def delete_agent_task(task_id: str, user_id: str = "default"):
    _owned_agent_task(task_id, user_id)
    try:
        task_agent_service.delete(task_id)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ok({"id": task_id, "deleted": True}, "Agent task deleted.")


@app.post("/api/tasks/{task_id}/report-decision", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/agent/tasks/{task_id}/report-decision", response_model=ApiResponse)
def decide_agent_task_report(
    task_id: str,
    payload: AgentTaskReportDecisionRequest,
    user_id: str = "default",
):
    _owned_agent_task(task_id, user_id)
    try:
        task = task_agent_service.decide_report(
            task_id,
            generate=payload.generate,
            report_store=report_store,
            response_language=payload.response_language,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    message = "Agent task report generated." if payload.generate else "Agent task report skipped."
    return ok(task, message)


@app.post("/api/tasks/{task_id}/report-download-decision", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/agent/tasks/{task_id}/report-download-decision", response_model=ApiResponse)
def decide_agent_task_report_download(
    task_id: str,
    payload: AgentTaskReportDownloadDecisionRequest,
    user_id: str = "default",
):
    _owned_agent_task(task_id, user_id)
    try:
        result = task_agent_service.decide_report_download(
            task_id,
            confirm=payload.confirm,
            report_format=payload.format,
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return ok(result, "Agent task report download decision completed.")


@app.get("/api/tasks/{task_id}/events", include_in_schema=False)
@app.get("/api/agent/tasks/{task_id}/events")
async def agent_task_events(
    task_id: str,
    request: Request,
    user_id: str = "default",
    after: int = 0,
):
    _owned_agent_task(task_id, user_id)

    last_event_id = str(request.headers.get("Last-Event-ID") or "").strip()
    try:
        resume_sequence = int(last_event_id) if last_event_id else 0
    except ValueError:
        resume_sequence = 0

    async def stream():
        sequence = max(0, after, resume_sequence)
        idle_ticks = 0
        while True:
            try:
                task, events = task_agent_service.event_stream_snapshot(task_id, after=sequence)
            except KeyError:
                yield "event: error\ndata: {\"message\": \"Agent task not found.\"}\n\n"
                break
            for event in events:
                sequence = max(sequence, int(event.get("sequence") or 0))
                yield f"id: {sequence}\nevent: {event.get('type', 'message')}\ndata: {json.dumps(event, ensure_ascii=False)}\n\n"
            if events:
                idle_ticks = 0
            report_running = str(task.get("report_decision") or "") == "generating"
            if (
                task.get("status") in {"completed", "failed", "cancelled", "interrupted"}
                and not report_running
                and not events
            ):
                break
            idle_ticks += 1
            if idle_ticks % 30 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(0.5)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )


def _owned_agent_task(task_id: str, user_id: str) -> dict:
    try:
        task = task_agent_service.get(task_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Agent task not found.") from exc
    if str(task.get("user_id") or "default") != (user_id or "default"):
        raise HTTPException(status_code=404, detail="Agent task not found.")
    return task


@app.get("/api/graph", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/langgraph/assistant", response_model=ApiResponse)
def graph():
    from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor

    return ok(
        assistant_multi_agent_supervisor.graph_spec(
            knowledge_graph=knowledge_graph,
            task_graph=task_agent_service.graph,
        ),
        "Multi-agent LangGraph specification loaded.",
    )


@app.get("/api/collector-graph", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/langgraph/collectors", response_model=ApiResponse)
def collector_graph_spec():
    return ok(collector_graph.graph_spec(), "Collector subgraph specification loaded.")


@app.get("/api/runtime", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/system/runtime", response_model=ApiResponse)
def runtime(user_id: str = "default"):
    return ok(runtime_status(user_id), "Runtime status loaded.")


@app.get("/api/reports", response_model=ApiResponse)
def reports():
    return ok(report_store.list_reports(), "Analysis reports loaded.")


@app.post("/api/report-actions", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/reports/actions", response_model=ApiResponse)
def start_report_action(payload: ReportActionRequest):
    outcome = report_capability_subgraph.start(payload.model_dump())
    answer = translate_assistant_answer(
        report_outcome_answer(outcome),
        response_language=str(outcome.get("response_language") or payload.response_language),
        user_id=payload.user_id,
        session_id=payload.session_id,
        content_scope="report_action_start",
    )
    return ok({**outcome, "answer": answer}, "Report action started.")


@app.post("/api/report-actions/resume", response_model=ApiResponse, include_in_schema=False)
@app.post("/api/reports/actions/resume", response_model=ApiResponse)
def resume_report_action(payload: ReportActionResumeRequest):
    try:
        outcome = report_capability_subgraph.resume(
            payload.thread_id,
            decision=payload.decision,
            user_id=payload.user_id,
            session_id=payload.session_id,
            report_format=payload.format or "",
            interrupt_id=payload.interrupt_id,
        )
    except (InterruptStateExpiredError, InterruptStateConflictError) as exc:
        raise HTTPException(status_code=409, detail="该报告确认已过期或流程已进入下一阶段，请刷新后重试。") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="该确认卡片不属于当前会话或已失效，请切换到发起扫描的对话后重试。") from exc
    answer = translate_assistant_answer(
        report_outcome_answer(outcome),
        response_language=str(outcome.get("response_language") or payload.response_language),
        user_id=payload.user_id,
        session_id=payload.session_id,
        content_scope="report_action_resume",
    )
    return ok({**outcome, "answer": answer}, "Report action resumed.")


@app.post("/api/assistant/interrupts/resume", response_model=ApiResponse)
def resume_assistant_interrupt(payload: AssistantInterruptResumeRequest):
    try:
        result = resume_assistant_operation(payload, memory=memory_service)
    except InterruptStateExpiredError:
        return _expired_assistant_interrupt_response(payload)
    except InterruptStateConflictError as exc:
        raise HTTPException(status_code=409, detail="该确认卡片已失效，流程已进入下一阶段，请刷新当前对话。") from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="该确认卡片不属于当前会话或已失效，请切换到发起任务的对话后重试。") from exc
    return ok(result, "Assistant interrupt resumed.")


def _expired_assistant_interrupt_response(payload: AssistantInterruptResumeRequest) -> ApiResponse:
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
    memory_service.update_interrupt_exchange(
        payload.user_id,
        payload.session_id,
        payload.thread_id,
        answer,
    )
    return ok(
        {
            "status": "expired",
            "thread_id": payload.thread_id,
            "interrupt": None,
            "summary": summary,
            "report": None,
            "artifacts": [],
            "error": "",
            "answer": answer,
        },
        "Expired assistant interrupt cleared.",
    )


@app.delete("/api/reports", response_model=ApiResponse)
def delete_reports(payload: ReportDeleteRequest):
    result = report_store.delete_reports(payload.report_ids)
    return ok(result, f"Deleted {result['deleted']} analysis reports.")


@app.get("/api/reports/{report_id}/download")
def download_report(report_id: str, format: str = "md"):
    try:
        path, file_name, media_type = report_store.resolve_download(report_id, format)
        return FileResponse(
            path,
            media_type=media_type,
            filename=file_name,
            headers={"Cache-Control": "no-store"},
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown report: {report_id}") from exc


@app.get("/api/reports/{report_id}", response_model=ApiResponse)
def report_detail(report_id: str):
    try:
        return ok(report_store.get_report(report_id), "Analysis report loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=f"Unknown report: {report_id}") from exc


@app.get("/api/llm/config", response_model=ApiResponse)
def llm_config(user_id: str = "default"):
    return ok(llm_public_config(user_id), "LLM configuration loaded.")


@app.get("/api/usage/model", response_model=ApiResponse)
def model_usage(
    user_id: str = Query(default="default", min_length=1, max_length=120),
    days: int = Query(default=30),
):
    if days not in {7, 30}:
        raise HTTPException(status_code=422, detail="days must be 7 or 30")
    history = memory_service.get_history(user_id, limit=memory_service.max_history)
    return ok(
        model_usage_service.snapshot(user_id, days, history=history),
        "Model usage loaded.",
    )


@app.patch("/api/llm/config", response_model=ApiResponse)
def update_llm_config(payload: LLMConfigRequest, user_id: str = "default"):
    try:
        return ok(
            save_llm_config(payload.model_dump(exclude_unset=True), user_id),
            "LLM configuration saved.",
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/llm/test", response_model=ApiResponse)
def test_llm(payload: LLMConfigRequest, user_id: str = "default"):
    try:
        result = test_llm_config(payload.model_dump(exclude_unset=True), user_id)
        return ok(result, result.get("message", "LLM connection test finished."))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.post("/api/llm/models", response_model=ApiResponse)
def llm_models(payload: LLMModelsRequest, user_id: str = "default"):
    try:
        result = list_llm_models(payload.model_dump(exclude_unset=True), user_id)
        return ok(result, result.get("message", "LLM models loaded."))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.delete("/api/memory", response_model=ApiResponse)
def clear_memory(payload: MemoryClearRequest):
    return ok(memory_service.clear_history(payload.user_id), "Memory cleared.")


@app.get("/api/memory/conversations", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/assistant/conversations", response_model=ApiResponse)
def list_assistant_conversations(
    user_id: str = Query(default="default", min_length=1, max_length=120),
    limit: int = Query(default=30, ge=1, le=100),
    archived: bool = False,
):
    return ok(
        memory_service.list_conversations(user_id, limit=limit, archived=archived),
        "Conversations loaded.",
    )


@app.get("/api/memory/conversations/{session_id}", response_model=ApiResponse, include_in_schema=False)
@app.get("/api/assistant/conversations/{session_id}", response_model=ApiResponse)
def assistant_conversation_detail(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
    try:
        return ok(memory_service.get_conversation(user_id, session_id), "Conversation loaded.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc


@app.patch("/api/assistant/conversations/{session_id}/exchanges/{exchange_id}/table-edits", response_model=ApiResponse)
def update_assistant_conversation_table_edits(
    session_id: str,
    exchange_id: str,
    payload: AssistantStructuredDataEditRequest,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
    if not exchange_id or len(exchange_id) > 200:
        raise HTTPException(status_code=422, detail="Invalid exchange ID.")
    try:
        update_tables = (
            memory_service.update_short_term_exchange_table_edits
            if session_id.startswith("information:")
            else memory_service.update_exchange_table_edits
        )
        tables = update_tables(
            user_id,
            session_id,
            exchange_id,
            [table.model_dump(mode="json", exclude_none=True) for table in payload.tables],
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation exchange not found.") from exc
    return ok(
        {"exchange_id": exchange_id, "tables": tables},
        "Conversation table edits saved.",
    )


@app.post("/api/assistant/conversations/{session_id}/archive", response_model=ApiResponse)
def archive_assistant_conversation(
    session_id: str,
    payload: AssistantConversationArchiveRequest,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
    try:
        conversation = memory_service.archive_conversation(user_id, session_id, payload.archived)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc
    message = "Conversation archived." if payload.archived else "Conversation restored."
    return ok(conversation, message)


@app.delete("/api/assistant/conversations/{session_id}", response_model=ApiResponse)
def delete_assistant_conversation(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
    try:
        return ok(memory_service.delete_conversation(user_id, session_id), "Conversation deleted.")
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Conversation not found.") from exc


@app.delete("/api/assistant/short-term-sessions/{session_id}", response_model=ApiResponse)
def clear_assistant_short_term_session(
    session_id: str,
    user_id: str = Query(default="default", min_length=1, max_length=120),
):
    if not session_id or len(session_id) > 120:
        raise HTTPException(status_code=422, detail="Invalid session ID.")
    if not session_id.startswith("information:"):
        raise HTTPException(status_code=422, detail="Invalid short-term consultation session.")
    return ok(
        memory_service.clear_short_term_session(user_id, session_id),
        "Short-term consultation cleared.",
    )
