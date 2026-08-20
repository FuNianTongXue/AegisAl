from __future__ import annotations

import re
from datetime import date
from threading import RLock
from typing import Any, Callable, TypedDict
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from app.agent.assistant_intent import assistant_intent_skill_metadata
from app.agent.translation_policy import (
    catalog_translation_status_is_complete,
    issue_stored_translation_attestation,
)
from app.catalog_snapshot import component_catalog_snapshot_store
from app.composition import invoke_generation_pinned_graph
from app.intelligence import intelligence_service
from app.langgraph.checkpoints import (
    authorize_pending_interrupt,
    delete_checkpoint_thread,
    emit_transient_event,
    persistent_checkpointer,
    register_event_sink,
    unregister_event_sink,
)
from app.mcp.protocol import call_mcp_tool, publish_mcp_workbook
from app.privacy import public_answer_payload, sanitize_public_text, severity_cn
from app.storage import now_iso
from app.trace_ui import tool_call_presentation

_CJK_TEXT = re.compile(r"[一-鿿]")  # CJK Unified Ideographs (一-鿿)
_CATALOG_PREVIEW_RECORD_LIMIT = 8


class ComponentCatalogState(TypedDict, total=False):
    plugin_state: dict[str, Any]
    question: str
    user_id: str
    session_id: str
    response_language: str
    date_filter: dict[str, str]
    filters: dict[str, list[str]]
    intent_plan: dict[str, Any]
    catalog_result: dict[str, Any]
    catalog_snapshot_id: str
    chart_data: dict[str, Any]
    artifacts: list[dict[str, Any]]
    cancelled: bool
    error: str
    summary: str
    trace: list[dict[str, Any]]
    event_sink_id: str
    event_sink: Callable[[dict[str, Any]], None]


class ComponentVulnerabilityCatalogSubgraph:
    def __init__(self, *, checkpointer: Any | None = None) -> None:
        self._checkpointer = checkpointer or MemorySaver()
        self._owners: dict[str, tuple[str, str]] = {}
        self._lock = RLock()
        self.graph = self._build_graph()

    def start(self, payload: dict[str, Any], *, thread_id: str | None = None) -> dict[str, Any]:
        clean_thread_id = str(thread_id or f"component-catalog-{uuid4().hex}").strip()
        user_id = str(payload.get("user_id") or "default").strip() or "default"
        session_id = str(payload.get("session_id") or "default").strip() or "default"
        event_sink = payload.get("event_sink")
        seed: ComponentCatalogState = {
            **{key: value for key, value in payload.items() if key != "event_sink"},
            "question": str(payload.get("question") or ""),
            "user_id": user_id,
            "session_id": session_id,
            "date_filter": dict(payload.get("date_filter") or {}),
            "filters": dict(payload.get("filters") or {}),
            "intent_plan": dict(payload.get("intent_plan") or {}),
            "catalog_result": {},
            "catalog_snapshot_id": "",
            "chart_data": {},
            "artifacts": [],
            "cancelled": False,
            "error": "",
            "summary": "",
            "trace": list(payload.get("trace") or []),
            "event_sink_id": clean_thread_id,
        }
        with self._lock:
            self._owners[clean_thread_id] = (user_id, session_id)
        register_event_sink(clean_thread_id, event_sink)
        try:
            result = invoke_generation_pinned_graph(
                self.graph,
                seed,
                self._config(clean_thread_id),
            )
        finally:
            unregister_event_sink(clean_thread_id)
        return self._public_result(clean_thread_id, result)

    def resume(
        self,
        thread_id: str,
        *,
        decision: str,
        user_id: str,
        session_id: str,
        interrupt_id: str = "",
    ) -> dict[str, Any]:
        clean_thread_id = str(thread_id or "").strip()
        owner = (str(user_id or "default").strip() or "default", str(session_id or "default").strip() or "default")
        with self._lock:
            expected = self._owners.get(clean_thread_id)
        expected = authorize_pending_interrupt(
            self.graph,
            self._config(clean_thread_id),
            expected_owner=expected,
            actual_owner=owner,
            interrupt_id=interrupt_id,
        )
        with self._lock:
            self._owners[clean_thread_id] = expected
        resume_value = {
            "decision": "confirm"
            if str(decision).strip().lower() in {"confirm", "confirmed", "yes", "true"}
            else "cancel"
        }
        result = invoke_generation_pinned_graph(
            self.graph,
            Command(resume=resume_value),
            self._config(clean_thread_id),
        )
        public = self._public_result(clean_thread_id, result)
        if public["status"] != "interrupted":
            with self._lock:
                self._owners.pop(clean_thread_id, None)
            delete_checkpoint_thread(self._checkpointer, clean_thread_id)
        return public

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Component Vulnerability Catalog LangGraph Subgraph",
            "nodes": [
                {"id": "validate_catalog_request", "label": "校验模型理解的时间与筛选条件"},
                {"id": "query_component_catalog", "label": "查询时间范围组件漏洞事实"},
                {"id": "d3_sankey_mcp", "label": "D3 Sankey MCP 生成目录图数据"},
                {"id": "interrupt_generate_excel", "label": "Interrupt：确认生成 Excel"},
                {"id": "excel_mcp", "label": "Excel MCP 消费固定结果生成工作簿"},
                {"id": "interrupt_download_excel", "label": "Interrupt：确认选择目录下载"},
                {"id": "compose_catalog_result", "label": "汇总组件漏洞目录"},
            ],
            "edges": [
                {"source": "validate_catalog_request", "target": "query_component_catalog", "label": "结构校验通过"},
                {"source": "query_component_catalog", "target": "d3_sankey_mcp", "label": "存在可核验记录"},
                {"source": "query_component_catalog", "target": "compose_catalog_result", "label": "无结果或查询失败"},
                {"source": "d3_sankey_mcp", "target": "interrupt_generate_excel", "label": "先展示查询清单"},
                {"source": "interrupt_generate_excel", "target": "excel_mcp", "label": "用户确认生成"},
                {"source": "interrupt_generate_excel", "target": "compose_catalog_result", "label": "用户暂不生成"},
                {"source": "excel_mcp", "target": "interrupt_download_excel", "label": "Excel 已生成"},
                {"source": "interrupt_download_excel", "target": "compose_catalog_result", "label": "用户确认或取消下载"},
            ],
        }

    def _build_graph(self):
        graph = StateGraph(ComponentCatalogState)
        graph.add_node("validate_catalog_request", self._validate_request)
        graph.add_node("query_component_catalog", self._query_catalog)
        graph.add_node("d3_sankey_mcp", self._build_sankey)
        graph.add_node("interrupt_generate_excel", self._confirm_generation)
        graph.add_node("excel_mcp", self._generate_excel)
        graph.add_node("interrupt_download_excel", self._confirm_download)
        graph.add_node("compose_catalog_result", self._compose_result)
        graph.set_entry_point("validate_catalog_request")
        graph.add_conditional_edges(
            "validate_catalog_request",
            lambda state: "compose" if state.get("error") else "query",
            {"query": "query_component_catalog", "compose": "compose_catalog_result"},
        )
        graph.add_conditional_edges(
            "query_component_catalog",
            lambda state: "sankey" if (state.get("catalog_result") or {}).get("records") and not state.get("error") else "compose",
            {"sankey": "d3_sankey_mcp", "compose": "compose_catalog_result"},
        )
        graph.add_edge("d3_sankey_mcp", "interrupt_generate_excel")
        graph.add_conditional_edges(
            "interrupt_generate_excel",
            lambda state: "compose" if state.get("cancelled") else "excel",
            {"excel": "excel_mcp", "compose": "compose_catalog_result"},
        )
        graph.add_conditional_edges(
            "excel_mcp",
            lambda state: "download" if state.get("artifacts") and not state.get("error") else "compose",
            {"download": "interrupt_download_excel", "compose": "compose_catalog_result"},
        )
        graph.add_edge("interrupt_download_excel", "compose_catalog_result")
        graph.add_edge("compose_catalog_result", END)
        return graph.compile(checkpointer=self._checkpointer)

    @staticmethod
    def _validate_request(state: ComponentCatalogState) -> ComponentCatalogState:
        date_filter = state.get("date_filter") or {}
        try:
            start = date.fromisoformat(str(date_filter.get("start_date") or "")[:10])
            end = date.fromisoformat(str(date_filter.get("end_date") or "")[:10])
        except ValueError:
            state["error"] = "未能从问题中确定有效的组件漏洞查询日期范围。"
            return _trace(state, "component_catalog.validate_request", state["error"], "warning")
        if start > end or (end - start).days > 366:
            state["error"] = "组件漏洞目录日期范围无效或超过 367 天。"
            return _trace(state, "component_catalog.validate_request", state["error"], "warning")
        state["date_filter"] = {**date_filter, "start_date": start.isoformat(), "end_date": end.isoformat()}
        return _trace(
            state,
            "component_catalog.validate_request",
            f"已校验语义规划结果：{start.isoformat()} 至 {end.isoformat()}。",
            presentation=tool_call_presentation(
                "validate_component_catalog_plan",
                state="completed",
                title="LLM semantic plan validation",
                input_summary={"question": state.get("question", "")},
                output={"date_filter": state["date_filter"], "filters": state.get("filters") or {}},
            ),
        )

    @staticmethod
    def _query_catalog(state: ComponentCatalogState) -> ComponentCatalogState:
        date_filter = state.get("date_filter") or {}
        filters = state.get("filters") or {}
        try:
            result = intelligence_service.query_component_vulnerability_catalog(
                str(date_filter.get("start_date") or ""),
                str(date_filter.get("end_date") or ""),
                ecosystems=list(filters.get("ecosystems") or []),
                severities=list(filters.get("severities") or []),
                component_names=list(filters.get("component_names") or []),
                include_realtime=True,
                response_language=str(state.get("response_language") or "zh-Hans"),
            )
            state["summary"] = _catalog_summary(result, str(state.get("response_language") or "zh-Hans"))
            records = [dict(record) for record in result.get("records") or [] if isinstance(record, dict)]
            if len(records) > _CATALOG_PREVIEW_RECORD_LIMIT:
                state["catalog_snapshot_id"] = component_catalog_snapshot_store.save(
                    records,
                    result_sha256=str(result.get("result_sha256") or ""),
                )
                result = {
                    **result,
                    "records": records[:_CATALOG_PREVIEW_RECORD_LIMIT],
                    "preview_count": min(len(records), _CATALOG_PREVIEW_RECORD_LIMIT),
                }
            state["catalog_result"] = result
            return _trace(
                state,
                "component_catalog.query",
                f"时间范围查询完成，确认 {int(result.get('total') or 0)} 条组件漏洞记录。",
                "completed" if result.get("records") else "warning",
                presentation=tool_call_presentation(
                    "query_component_vulnerability_catalog",
                    state="completed",
                    title="Component vulnerability catalog query",
                    input_summary={"date_filter": date_filter, "filters": filters},
                    output={
                        "total": int(result.get("total") or 0),
                        "component_count": int(result.get("component_count") or 0),
                        "truncated": bool(result.get("truncated")),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["catalog_result"] = {}
            state["error"] = sanitize_public_text(str(exc)).strip() or "组件漏洞目录查询失败。"
            return _trace(state, "component_catalog.query", state["error"], "warning")

    @staticmethod
    def _build_sankey(state: ComponentCatalogState) -> ComponentCatalogState:
        result = dict(state.get("catalog_result") or {})
        try:
            sankey = call_mcp_tool(
                agent_id="component_agent",
                tool_id="mcp__d3_sankey__build_component_sankey",
                arguments={"graph": dict(result.get("graph") or {})},
            )
            state["chart_data"] = _catalog_chart_data(
                result,
                sankey,
                str(state.get("response_language") or "zh-Hans"),
            )
            message = "D3 Sankey MCP 已生成组件、漏洞与修复版本关系图。"
            status = "completed"
        except Exception as exc:  # noqa: BLE001
            state["chart_data"] = _catalog_chart_data(
                result,
                {},
                str(state.get("response_language") or "zh-Hans"),
            )
            message = f"桑基图生成失败，保留清单结果：{sanitize_public_text(str(exc))}"
            status = "warning"
        # The normalized chart is now in chart_data.  Keeping the source graph
        # in every later checkpoint would rewrite the same 80-record graph at
        # the confirmation, Excel, and download nodes.
        result.pop("graph", None)
        state["catalog_result"] = result
        return _trace(state, "component_catalog.d3_sankey_mcp", message, status)

    @staticmethod
    def _confirm_generation(state: ComponentCatalogState) -> ComponentCatalogState:
        result = state.get("catalog_result") or {}
        response = interrupt(
            {
                "kind": "component_excel_generation_confirmation",
                "action": "generate_component_catalog_excel",
                "question": "组件漏洞清单已查询完成，是否生成 Excel？",
                "detail": (
                    f"时间范围 {result.get('start_date')} 至 {result.get('end_date')}，"
                    f"共 {int(result.get('total') or 0)} 条漏洞、{int(result.get('component_count') or 0)} 个组件。"
                    "确认后 Excel MCP 将使用当前固定结果生成工作簿，不会重新查询。"
                ),
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["cancelled"] = True
            return _trace(state, "component_catalog.interrupt_generate_excel", "用户选择暂不生成 Excel。")
        return _trace(state, "component_catalog.interrupt_generate_excel", "用户已确认生成 Excel。")

    @staticmethod
    def _generate_excel(state: ComponentCatalogState) -> ComponentCatalogState:
        result = state.get("catalog_result") or {}
        try:
            records = _fixed_catalog_records(state)
        except (KeyError, OSError, ValueError):
            state["error"] = "组件漏洞固定结果已过期，请重新执行查询后再生成 Excel。"
            return _trace(state, "component_catalog.snapshot", state["error"], "warning")
        # Translation is an ingestion concern. Export consumes the immutable
        # catalog snapshot while the local offline worker backfills pending rows.
        if str(state.get("response_language") or "").lower().startswith("zh"):
            pending_translations = sum(
                1
                for record in records
                if str(record.get("summary") or "").strip()
                and not _CJK_TEXT.search(str(record.get("summary") or ""))
            )
            if pending_translations:
                _trace(
                    state,
                    "component_catalog.translation_cache",
                    (
                        f"已直接复用情报库译文；{pending_translations} 条描述仍在后台补译，"
                        "本次 Excel 保留核验原文，未重复执行离线翻译。"
                    ),
                    "warning",
                )
            else:
                _trace(
                    state,
                    "component_catalog.translation_cache",
                    "已直接复用情报库中预先存储的中文译文，未重复执行离线翻译。",
                )
        try:
            generated_at = str(result.get("generated_at") or now_iso())
            mcp_result = call_mcp_tool(
                agent_id="component_agent",
                tool_id="mcp__excel__export_component_vulnerability_catalog",
                arguments={
                    "records": records,
                    "start_date": str(result.get("start_date") or ""),
                    "end_date": str(result.get("end_date") or ""),
                    "filters": dict(result.get("filters") or {}),
                    "generated_at": generated_at,
                },
            )
            artifact = publish_mcp_workbook(
                mcp_result,
                kind="component",
                default_file_name="SecFlow-component-vulnerabilities.xlsx",
                generated_at=generated_at,
                user_id=str(state.get("user_id") or "default"),
                session_id=str(state.get("session_id") or ""),
                task_id=str(state.get("event_sink_id") or ""),
            )
            state["artifacts"] = [artifact]
            state["summary"] = f"组件漏洞目录 Excel 已生成：{artifact.get('file_name')}。"
            return _trace(
                state,
                "component_catalog.excel_mcp",
                state["summary"],
                presentation=tool_call_presentation(
                    "export_component_vulnerability_catalog",
                    state="completed",
                    title="Excel MCP",
                    input_summary={"record_count": len(records)},
                    output={"artifact_id": artifact.get("id"), "sha256": artifact.get("sha256")},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "Excel MCP 生成失败。"
            return _trace(state, "component_catalog.excel_mcp", state["error"], "warning")

    @staticmethod
    def _confirm_download(state: ComponentCatalogState) -> ComponentCatalogState:
        artifact = (state.get("artifacts") or [{}])[0]
        response = interrupt(
            {
                "kind": "component_excel_download_confirmation",
                "action": "download_component_catalog_excel",
                "artifact_ids": [str(artifact.get("id") or "")],
                "question": "Excel 已生成，是否选择目录并下载？",
                "detail": str(artifact.get("file_name") or "组件漏洞目录.xlsx"),
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["cancelled"] = True
            return _trace(state, "component_catalog.interrupt_download_excel", "用户选择暂不下载 Excel。")
        state["summary"] = f"下载已确认：{artifact.get('file_name')}。"
        return _trace(state, "component_catalog.interrupt_download_excel", "用户已确认选择目录下载 Excel。")

    @staticmethod
    def _compose_result(state: ComponentCatalogState) -> ComponentCatalogState:
        if state.get("error"):
            state["summary"] = state["error"]
        elif not state.get("summary"):
            state["summary"] = _catalog_summary(
                state.get("catalog_result") or {},
                str(state.get("response_language") or "zh-Hans"),
            )
        return _trace(
            state,
            "component_catalog.compose_result",
            state["summary"],
            "warning" if state.get("error") else "completed",
        )

    @staticmethod
    def _config(thread_id: str) -> dict[str, Any]:
        return {"configurable": {"thread_id": thread_id}}

    @staticmethod
    def _public_result(thread_id: str, state: dict[str, Any]) -> dict[str, Any]:
        raw_interrupts = list(state.get("__interrupt__") or [])
        envelope: dict[str, Any] | None = None
        if raw_interrupts:
            current = raw_interrupts[0]
            value = dict(current.value) if isinstance(current.value, dict) else {"question": str(current.value)}
            envelope = {
                **value,
                "interrupt_id": str(current.id),
                "thread_id": thread_id,
                "user_id": str(state.get("user_id") or "default"),
                "session_id": str(state.get("session_id") or "default"),
            }
        status = "interrupted" if envelope else ("cancelled" if state.get("cancelled") else ("failed" if state.get("error") else "completed"))
        result = dict(state.get("catalog_result") or {})
        return {
            "status": status,
            "thread_id": thread_id,
            "response_language": str(state.get("response_language") or "zh-Hans"),
            "interrupt": envelope,
            "summary": sanitize_public_text(state.get("summary") or (envelope or {}).get("question") or ""),
            "fields": {
                "查询开始日期": str(result.get("start_date") or (state.get("date_filter") or {}).get("start_date") or ""),
                "查询结束日期": str(result.get("end_date") or (state.get("date_filter") or {}).get("end_date") or ""),
                "漏洞数量": str(int(result.get("total") or 0)),
                "组件数量": str(int(result.get("component_count") or 0)),
                "结果是否截断": "是" if result.get("truncated") else "否",
                "严重漏洞": str(int((result.get("severity") or {}).get("CRITICAL") or 0)),
                "高危漏洞": str(int((result.get("severity") or {}).get("HIGH") or 0)),
                "结果指纹": str(result.get("result_sha256") or ""),
                "语义规划器": str((state.get("intent_plan") or {}).get("planner") or "validated"),
            },
            "chart_data": dict(state.get("chart_data") or {}),
            "artifacts": list(state.get("artifacts") or []),
            "catalog_translation": dict(result.get("catalog_translation") or {}),
            "error": sanitize_public_text(state.get("error") or ""),
            "trace": list(state.get("trace") or []),
            "skill": assistant_intent_skill_metadata(),
        }


def component_catalog_outcome_answer(outcome: dict[str, Any]) -> dict[str, Any]:
    answer = {
        "mode": "component_vulnerability_catalog",
        "summary": str(outcome.get("summary") or (outcome.get("interrupt") or {}).get("question") or "组件漏洞目录等待确认。"),
        "fields": dict(outcome.get("fields") or {}),
        "vulnerability_card": {},
        "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "chart_data": dict(outcome.get("chart_data") or {}),
        "artifacts": list(outcome.get("artifacts") or []),
        "interrupt": outcome.get("interrupt"),
        "confidence": 0.95 if not outcome.get("error") else 0.5,
        "trace": list(outcome.get("trace") or []),
        "generated_at": now_iso(),
    }
    answer = public_answer_payload(answer)
    language = str(outcome.get("response_language") or "zh-Hans")
    status = outcome.get("catalog_translation")
    if catalog_translation_status_is_complete(status, language):
        record_count = status["record_count"]
        answer["translation"] = issue_stored_translation_attestation(
            answer,
            target_language=language,
            record_count=record_count,
            source="component-vulnerability-catalog",
        )
    return answer


def _catalog_summary(result: dict[str, Any], language: str = "zh-Hans") -> str:
    start = str(result.get("start_date") or "")
    end = str(result.get("end_date") or "")
    total = int(result.get("total") or 0)
    components = int(result.get("component_count") or 0)
    lines = [f"已核验 {start} 至 {end} 的组件漏洞目录，共 {total} 条漏洞，涉及 {components} 个组件。"]
    for record in list(result.get("records") or [])[:8]:
        names = list(
            dict.fromkeys(
                str(component.get("name") or "").strip()
                for component in record.get("components") or []
                if isinstance(component, dict) and str(component.get("name") or "").strip()
            )
        )
        component_text = "、".join(names[:3]) or "组件待核验"
        description = str(record.get("title") or record.get("summary") or "").strip()
        if str(language or "").lower().startswith("zh") and description and not _CJK_TEXT.search(description):
            description = "描述正在后台补译"
        lines.append(
            f"- {record.get('id')} | {_catalog_severity_label(record.get('severity'), language)} | "
            f"{component_text} | {description or '未提供标题'}"
        )
    if result.get("truncated"):
        lines.append("结果已达到目录上限，当前预览和后续 Excel 会明确标记为截断结果。")
    return "\n".join(lines)


def _catalog_chart_data(result: dict[str, Any], sankey: dict[str, Any], language: str = "zh-Hans") -> dict[str, Any]:
    severity = result.get("severity") if isinstance(result.get("severity"), dict) else {}
    ecosystems = result.get("ecosystem_counts") if isinstance(result.get("ecosystem_counts"), dict) else {}
    return {
        "schema_version": 1,
        "sankey": {
            "nodes": list(sankey.get("nodes") or []),
            "links": list(sankey.get("links") or []),
        },
        "severity_ring": [
            {
                "id": key.lower(),
                "label": _catalog_severity_label(key, language),
                "key": key,
                "value": int(severity.get(key) or 0),
            }
            for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        ],
        "risk_bars": [
            {"id": str(key).casefold(), "label": str(key), "key": str(key), "value": int(value)}
            for key, value in list(ecosystems.items())[:12]
        ],
    }


def _fixed_catalog_records(state: ComponentCatalogState) -> list[dict[str, Any]]:
    result = state.get("catalog_result") or {}
    snapshot_id = str(state.get("catalog_snapshot_id") or "").strip()
    if snapshot_id:
        return component_catalog_snapshot_store.load(
            snapshot_id,
            expected_sha256=str(result.get("result_sha256") or ""),
        )
    return [dict(record) for record in result.get("records") or [] if isinstance(record, dict)]


def _catalog_severity_label(value: Any, language: str) -> str:
    severity = str(value or "UNKNOWN").strip().upper() or "UNKNOWN"
    normalized_language = str(language or "zh-Hans").strip().lower().replace("_", "-")
    if normalized_language in {"zh", "zh-cn", "zh-hans"}:
        return severity_cn(severity)
    if normalized_language in {"zh-tw", "zh-hk", "zh-hant"}:
        return {
            "CRITICAL": "嚴重",
            "HIGH": "高危",
            "MEDIUM": "中危",
            "LOW": "低危",
            "UNKNOWN": "待定",
        }.get(severity, severity)
    if normalized_language == "en":
        return {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "UNKNOWN": "Unknown",
        }.get(severity, severity.title())
    return severity


def _trace(
    state: ComponentCatalogState,
    node: str,
    message: str,
    status: str = "completed",
    presentation: dict[str, Any] | None = None,
) -> ComponentCatalogState:
    item = {"node": node, "status": status, "message": sanitize_public_text(message), "time": now_iso()}
    if presentation:
        item["presentation"] = presentation
    state["trace"] = [*state.get("trace", []), item]
    event_sink = state.get("event_sink")
    if event_sink is not None:
        try:
            event_sink(dict(item))
        except Exception:  # noqa: BLE001
            pass
    emit_transient_event(str(state.get("event_sink_id") or ""), item)
    return state


component_vulnerability_catalog_subgraph = ComponentVulnerabilityCatalogSubgraph(
    checkpointer=persistent_checkpointer("component-catalog")
)
