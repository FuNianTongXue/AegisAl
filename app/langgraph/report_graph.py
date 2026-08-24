from __future__ import annotations

import base64
import hashlib
import json
import re
from pathlib import Path
from threading import RLock
from typing import Any, TypedDict
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from app.agent.translation_agent import translation_agent
from app.agent.translation_policy import failed_translation_audit, translation_audit_is_publishable
from app.composition import invoke_generation_pinned_graph
from app.privacy import sanitize_public_text
from app.langgraph.checkpoints import (
    authorize_pending_interrupt,
    delete_checkpoint_thread,
    persistent_checkpointer,
)
from app.mcp.protocol import call_mcp_tool, read_mcp_artifact, release_mcp_artifacts
from app.report_pipeline import build_report_plan, validate_report_quality
from app.reports import (
    build_report_document_json,
    build_scan_result_json,
    build_agent_task_markdown_report,
    build_dependency_markdown_report,
    ReportStore,
    REPORT_DOCUMENT_SCHEMA_VERSION,
    report_store,
)
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


REPORT_FORMATS = ("md", "html", "docx", "xlsx", "pdf")
_REPORT_ID = re.compile(r"report-[A-Za-z0-9._:+-]+", flags=re.IGNORECASE)
_REPORT_PROGRESS_LOCK = RLock()
_REPORT_PROGRESS_SINKS: dict[str, Any] = {}


class ReportSubgraphState(TypedDict, total=False):
    plugin_state: dict[str, Any]
    operation_thread_id: str
    action: str
    question: str
    user_id: str
    session_id: str
    response_language: str
    source_kind: str
    scan_data: dict[str, Any]
    scan_json: dict[str, Any]
    report_ids: list[str]
    formats: list[str]
    report_catalog: list[dict[str, Any]]
    report_charts: dict[str, Any]
    report_sarif: dict[str, Any]
    report_mermaid: dict[str, Any]
    report_mcp: dict[str, Any]
    report_mcps: list[dict[str, Any]]
    report_translation: dict[str, Any]
    report_plan: dict[str, Any]
    report_template: dict[str, Any]
    report_qa: dict[str, Any]
    report_draft: dict[str, Any]
    report_document: dict[str, Any]
    rendered_artifacts: dict[str, Any]
    report: dict[str, Any]
    artifacts: list[dict[str, Any]]
    cancelled: bool
    error: str
    summary: str
    trace: list[dict[str, Any]]
    report_store_root: str


class ReportCapabilitySubgraph:
    def __init__(self, *, checkpointer: Any | None = None) -> None:
        self._checkpointer = checkpointer or MemorySaver()
        self._owners: dict[str, tuple[str, str]] = {}
        self._lock = RLock()
        self.graph = self._build_graph()

    def start(self, payload: dict[str, Any], *, thread_id: str | None = None) -> dict[str, Any]:
        clean_thread_id = str(thread_id or f"report-{uuid4().hex}").strip()
        user_id = str(payload.get("user_id") or "default").strip() or "default"
        session_id = str(payload.get("session_id") or "default").strip() or "default"
        seed: ReportSubgraphState = {
            **{key: value for key, value in payload.items() if key != "event_sink"},
            "operation_thread_id": clean_thread_id,
            "user_id": user_id,
            "session_id": session_id,
            "question": str(payload.get("question") or ""),
            "source_kind": str(payload.get("source_kind") or "report_center"),
            "scan_data": dict(payload.get("scan_data") or {}),
            "scan_json": {},
            "report_ids": list(payload.get("report_ids") or []),
            "formats": list(payload.get("formats") or []),
            "report_catalog": [],
            "report_charts": {},
            "report_sarif": {},
            "report_mermaid": {},
            "report": {},
            "report_mcps": [],
            "report_translation": {},
            "report_plan": {},
            "report_template": {},
            "report_qa": {},
            "report_draft": {},
            "report_document": {},
            "rendered_artifacts": {},
            "artifacts": [],
            "cancelled": False,
            "error": "",
            "summary": "",
            "trace": [],
            "report_store_root": str(payload.get("report_store_root") or ""),
        }
        with self._lock:
            self._owners[clean_thread_id] = (user_id, session_id)
        result = invoke_generation_pinned_graph(
            self.graph,
            seed,
            self._config(clean_thread_id),
        )
        return self._public_result(clean_thread_id, result)

    def resume(
        self,
        thread_id: str,
        *,
        decision: str,
        user_id: str,
        session_id: str,
        report_format: str = "",
        interrupt_id: str = "",
        event_sink: Any = None,
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
        raw_format = str(report_format or "").strip().lower()
        resume_value = {
            "decision": "confirm" if str(decision).strip().lower() in {"confirm", "confirmed", "yes", "true"} else "cancel",
            "format": "all" if raw_format == "all" else _normalize_optional_format(raw_format),
        }
        if event_sink is not None:
            with _REPORT_PROGRESS_LOCK:
                _REPORT_PROGRESS_SINKS[clean_thread_id] = event_sink
        try:
            result = invoke_generation_pinned_graph(
                self.graph,
                Command(resume=resume_value),
                self._config(clean_thread_id),
            )
        finally:
            if event_sink is not None:
                with _REPORT_PROGRESS_LOCK:
                    if _REPORT_PROGRESS_SINKS.get(clean_thread_id) is event_sink:
                        _REPORT_PROGRESS_SINKS.pop(clean_thread_id, None)
        public = self._public_result(clean_thread_id, result)
        if public["status"] != "interrupted":
            with self._lock:
                self._owners.pop(clean_thread_id, None)
            delete_checkpoint_thread(self._checkpointer, clean_thread_id)
        return public

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Report Center Capability LangGraph Subgraph",
            "nodes": [
                {"id": "parse_report_request", "label": "解析报告中心操作"},
                {"id": "load_report_catalog", "label": "加载并校验报告清单"},
                {"id": "interrupt_generate_report", "label": "Interrupt：确认生成报告"},
                {"id": "build_scan_result_json", "label": "代码与依赖扫描事实规范化为 JSON"},
                {"id": "translation_agent", "label": "Translation Agent 调用翻译 MCP"},
                {"id": "report_sarif_mcp", "label": "SARIF MCP 生成完整污点 codeFlows/threadFlows"},
                {"id": "report_chart_mcp", "label": "Report Chart MCP 消费 JSON 并生成图表数据"},
                {"id": "report_planner_agent", "label": "Report Planner Agent 规划报告类型、章节与格式"},
                {"id": "report_template_mcp", "label": "Template MCP 解析统一企业模板与平台字体"},
                {"id": "prepare_report_draft", "label": "根据已核验 JSON 准备报告事实草稿"},
                {"id": "report_mermaid_mcp", "label": "Mermaid MCP 生成关系图与严重度图"},
                {"id": "report_markdown_mcp", "label": "Markdown MCP 生成 MD 报告"},
                {"id": "report_qa_agent", "label": "QA Agent 校验数据、章节、模板与格式完整性"},
                {"id": "report_word_mcp", "label": "Word MCP 生成 DOCX 报告"},
                {"id": "report_excel_mcp", "label": "Excel MCP 生成 XLSX 报告"},
                {"id": "report_pdf_mcp", "label": "PDF MCP 生成 PDF 报告"},
                {"id": "persist_report", "label": "校验并登记所有报告制品"},
                {"id": "interrupt_download_report", "label": "Interrupt：确认下载与格式"},
                {"id": "prepare_report_download", "label": "准备单份、单格式或全部报告"},
                {"id": "compose_report_result", "label": "汇总报告操作结果"},
            ],
            "edges": [
                {"source": "parse_report_request", "target": "load_report_catalog", "label": "操作与格式已识别"},
                {"source": "load_report_catalog", "target": "interrupt_generate_report", "label": "生成扫描报告"},
                {"source": "load_report_catalog", "target": "interrupt_download_report", "label": "下载已有报告"},
                {"source": "interrupt_generate_report", "target": "build_scan_result_json", "label": "用户确认生成"},
                {"source": "build_scan_result_json", "target": "translation_agent", "label": "JSON 校验与哈希完成"},
                {"source": "translation_agent", "target": "report_sarif_mcp", "label": "目标语言 JSON 已校验"},
                {"source": "report_sarif_mcp", "target": "report_chart_mcp", "label": "SARIF 污点路径已生成"},
                {"source": "report_chart_mcp", "target": "report_planner_agent", "label": "图表事实已生成"},
                {"source": "report_planner_agent", "target": "report_template_mcp", "label": "报告章节与格式已规划"},
                {"source": "report_template_mcp", "target": "prepare_report_draft", "label": "企业模板已解析"},
                {"source": "prepare_report_draft", "target": "report_mermaid_mcp", "label": "报告事实草稿已准备"},
                {"source": "report_mermaid_mcp", "target": "report_markdown_mcp", "label": "Mermaid 图已生成"},
                {"source": "report_markdown_mcp", "target": "report_qa_agent", "label": "统一 Report JSON 已生成"},
                {"source": "report_qa_agent", "target": "report_word_mcp", "label": "QA 质量门已通过"},
                {"source": "report_word_mcp", "target": "report_excel_mcp", "label": "DOCX 已生成并校验"},
                {"source": "report_excel_mcp", "target": "report_pdf_mcp", "label": "XLSX 已生成并校验"},
                {"source": "report_pdf_mcp", "target": "persist_report", "label": "PDF 已生成并校验"},
                {"source": "persist_report", "target": "interrupt_download_report", "label": "报告生成后确认下载"},
                {"source": "interrupt_download_report", "target": "prepare_report_download", "label": "用户确认下载"},
                {"source": "prepare_report_download", "target": "compose_report_result", "label": "制品已登记"},
            ],
        }

    def _build_graph(self):
        graph = StateGraph(ReportSubgraphState)
        graph.add_node("parse_report_request", self._parse_request)
        graph.add_node("load_report_catalog", self._load_catalog)
        graph.add_node("interrupt_generate_report", self._confirm_generation)
        graph.add_node("build_scan_result_json", self._build_scan_json)
        graph.add_node("translation_agent", self._translate_scan_json)
        graph.add_node("report_sarif_mcp", self._build_sarif)
        graph.add_node("report_chart_mcp", self._build_charts)
        graph.add_node("report_planner_agent", self._plan_report)
        graph.add_node("report_template_mcp", self._resolve_template)
        graph.add_node("prepare_report_draft", self._prepare_report_draft)
        graph.add_node("report_mermaid_mcp", self._build_mermaid)
        graph.add_node("report_markdown_mcp", self._render_markdown)
        graph.add_node("report_qa_agent", self._quality_gate)
        graph.add_node("report_word_mcp", self._render_word)
        graph.add_node("report_excel_mcp", self._render_excel)
        graph.add_node("report_pdf_mcp", self._render_pdf)
        graph.add_node("persist_report", self._persist_report)
        graph.add_node("interrupt_download_report", self._confirm_download)
        graph.add_node("prepare_report_download", self._prepare_download)
        graph.add_node("compose_report_result", self._compose_result)
        graph.set_entry_point("parse_report_request")
        graph.add_edge("parse_report_request", "load_report_catalog")
        graph.add_conditional_edges(
            "load_report_catalog",
            self._route_catalog,
            {
                "generate": "interrupt_generate_report",
                "download": "interrupt_download_report",
                "compose": "compose_report_result",
            },
        )
        graph.add_conditional_edges(
            "interrupt_generate_report",
            lambda state: "compose" if state.get("cancelled") else "json",
            {"json": "build_scan_result_json", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "build_scan_result_json",
            lambda state: "compose" if state.get("error") else "translate",
            {"translate": "translation_agent", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "translation_agent",
            lambda state: "compose" if state.get("error") else "sarif",
            {"sarif": "report_sarif_mcp", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "report_sarif_mcp",
            lambda state: "compose" if state.get("error") else "charts",
            {"charts": "report_chart_mcp", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "report_chart_mcp",
            lambda state: "compose" if state.get("error") else "plan",
            {"plan": "report_planner_agent", "compose": "compose_report_result"},
        )
        for source, success, target in (
            ("report_planner_agent", "template", "report_template_mcp"),
            ("report_template_mcp", "draft", "prepare_report_draft"),
            ("prepare_report_draft", "mermaid", "report_mermaid_mcp"),
            ("report_mermaid_mcp", "markdown", "report_markdown_mcp"),
            ("report_markdown_mcp", "qa", "report_qa_agent"),
            ("report_qa_agent", "word", "report_word_mcp"),
            ("report_word_mcp", "excel", "report_excel_mcp"),
            ("report_excel_mcp", "pdf", "report_pdf_mcp"),
            ("report_pdf_mcp", "persist", "persist_report"),
        ):
            graph.add_conditional_edges(
                source,
                lambda state, success=success: "compose" if state.get("error") else success,
                {success: target, "compose": "compose_report_result"},
            )
        graph.add_conditional_edges(
            "persist_report",
            lambda state: "download" if state.get("report") and not state.get("error") else "compose",
            {"download": "interrupt_download_report", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "interrupt_download_report",
            lambda state: "compose" if state.get("cancelled") else "prepare",
            {"prepare": "prepare_report_download", "compose": "compose_report_result"},
        )
        graph.add_edge("prepare_report_download", "compose_report_result")
        graph.add_edge("compose_report_result", END)
        return graph.compile(checkpointer=self._checkpointer)

    @staticmethod
    def _parse_request(state: ReportSubgraphState) -> ReportSubgraphState:
        action = str(state.get("action") or "").strip().lower()
        question = str(state.get("question") or "")
        lowered = question.lower()
        if not action:
            if re.search(r"下载|download|export", lowered):
                if re.search(r"全部格式|所有格式|all\s+formats?", lowered):
                    action = "download_report_all_formats"
                elif re.search(r"全部报告|所有报告|all\s+reports?", lowered):
                    action = "download_all"
                else:
                    action = "download_report"
            elif re.search(r"生成|创建|create|generate", lowered) and re.search(r"报告|report", lowered):
                action = "generate"
        aliases = {
            "generate_report": "generate",
            "download": "download_report",
            "download_single": "download_report",
            "download_single_format": "download_report",
            "download_all_reports": "download_all",
            "download_all_formats": "download_report_all_formats",
        }
        action = aliases.get(action, action)
        if action not in {"generate", "download_report", "download_report_all_formats", "download_all"}:
            state["error"] = "无法识别报告操作，请明确生成报告、下载某份报告、下载单一格式或下载全部报告。"
            state["action"] = ""
            return _trace(state, "report.parse_request", "报告操作不明确。", "warning")
        state["action"] = action
        if not state.get("report_ids"):
            state["report_ids"] = list(dict.fromkeys(match.group(0) for match in _REPORT_ID.finditer(question)))
        formats = [_normalize_optional_format(value) for value in state.get("formats") or []]
        for value in REPORT_FORMATS:
            if re.search(rf"(?<![a-z]){value}(?![a-z])", lowered):
                formats.append(value)
        if re.search(r"(?<![a-z])word(?![a-z])|微软文档|文档格式", lowered):
            formats.append("docx")
        state["formats"] = list(dict.fromkeys(value for value in formats if value))
        if action == "download_report_all_formats":
            state["formats"] = list(REPORT_FORMATS)
        elif action == "download_all" and not state["formats"]:
            state["formats"] = list(REPORT_FORMATS)
        return _trace(state, "report.parse_request", f"已识别报告操作：{action}。")

    @staticmethod
    def _load_catalog(state: ReportSubgraphState) -> ReportSubgraphState:
        if state.get("error"):
            return state
        user_id = str(state.get("user_id") or "default")
        catalog = [item for item in _store_for_state(state).list_reports() if _report_owned_by(item, user_id)]
        state["report_catalog"] = catalog
        action = state.get("action")
        if action == "download_all":
            state["report_ids"] = [str(item.get("id") or "") for item in catalog]
        elif action in {"download_report", "download_report_all_formats"} and not state.get("report_ids"):
            if catalog:
                state["report_ids"] = [str(catalog[0].get("id") or "")]
        requested = set(state.get("report_ids") or [])
        known = {str(item.get("id") or "") for item in catalog}
        missing = requested - known
        if action != "generate" and (not requested or missing):
            state["error"] = "未找到可下载的报告。" if not requested else f"报告不存在或无权访问：{', '.join(sorted(missing))}"
            return _trace(state, "report.load_catalog", state["error"], "warning")
        return _trace(state, "report.load_catalog", f"已加载 {len(catalog)} 份可访问报告。")

    @staticmethod
    def _route_catalog(state: ReportSubgraphState) -> str:
        if state.get("error"):
            return "compose"
        return "generate" if state.get("action") == "generate" else "download"

    @staticmethod
    def _confirm_generation(state: ReportSubgraphState) -> ReportSubgraphState:
        scan_data = state.get("scan_data") or {}
        if not scan_data:
            state["error"] = "当前没有已完成的扫描数据，不能生成可核验报告。"
            return _trace(state, "report.interrupt_generate", state["error"], "warning")
        response = interrupt(
            {
                "kind": "report_generation_confirmation",
                "action": "generate",
                "question": "扫描已完成，是否根据本次扫描事实生成完整报告？",
                "detail": (
                    "确认后先校验代码与依赖 JSON，再生成 SARIF 2.1.0 完整污点路径，"
                    "由 Mermaid 转为 JPEG，并将同一图像嵌入 HTML、Word 和 PDF；各格式独立校验哈希。"
                ),
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["cancelled"] = True
            state["summary"] = "已按用户选择跳过报告生成，扫描结果保持不变。"
            return _trace(state, "report.interrupt_generate", "用户取消生成报告。", "completed")
        return _trace(state, "report.interrupt_generate", "用户已确认生成报告。")

    @staticmethod
    def _build_scan_json(state: ReportSubgraphState) -> ReportSubgraphState:
        try:
            scan_json = build_scan_result_json(
                state.get("scan_data") or {},
                source_kind=str(state.get("source_kind") or "assistant_scan"),
                language=str(state.get("response_language") or "zh-Hans"),
            )
            state["scan_json"] = scan_json
            audit = scan_json.get("audit") if isinstance(scan_json.get("audit"), dict) else {}
            counts = scan_json.get("counts") if isinstance(scan_json.get("counts"), dict) else {}
            return _trace(
                state,
                "report.scan_json",
                (
                    "代码与依赖扫描结果已完成 JSON 往返校验："
                    f"{int(counts.get('code_findings') or 0)} 条代码发现，"
                    f"{int(counts.get('dependencies') or 0)} 个依赖，"
                    f"{int(counts.get('dependency_vulnerabilities') or 0)} 条依赖漏洞。"
                ),
                presentation=tool_call_presentation(
                    "build_scan_result_json",
                    state="completed",
                    title="Scan Results JSON",
                    input_summary={"source_kind": state.get("source_kind") or "assistant_scan"},
                    output={
                        "schema": scan_json.get("$schema"),
                        "payload_sha256": audit.get("payload_sha256"),
                        "counts": counts,
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            message = sanitize_public_text(str(exc)).strip() or "扫描结果无法转换为 JSON"
            state["scan_json"] = {}
            state["error"] = f"扫描结果 JSON 规范化失败，报告未生成：{message}"
            return _trace(state, "report.scan_json", state["error"], "warning")

    @staticmethod
    def _translate_scan_json(state: ReportSubgraphState) -> ReportSubgraphState:
        source_json = dict(state.get("scan_json") or {})
        target_language = str(state.get("response_language") or "zh-Hans")
        try:
            result = translation_agent.translate_json(
                source_json,
                target_language=target_language,
                user_id=str(state.get("user_id") or "default"),
                session_id=str(state.get("session_id") or "default"),
                content_scope="report_source",
            )
            translated = result.payload
            audit = dict(result.audit)
            if (
                audit.get("target_language") != target_language
                or not translation_audit_is_publishable(audit)
            ):
                return ReportCapabilitySubgraph._report_translation_fallback(
                    state,
                    source_json,
                    audit,
                    "翻译 MCP 未生成完整的目标语言报告数据",
                )
            source_hash = str(((translated.get("audit") or {}).get("payload_sha256") or ""))
            if not source_hash:
                raise ValueError("translated report JSON is missing its verified payload hash")
            audit["translation_input_sha256"] = audit.get("input_sha256") or ""
            audit["translation_output_sha256"] = audit.get("output_sha256") or ""
            audit["input_sha256"] = source_hash
            audit["output_sha256"] = source_hash
            state["scan_json"] = translated
            state["report_translation"] = audit
            _append_format_audit(state, audit)
            return _trace(
                state,
                "report.translation_agent",
                (
                    "Translation Agent 已调用翻译 MCP 处理报告 JSON："
                    f"目标语言 {audit['target_language']}，翻译 {audit['translated_fields']} 个字段。"
                ),
                presentation=tool_call_presentation(
                    "translate_json_payload",
                    state="completed",
                    title="Translation MCP",
                    input_summary={
                        "content_scope": "report_source",
                        "target_language": audit["target_language"],
                        "candidate_fields": audit["candidate_fields"],
                    },
                    output={
                        "translated_fields": audit["translated_fields"],
                        "translation_status": audit["translation_status"],
                        "payload_sha256": source_hash,
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            message = sanitize_public_text(str(exc)).strip() or "翻译 MCP 未返回可校验 JSON"
            return ReportCapabilitySubgraph._report_translation_fallback(
                state,
                source_json,
                failed_translation_audit(target_language, message),
                message,
            )

    @staticmethod
    def _report_translation_fallback(
        state: ReportSubgraphState,
        source_json: dict[str, Any],
        audit: dict[str, Any],
        reason: str,
    ) -> ReportSubgraphState:
        """Keep verified report facts usable when the single translation pass is incomplete."""

        source_hash = str(((source_json.get("audit") or {}).get("payload_sha256") or ""))
        fallback_audit = {
            **dict(audit or {}),
            "status": "partial",
            "translation_status": "fallback",
            "target_language": str(state.get("response_language") or "zh-Hans"),
            "fallback_used": True,
            "fallback_source": "verified_scan_json",
            "publication_status": "source_facts",
            "input_sha256": str((audit or {}).get("input_sha256") or source_hash),
            "output_sha256": source_hash or str((audit or {}).get("output_sha256") or ""),
            "error": sanitize_public_text(reason).strip(),
        }
        state["scan_json"] = source_json
        state["report_translation"] = fallback_audit
        _append_format_audit(state, fallback_audit)
        return _trace(
            state,
            "report.translation_agent",
            "Translation Agent 未完成目标语言转换，已回退到已核验的原始报告 JSON，报告继续生成。",
            "warning",
            presentation=tool_call_presentation(
                "translate_json_payload",
                state="error",
                title="Translation MCP",
                input_summary={
                    "content_scope": "report_source",
                    "target_language": fallback_audit["target_language"],
                },
                output={
                    "translation_status": "fallback",
                    "fallback_source": "verified_scan_json",
                    "payload_sha256": source_hash,
                },
                error=fallback_audit["error"],
            ),
        )

    @staticmethod
    def _build_charts(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        try:
            charts = call_mcp_tool(
                agent_id="report_agent",
                tool_id="mcp__report_chart__build_scan_report_charts",
                arguments={"report_json": state.get("scan_json") or {}},
            )
            state["report_charts"] = charts
            state["report_mcp"] = {
                "server": "AegisAl Report Chart MCP",
                "tool": "build_scan_report_charts",
                "transport": str((charts.get("_mcp_runtime") or {}).get("transport") or "stdio"),
                "endpoint": "managed-child-process",
                "status": "completed",
                "invoked_at": invoked_at,
                "fact_count": int(charts.get("fact_count") or 0),
                "code_block_count": len(charts.get("code_blocks") or []),
                "renderer": str(charts.get("renderer") or ""),
                "output_sha256": hashlib.sha256(
                    json.dumps(charts, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
                "input_sha256": str(((state.get("scan_json") or {}).get("audit") or {}).get("payload_sha256") or ""),
            }
            state["report_mcps"] = [*state.get("report_mcps", []), dict(state["report_mcp"])]
            return _trace(
                state,
                "report.chart_mcp",
                f"Report Chart MCP 已处理 {state['report_mcp']['fact_count']} 条扫描事实并生成可审计图表数据。",
                presentation=tool_call_presentation(
                    "build_scan_report_charts",
                    state="completed",
                    title="Report Chart MCP",
                    input_summary={"source_kind": state.get("source_kind") or "assistant_scan"},
                    output={
                        "fact_count": state["report_mcp"]["fact_count"],
                        "output_sha256": state["report_mcp"]["output_sha256"],
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["report_charts"] = {}
            message = sanitize_public_text(str(exc)).strip() or "未知 MCP 错误"
            state["report_mcp"] = {
                "server": "AegisAl Report Chart MCP",
                "tool": "build_scan_report_charts",
                "transport": "stdio",
                "endpoint": "managed-child-process",
                "status": "failed",
                "invoked_at": invoked_at,
                "error": message,
            }
            state["report_mcps"] = [*state.get("report_mcps", []), dict(state["report_mcp"])]
            state["error"] = f"Report Chart MCP 调用失败，报告未生成：{message}"
            return _trace(
                state,
                "report.chart_mcp",
                state["error"],
                "warning",
                presentation=tool_call_presentation(
                    "build_scan_report_charts",
                    state="error",
                    title="Report Chart MCP",
                    input_summary={"source_kind": state.get("source_kind") or "assistant_scan"},
                    error=message,
                ),
            )

    @staticmethod
    def _build_sarif(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        try:
            result = call_mcp_tool(
                agent_id="report_agent",
                tool_id="mcp__report_sarif__build_scan_sarif",
                arguments={"report_json": state.get("scan_json") or {}},
            )
            sarif = result.get("sarif") if isinstance(result.get("sarif"), dict) else {}
            digest = hashlib.sha256(
                json.dumps(sarif, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            if not digest or digest != str(result.get("output_sha256") or ""):
                raise ValueError("SARIF MCP output hash verification failed")
            state["report_sarif"] = result
            audit = _format_mcp_audit(
                server="AegisAl SARIF MCP",
                tool="build_scan_sarif",
                invoked_at=invoked_at,
                input_sha256=str(result.get("input_sha256") or ""),
                output_sha256=digest,
                media_type="application/sarif+json",
                artifact_size=len(json.dumps(sarif, ensure_ascii=False).encode("utf-8")),
                renderer=str(result.get("renderer") or "secflow-sarif-2.1.0"),
            )
            audit["result_count"] = int(result.get("result_count") or 0)
            audit["thread_flow_count"] = int(result.get("thread_flow_count") or 0)
            audit["thread_flow_location_count"] = int(result.get("thread_flow_location_count") or 0)
            _append_format_audit(state, audit)
            return _trace(
                state,
                "report.sarif_mcp",
                (
                    "SARIF MCP 已生成 "
                    f"{audit['thread_flow_count']} 条污点路径、"
                    f"{audit['thread_flow_location_count']} 个完整路径节点。"
                ),
                presentation=tool_call_presentation(
                    "build_scan_sarif",
                    state="completed",
                    title="SARIF MCP",
                    input_summary={"scan_sha256": audit["input_sha256"]},
                    output={
                        "result_count": audit["result_count"],
                        "thread_flow_count": audit["thread_flow_count"],
                        "thread_flow_location_count": audit["thread_flow_location_count"],
                        "output_sha256": digest,
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["report_sarif"] = {}
            return _format_mcp_failure(
                state,
                server="AegisAl SARIF MCP",
                tool="build_scan_sarif",
                invoked_at=invoked_at,
                node="report.sarif_mcp",
                exc=exc,
            )

    @staticmethod
    def _plan_report(state: ReportSubgraphState) -> ReportSubgraphState:
        try:
            plan = build_report_plan(
                state.get("scan_json") or {},
                source_kind=str(state.get("source_kind") or "assistant_scan"),
                language=str(state.get("response_language") or "zh-Hans"),
            )
            state["report_plan"] = plan
            return _trace(
                state,
                "report.planner_agent",
                (
                    f"Report Planner Agent 已规划 {len(plan.get('sections') or [])} 个章节、"
                    f"{len(plan.get('formats') or [])} 种格式，报告类型为 {plan.get('scan_type')}。"
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "报告规划失败。"
            return _trace(state, "report.planner_agent", f"报告规划失败：{state['error']}", "warning")

    @staticmethod
    def _resolve_template(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        plan = state.get("report_plan") or {}
        try:
            template = call_mcp_tool(
                agent_id="report_agent",
                tool_id="mcp__report_template__resolve_report_template",
                arguments={
                    "template_id": str(plan.get("template_id") or "security"),
                    "platform": "auto",
                    "language": str(state.get("response_language") or "zh-Hans"),
                },
            )
            state["report_template"] = template
            encoded = json.dumps(template, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            audit = _format_mcp_audit(
                server="AegisAl Template MCP",
                tool="resolve_report_template",
                invoked_at=invoked_at,
                input_sha256=str(plan.get("source_sha256") or ""),
                output_sha256=hashlib.sha256(encoded).hexdigest(),
                media_type="application/vnd.secflow.report-template+json",
                artifact_size=len(encoded),
                renderer="secflow-offline-template",
            )
            _append_format_audit(state, audit)
            return _trace(
                state,
                "report.template_mcp",
                f"Template MCP 已解析 {template.get('name') or template.get('id')} 并统一跨格式字体与色板。",
                presentation=tool_call_presentation(
                    "resolve_report_template",
                    state="completed",
                    title="Template MCP",
                    input_summary={"template_id": plan.get("template_id")},
                    output={"platform": template.get("platform"), "output_sha256": audit["output_sha256"]},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return _format_mcp_failure(
                state,
                server="AegisAl Template MCP",
                tool="resolve_report_template",
                invoked_at=invoked_at,
                node="report.template_mcp",
                exc=exc,
            )

    @staticmethod
    def _prepare_report_draft(state: ReportSubgraphState) -> ReportSubgraphState:
        scan_json = state.get("scan_json") or {}
        scan_data = scan_json.get("payload") if isinstance(scan_json.get("payload"), dict) else {}
        source_kind = str(state.get("source_kind") or "assistant_scan")
        try:
            created_at = now_iso()
            if source_kind == "agent_task":
                task = scan_data.get("task") if isinstance(scan_data.get("task"), dict) else scan_data
                result = task.get("result") if isinstance(task.get("result"), dict) else {}
                content = build_agent_task_markdown_report(
                    task,
                    mcp_audit=state.get("report_mcp") or {},
                    report_code_blocks=list((state.get("report_charts") or {}).get("code_blocks") or []),
                )
                title = f"{task.get('workspace_name') or '项目'} 代码安全漏洞扫描报告"
                metadata = {
                    "task_id": str(task.get("id") or ""),
                    "project_name": str(task.get("workspace_name") or "项目"),
                    "workspace_name": str(task.get("workspace_name") or ""),
                    "workspace_path": str(task.get("workspace_path") or ""),
                    "languages": list(task.get("languages") or []),
                    "user_id": state.get("user_id", "default"),
                    "session_id": state.get("session_id", "default"),
                    "language": state.get("response_language", "zh-Hans"),
                    "created_at": created_at,
                    "mode": "agent_static_scan",
                    "report_schema_version": REPORT_DOCUMENT_SCHEMA_VERSION,
                    "scan_json_schema": scan_json.get("$schema"),
                    "scan_json_sha256": ((scan_json.get("audit") or {}).get("payload_sha256")),
                    "report_metrics": _report_metrics_from_scan_json(
                        scan_json,
                        scan_data.get("report_metrics"),
                        language=str(state.get("response_language") or "zh-Hans"),
                    ),
                    "report_charts": state.get("report_charts") or {},
                    "chart_mcp": "build_scan_report_charts",
                    "report_mcp": state.get("report_mcp") or {},
                    "report_mcps": list(state.get("report_mcps") or []),
                }
                vulnerability_count = int(result.get("dependency_vulnerability_count") or 0)
                finding_count = int(result.get("total_findings") or 0)
                fingerprint = f"agent-task:{task.get('id') or ''}"
                mode = "agent_static_scan"
            else:
                content = build_dependency_markdown_report(
                    question=sanitize_public_text(scan_data.get("question") or "附件安全扫描"),
                    dependency_scan=scan_data.get("dependency_scan") or {},
                    records=list(scan_data.get("records") or []),
                    static_analysis=scan_data.get("static_analysis") or {},
                    summary=str(scan_data.get("summary") or "扫描已完成。"),
                    fields=dict(scan_data.get("fields") or {}),
                    language=str(state.get("response_language") or "zh-Hans"),
                    mcp_audit=state.get("report_mcp") or {},
                    report_code_blocks=list((state.get("report_charts") or {}).get("code_blocks") or []),
                )
                title = str(scan_data.get("title") or "依赖漏洞与代码漏洞分析报告")
                records = list(scan_data.get("records") or [])
                static_analysis = scan_data.get("static_analysis") or {}
                metadata = {
                    "user_id": state.get("user_id", "default"),
                    "session_id": state.get("session_id", "default"),
                    "report_schema_version": REPORT_DOCUMENT_SCHEMA_VERSION,
                    "created_at": created_at,
                    "scan_json_schema": scan_json.get("$schema"),
                    "scan_json_sha256": ((scan_json.get("audit") or {}).get("payload_sha256")),
                    "files": (scan_data.get("dependency_scan") or {}).get("files", []),
                    "language": state.get("response_language", "zh-Hans"),
                    "report_metrics": scan_data.get("report_metrics") or {},
                    "report_charts": state.get("report_charts") or {},
                    "chart_mcp": "build_scan_report_charts",
                    "report_mcp": state.get("report_mcp") or {},
                    "report_mcps": list(state.get("report_mcps") or []),
                }
                vulnerability_count = len(records)
                finding_count = int(static_analysis.get("finding_count") or len(static_analysis.get("findings") or []))
                fingerprint = str(scan_data.get("input_fingerprint") or "")
                mode = "dependency_vulnerability_report"
            metadata["report_plan"] = state.get("report_plan") or {}
            metadata["report_template"] = state.get("report_template") or {}
            metadata["report_qa"] = state.get("report_qa") or {}
            metadata["available_formats"] = list((state.get("report_plan") or {}).get("formats") or REPORT_FORMATS)
            state["report_draft"] = {
                "title": title,
                "content": content,
                "source_content": content,
                "metadata": metadata,
                "mode": mode,
                "vulnerability_count": vulnerability_count,
                "finding_count": finding_count,
                "input_fingerprint": fingerprint,
            }
            return _trace(state, "report.prepare_draft", "已根据扫描 JSON 准备报告事实草稿。")
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "报告生成失败。"
            return _trace(state, "report.prepare_draft", f"报告草稿准备失败：{state['error']}", "warning")

    @staticmethod
    def _build_mermaid(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        result: dict[str, Any] | None = None
        try:
            result = call_mcp_tool(
                agent_id="report_agent",
                tool_id="mcp__report_mermaid__build_report_mermaid",
                arguments={
                    "report_json": state.get("scan_json") or {},
                    "report_charts": state.get("report_charts") or {},
                    "sarif": state.get("report_sarif") or {},
                    "language": state.get("response_language") or "zh-Hans",
                },
            )
            diagrams = [dict(item) for item in result.get("diagrams") or [] if isinstance(item, dict)]
            for diagram in diagrams:
                artifact_index = diagram.get("artifact_index")
                if not isinstance(artifact_index, int):
                    raise ValueError("Mermaid MCP did not return a Host artifact index")
                image = read_mcp_artifact(result, index=artifact_index)
                image_digest = hashlib.sha256(image).hexdigest()
                if image_digest != str(diagram.get("image_sha256") or ""):
                    raise ValueError("Mermaid MCP image hash verification failed")
                diagram["image_base64"] = ""
            result["diagrams"] = diagrams
            state["report_mermaid"] = result
            encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            audit = _format_mcp_audit(
                server="AegisAl Mermaid MCP",
                tool="build_report_mermaid",
                invoked_at=invoked_at,
                input_sha256=str(result.get("input_sha256") or ""),
                output_sha256=hashlib.sha256(encoded).hexdigest(),
                media_type="application/vnd.secflow.mermaid+json",
                artifact_size=sum(
                    len(str(item.get("source") or "").encode("utf-8"))
                    + _mermaid_artifact_size(result, item)
                    for item in result.get("diagrams") or []
                ),
                renderer=str(result.get("renderer") or "mermaid"),
            )
            _append_format_audit(state, audit)
            return _trace(
                state,
                "report.mermaid_mcp",
                (
                    f"Mermaid MCP 已生成 {len(result.get('diagrams') or [])} 个可验证图表，"
                    f"完整呈现 {int(result.get('taint_path_count') or 0)} 条污点路径、"
                    f"{int(result.get('taint_node_count') or 0)} 个路径节点。"
                ),
                presentation=tool_call_presentation(
                    "build_report_mermaid",
                    state="completed",
                    title="Mermaid MCP",
                    input_summary={"scan_sha256": audit["input_sha256"]},
                    output={
                        "diagram_count": len(result.get("diagrams") or []),
                        "taint_path_count": int(result.get("taint_path_count") or 0),
                        "taint_node_count": int(result.get("taint_node_count") or 0),
                        "output_sha256": audit["output_sha256"],
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            if result is not None:
                release_mcp_artifacts(result)
            return _format_mcp_failure(
                state,
                server="AegisAl Mermaid MCP",
                tool="build_report_mermaid",
                invoked_at=invoked_at,
                node="report.mermaid_mcp",
                exc=exc,
            )

    @staticmethod
    def _render_markdown(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        draft = state.get("report_draft") or {}
        try:
            result = call_mcp_tool(
                agent_id="report_agent",
                tool_id="mcp__report_markdown__render_markdown_report",
                arguments={
                    "report_json": state.get("scan_json") or {},
                    "markdown": str(draft.get("content") or ""),
                    "mermaid": _hydrate_mermaid_artifacts(state.get("report_mermaid") or {}),
                    "language": state.get("response_language") or "zh-Hans",
                },
            )
            content = str(result.get("content") or "")
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if digest != str(result.get("output_sha256") or ""):
                raise ValueError("Markdown MCP output hash verification failed")
            draft["content"] = content
            state["report_draft"] = draft
            audit = _format_mcp_audit(
                server="AegisAl Markdown MCP",
                tool="render_markdown_report",
                invoked_at=invoked_at,
                input_sha256=str(result.get("input_sha256") or ""),
                output_sha256=digest,
                media_type=str(result.get("media_type") or "text/markdown; charset=utf-8"),
                artifact_size=len(content.encode("utf-8")),
                renderer=str(result.get("renderer") or "secflow-markdown"),
            )
            _append_format_audit(state, audit)
            _refresh_report_document(state)
            return _trace(
                state,
                "report.markdown_mcp",
                "Markdown MCP 已生成并校验 MD 报告。",
                presentation=tool_call_presentation(
                    "render_markdown_report",
                    state="completed",
                    title="Markdown MCP",
                    input_summary={"scan_sha256": audit["input_sha256"]},
                    output={"size": audit["artifact_size"], "output_sha256": digest},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return _format_mcp_failure(
                state,
                server="AegisAl Markdown MCP",
                tool="render_markdown_report",
                invoked_at=invoked_at,
                node="report.markdown_mcp",
                exc=exc,
            )

    @staticmethod
    def _render_word(state: ReportSubgraphState) -> ReportSubgraphState:
        return _render_binary_mcp(
            state,
            server="AegisAl Word MCP",
            tool="render_word_report",
            node="report.word_mcp",
            report_format="docx",
            signature=b"PK",
            tool_id="mcp__report_word__render_word_report",
        )

    @staticmethod
    def _quality_gate(state: ReportSubgraphState) -> ReportSubgraphState:
        try:
            _refresh_report_document(state)
            result = validate_report_quality(
                _materialize_report_document(state),
                state.get("report_plan") or {},
            )
            state["report_qa"] = result
            draft = state.get("report_draft") or {}
            metadata = dict(draft.get("metadata") or {})
            metadata["report_qa"] = result
            draft["metadata"] = metadata
            state["report_draft"] = draft
            _refresh_report_document(state)
            return _trace(
                state,
                "report.qa_agent",
                f"Report QA Agent 已通过 {len(result.get('checks') or [])} 项质量校验，得分 {result.get('score')}。",
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "报告 QA 校验失败。"
            return _trace(state, "report.qa_agent", state["error"], "warning")

    @staticmethod
    def _render_excel(state: ReportSubgraphState) -> ReportSubgraphState:
        return _render_binary_mcp(
            state,
            server="AegisAl Excel MCP",
            tool="render_excel_report",
            node="report.excel_mcp",
            report_format="xlsx",
            signature=b"PK",
            tool_id="mcp__report_excel__render_excel_report",
        )

    @staticmethod
    def _render_pdf(state: ReportSubgraphState) -> ReportSubgraphState:
        return _render_binary_mcp(
            state,
            server="AegisAl PDF MCP",
            tool="render_pdf_report",
            node="report.pdf_mcp",
            report_format="pdf",
            signature=b"%PDF",
            tool_id="mcp__report_pdf__render_pdf_report",
        )

    @staticmethod
    def _persist_report(state: ReportSubgraphState) -> ReportSubgraphState:
        draft = state.get("report_draft") or {}
        rendered = state.get("rendered_artifacts") or {}
        try:
            _refresh_report_document(state)
            draft = state.get("report_draft") or draft
            metadata = dict(draft.get("metadata") or {})
            metadata["report_mcps"] = list(state.get("report_mcps") or [])
            metadata["report_mermaid"] = _mermaid_audit_payload(state.get("report_mermaid") or {})
            artifacts: dict[str, Any] = {"md": str(draft.get("content") or "")}
            for report_format in ("docx", "xlsx", "pdf"):
                pending = rendered.get(report_format)
                if not isinstance(pending, dict):
                    raise ValueError(f"Missing pending {report_format.upper()} Host artifact")
                artifacts[report_format] = read_mcp_artifact(pending)
            saved = _store_for_state(state).save_json_report(
                str(draft.get("title") or "神盾安全报告"),
                str(draft.get("content") or ""),
                report_source=state.get("scan_json") or {},
                mode=str(draft.get("mode") or "dependency_vulnerability_report"),
                vulnerability_count=int(draft.get("vulnerability_count") or 0),
                finding_count=int(draft.get("finding_count") or 0),
                metadata=metadata,
                input_fingerprint=str(draft.get("input_fingerprint") or ""),
                rendered_artifacts=artifacts,
                report_document=_materialize_report_document(state),
            )
            missing = set(REPORT_FORMATS) - set(saved.get("available_formats") or [])
            if missing:
                raise RuntimeError(f"报告格式生成不完整：{', '.join(sorted(missing))}")
            state["report"] = saved
            state["report_ids"] = [str(saved.get("id") or "")]
            state["summary"] = f"报告已生成：{saved.get('file_name') or saved.get('title')}。"
            for pending in rendered.values():
                if isinstance(pending, dict):
                    release_mcp_artifacts(pending)
            release_mcp_artifacts(state.get("report_mermaid") or {})
            state["rendered_artifacts"] = {}
            return _trace(state, "report.persist", state["summary"])
        except Exception as exc:  # noqa: BLE001
            for pending in rendered.values():
                if isinstance(pending, dict):
                    release_mcp_artifacts(pending)
            release_mcp_artifacts(state.get("report_mermaid") or {})
            state["error"] = sanitize_public_text(str(exc)).strip() or "报告制品保存失败。"
            return _trace(state, "report.persist", f"报告制品保存失败：{state['error']}", "warning")

    @staticmethod
    def _confirm_download(state: ReportSubgraphState) -> ReportSubgraphState:
        formats = list(state.get("formats") or [])
        response = interrupt(
            {
                "kind": "report_download_confirmation",
                "action": str(state.get("action") or "download_report"),
                "report_ids": list(state.get("report_ids") or []),
                "formats": formats or list(REPORT_FORMATS),
                "allow_format_selection": not bool(formats),
                "question": "报告已准备好，是否确认下载？",
                "detail": "可下载单一格式、当前报告全部格式，或全部报告归档。",
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["cancelled"] = True
            state["summary"] = state.get("summary") or "已取消下载，报告仍保留在报告中心。"
            return _trace(state, "report.interrupt_download", "用户取消下载报告。")
        raw_selection = str((response or {}).get("format") or "").strip().lower()
        selected = _normalize_optional_format(raw_selection)
        if raw_selection == "all":
            state["formats"] = list(REPORT_FORMATS)
        elif selected:
            state["formats"] = [selected]
        elif not formats:
            state["formats"] = ["pdf"]
        return _trace(state, "report.interrupt_download", "用户已确认下载报告。")

    @staticmethod
    def _prepare_download(state: ReportSubgraphState) -> ReportSubgraphState:
        try:
            artifact = _store_for_state(state).prepare_download_artifact(
                list(state.get("report_ids") or []),
                list(state.get("formats") or ["pdf"]),
                user_id=str(state.get("user_id") or "default"),
            )
            state["artifacts"] = [artifact]
            state["summary"] = f"下载制品已准备好：{artifact.get('file_name')}。"
            return _trace(state, "report.prepare_download", state["summary"])
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "下载制品准备失败。"
            return _trace(state, "report.prepare_download", f"下载制品准备失败：{state['error']}", "warning")

    @staticmethod
    def _compose_result(state: ReportSubgraphState) -> ReportSubgraphState:
        if state.get("error"):
            state["summary"] = state["error"]
        elif not state.get("summary"):
            state["summary"] = "报告操作已完成。"
        return _trace(state, "report.compose_result", state["summary"], "warning" if state.get("error") else "completed")

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
        status = (
            "interrupted"
            if envelope
            else ("cancelled" if state.get("cancelled") else ("failed" if state.get("error") else "completed"))
        )
        return {
            "status": status,
            "thread_id": thread_id,
            "response_language": str(state.get("response_language") or "zh-Hans"),
            "interrupt": envelope,
            "summary": sanitize_public_text(state.get("summary") or (envelope or {}).get("question") or ""),
            "report": dict(state.get("report") or {}),
            "artifacts": list(state.get("artifacts") or []),
            "report_charts": dict(state.get("report_charts") or {}),
            "report_mermaid": _mermaid_audit_payload(state.get("report_mermaid") or {}),
            "report_plan": dict(state.get("report_plan") or {}),
            "report_template": dict(state.get("report_template") or {}),
            "report_qa": dict(state.get("report_qa") or {}),
            "report_translation": dict(state.get("report_translation") or {}),
            "report_mcp": dict(state.get("report_mcp") or {}),
            "report_mcps": list(state.get("report_mcps") or []),
            "error": sanitize_public_text(state.get("error") or ""),
            "trace": list(state.get("trace") or []),
        }


def looks_like_report_request(question: str) -> bool:
    text = str(question or "").strip()
    return bool(re.search(r"报告|report", text, flags=re.IGNORECASE) and re.search(r"生成|创建|下载|导出|generate|create|download|export", text, flags=re.IGNORECASE))


def report_outcome_answer(outcome: dict[str, Any]) -> dict[str, Any]:
    report = dict(outcome.get("report") or {})
    fields: dict[str, str] = {"报告操作状态": str(outcome.get("status") or "completed")}
    if report:
        fields["报告编号"] = str(report.get("id") or "")
        fields["报告文件"] = str(report.get("file_name") or "")
    return {
        "mode": "report_operation",
        "summary": str(outcome.get("summary") or (outcome.get("interrupt") or {}).get("question") or "报告操作等待确认。"),
        "fields": fields,
        "vulnerability_card": {},
        "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "chart_data": {},
        "artifacts": list(outcome.get("artifacts") or []),
        "report": report or None,
        "translation": dict(outcome.get("report_translation") or {}),
        "report_mcps": list(outcome.get("report_mcps") or []),
        "interrupt": outcome.get("interrupt"),
        "confidence": 1.0,
        "trace": list(outcome.get("trace") or []),
        "generated_at": now_iso(),
    }


def _trace(
    state: ReportSubgraphState,
    node: str,
    message: str,
    status: str = "completed",
    presentation: dict[str, Any] | None = None,
) -> ReportSubgraphState:
    item = {"node": node, "status": status, "message": sanitize_public_text(message), "time": now_iso()}
    if presentation:
        item["presentation"] = presentation
    state["trace"] = [
        *state.get("trace", []),
        item,
    ]
    thread_id = str(state.get("operation_thread_id") or "")
    with _REPORT_PROGRESS_LOCK:
        event_sink = _REPORT_PROGRESS_SINKS.get(thread_id)
    if event_sink is not None:
        try:
            event_sink(dict(item))
        except Exception:  # noqa: BLE001 - progress delivery must never break report generation.
            pass
    return state


def _refresh_report_document(state: ReportSubgraphState) -> None:
    state["report_document"] = _build_report_document_for_state(
        state,
        inline_visuals=False,
    )


def _materialize_report_document(state: ReportSubgraphState) -> dict[str, Any]:
    return _build_report_document_for_state(state, inline_visuals=True)


def _build_report_document_for_state(
    state: ReportSubgraphState,
    *,
    inline_visuals: bool,
) -> dict[str, Any]:
    draft = state.get("report_draft") or {}
    metadata = dict(draft.get("metadata") or {})
    metadata["report_mcps"] = list(state.get("report_mcps") or [])
    metadata["report_mermaid"] = _mermaid_audit_payload(state.get("report_mermaid") or {})
    metadata["report_plan"] = state.get("report_plan") or metadata.get("report_plan") or {}
    metadata["report_template"] = state.get("report_template") or metadata.get("report_template") or {}
    metadata["report_qa"] = state.get("report_qa") or metadata.get("report_qa") or {}
    draft["metadata"] = metadata
    state["report_draft"] = draft
    visuals = (
        _hydrate_mermaid_artifacts(state.get("report_mermaid") or {})
        if inline_visuals
        else _mermaid_audit_payload(state.get("report_mermaid") or {})
    )
    return build_report_document_json(
        str(draft.get("source_content") or draft.get("content") or ""),
        metadata,
        report_source=state.get("scan_json") or {},
        sarif=state.get("report_sarif") or {},
        visuals=visuals,
        rendered_markdown=str(draft.get("content") or ""),
    )


def _render_binary_mcp(
    state: ReportSubgraphState,
    *,
    server: str,
    tool: str,
    node: str,
    report_format: str,
    signature: bytes,
    tool_id: str,
) -> ReportSubgraphState:
    invoked_at = now_iso()
    result: dict[str, Any] | None = None
    retained = False
    try:
        _refresh_report_document(state)
        arguments = {"report_document": _materialize_report_document(state)}
        if report_format in {"docx", "pdf"}:
            arguments["mermaid"] = _hydrate_mermaid_artifacts(
                state.get("report_mermaid") or {}
            )
        result = call_mcp_tool(
            agent_id="report_agent",
            tool_id=tool_id,
            arguments=arguments,
        )
        payload = read_mcp_artifact(result)
        if not payload.startswith(signature):
            raise ValueError(f"{server} returned an invalid {report_format.upper()} signature")
        digest = hashlib.sha256(payload).hexdigest()
        if digest != str(result.get("output_sha256") or ""):
            raise ValueError(f"{server} output hash verification failed")
        state["rendered_artifacts"] = {
            **state.get("rendered_artifacts", {}),
            report_format: {
                "artifacts": list(result.get("artifacts") or []),
                "_mcp_runtime": dict(result.get("_mcp_runtime") or {}),
                "output_sha256": digest,
                "media_type": str(result.get("media_type") or "application/octet-stream"),
            },
        }
        retained = True
        audit = _format_mcp_audit(
            server=server,
            tool=tool,
            invoked_at=invoked_at,
            input_sha256=str(result.get("input_sha256") or ""),
            output_sha256=digest,
            media_type=str(result.get("media_type") or "application/octet-stream"),
            artifact_size=len(payload),
            renderer=str(result.get("renderer") or ""),
        )
        _append_format_audit(state, audit)
        return _trace(
            state,
            node,
            f"{server} 已生成并校验 {report_format.upper()} 报告。",
            presentation=tool_call_presentation(
                tool,
                state="completed",
                title=server,
                input_summary={"scan_sha256": audit["input_sha256"]},
                output={
                    "media_type": audit["media_type"],
                    "artifact_size": audit["artifact_size"],
                    "output_sha256": digest,
                },
            ),
        )
    except Exception as exc:  # noqa: BLE001
        if result is not None and not retained:
            release_mcp_artifacts(result)
        return _format_mcp_failure(
            state,
            server=server,
            tool=tool,
            invoked_at=invoked_at,
            node=node,
            exc=exc,
        )


def _format_mcp_audit(
    *,
    server: str,
    tool: str,
    invoked_at: str,
    input_sha256: str,
    output_sha256: str,
    media_type: str,
    artifact_size: int,
    renderer: str,
) -> dict[str, Any]:
    return {
        "server": server,
        "tool": tool,
        "transport": "stdio",
        "endpoint": "managed-child-process",
        "status": "completed",
        "invoked_at": invoked_at,
        "input_sha256": input_sha256,
        "output_sha256": output_sha256,
        "media_type": media_type,
        "artifact_size": int(artifact_size),
        "renderer": renderer,
    }


def _append_format_audit(state: ReportSubgraphState, audit: dict[str, Any]) -> None:
    state["report_mcps"] = [*state.get("report_mcps", []), dict(audit)]
    draft = state.get("report_draft")
    if isinstance(draft, dict):
        metadata = dict(draft.get("metadata") or {})
        metadata["report_mcps"] = list(state["report_mcps"])
        metadata["report_mermaid"] = _mermaid_audit_payload(state.get("report_mermaid") or {})
        draft["metadata"] = metadata
        state["report_draft"] = draft


def _mermaid_audit_payload(value: dict[str, Any]) -> dict[str, Any]:
    payload = {
        key: item
        for key, item in dict(value or {}).items()
        if key not in {"artifacts", "_mcp_runtime"}
    }
    payload["diagrams"] = [
        {key: item for key, item in diagram.items() if key != "image_base64"}
        for diagram in payload.get("diagrams") or []
        if isinstance(diagram, dict)
    ]
    return payload


def _hydrate_mermaid_artifacts(value: dict[str, Any]) -> dict[str, Any]:
    """Build transient inline visuals without placing binary data in checkpoints."""

    hydrated = _mermaid_audit_payload(value)
    diagrams = [dict(item) for item in hydrated.get("diagrams") or [] if isinstance(item, dict)]
    for diagram in diagrams:
        index = diagram.get("artifact_index")
        if not isinstance(index, int):
            raise ValueError("Mermaid diagram has no Host artifact index")
        payload = read_mcp_artifact(value, index=index)
        digest = hashlib.sha256(payload).hexdigest()
        if digest != str(diagram.get("image_sha256") or ""):
            raise ValueError("Mermaid Host artifact hash verification failed")
        diagram["image_base64"] = base64.b64encode(payload).decode("ascii")
    hydrated["diagrams"] = diagrams
    return hydrated


def _mermaid_artifact_size(result: dict[str, Any], diagram: dict[str, Any]) -> int:
    index = diagram.get("artifact_index")
    artifacts = result.get("artifacts")
    if not isinstance(index, int) or not isinstance(artifacts, list) or index >= len(artifacts):
        return 0
    item = artifacts[index]
    return int(item.get("size_bytes") or 0) if isinstance(item, dict) else 0


def _report_metrics_from_scan_json(
    scan_json: dict[str, Any],
    supplied: Any,
    *,
    language: str,
) -> dict[str, Any]:
    metrics = dict(supplied) if isinstance(supplied, dict) else {}
    counts = scan_json.get("counts") if isinstance(scan_json.get("counts"), dict) else {}
    facts = scan_json.get("facts") if isinstance(scan_json.get("facts"), dict) else {}
    payload = scan_json.get("payload") if isinstance(scan_json.get("payload"), dict) else {}
    task = payload.get("task") if isinstance(payload.get("task"), dict) else payload
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    dependencies = [item for item in facts.get("dependencies") or [] if isinstance(item, dict)]

    severity = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    aliases = {
        "SEVERE": "CRITICAL",
        "严重": "CRITICAL",
        "危急": "CRITICAL",
        "高危": "HIGH",
        "高": "HIGH",
        "MODERATE": "MEDIUM",
        "中危": "MEDIUM",
        "中": "MEDIUM",
        "低危": "LOW",
        "低": "LOW",
    }
    for item in [
        *[entry for entry in facts.get("dependency_vulnerabilities") or [] if isinstance(entry, dict)],
        *[entry for entry in facts.get("code_findings") or [] if isinstance(entry, dict)],
    ]:
        raw = str(item.get("severity") or "").strip().upper()
        normalized = aliases.get(raw, raw)
        if normalized in severity:
            severity[normalized] += 1

    dependency_vulnerabilities = int(counts.get("dependency_vulnerabilities") or 0)
    code_findings = int(counts.get("code_findings") or 0)
    metrics.update(
        {
            "language": str(metrics.get("language") or language),
            "generated_at": str(metrics.get("generated_at") or scan_json.get("completed_at") or now_iso()),
            "attachments": int(metrics.get("attachments") or result.get("total_files") or 0),
            "dependencies": int(counts.get("dependencies") or 0),
            "licenses": int(counts.get("licenses") or 0),
            "unresolved_dependencies": sum(1 for dependency in dependencies if not dependency.get("version")),
            "dependency_vulnerabilities": dependency_vulnerabilities,
            "code_findings": code_findings,
            "severity": severity,
            "high_risk": severity["CRITICAL"] + severity["HIGH"],
            "medium_risk": severity["MEDIUM"],
            "total_risks": dependency_vulnerabilities + code_findings,
            "has_dependency_scope": bool(dependencies or dependency_vulnerabilities or counts.get("licenses")),
            "has_code_scope": bool(result.get("language_results") or code_findings),
        }
    )
    return metrics


def _format_mcp_failure(
    state: ReportSubgraphState,
    *,
    server: str,
    tool: str,
    invoked_at: str,
    node: str,
    exc: Exception,
) -> ReportSubgraphState:
    message = sanitize_public_text(str(exc)).strip() or "未知 MCP 错误"
    audit = {
        "server": server,
        "tool": tool,
        "transport": "stdio",
        "endpoint": "managed-child-process",
        "status": "failed",
        "invoked_at": invoked_at,
        "error": message,
    }
    _append_format_audit(state, audit)
    state["error"] = f"{server} 调用失败，报告未登记：{message}"
    return _trace(
        state,
        node,
        state["error"],
        "warning",
        presentation=tool_call_presentation(
            tool,
            state="error",
            title=server,
            input_summary={"source_kind": state.get("source_kind") or "assistant_scan"},
            error=message,
        ),
    )


def _normalize_optional_format(value: Any) -> str:
    clean = str(value or "").strip().lower()
    aliases = {"markdown": "md", "htm": "html", "word": "docx"}
    clean = aliases.get(clean, clean)
    return clean if clean in REPORT_FORMATS else ""


def _report_owned_by(report: dict[str, Any], user_id: str) -> bool:
    metadata = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    owner = str(metadata.get("user_id") or "default")
    return owner == (user_id or "default")


def _store_for_state(state: ReportSubgraphState) -> ReportStore:
    root = str(state.get("report_store_root") or "").strip()
    return ReportStore(Path(root)) if root else report_store


report_capability_subgraph = ReportCapabilitySubgraph(checkpointer=persistent_checkpointer("reports"))
