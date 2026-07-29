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

from app.privacy import sanitize_public_text
from app.langgraph.checkpoints import (
    authorize_pending_interrupt,
    delete_checkpoint_thread,
    persistent_checkpointer,
)
from app.mcp.report_charts import invoke_report_chart_mcp
from app.mcp.report_markdown import invoke_report_markdown_mcp
from app.mcp.report_mermaid import invoke_report_mermaid_mcp
from app.mcp.report_pdf import invoke_report_pdf_mcp
from app.mcp.report_word import invoke_report_word_mcp
from app.reports import (
    build_report_document_json,
    build_scan_result_json,
    build_agent_task_markdown_report,
    build_dependency_markdown_report,
    ReportStore,
    report_store,
)
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


REPORT_FORMATS = ("md", "html", "docx", "pdf")
_REPORT_ID = re.compile(r"report-[A-Za-z0-9._:+-]+", flags=re.IGNORECASE)


class ReportSubgraphState(TypedDict, total=False):
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
    report_mermaid: dict[str, Any]
    report_mcp: dict[str, Any]
    report_mcps: list[dict[str, Any]]
    report_draft: dict[str, Any]
    report_document: dict[str, Any]
    rendered_artifacts: dict[str, str]
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
            "report_mermaid": {},
            "report": {},
            "report_mcps": [],
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
        result = self.graph.invoke(seed, self._config(clean_thread_id))
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
            "decision": "confirm" if str(decision).strip().lower() in {"confirm", "confirmed", "yes", "true"} else "cancel",
            "format": _normalize_optional_format(report_format),
        }
        result = self.graph.invoke(Command(resume=resume_value), self._config(clean_thread_id))
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
                {"id": "report_chart_mcp", "label": "Report Chart MCP 消费 JSON 并生成图表数据"},
                {"id": "prepare_report_draft", "label": "根据已核验 JSON 准备报告事实草稿"},
                {"id": "report_mermaid_mcp", "label": "Mermaid MCP 生成关系图与严重度图"},
                {"id": "report_markdown_mcp", "label": "Markdown MCP 生成 MD 报告"},
                {"id": "report_word_mcp", "label": "Word MCP 生成 DOCX 报告"},
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
                {"source": "build_scan_result_json", "target": "report_chart_mcp", "label": "JSON 校验与哈希完成"},
                {"source": "report_chart_mcp", "target": "prepare_report_draft", "label": "图表事实已生成"},
                {"source": "prepare_report_draft", "target": "report_mermaid_mcp", "label": "报告事实草稿已准备"},
                {"source": "report_mermaid_mcp", "target": "report_markdown_mcp", "label": "Mermaid 图已生成"},
                {"source": "report_markdown_mcp", "target": "report_word_mcp", "label": "Markdown 已生成"},
                {"source": "report_word_mcp", "target": "report_pdf_mcp", "label": "DOCX 已生成并校验"},
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
        graph.add_node("report_chart_mcp", self._build_charts)
        graph.add_node("prepare_report_draft", self._prepare_report_draft)
        graph.add_node("report_mermaid_mcp", self._build_mermaid)
        graph.add_node("report_markdown_mcp", self._render_markdown)
        graph.add_node("report_word_mcp", self._render_word)
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
            lambda state: "compose" if state.get("error") else "charts",
            {"charts": "report_chart_mcp", "compose": "compose_report_result"},
        )
        graph.add_conditional_edges(
            "report_chart_mcp",
            lambda state: "compose" if state.get("error") else "draft",
            {"draft": "prepare_report_draft", "compose": "compose_report_result"},
        )
        for source, success, target in (
            ("prepare_report_draft", "mermaid", "report_mermaid_mcp"),
            ("report_mermaid_mcp", "markdown", "report_markdown_mcp"),
            ("report_markdown_mcp", "word", "report_word_mcp"),
            ("report_word_mcp", "pdf", "report_pdf_mcp"),
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
                "detail": "确认后先校验代码与依赖 JSON，再依次调用 Mermaid、Markdown、Word 和 PDF MCP；HTML 由已核验 Markdown 转换。",
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
    def _build_charts(state: ReportSubgraphState) -> ReportSubgraphState:
        invoked_at = now_iso()
        try:
            charts = invoke_report_chart_mcp(
                {"report_json": state.get("scan_json") or {}}
            )
            state["report_charts"] = charts
            state["report_mcp"] = {
                "server": "SecFlow Report Chart MCP",
                "tool": "build_scan_report_charts",
                "transport": "in-process",
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
                "server": "SecFlow Report Chart MCP",
                "tool": "build_scan_report_charts",
                "transport": "in-process",
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
                    "report_schema_version": 4,
                    "scan_json_schema": scan_json.get("$schema"),
                    "scan_json_sha256": ((scan_json.get("audit") or {}).get("payload_sha256")),
                    "report_metrics": scan_data.get("report_metrics") or {},
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
                    "report_schema_version": 4,
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
            state["report_draft"] = {
                "title": title,
                "content": content,
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
        try:
            result = invoke_report_mermaid_mcp(
                {
                    "report_json": state.get("scan_json") or {},
                    "report_charts": state.get("report_charts") or {},
                    "language": state.get("response_language") or "zh-Hans",
                }
            )
            state["report_mermaid"] = result
            encoded = json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
            audit = _format_mcp_audit(
                server="SecFlow Mermaid MCP",
                tool="build_report_mermaid",
                invoked_at=invoked_at,
                input_sha256=str(result.get("input_sha256") or ""),
                output_sha256=hashlib.sha256(encoded).hexdigest(),
                media_type="text/vnd.mermaid",
                artifact_size=sum(len(str(item.get("source") or "").encode("utf-8")) for item in result.get("diagrams") or []),
                renderer=str(result.get("renderer") or "mermaid"),
            )
            _append_format_audit(state, audit)
            return _trace(
                state,
                "report.mermaid_mcp",
                f"Mermaid MCP 已生成 {len(result.get('diagrams') or [])} 个可验证图表。",
                presentation=tool_call_presentation(
                    "build_report_mermaid",
                    state="completed",
                    title="Mermaid MCP",
                    input_summary={"scan_sha256": audit["input_sha256"]},
                    output={"diagram_count": len(result.get("diagrams") or []), "output_sha256": audit["output_sha256"]},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return _format_mcp_failure(
                state,
                server="SecFlow Mermaid MCP",
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
            result = invoke_report_markdown_mcp(
                {
                    "report_json": state.get("scan_json") or {},
                    "markdown": str(draft.get("content") or ""),
                    "mermaid": state.get("report_mermaid") or {},
                    "language": state.get("response_language") or "zh-Hans",
                }
            )
            content = str(result.get("content") or "")
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            if digest != str(result.get("output_sha256") or ""):
                raise ValueError("Markdown MCP output hash verification failed")
            draft["content"] = content
            state["report_draft"] = draft
            audit = _format_mcp_audit(
                server="SecFlow Markdown MCP",
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
                server="SecFlow Markdown MCP",
                tool="render_markdown_report",
                invoked_at=invoked_at,
                node="report.markdown_mcp",
                exc=exc,
            )

    @staticmethod
    def _render_word(state: ReportSubgraphState) -> ReportSubgraphState:
        return _render_binary_mcp(
            state,
            server="SecFlow Word MCP",
            tool="render_word_report",
            node="report.word_mcp",
            report_format="docx",
            signature=b"PK",
            invoke=invoke_report_word_mcp,
        )

    @staticmethod
    def _render_pdf(state: ReportSubgraphState) -> ReportSubgraphState:
        return _render_binary_mcp(
            state,
            server="SecFlow PDF MCP",
            tool="render_pdf_report",
            node="report.pdf_mcp",
            report_format="pdf",
            signature=b"%PDF",
            invoke=invoke_report_pdf_mcp,
        )

    @staticmethod
    def _persist_report(state: ReportSubgraphState) -> ReportSubgraphState:
        draft = state.get("report_draft") or {}
        rendered = state.get("rendered_artifacts") or {}
        try:
            metadata = dict(draft.get("metadata") or {})
            metadata["report_mcps"] = list(state.get("report_mcps") or [])
            metadata["report_mermaid"] = dict(state.get("report_mermaid") or {})
            artifacts = {
                "md": str(draft.get("content") or ""),
                "docx": base64.b64decode(str(rendered.get("docx") or ""), validate=True),
                "pdf": base64.b64decode(str(rendered.get("pdf") or ""), validate=True),
            }
            saved = _store_for_state(state).save_json_report(
                str(draft.get("title") or "SecFlow 安全报告"),
                str(draft.get("content") or ""),
                report_source=state.get("scan_json") or {},
                mode=str(draft.get("mode") or "dependency_vulnerability_report"),
                vulnerability_count=int(draft.get("vulnerability_count") or 0),
                finding_count=int(draft.get("finding_count") or 0),
                metadata=metadata,
                input_fingerprint=str(draft.get("input_fingerprint") or ""),
                rendered_artifacts=artifacts,
            )
            missing = set(REPORT_FORMATS) - set(saved.get("available_formats") or [])
            if missing:
                raise RuntimeError(f"报告格式生成不完整：{', '.join(sorted(missing))}")
            state["report"] = saved
            state["report_ids"] = [str(saved.get("id") or "")]
            state["summary"] = f"报告已生成：{saved.get('file_name') or saved.get('title')}。"
            return _trace(state, "report.persist", state["summary"])
        except Exception as exc:  # noqa: BLE001
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
        selected = _normalize_optional_format((response or {}).get("format"))
        if selected:
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
            }
        status = (
            "interrupted"
            if envelope
            else ("cancelled" if state.get("cancelled") else ("failed" if state.get("error") else "completed"))
        )
        return {
            "status": status,
            "thread_id": thread_id,
            "interrupt": envelope,
            "summary": sanitize_public_text(state.get("summary") or (envelope or {}).get("question") or ""),
            "report": dict(state.get("report") or {}),
            "artifacts": list(state.get("artifacts") or []),
            "report_charts": dict(state.get("report_charts") or {}),
            "report_mermaid": dict(state.get("report_mermaid") or {}),
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
    return state


def _refresh_report_document(state: ReportSubgraphState) -> None:
    draft = state.get("report_draft") or {}
    metadata = dict(draft.get("metadata") or {})
    metadata["report_mcps"] = list(state.get("report_mcps") or [])
    metadata["report_mermaid"] = dict(state.get("report_mermaid") or {})
    draft["metadata"] = metadata
    state["report_draft"] = draft
    state["report_document"] = build_report_document_json(
        str(draft.get("content") or ""),
        metadata,
        report_source=state.get("scan_json") or {},
    )


def _render_binary_mcp(
    state: ReportSubgraphState,
    *,
    server: str,
    tool: str,
    node: str,
    report_format: str,
    signature: bytes,
    invoke: Any,
) -> ReportSubgraphState:
    invoked_at = now_iso()
    try:
        _refresh_report_document(state)
        result = invoke(
            {
                "report_document": state.get("report_document") or {},
                "mermaid": state.get("report_mermaid") or {},
            }
        )
        payload = base64.b64decode(str(result.get("artifact_base64") or ""), validate=True)
        if not payload.startswith(signature):
            raise ValueError(f"{server} returned an invalid {report_format.upper()} signature")
        digest = hashlib.sha256(payload).hexdigest()
        if digest != str(result.get("output_sha256") or ""):
            raise ValueError(f"{server} output hash verification failed")
        state["rendered_artifacts"] = {
            **state.get("rendered_artifacts", {}),
            report_format: base64.b64encode(payload).decode("ascii"),
        }
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
        "transport": "in-process",
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
        metadata["report_mermaid"] = dict(state.get("report_mermaid") or {})
        draft["metadata"] = metadata
        state["report_draft"] = draft


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
        "transport": "in-process",
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
