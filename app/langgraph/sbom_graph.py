from __future__ import annotations

import json
from pathlib import Path
from threading import RLock
from typing import Any, Callable, TypedDict
from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, StateGraph
from langgraph.types import Command, interrupt

from app.agent.assistant_intent import sbom_skill_metadata
from app.agent.task_agent import collect_workspace_inventory, read_workspace_attachments, resolve_workspace_path
from app.dependencies import scan_dependency_attachments
from app.langgraph.checkpoints import (
    authorize_pending_interrupt,
    delete_checkpoint_thread,
    emit_transient_event,
    persistent_checkpointer,
    register_event_sink,
    unregister_event_sink,
)
from app.mcp.sbom import invoke_sbom_excel_mcp
from app.privacy import sanitize_public_text
from app.sbom import build_cyclonedx_sbom, canonical_sbom_json, match_sbom_vulnerabilities
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


class SBOMState(TypedDict, total=False):
    question: str
    workspace_path: str
    user_id: str
    session_id: str
    response_language: str
    destination_hint: str
    dependency_scan: dict[str, Any]
    sbom: dict[str, Any]
    matching: dict[str, Any]
    match_requested: bool
    generation_cancelled: bool
    download_cancelled: bool
    artifacts: list[dict[str, Any]]
    error: str
    summary: str
    trace: list[dict[str, Any]]
    event_sink_id: str
    event_sink: Callable[[dict[str, Any]], None]


class ProjectSBOMSubgraph:
    def __init__(self, *, checkpointer: Any | None = None) -> None:
        self._checkpointer = checkpointer or MemorySaver()
        self._owners: dict[str, tuple[str, str]] = {}
        self._lock = RLock()
        self.graph = self._build_graph()

    def start(self, payload: dict[str, Any], *, thread_id: str | None = None) -> dict[str, Any]:
        clean_thread_id = str(thread_id or f"sbom-{uuid4().hex}").strip()
        user_id = str(payload.get("user_id") or "default").strip() or "default"
        session_id = str(payload.get("session_id") or "default").strip() or "default"
        event_sink = payload.get("event_sink")
        seed: SBOMState = {
            **{key: value for key, value in payload.items() if key != "event_sink"},
            "question": str(payload.get("question") or ""),
            "workspace_path": str(payload.get("workspace_path") or ""),
            "user_id": user_id,
            "session_id": session_id,
            "response_language": str(payload.get("response_language") or "zh-Hans"),
            "destination_hint": _normalize_destination_hint(payload.get("destination_hint")),
            "dependency_scan": {},
            "sbom": {},
            "matching": {},
            "match_requested": False,
            "generation_cancelled": False,
            "download_cancelled": False,
            "artifacts": [],
            "error": "",
            "summary": "",
            "trace": list(payload.get("trace") or []),
            "event_sink_id": clean_thread_id,
        }
        with self._lock:
            self._owners[clean_thread_id] = (user_id, session_id)
        register_event_sink(clean_thread_id, event_sink)
        try:
            result = self.graph.invoke(seed, self._config(clean_thread_id))
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
        result = self.graph.invoke(Command(resume=resume_value), self._config(clean_thread_id))
        public = self._public_result(clean_thread_id, result)
        if public["status"] not in {"interrupted"}:
            with self._lock:
                self._owners.pop(clean_thread_id, None)
            delete_checkpoint_thread(self._checkpointer, clean_thread_id)
        return public

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Project SBOM LangGraph Subgraph",
            "nodes": [
                {"id": "validate_sbom_request", "label": "校验项目范围与系统下载目标"},
                {"id": "extract_project_dependencies", "label": "解析完整项目依赖清单"},
                {"id": "build_sbom_json", "label": "生成 CycloneDX 兼容 SBOM JSON"},
                {"id": "interrupt_match_vulnerabilities", "label": "Interrupt：确认匹配组件漏洞情报"},
                {"id": "match_sbom_vulnerabilities", "label": "按组件与版本匹配漏洞情报"},
                {"id": "interrupt_generate_sbom_excel", "label": "Interrupt：确认生成 SBOM Excel"},
                {"id": "sbom_excel_mcp", "label": "SBOM Excel MCP 消费固定 JSON"},
                {"id": "interrupt_download_sbom_excel", "label": "Interrupt：确认下载位置"},
                {"id": "compose_sbom_result", "label": "汇总 SBOM 结果与审计字段"},
            ],
            "edges": [
                {"source": "validate_sbom_request", "target": "extract_project_dependencies", "label": "项目范围有效"},
                {"source": "extract_project_dependencies", "target": "build_sbom_json", "label": "依赖事实固定"},
                {"source": "build_sbom_json", "target": "interrupt_match_vulnerabilities", "label": "存在组件"},
                {"source": "build_sbom_json", "target": "interrupt_generate_sbom_excel", "label": "空清单仍可导出"},
                {"source": "interrupt_match_vulnerabilities", "target": "match_sbom_vulnerabilities", "label": "用户确认匹配"},
                {"source": "interrupt_match_vulnerabilities", "target": "interrupt_generate_sbom_excel", "label": "用户仅导出 SBOM"},
                {"source": "match_sbom_vulnerabilities", "target": "interrupt_generate_sbom_excel", "label": "匹配结果固定"},
                {"source": "interrupt_generate_sbom_excel", "target": "sbom_excel_mcp", "label": "用户确认生成"},
                {"source": "interrupt_generate_sbom_excel", "target": "compose_sbom_result", "label": "用户暂不生成"},
                {"source": "sbom_excel_mcp", "target": "interrupt_download_sbom_excel", "label": "Excel 已生成"},
                {"source": "interrupt_download_sbom_excel", "target": "compose_sbom_result", "label": "用户确认或取消下载"},
            ],
        }

    def _build_graph(self):
        graph = StateGraph(SBOMState)
        graph.add_node("validate_sbom_request", self._validate_request)
        graph.add_node("extract_project_dependencies", self._extract_dependencies)
        graph.add_node("build_sbom_json", self._build_sbom)
        graph.add_node("interrupt_match_vulnerabilities", self._confirm_matching)
        graph.add_node("match_sbom_vulnerabilities", self._match_vulnerabilities)
        graph.add_node("interrupt_generate_sbom_excel", self._confirm_generation)
        graph.add_node("sbom_excel_mcp", self._generate_excel)
        graph.add_node("interrupt_download_sbom_excel", self._confirm_download)
        graph.add_node("compose_sbom_result", self._compose_result)
        graph.set_entry_point("validate_sbom_request")
        graph.add_conditional_edges(
            "validate_sbom_request",
            lambda state: "compose" if state.get("error") else "extract",
            {"extract": "extract_project_dependencies", "compose": "compose_sbom_result"},
        )
        graph.add_conditional_edges(
            "extract_project_dependencies",
            lambda state: "compose" if state.get("error") else "build",
            {"build": "build_sbom_json", "compose": "compose_sbom_result"},
        )
        graph.add_conditional_edges(
            "build_sbom_json",
            lambda state: "match" if (state.get("dependency_scan") or {}).get("dependencies") else "generate",
            {"match": "interrupt_match_vulnerabilities", "generate": "interrupt_generate_sbom_excel"},
        )
        graph.add_conditional_edges(
            "interrupt_match_vulnerabilities",
            lambda state: "match" if state.get("match_requested") else "generate",
            {"match": "match_sbom_vulnerabilities", "generate": "interrupt_generate_sbom_excel"},
        )
        graph.add_edge("match_sbom_vulnerabilities", "interrupt_generate_sbom_excel")
        graph.add_conditional_edges(
            "interrupt_generate_sbom_excel",
            lambda state: "compose" if state.get("generation_cancelled") else "excel",
            {"excel": "sbom_excel_mcp", "compose": "compose_sbom_result"},
        )
        graph.add_conditional_edges(
            "sbom_excel_mcp",
            lambda state: "download" if state.get("artifacts") and not state.get("error") else "compose",
            {"download": "interrupt_download_sbom_excel", "compose": "compose_sbom_result"},
        )
        graph.add_edge("interrupt_download_sbom_excel", "compose_sbom_result")
        graph.add_edge("compose_sbom_result", END)
        return graph.compile(checkpointer=self._checkpointer)

    @staticmethod
    def _validate_request(state: SBOMState) -> SBOMState:
        try:
            workspace = resolve_workspace_path(state.get("workspace_path") or "", apply_limits=False)
        except ValueError as exc:
            state["error"] = sanitize_public_text(str(exc)) or "项目路径无效。"
            return _trace(state, "sbom.validate_request", state["error"], "warning")
        state["workspace_path"] = str(workspace)
        state["destination_hint"] = _normalize_destination_hint(state.get("destination_hint"))
        return _trace(
            state,
            "sbom.validate_request",
            f"已确认项目范围：{workspace.name}；下载目标：{state['destination_hint']}。",
            presentation=tool_call_presentation(
                "validate_project_sbom_request",
                state="completed",
                title="Project SBOM request validation",
                input_summary={"workspace_name": workspace.name},
                output={"destination_hint": state["destination_hint"], "skill": sbom_skill_metadata()},
            ),
        )

    @staticmethod
    def _extract_dependencies(state: SBOMState) -> SBOMState:
        try:
            workspace = Path(state["workspace_path"])
            inventory = collect_workspace_inventory(workspace, apply_limits=False)
            manifest_files = list(inventory.get("manifest_files") or [])
            source_files = [path for paths in (inventory.get("files_by_language") or {}).values() for path in paths]
            selected = manifest_files or source_files
            attachments = read_workspace_attachments(workspace, selected, apply_limits=False)
            scan = scan_dependency_attachments(attachments, max_dependencies=None, include_all_attachments=True)
            scan["inventory"] = {
                "manifest_files": len(manifest_files),
                "source_files": len(source_files),
                "selected_files": len(selected),
                "skipped_files": int(inventory.get("skipped_files") or 0),
            }
            state["dependency_scan"] = scan
            return _trace(
                state,
                "sbom.extract_project_dependencies",
                f"已从 {len(scan.get('files') or [])} 个项目文件识别 {int(scan.get('dependency_count') or 0)} 个组件。",
                "completed" if scan.get("dependencies") else "warning",
                presentation=tool_call_presentation(
                    "extract_project_sbom_dependencies",
                    state="completed",
                    title="Project dependency extraction",
                    input_summary={"manifest_files": len(manifest_files), "fallback_source_files": 0 if manifest_files else len(source_files)},
                    output={"component_count": int(scan.get("dependency_count") or 0), "rejected_files": len(scan.get("rejected_files") or [])},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "项目依赖解析失败。"
            return _trace(state, "sbom.extract_project_dependencies", state["error"], "warning")

    @staticmethod
    def _build_sbom(state: SBOMState) -> SBOMState:
        workspace = Path(state["workspace_path"])
        state["sbom"] = build_cyclonedx_sbom(
            state.get("dependency_scan") or {},
            project_name=workspace.name,
            workspace_path=str(workspace),
        )
        return _trace(
            state,
            "sbom.build_sbom_json",
            f"CycloneDX 兼容 SBOM JSON 已固定，共 {len((state.get('sbom') or {}).get('components') or [])} 个组件。",
        )

    @staticmethod
    def _confirm_matching(state: SBOMState) -> SBOMState:
        count = len((state.get("sbom") or {}).get("components") or [])
        response = interrupt(
            {
                "kind": "sbom_vulnerability_match_confirmation",
                "action": "match_sbom_vulnerabilities",
                "question": "SBOM 组件清单已生成，是否匹配漏洞情报？",
                "detail": f"当前共 {count} 个组件。确认后将按生态、组件和明确版本匹配本地及实时漏洞情报；不确认也可继续导出纯 SBOM。",
                "options": ["confirm", "cancel"],
            }
        )
        state["match_requested"] = str((response or {}).get("decision") or "").lower() == "confirm"
        message = "用户已确认匹配 SBOM 组件漏洞情报。" if state["match_requested"] else "用户选择导出纯 SBOM，不匹配漏洞情报。"
        return _trace(state, "sbom.interrupt_match_vulnerabilities", message)

    @staticmethod
    def _match_vulnerabilities(state: SBOMState) -> SBOMState:
        try:
            sbom, matching = match_sbom_vulnerabilities(
                state.get("sbom") or {},
                state.get("dependency_scan") or {},
                response_language=state.get("response_language") or "zh-Hans",
            )
            state["sbom"] = sbom
            state["matching"] = matching
            return _trace(
                state,
                "sbom.match_vulnerabilities",
                f"组件漏洞匹配完成：命中 {int(matching.get('vulnerability_count') or 0)} 个漏洞，覆盖状态 {matching.get('coverage_status')}。",
                "completed" if matching.get("coverage_status") == "complete" else "warning",
                presentation=tool_call_presentation(
                    "match_sbom_vulnerabilities",
                    state="completed" if matching.get("coverage_status") == "complete" else "error",
                    title="SBOM vulnerability intelligence matching",
                    input_summary={"versioned_components": matching.get("versioned_component_count")},
                    output={
                        "vulnerability_count": matching.get("vulnerability_count"),
                        "matched_component_count": matching.get("matched_component_count"),
                        "coverage_status": matching.get("coverage_status"),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["matching"] = {"coverage_status": "failed", "errors": [type(exc).__name__], "records": []}
            return _trace(
                state,
                "sbom.match_vulnerabilities",
                f"漏洞匹配失败，仍可导出纯 SBOM：{sanitize_public_text(str(exc))}",
                "warning",
            )

    @staticmethod
    def _confirm_generation(state: SBOMState) -> SBOMState:
        matching = state.get("matching") or {}
        detail = f"工作簿将包含 {len((state.get('sbom') or {}).get('components') or [])} 个组件"
        if state.get("match_requested"):
            detail += f"和 {int(matching.get('vulnerability_count') or 0)} 个已匹配漏洞"
        response = interrupt(
            {
                "kind": "sbom_excel_generation_confirmation",
                "action": "generate_sbom_excel",
                "question": "是否根据固定 SBOM JSON 生成 Excel？",
                "detail": f"{detail}，并附带来源、覆盖状态、JSON 指纹与审计数据。",
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["generation_cancelled"] = True
            return _trace(state, "sbom.interrupt_generate_excel", "用户选择暂不生成 SBOM Excel。")
        return _trace(state, "sbom.interrupt_generate_excel", "用户已确认生成 SBOM Excel。")

    @staticmethod
    def _generate_excel(state: SBOMState) -> SBOMState:
        try:
            workspace_name = Path(state["workspace_path"]).name
            artifact = invoke_sbom_excel_mcp(
                {
                    "sbom_json": canonical_sbom_json(state.get("sbom") or {}),
                    "matching_json": json.dumps(state.get("matching") or {}, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                    "project_name": workspace_name,
                    "generated_at": str(((state.get("sbom") or {}).get("metadata") or {}).get("timestamp") or now_iso()),
                }
            )
            state["artifacts"] = [artifact]
            state["summary"] = f"项目 SBOM Excel 已生成：{artifact.get('file_name')}。"
            return _trace(
                state,
                "sbom.excel_mcp",
                state["summary"],
                presentation=tool_call_presentation(
                    "export_project_sbom_excel",
                    state="completed",
                    title="SBOM Excel MCP",
                    input_summary={
                        "component_count": len((state.get("sbom") or {}).get("components") or []),
                        "vulnerability_count": len((state.get("sbom") or {}).get("vulnerabilities") or []),
                    },
                    output={"artifact_id": artifact.get("id"), "sha256": artifact.get("sha256")},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "SBOM Excel MCP 生成失败。"
            return _trace(state, "sbom.excel_mcp", state["error"], "warning")

    @staticmethod
    def _confirm_download(state: SBOMState) -> SBOMState:
        artifact = (state.get("artifacts") or [{}])[0]
        destination_hint = _normalize_destination_hint(state.get("destination_hint"))
        if destination_hint == "desktop":
            question = "SBOM Excel 已生成，是否下载到本机桌面？"
            detail = f"客户端会通过 macOS 系统目录 API 定位当前用户桌面，不使用模型生成的绝对路径。文件：{artifact.get('file_name')}"
        else:
            question = "SBOM Excel 已生成，是否选择目录并下载？"
            detail = str(artifact.get("file_name") or "SecFlow-project-SBOM.xlsx")
        response = interrupt(
            {
                "kind": "sbom_excel_download_confirmation",
                "action": "download_sbom_excel",
                "artifact_ids": [str(artifact.get("id") or "")],
                "destination_hint": destination_hint,
                "question": question,
                "detail": detail,
                "options": ["confirm", "cancel"],
            }
        )
        if str((response or {}).get("decision") or "").lower() != "confirm":
            state["download_cancelled"] = True
            return _trace(state, "sbom.interrupt_download_excel", "用户选择暂不下载 SBOM Excel。")
        state["summary"] = f"下载已确认：{artifact.get('file_name')}。"
        return _trace(state, "sbom.interrupt_download_excel", f"用户已确认下载 SBOM Excel，目标提示为 {destination_hint}。")

    @staticmethod
    def _compose_result(state: SBOMState) -> SBOMState:
        if state.get("error"):
            state["summary"] = state["error"]
        elif not state.get("summary"):
            component_count = len((state.get("sbom") or {}).get("components") or [])
            state["summary"] = f"项目 SBOM 已生成 JSON 清单，共 {component_count} 个组件。"
        return _trace(
            state,
            "sbom.compose_result",
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
            envelope = {**value, "interrupt_id": str(current.id), "thread_id": thread_id}
        if envelope:
            status = "interrupted"
        elif state.get("error"):
            status = "failed"
        elif state.get("generation_cancelled") or state.get("download_cancelled"):
            status = "cancelled"
        else:
            status = "completed"
        sbom = state.get("sbom") or {}
        matching = state.get("matching") or {}
        dependency_scan = state.get("dependency_scan") or {}
        return {
            "status": status,
            "thread_id": thread_id,
            "interrupt": envelope,
            "summary": sanitize_public_text(state.get("summary") or (envelope or {}).get("question") or ""),
            "fields": {
                "项目": Path(str(state.get("workspace_path") or "project")).name,
                "SBOM 格式": f"{sbom.get('bomFormat') or 'CycloneDX'} {sbom.get('specVersion') or ''}".strip(),
                "组件数量": str(len(sbom.get("components") or [])),
                "依赖来源文件": str(len(dependency_scan.get("files") or [])),
                "版本未解析组件": str(sum(str(item.get("version") or "") == "UNKNOWN" for item in sbom.get("components") or [])),
                "是否匹配漏洞": "是" if state.get("match_requested") else "否",
                "匹配漏洞数量": str(int(matching.get("vulnerability_count") or 0)),
                "匹配覆盖状态": str(matching.get("coverage_status") or "未执行"),
                "下载目标": _normalize_destination_hint(state.get("destination_hint")),
                "SBOM 序列号": str(sbom.get("serialNumber") or ""),
            },
            "artifacts": list(state.get("artifacts") or []),
            "error": sanitize_public_text(state.get("error") or ""),
            "trace": list(state.get("trace") or []),
            "skill": sbom_skill_metadata(),
        }


def sbom_outcome_answer(outcome: dict[str, Any]) -> dict[str, Any]:
    return {
        "mode": "project_sbom_export",
        "summary": str(outcome.get("summary") or (outcome.get("interrupt") or {}).get("question") or "项目 SBOM 等待确认。"),
        "fields": dict(outcome.get("fields") or {}),
        "vulnerability_card": {},
        "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "chart_data": {},
        "artifacts": list(outcome.get("artifacts") or []),
        "interrupt": outcome.get("interrupt"),
        "confidence": 0.96 if not outcome.get("error") else 0.5,
        "token_usage": 0,
        "evidence_sources": [],
        "trace": list(outcome.get("trace") or []),
        "generated_at": now_iso(),
    }


def _normalize_destination_hint(value: Any) -> str:
    clean = str(value or "unspecified").strip().lower().replace("-", "_")
    return clean if clean in {"desktop", "downloads", "documents", "choose", "unspecified"} else "unspecified"


def _trace(
    state: SBOMState,
    node: str,
    message: str,
    status: str = "completed",
    presentation: dict[str, Any] | None = None,
) -> SBOMState:
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


project_sbom_subgraph = ProjectSBOMSubgraph(checkpointer=persistent_checkpointer("project-sbom"))
