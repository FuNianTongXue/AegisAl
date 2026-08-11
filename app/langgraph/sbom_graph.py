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
from app.agent.task_agent import collect_project_sbom, resolve_workspace_path
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
    license_scan: dict[str, Any]
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
    def __init__(
        self,
        *,
        checkpointer: Any | None = None,
        license_scanner: Callable[[str], dict[str, Any]] | None = None,
    ) -> None:
        self._checkpointer = checkpointer or MemorySaver()
        from app.agent.specialist_agents import SBOMLicenseCapability

        self._license_capability = SBOMLicenseCapability(license_scanner)
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
            "license_scan": {},
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

    def inspect(self, thread_id: str, *, user_id: str) -> dict[str, Any]:
        """Read a user-owned SBOM checkpoint without advancing its interrupt."""

        clean_thread_id = str(thread_id or "").strip()
        snapshot = self.graph.get_state(self._config(clean_thread_id))
        state = dict(snapshot.values) if isinstance(snapshot.values, dict) else {}
        if not state or str(state.get("user_id") or "default") != (str(user_id or "default").strip() or "default"):
            raise KeyError(clean_thread_id)
        interrupts = [
            item
            for task in snapshot.tasks
            for item in (getattr(task, "interrupts", ()) or ())
        ]
        if interrupts:
            state["__interrupt__"] = interrupts
        return self._operation_context(clean_thread_id, state)

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Project SBOM LangGraph Subgraph",
            "nodes": [
                {"id": "validate_sbom_request", "label": "校验项目范围与系统下载目标"},
                {"id": "extract_project_dependencies", "label": "解析完整项目依赖清单"},
                {"id": "identify_project_licenses", "label": "License MCP：SPDX 与 OSI 许可识别"},
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
                {"source": "extract_project_dependencies", "target": "identify_project_licenses", "label": "依赖事实固定"},
                {"source": "identify_project_licenses", "target": "build_sbom_json", "label": "许可事实固定"},
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
        graph.add_node("identify_project_licenses", self._identify_licenses)
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
            lambda state: "compose" if state.get("error") else "licenses",
            {"licenses": "identify_project_licenses", "compose": "compose_sbom_result"},
        )
        graph.add_edge("identify_project_licenses", "build_sbom_json")
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
            scan = collect_project_sbom(workspace)
            inferred_count = int(scan.get("inferred_count") or 0)
            internal_count = int(scan.get("internal_component_count") or 0)
            if not scan.get("manifest_files"):
                scan.setdefault("warnings", []).append(
                    "项目中未发现支持的依赖清单或锁文件，SBOM 无清单声明组件可收录。"
                )
                if inferred_count:
                    scan["warnings"].append(
                        f"另有 {inferred_count} 个源码引用组件因版本未知未纳入 SBOM。"
                    )
            inventory = dict(scan.get("inventory") or {})
            state["dependency_scan"] = scan
            return _trace(
                state,
                "sbom.extract_project_dependencies",
                (
                    f"已从 {len(scan.get('files') or [])} 个项目文件识别 {int(scan.get('dependency_count') or 0)} 个 SBOM 组件"
                    + (f"（另有 {inferred_count} 个源码引用观察，版本未知未纳入）" if inferred_count else "")
                    + (f"，已排除 {internal_count} 个项目自身组件。" if internal_count else "。")
                ),
                "completed" if scan.get("dependencies") else "warning",
                presentation=tool_call_presentation(
                    "extract_project_sbom_dependencies",
                    state="completed",
                    title="Project dependency extraction",
                    input_summary={
                        "manifest_files": int(inventory.get("manifest_files") or 0),
                        "source_files": int(inventory.get("source_files") or 0),
                    },
                    output={
                        "component_count": int(scan.get("dependency_count") or 0),
                        "inferred_count": inferred_count,
                        "rejected_files": len(scan.get("rejected_files") or []),
                        "warnings": list(scan.get("warnings") or []),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["error"] = sanitize_public_text(str(exc)).strip() or "项目依赖解析失败。"
            return _trace(state, "sbom.extract_project_dependencies", state["error"], "warning")

    def _identify_licenses(self, state: SBOMState) -> SBOMState:
        try:
            scan = self._license_capability.identify_project_licenses(str(state["workspace_path"]))
            if not isinstance(scan, dict):
                raise ValueError("许可识别器未返回结构化结果")
            state["license_scan"] = scan
            return _trace(
                state,
                "sbom.identify_project_licenses",
                (
                    f"项目许可识别完成：发现 {int(scan.get('license_count') or 0)} 种许可，"
                    f"覆盖状态 {scan.get('coverage_status') or 'unknown'}。"
                ),
                "completed" if scan.get("coverage_status") == "complete" else "warning",
                presentation=tool_call_presentation(
                    "identify_project_licenses",
                    state="completed" if scan.get("coverage_status") in {"complete", "partial"} else "error",
                    title="SecFlow License MCP identification",
                    input_summary={"workspace_name": Path(state["workspace_path"]).name},
                    output={
                        "license_count": int(scan.get("license_count") or 0),
                        "coverage_status": str(scan.get("coverage_status") or "unknown"),
                        "registry_status": str((scan.get("registry") or {}).get("status") or "unknown"),
                        "mcp": dict(scan.get("_license_mcp") or {}),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001 - license inventory failure must not block SBOM export.
            state["license_scan"] = {
                "schema_version": 1,
                "coverage_status": "failed",
                "license_count": 0,
                "licenses": [],
                "registry": {
                    "id": "osi-license-api",
                    "url": "https://opensource.org/api/licenses",
                    "status": "unavailable",
                    "error": type(exc).__name__,
                },
                "error": sanitize_public_text(str(exc)),
            }
            return _trace(
                state,
                "sbom.identify_project_licenses",
                f"许可识别失败，仍可生成带明确失败状态的 SBOM：{sanitize_public_text(str(exc))}",
                "warning",
            )

    @staticmethod
    def _build_sbom(state: SBOMState) -> SBOMState:
        workspace = Path(state["workspace_path"])
        state["sbom"] = build_cyclonedx_sbom(
            state.get("dependency_scan") or {},
            project_name=workspace.name,
            workspace_path=str(workspace),
            license_scan=state.get("license_scan") or {},
        )
        license_count = int((state.get("license_scan") or {}).get("license_count") or 0)
        return _trace(
            state,
            "sbom.build_sbom_json",
            (
                f"CycloneDX 兼容 SBOM JSON 已固定，共 {len((state.get('sbom') or {}).get('components') or [])} 个组件，"
                f"识别 {license_count} 种项目许可。"
            ),
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
        license_count = int((state.get("license_scan") or {}).get("license_count") or 0)
        detail = (
            f"工作簿将包含 {len((state.get('sbom') or {}).get('components') or [])} 个组件"
            f"和 {license_count} 种项目许可"
        )
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
            envelope = {
                **value,
                "interrupt_id": str(current.id),
                "thread_id": thread_id,
                "user_id": str(state.get("user_id") or "default"),
                "session_id": str(state.get("session_id") or "default"),
            }
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
        license_scan = state.get("license_scan") or {}
        license_names = [
            str(item.get("spdx_id") or item.get("name") or "").strip()
            for item in license_scan.get("licenses") or []
            if isinstance(item, dict) and str(item.get("spdx_id") or item.get("name") or "").strip()
        ]
        result = {
            "status": status,
            "thread_id": thread_id,
            "response_language": str(state.get("response_language") or "zh-Hans"),
            "interrupt": envelope,
            "summary": sanitize_public_text(state.get("summary") or (envelope or {}).get("question") or ""),
            "fields": {
                "项目": Path(str(state.get("workspace_path") or "project")).name,
                "SBOM 格式": f"{sbom.get('bomFormat') or 'CycloneDX'} {sbom.get('specVersion') or ''}".strip(),
                "组件数量": str(len(sbom.get("components") or [])),
                "依赖来源文件": str(len(dependency_scan.get("files") or [])),
                "项目许可": "、".join(license_names) or "未识别",
                "许可数量": str(int(license_scan.get("license_count") or 0)),
                "许可识别覆盖": str(license_scan.get("coverage_status") or "未执行"),
                "OSI 接口状态": str((license_scan.get("registry") or {}).get("status") or "未执行"),
                "版本未解析组件": str(sum(str(item.get("version") or "") == "UNKNOWN" for item in sbom.get("components") or [])),
                "源码引用观察（未纳入 SBOM）": str(int(dependency_scan.get("inferred_count") or 0)),
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
            "license_analysis": {
                "coverage_status": str(license_scan.get("coverage_status") or "not_requested"),
                "licenses": list(license_scan.get("licenses") or []),
                "registry": dict(license_scan.get("registry") or {}),
                "license_mcp": dict(license_scan.get("_license_mcp") or {}),
            },
        }
        result["_operation_context"] = ProjectSBOMSubgraph._operation_context(
            thread_id,
            state,
            public=result,
        )
        return result

    @staticmethod
    def _operation_context(
        thread_id: str,
        state: dict[str, Any],
        *,
        public: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if public is None:
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
                else "failed" if state.get("error") else "cancelled"
                if state.get("generation_cancelled") or state.get("download_cancelled")
                else "completed"
            )
            visible = {"status": status, "interrupt": envelope}
        else:
            visible = public
        sbom = state.get("sbom") if isinstance(state.get("sbom"), dict) else {}
        matching = state.get("matching") if isinstance(state.get("matching"), dict) else {}
        license_scan = state.get("license_scan") if isinstance(state.get("license_scan"), dict) else {}
        dependency_scan = state.get("dependency_scan") if isinstance(state.get("dependency_scan"), dict) else {}
        components = [
            {
                "bom_ref": str(item.get("bom-ref") or ""),
                "group": str(item.get("group") or ""),
                "name": str(item.get("name") or ""),
                "version": str(item.get("version") or "UNKNOWN"),
                "purl": str(item.get("purl") or ""),
            }
            for item in sbom.get("components") or []
            if isinstance(item, dict)
        ]
        return {
            "thread_id": thread_id,
            "project_name": Path(str(state.get("workspace_path") or "project")).name,
            "workspace_path": str(state.get("workspace_path") or ""),
            "status": str(visible.get("status") or "unknown"),
            "component_count": len(components),
            "inferred_count": int(dependency_scan.get("inferred_count") or 0),
            "components": components,
            "match_requested": bool(state.get("match_requested")),
            "matching": {
                key: value
                for key, value in matching.items()
                if key
                in {
                    "generated_at",
                    "requested_component_count",
                    "versioned_component_count",
                    "unresolved_version_count",
                    "attempted_component_count",
                    "completed_batch_count",
                    "failed_batch_count",
                    "matched_component_count",
                    "vulnerability_count",
                    "coverage_status",
                    "errors",
                    "records",
                }
            },
            "license_analysis": {
                "coverage_status": str(license_scan.get("coverage_status") or "not_requested"),
                "license_count": int(license_scan.get("license_count") or 0),
                "licenses": list(license_scan.get("licenses") or []),
                "registry": dict(license_scan.get("registry") or {}),
            },
            "interrupt": dict(visible.get("interrupt") or {}) or None,
            "artifacts": list(state.get("artifacts") or []),
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
        "license_analysis": dict(outcome.get("license_analysis") or {}),
        "generated_at": now_iso(),
    }


def sbom_follow_up_answer(operation: dict[str, Any], question: str = "") -> dict[str, Any]:
    matching = operation.get("matching") if isinstance(operation.get("matching"), dict) else {}
    component_count = int(operation.get("componentCount") or operation.get("component_count") or 0)
    match_requested = bool(operation.get("matchRequested") or operation.get("match_requested"))
    coverage = str(matching.get("coverage_status") or "not_requested")
    vulnerability_count = int(matching.get("vulnerability_count") or 0)
    records = [item for item in matching.get("records") or [] if isinstance(item, dict)]
    interrupt = operation.get("interrupt") if isinstance(operation.get("interrupt"), dict) else {}
    project_name = str(operation.get("projectName") or operation.get("project_name") or "项目")
    asks_license = any(token in str(question or "").casefold() for token in ("许可", "许可证", "license"))

    if asks_license:
        license_analysis = (
            operation.get("licenseAnalysis")
            if isinstance(operation.get("licenseAnalysis"), dict)
            else operation.get("license_analysis") if isinstance(operation.get("license_analysis"), dict) else {}
        )
        licenses = [item for item in license_analysis.get("licenses") or [] if isinstance(item, dict)]
        names = [str(item.get("spdx_id") or item.get("name") or "未命名许可") for item in licenses]
        summary = (
            f"### {project_name} 许可识别结果\n\n"
            f"共识别 {len(licenses)} 种项目许可，覆盖状态为 `{license_analysis.get('coverage_status') or 'not_requested'}`。"
        )
        if names:
            summary += "\n\n" + "\n".join(f"- `{name}`" for name in names)
    elif not match_requested:
        summary = (
            f"{project_name} 的 SBOM 已包含 {component_count} 个组件，但尚未执行组件漏洞匹配。"
            "请先在原确认卡片中决定是否匹配漏洞情报。"
        )
    elif coverage in {"not_requested", ""}:
        summary = f"{project_name} 的 SBOM 已包含 {component_count} 个组件，漏洞匹配结果尚未形成。"
    else:
        summary = (
            f"### {project_name} SBOM 漏洞匹配结果\n\n"
            f"共 {component_count} 个组件；匹配覆盖状态为 `{coverage}`；当前命中 {vulnerability_count} 个漏洞。"
        )
        if records:
            rows = ["| 漏洞编号 | 组件与版本 | 严重度 | 漏洞描述 |", "| --- | --- | --- | --- |"]
            for record in records[:50]:
                dependencies = [item for item in record.get("matched_dependencies") or [] if isinstance(item, dict)]
                component = "、".join(
                    f"{item.get('name') or '-'} {item.get('version') or '-'}" for item in dependencies
                ) or "-"
                description = str(record.get("summary_zh") or record.get("summary") or record.get("title") or "-")
                rows.append(
                    "| {id} | {component} | {severity} | {description} |".format(
                        id=str(record.get("id") or "-").replace("|", "/"),
                        component=component.replace("|", "/"),
                        severity=str(record.get("severity") or "UNKNOWN").replace("|", "/"),
                        description=" ".join(description.split()).replace("|", "/"),
                    )
                )
            summary += "\n\n" + "\n".join(rows)
    if interrupt:
        summary += f"\n\n原操作仍停留在“{interrupt.get('question') or interrupt.get('kind')}”，本次只读查询未确认或取消该节点。"
    return {
        "mode": "sbom_result_follow_up",
        "summary": summary,
        "fields": {
            "项目": project_name,
            "组件数量": str(component_count),
            "是否已请求漏洞匹配": "是" if match_requested else "否",
            "匹配覆盖状态": coverage,
            "匹配漏洞数量": str(vulnerability_count),
            "待确认操作": str(interrupt.get("kind") or "无"),
        },
        "vulnerability_card": {},
        "knowledge_graph": {"nodes": [], "edges": [], "node_count": 0, "edge_count": 0},
        "chart_data": {},
        "artifacts": list(operation.get("artifacts") or []),
        "interrupt": None,
        "confidence": 1.0,
        "token_usage": 0,
        "evidence_sources": [],
        "trace": [],
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
