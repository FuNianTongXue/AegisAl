from __future__ import annotations

import hashlib
import json
import os
import time as monotonic_time
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any, Callable, Mapping, TypedDict
from uuid import uuid4

try:
    from langgraph.graph import END, StateGraph
except Exception:  # pragma: no cover - packaged fallback
    END = "__end__"
    StateGraph = None

from app.dependencies import (
    attachment_kind,
    dependency_attachment_priority,
    is_allowed_attachment_name,
    is_python_requirements_name,
    read_project_identities,
    scan_dependency_attachments,
    split_dependency_layers,
)
from app.language_support import language_for_file, supported_flow_languages
from app.privacy import sanitize_public_text
from app.agent.project_adaptive_scan import (
    MAX_ADAPTATION_ITERATIONS,
    OverlaySynthesizer,
    apply_overlay_classification,
    build_overlay_request,
    build_project_profile,
    default_overlay_synthesizer,
    empty_project_overlay,
    fuse_project_evidence,
    overlay_languages,
    overlay_preprocessor_definitions,
    project_adaptive_skill_metadata,
    project_overlay_rule_file,
)
from app.composition import SecFlowRuntime, secflow_runtime, task_plugin_state
from app.langgraph.report_graph import report_capability_subgraph
from app.mcp.protocol import CodeScanMCPClient, CodeScanMCPError
from app.agent.specialist_agents import SBOMLicenseCapability
from app.sbom import build_cyclonedx_sbom, match_sbom_vulnerabilities
from app.semgrep_tool import semgrep_rule_paths_for_language, semgrep_tool
from app.source_filter import EXCLUDED_SOURCE_PARTS, is_analyzable_source_path, is_symlink_like_source_stub
from app.storage import now_iso
from app.agent.task_store import AgentTaskStore, clear_cancelled_task_data


MAX_WORKSPACE_FILES = 300
MAX_WORKSPACE_MANIFEST_FILES = 80
MAX_WORKSPACE_FILE_BYTES = 500_000
MAX_WORKSPACE_TOTAL_BYTES = 6_000_000
MAX_AGENT_DEPENDENCIES = 2_000
MAX_AGENT_FINDINGS_PER_LANGUAGE = 2_000
MAX_AGENT_FILE_PATH_PREVIEW = 300
SCAN_HEARTBEAT_INTERVAL_SECONDS = 5.0
LANGUAGE_ORDER = ("java", "python", "go", "c", "cpp", "csharp", "rust", "solidity")
LANGUAGE_LABELS = {
    "java": "Java",
    "python": "Python",
    "go": "Go",
    "c": "C",
    "cpp": "C++",
    "csharp": "C#",
    "rust": "Rust",
    "solidity": "Solidity",
}
TERMINAL_TASK_STATUSES = {"completed", "failed", "cancelled", "interrupted"}
TERMINAL_PLAN_STATUSES = {"completed", "skipped"}


class TaskCancelled(RuntimeError):
    pass


def agent_task_report_ready(task: dict[str, Any]) -> bool:
    """Require a finalized result, terminal plan, and persisted completion event."""

    if task.get("status") != "completed" or not isinstance(task.get("result"), dict):
        return False
    if language_scan_failure_reasons(task["result"]):
        return False
    plan = task.get("plan")
    if not isinstance(plan, list) or not plan:
        return False
    if any(
        str(step.get("status") or "") not in TERMINAL_PLAN_STATUSES
        for step in plan
        if isinstance(step, dict)
    ):
        return False
    events = task.get("events") if isinstance(task.get("events"), list) else []
    return any(
        event.get("type") == "task.completed" and event.get("status") == "completed"
        for event in events
        if isinstance(event, dict)
    )


def language_scan_failure_reasons(result: dict[str, Any]) -> list[str]:
    language_results = result.get("language_results")
    declared_languages = [
        str(item).strip()
        for item in result.get("languages") or []
        if str(item).strip()
    ]
    if not isinstance(language_results, dict):
        return ["缺少语言扫描结果"] if declared_languages else []

    failures: list[str] = []
    languages = declared_languages or [str(item) for item in language_results]
    for language in languages:
        scan = language_results.get(language)
        if not isinstance(scan, dict):
            failures.append(f"{language}: 缺少扫描结果")
            continue
        status = str(scan.get("status") or "").strip().lower()
        mode = str(scan.get("mode") or "").strip().lower()
        if status != "completed":
            failures.append(f"{language}: 扫描状态为 {status or 'unknown'}")
        if mode.endswith("fallback") or mode in {"internal", "disabled", "unavailable"}:
            failures.append(f"{language}: 扫描引擎降级为 {mode or 'unknown'}")
    return failures


class TaskAgentState(TypedDict, total=False):
    task_id: str
    objective: str
    workspace_path: str
    user_id: str
    files_by_language: dict[str, list[str]]
    manifest_files: list[str]
    unsupported_files: list[str]
    skipped_files: int
    complete_workspace_scan: bool
    languages: list[str]
    pending_languages: list[str]
    plan: list[dict[str, Any]]
    dependency_scan: dict[str, Any]
    license_scan: dict[str, Any]
    sbom: dict[str, Any]
    vulnerability_matching: dict[str, Any]
    vulnerability_hits: list[dict[str, Any]]
    vulnerability_severities: dict[str, int]
    language_results: dict[str, dict[str, Any]]
    adaptive_enabled: bool
    scan_mode: str
    project_profile: dict[str, Any]
    analysis_evidence: dict[str, Any]
    project_overlay: dict[str, Any]
    adaptation: dict[str, Any]
    scan_mcp_invocations: list[dict[str, Any]]
    license_mcp_invocations: list[dict[str, Any]]
    result: dict[str, Any]


EventSink = Callable[[str, str, str, str, str, dict[str, Any] | None], None]
CancelCheck = Callable[[str], bool]
ProjectMemorySink = Callable[[dict[str, Any]], None]
LanguageScanner = Callable[
    [str, list[dict[str, Any]], dict[str, Any], list[str], Callable[[], bool]],
    dict[str, Any],
]


def _public_vulnerability_hit(record: dict[str, Any]) -> dict[str, Any]:
    """Trim a matched vulnerability record for lean, report-ready task results."""

    aliases = [
        str(value)
        for value in record.get("aliases") or []
        if str(value).upper().startswith(("CVE-", "GHSA-"))
    ]
    return {
        "id": str(record.get("id") or ""),
        "aliases": aliases[:5],
        "severity": str(record.get("severity") or "UNKNOWN"),
        "cvss_score": record.get("cvss_score"),
        "summary": str(record.get("summary") or record.get("title") or ""),
        "known_exploited": bool(record.get("known_exploited")),
        "affected_versions": [str(item) for item in record.get("affected_versions") or []][:8],
        "fixed_versions": [str(item) for item in record.get("fixed_versions") or []][:8],
        "matched_dependencies": deepcopy(record.get("matched_dependencies") or []),
    }


def dependency_completion_message(
    scan: dict[str, Any],
    go_mod_files: list[str],
    requirements_files: list[str],
) -> str:
    count = scan.get("dependency_count", 0)
    inferred = int(scan.get("inferred_count") or 0)
    suffix = f"另有 {inferred} 个源码引用观察（版本未知，不参与漏洞匹配）。" if inferred else ""
    if go_mod_files and requirements_files:
        return f"已优先解析 go.mod 与 requirements.txt，识别 {count} 个 SBOM 依赖组件。{suffix}"
    if go_mod_files:
        return f"已优先解析 go.mod，识别 {count} 个 SBOM 依赖组件。{suffix}"
    if requirements_files:
        return f"已优先解析 requirements.txt，识别 {count} 个 SBOM 依赖组件。{suffix}"
    return f"已识别 {count} 个 SBOM 依赖组件。{suffix}"


class TaskAgentGraph:
    def __init__(
        self,
        *,
        event_sink: EventSink | None = None,
        cancel_check: CancelCheck | None = None,
        language_scanner: LanguageScanner | None = None,
        code_scan_client: CodeScanMCPClient | None = None,
        overlay_synthesizer: OverlaySynthesizer | None = None,
        adaptive_upload: bool = False,
    ) -> None:
        self._event_sink = event_sink
        self._cancel_check = cancel_check or (lambda _task_id: False)
        self._language_scanner = language_scanner
        self._code_scan_client = code_scan_client or CodeScanMCPClient()
        self._sbom_license_capability = SBOMLicenseCapability()
        self._overlay_synthesizer = overlay_synthesizer or default_overlay_synthesizer
        self._adaptive_upload = adaptive_upload
        self._scan_subgraph = self._build_scan_subgraph()
        self._graph = self._build_graph()

    def invoke(
        self,
        *,
        task_id: str,
        objective: str,
        workspace_path: str,
        user_id: str,
    ) -> TaskAgentState:
        adaptive_enabled = self._adaptive_upload and not task_id.startswith("evaluation-")
        state: TaskAgentState = {
            "task_id": task_id,
            "objective": objective,
            "workspace_path": workspace_path,
            "user_id": user_id,
            "files_by_language": {},
            "manifest_files": [],
            "unsupported_files": [],
            "skipped_files": 0,
            "complete_workspace_scan": adaptive_enabled,
            "languages": [],
            "pending_languages": [],
            "plan": [],
            "dependency_scan": {"files": [], "dependencies": [], "dependency_count": 0, "rejected_files": []},
            "license_scan": {},
            "sbom": {},
            "vulnerability_matching": {},
            "vulnerability_hits": [],
            "vulnerability_severities": {},
            "language_results": {},
            "adaptive_enabled": adaptive_enabled,
            "scan_mode": "adaptive_upload" if adaptive_enabled else "frozen_evaluation",
            "project_profile": {},
            "analysis_evidence": {},
            "project_overlay": empty_project_overlay("尚未执行项目自适应分析。"),
            "adaptation": {
                "enabled": adaptive_enabled,
                "mode": "adaptive_upload" if adaptive_enabled else "frozen_evaluation",
                "status": "pending" if adaptive_enabled else "disabled",
                "attempts": 0,
                "iterations": 0,
                "overlay_fingerprints": [],
                "overlays": [],
                "next_action": "",
                "skill": project_adaptive_skill_metadata(),
            },
            "scan_mcp_invocations": [],
            "license_mcp_invocations": [],
            "result": {},
        }
        if self._graph is not None:
            return self._graph.invoke(state)
        state = self._inspect_workspace(state)
        state = self._detect_languages(state)
        state = self._plan_task(state)
        state = self._invoke_scan_subgraph_fallback(state)
        state = self._verify_results(state)
        return self._compose_result(state)

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        language_nodes = [
            {
                "id": f"scan_{language}",
                "label": f"{LANGUAGE_LABELS[language]} · 静态规则 + AST/CFG/DFG/污点",
            }
            for language in LANGUAGE_ORDER
        ]
        return {
            "name": "AegisAl Workspace Task Agent",
            "nodes": [
                {"id": "inspect_workspace", "label": "检查授权工作区"},
                {"id": "detect_languages", "label": "识别项目语言"},
                {"id": "plan_task", "label": "生成扫描计划"},
                {"id": "project_scan_subgraph", "label": "上传项目自适应扫描子图"},
                {"id": "scan_dependencies", "label": "依赖与组件识别 · 优先标准项目清单"},
                {"id": "identify_project_licenses", "label": "SBOM Agent · SPDX + OSI 许可识别"},
                {"id": "match_dependency_vulnerabilities", "label": "组件漏洞情报匹配 · 本地目录优先"},
                {"id": "profile_project", "label": "构建项目画像与构建上下文"},
                {"id": "dispatch_language", "label": "按语言分派扫描节点"},
                *language_nodes,
                {"id": "fuse_analysis_evidence", "label": "融合静态规则与 AST/CFG/DFG/污点证据"},
                {"id": "synthesize_project_overlay", "label": "LLM 生成受限项目 Overlay"},
                {"id": "rescan_project_overlay", "label": "沙箱重扫与差分回归 · 最多三轮"},
                {"id": "verify_results", "label": "校验扫描结果"},
                {"id": "compose_result", "label": "汇总任务结果"},
            ],
            "edges": [
                {"source": "inspect_workspace", "target": "detect_languages", "label": "文件清单"},
                {"source": "detect_languages", "target": "plan_task", "label": "语言画像"},
                {"source": "plan_task", "target": "project_scan_subgraph", "label": "进入上传扫描子图"},
                {"source": "project_scan_subgraph", "target": "scan_dependencies", "label": "子图入口"},
                {"source": "scan_dependencies", "target": "identify_project_licenses", "label": "交接 SBOM Agent"},
                {"source": "identify_project_licenses", "target": "match_dependency_vulnerabilities", "label": "固定许可事实"},
                {"source": "match_dependency_vulnerabilities", "target": "profile_project", "label": "漏洞命中事实"},
                {"source": "profile_project", "target": "dispatch_language", "label": "项目画像"},
                *[
                    {"source": "dispatch_language", "target": f"scan_{language}", "label": LANGUAGE_LABELS[language]}
                    for language in LANGUAGE_ORDER
                ],
                *[
                    {"source": f"scan_{language}", "target": "dispatch_language", "label": "继续下一语言"}
                    for language in LANGUAGE_ORDER
                ],
                {"source": "dispatch_language", "target": "fuse_analysis_evidence", "label": "全部语言完成"},
                {"source": "fuse_analysis_evidence", "target": "synthesize_project_overlay", "label": "可引用证据"},
                {"source": "synthesize_project_overlay", "target": "rescan_project_overlay", "label": "受限 Overlay"},
                {"source": "rescan_project_overlay", "target": "fuse_analysis_evidence", "label": "差分结果"},
                {"source": "synthesize_project_overlay", "target": "verify_results", "label": "无变化或达到上限"},
                {"source": "verify_results", "target": "compose_result", "label": "验证通过"},
            ],
            "subgraphs": [
                {
                    "id": "project_scan_subgraph",
                    "entry": "scan_dependencies",
                    "exit": "synthesize_project_overlay",
                    "max_adaptation_iterations": MAX_ADAPTATION_ITERATIONS,
                    "evaluation_mode": "frozen_evaluation",
                    "user_scan_transport": "mcp-stdio",
                "mcp_server": "AegisAl Code Scan MCP",
                    "mcp_tools": ["scan_language"],
                    "delegated_agents": ["sbom_agent:identify_project_licenses"],
                    "skill": project_adaptive_skill_metadata(),
                }
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(TaskAgentState)
        graph.add_node("inspect_workspace", self._inspect_workspace)
        graph.add_node("detect_languages", self._detect_languages)
        graph.add_node("plan_task", self._plan_task)
        if self._scan_subgraph is None:  # pragma: no cover - guarded by StateGraph availability.
            graph.add_node("project_scan_subgraph", self._invoke_scan_subgraph_fallback)
        else:
            graph.add_node("project_scan_subgraph", self._scan_subgraph)
        graph.add_node("verify_results", self._verify_results)
        graph.add_node("compose_result", self._compose_result)
        graph.set_entry_point("inspect_workspace")
        graph.add_edge("inspect_workspace", "detect_languages")
        graph.add_edge("detect_languages", "plan_task")
        graph.add_edge("plan_task", "project_scan_subgraph")
        graph.add_edge("project_scan_subgraph", "verify_results")
        graph.add_edge("verify_results", "compose_result")
        graph.add_edge("compose_result", END)
        return graph.compile()

    def _build_scan_subgraph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(TaskAgentState)
        graph.add_node("scan_dependencies", self._scan_dependencies)
        graph.add_node("identify_project_licenses", self._identify_project_licenses)
        graph.add_node("match_dependency_vulnerabilities", self._match_dependency_vulnerabilities)
        graph.add_node("profile_project", self._profile_project)
        graph.add_node("dispatch_language", self._dispatch_language)
        for language in LANGUAGE_ORDER:
            graph.add_node(
                f"scan_{language}",
                lambda state, selected=language: self._scan_language(selected, state),
            )
        graph.add_node("fuse_analysis_evidence", self._fuse_analysis_evidence)
        graph.add_node("synthesize_project_overlay", self._synthesize_project_overlay)
        graph.add_node("rescan_project_overlay", self._rescan_project_overlay)
        graph.set_entry_point("scan_dependencies")
        graph.add_edge("scan_dependencies", "identify_project_licenses")
        graph.add_edge("identify_project_licenses", "match_dependency_vulnerabilities")
        graph.add_edge("match_dependency_vulnerabilities", "profile_project")
        graph.add_edge("profile_project", "dispatch_language")
        graph.add_conditional_edges(
            "dispatch_language",
            self._next_language_node,
            {
                **{f"scan_{language}": f"scan_{language}" for language in LANGUAGE_ORDER},
                "fuse_analysis_evidence": "fuse_analysis_evidence",
            },
        )
        for language in LANGUAGE_ORDER:
            graph.add_edge(f"scan_{language}", "dispatch_language")
        graph.add_edge("fuse_analysis_evidence", "synthesize_project_overlay")
        graph.add_conditional_edges(
            "synthesize_project_overlay",
            self._next_adaptation_node,
            {"rescan_project_overlay": "rescan_project_overlay", "done": END},
        )
        graph.add_edge("rescan_project_overlay", "fuse_analysis_evidence")
        return graph.compile()

    def _inspect_workspace(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        self._emit(state, "node.started", "inspect_workspace", "running", "正在检查工作区文件。")
        complete_scan = bool(state.get("complete_workspace_scan"))
        inventory = collect_workspace_inventory(
            Path(state["workspace_path"]),
            apply_limits=not complete_scan,
        )
        state.update(inventory)
        total_files = sum(len(paths) for paths in inventory["files_by_language"].values())
        self._emit(
            state,
            "node.completed",
            "inspect_workspace",
            "completed",
            f"已纳入 {total_files} 个源文件和 {len(inventory['manifest_files'])} 个项目清单。",
            {
                "source_files": total_files,
                "manifest_files": len(inventory["manifest_files"]),
                "complete_workspace_scan": complete_scan,
                "skipped_files": int(inventory.get("skipped_files") or 0),
            },
        )
        return state

    def _detect_languages(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        languages = [
            language
            for language in LANGUAGE_ORDER
            if state.get("files_by_language", {}).get(language)
        ]
        state["languages"] = languages
        state["pending_languages"] = list(languages)
        labels = "、".join(LANGUAGE_LABELS[item] for item in languages) if languages else "无受支持语言"
        self._emit(
            state,
            "languages.detected",
            "detect_languages",
            "completed" if languages else "warning",
            f"项目语言识别完成：{labels}。",
            {"languages": languages, "unsupported_files": len(state.get("unsupported_files", []))},
        )
        return state

    def _plan_task(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        languages = set(state.get("languages", []))
        if {"go", "python"}.issubset(languages):
            dependency_title = "优先解析 go.mod 与 requirements.txt 并识别依赖组件"
        elif "go" in languages:
            dependency_title = "优先解析 go.mod 并识别依赖组件"
        elif "python" in languages:
            dependency_title = "优先解析 requirements.txt 并识别依赖组件"
        else:
            dependency_title = "识别项目依赖与组件"
        plan = [
            {"id": "inspect", "title": "检查工作区与识别语言", "node": "inspect_workspace", "status": "completed", "language": ""},
            {"id": "dependencies", "title": dependency_title, "node": "scan_dependencies", "status": "pending", "language": ""},
            {
                "id": "profile",
                "title": "构建项目画像、框架与编译上下文",
                "node": "profile_project",
                "status": "pending",
                "language": "",
            },
        ]
        if state.get("complete_workspace_scan"):
            plan.insert(
                2,
                {
                    "id": "licenses",
                    "title": "交由 SBOM Agent 识别项目许可并通过 OSI License API 标准化",
                    "node": "identify_project_licenses",
                    "status": "pending",
                    "language": "",
                },
            )
        vulnerabilities_index = next(
            (index + 1 for index, item in enumerate(plan) if str(item.get("id") or "") == "licenses"),
            next((index + 1 for index, item in enumerate(plan) if str(item.get("id") or "") == "dependencies"), 2),
        )
        plan.insert(
            vulnerabilities_index,
            {
                "id": "vulnerabilities",
                "title": "按组件与版本匹配漏洞情报并汇总命中",
                "node": "match_dependency_vulnerabilities",
                "status": "pending",
                "language": "",
            },
        )
        plan.extend(
            {
                "id": f"language-{language}",
                "title": f"执行 {LANGUAGE_LABELS[language]} 专属规则和 AST/CFG/DFG 扫描",
                "node": f"scan_{language}",
                "status": "pending",
                "language": language,
            }
            for language in state.get("languages", [])
        )
        plan.extend(
            [
                {
                    "id": "evidence",
                    "title": "融合静态规则与 AST/CFG/DFG/污点证据",
                    "node": "fuse_analysis_evidence",
                    "status": "pending",
                    "language": "",
                },
                {
                    "id": "adaptation",
                    "title": (
                        "生成项目级 Overlay 并执行有界重扫"
                        if state.get("adaptive_enabled")
                        else "保持冻结扫描基线，不启用项目自适应"
                    ),
                    "node": "synthesize_project_overlay",
                    "status": "pending",
                    "language": "",
                },
            ]
        )
        plan.append(
            {"id": "verify", "title": "验证并汇总扫描结果", "node": "verify_results", "status": "pending", "language": ""}
        )
        state["plan"] = plan
        self._emit(
            state,
            "plan.updated",
            "plan_task",
            "completed",
            f"已生成 {len(plan)} 个执行步骤。",
            {"plan": plan},
        )
        return state

    def _profile_project(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        self._set_plan_status(state, "profile", "running")
        self._emit(
            state,
            "node.started",
            "profile_project",
            "running",
            "正在构建项目语言、依赖、框架和编译上下文画像。",
        )
        profile = build_project_profile(
            workspace_path=state["workspace_path"],
            languages=list(state.get("languages") or []),
            manifest_files=list(state.get("manifest_files") or []),
            dependency_scan=state.get("dependency_scan") or {},
            adaptive_enabled=bool(state.get("adaptive_enabled")),
        )
        state["project_profile"] = profile
        self._set_plan_status(state, "profile", "completed")
        self._emit(
            state,
            "node.completed",
            "profile_project",
            "completed",
            f"项目画像完成：{len(profile['languages'])} 种语言、{len(profile['build_systems'])} 类构建上下文。",
            {
                "languages": profile["languages"],
                "build_systems": profile["build_systems"],
                "adaptive_enabled": profile["adaptive_enabled"],
                "scope_fingerprint": profile["scope_fingerprint"],
            },
        )
        return state

    def _scan_dependencies(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        self._set_plan_status(state, "dependencies", "running")
        # SBOM collection is always full-fidelity and independent of the
        # semantic-scan adaptive/limits switch, so every scan type reports the
        # same component basis for the same project.
        scan = collect_project_sbom(Path(state["workspace_path"]))
        manifest_files = list(scan.get("manifest_files") or [])
        go_mod_files = [path for path in manifest_files if Path(path).name.lower() == "go.mod"]
        requirements_files = [path for path in manifest_files if is_python_requirements_name(path)]
        languages = set(state.get("languages", []))
        if go_mod_files and requirements_files:
            strategy = "go_mod_and_requirements_first"
            message = (
                f"正在优先解析 {len(go_mod_files)} 个 go.mod 和 {len(requirements_files)} 个 requirements 清单，"
                "再补充其他清单与源码引用。"
            )
        elif go_mod_files:
            strategy = "go_mod_first"
            message = f"正在优先解析 {len(go_mod_files)} 个 go.mod，再补充其他清单与源码引用。"
        elif requirements_files:
            strategy = "requirements_first"
            message = (
                f"正在优先解析 {len(requirements_files)} 个 requirements 清单，再补充其他清单与源码引用。"
            )
        elif "python" in languages:
            strategy = "manifest_first"
            message = "未找到 requirements.txt，正在解析其他 Python 项目清单与源码引用。"
        else:
            strategy = "manifest_first"
            message = "正在解析依赖清单与源码引用。"
        self._emit(
            state,
            "node.started",
            "scan_dependencies",
            "running",
            message,
            {
                "strategy": strategy,
                "go_mod_files": go_mod_files,
                "requirements_files": requirements_files,
            },
        )
        scan["strategy"] = strategy
        scan["go_mod_files"] = go_mod_files
        scan["requirements_files"] = requirements_files
        state["dependency_scan"] = scan
        self._set_plan_status(state, "dependencies", "completed")
        self._emit(
            state,
            "node.completed",
            "scan_dependencies",
            "completed",
            dependency_completion_message(scan, go_mod_files, requirements_files),
            {
                "dependency_count": scan.get("dependency_count", 0),
                "inferred_count": scan.get("inferred_count", 0),
                "strategy": scan["strategy"],
                "go_mod_files": go_mod_files,
                "requirements_files": requirements_files,
            },
        )
        return state

    def _identify_project_licenses(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        has_plan_step = any(str(item.get("id") or "") == "licenses" for item in state.get("plan") or [])
        if not state.get("complete_workspace_scan") or self._language_scanner is not None:
            state["license_scan"] = {}
            if has_plan_step:
                self._set_plan_status(state, "licenses", "completed")
                self._emit(
                    state,
                    "license.skipped",
                    "identify_project_licenses",
                    "completed",
                    "当前扫描模式未启用独立许可识别。",
                )
            return state

        self._set_plan_status(state, "licenses", "running")
        self._emit(
            state,
            "node.started",
            "identify_project_licenses",
            "running",
            "正在通过独立 License MCP 识别 SPDX、依赖清单和许可证文件，并查询 OSI 许可元数据。",
            {
                "transport": "stdio",
                "endpoint": "managed-child-process",
                "mcp_server": "AegisAl License MCP",
                "mcp_tool": "identify_project_licenses",
                "registry": "https://opensource.org/api/licenses",
            },
        )
        try:
            scan = self._sbom_license_capability.identify_project_licenses(
                state["workspace_path"],
                cancelled=lambda: self._cancel_check(state["task_id"]),
            )
        except Exception as exc:  # noqa: BLE001 - preserve partial SBOM facts when license metadata is unavailable.
            if self._cancel_check(state["task_id"]):
                raise TaskCancelled("任务已由用户停止。") from exc
            scan = {
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
        state["license_scan"] = scan
        mcp_audit = scan.get("_license_mcp") if isinstance(scan.get("_license_mcp"), dict) else {}
        if mcp_audit:
            state["license_mcp_invocations"] = [
                *state.get("license_mcp_invocations", []),
                deepcopy(mcp_audit),
            ]
        status = "completed" if scan.get("coverage_status") == "complete" else "warning"
        self._set_plan_status(state, "licenses", "completed")
        self._emit(
            state,
            "node.completed",
            "identify_project_licenses",
            status,
            (
                f"项目许可识别完成：发现 {int(scan.get('license_count') or 0)} 种许可，"
                f"覆盖状态 {scan.get('coverage_status') or 'unknown'}。"
            ),
            {
                "license_count": int(scan.get("license_count") or 0),
                "coverage_status": str(scan.get("coverage_status") or "unknown"),
                "registry_status": str((scan.get("registry") or {}).get("status") or "unknown"),
                "license_mcp": deepcopy(mcp_audit),
            },
        )
        return state

    def _match_dependency_vulnerabilities(self, state: TaskAgentState) -> TaskAgentState:
        """Match identified dependencies against vulnerability intelligence.

        A full scan must not stop at a dependency list: known CVEs (for
        example Log4Shell on log4j-core 2.14.1) are the highest-signal alerts
        a security scan can raise. Matching reuses the SBOM matcher, which is
        local-catalog first with a short-budget realtime fallback, and it must
        never fail the scan itself.
        """
        self._ensure_not_cancelled(state)
        dependency_scan = state.get("dependency_scan") or {}
        dependencies = [
            item for item in dependency_scan.get("dependencies") or [] if isinstance(item, dict)
        ]
        if not dependencies:
            state["vulnerability_matching"] = {
                "vulnerability_count": 0,
                "coverage_status": "skipped",
                "errors": [],
            }
            state["vulnerability_hits"] = []
            state["vulnerability_severities"] = {}
            self._set_plan_status(state, "vulnerabilities", "completed")
            self._emit(
                state,
                "vulnerability.skipped",
                "match_dependency_vulnerabilities",
                "completed",
                "未识别到依赖组件，跳过组件漏洞情报匹配。",
            )
            return state
        self._set_plan_status(state, "vulnerabilities", "running")
        self._emit(
            state,
            "node.started",
            "match_dependency_vulnerabilities",
            "running",
            f"正在按组件与版本匹配漏洞情报（本地漏洞目录优先，{len(dependencies)} 个依赖组件）。",
        )
        try:
            sbom = build_cyclonedx_sbom(
                dependency_scan,
                project_name=Path(str(state.get("workspace_path") or "project")).name or "project",
                workspace_path=str(state.get("workspace_path") or ""),
                license_scan=state.get("license_scan") or None,
            )
            sbom, matching = match_sbom_vulnerabilities(sbom, dependency_scan)
        except Exception as exc:  # noqa: BLE001 - matching degrades, the scan continues.
            state["vulnerability_matching"] = {
                "vulnerability_count": 0,
                "coverage_status": "failed",
                "errors": [f"{type(exc).__name__}: {exc}"],
            }
            state["vulnerability_hits"] = []
            state["vulnerability_severities"] = {}
            self._set_plan_status(state, "vulnerabilities", "completed")
            self._emit(
                state,
                "vulnerability.failed",
                "match_dependency_vulnerabilities",
                "warning",
                f"组件漏洞情报匹配降级：{type(exc).__name__}，已保留依赖清单并继续扫描。",
            )
            return state
        state["sbom"] = sbom
        state["vulnerability_matching"] = matching
        records = [record for record in matching.get("records") or [] if isinstance(record, dict)]
        severities = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
        for record in records:
            severity = str(record.get("severity") or "").upper()
            if severity in severities:
                severities[severity] += 1
        state["vulnerability_severities"] = severities
        state["vulnerability_hits"] = [_public_vulnerability_hit(record) for record in records[:20]]
        vulnerability_count = int(matching.get("vulnerability_count") or 0)
        coverage_status = str(matching.get("coverage_status") or "unknown")
        severity_note = ""
        if vulnerability_count:
            severity_note = f"（严重 {severities['CRITICAL']}、高危 {severities['HIGH']}）"
        self._set_plan_status(state, "vulnerabilities", "completed")
        self._emit(
            state,
            "vulnerability.matched",
            "match_dependency_vulnerabilities",
            "completed" if coverage_status == "complete" else "warning",
            (
                f"组件漏洞匹配完成：命中 {vulnerability_count} 个已知漏洞{severity_note}，"
                f"覆盖状态 {coverage_status}。"
            ),
            {
                "vulnerability_count": vulnerability_count,
                "matched_component_count": int(matching.get("matched_component_count") or 0),
                "coverage_status": coverage_status,
                "severities": deepcopy(severities),
            },
        )
        return state

    def _dispatch_language(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        return state

    def _next_language_node(self, state: TaskAgentState) -> str:
        pending = state.get("pending_languages", [])
        return f"scan_{pending[0]}" if pending else "fuse_analysis_evidence"

    def _scan_language(self, language: str, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        if language not in state.get("pending_languages", []):
            return state
        label = LANGUAGE_LABELS[language]
        step_id = f"language-{language}"
        self._set_plan_status(state, step_id, "running")
        rules = semgrep_rule_paths_for_language(language)
        self._emit(
            state,
            "node.started",
            f"scan_{language}",
            "running",
            f"正在执行 {label} 静态规则与 AST/CFG/DFG/污点语义引擎。",
            {
                "language": language,
                "rules": [Path(item).name for item in rules],
                "transport": self._scan_transport(state["task_id"]),
                "mcp_server": "AegisAl Code Scan MCP" if self._uses_scan_mcp(state["task_id"]) else "",
                "mcp_tool": "scan_language" if self._uses_scan_mcp(state["task_id"]) else "",
            },
        )
        source_paths = state.get("files_by_language", {}).get(language, [])
        relative_paths = [*state.get("manifest_files", []), *source_paths]
        attachments = (
            []
            if self._uses_scan_mcp(state["task_id"])
            else read_workspace_attachments(
                Path(state["workspace_path"]),
                relative_paths,
                apply_limits=not bool(state.get("complete_workspace_scan")),
            )
        )
        heartbeat_stop = Event()
        heartbeat = Thread(
            target=self._emit_scan_heartbeats,
            args=(state, language, label, len(source_paths), heartbeat_stop),
            daemon=True,
            name=f"secflow-scan-heartbeat-{language}",
        )
        heartbeat.start()
        try:
            result = self._run_language_scanner(
                language,
                attachments,
                state.get("dependency_scan", {}),
                rules,
                lambda: self._cancel_check(state["task_id"]),
                complete_scan=bool(state.get("complete_workspace_scan")),
                task_id=state["task_id"],
                workspace_path=state["workspace_path"],
                source_paths=source_paths,
                manifest_files=state.get("manifest_files", []),
            )
        except CodeScanMCPError as exc:
            if self._cancel_check(state["task_id"]):
                raise TaskCancelled("任务已由用户停止。") from exc
            raise
        finally:
            heartbeat_stop.set()
            heartbeat.join(timeout=0.2)
        self._ensure_not_cancelled(state)
        compact = compact_language_result(
            language,
            result,
            source_paths,
            rules,
            complete_scan=bool(state.get("complete_workspace_scan")),
        )
        state["language_results"] = {**state.get("language_results", {}), language: compact}
        if compact.get("scan_mcp"):
            state["scan_mcp_invocations"] = [
                *state.get("scan_mcp_invocations", []),
                deepcopy(compact["scan_mcp"]),
            ]
        state["pending_languages"] = [item for item in state.get("pending_languages", []) if item != language]
        self._set_plan_status(state, step_id, "completed")
        self._emit(
            state,
            "node.completed",
            f"scan_{language}",
            compact["status"],
            f"{label} 扫描完成：{compact['file_count']} 个文件，{compact['finding_count']} 条发现。",
            {
                "language": language,
                "file_count": compact["file_count"],
                "finding_count": compact["finding_count"],
                "mode": str(compact.get("mode") or ""),
                "cli_status": str(compact.get("cli_status") or ""),
                "diagnostics": [
                    sanitize_public_text(str(item))
                    for item in (compact.get("diagnostics") or [])[:8]
                    if str(item).strip()
                ],
                "syntax_summary": compact["syntax_summary"],
                "scan_mcp": deepcopy(compact.get("scan_mcp") or {}),
            },
        )
        return state

    def _emit_scan_heartbeats(
        self,
        state: TaskAgentState,
        language: str,
        label: str,
        total_files: int,
        stop: Event,
    ) -> None:
        started_at = monotonic_time.monotonic()
        while not stop.wait(SCAN_HEARTBEAT_INTERVAL_SECONDS):
            if self._cancel_check(state["task_id"]):
                return
            elapsed_seconds = max(1, int(monotonic_time.monotonic() - started_at))
            self._emit(
                state,
                "node.progress",
                f"scan_{language}",
                "running",
                f"{label} 语义扫描仍在执行：共 {total_files} 个文件，已运行 {elapsed_seconds} 秒。",
                {
                    "language": language,
                    "stage": "ast_cfg_dfg_taint",
                    "processed_files": None,
                    "total_files": total_files,
                    "elapsed_seconds": elapsed_seconds,
                    "heartbeat": True,
                },
            )

    def _fuse_analysis_evidence(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        self._set_plan_status(state, "evidence", "running")
        self._emit(
            state,
            "node.started",
            "fuse_analysis_evidence",
            "running",
            "正在融合静态规则、解析状态、CFG/DFG 与污点候选证据。",
        )
        evidence = fuse_project_evidence(
            state.get("project_profile") or {},
            state.get("language_results") or {},
        )
        state["analysis_evidence"] = evidence
        adaptation = dict(state.get("adaptation") or {})
        if not adaptation.get("baseline_metrics"):
            adaptation["baseline_metrics"] = deepcopy(evidence["metrics"])
        adaptation["current_metrics"] = deepcopy(evidence["metrics"])
        state["adaptation"] = adaptation
        self._set_plan_status(state, "evidence", "completed")
        self._emit(
            state,
            "node.completed",
            "fuse_analysis_evidence",
            "completed",
            (
                f"证据融合完成：{evidence['metrics']['findings']} 条主告警、"
                f"{evidence['metrics']['review_findings']} 条复核候选、"
                f"{evidence['metrics']['parse_error_files']} 个解析缺口。"
            ),
            deepcopy(evidence["metrics"]),
        )
        return state

    def _synthesize_project_overlay(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        adaptation = dict(state.get("adaptation") or {})
        self._set_plan_status(state, "adaptation", "running")
        if not state.get("adaptive_enabled"):
            overlay = empty_project_overlay("冻结评测模式禁止模型调整和项目 Overlay。")
            state["project_overlay"] = overlay
            adaptation.update(
                status="disabled",
                next_action="",
                termination_reason="frozen_evaluation",
            )
            state["adaptation"] = adaptation
            self._set_plan_status(state, "adaptation", "completed")
            self._emit(
                state,
                "adaptation.skipped",
                "synthesize_project_overlay",
                "completed",
                "当前为冻结评测模式，未调用大模型且未应用项目 Overlay。",
                {"mode": "frozen_evaluation"},
            )
            return state

        if adaptation.get("stop_after_rejection"):
            adaptation.update(next_action="")
            state["adaptation"] = adaptation
            self._set_plan_status(state, "adaptation", "completed")
            self._emit(
                state,
                "adaptation.skipped",
                "synthesize_project_overlay",
                "warning",
                "项目 Overlay 预检或重扫未通过，已停止继续自适应并保留首轮验证结果。",
                {
                    "termination_reason": str(adaptation.get("termination_reason") or "overlay_rejected"),
                    "rejection_count": len(adaptation.get("overlay_rejections") or []),
                },
            )
            return state

        attempts = int(adaptation.get("attempts") or 0)
        iterations = int(adaptation.get("iterations") or 0)
        metrics = (state.get("analysis_evidence") or {}).get("metrics") or {}
        evidence_count = sum(
            int(metrics.get(key) or 0)
            for key in ("findings", "review_findings", "parse_error_files")
        )
        if attempts >= MAX_ADAPTATION_ITERATIONS or iterations >= MAX_ADAPTATION_ITERATIONS:
            adaptation.update(
                status="max_iterations",
                next_action="",
                termination_reason="max_iterations",
            )
            state["adaptation"] = adaptation
            self._set_plan_status(state, "adaptation", "completed")
            self._emit(
                state,
                "adaptation.skipped",
                "synthesize_project_overlay",
                "completed",
                "项目 Overlay 已达到有界重扫次数，保留当前已验证扫描结果。",
                {"attempts": attempts, "iterations": iterations},
            )
            return state
        if evidence_count == 0:
            state["project_overlay"] = empty_project_overlay("没有需要项目级调整的证据。")
            adaptation.update(status="no_change", next_action="", termination_reason="no_discrepancy")
            state["adaptation"] = adaptation
            self._set_plan_status(state, "adaptation", "completed")
            self._emit(
                state,
                "adaptation.skipped",
                "synthesize_project_overlay",
                "completed",
                "当前扫描没有可用于项目级 Overlay 的差异证据，已保留基线结果。",
                {"evidence_count": 0},
            )
            return state

        request = build_overlay_request(
            project_profile=state.get("project_profile") or {},
            evidence=state.get("analysis_evidence") or {},
            iteration=attempts + 1,
            previous_overlay_fingerprints=list(adaptation.get("overlay_fingerprints") or []),
            user_id=state.get("user_id", "default"),
        )
        self._emit(
            state,
            "node.started",
            "synthesize_project_overlay",
            "running",
            f"正在执行第 {attempts + 1} 轮项目级 Overlay 证据分析。",
            {
                "iteration": attempts + 1,
                "max_iterations": MAX_ADAPTATION_ITERATIONS,
            },
        )
        try:
            response = self._overlay_synthesizer(request)
        except Exception as exc:  # noqa: BLE001 - adaptation must fail closed to the baseline.
            response = {
                "status": "failed",
                "reason": sanitize_public_text(str(exc)) or "项目 Overlay 生成失败。",
                "overlay": empty_project_overlay("项目 Overlay 生成失败。"),
            }
        overlay = response.get("overlay") if isinstance(response.get("overlay"), dict) else empty_project_overlay(
            "模型未返回可用 Overlay。"
        )
        fingerprint = str(overlay.get("fingerprint") or "")
        history = list(adaptation.get("overlay_fingerprints") or [])
        attempts += 1
        adaptation["attempts"] = attempts
        adaptation["last_response"] = {
            "status": str(response.get("status") or "failed"),
            "reason": str(response.get("reason") or overlay.get("reason") or ""),
            "model": deepcopy(response.get("model") or {}),
        }
        repeated = bool(fingerprint and fingerprint in history)
        ready = (
            response.get("status") == "ready"
            and overlay.get("decision") == "apply_overlay"
            and not repeated
        )
        if ready:
            history.append(fingerprint)
            adaptation["overlay_fingerprints"] = history
            adaptation["overlays"] = [
                *list(adaptation.get("overlays") or []),
                deepcopy(overlay),
            ][:MAX_ADAPTATION_ITERATIONS]
            adaptation.update(status="overlay_ready", next_action="rescan_project_overlay")
            state["project_overlay"] = overlay
        else:
            adaptation.update(
                status="no_change" if response.get("status") in {"no_change", "ready"} else str(response.get("status") or "failed"),
                next_action="",
                termination_reason="repeated_overlay" if repeated else str(response.get("status") or "no_change"),
            )
            state["project_overlay"] = overlay
            self._set_plan_status(state, "adaptation", "completed")
        state["adaptation"] = adaptation
        self._emit(
            state,
            "node.completed",
            "synthesize_project_overlay",
            "completed" if ready or adaptation["status"] == "no_change" else "warning",
            (
                "项目 Overlay 已通过结构门禁，准备沙箱重扫。"
                if ready
                else f"本轮未应用 Overlay：{adaptation['termination_reason']}。"
            ),
            {
                "status": adaptation["status"],
                "attempts": attempts,
                "iterations": iterations,
                "overlay_fingerprint": fingerprint,
            },
        )
        return state

    @staticmethod
    def _next_adaptation_node(state: TaskAgentState) -> str:
        adaptation = state.get("adaptation") or {}
        return "rescan_project_overlay" if adaptation.get("next_action") == "rescan_project_overlay" else "done"

    def _rescan_project_overlay(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        overlay = state.get("project_overlay") or {}
        adaptation = dict(state.get("adaptation") or {})
        action_ids = {
            *list(overlay.get("promote_review_finding_ids") or []),
            *list(overlay.get("demote_finding_ids") or []),
        }
        action_languages = {
            str(item.get("language") or "")
            for key in ("findings", "review_findings")
            for item in (state.get("analysis_evidence") or {}).get(key) or []
            if str(item.get("finding_id") or "") in action_ids
        }
        selected_languages = [
            language
            for language in state.get("languages") or []
            if language in (overlay_languages(overlay) | action_languages)
        ]
        self._emit(
            state,
            "node.started",
            "rescan_project_overlay",
            "running",
            f"正在使用项目 Overlay 重扫 {len(selected_languages)} 种语言。",
            {
                "languages": selected_languages,
                "overlay_fingerprint": overlay.get("fingerprint"),
            },
        )
        language_results = dict(state.get("language_results") or {})
        applied_languages: list[str] = []
        overlay_rejections: list[dict[str, Any]] = []
        for language in selected_languages:
            self._ensure_not_cancelled(state)
            source_paths = state.get("files_by_language", {}).get(language, [])
            relative_paths = [*state.get("manifest_files", []), *source_paths]
            attachments = (
                []
                if self._uses_scan_mcp(state["task_id"])
                else read_workspace_attachments(
                    Path(state["workspace_path"]),
                    relative_paths,
                    apply_limits=not bool(state.get("complete_workspace_scan")),
                )
            )
            dependency_scan = deepcopy(state.get("dependency_scan") or {})
            dependency_scan["project_preprocessor_definitions"] = overlay_preprocessor_definitions(
                overlay,
                language,
            )
            base_rules = semgrep_rule_paths_for_language(language)
            with project_overlay_rule_file(overlay, language) as overlay_rule_path:
                if overlay_rule_path:
                    validation = semgrep_tool.validate_rule_paths([overlay_rule_path])
                    if not validation.get("valid"):
                        rejection = {
                            "language": language,
                            "stage": "rule_validation",
                            "status": str(validation.get("status") or "failed"),
                            "diagnostics": [
                                sanitize_public_text(str(item))
                                for item in (validation.get("diagnostics") or [])[:8]
                                if str(item).strip()
                            ],
                        }
                        overlay_rejections.append(rejection)
                        self._emit(
                            state,
                            "adaptation.rejected",
                            "rescan_project_overlay",
                            "warning",
                            f"{LANGUAGE_LABELS.get(language, language)} Overlay 规则未通过语法预检，已保留首轮扫描结果。",
                            deepcopy(rejection),
                        )
                        continue
                rules = [*base_rules, *([overlay_rule_path] if overlay_rule_path else [])]
                raw = self._run_language_scanner(
                    language,
                    attachments,
                    dependency_scan,
                    rules,
                    lambda: self._cancel_check(state["task_id"]),
                    complete_scan=bool(state.get("complete_workspace_scan")),
                    task_id=state["task_id"],
                    workspace_path=state["workspace_path"],
                    source_paths=source_paths,
                    manifest_files=state.get("manifest_files", []),
                )
            scan_failures = language_scan_failure_reasons(
                {"languages": [language], "language_results": {language: raw}}
            )
            if scan_failures:
                rejection = {
                    "language": language,
                    "stage": "overlay_rescan",
                    "status": str(raw.get("status") or "unknown"),
                    "mode": str(raw.get("mode") or "unknown"),
                    "cli_status": str(raw.get("cli_status") or ""),
                    "failures": scan_failures,
                    "diagnostics": [
                        sanitize_public_text(str(item))
                        for item in (raw.get("diagnostics") or [])[:8]
                        if str(item).strip()
                    ],
                }
                overlay_rejections.append(rejection)
                self._emit(
                    state,
                    "adaptation.rejected",
                    "rescan_project_overlay",
                    "warning",
                    f"{LANGUAGE_LABELS.get(language, language)} Overlay 重扫未通过完整性门禁，已保留首轮扫描结果。",
                    deepcopy(rejection),
                )
                continue
            adapted = apply_overlay_classification(raw, overlay)
            compact = compact_language_result(
                language,
                adapted,
                source_paths,
                rules,
                complete_scan=bool(state.get("complete_workspace_scan")),
            )
            language_results[language] = compact
            applied_languages.append(language)
            if compact.get("scan_mcp"):
                state["scan_mcp_invocations"] = [
                    *state.get("scan_mcp_invocations", []),
                    {**deepcopy(compact["scan_mcp"]), "overlay_rescan": True},
                ]
        state["language_results"] = language_results
        adaptation["iterations"] = int(adaptation.get("iterations") or 0) + 1
        if overlay_rejections:
            adaptation["overlay_rejections"] = [
                *list(adaptation.get("overlay_rejections") or []),
                *deepcopy(overlay_rejections),
            ][-MAX_ADAPTATION_ITERATIONS * max(1, len(LANGUAGE_ORDER)) :]
            adaptation["status"] = "rescanned_with_rejections" if applied_languages else "overlay_rejected"
            adaptation["termination_reason"] = (
                "overlay_rule_validation_failed"
                if any(item.get("stage") == "rule_validation" for item in overlay_rejections)
                else "overlay_rescan_degraded"
            )
            adaptation["stop_after_rejection"] = True
        else:
            adaptation["status"] = "rescanned"
        adaptation["next_action"] = ""
        state["adaptation"] = adaptation
        self._emit(
            state,
            "node.completed",
            "rescan_project_overlay",
            "warning" if overlay_rejections else "completed",
            (
                f"项目 Overlay 第 {adaptation['iterations']} 轮重扫完成："
                f"{len(applied_languages)} 种语言应用成功，{len(overlay_rejections)} 种语言保留首轮结果。"
                if overlay_rejections
                else f"项目 Overlay 第 {adaptation['iterations']} 轮重扫完成，正在重新融合证据。"
            ),
            {
                "iteration": adaptation["iterations"],
                "languages": selected_languages,
                "applied_languages": applied_languages,
                "rejected_languages": [item["language"] for item in overlay_rejections],
                "overlay_fingerprint": overlay.get("fingerprint"),
            },
        )
        return state

    def _invoke_scan_subgraph_fallback(self, state: TaskAgentState) -> TaskAgentState:
        state = self._scan_dependencies(state)
        state = self._match_dependency_vulnerabilities(state)
        state = self._profile_project(state)
        while state.get("pending_languages"):
            state = self._scan_language(state["pending_languages"][0], state)
        while True:
            state = self._fuse_analysis_evidence(state)
            state = self._synthesize_project_overlay(state)
            if self._next_adaptation_node(state) != "rescan_project_overlay":
                return state
            state = self._rescan_project_overlay(state)

    def _verify_results(self, state: TaskAgentState) -> TaskAgentState:
        self._ensure_not_cancelled(state)
        results = state.get("language_results", {})
        failures = language_scan_failure_reasons(
            {
                "languages": state.get("languages", []),
                "language_results": results,
            }
        )
        if failures:
            self._set_plan_status(state, "verify", "failed")
            message = "完整扫描未通过：" + "；".join(failures)
            self._emit(
                state,
                "verification.failed",
                "verify_results",
                "failed",
                message,
                {
                    "failures": failures,
                    "language_results": {
                        str(language): {
                            "status": str(scan.get("status") or ""),
                            "mode": str(scan.get("mode") or ""),
                            "cli_status": str(scan.get("cli_status") or ""),
                            "diagnostics": [
                                sanitize_public_text(str(item))
                                for item in (scan.get("diagnostics") or [])[:8]
                                if str(item).strip()
                            ],
                        }
                        for language, scan in results.items()
                        if isinstance(scan, dict)
                    },
                },
            )
            raise RuntimeError(message)
        finding_count = sum(int(item.get("finding_count") or 0) for item in results.values())
        parsed_files = sum(
            int((item.get("syntax_summary") or {}).get("parsed_files") or 0)
            for item in results.values()
        )
        parse_errors = sum(
            int((item.get("syntax_summary") or {}).get("parse_error_files") or 0)
            for item in results.values()
        )
        self._set_plan_status(state, "verify", "completed")
        self._emit(
            state,
            "verification.completed",
            "verify_results",
            "completed" if parse_errors == 0 else "warning",
            f"结果验证完成：解析 {parsed_files} 个文件，发现 {finding_count} 条风险，语法错误文件 {parse_errors} 个。",
            {"parsed_files": parsed_files, "finding_count": finding_count, "parse_error_files": parse_errors},
        )
        return state

    def _compose_result(self, state: TaskAgentState) -> TaskAgentState:
        results = state.get("language_results", {})
        total_findings = sum(int(item.get("finding_count") or 0) for item in results.values())
        total_review_findings = sum(int(item.get("review_finding_count") or 0) for item in results.values())
        total_files = sum(int(item.get("file_count") or 0) for item in results.values())
        labels = "、".join(LANGUAGE_LABELS[item] for item in state.get("languages", [])) or "未识别到受支持语言"
        license_scan = state.get("license_scan") if isinstance(state.get("license_scan"), dict) else {}
        license_count = int(license_scan.get("license_count") or 0)
        license_summary = f"、{license_count} 种项目许可" if license_scan else ""
        vulnerability_matching = (
            state.get("vulnerability_matching") if isinstance(state.get("vulnerability_matching"), dict) else {}
        )
        vulnerability_count = int(vulnerability_matching.get("vulnerability_count") or 0)
        vulnerability_severities = {
            key: int(value or 0)
            for key, value in (state.get("vulnerability_severities") or {}).items()
            if key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        }
        vulnerability_summary = ""
        if vulnerability_count:
            severity_note = (
                f"（严重 {vulnerability_severities.get('CRITICAL', 0)}、高危 {vulnerability_severities.get('HIGH', 0)}）"
                if vulnerability_severities.get("CRITICAL") or vulnerability_severities.get("HIGH")
                else ""
            )
            vulnerability_summary = f"、命中 {vulnerability_count} 个组件已知漏洞{severity_note}"
        state["result"] = {
            "summary": (
                f"已按 {labels} 分派专属扫描节点，完成 {total_files} 个源文件的静态规则与 AST/CFG/DFG/污点分析，"
                f"识别 {state.get('dependency_scan', {}).get('dependency_count', 0)} 个依赖组件{license_summary}"
                f"{vulnerability_summary}和 {total_findings} 条代码风险。"
            ),
            "scan_mode": state.get("scan_mode", "frozen_evaluation"),
            "languages": state.get("languages", []),
            "dependency_count": state.get("dependency_scan", {}).get("dependency_count", 0),
            "dependencies": deepcopy(state.get("dependency_scan", {}).get("dependencies", [])),
            "inferred_dependency_count": int(state.get("dependency_scan", {}).get("inferred_count") or 0),
            "inferred_dependencies": deepcopy(state.get("dependency_scan", {}).get("inferred_dependencies", [])),
            "vulnerability_count": vulnerability_count,
            "vulnerability_severities": deepcopy(vulnerability_severities),
            "vulnerabilities": deepcopy(state.get("vulnerability_hits") or []),
            "vulnerability_matching": {
                key: deepcopy(value) for key, value in vulnerability_matching.items() if key != "records"
            },
            "total_files": total_files,
            "total_findings": total_findings,
            "total_review_findings": total_review_findings,
            "coverage": {
                "mode": "complete_workspace" if state.get("complete_workspace_scan") else "frozen_evaluation",
                "limits_applied": not bool(state.get("complete_workspace_scan")),
                "source_files": total_files,
                "manifest_files": len(state.get("manifest_files") or []),
                "unsupported_files": len(state.get("unsupported_files") or []),
                "skipped_files": int(state.get("skipped_files") or 0),
            },
            "language_results": results,
            "project_profile": deepcopy(state.get("project_profile") or {}),
            "adaptation": deepcopy(state.get("adaptation") or {}),
            "scan_mcp": {
                "enabled": any(
                    str(item.get("transport") or "") == "stdio"
                    for item in state.get("scan_mcp_invocations", [])
                    if isinstance(item, dict)
                ),
                "transport": "stdio" if state.get("scan_mcp_invocations") else "in-process",
                "server": "AegisAl Code Scan MCP" if state.get("scan_mcp_invocations") else "",
                "tool": "scan_language" if state.get("scan_mcp_invocations") else "",
                "invocation_count": len(state.get("scan_mcp_invocations", [])),
                "tools": sorted(
                    {
                        str(item.get("tool") or "")
                        for item in state.get("scan_mcp_invocations", [])
                        if isinstance(item, dict) and str(item.get("tool") or "")
                    }
                ),
                "invocations": deepcopy(state.get("scan_mcp_invocations", [])),
            },
            "license_mcp": {
                "enabled": bool(state.get("license_mcp_invocations")),
                "transport": "stdio" if state.get("license_mcp_invocations") else "disabled",
                "endpoint": "managed-child-process" if state.get("license_mcp_invocations") else "",
                "server": "AegisAl License MCP" if state.get("license_mcp_invocations") else "",
                "tool": "identify_project_licenses" if state.get("license_mcp_invocations") else "",
                "invocation_count": len(state.get("license_mcp_invocations", [])),
                "tools": sorted(
                    {
                        str(item.get("tool") or "")
                        for item in state.get("license_mcp_invocations", [])
                        if isinstance(item, dict) and str(item.get("tool") or "")
                    }
                ),
                "invocations": deepcopy(state.get("license_mcp_invocations", [])),
            },
        }
        if license_scan:
            state["result"].update(
                {
                    "license_count": license_count,
                    "licenses": deepcopy(license_scan.get("licenses") or []),
                    "license_scan": deepcopy(license_scan),
                }
            )
        self._emit(
            state,
            "task.completed",
            "compose_result",
            "completed",
            state["result"]["summary"],
        )
        return state

    def _ensure_not_cancelled(self, state: TaskAgentState) -> None:
        if self._cancel_check(state["task_id"]):
            raise TaskCancelled("任务已由用户停止。")

    def _emit(
        self,
        state: TaskAgentState,
        event_type: str,
        node: str,
        status: str,
        message: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        if self._event_sink is not None:
            self._event_sink(state["task_id"], event_type, node, status, message, data)

    @staticmethod
    def _set_plan_status(state: TaskAgentState, step_id: str, status: str) -> None:
        state["plan"] = [
            {**step, "status": status if step.get("id") == step_id else step.get("status", "pending")}
            for step in state.get("plan", [])
        ]

    def _run_language_scanner(
        self,
        language: str,
        attachments: list[dict[str, Any]],
        dependency_scan: dict[str, Any],
        rule_paths: list[str],
        cancelled: Callable[[], bool],
        *,
        complete_scan: bool,
        task_id: str,
        workspace_path: str,
        source_paths: list[str],
        manifest_files: list[str],
    ) -> dict[str, Any]:
        if self._language_scanner is not None:
            return self._language_scanner(
                language,
                attachments,
                dependency_scan,
                rule_paths,
                cancelled,
            )
        if self._uses_scan_mcp(task_id):
            try:
                return self._code_scan_client.scan_language(
                    workspace_path=workspace_path,
                    language=language,
                    source_paths=source_paths,
                    manifest_files=manifest_files,
                    dependency_scan=dependency_scan,
                    rule_paths=rule_paths,
                    complete_scan=complete_scan,
                    cancelled=cancelled,
                )
            except CodeScanMCPError as exc:
                if cancelled():
                    raise TaskCancelled("任务已由用户停止。") from exc
                raise
        return semgrep_tool.analyze(
            attachments,
            dependency_scan,
            [],
            rule_paths=rule_paths,
            cancelled=cancelled,
            language_hint=language,
            include_all_attachments=complete_scan,
        )

    def _uses_scan_mcp(self, task_id: str) -> bool:
        if self._language_scanner is not None:
            return False
        if str(task_id).startswith("evaluation-"):
            return False
        return self._code_scan_client.enabled

    def _scan_transport(self, task_id: str) -> str:
        return "mcp-stdio" if self._uses_scan_mcp(task_id) else "in-process"

    def shutdown(self) -> None:
        self._code_scan_client.shutdown()
        self._sbom_license_capability.shutdown()

    def cancel_active_scan(self) -> None:
        self._code_scan_client.cancel_active_scan()


class TaskAgentService:
    def __init__(
        self,
        store: AgentTaskStore | None = None,
        *,
        max_workers: int = 2,
        graph: TaskAgentGraph | None = None,
        language_scanner: LanguageScanner | None = None,
        code_scan_client: CodeScanMCPClient | None = None,
        overlay_synthesizer: OverlaySynthesizer | None = None,
        adaptive_upload: bool = True,
        project_memory_sink: ProjectMemorySink | None = None,
        execution_mode: str | None = None,
        plugin_runtime: SecFlowRuntime | None = None,
    ) -> None:
        self.store = store or AgentTaskStore()
        self._max_workers = max_workers
        injected_runtime = any(
            value is not None
            for value in (graph, language_scanner, code_scan_client, overlay_synthesizer)
        )
        configured_mode = str(
            execution_mode or os.getenv("SECFLOW_TASK_EXECUTION_MODE", "")
        ).strip().lower()
        self._execution_mode = configured_mode or ("inline" if injected_runtime else "external")
        if self._execution_mode not in {"external", "inline", "worker"}:
            raise ValueError(f"unsupported task execution mode: {self._execution_mode}")
        self._executor: ThreadPoolExecutor | None = None
        self._supervisor: Any = None
        self._cancel_events: dict[str, Event] = {}
        self._lease_lost_events: dict[str, Event] = {}
        self._futures: dict[str, Future[Any]] = {}
        self._lock = RLock()
        self._project_memory_sink = project_memory_sink
        self._plugin_runtime = plugin_runtime
        self.graph = graph or TaskAgentGraph(
            event_sink=self._record_event,
            cancel_check=self.is_cancelled,
            language_scanner=language_scanner,
            code_scan_client=code_scan_client,
            overlay_synthesizer=overlay_synthesizer,
            adaptive_upload=adaptive_upload,
        )

    def create(
        self,
        *,
        objective: str,
        workspace_path: str,
        user_id: str,
        session_id: str = "",
        baseline_task_id: str = "",
        root_task_id: str = "",
        run_number: int = 1,
    ) -> dict[str, Any]:
        workspace = resolve_workspace_path(workspace_path)
        timestamp = now_iso()
        task_id = f"task-{uuid4()}"
        resolved_session_id = session_id.strip() or f"agent-task:{task_id}"
        task = {
            "id": task_id,
            "objective": objective.strip(),
            "workspace_path": str(workspace),
            "workspace_name": workspace.name,
            "workspace_type": "directory" if workspace.is_dir() else "file",
            "user_id": user_id or "default",
            "session_id": resolved_session_id,
            "baseline_task_id": baseline_task_id or None,
            "root_task_id": root_task_id or task_id,
            "run_number": max(1, int(run_number)),
            "status": "queued",
            "current_node": "queued",
            "languages": [],
            "plan": [],
            "events": [],
            "result": None,
            "report_ready": False,
            "report_decision": "unavailable",
            "report": None,
            "plugin_state": self._runtime().task_pin(),
            "error": "",
            "archived": False,
            "archived_at": None,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        self.store.create(task)
        memory_status = ""
        if self._project_memory_sink is not None:
            memory_status = "failed"
            try:
                self._project_memory_sink(deepcopy(task))
                memory_status = "stored"
            except Exception:  # noqa: BLE001 - memory failure must not cancel an authorized scan.
                memory_status = "failed"
            self.store.update(
                task_id,
                project_memory={
                    "status": memory_status,
                    "user_id": str(task.get("user_id") or "default"),
                    "session_id": resolved_session_id,
                    "stored_at": now_iso() if memory_status == "stored" else "",
                },
            )
        self._record_event(
            task_id,
            "task.created",
            "queued",
            "warning" if self._project_memory_sink is not None and memory_status == "failed" else "queued",
            (
                "任务已创建并写入当前用户的长期项目记忆，等待执行。"
                if self._project_memory_sink is not None and memory_status == "stored"
                else "任务已创建，等待执行。"
            ),
            {"project_memory": memory_status} if self._project_memory_sink is not None else {},
        )
        self._submit(task_id)
        return self.store.get(task_id)

    def rescan(
        self,
        baseline_task_id: str,
        *,
        objective: str,
        user_id: str,
        session_id: str = "",
    ) -> dict[str, Any]:
        baseline = self.store.get(baseline_task_id)
        if str(baseline.get("user_id") or "default") != (user_id or "default"):
            raise KeyError(baseline_task_id)
        if baseline.get("status") != "completed" or not isinstance(baseline.get("result"), dict):
            raise ValueError("只有已完成且包含扫描结果的任务可以作为重新扫描基线。")
        return self.create(
            objective=objective.strip() or f"重新扫描 {baseline.get('workspace_name') or '项目'}",
            workspace_path=str(baseline.get("workspace_path") or ""),
            user_id=user_id,
            session_id=session_id.strip() or str(baseline.get("session_id") or ""),
            baseline_task_id=str(baseline.get("id") or baseline_task_id),
            root_task_id=str(baseline.get("root_task_id") or baseline.get("id") or baseline_task_id),
            run_number=int(baseline.get("run_number") or 1) + 1,
        )

    def get(self, task_id: str) -> dict[str, Any]:
        return self.store.get(task_id)

    def event_stream_snapshot(self, task_id: str, *, after: int = 0) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        task = self.store.get(task_id, include_events=False)
        events = self.store.events(task_id, after=after)
        return task, events

    def list(
        self,
        user_id: str,
        limit: int = 30,
        *,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        return self.store.list(user_id, limit, archived=archived)

    def execution_status(self) -> dict[str, Any]:
        with self._lock:
            supervisor = self._supervisor
            executor_running = self._executor is not None
        if supervisor is not None:
            return supervisor.snapshot()
        return {
            "mode": self._execution_mode,
            "configured_workers": self._max_workers,
            "running_workers": self._max_workers if executor_running else 0,
        }

    def archive(self, task_id: str, *, archived: bool) -> dict[str, Any]:
        task = self.store.get(task_id)
        if bool(task.get("archived", False)) is archived:
            return task
        if task.get("status") not in TERMINAL_TASK_STATUSES:
            raise ValueError("运行中的任务不能归档，请先停止任务。")
        updated = self.store.update(
            task_id,
            archived=archived,
            archived_at=now_iso() if archived else None,
        )
        self._record_event(
            task_id,
            "task.archived" if archived else "task.restored",
            "archive",
            "completed",
            "任务已归档。" if archived else "任务已从归档恢复。",
            {"archived": archived},
        )
        return self.store.get(task_id)

    def delete(self, task_id: str) -> dict[str, Any]:
        task = self.store.get(task_id)
        if task.get("status") not in TERMINAL_TASK_STATUSES:
            raise ValueError("运行中的任务不能删除，请先停止任务。")
        with self._lock:
            self._cancel_events.pop(task_id, None)
            self._futures.pop(task_id, None)
        return self.store.delete(task_id)

    def cancel(self, task_id: str) -> dict[str, Any]:
        task = self.store.get(task_id)
        if task.get("status") in TERMINAL_TASK_STATUSES:
            return task
        with self._lock:
            event = self._cancel_events.setdefault(task_id, Event())
            event.set()
        cancel_active_scan = getattr(self.graph, "cancel_active_scan", None)
        if callable(cancel_active_scan):
            cancel_active_scan()
        if self._execution_mode != "inline" and self.store.cancel_queued_job(task_id):
            def cancel_queued(value: dict[str, Any]) -> None:
                if value.get("status") in TERMINAL_TASK_STATUSES:
                    return
                clear_cancelled_task_data(value)
                value.update(status="cancelled", error="任务在开始执行前已由用户停止。")

            cancelled_task = self.store.mutate(task_id, cancel_queued)
            if cancelled_task.get("status") != "cancelled":
                return cancelled_task
            self._record_event(
                task_id,
                "task.cancelled",
                "cancel",
                "warning",
                "任务在开始执行前已由用户停止。",
                None,
            )
            return self.store.get(task_id)

        def mark_cancelling(value: dict[str, Any]) -> None:
            if value.get("status") in TERMINAL_TASK_STATUSES:
                return
            clear_cancelled_task_data(value)
            value.update(status="cancelling", error="")

        cancelling_task = self.store.mutate(task_id, mark_cancelling)
        if cancelling_task.get("status") != "cancelling":
            return cancelling_task
        self._record_event(task_id, "task.cancelling", "cancel", "warning", "正在停止任务。", None)
        return self.store.get(task_id)

    def decide_report(
        self,
        task_id: str,
        *,
        generate: bool,
        report_store: Any,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        task = self.store.get(task_id)
        if not agent_task_report_ready(task):
            raise ValueError("扫描尚未完成，暂时不能处理报告选择。")

        decision = str(task.get("report_decision") or "pending")
        if decision == "generating":
            raise ValueError("Report Agent 正在生成报告，请勿重复提交。")
        if decision == "generated" and isinstance(task.get("report"), dict):
            metadata = task["report"].get("metadata") if isinstance(task["report"].get("metadata"), dict) else {}
            mcp_audit = metadata.get("report_mcp") if isinstance(metadata.get("report_mcp"), dict) else {}
            is_current_report = (
                int(metadata.get("report_schema_version") or 0) >= 5
                and str(metadata.get("scan_json_schema") or "") == "secflow.scan-results/v1"
                and bool(metadata.get("scan_json_sha256"))
                and str(mcp_audit.get("status") or "") == "completed"
            )
            if is_current_report or not generate:
                return task
        if decision == "declined" and not generate:
            return task

        session_id = f"agent-task:{task_id}"
        self.store.update(task_id, report_decision="generating")
        self._record_event(
            task_id,
            "report.agent.started",
            "report_agent",
            "running",
            "已将固定扫描事实交给 Report Agent，正在规划报告生成工具链。",
            {"agent_id": "report_agent", "decision": "confirm" if generate else "cancel"},
        )
        progress_sink = self._report_progress_sink(task_id)
        try:
            operation = self._start_report_agent_operation(
                task,
                report_store=report_store,
                generate=generate,
                event_sink=progress_sink,
                response_language=response_language,
            )
            orchestration = operation.get("orchestration") if isinstance(operation.get("orchestration"), dict) else {}
            if str(orchestration.get("final_agent") or "") != "report_agent":
                raise ValueError("报告确认未能交接给 Report Agent。")
            interrupt_envelope = operation.get("interrupt") if isinstance(operation.get("interrupt"), dict) else {}
            thread_id = str(interrupt_envelope.get("thread_id") or "")
            if not interrupt_envelope or not thread_id:
                raise ValueError(str(operation.get("error") or "未能建立 Report Agent 报告生成确认。"))
            outcome = report_capability_subgraph.resume(
                thread_id,
                decision="confirm" if generate else "cancel",
                user_id=str(task.get("user_id") or "default"),
                session_id=session_id,
                interrupt_id=str(interrupt_envelope.get("interrupt_id") or ""),
                event_sink=progress_sink,
            )
        except Exception as exc:  # noqa: BLE001 - failed report orchestration must remain retryable.
            message = sanitize_public_text(str(exc)).strip() or "Report Agent 执行失败。"
            self.store.update(task_id, report_decision="pending")
            self._record_event(
                task_id,
                "report.agent.failed",
                "report_agent",
                "failed",
                message,
                {"agent_id": "report_agent"},
            )
            raise ValueError(message) from exc
        if not generate:
            self.store.update(
                task_id,
                report_decision="declined",
                report=None,
                report_interrupt=None,
                report_thread_id=None,
                report_orchestration=orchestration,
            )
            self._record_event(
                task_id,
                "report.agent.completed",
                "report_agent",
                "completed",
                "Report Agent 已按用户确认结束报告流程，扫描结果保持不变。",
                {"agent_id": "report_agent", "orchestration": orchestration},
            )
            self._record_event(
                task_id,
                "report.declined",
                "report_interrupt",
                "completed",
                "已按用户选择跳过报告生成，保留完整扫描结果。",
                {"interrupt_id": interrupt_envelope.get("interrupt_id")},
            )
            return self.store.get(task_id)

        mcp_audit = outcome.get("report_mcp") if isinstance(outcome.get("report_mcp"), dict) else {}
        mcp_status = str(mcp_audit.get("status") or "failed")
        self._record_event(
            task_id,
            "report.mcp.completed" if mcp_status == "completed" else "report.mcp.failed",
            "report.chart_mcp",
            "completed" if mcp_status == "completed" else "warning",
            (
                f"Report Chart MCP 已处理 {int(mcp_audit.get('fact_count') or 0)} 条扫描事实。"
                if mcp_status == "completed"
                else f"Report Chart MCP 调用失败：{mcp_audit.get('error') or outcome.get('error') or '未知错误'}"
            ),
            mcp_audit,
        )
        report = dict(outcome.get("report") or {})
        if not report:
            message = sanitize_public_text(outcome.get("error") or "报告生成失败。").strip()
            self.store.update(task_id, report_decision="pending")
            self._record_event(
                task_id,
                "report.agent.failed",
                "report_agent",
                "failed",
                message,
                {"agent_id": "report_agent", "orchestration": orchestration},
            )
            raise ValueError(message)
        self.store.update(
            task_id,
            report_decision="generated",
            report=report,
            report_interrupt=outcome.get("interrupt"),
            report_thread_id=outcome.get("thread_id"),
            report_orchestration=orchestration,
        )
        self._record_event(
            task_id,
            "report.agent.completed",
            "report_agent",
            "completed",
            "Report Agent 已完成固定扫描事实核验和多格式报告生成。",
            {
                "agent_id": "report_agent",
                "report_id": report.get("id"),
                "orchestration": orchestration,
            },
        )
        self._record_event(
            task_id,
            "report.generated",
            "report_capability_subgraph",
            "completed",
            f"分析报告已生成：{report.get('file_name') or report.get('title') or report.get('id')}。",
            {
                "report_id": report.get("id"),
                "file_name": report.get("file_name"),
                "generation_interrupt_id": interrupt_envelope.get("interrupt_id"),
                "download_interrupt_id": (outcome.get("interrupt") or {}).get("interrupt_id"),
                "chart_mcp": mcp_audit.get("tool") or "build_scan_report_charts",
                "mcp_status": mcp_status,
                "mcp_output_sha256": mcp_audit.get("output_sha256"),
                "scan_json_sha256": (report.get("metadata") or {}).get("scan_json_sha256"),
            },
        )
        return self.store.get(task_id)

    def _start_report_agent_operation(
        self,
        task: dict[str, Any],
        *,
        report_store: Any,
        generate: bool,
        event_sink: Any,
        response_language: str = "zh-Hans",
    ) -> dict[str, Any]:
        from app.agent.assistant_intent import plan_assistant_intent
        from app.langgraph.assistant_graph import knowledge_graph
        from app.langgraph.multi_agent_graph import assistant_multi_agent_supervisor
        from app.memory import memory_service

        task_id = str(task.get("id") or "")
        session_id = f"agent-task:{task_id}"
        question = (
            "基于当前已完成的固定扫描事实生成完整安全报告"
            if generate
            else "暂不生成当前扫描报告"
        )
        intent_plan = {
            "intent": "report_operation",
            "reason": "用户已在扫描任务卡中确认报告操作。",
            "confidence": 1.0,
            "planner": "deterministic-task-report-confirmation",
        }
        return assistant_multi_agent_supervisor.invoke(
            question=question,
            top_k=8,
            user_id=str(task.get("user_id") or "default"),
            session_id=session_id,
            response_language=str(response_language or "zh-Hans"),
            attachments=[],
            workspace_path=str(task.get("workspace_path") or ""),
            task_context={
                "report_task": task,
                "report_metrics": agent_task_report_metrics(task),
                "report_store_root": str(report_store.root),
            },
            active_task=task,
            runtime_graph=knowledge_graph,
            memory=memory_service,
            planner=plan_assistant_intent,
            intent_plan=intent_plan,
            task_service=self,
            event_sink=event_sink,
            allow_workspace_recovery=False,
            allow_task_creation=False,
        )

    def _report_progress_sink(self, task_id: str) -> Callable[[dict[str, Any]], None]:
        def emit(item: dict[str, Any]) -> None:
            node = str(item.get("node") or "report_agent")
            status = str(item.get("status") or "completed")
            if node == "report_agent" and status == "completed":
                status = "running"
            presentation = item.get("presentation") if isinstance(item.get("presentation"), dict) else {}
            data: dict[str, Any] = {"agent_id": node if node.endswith("_agent") else "report_agent"}
            if presentation:
                data["presentation"] = presentation
                if presentation.get("tool_name"):
                    data["tool_name"] = str(presentation["tool_name"])
            self._record_event(
                task_id,
                "report.agent.progress",
                node,
                status,
                str(item.get("message") or "Report Agent 正在执行。"),
                data,
            )

        return emit

    def decide_report_download(self, task_id: str, *, confirm: bool, report_format: str) -> dict[str, Any]:
        task = self.store.get(task_id)
        requested_format = str(report_format or "pdf").strip().lower()
        download_action = "download_report_all_formats" if requested_format == "all" else "download_report"
        requested_formats = [] if requested_format == "all" else [requested_format]
        thread_id = str(task.get("report_thread_id") or "")
        envelope = task.get("report_interrupt") if isinstance(task.get("report_interrupt"), dict) else {}
        if not thread_id or not envelope:
            if not confirm or not isinstance(task.get("report"), dict):
                outcome = {"artifacts": []}
            else:
                restarted = report_capability_subgraph.start(
                    {
                        "action": download_action,
                        "report_ids": [str(task["report"].get("id") or "")],
                        "formats": requested_formats,
                        "user_id": str(task.get("user_id") or "default"),
                        "session_id": f"agent-task:{task_id}",
                    }
                )
                outcome = report_capability_subgraph.resume(
                    str(restarted.get("thread_id") or ""),
                    decision="confirm",
                    user_id=str(task.get("user_id") or "default"),
                    session_id=f"agent-task:{task_id}",
                    report_format=None if requested_format == "all" else requested_format,
                )
        else:
            try:
                outcome = report_capability_subgraph.resume(
                    thread_id,
                    decision="confirm" if confirm else "cancel",
                    user_id=str(task.get("user_id") or "default"),
                    session_id=f"agent-task:{task_id}",
                    report_format=requested_format,
                )
            except KeyError:
                if not confirm or not isinstance(task.get("report"), dict):
                    outcome = {"artifacts": []}
                else:
                    restarted = report_capability_subgraph.start(
                        {
                            "action": download_action,
                            "report_ids": [str(task["report"].get("id") or "")],
                            "formats": requested_formats,
                            "user_id": str(task.get("user_id") or "default"),
                            "session_id": f"agent-task:{task_id}",
                        }
                    )
                    outcome = report_capability_subgraph.resume(
                        str(restarted.get("thread_id") or ""),
                        decision="confirm",
                        user_id=str(task.get("user_id") or "default"),
                        session_id=f"agent-task:{task_id}",
                        report_format=None if requested_format == "all" else requested_format,
                    )
        artifact = next(iter(outcome.get("artifacts") or []), None)
        self.store.update(
            task_id,
            report_interrupt=None,
            report_thread_id=None,
            report_download_artifact=artifact,
        )
        self._record_event(
            task_id,
            "report.download_confirmed" if confirm else "report.download_declined",
            "report_download_interrupt",
            "completed",
            f"报告下载已确认：{artifact.get('file_name')}." if artifact else "已取消报告下载，报告仍保留在报告中心。",
            {
                "interrupt_id": envelope.get("interrupt_id"),
                "format": requested_format,
                "artifact_id": (artifact or {}).get("id"),
            },
        )
        return {"task": self.store.get(task_id), "artifact": artifact}

    def resume(self, task_id: str) -> dict[str, Any]:
        task = self.store.get(task_id)
        if task.get("status") not in {"failed", "cancelled", "interrupted"}:
            return task

        def reset(value: dict[str, Any]) -> None:
            value.update(
                status="queued",
                current_node="queued",
                languages=[],
                plan=[],
                result=None,
                report_ready=False,
                report_decision="unavailable",
                report=None,
                report_interrupt=None,
                report_thread_id=None,
                report_download_artifact=None,
                report_orchestration=None,
                workspace_fingerprint=None,
                ruleset_fingerprint=None,
                engine_fingerprint=None,
                error="",
            )

        self.store.mutate(task_id, reset)
        self._record_event(task_id, "task.resumed", "queued", "queued", "任务已重新排队。", None)
        self._submit(task_id)
        return self.store.get(task_id)

    def is_cancelled(self, task_id: str) -> bool:
        with self._lock:
            if self._cancel_events.get(task_id, Event()).is_set():
                return True
            if self._lease_lost_events.get(task_id, Event()).is_set():
                return True
        try:
            return str(self.store.get(task_id, include_events=False).get("status") or "") in {
                "cancelling",
                "cancelled",
            }
        except KeyError:
            return True

    def signal_lease_lost(self, task_id: str) -> None:
        with self._lock:
            self._lease_lost_events.setdefault(task_id, Event()).set()

    def lease_was_lost(self, task_id: str) -> bool:
        with self._lock:
            return self._lease_lost_events.get(task_id, Event()).is_set()

    def shutdown(self, *, wait: bool = False) -> None:
        with self._lock:
            for event in self._cancel_events.values():
                event.set()
            executor = self._executor
            self._executor = None
            supervisor = self._supervisor
            self._supervisor = None
        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)
        if supervisor is not None:
            supervisor.stop(wait=wait)
        shutdown_graph = getattr(self.graph, "shutdown", None)
        if callable(shutdown_graph):
            shutdown_graph()

    def start(self) -> None:
        if self._execution_mode == "worker":
            return
        if self._execution_mode == "external":
            with self._lock:
                if self._supervisor is not None:
                    return
                recovered = self.store.reconcile_pending_jobs()
                for task_id in recovered:
                    self._record_event(
                        task_id,
                        "task.requeued",
                        "queued",
                        "warning",
                        "检测到上次执行未完成，任务已由持久队列重新排队。",
                        {"recovery": "expired-or-missing-worker-lease"},
                    )
                from app.agent.task_worker import TaskWorkerProcessSupervisor

                self._supervisor = TaskWorkerProcessSupervisor(
                    store_path=self.store.path,
                    worker_count=self._max_workers,
                )
                self._supervisor.start()
            return
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="secflow-task-agent",
                )

    def _submit(self, task_id: str) -> None:
        if self._execution_mode != "inline":
            self.store.enqueue(task_id)
            if self._execution_mode == "external":
                self.start()
            return
        self.start()
        with self._lock:
            self._cancel_events[task_id] = Event()
            if self._executor is None:  # pragma: no cover - start() guarantees an executor.
                raise RuntimeError("任务执行器未启动")
            self._futures[task_id] = self._executor.submit(self._run, task_id)

    def _runtime(self) -> SecFlowRuntime:
        return self._plugin_runtime or secflow_runtime()

    def run_claimed(self, task_id: str, worker_id: str, *, recovered: bool = False) -> dict[str, Any]:
        """Execute one already-leased job inside the dedicated worker process."""

        with self._lock:
            self._cancel_events[task_id] = Event()
            self._lease_lost_events[task_id] = Event()
        if recovered:
            self._record_event(
                task_id,
                "task.recovered",
                "queued",
                "warning",
                "上一个 Worker 的租约已失效，当前 Worker 将从持久任务状态重新执行。",
                {"worker_id": worker_id},
            )
        try:
            self._run(task_id)
            task = self.store.get(task_id, include_events=False)
            if self.lease_was_lost(task_id):
                return task
            status = str(task.get("status") or "failed")
            terminal_state = status if status in {"completed", "failed", "cancelled"} else "failed"
            self.store.finish_job(
                task_id,
                worker_id,
                state=terminal_state,
                error=str(task.get("error") or ""),
            )
            return task
        finally:
            with self._lock:
                self._cancel_events.pop(task_id, None)
                self._lease_lost_events.pop(task_id, None)

    def fail_claimed(self, task_id: str, worker_id: str, message: str) -> None:
        public_message = sanitize_public_text(message) or "任务在多次 Worker 恢复后仍无法执行。"
        self.store.update(task_id, status="failed", report_ready=False, error=public_message)
        self._record_event(task_id, "task.failed", "worker_recovery", "failed", public_message, None)
        self.store.finish_job(task_id, worker_id, state="failed", error=public_message)

    def _run(self, task_id: str) -> None:
        try:
            started = False

            def mark_running(value: dict[str, Any]) -> None:
                nonlocal started
                if value.get("status") in {"cancelling", "cancelled"}:
                    return
                if value.get("status") in TERMINAL_TASK_STATUSES:
                    return
                value.update(status="running", error="")
                started = True

            task = self.store.mutate(task_id, mark_running)
            if not started:
                if task.get("status") in {"cancelling", "cancelled"}:
                    raise TaskCancelled("任务已由用户停止。")
                return
            if self.is_cancelled(task_id):
                raise TaskCancelled("任务已由用户停止。")
            self._record_event(task_id, "task.started", "inspect_workspace", "running", "任务开始执行。", None)
            runtime = self._runtime()
            with runtime.pin() as runtime_snapshot:
                persisted_pin = task.get("plugin_state")
                if persisted_pin is None:
                    # Tasks created before plugin pinning existed are adopted by
                    # the first runtime that resumes them, then become strict.
                    persisted_pin = task_plugin_state(runtime_snapshot)
                    task = self.store.update(task_id, plugin_state=persisted_pin)
                    self._record_event(
                        task_id,
                        "task.plugin_state_migrated",
                        "inspect_workspace",
                        "warning",
                        "旧任务已绑定当前插件运行时快照。",
                        {
                            "schema_version": persisted_pin["schema_version"],
                            "runtime_generation": persisted_pin["runtime_generation"],
                        },
                    )
                elif not isinstance(persisted_pin, Mapping):
                    raise ValueError("Task plugin state is invalid")
                runtime.validate_task_pin(persisted_pin, snapshot=runtime_snapshot)
                state = self.graph.invoke(
                    task_id=task_id,
                    objective=str(task.get("objective") or ""),
                    workspace_path=str(task.get("workspace_path") or ""),
                    user_id=str(task.get("user_id") or "default"),
                )
            if self.is_cancelled(task_id):
                raise TaskCancelled("任务已由用户停止。")
            result = deepcopy(state.get("result") or {})
            baseline_task_id = str(task.get("baseline_task_id") or "")
            if baseline_task_id:
                baseline = self.store.get(baseline_task_id)
                baseline_result = baseline.get("result") if isinstance(baseline.get("result"), dict) else {}
                result["result_diff"] = build_scan_result_diff(baseline_result, result)
                result["baseline_task_id"] = baseline_task_id
            result["ruleset_fingerprint"] = task_ruleset_fingerprint(result)
            result["engine_fingerprint"] = task_engine_fingerprint()
            result["workspace_fingerprint"] = str(
                (result.get("project_profile") or {}).get("scope_fingerprint") or ""
            )
            completed = False

            def mark_completed(value: dict[str, Any]) -> None:
                nonlocal completed
                if value.get("status") in {"cancelling", "cancelled"}:
                    return
                value.update(
                    status="completed",
                    current_node="compose_result",
                    languages=state.get("languages", []),
                    plan=state.get("plan", []),
                    result=result,
                    report_ready=True,
                    workspace_fingerprint=result.get("workspace_fingerprint") or None,
                    ruleset_fingerprint=result.get("ruleset_fingerprint") or None,
                    engine_fingerprint=result.get("engine_fingerprint") or None,
                    report_decision="pending",
                    report=None,
                    error="",
                )
                completed = True

            completion_snapshot = self.store.mutate(task_id, mark_completed)
            if not completed:
                if completion_snapshot.get("status") in {"cancelling", "cancelled"}:
                    raise TaskCancelled("任务已由用户停止。")
                return
        except TaskCancelled as exc:
            if not self.lease_was_lost(task_id):
                cancel_active_scan = getattr(self.graph, "cancel_active_scan", None)
                if callable(cancel_active_scan):
                    cancel_active_scan()

                cancellation_persisted = False

                def finish_cancel(value: dict[str, Any]) -> None:
                    nonlocal cancellation_persisted
                    if value.get("status") in TERMINAL_TASK_STATUSES and value.get("status") != "cancelled":
                        return
                    clear_cancelled_task_data(value)
                    value.update(status="cancelled", error=str(exc))
                    cancellation_persisted = True

                self.store.mutate(task_id, finish_cancel)
                if cancellation_persisted:
                    self._record_in_flight_node_cancellation(task_id)
                    self._record_event(task_id, "task.cancelled", "cancel", "warning", str(exc), None)
        except Exception as exc:  # noqa: BLE001 - task failure must be persisted for the UI.
            message = sanitize_public_text(str(exc)) or "任务执行失败。"
            self.store.update(task_id, status="failed", report_ready=False, error=message)
            self._record_event(task_id, "task.failed", "failed", "failed", message, None)
        finally:
            with self._lock:
                self._futures.pop(task_id, None)
                if self._execution_mode == "inline":
                    self._cancel_events.pop(task_id, None)
                    self._lease_lost_events.pop(task_id, None)

    def _record_in_flight_node_cancellation(self, task_id: str) -> None:
        """Persist a terminal event for the node interrupted by cancellation.

        Long-running nodes (for example language semantic scans) emit
        heartbeat/progress events whose status stays ``running``. Without a
        terminal event the timeline keeps rendering a spinner for a task that
        the user has already stopped.
        """

        snapshot = self.store.get(task_id)
        for event in reversed(snapshot.get("events", []) or []):
            event_type = str(event.get("type") or "")
            node = str(event.get("node") or "")
            if not node or event_type.startswith("task."):
                continue
            if str(event.get("status") or "") in {"running", "started"}:
                self._record_event(
                    task_id,
                    "node.cancelled",
                    node,
                    "cancelled",
                    "该步骤已随用户停止而终止。",
                    None,
                )
            return

    def _record_event(
        self,
        task_id: str,
        event_type: str,
        node: str,
        status: str,
        message: str,
        data: dict[str, Any] | None,
    ) -> None:
        self.store.add_event(
            task_id,
            event_type=event_type,
            node=node,
            status=status,
            message=sanitize_public_text(message),
            data=data,
        )
        if event_type == "languages.detected" and data is not None:
            def update_languages(task: dict[str, Any]) -> None:
                if task.get("status") not in {"cancelling", "cancelled"}:
                    task["languages"] = list(data.get("languages") or [])

            self.store.mutate(task_id, update_languages)
        elif event_type == "plan.updated" and data is not None:
            def replace_plan(task: dict[str, Any]) -> None:
                if task.get("status") not in {"cancelling", "cancelled"}:
                    task["plan"] = list(data.get("plan") or [])

            self.store.mutate(task_id, replace_plan)
        elif event_type in {"node.started", "node.completed", "verification.completed"}:
            plan_status = "running" if event_type == "node.started" else "completed"

            def update_plan(task: dict[str, Any]) -> None:
                if task.get("status") in {"cancelling", "cancelled"}:
                    return
                task["plan"] = [
                    {**step, "status": plan_status if step.get("node") == node else step.get("status", "pending")}
                    for step in task.get("plan", [])
                ]

            self.store.mutate(task_id, update_plan)


def resolve_workspace_path(value: str, *, apply_limits: bool = False) -> Path:
    clean = value.strip()
    if not clean or "\x00" in clean:
        raise ValueError("请选择有效的代码文件或项目目录。")
    unresolved = Path(clean).expanduser()
    if unresolved.is_symlink():
        raise ValueError("不能把符号链接作为扫描范围。")
    try:
        path = unresolved.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("所选文件或目录不存在或无法读取。") from exc
    if path.is_dir() and path == Path(path.anchor):
        raise ValueError("不能把磁盘根目录作为任务工作区。")
    if path.is_dir():
        return path
    if not path.is_file() or not is_allowed_attachment_name(path.name):
        raise ValueError("请选择受支持的代码文件、项目清单或项目目录。")
    if attachment_kind(path.name) == "code":
        language = language_for_file(path.name)
        if language not in set(supported_flow_languages()) or not is_analyzable_source_path(path.name):
            raise ValueError("该代码文件的语言暂不支持工作区扫描。")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ValueError("所选文件无法读取。") from exc
    if size <= 0:
        raise ValueError("所选文件为空，无法执行扫描。")
    if apply_limits and size > MAX_WORKSPACE_FILE_BYTES:
        raise ValueError(f"单个扫描文件不能超过 {MAX_WORKSPACE_FILE_BYTES // 1_000} KB。")
    return path


def collect_workspace_inventory(root: Path, *, apply_limits: bool = True) -> dict[str, Any]:
    workspace = resolve_workspace_path(str(root), apply_limits=apply_limits)
    supported = set(supported_flow_languages())
    files_by_language: dict[str, list[str]] = {language: [] for language in LANGUAGE_ORDER}
    manifest_files: list[str] = []
    unsupported_files: list[str] = []
    skipped_files = 0
    total_bytes = 0
    accepted = 0
    accepted_manifests = 0
    seen_paths: set[str] = set()

    if workspace.is_file():
        relative = workspace.name
        kind = attachment_kind(relative)
        language = language_for_file(relative)
        try:
            size = workspace.stat().st_size
        except OSError:
            size = 0
        if kind == "code" and size <= 512 and _is_symlink_like_workspace_file(workspace, relative):
            return {
                "files_by_language": {},
                "manifest_files": [],
                "unsupported_files": [],
                "skipped_files": 1,
            }
        if kind != "code":
            manifest_files.append(relative)
        elif language in supported:
            files_by_language[language].append(relative)
        else:
            unsupported_files.append(relative)
        return {
            "files_by_language": {key: value for key, value in files_by_language.items() if value},
            "manifest_files": manifest_files,
            "unsupported_files": unsupported_files,
            "skipped_files": 0,
        }

    def workspace_candidates():
        for directory, names, file_names in os.walk(workspace, followlinks=False):
            relative_directory = Path(directory).relative_to(workspace)
            names[:] = sorted(
                name
                for name in names
                if name.lower() not in EXCLUDED_SOURCE_PARTS
                and not name.startswith(".")
                and not (Path(directory) / name).is_symlink()
            )
            for file_name in sorted(file_names):
                yield Path(directory) / file_name, (relative_directory / file_name).as_posix()

    for relative in common_compile_database_paths(workspace):
        if relative in seen_paths:
            continue
        candidate = workspace / relative
        try:
            resolved = candidate.resolve(strict=True)
            size = resolved.stat().st_size
        except OSError:
            skipped_files += 1
            continue
        if (
            not resolved.is_relative_to(workspace)
            or not resolved.is_file()
            or size <= 0
            or (apply_limits and size > MAX_WORKSPACE_FILE_BYTES)
        ):
            skipped_files += 1
            continue
        if apply_limits and (
            accepted_manifests >= MAX_WORKSPACE_MANIFEST_FILES
            or accepted >= MAX_WORKSPACE_FILES
            or total_bytes + size > MAX_WORKSPACE_TOTAL_BYTES
        ):
            skipped_files += 1
            continue
        manifest_files.append(relative)
        accepted_manifests += 1
        total_bytes += size
        accepted += 1
        seen_paths.add(relative)

    # Reserve the bounded attachment budget for authoritative manifests first,
    # then other manifests, translation units, and finally ambiguous headers.
    for inventory_phase in (0, 1, 2, 3):
        for candidate, relative in workspace_candidates():
            if relative in seen_paths:
                continue
            if (
                candidate.is_symlink()
                or not candidate.is_file()
                or not is_allowed_attachment_name(relative)
                or not is_analyzable_source_path(relative)
            ):
                continue
            kind = attachment_kind(relative)
            manifest_priority = dependency_attachment_priority(relative, kind)[0]
            is_header = Path(relative).suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}
            candidate_phase = 0 if manifest_priority == 0 else (1 if kind != "code" else (3 if is_header else 2))
            if candidate_phase != inventory_phase:
                continue
            if apply_limits and kind != "code" and accepted_manifests >= MAX_WORKSPACE_MANIFEST_FILES:
                skipped_files += 1
                continue
            if apply_limits and (accepted >= MAX_WORKSPACE_FILES or total_bytes >= MAX_WORKSPACE_TOTAL_BYTES):
                skipped_files += 1
                continue
            language = language_for_file(relative)
            if Path(relative).suffix.lower() == ".h" and files_by_language.get("cpp"):
                language = "cpp"
            if kind == "code" and not is_analyzable_source_path(relative):
                continue
            try:
                resolved = candidate.resolve(strict=True)
                size = resolved.stat().st_size
            except OSError:
                skipped_files += 1
                continue
            if (
                not resolved.is_relative_to(workspace)
                or size <= 0
                or (apply_limits and size > MAX_WORKSPACE_FILE_BYTES)
            ):
                skipped_files += 1
                continue
            if apply_limits and total_bytes + size > MAX_WORKSPACE_TOTAL_BYTES:
                skipped_files += 1
                continue
            if kind == "code" and size <= 512 and _is_symlink_like_workspace_file(candidate, relative):
                skipped_files += 1
                continue
            if kind != "code":
                manifest_files.append(relative)
                accepted_manifests += 1
            elif language in supported:
                files_by_language[language].append(relative)
            else:
                unsupported_files.append(relative)
            total_bytes += size
            accepted += 1
            seen_paths.add(relative)

    return {
        "files_by_language": {key: value for key, value in files_by_language.items() if value},
        "manifest_files": manifest_files,
        "unsupported_files": unsupported_files[:100],
        "skipped_files": skipped_files,
    }


def common_compile_database_paths(workspace: Path) -> list[str]:
    candidates = [
        "compile_commands.json",
        "build/compile_commands.json",
        "cmake-build-debug/compile_commands.json",
        "cmake-build-release/compile_commands.json",
    ]
    return [relative for relative in candidates if (workspace / relative).is_file()]


def read_workspace_attachments(
    root: Path,
    relative_paths: list[str],
    *,
    apply_limits: bool = True,
) -> list[dict[str, Any]]:
    workspace = resolve_workspace_path(str(root), apply_limits=apply_limits)
    workspace_root = workspace if workspace.is_dir() else workspace.parent
    attachments: list[dict[str, Any]] = []
    total_characters = 0
    selected_paths = list(dict.fromkeys(relative_paths))
    if apply_limits:
        selected_paths = selected_paths[:MAX_WORKSPACE_FILES]
    for relative in selected_paths:
        if workspace.is_file():
            if Path(relative).name != workspace.name or Path(relative).parent != Path("."):
                continue
            candidate = workspace
        else:
            candidate = (workspace / relative).resolve(strict=True)
        if not candidate.is_relative_to(workspace_root) or not candidate.is_file():
            continue
        data = candidate.read_bytes()
        if (
            not data
            or (apply_limits and len(data) > MAX_WORKSPACE_FILE_BYTES)
            or b"\x00" in data[:8_192]
        ):
            continue
        content = data.decode("utf-8", errors="replace")
        if attachment_kind(relative) == "code" and is_symlink_like_source_stub(relative, content):
            continue
        if apply_limits and total_characters + len(content) > MAX_WORKSPACE_TOTAL_BYTES:
            break
        attachments.append({"file_name": relative, "content": content, "mime_type": "text/plain"})
        total_characters += len(content)
    return attachments


def collect_project_sbom(workspace: Path, *, include_source_inference: bool = True) -> dict[str, Any]:
    """Collect the full-fidelity project SBOM basis shared by every scan flow.

    Both the dedicated SBOM export and the complete security scan must produce
    the same component list for the same project, so this collector always
    walks the workspace without file/count/byte limits. Manifest/lock-file
    facts form the declared layer (SBOM + vulnerability matching); source
    import inference forms a separate inferred observation layer that never
    enters the SBOM and never participates in vulnerability matching.
    """
    inventory = collect_workspace_inventory(workspace, apply_limits=False)
    manifest_files = list(inventory.get("manifest_files") or [])
    source_files = [
        relative
        for paths in (inventory.get("files_by_language") or {}).values()
        for relative in paths
    ]
    selected = [*manifest_files, *source_files] if include_source_inference else list(manifest_files)
    attachments = read_workspace_attachments(workspace, selected, apply_limits=False)
    identities = read_project_identities(attachments)
    scan = scan_dependency_attachments(attachments, max_dependencies=None, include_all_attachments=True)
    raw_dependencies = scan.get("dependencies") or []
    declared, inferred = split_dependency_layers(raw_dependencies, identities)
    scan["manifest_files"] = manifest_files
    scan["dependencies"] = declared
    scan["dependency_count"] = len(declared)
    scan["inferred_dependencies"] = inferred
    scan["inferred_count"] = len(inferred)
    scan["internal_component_count"] = len(raw_dependencies) - len(declared) - len(inferred)
    scan["project_identities"] = identities
    scan["inventory"] = {
        "manifest_files": len(manifest_files),
        "source_files": len(source_files) if include_source_inference else 0,
        "selected_files": len(selected),
        "skipped_files": int(inventory.get("skipped_files") or 0),
    }
    return scan


def _is_symlink_like_workspace_file(path: Path, relative: str) -> bool:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return is_symlink_like_source_stub(relative, content)


def compact_language_result(
    language: str,
    result: dict[str, Any],
    source_paths: list[str],
    rule_paths: list[str],
    *,
    complete_scan: bool = False,
) -> dict[str, Any]:
    findings = list(result.get("findings") or [])
    review_findings = list(result.get("review_findings") or [])
    file_preview = list(source_paths[:MAX_AGENT_FILE_PATH_PREVIEW])
    return {
        "language": language,
        "status": str(result.get("status") or "warning"),
        "mode": str(result.get("mode") or "internal-fallback"),
        "cli_status": str(result.get("cli_status") or ""),
        "file_count": len(source_paths),
        "files": file_preview,
        "file_preview_count": len(file_preview),
        "files_truncated": len(source_paths) > len(file_preview),
        "rule_files": [Path(item).name for item in rule_paths],
        "syntax_summary": deepcopy(result.get("syntax_summary") or {}),
        "parse_error_file_details": compact_parse_error_file_details(result),
        "finding_count": int(result.get("finding_count") or len(findings)),
        "findings": [
            compact_task_finding(item, index)
            for index, item in enumerate(
                findings if complete_scan else findings[:MAX_AGENT_FINDINGS_PER_LANGUAGE],
                start=1,
            )
        ],
        "review_finding_count": int(result.get("review_finding_count") or len(review_findings)),
        "review_findings": [
            compact_task_finding(item, index)
            for index, item in enumerate(
                review_findings if complete_scan else review_findings[:MAX_AGENT_FINDINGS_PER_LANGUAGE],
                start=1,
            )
        ],
        "diagnostics": [str(item) for item in (result.get("diagnostics") or [])[:30]],
        "project_overlay": deepcopy(result.get("project_overlay") or {}),
        "scan_mcp": deepcopy(result.get("_scan_mcp") or {}),
    }


def compact_parse_error_file_details(result: dict[str, Any]) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []
    for item in result.get("files") or []:
        if not isinstance(item, dict):
            continue
        syntax = item.get("syntax") if isinstance(item.get("syntax"), dict) else {}
        if not syntax.get("parse_error"):
            continue
        details.append(
            {
                "file_name": str(item.get("file_name") or syntax.get("file") or ""),
                "language": str(syntax.get("language") or item.get("language") or ""),
                "parser_mode": str(syntax.get("parser_mode") or ""),
                "parser_error_nodes": int(syntax.get("parser_error_nodes") or 0),
                "raw_parse_error": bool(syntax.get("raw_parse_error")),
                "recovered_parse_error": bool(syntax.get("recovered_parse_error")),
            }
        )
    return details


def compact_task_finding(item: dict[str, Any], index: int) -> dict[str, Any]:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
    line_value = item.get("line") or item.get("risk_line") or sink.get("line")
    try:
        line = max(1, int(line_value)) if line_value not in {None, ""} else None
    except (TypeError, ValueError):
        line = None
    raw_path = (
        item.get("file_name")
        or item.get("file")
        or sink.get("file")
        or source.get("file")
        or ""
    )
    if not raw_path and isinstance(item.get("path"), str):
        raw_path = item.get("path")
    path = str(raw_path) or None
    message = str(item.get("message") or item.get("description") or item.get("summary") or "") or None
    compact = {
        "id": str(item.get("id") or f"finding-{index}"),
        "rule_id": str(item.get("rule_id") or "") or None,
        "title": str(item.get("title") or item.get("scenario") or "代码风险"),
        "severity": str(item.get("severity") or "UNKNOWN").upper(),
        "file_name": path,
        "path": path,
        "line": line,
        "message": message,
        "description": message,
    }
    for key in ("line_start", "line_end"):
        value = item.get(key)
        try:
            parsed = max(1, int(value)) if value not in {None, ""} else None
        except (TypeError, ValueError):
            parsed = None
        if parsed is not None:
            compact[key] = parsed
    for key in (
        "scenario",
        "confidence",
        "remediation",
        "cfg",
        "dfg",
        "fixed_snippet",
        "verification_steps",
    ):
        value = _compact_task_evidence_value(item.get(key), 1_600)
        if value is not None:
            compact[key] = value
    snippet = _compact_task_evidence_value(
        item.get("vulnerable_snippet")
        or item.get("code_snippet")
        or item.get("snippet")
        or sink.get("snippet")
        or item.get("evidence"),
        4_000,
    )
    if snippet is not None:
        compact["vulnerable_snippet"] = snippet
    source_value = _compact_task_evidence_value(item.get("source"), 800)
    sink_value = _compact_task_evidence_value(item.get("sink"), 800)
    taint_path = _structured_taint_path(
        item.get("taint_path") or item.get("dataflow") or item.get("path")
    )
    if source_value is not None:
        compact["source"] = source_value
    if sink_value is not None:
        compact["sink"] = sink_value
    if taint_path is not None:
        compact["taint_path"] = taint_path
    if item.get("project_overlay_action"):
        compact["project_overlay_action"] = str(item["project_overlay_action"])
    compact["location"] = {
        "path": path,
        "line_start": compact.get("line_start") or line,
        "line_end": compact.get("line_end") or compact.get("line_start") or line,
    }
    compact["finding_fingerprint"] = task_finding_fingerprint(compact)
    return compact


def task_finding_fingerprint(finding: dict[str, Any]) -> str:
    source = finding.get("source") if isinstance(finding.get("source"), dict) else {}
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    stable_anchor = {
        "rule_id": str(finding.get("rule_id") or "").casefold(),
        "path": _normalized_finding_path(finding.get("path") or finding.get("file_name")),
        "title": " ".join(str(finding.get("title") or "").casefold().split()),
        "source_file": _normalized_finding_path(source.get("file")),
        "source_kind": str(source.get("kind") or source.get("type") or source.get("symbol") or "").casefold(),
        "source_anchor": _normalized_finding_text(
            source.get("symbol") or source.get("label") or source.get("snippet")
        ),
        "sink_file": _normalized_finding_path(sink.get("file")),
        "sink_kind": str(sink.get("kind") or sink.get("type") or sink.get("symbol") or "").casefold(),
        "sink_anchor": _normalized_finding_text(
            sink.get("symbol") or sink.get("label") or sink.get("snippet")
        ),
        "evidence_anchor": _normalized_finding_text(finding.get("vulnerable_snippet")),
    }
    if not any((stable_anchor["source_anchor"], stable_anchor["sink_anchor"], stable_anchor["evidence_anchor"])):
        stable_anchor["line_hint"] = int(finding.get("line") or 0)
    payload = json.dumps(stable_anchor, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_scan_result_diff(
    baseline_result: dict[str, Any],
    current_result: dict[str, Any],
) -> dict[str, Any]:
    baseline_findings = _result_findings_by_fingerprint(baseline_result)
    current_findings = _result_findings_by_fingerprint(current_result)
    baseline_ids = set(baseline_findings)
    current_ids = set(current_findings)
    shared = baseline_ids & current_ids
    unchanged: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    for fingerprint in sorted(shared):
        before = baseline_findings[fingerprint]
        after = current_findings[fingerprint]
        if _finding_comparison_payload(before) == _finding_comparison_payload(after):
            unchanged.append(deepcopy(after))
        else:
            changed.append({"finding_fingerprint": fingerprint, "before": deepcopy(before), "after": deepcopy(after)})
    new = [deepcopy(current_findings[value]) for value in sorted(current_ids - baseline_ids)]
    resolved = [deepcopy(baseline_findings[value]) for value in sorted(baseline_ids - current_ids)]
    return {
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "unchanged": len(unchanged),
            "changed": len(changed),
        },
        "new": new,
        "resolved": resolved,
        "unchanged": unchanged,
        "changed": changed,
    }


def task_ruleset_fingerprint(result: dict[str, Any]) -> str:
    repository_root = Path(__file__).resolve().parents[2]
    entries: list[dict[str, str]] = []
    rule_names = sorted({
        str(rule_name)
        for language_result in (result.get("language_results") or {}).values()
        for rule_name in (language_result.get("rule_files") or [])
    })
    for rule_name in rule_names:
        rule_path = repository_root / "config" / "semgrep" / Path(rule_name).name
        try:
            digest = hashlib.sha256(rule_path.read_bytes()).hexdigest()
        except OSError:
            digest = "missing"
        entries.append({"name": Path(rule_name).name, "sha256": digest})
    payload = json.dumps(entries, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def task_engine_fingerprint() -> str:
    repository_root = Path(__file__).resolve().parents[2]
    relative_paths = (
        "app/agent/task_agent.py",
        "app/mcp/code_scan.py",
        "app/mcp/code_scan_client.py",
        "app/semgrep_tool.py",
        "app/java_flow_analyzer.py",
        "app/go_semantic_analyzer.py",
        "app/agent/project_adaptive_scan.py",
    )
    digest = hashlib.sha256()
    for relative in relative_paths:
        path = repository_root / relative
        digest.update(relative.encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest()


def task_assistant_context(task: dict[str, Any], *, finding_limit: int = 100) -> dict[str, Any]:
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    findings = list(_result_findings_by_fingerprint(result).values())
    findings.sort(key=lambda item: (_severity_sort_key(item.get("severity")), str(item.get("path") or "")), reverse=True)
    return {
        "task_id": str(task.get("id") or ""),
        "baseline_task_id": str(task.get("baseline_task_id") or ""),
        "root_task_id": str(task.get("root_task_id") or task.get("id") or ""),
        "run_number": int(task.get("run_number") or 1),
        "status": str(task.get("status") or ""),
        "workspace_name": str(task.get("workspace_name") or ""),
        "objective": str(task.get("objective") or ""),
        "summary": str(result.get("summary") or ""),
        "metrics": {
            "total_files": int(result.get("total_files") or 0),
            "dependency_count": int(result.get("dependency_count") or 0),
            "total_findings": int(result.get("total_findings") or 0),
            "total_review_findings": int(result.get("total_review_findings") or 0),
        },
        "findings": deepcopy(findings[: max(1, min(int(finding_limit), 500))]),
        "finding_context_truncated": len(findings) > finding_limit,
        "result_diff": deepcopy(result.get("result_diff") or {}),
        "workspace_fingerprint": str(result.get("workspace_fingerprint") or task.get("workspace_fingerprint") or ""),
        "ruleset_fingerprint": str(result.get("ruleset_fingerprint") or task.get("ruleset_fingerprint") or ""),
        "engine_fingerprint": str(result.get("engine_fingerprint") or task.get("engine_fingerprint") or ""),
    }


def _result_findings_by_fingerprint(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for language, language_result in (result.get("language_results") or {}).items():
        for raw in language_result.get("findings") or []:
            finding = deepcopy(raw)
            finding["language"] = str(language)
            stored_fingerprint = str(finding.get("finding_fingerprint") or "")
            fingerprint = task_finding_fingerprint(finding)
            if stored_fingerprint and stored_fingerprint != fingerprint:
                finding["engine_finding_fingerprint"] = stored_fingerprint
            finding["finding_fingerprint"] = fingerprint
            output[fingerprint] = finding
    return output


def _finding_comparison_payload(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        key: finding.get(key)
        for key in (
            "severity",
            "message",
            "description",
            "source",
            "sink",
            "taint_path",
            "vulnerable_snippet",
            "remediation",
            "fixed_snippet",
            "verification_steps",
        )
    }


def _normalized_finding_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().casefold()


def _normalized_finding_text(value: Any) -> str:
    return " ".join(str(value or "").casefold().split())[:500]


def _severity_sort_key(value: Any) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(value or "").upper(), 0)


def _compact_task_evidence_value(value: Any, limit: int) -> Any | None:
    if value is None or value == "" or value == [] or value == {}:
        return None
    try:
        import json

        serialized = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        serialized = str(value)
    if len(serialized) <= limit:
        return deepcopy(value)
    return serialized[:limit]


def _structured_taint_path(value: Any) -> list[dict[str, Any]] | None:
    """Keep every scanner-supplied path node structured for SARIF/report export."""
    if not isinstance(value, list):
        return None
    nodes = [deepcopy(node) for node in value if isinstance(node, dict)]
    return nodes or None


def agent_task_report_metrics(task: dict[str, Any]) -> dict[str, Any]:
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    severities = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for language_result in (result.get("language_results") or {}).values():
        for finding in language_result.get("findings") or []:
            severity = str(finding.get("severity") or "").upper()
            if severity in severities:
                severities[severity] += 1
    vulnerability_count = int(result.get("vulnerability_count") or 0)
    vulnerability_severities = result.get("vulnerability_severities")
    if isinstance(vulnerability_severities, dict):
        for key in severities:
            severities[key] += int(vulnerability_severities.get(key) or 0)
    code_findings = int(result.get("total_findings") or 0)
    return {
        "language": "zh-Hans",
        "generated_at": now_iso(),
        "attachments": int(result.get("total_files") or 0),
        "dependencies": int(result.get("dependency_count") or 0),
        "licenses": int(result.get("license_count") or len(result.get("licenses") or [])),
        "dependency_vulnerabilities": vulnerability_count,
        "code_findings": code_findings,
        "high_risk": severities["CRITICAL"] + severities["HIGH"],
        "medium_risk": severities["MEDIUM"],
        "total_risks": vulnerability_count + code_findings,
        "severity": severities,
    }


def remember_project_submission(task: dict[str, Any]) -> None:
    from app.memory import memory_service

    project_name = str(task.get("workspace_name") or "项目")
    objective = str(task.get("objective") or "项目代码安全扫描")
    run_number = max(1, int(task.get("run_number") or 1))
    action = "重新提交扫描" if run_number > 1 or task.get("baseline_task_id") else "提交扫描"
    memory_service.remember_project_link(
        str(task.get("user_id") or "default"),
        str(task.get("session_id") or "default"),
        project_name=project_name,
        workspace_path=str(task.get("workspace_path") or ""),
        task_id=str(task.get("id") or ""),
    )
    memory_service.add_exchange(
        str(task.get("user_id") or "default"),
        objective,
        {
            "mode": "project_submission",
            "summary": (
                f"项目 {project_name} 已{action}，任务编号 {task.get('id') or '-'}，目标：{objective}。"
                "后续问题应优先关联该项目及其扫描任务。"
            ),
            "fields": {
                "项目名称": project_name,
                "项目路径": str(task.get("workspace_path") or ""),
                "任务编号": str(task.get("id") or ""),
                "任务目标": objective,
                "提交轮次": run_number,
            },
            "confidence": 1.0,
            "generated_at": now_iso(),
        },
        session_id=str(task.get("session_id") or "default"),
    )


task_agent_service = TaskAgentService(project_memory_sink=remember_project_submission)
