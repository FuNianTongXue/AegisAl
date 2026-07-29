from __future__ import annotations

import hashlib
import json
import os
import time as monotonic_time
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any, Callable, TypedDict
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
    scan_dependency_attachments,
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
from app.langgraph.report_graph import report_capability_subgraph
from app.semgrep_tool import semgrep_rule_paths_for_language, semgrep_tool
from app.source_filter import EXCLUDED_SOURCE_PARTS, is_analyzable_source_path, is_symlink_like_source_stub
from app.storage import now_iso
from app.agent.task_store import AgentTaskStore


MAX_WORKSPACE_FILES = 300
MAX_WORKSPACE_MANIFEST_FILES = 80
MAX_WORKSPACE_FILE_BYTES = 500_000
MAX_WORKSPACE_TOTAL_BYTES = 6_000_000
MAX_AGENT_DEPENDENCIES = 2_000
MAX_AGENT_FINDINGS_PER_LANGUAGE = 2_000
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
    language_results: dict[str, dict[str, Any]]
    adaptive_enabled: bool
    scan_mode: str
    project_profile: dict[str, Any]
    analysis_evidence: dict[str, Any]
    project_overlay: dict[str, Any]
    adaptation: dict[str, Any]
    result: dict[str, Any]


EventSink = Callable[[str, str, str, str, str, dict[str, Any] | None], None]
CancelCheck = Callable[[str], bool]
LanguageScanner = Callable[
    [str, list[dict[str, Any]], dict[str, Any], list[str], Callable[[], bool]],
    dict[str, Any],
]


def dependency_completion_message(
    scan: dict[str, Any],
    go_mod_files: list[str],
    requirements_files: list[str],
) -> str:
    count = scan.get("dependency_count", 0)
    if go_mod_files and requirements_files:
        return f"已优先解析 go.mod 与 requirements.txt，识别 {count} 个依赖组件。"
    if go_mod_files:
        return f"已优先解析 go.mod，识别 {count} 个依赖组件。"
    if requirements_files:
        return f"已优先解析 requirements.txt，识别 {count} 个依赖组件。"
    return f"已识别 {count} 个依赖组件。"


class TaskAgentGraph:
    def __init__(
        self,
        *,
        event_sink: EventSink | None = None,
        cancel_check: CancelCheck | None = None,
        language_scanner: LanguageScanner | None = None,
        overlay_synthesizer: OverlaySynthesizer | None = None,
        adaptive_upload: bool = False,
    ) -> None:
        self._event_sink = event_sink
        self._cancel_check = cancel_check or (lambda _task_id: False)
        self._language_scanner = language_scanner
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
            "name": "SecFlow Workspace Task Agent",
            "nodes": [
                {"id": "inspect_workspace", "label": "检查授权工作区"},
                {"id": "detect_languages", "label": "识别项目语言"},
                {"id": "plan_task", "label": "生成扫描计划"},
                {"id": "project_scan_subgraph", "label": "上传项目自适应扫描子图"},
                {"id": "scan_dependencies", "label": "依赖与组件识别 · 优先标准项目清单"},
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
                {"source": "scan_dependencies", "target": "profile_project", "label": "依赖事实"},
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
        graph.add_edge("scan_dependencies", "profile_project")
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
        manifest_files = list(state.get("manifest_files", []))
        go_mod_files = [path for path in manifest_files if Path(path).name.lower() == "go.mod"]
        requirements_files = [path for path in manifest_files if is_python_requirements_name(path)]
        priority_manifests = {*go_mod_files, *requirements_files}
        other_manifests = [path for path in manifest_files if path not in priority_manifests]
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
        paths = [*go_mod_files, *requirements_files, *other_manifests]
        for language in state.get("languages", []):
            paths.extend(state.get("files_by_language", {}).get(language, []))
        complete_scan = bool(state.get("complete_workspace_scan"))
        attachments = read_workspace_attachments(
            Path(state["workspace_path"]),
            paths,
            apply_limits=not complete_scan,
        )
        scan = scan_dependency_attachments(
            attachments,
            max_dependencies=None if complete_scan else MAX_AGENT_DEPENDENCIES,
            include_all_attachments=complete_scan,
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
                "strategy": scan["strategy"],
                "go_mod_files": go_mod_files,
                "requirements_files": requirements_files,
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
            {"language": language, "rules": [Path(item).name for item in rules]},
        )
        source_paths = state.get("files_by_language", {}).get(language, [])
        attachments = read_workspace_attachments(
            Path(state["workspace_path"]),
            [*state.get("manifest_files", []), *source_paths],
            apply_limits=not bool(state.get("complete_workspace_scan")),
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
            )
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
                "syntax_summary": compact["syntax_summary"],
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
            return state
        if evidence_count == 0:
            state["project_overlay"] = empty_project_overlay("没有需要项目级调整的证据。")
            adaptation.update(status="no_change", next_action="", termination_reason="no_discrepancy")
            state["adaptation"] = adaptation
            self._set_plan_status(state, "adaptation", "completed")
            return state

        request = build_overlay_request(
            project_profile=state.get("project_profile") or {},
            evidence=state.get("analysis_evidence") or {},
            iteration=attempts + 1,
            previous_overlay_fingerprints=list(adaptation.get("overlay_fingerprints") or []),
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
        for language in selected_languages:
            self._ensure_not_cancelled(state)
            source_paths = state.get("files_by_language", {}).get(language, [])
            attachments = read_workspace_attachments(
                Path(state["workspace_path"]),
                [*state.get("manifest_files", []), *source_paths],
                apply_limits=not bool(state.get("complete_workspace_scan")),
            )
            dependency_scan = deepcopy(state.get("dependency_scan") or {})
            dependency_scan["project_preprocessor_definitions"] = overlay_preprocessor_definitions(
                overlay,
                language,
            )
            base_rules = semgrep_rule_paths_for_language(language)
            with project_overlay_rule_file(overlay, language) as overlay_rule_path:
                rules = [*base_rules, *([overlay_rule_path] if overlay_rule_path else [])]
                raw = self._run_language_scanner(
                    language,
                    attachments,
                    dependency_scan,
                    rules,
                    lambda: self._cancel_check(state["task_id"]),
                    complete_scan=bool(state.get("complete_workspace_scan")),
                )
            adapted = apply_overlay_classification(raw, overlay)
            language_results[language] = compact_language_result(
                language,
                adapted,
                source_paths,
                rules,
                complete_scan=bool(state.get("complete_workspace_scan")),
            )
        state["language_results"] = language_results
        adaptation["iterations"] = int(adaptation.get("iterations") or 0) + 1
        adaptation["status"] = "rescanned"
        adaptation["next_action"] = ""
        state["adaptation"] = adaptation
        self._emit(
            state,
            "node.completed",
            "rescan_project_overlay",
            "completed",
            f"项目 Overlay 第 {adaptation['iterations']} 轮重扫完成，正在重新融合证据。",
            {
                "iteration": adaptation["iterations"],
                "languages": selected_languages,
                "overlay_fingerprint": overlay.get("fingerprint"),
            },
        )
        return state

    def _invoke_scan_subgraph_fallback(self, state: TaskAgentState) -> TaskAgentState:
        state = self._scan_dependencies(state)
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
        state["result"] = {
            "summary": (
                f"已按 {labels} 分派专属扫描节点，完成 {total_files} 个源文件的静态规则与 AST/CFG/DFG/污点分析，"
                f"识别 {state.get('dependency_scan', {}).get('dependency_count', 0)} 个依赖组件和 {total_findings} 条代码风险。"
            ),
            "scan_mode": state.get("scan_mode", "frozen_evaluation"),
            "languages": state.get("languages", []),
            "dependency_count": state.get("dependency_scan", {}).get("dependency_count", 0),
            "dependencies": deepcopy(state.get("dependency_scan", {}).get("dependencies", [])),
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
        }
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
    ) -> dict[str, Any]:
        if self._language_scanner is not None:
            return self._language_scanner(
                language,
                attachments,
                dependency_scan,
                rule_paths,
                cancelled,
            )
        return semgrep_tool.analyze(
            attachments,
            dependency_scan,
            [],
            rule_paths=rule_paths,
            cancelled=cancelled,
            language_hint=language,
            include_all_attachments=complete_scan,
        )


class TaskAgentService:
    def __init__(
        self,
        store: AgentTaskStore | None = None,
        *,
        max_workers: int = 2,
        graph: TaskAgentGraph | None = None,
        language_scanner: LanguageScanner | None = None,
        overlay_synthesizer: OverlaySynthesizer | None = None,
        adaptive_upload: bool = True,
    ) -> None:
        self.store = store or AgentTaskStore()
        self._max_workers = max_workers
        self._executor: ThreadPoolExecutor | None = None
        self._cancel_events: dict[str, Event] = {}
        self._futures: dict[str, Future[Any]] = {}
        self._lock = RLock()
        self.graph = graph or TaskAgentGraph(
            event_sink=self._record_event,
            cancel_check=self.is_cancelled,
            language_scanner=language_scanner,
            overlay_synthesizer=overlay_synthesizer,
            adaptive_upload=adaptive_upload,
        )
        self.store.recover_interrupted()
        self.start()

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
            "error": "",
            "archived": False,
            "archived_at": None,
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        self.store.create(task)
        self._record_event(task_id, "task.created", "queued", "queued", "任务已创建，等待执行。", None)
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

    def list(
        self,
        user_id: str,
        limit: int = 30,
        *,
        archived: bool = False,
    ) -> list[dict[str, Any]]:
        return self.store.list(user_id, limit, archived=archived)

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
        if task.get("status") in {"completed", "failed", "cancelled"}:
            return task
        with self._lock:
            event = self._cancel_events.setdefault(task_id, Event())
            event.set()
        self.store.update(task_id, status="cancelling")
        self._record_event(task_id, "task.cancelling", "cancel", "warning", "正在停止任务。", None)
        return self.store.get(task_id)

    def decide_report(self, task_id: str, *, generate: bool, report_store: Any) -> dict[str, Any]:
        task = self.store.get(task_id)
        if not agent_task_report_ready(task):
            raise ValueError("扫描尚未完成，暂时不能处理报告选择。")

        decision = str(task.get("report_decision") or "pending")
        if decision == "generated" and isinstance(task.get("report"), dict):
            metadata = task["report"].get("metadata") if isinstance(task["report"].get("metadata"), dict) else {}
            mcp_audit = metadata.get("report_mcp") if isinstance(metadata.get("report_mcp"), dict) else {}
            is_current_report = (
                int(metadata.get("report_schema_version") or 0) >= 4
                and str(metadata.get("scan_json_schema") or "") == "secflow.scan-results/v1"
                and bool(metadata.get("scan_json_sha256"))
                and str(mcp_audit.get("status") or "") == "completed"
            )
            if is_current_report or not generate:
                return task
        if decision == "declined" and not generate:
            return task

        session_id = f"agent-task:{task_id}"
        outcome = report_capability_subgraph.start(
            {
                "action": "generate",
                "question": str(task.get("objective") or "生成扫描报告"),
                "user_id": str(task.get("user_id") or "default"),
                "session_id": session_id,
                "response_language": "zh-Hans",
                "source_kind": "agent_task",
                "scan_data": {"task": task, "report_metrics": agent_task_report_metrics(task)},
                "report_store_root": str(report_store.root),
            }
        )
        interrupt_envelope = outcome.get("interrupt") or {}
        if not interrupt_envelope:
            raise ValueError(outcome.get("error") or "未能建立报告生成确认。")
        outcome = report_capability_subgraph.resume(
            str(outcome.get("thread_id") or ""),
            decision="confirm" if generate else "cancel",
            user_id=str(task.get("user_id") or "default"),
            session_id=session_id,
        )
        if not generate:
            self.store.update(
                task_id,
                report_decision="declined",
                report=None,
                report_interrupt=None,
                report_thread_id=None,
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
            raise ValueError(outcome.get("error") or "报告生成失败。")
        self.store.update(
            task_id,
            report_decision="generated",
            report=report,
            report_interrupt=outcome.get("interrupt"),
            report_thread_id=outcome.get("thread_id"),
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

    def decide_report_download(self, task_id: str, *, confirm: bool, report_format: str) -> dict[str, Any]:
        task = self.store.get(task_id)
        thread_id = str(task.get("report_thread_id") or "")
        envelope = task.get("report_interrupt") if isinstance(task.get("report_interrupt"), dict) else {}
        if not thread_id or not envelope:
            raise ValueError("当前没有等待确认的报告下载操作。")
        try:
            outcome = report_capability_subgraph.resume(
                thread_id,
                decision="confirm" if confirm else "cancel",
                user_id=str(task.get("user_id") or "default"),
                session_id=f"agent-task:{task_id}",
                report_format=report_format,
            )
        except KeyError:
            if not confirm or not isinstance(task.get("report"), dict):
                outcome = {"artifacts": []}
            else:
                restarted = report_capability_subgraph.start(
                    {
                        "action": "download_report",
                        "report_ids": [str(task["report"].get("id") or "")],
                        "formats": [report_format],
                        "user_id": str(task.get("user_id") or "default"),
                        "session_id": f"agent-task:{task_id}",
                    }
                )
                outcome = report_capability_subgraph.resume(
                    str(restarted.get("thread_id") or ""),
                    decision="confirm",
                    user_id=str(task.get("user_id") or "default"),
                    session_id=f"agent-task:{task_id}",
                    report_format=report_format,
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
                "format": report_format,
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
                error="",
            )

        self.store.mutate(task_id, reset)
        self._record_event(task_id, "task.resumed", "queued", "queued", "任务已重新排队。", None)
        self._submit(task_id)
        return self.store.get(task_id)

    def is_cancelled(self, task_id: str) -> bool:
        with self._lock:
            return self._cancel_events.get(task_id, Event()).is_set()

    def shutdown(self, *, wait: bool = False) -> None:
        with self._lock:
            for event in self._cancel_events.values():
                event.set()
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=wait, cancel_futures=True)

    def start(self) -> None:
        with self._lock:
            if self._executor is None:
                self._executor = ThreadPoolExecutor(
                    max_workers=self._max_workers,
                    thread_name_prefix="secflow-task-agent",
                )

    def _submit(self, task_id: str) -> None:
        self.start()
        with self._lock:
            self._cancel_events[task_id] = Event()
            if self._executor is None:  # pragma: no cover - start() guarantees an executor.
                raise RuntimeError("任务执行器未启动")
            self._futures[task_id] = self._executor.submit(self._run, task_id)

    def _run(self, task_id: str) -> None:
        task = self.store.get(task_id)
        self.store.update(task_id, status="running", error="")
        self._record_event(task_id, "task.started", "inspect_workspace", "running", "任务开始执行。", None)
        try:
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
            self.store.update(
                task_id,
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
        except TaskCancelled as exc:
            self.store.update(task_id, status="cancelled", report_ready=False, error=str(exc))
            self._record_event(task_id, "task.cancelled", "cancel", "warning", str(exc), None)
        except Exception as exc:  # noqa: BLE001 - task failure must be persisted for the UI.
            message = sanitize_public_text(str(exc)) or "任务执行失败。"
            self.store.update(task_id, status="failed", report_ready=False, error=message)
            self._record_event(task_id, "task.failed", "failed", "failed", message, None)
        finally:
            with self._lock:
                self._futures.pop(task_id, None)

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
            self.store.update(task_id, languages=list(data.get("languages") or []))
        elif event_type == "plan.updated" and data is not None:
            self.store.update(task_id, plan=list(data.get("plan") or []))
        elif event_type in {"node.started", "node.completed", "verification.completed"}:
            plan_status = "running" if event_type == "node.started" else "completed"

            def update_plan(task: dict[str, Any]) -> None:
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
    return {
        "language": language,
        "status": str(result.get("status") or "warning"),
        "mode": str(result.get("mode") or "internal-fallback"),
        "file_count": len(source_paths),
        "files": list(source_paths) if complete_scan else source_paths[:300],
        "rule_files": [Path(item).name for item in rule_paths],
        "syntax_summary": deepcopy(result.get("syntax_summary") or {}),
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
    }


def compact_task_finding(item: dict[str, Any], index: int) -> dict[str, Any]:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    sink = item.get("sink") if isinstance(item.get("sink"), dict) else {}
    line_value = item.get("line") or item.get("risk_line") or sink.get("line")
    try:
        line = max(1, int(line_value)) if line_value not in {None, ""} else None
    except (TypeError, ValueError):
        line = None
    path = str(
        item.get("path")
        or item.get("file_name")
        or item.get("file")
        or sink.get("file")
        or source.get("file")
        or ""
    ) or None
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
    for key in ("confidence", "remediation", "cfg", "dfg", "fixed_snippet", "verification_steps"):
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
    taint_path = _compact_task_evidence_value(
        item.get("taint_path") or item.get("dataflow") or item.get("path"),
        1_600,
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
        "sink_file": _normalized_finding_path(sink.get("file")),
        "sink_kind": str(sink.get("kind") or sink.get("type") or sink.get("symbol") or "").casefold(),
    }
    if not any((stable_anchor["source_kind"], stable_anchor["sink_kind"])):
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
            fingerprint = str(finding.get("finding_fingerprint") or task_finding_fingerprint(finding))
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


def agent_task_report_metrics(task: dict[str, Any]) -> dict[str, Any]:
    result = task.get("result") if isinstance(task.get("result"), dict) else {}
    severities = {key: 0 for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    for language_result in (result.get("language_results") or {}).values():
        for finding in language_result.get("findings") or []:
            severity = str(finding.get("severity") or "").upper()
            if severity in severities:
                severities[severity] += 1
    return {
        "language": "zh-Hans",
        "generated_at": now_iso(),
        "attachments": int(result.get("total_files") or 0),
        "dependencies": int(result.get("dependency_count") or 0),
        "dependency_vulnerabilities": 0,
        "code_findings": int(result.get("total_findings") or 0),
        "high_risk": severities["CRITICAL"] + severities["HIGH"],
        "medium_risk": severities["MEDIUM"],
        "total_risks": int(result.get("total_findings") or 0),
        "severity": severities,
    }


task_agent_service = TaskAgentService()
