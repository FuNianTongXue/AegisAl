from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

try:
    from tree_sitter import Language, Node, Parser
    import tree_sitter_java
except Exception:  # noqa: BLE001
    Language = None
    Node = Any
    Parser = None
    tree_sitter_java = None


ENTRYPOINT_ANNOTATIONS = {
    "RequestMapping",
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "PatchMapping",
    "DeleteMapping",
    "MessageMapping",
}

SOURCE_PARAMETER_ANNOTATIONS = {
    "RequestParam",
    "PathVariable",
    "RequestBody",
    "RequestHeader",
    "CookieValue",
    "ModelAttribute",
}

CONTROL_TYPES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_expression",
    "switch_statement",
    "try_statement",
    "catch_clause",
    "synchronized_statement",
}

SCENARIOS: dict[str, dict[str, Any]] = {
    "command_execution": {
        "title": "跨方法外部输入进入命令执行接口",
        "severity": "HIGH",
        "cwes": ["CWE-78"],
    },
    "sql_injection": {
        "title": "跨方法外部输入进入 SQL 执行接口",
        "severity": "HIGH",
        "cwes": ["CWE-89"],
    },
    "path_traversal": {
        "title": "跨方法外部输入进入文件系统路径",
        "severity": "HIGH",
        "cwes": ["CWE-22"],
    },
    "cross_site_scripting": {
        "title": "跨方法外部输入未经编码写入 HTTP 响应",
        "severity": "HIGH",
        "cwes": ["CWE-79"],
    },
    "ldap_injection": {
        "title": "跨方法外部输入进入 LDAP 查询过滤器",
        "severity": "HIGH",
        "cwes": ["CWE-90"],
    },
    "xpath_injection": {
        "title": "跨方法外部输入进入 XPath 表达式",
        "severity": "HIGH",
        "cwes": ["CWE-643"],
    },
    "ssrf": {
        "title": "跨方法外部输入控制服务端请求目标",
        "severity": "HIGH",
        "cwes": ["CWE-918"],
    },
    "log_injection_lookup": {
        "title": "跨方法外部输入未经规范化写入日志",
        "severity": "MEDIUM",
        "cwes": ["CWE-117"],
    },
    "deserialization": {
        "title": "跨方法不可信数据进入反序列化接口",
        "severity": "HIGH",
        "cwes": ["CWE-502"],
    },
    "response_splitting": {
        "title": "跨方法外部输入进入 HTTP 响应头",
        "severity": "HIGH",
        "cwes": ["CWE-113"],
    },
    "trust_boundary": {
        "title": "跨方法外部输入未经验证写入信任域",
        "severity": "HIGH",
        "cwes": ["CWE-501"],
    },
}


@dataclass(frozen=True)
class TraceStep:
    kind: str
    file: str
    line: int
    label: str
    snippet: str
    method: str = ""

    def public(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "file": self.file,
            "line": self.line,
            "label": self.label,
            "snippet": self.snippet,
            "method": self.method,
        }


@dataclass(frozen=True)
class FlowItem:
    origin_kind: str
    param_index: int = -1
    source_key: str = ""
    steps: tuple[TraceStep, ...] = ()
    sanitized_for: frozenset[str] = frozenset()

    def append(self, *steps: TraceStep, sanitized_for: Iterable[str] = ()) -> "FlowItem":
        return FlowItem(
            origin_kind=self.origin_kind,
            param_index=self.param_index,
            source_key=self.source_key,
            steps=_compact_steps((*self.steps, *steps)),
            sanitized_for=self.sanitized_for | frozenset(sanitized_for),
        )


@dataclass(frozen=True)
class Flow:
    items: tuple[FlowItem, ...] = ()

    @staticmethod
    def merge(*flows: "Flow") -> "Flow":
        items: list[FlowItem] = []
        seen: set[tuple[Any, ...]] = set()
        for flow in flows:
            for item in flow.items:
                last = item.steps[-1] if item.steps else None
                key = (
                    item.origin_kind,
                    item.param_index,
                    item.source_key,
                    tuple(sorted(item.sanitized_for)),
                    last.file if last else "",
                    last.line if last else 0,
                    last.label if last else "",
                )
                if key in seen:
                    continue
                seen.add(key)
                items.append(item)
        return Flow(tuple(items))

    def append(self, *steps: TraceStep, sanitized_for: Iterable[str] = ()) -> "Flow":
        return Flow(tuple(item.append(*steps, sanitized_for=sanitized_for) for item in self.items))


@dataclass(frozen=True)
class Parameter:
    name: str
    type_name: str
    annotations: frozenset[str]
    line: int
    snippet: str


@dataclass
class JavaMethod:
    key: str
    file_name: str
    class_name: str
    name: str
    parameters: tuple[Parameter, ...]
    annotations: frozenset[str]
    class_annotations: frozenset[str]
    modifiers: str
    body: Node
    source: bytes
    lines: tuple[str, ...]
    field_types: dict[str, str]

    @property
    def arity(self) -> int:
        return len(self.parameters)

    @property
    def display(self) -> str:
        return f"{self.class_name}.{self.name}/{self.arity}"


@dataclass(frozen=True)
class SinkTemplate:
    param_index: int
    scenario: str
    path_after_parameter: tuple[TraceStep, ...]
    sink: TraceStep
    unique_resolution: bool = True


@dataclass(frozen=True)
class MethodSummary:
    returns: tuple[FlowItem, ...] = ()
    sinks: tuple[SinkTemplate, ...] = ()


@dataclass(frozen=True)
class FlowCandidate:
    scenario: str
    path: tuple[TraceStep, ...]
    method_key: str
    unique_resolution: bool


@dataclass
class ExecutionState:
    variables: dict[str, Flow] = field(default_factory=dict)
    types: dict[str, str] = field(default_factory=dict)
    constants: dict[str, Any] = field(default_factory=dict)

    def clone(self) -> "ExecutionState":
        return ExecutionState(dict(self.variables), dict(self.types), dict(self.constants))

    @staticmethod
    def merge(*states: "ExecutionState") -> "ExecutionState":
        merged = ExecutionState()
        names = {name for state in states for name in state.variables}
        for name in names:
            merged.variables[name] = Flow.merge(*(state.variables.get(name, Flow()) for state in states))
        for state in states:
            merged.types.update(state.types)
        if states:
            for name, value in states[0].constants.items():
                if all(name in state.constants and state.constants[name] == value for state in states[1:]):
                    merged.constants[name] = value
        return merged


@dataclass
class MethodRun:
    return_flow: Flow = field(default_factory=Flow)
    sink_templates: list[SinkTemplate] = field(default_factory=list)
    candidates: list[FlowCandidate] = field(default_factory=list)
    call_edges: set[tuple[str, str]] = field(default_factory=set)


class JavaFlowAnalyzer:
    def __init__(
        self,
        code_files: list[dict[str, str]],
        *,
        complete_analysis: bool = False,
        cancelled: Callable[[], bool] | None = None,
    ) -> None:
        self.code_files = [item for item in code_files if str(item.get("file_name") or "").lower().endswith(".java")]
        self.complete_analysis = complete_analysis
        self.cancelled = cancelled or (lambda: False)
        self.methods: dict[str, JavaMethod] = {}
        self.by_class_name_arity: dict[tuple[str, str, int], list[str]] = {}
        self.by_name_arity: dict[tuple[str, int], list[str]] = {}
        self.diagnostics: list[str] = []
        self.parse_error_files = 0
        self.call_edges: set[tuple[str, str]] = set()
        self.finance_analysis: dict[str, Any] = {}
        self.started_at = 0.0
        self.max_seconds = (
            None
            if complete_analysis
            else _env_float("SECFLOW_JAVA_FLOW_MAX_SECONDS", 18.0, minimum=2.0, maximum=300.0)
        )

    def analyze(self) -> dict[str, Any]:
        self.started_at = time.monotonic()
        if Parser is None or Language is None or tree_sitter_java is None:
            return {
                "status": "unavailable",
                "findings": [],
                "finding_count": 0,
                "diagnostics": ["跨方法 Java 分析运行库不可用，已跳过该分析阶段。"],
            }
        self._parse_project()
        if self.cancelled():
            return self._cancelled_result(0)
        if self._timed_out():
            return self._timeout_result(0)
        if not self.methods:
            return {
                "status": "warning",
                "findings": [],
                "finding_count": 0,
                "diagnostics": self.diagnostics or ["未解析到 Java 方法。"],
                "method_count": 0,
                "call_edge_count": 0,
            }
        max_methods = (
            None
            if self.complete_analysis
            else _env_int("SECFLOW_JAVA_FLOW_MAX_METHODS", 50000, minimum=100, maximum=250000)
        )
        if max_methods is not None and len(self.methods) > max_methods:
            self.diagnostics.append(f"项目包含 {len(self.methods)} 个方法，超过跨方法分析上限 {max_methods}。")
            return {
                "status": "limit_exceeded",
                "findings": [],
                "finding_count": 0,
                "diagnostics": self.diagnostics,
                "method_count": len(self.methods),
                "call_edge_count": 0,
            }

        try:
            from app.java_finance_analyzer import analyze_java_finance

            self.finance_analysis = analyze_java_finance(
                self.methods,
                self.by_class_name_arity,
                self.code_files,
            )
        except Exception as exc:  # noqa: BLE001
            self.diagnostics.append(f"原生资金 CFG/DFG 分析失败，已保留其它分析结果：{exc}")

        summaries = {key: MethodSummary() for key in self.methods}
        max_iterations = (
            None
            if self.complete_analysis
            else _env_int("SECFLOW_JAVA_FLOW_MAX_ITERATIONS", 6, minimum=2, maximum=12)
        )
        completed_iterations = 0
        while max_iterations is None or completed_iterations < max_iterations:
            updated: dict[str, MethodSummary] = {}
            changed = False
            for key, method in self.methods.items():
                if self.cancelled():
                    return self._cancelled_result(completed_iterations)
                if self._timed_out():
                    self.diagnostics.append(self._timeout_message("已降级保留其它本地扫描结果。"))
                    return self._timeout_result(completed_iterations)
                summary, _, edges = self._run_method(method, summaries, collect=False)
                updated[key] = summary
                self.call_edges.update(edges)
                if self.complete_analysis:
                    changed = changed or _summary_semantic_signature(summary) != _summary_semantic_signature(summaries[key])
                else:
                    changed = changed or summary != summaries[key]
            summaries = updated
            completed_iterations += 1
            if not changed:
                break

        candidates: list[FlowCandidate] = []
        for method in self.methods.values():
            if self.cancelled():
                return self._cancelled_result(completed_iterations)
            if self._timed_out():
                self.diagnostics.append(self._timeout_message("已返回超时前的基础信息。"))
                return self._timeout_result(completed_iterations)
            _, method_candidates, edges = self._run_method(method, summaries, collect=True)
            candidates.extend(method_candidates)
            self.call_edges.update(edges)

        findings = [*self._public_findings(candidates), *(self.finance_analysis.get("findings") or [])]
        max_findings = _env_int("SECFLOW_STATIC_MAX_FINDINGS", 500, minimum=1, maximum=5000)
        findings = findings[:max_findings]
        return {
            "status": "completed",
            "findings": findings,
            "finding_count": len(findings),
            "diagnostics": self.diagnostics,
            "method_count": len(self.methods),
            "call_edge_count": len(self.call_edges),
            "iterations": completed_iterations,
            "parse_error_files": self.parse_error_files,
            "finance_analysis": {
                key: value
                for key, value in self.finance_analysis.items()
                if key not in {"findings", "finding_count"}
            },
            "cfg_node_count": int(self.finance_analysis.get("cfg_node_count") or 0),
            "cfg_edge_count": int(self.finance_analysis.get("cfg_edge_count") or 0),
            "dfg_edge_count": int(self.finance_analysis.get("dfg_edge_count") or 0),
        }

    def _parse_project(self) -> None:
        parser = Parser(Language(tree_sitter_java.language()))
        for code_file in self.code_files:
            if self.cancelled():
                self.diagnostics.append("跨方法 Java 分析已由用户停止。")
                break
            if self._timed_out():
                self.diagnostics.append(self._timeout_message("解析 Java 文件阶段已停止。"))
                break
            file_name = str(code_file.get("file_name") or "")
            source = str(code_file.get("content") or "").encode("utf-8", errors="replace")
            tree = parser.parse(source)
            if tree.root_node.has_error:
                self.parse_error_files += 1
            lines = tuple(source.decode("utf-8", errors="replace").splitlines())
            for class_node in _descendants_of_types(
                tree.root_node,
                {"class_declaration", "interface_declaration", "enum_declaration", "record_declaration"},
            ):
                class_name = _node_text(class_node.child_by_field_name("name"), source)
                if not class_name:
                    continue
                class_annotations = frozenset(_annotations(class_node, source))
                fields = _class_field_types(class_node, source)
                body = class_node.child_by_field_name("body")
                if body is None:
                    continue
                for method_node in body.named_children:
                    if method_node.type not in {"method_declaration", "constructor_declaration"}:
                        continue
                    method = _java_method(
                        method_node,
                        file_name=file_name,
                        class_name=class_name,
                        class_annotations=class_annotations,
                        field_types=fields,
                        source=source,
                        lines=lines,
                    )
                    if method is None:
                        continue
                    key = method.key
                    if key in self.methods:
                        key = f"{key}@{method_node.start_point.row + 1}"
                        method.key = key
                    self.methods[key] = method
        for key, method in self.methods.items():
            self.by_class_name_arity.setdefault((method.class_name, method.name, method.arity), []).append(key)
            self.by_name_arity.setdefault((method.name, method.arity), []).append(key)

    def _timed_out(self) -> bool:
        return bool(
            self.max_seconds is not None
            and self.started_at
            and time.monotonic() - self.started_at >= self.max_seconds
        )

    def _timeout_message(self, suffix: str) -> str:
        limit = f"{self.max_seconds:.1f}s" if self.max_seconds is not None else "配置的时间上限"
        return f"跨方法 Java 分析超过 {limit}，{suffix}"

    def _timeout_result(self, completed_iterations: int) -> dict[str, Any]:
        finance_findings = list(self.finance_analysis.get("findings") or [])
        return {
            "status": "timeout",
            "findings": finance_findings,
            "finding_count": len(finance_findings),
            "diagnostics": self.diagnostics
            or [self._timeout_message("已降级保留其它本地扫描结果。")],
            "method_count": len(self.methods),
            "call_edge_count": len(self.call_edges),
            "iterations": completed_iterations,
            "parse_error_files": self.parse_error_files,
            "finance_analysis": {
                key: value
                for key, value in self.finance_analysis.items()
                if key not in {"findings", "finding_count"}
            },
            "cfg_node_count": int(self.finance_analysis.get("cfg_node_count") or 0),
            "cfg_edge_count": int(self.finance_analysis.get("cfg_edge_count") or 0),
            "dfg_edge_count": int(self.finance_analysis.get("dfg_edge_count") or 0),
        }

    def _cancelled_result(self, completed_iterations: int) -> dict[str, Any]:
        finance_findings = list(self.finance_analysis.get("findings") or [])
        diagnostics = list(self.diagnostics)
        if not any("用户停止" in item for item in diagnostics):
            diagnostics.append("跨方法 Java 分析已由用户停止。")
        return {
            "status": "cancelled",
            "findings": finance_findings,
            "finding_count": len(finance_findings),
            "diagnostics": diagnostics,
            "method_count": len(self.methods),
            "call_edge_count": len(self.call_edges),
            "iterations": completed_iterations,
            "parse_error_files": self.parse_error_files,
            "cfg_node_count": int(self.finance_analysis.get("cfg_node_count") or 0),
            "cfg_edge_count": int(self.finance_analysis.get("cfg_edge_count") or 0),
            "dfg_edge_count": int(self.finance_analysis.get("dfg_edge_count") or 0),
        }

    def _run_method(
        self,
        method: JavaMethod,
        summaries: dict[str, MethodSummary],
        *,
        collect: bool,
    ) -> tuple[MethodSummary, list[FlowCandidate], set[tuple[str, str]]]:
        state = ExecutionState(types=dict(method.field_types))
        for index, parameter in enumerate(method.parameters):
            step = TraceStep(
                kind="source" if _parameter_is_source(method, parameter) else "parameter",
                file=method.file_name,
                line=parameter.line,
                label="外部入口参数 source" if _parameter_is_source(method, parameter) else "方法参数",
                snippet=parameter.snippet,
                method=method.display,
            )
            if _parameter_is_source(method, parameter):
                source_key = f"{method.key}:{index}:{parameter.line}"
                state.variables[parameter.name] = Flow(
                    (FlowItem("source", source_key=source_key, steps=(step,)),)
                )
            else:
                state.variables[parameter.name] = Flow(
                    (FlowItem("parameter", param_index=index, steps=(step,)),)
                )
            state.types[parameter.name] = parameter.type_name

        run = MethodRun()
        self._process_node(method.body, method, state, summaries, run, controls=(), collect=collect)
        summary = MethodSummary(
            returns=_compact_flow_items(run.return_flow.items),
            sinks=_compact_sink_templates(run.sink_templates),
        )
        return summary, run.candidates, run.call_edges

    def _process_node(
        self,
        node: Node,
        method: JavaMethod,
        state: ExecutionState,
        summaries: dict[str, MethodSummary],
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
    ) -> None:
        if node.type in {"block", "class_body"}:
            for child in node.named_children:
                self._process_node(child, method, state, summaries, run, controls=controls, collect=collect)
            return

        if node.type == "local_variable_declaration":
            type_name = _node_text(node.child_by_field_name("type"), method.source)
            for declarator in [child for child in node.named_children if child.type == "variable_declarator"]:
                name = _node_text(declarator.child_by_field_name("name"), method.source)
                value = declarator.child_by_field_name("value")
                if name:
                    state.types[name] = type_name
                    state.variables[name] = self._eval_expr(
                        value,
                        method,
                        state,
                        summaries,
                        run,
                        controls=controls,
                        collect=collect,
                    )
                    _update_constant(state, name, value, method.source)
            return

        if node.type == "expression_statement":
            for child in node.named_children:
                if child.type == "assignment_expression":
                    left = child.child_by_field_name("left")
                    right = child.child_by_field_name("right")
                    name = _assignment_name(left, method.source)
                    flow = self._eval_expr(
                        right,
                        method,
                        state,
                        summaries,
                        run,
                        controls=controls,
                        collect=collect,
                    )
                    if name:
                        step = _step_from_node("dataflow_step", child, method, f"赋值到 {name}")
                        state.variables[name] = flow.append(step)
                        _update_constant(state, name, right, method.source)
                else:
                    self._eval_expr(
                        child,
                        method,
                        state,
                        summaries,
                        run,
                        controls=controls,
                        collect=collect,
                    )
            return

        if node.type == "return_statement":
            expressions = [child for child in node.named_children if child.type != "return"]
            for expression in expressions:
                flow = self._eval_expr(
                    expression,
                    method,
                    state,
                    summaries,
                    run,
                    controls=controls,
                    collect=collect,
                )
                step = _step_from_node("return", node, method, "方法返回值")
                run.return_flow = Flow.merge(run.return_flow, flow.append(*controls, step))
            return

        if node.type == "if_statement":
            condition = node.child_by_field_name("condition")
            if condition is not None:
                self._eval_expr(condition, method, state, summaries, run, controls=controls, collect=collect)
            control = _step_from_node("cfg_condition", condition or node, method, "if 控制条件")
            before = state.clone()
            condition_value = _constant_value(condition, method.source, before.constants)
            consequence_state = before.clone()
            consequence = node.child_by_field_name("consequence")
            if consequence is not None and condition_value is not False:
                self._process_node(
                    consequence,
                    method,
                    consequence_state,
                    summaries,
                    run,
                    controls=(*controls, control),
                    collect=collect,
                )
            alternative_state = before.clone()
            alternative = node.child_by_field_name("alternative")
            if alternative is not None and condition_value is not True:
                self._process_node(
                    alternative,
                    method,
                    alternative_state,
                    summaries,
                    run,
                    controls=(*controls, control),
                    collect=collect,
                )
            if condition_value is True:
                merged = consequence_state
            elif condition_value is False:
                merged = alternative_state if alternative is not None else before
            elif alternative is not None:
                merged = ExecutionState.merge(consequence_state, alternative_state)
            else:
                merged = ExecutionState.merge(before, consequence_state)
            state.variables = merged.variables
            state.types = merged.types
            return

        if node.type in CONTROL_TYPES:
            control = _step_from_node("cfg_condition", node, method, _control_label(node.type))
            before = state.clone()
            branch = state.clone()
            for child in node.named_children:
                if child.type in {"parenthesized_expression", "condition"}:
                    self._eval_expr(child, method, branch, summaries, run, controls=controls, collect=collect)
                else:
                    self._process_node(
                        child,
                        method,
                        branch,
                        summaries,
                        run,
                        controls=(*controls, control),
                        collect=collect,
                    )
            merged = ExecutionState.merge(before, branch)
            state.variables = merged.variables
            state.types = merged.types
            return

        if node.type == "enhanced_for_statement":
            value = node.child_by_field_name("value")
            name_node = node.child_by_field_name("name")
            name = _node_text(name_node, method.source)
            branch = state.clone()
            if name:
                branch.variables[name] = self._eval_expr(
                    value,
                    method,
                    state,
                    summaries,
                    run,
                    controls=controls,
                    collect=collect,
                )
                branch.types[name] = _node_text(node.child_by_field_name("type"), method.source)
                branch.constants.pop(name, None)
            body = node.child_by_field_name("body")
            control = _step_from_node("cfg_condition", node, method, "for 控制条件")
            if body is not None:
                self._process_node(
                    body,
                    method,
                    branch,
                    summaries,
                    run,
                    controls=(*controls, control),
                    collect=collect,
                )
            merged = ExecutionState.merge(state, branch)
            state.variables = merged.variables
            state.types = merged.types
            return

        for child in node.named_children:
            if child.type in {
                "method_invocation",
                "object_creation_expression",
                "assignment_expression",
                "update_expression",
            }:
                self._eval_expr(child, method, state, summaries, run, controls=controls, collect=collect)
            elif child.type not in {"method_declaration", "class_declaration", "lambda_expression"}:
                self._process_node(child, method, state, summaries, run, controls=controls, collect=collect)

    def _eval_expr(
        self,
        node: Node | None,
        method: JavaMethod,
        state: ExecutionState,
        summaries: dict[str, MethodSummary],
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
    ) -> Flow:
        if node is None:
            return Flow()
        if node.type == "identifier":
            return state.variables.get(_node_text(node, method.source), Flow())
        if node.type == "this":
            return state.variables.get("this", Flow())
        if node.type == "assignment_expression":
            right = node.child_by_field_name("right")
            flow = self._eval_expr(right, method, state, summaries, run, controls=controls, collect=collect)
            name = _assignment_name(node.child_by_field_name("left"), method.source)
            if name:
                state.variables[name] = flow.append(_step_from_node("dataflow_step", node, method, f"赋值到 {name}"))
                _update_constant(state, name, right, method.source)
            return flow
        if node.type == "method_invocation":
            return self._eval_method_call(node, method, state, summaries, run, controls=controls, collect=collect)
        if node.type == "object_creation_expression":
            return self._eval_constructor(node, method, state, summaries, run, controls=controls, collect=collect)
        if node.type == "ternary_expression":
            condition = node.child_by_field_name("condition")
            self._eval_expr(
                condition,
                method,
                state,
                summaries,
                run,
                controls=controls,
                collect=collect,
            )
            condition_value = _constant_value(condition, method.source, state.constants)
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            selected: list[Flow] = []
            if condition_value is not False:
                selected.append(
                    self._eval_expr(
                        consequence,
                        method,
                        state,
                        summaries,
                        run,
                        controls=controls,
                        collect=collect,
                    )
                )
            if condition_value is not True:
                selected.append(
                    self._eval_expr(
                        alternative,
                        method,
                        state,
                        summaries,
                        run,
                        controls=controls,
                        collect=collect,
                    )
                )
            merged = Flow.merge(*selected)
            if merged.items:
                return merged.append(_step_from_node("cfg_condition", condition or node, method, "三元条件表达式"))
            return merged
        flows = [
            self._eval_expr(child, method, state, summaries, run, controls=controls, collect=collect)
            for child in node.named_children
        ]
        merged = Flow.merge(*flows)
        if merged.items and node.type in {
            "binary_expression",
            "string_template_expression",
            "cast_expression",
            "ternary_expression",
            "array_access",
            "field_access",
        }:
            return merged.append(_step_from_node("dataflow_step", node, method, "表达式传播"))
        return merged

    def _eval_method_call(
        self,
        node: Node,
        method: JavaMethod,
        state: ExecutionState,
        summaries: dict[str, MethodSummary],
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
    ) -> Flow:
        name = _node_text(node.child_by_field_name("name"), method.source)
        object_node = node.child_by_field_name("object")
        object_text = _node_text(object_node, method.source)
        object_flow = self._eval_expr(
            object_node,
            method,
            state,
            summaries,
            run,
            controls=controls,
            collect=collect,
        )
        arguments_node = node.child_by_field_name("arguments")
        argument_nodes = tuple(arguments_node.named_children) if arguments_node is not None else ()
        argument_flows = tuple(
            self._eval_expr(arg, method, state, summaries, run, controls=controls, collect=collect)
            for arg in argument_nodes
        )

        source_label = _source_call_label(name, object_text, state)
        if source_label:
            step = _step_from_node("source", node, method, source_label)
            return Flow((FlowItem("source", source_key=f"{method.key}:{step.line}:{name}", steps=(step,)),))

        sanitized_for = _sanitizer_scenarios(name, object_text)
        merged_arguments = Flow.merge(object_flow, *argument_flows)
        if sanitized_for:
            return merged_arguments.append(
                _step_from_node("sanitizer", node, method, f"净化函数 {name}"),
                sanitized_for=sanitized_for,
            )

        scenario = _sink_scenario(name, object_text, state)
        if scenario:
            sink_flow = _sink_argument_flow(scenario, object_flow, argument_flows)
            self._emit_sink(
                sink_flow,
                scenario,
                _step_from_node("sink", node, method, _sink_label(scenario)),
                method,
                run,
                controls=controls,
                collect=collect,
                unique_resolution=True,
            )

        callee, unique = self._resolve_call(method, name, object_text, len(argument_nodes), state)
        if callee is None:
            return merged_arguments.append(_step_from_node("dataflow_step", node, method, f"调用 {name}"))

        run.call_edges.add((method.key, callee.key))
        summary = summaries.get(callee.key, MethodSummary())
        call_step = _step_from_node("call", node, method, f"调用 {callee.display}")
        self._apply_callee_sinks(
            summary,
            argument_flows,
            call_step,
            method,
            run,
            controls=controls,
            collect=collect,
            unique_resolution=unique,
        )
        return self._callee_return_flow(summary, argument_flows, call_step)

    def _eval_constructor(
        self,
        node: Node,
        method: JavaMethod,
        state: ExecutionState,
        summaries: dict[str, MethodSummary],
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
    ) -> Flow:
        type_name = _node_text(node.child_by_field_name("type"), method.source)
        arguments_node = node.child_by_field_name("arguments")
        argument_nodes = tuple(arguments_node.named_children) if arguments_node is not None else ()
        argument_flows = tuple(
            self._eval_expr(arg, method, state, summaries, run, controls=controls, collect=collect)
            for arg in argument_nodes
        )
        merged = Flow.merge(*argument_flows)
        scenario = _constructor_sink_scenario(type_name)
        if scenario:
            self._emit_sink(
                merged,
                scenario,
                _step_from_node("sink", node, method, _sink_label(scenario)),
                method,
                run,
                controls=controls,
                collect=collect,
                unique_resolution=True,
            )
        return merged.append(_step_from_node("dataflow_step", node, method, f"构造 {type_name}"))

    def _emit_sink(
        self,
        flow: Flow,
        scenario: str,
        sink: TraceStep,
        method: JavaMethod,
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
        unique_resolution: bool,
    ) -> None:
        for item in flow.items:
            if scenario in item.sanitized_for:
                continue
            path = _compact_steps((*item.steps, *controls, sink))
            if item.origin_kind == "parameter":
                run.sink_templates.append(
                    SinkTemplate(
                        param_index=item.param_index,
                        scenario=scenario,
                        path_after_parameter=path[1:] if path else (),
                        sink=sink,
                        unique_resolution=unique_resolution,
                    )
                )
            elif collect and item.origin_kind == "source":
                run.candidates.append(
                    FlowCandidate(
                        scenario=scenario,
                        path=path,
                        method_key=method.key,
                        unique_resolution=unique_resolution,
                    )
                )

    def _apply_callee_sinks(
        self,
        summary: MethodSummary,
        argument_flows: tuple[Flow, ...],
        call_step: TraceStep,
        method: JavaMethod,
        run: MethodRun,
        *,
        controls: tuple[TraceStep, ...],
        collect: bool,
        unique_resolution: bool,
    ) -> None:
        for template in summary.sinks:
            if template.param_index < 0 or template.param_index >= len(argument_flows):
                continue
            flow = argument_flows[template.param_index].append(*controls, call_step, *template.path_after_parameter)
            self._emit_propagated_sink(
                flow,
                template,
                method,
                run,
                collect=collect,
                unique_resolution=unique_resolution and template.unique_resolution,
            )

    def _emit_propagated_sink(
        self,
        flow: Flow,
        template: SinkTemplate,
        method: JavaMethod,
        run: MethodRun,
        *,
        collect: bool,
        unique_resolution: bool,
    ) -> None:
        for item in flow.items:
            if template.scenario in item.sanitized_for:
                continue
            if item.origin_kind == "parameter":
                run.sink_templates.append(
                    SinkTemplate(
                        param_index=item.param_index,
                        scenario=template.scenario,
                        path_after_parameter=item.steps[1:] if item.steps else (),
                        sink=template.sink,
                        unique_resolution=unique_resolution,
                    )
                )
            elif collect and item.origin_kind == "source":
                run.candidates.append(
                    FlowCandidate(
                        scenario=template.scenario,
                        path=item.steps,
                        method_key=method.key,
                        unique_resolution=unique_resolution,
                    )
                )

    @staticmethod
    def _callee_return_flow(
        summary: MethodSummary,
        argument_flows: tuple[Flow, ...],
        call_step: TraceStep,
    ) -> Flow:
        returned: list[Flow] = []
        for item in summary.returns:
            if item.origin_kind == "parameter":
                if item.param_index < 0 or item.param_index >= len(argument_flows):
                    continue
                tail = item.steps[1:] if item.steps else ()
                returned.append(argument_flows[item.param_index].append(call_step, *tail, sanitized_for=item.sanitized_for))
            else:
                returned.append(Flow((item.append(call_step),)))
        return Flow.merge(*returned)

    def _resolve_call(
        self,
        method: JavaMethod,
        name: str,
        object_text: str,
        arity: int,
        state: ExecutionState,
    ) -> tuple[JavaMethod | None, bool]:
        candidates: list[str] = []
        receiver = object_text.strip()
        if not receiver or receiver in {"this", "super"}:
            candidates = self.by_class_name_arity.get((method.class_name, name, arity), [])
        else:
            receiver_name = receiver.split(".", 1)[0]
            receiver_type = state.types.get(receiver_name) or method.field_types.get(receiver_name) or ""
            simple_type = _simple_type(receiver_type)
            creation = re.match(r"new\s+(?:[A-Za-z_$][\w$]*\.)*([A-Za-z_$][\w$]*)\s*\(", receiver)
            if not simple_type and creation:
                simple_type = creation.group(1)
            if simple_type:
                candidates = self.by_class_name_arity.get((simple_type, name, arity), [])
            if not candidates:
                object_class = _simple_type(receiver)
                candidates = self.by_class_name_arity.get((object_class, name, arity), [])
        if len(candidates) != 1:
            return None, False
        return self.methods[candidates[0]], True

    def _public_findings(self, candidates: list[FlowCandidate]) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen: set[tuple[str, str, int, str, int]] = set()
        for candidate in candidates:
            if not candidate.path:
                continue
            source = next((step for step in candidate.path if step.kind == "source"), None)
            sink = next((step for step in reversed(candidate.path) if step.kind == "sink"), None)
            if source is None or sink is None:
                continue
            key = (candidate.scenario, sink.file, sink.line, source.file, source.line)
            if key in seen:
                continue
            seen.add(key)
            metadata = SCENARIOS[candidate.scenario]
            cfg_steps = [step for step in candidate.path if step.kind == "cfg_condition"]
            calls = [step for step in candidate.path if step.kind == "call"]
            findings.append(
                {
                    "id": f"flow-{len(findings) + 1}",
                    "engine": "static-path-analysis",
                    "rule_id": f"secflow.java.interprocedural.{candidate.scenario}",
                    "scenario": candidate.scenario,
                    "title": metadata["title"],
                    "record_id": "",
                    "component": "",
                    "severity": metadata["severity"],
                    "cwes": list(metadata["cwes"]),
                    "confidence": "high" if candidate.unique_resolution and calls else "medium",
                    "source": source.public(),
                    "sink": sink.public(),
                    "path": [step.public() for step in candidate.path],
                    "ast": {
                        "entry_method": source.method,
                        "sink_method": sink.method,
                        "resolved_calls": [step.label for step in calls],
                    },
                    "cfg": (
                        "source 到 sink 经过控制条件："
                        + "；".join(f"{step.file}:{step.line}" for step in cfg_steps)
                        if cfg_steps
                        else "跨方法 source 到 sink 路径未经过显式条件分支。"
                    ),
                    "dfg": " → ".join(step.label for step in candidate.path if step.kind != "cfg_condition"),
                    "evidence": sink.snippet,
                    "analysis_depth": len(calls),
                }
            )
        max_findings = _env_int("SECFLOW_STATIC_MAX_FINDINGS", 500, minimum=1, maximum=5000)
        return findings[:max_findings]


def analyze_java_interprocedural(
    code_files: list[dict[str, str]],
    *,
    complete_analysis: bool = False,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    analysis = JavaFlowAnalyzer(
        code_files,
        complete_analysis=complete_analysis,
        cancelled=cancelled,
    ).analyze()
    if (
        analysis.get("status") == "limit_exceeded"
        and len(code_files) > 1
        and str(os.getenv("SECFLOW_JAVA_FLOW_DISABLE_CHUNKING", "")).strip().lower() not in {"1", "true", "yes", "on"}
    ):
        return _analyze_java_interprocedural_chunks(
            code_files,
            analysis,
            complete_analysis=complete_analysis,
            cancelled=cancelled,
        )
    return analysis


def _analyze_java_interprocedural_chunks(
    code_files: list[dict[str, str]],
    base_analysis: dict[str, Any],
    *,
    complete_analysis: bool = False,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    chunks = _module_chunks(code_files)
    min_chunk_files = _env_int("SECFLOW_JAVA_FLOW_MIN_CHUNK_FILES", 8, minimum=1, maximum=5000)
    findings: list[dict[str, Any]] = []
    diagnostics = list(base_analysis.get("diagnostics") or [])
    total_methods = 0
    total_call_edges = 0
    total_iterations = 0
    total_parse_errors = 0
    total_cfg_nodes = 0
    total_cfg_edges = 0
    total_dfg_edges = 0
    completed_chunks = 0
    skipped_chunks = 0

    for chunk_name, chunk_files in chunks:
        if len(chunk_files) < min_chunk_files and len(chunks) > 1:
            continue
        chunk_analysis = JavaFlowAnalyzer(
            chunk_files,
            complete_analysis=complete_analysis,
            cancelled=cancelled,
        ).analyze()
        status = str(chunk_analysis.get("status") or "")
        total_methods += int(chunk_analysis.get("method_count") or 0)
        total_call_edges += int(chunk_analysis.get("call_edge_count") or 0)
        total_iterations = max(total_iterations, int(chunk_analysis.get("iterations") or 0))
        total_parse_errors += int(chunk_analysis.get("parse_error_files") or 0)
        total_cfg_nodes += int(chunk_analysis.get("cfg_node_count") or 0)
        total_cfg_edges += int(chunk_analysis.get("cfg_edge_count") or 0)
        total_dfg_edges += int(chunk_analysis.get("dfg_edge_count") or 0)
        if status in {"completed", "timeout"} and chunk_analysis.get("findings"):
            completed_chunks += 1
            for finding in chunk_analysis.get("findings") or []:
                if isinstance(finding, dict):
                    findings.append(finding)
        elif status == "limit_exceeded":
            skipped_chunks += 1
            diagnostics.append(f"模块 {chunk_name} 仍超过跨方法分析上限，已跳过该模块。")
        elif status in {"warning", "unavailable"}:
            skipped_chunks += 1
            diagnostics.extend(str(item) for item in chunk_analysis.get("diagnostics") or [])

    if not completed_chunks:
        return base_analysis

    deduped = _dedupe_public_findings(findings)
    max_findings = _env_int("SECFLOW_STATIC_MAX_FINDINGS", 500, minimum=1, maximum=5000)
    diagnostics.append(
        f"整仓超过跨方法分析上限，已按 {len(chunks)} 个模块切片分析；"
        "跨模块调用路径不会在切片模式中合并。"
    )
    if skipped_chunks:
        diagnostics.append(f"切片模式跳过 {skipped_chunks} 个仍超限或不可解析模块。")
    return {
        "status": "completed",
        "chunked": True,
        "chunk_count": len(chunks),
        "completed_chunk_count": completed_chunks,
        "skipped_chunk_count": skipped_chunks,
        "findings": deduped[:max_findings],
        "finding_count": len(deduped[:max_findings]),
        "diagnostics": diagnostics,
        "method_count": total_methods or int(base_analysis.get("method_count") or 0),
        "call_edge_count": total_call_edges,
        "iterations": total_iterations,
        "parse_error_files": total_parse_errors,
        "cfg_node_count": total_cfg_nodes,
        "cfg_edge_count": total_cfg_edges,
        "dfg_edge_count": total_dfg_edges,
    }


def _module_chunks(code_files: list[dict[str, str]]) -> list[tuple[str, list[dict[str, str]]]]:
    grouped: dict[str, list[dict[str, str]]] = {}
    for code_file in code_files:
        file_name = str(code_file.get("file_name") or "")
        grouped.setdefault(_module_key(file_name), []).append(code_file)
    return sorted(grouped.items(), key=lambda item: (-len(item[1]), item[0]))


def _module_key(file_name: str) -> str:
    posix = file_name.replace("\\", "/").strip("/")
    for marker in ("/src/main/", "/src/"):
        if marker in posix:
            return posix.split(marker, 1)[0] or "."
    parts = [part for part in posix.split("/") if part]
    return parts[0] if parts else "."


def _dedupe_public_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        sink = finding.get("sink") or {}
        key = (
            str(finding.get("scenario") or ""),
            str(sink.get("file") or finding.get("file") or ""),
            int(sink.get("line") or finding.get("risk_line") or 0),
        )
        if key in seen:
            continue
        seen.add(key)
        copied = dict(finding)
        copied["id"] = f"flow-{len(deduped) + 1}"
        deduped.append(copied)
    return deduped


def _java_method(
    node: Node,
    *,
    file_name: str,
    class_name: str,
    class_annotations: frozenset[str],
    field_types: dict[str, str],
    source: bytes,
    lines: tuple[str, ...],
) -> JavaMethod | None:
    name = _node_text(node.child_by_field_name("name"), source) or class_name
    parameters_node = node.child_by_field_name("parameters")
    parameters: list[Parameter] = []
    if parameters_node is not None:
        for child in parameters_node.named_children:
            if child.type not in {"formal_parameter", "spread_parameter", "receiver_parameter"}:
                continue
            parameter_name = _node_text(child.child_by_field_name("name"), source)
            if not parameter_name:
                identifiers = [item for item in child.named_children if item.type == "identifier"]
                parameter_name = _node_text(identifiers[-1] if identifiers else None, source)
            parameters.append(
                Parameter(
                    name=parameter_name,
                    type_name=_node_text(child.child_by_field_name("type"), source),
                    annotations=frozenset(_annotations(child, source)),
                    line=child.start_point.row + 1,
                    snippet=_line(lines, child.start_point.row + 1),
                )
            )
    body = node.child_by_field_name("body")
    if body is None:
        return None
    key = f"{file_name}::{class_name}::{name}/{len(parameters)}"
    modifiers = next((child for child in node.named_children if child.type == "modifiers"), None)
    return JavaMethod(
        key=key,
        file_name=file_name,
        class_name=class_name,
        name=name,
        parameters=tuple(parameters),
        annotations=frozenset(_annotations(node, source)),
        class_annotations=class_annotations,
        modifiers=_node_text(modifiers, source),
        body=body,
        source=source,
        lines=lines,
        field_types=dict(field_types),
    )


def _class_field_types(class_node: Node, source: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    body = class_node.child_by_field_name("body")
    if body is None:
        return result
    for child in body.named_children:
        if child.type not in {"field_declaration", "constant_declaration"}:
            continue
        type_name = _node_text(child.child_by_field_name("type"), source)
        for declarator in [item for item in child.named_children if item.type == "variable_declarator"]:
            name = _node_text(declarator.child_by_field_name("name"), source)
            if name:
                result[name] = type_name
    return result


def _parameter_is_source(method: JavaMethod, parameter: Parameter) -> bool:
    if parameter.annotations & SOURCE_PARAMETER_ANNOTATIONS:
        return True
    method_entrypoint = bool(method.annotations & ENTRYPOINT_ANNOTATIONS)
    controller = bool(method.class_annotations & {"Controller", "RestController"})
    if method_entrypoint and controller and _simple_type(parameter.type_name) not in {
        "HttpServletRequest",
        "HttpServletResponse",
        "ServerWebExchange",
        "Principal",
    }:
        return True
    return False


def _source_call_label(name: str, object_text: str, state: ExecutionState) -> str:
    receiver = object_text.split(".", 1)[0]
    receiver_type = _simple_type(state.types.get(receiver, ""))
    request_types = {
        "HttpServletRequest",
        "ServletRequest",
        "WebRequest",
        "NativeWebRequest",
        "ServerHttpRequest",
        "MultipartHttpServletRequest",
    }
    request_receiver = receiver_type in request_types or receiver.lower() in {"request", "req", "httprequest"}
    if name in {
        "getParameter",
        "getParameterMap",
        "getParameterValues",
        "getHeader",
        "getHeaders",
        "getQueryString",
        "getRequestURI",
        "getPathInfo",
    } and request_receiver:
        return f"外部输入 API {name} source"
    if name in {"getInputStream", "getReader"} and (
        request_receiver or receiver_type in {"MultipartFile", "Part"}
    ):
        return f"外部输入 API {name} source"
    if name in {"getOriginalFilename", "getSubmittedFileName"} and receiver_type in {"MultipartFile", "Part"}:
        return f"外部输入 API {name} source"
    if name == "nextLine" and receiver_type == "Scanner":
        return "流式输入 API nextLine source"
    if name == "nextElement" and receiver_type == "Enumeration":
        return "枚举输入 API nextElement source"
    if name == "getTheParameter":
        return "封装请求参数 API getTheParameter source"
    if name == "getenv" and object_text.endswith("System"):
        return f"进程环境 API {name} source"
    if name == "getCookies":
        return "HTTP Cookie 集合 source"
    if name == "getValue" and ("cookie" in receiver.lower() or receiver_type == "Cookie"):
        return "HTTP Cookie 值 source"
    return ""


def _sanitizer_scenarios(name: str, object_text: str) -> frozenset[str]:
    if name in {"parseInt", "parseLong", "parseUnsignedInt", "fromString"}:
        return frozenset(
            {
                "command_execution",
                "sql_injection",
                "path_traversal",
                "ldap_injection",
                "xpath_injection",
                "ssrf",
                "response_splitting",
                "trust_boundary",
            }
        )
    if name in {"encodeForHTML", "encodeForHTMLAttribute", "htmlEscape", "escapeHtml4"}:
        return frozenset({"cross_site_scripting"})
    if name in {"filterEncode", "escapeLDAPSearchFilter"}:
        return frozenset({"ldap_injection"})
    if name in {"getFileName", "getName", "normalize"} and any(
        token in object_text for token in {"Paths", "Path", "FilenameUtils"}
    ):
        return frozenset({"path_traversal"})
    if name in {"sanitizeForLog", "safeLogValue"}:
        return frozenset({"log_injection_lookup"})
    return frozenset()


def _sink_scenario(name: str, object_text: str, state: ExecutionState) -> str:
    receiver = object_text.split(".", 1)[0]
    receiver_type = _simple_type(state.types.get(receiver, ""))
    lowered_object = object_text.lower()
    if name == "exec" and (
        receiver_type == "Runtime"
        or "runtime.getruntime" in lowered_object
        or receiver.lower() == "runtime"
    ):
        return "command_execution"
    if name == "command" and receiver_type == "ProcessBuilder":
        return "command_execution"
    if name == "eval" and "script" in lowered_object:
        return "command_execution"
    if name == "execute" and (
        receiver_type in {"HttpClient", "CloseableHttpClient"}
        or "httpclient" in lowered_object
    ):
        return "ssrf"
    sql_receivers = {
        "Statement",
        "PreparedStatement",
        "CallableStatement",
        "Connection",
        "EntityManager",
        "Session",
        "JdbcTemplate",
        "NamedParameterJdbcTemplate",
    }
    sql_receiver_markers = {
        "createstatement",
        "preparestatement",
        "entitymanager",
        "jdbctemplate",
    }
    if name in {
        "execute",
        "executeQuery",
        "executeUpdate",
        "addBatch",
        "query",
        "queryForObject",
        "queryForList",
        "queryForMap",
        "queryForRowSet",
        "update",
        "batchUpdate",
    } and (
        receiver_type in sql_receivers
        or any(marker in lowered_object for marker in sql_receiver_markers)
    ):
        return "sql_injection"
    if name in {"prepareStatement", "prepareCall"} and receiver_type == "Connection":
        return "sql_injection"
    if name in {"createQuery", "createNativeQuery"} and receiver_type in {"EntityManager", "Session"}:
        return "sql_injection"
    if name in {"search"} and ("ldap" in lowered_object or receiver_type in {"DirContext", "InitialDirContext", "LdapTemplate"}):
        return "ldap_injection"
    if name in {"compile", "evaluate"} and ("xpath" in lowered_object or receiver_type == "XPath"):
        return "xpath_injection"
    if name in {"print", "println", "write", "append", "format", "printf"} and (
        "getwriter" in lowered_object or receiver_type in {"PrintWriter", "JspWriter"}
    ):
        return "cross_site_scripting"
    if name in {"setHeader", "addHeader", "sendRedirect"}:
        return "response_splitting"
    if name in {"openConnection", "openStream", "getForObject", "postForObject", "exchange"}:
        return "ssrf"
    if name in {"trace", "debug", "info", "warn", "error", "fatal"} and (
        "log" in receiver.lower() or receiver_type in {"Logger", "Log"}
    ):
        return "log_injection_lookup"
    if name in {"readObject", "load", "readValue", "enableDefaultTyping", "activateDefaultTyping"}:
        if receiver_type in {"ObjectInputStream", "Yaml", "ObjectMapper"} or any(
            token in lowered_object for token in {"yaml", "mapper", "objectinput"}
        ):
            return "deserialization"
    if name in {"setAttribute", "putValue"} and (
        "session" in lowered_object or receiver_type in {"HttpSession", "Session"}
    ):
        return "trust_boundary"
    if name in {"readAllBytes", "write", "copy", "newInputStream", "newOutputStream"} and (
        object_text.endswith("Files") or receiver_type == "Files"
    ):
        return "path_traversal"
    return ""


def _constructor_sink_scenario(type_name: str) -> str:
    simple = _simple_type(type_name)
    if simple in {"ProcessBuilder"}:
        return "command_execution"
    if simple in {"File", "FileInputStream", "FileOutputStream", "RandomAccessFile"}:
        return "path_traversal"
    return ""


def _sink_argument_flow(scenario: str, object_flow: Flow, arguments: tuple[Flow, ...]) -> Flow:
    if scenario == "sql_injection":
        return arguments[0] if arguments else Flow()
    if scenario == "deserialization" and not arguments:
        return object_flow
    return Flow.merge(*arguments, object_flow if scenario in {"ssrf", "deserialization"} else Flow())


def _sink_label(scenario: str) -> str:
    return {
        "command_execution": "命令执行 sink",
        "sql_injection": "SQL 执行 sink",
        "path_traversal": "文件系统 sink",
        "cross_site_scripting": "HTTP 响应输出 sink",
        "ldap_injection": "LDAP 查询 sink",
        "xpath_injection": "XPath 执行 sink",
        "ssrf": "服务端网络请求 sink",
        "log_injection_lookup": "日志输出 sink",
        "deserialization": "反序列化 sink",
        "response_splitting": "HTTP 响应头 sink",
        "trust_boundary": "信任域写入 sink",
    }.get(scenario, "危险调用 sink")


def _annotations(node: Node, source: bytes) -> set[str]:
    result: set[str] = set()
    modifiers = next((child for child in node.named_children if child.type == "modifiers"), None)
    if modifiers is None:
        return result
    for annotation in modifiers.named_children:
        if annotation.type not in {"annotation", "marker_annotation"}:
            continue
        name = _node_text(annotation.child_by_field_name("name"), source)
        if name:
            result.add(name.rsplit(".", 1)[-1])
    return result


def _descendants_of_types(node: Node, types: set[str]) -> Iterable[Node]:
    pending = list(reversed(node.named_children))
    while pending:
        child = pending.pop()
        if child.type in types:
            yield child
        pending.extend(reversed(child.named_children))


def _node_text(node: Node | None, source: bytes) -> str:
    if node is None:
        return ""
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _step_from_node(kind: str, node: Node, method: JavaMethod, label: str) -> TraceStep:
    line = node.start_point.row + 1
    return TraceStep(
        kind=kind,
        file=method.file_name,
        line=line,
        label=label,
        snippet=_line(method.lines, line),
        method=method.display,
    )


def _assignment_name(node: Node | None, source: bytes) -> str:
    text = _node_text(node, source)
    identifiers = re.findall(r"[A-Za-z_$][\w$]*", text)
    return identifiers[-1] if identifiers else ""


_UNKNOWN_CONSTANT = object()


def _update_constant(state: ExecutionState, name: str, node: Node | None, source: bytes) -> None:
    value = _constant_value(node, source, state.constants)
    if value is _UNKNOWN_CONSTANT:
        state.constants.pop(name, None)
    else:
        state.constants[name] = value


def _constant_value(node: Node | None, source: bytes, constants: dict[str, Any]) -> Any:
    if node is None:
        return _UNKNOWN_CONSTANT
    if node.type in {"parenthesized_expression", "cast_expression"}:
        children = [child for child in node.named_children if child.type not in {"type_identifier", "integral_type", "floating_point_type"}]
        return _constant_value(children[-1] if children else None, source, constants)
    if node.type == "identifier":
        return constants.get(_node_text(node, source), _UNKNOWN_CONSTANT)
    if node.type in {"true", "false"}:
        return node.type == "true"
    if node.type == "null_literal":
        return None
    text = _node_text(node, source).replace("_", "")
    if node.type in {"decimal_integer_literal", "hex_integer_literal", "octal_integer_literal", "binary_integer_literal"}:
        try:
            return int(re.sub(r"[lL]$", "", text), 0)
        except ValueError:
            return _UNKNOWN_CONSTANT
    if node.type in {"decimal_floating_point_literal", "hex_floating_point_literal"}:
        try:
            return float(re.sub(r"[fFdD]$", "", text))
        except ValueError:
            return _UNKNOWN_CONSTANT
    if node.type == "string_literal":
        match = re.fullmatch(r'"([^"\\]*)"', text)
        return match.group(1) if match else _UNKNOWN_CONSTANT
    if node.type == "ternary_expression":
        condition = _constant_value(node.child_by_field_name("condition"), source, constants)
        if condition is _UNKNOWN_CONSTANT:
            return _UNKNOWN_CONSTANT
        branch = "consequence" if bool(condition) else "alternative"
        return _constant_value(node.child_by_field_name(branch), source, constants)
    if node.type == "unary_expression" and node.named_children:
        value = _constant_value(node.named_children[-1], source, constants)
        if value is _UNKNOWN_CONSTANT:
            return value
        operator = text[: max(0, node.named_children[-1].start_byte - node.start_byte)].strip()
        try:
            if operator == "!":
                return not bool(value)
            if operator == "-":
                return -value
            if operator == "+":
                return +value
            if operator == "~":
                return ~value
        except (TypeError, ValueError):
            return _UNKNOWN_CONSTANT
        return _UNKNOWN_CONSTANT
    if node.type == "binary_expression":
        left_node = node.child_by_field_name("left")
        right_node = node.child_by_field_name("right")
        left = _constant_value(left_node, source, constants)
        right = _constant_value(right_node, source, constants)
        if left is _UNKNOWN_CONSTANT or right is _UNKNOWN_CONSTANT or left_node is None or right_node is None:
            return _UNKNOWN_CONSTANT
        operator = source[left_node.end_byte : right_node.start_byte].decode("utf-8", errors="replace").strip()
        try:
            operations = {
                "+": lambda: left + right,
                "-": lambda: left - right,
                "*": lambda: left * right,
                "/": lambda: left / right,
                "%": lambda: left % right,
                "<": lambda: left < right,
                "<=": lambda: left <= right,
                ">": lambda: left > right,
                ">=": lambda: left >= right,
                "==": lambda: left == right,
                "!=": lambda: left != right,
                "&&": lambda: bool(left) and bool(right),
                "||": lambda: bool(left) or bool(right),
                "&": lambda: left & right,
                "|": lambda: left | right,
                "^": lambda: left ^ right,
                "<<": lambda: left << right,
                ">>": lambda: left >> right,
                ">>>": lambda: left >> right,
            }
            operation = operations.get(operator)
            return operation() if operation else _UNKNOWN_CONSTANT
        except (ArithmeticError, TypeError, ValueError):
            return _UNKNOWN_CONSTANT
    return _UNKNOWN_CONSTANT


def _simple_type(value: str) -> str:
    cleaned = re.sub(r"<.*>", "", value or "").replace("[]", "").strip()
    return cleaned.rsplit(".", 1)[-1]


def _line(lines: tuple[str, ...], line: int) -> str:
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def _compact_steps(steps: Iterable[TraceStep]) -> tuple[TraceStep, ...]:
    result: list[TraceStep] = []
    seen_consecutive: tuple[str, str, int, str] | None = None
    for step in steps:
        key = (step.kind, step.file, step.line, step.label)
        if key == seen_consecutive:
            continue
        result.append(step)
        seen_consecutive = key
    return tuple(result[-40:])


def _summary_semantic_signature(summary: MethodSummary) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    returns = tuple(
        sorted(
            (
                item.origin_kind,
                item.param_index,
                item.source_key,
                tuple(sorted(item.sanitized_for)),
            )
            for item in summary.returns
        )
    )
    sinks = tuple(
        sorted(
            (
                item.param_index,
                item.scenario,
                item.sink.file,
                item.sink.line,
                item.unique_resolution,
            )
            for item in summary.sinks
        )
    )
    return returns, sinks


def _compact_flow_items(items: Iterable[FlowItem]) -> tuple[FlowItem, ...]:
    result: list[FlowItem] = []
    seen: set[tuple[Any, ...]] = set()
    for item in items:
        key = (item.origin_kind, item.param_index, item.source_key, tuple(sorted(item.sanitized_for)))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)


def _compact_sink_templates(items: Iterable[SinkTemplate]) -> tuple[SinkTemplate, ...]:
    result: list[SinkTemplate] = []
    seen: set[tuple[Any, ...]] = set()
    for item in items:
        key = (item.param_index, item.scenario, item.sink.file, item.sink.line)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return tuple(result)


def _control_label(node_type: str) -> str:
    return {
        "for_statement": "for 控制条件",
        "enhanced_for_statement": "for-each 控制条件",
        "while_statement": "while 控制条件",
        "do_statement": "do-while 控制条件",
        "switch_expression": "switch 控制条件",
        "switch_statement": "switch 控制条件",
        "try_statement": "try 异常控制路径",
        "catch_clause": "catch 异常控制路径",
        "synchronized_statement": "synchronized 控制路径",
    }.get(node_type, "控制流条件")


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    try:
        value = float(os.getenv(name, str(default)))
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))
