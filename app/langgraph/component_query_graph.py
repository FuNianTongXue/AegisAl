from __future__ import annotations

import re
from typing import Any, Callable, TypedDict

try:
    from langgraph.graph import END, StateGraph
except Exception:  # noqa: BLE001
    END = "__end__"
    StateGraph = None

from app.mcp.component_query import invoke_detail_mcp, invoke_excel_mcp, invoke_sankey_mcp
from app.intelligence import intelligence_service
from app.privacy import sanitize_public_text
from app.storage import now_iso
from app.trace_ui import tool_call_presentation


_VERSION = r"v?\d+(?:\.\d+){1,4}(?:[-+][0-9A-Za-z.-]+)?"
_COORDINATE = re.compile(
    rf"(?P<name>@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+(?:[/:][A-Za-z0-9_.-]+)*)@(?P<version>{_VERSION})",
    flags=re.IGNORECASE,
)
_NAME_AND_VERSION = re.compile(
    rf"(?P<name>@?[A-Za-z0-9_.-]+(?:[/:][A-Za-z0-9_.-]+)*)\s+(?P<version>{_VERSION})(?![0-9A-Za-z.-])",
    flags=re.IGNORECASE,
)
_COMPONENT_SIGNAL = re.compile(
    r"组件|依赖|软件包|包版本|component|dependency|package|artifact",
    flags=re.IGNORECASE,
)
_QUERY_SIGNAL = re.compile(
    r"查询|漏洞|风险|影响|安全|vulnerab|affected|risk|secure|cve|ghsa",
    flags=re.IGNORECASE,
)
_ECOSYSTEM_ALIASES = (
    ("Maven", ("maven", "gradle")),
    ("npm", ("npm", "node.js", "nodejs")),
    ("PyPI", ("pypi", "python", "pip")),
    ("Go", ("golang", "go module", "go.mod")),
    ("crates.io", ("crates.io", "cargo", "rust")),
    ("NuGet", ("nuget", ".net", "dotnet")),
    ("RubyGems", ("rubygems", "gem", "ruby")),
    ("Packagist", ("packagist", "composer", "php")),
)


class ComponentQueryState(TypedDict, total=False):
    question: str
    response_language: str
    component_query: dict[str, Any]
    component_result: dict[str, Any]
    component_detail: dict[str, Any]
    component_error: str
    records: list[dict[str, Any]]
    knowledge_graph: dict[str, Any]
    chart_data: dict[str, Any]
    artifacts: list[dict[str, Any]]
    trace: list[dict[str, Any]]
    event_sink: Callable[[dict[str, Any]], None]


class ComponentQuerySubgraph:
    def __init__(self) -> None:
        self.graph = self._build_graph()

    def invoke(self, state: dict[str, Any]) -> dict[str, Any]:
        seed: ComponentQueryState = {
            **state,
            "component_query": dict(state.get("component_query") or {}),
            "component_result": dict(state.get("component_result") or {}),
            "component_detail": dict(state.get("component_detail") or {}),
            "component_error": str(state.get("component_error") or ""),
            "records": list(state.get("records") or []),
            "knowledge_graph": dict(state.get("knowledge_graph") or {}),
            "chart_data": dict(state.get("chart_data") or {}),
            "artifacts": list(state.get("artifacts") or []),
            "trace": list(state.get("trace") or []),
        }
        if self.graph is not None:
            return dict(self.graph.invoke(seed))
        seed = self._parse_coordinates(seed)
        if not seed.get("component_error"):
            seed = self._query_component(seed)
        if not seed.get("component_error"):
            seed = self._detail_mcp(seed)
            seed = self._excel_mcp(seed)
            seed = self._sankey_mcp(seed)
        return dict(self._compose_result(seed))

    @staticmethod
    def graph_spec() -> dict[str, Any]:
        return {
            "name": "Component Query LangGraph Subgraph",
            "nodes": [
                {"id": "parse_component_coordinates", "label": "解析组件坐标"},
                {"id": "query_component_vulnerabilities", "label": "查询组件漏洞"},
                {"id": "component_detail_mcp", "label": "组件漏洞详情 MCP 生成页面模型"},
                {"id": "excel_mcp", "label": "Excel MCP 生成工作簿"},
                {"id": "d3_sankey_mcp", "label": "D3 Sankey MCP 生成图数据"},
                {"id": "compose_component_result", "label": "汇总组件查询"},
            ],
            "edges": [
                {"source": "parse_component_coordinates", "target": "query_component_vulnerabilities", "label": "坐标有效"},
                {"source": "parse_component_coordinates", "target": "compose_component_result", "label": "需要补充名称或版本"},
                {"source": "query_component_vulnerabilities", "target": "component_detail_mcp", "label": "事实查询完成"},
                {"source": "query_component_vulnerabilities", "target": "compose_component_result", "label": "查询失败"},
                {"source": "component_detail_mcp", "target": "excel_mcp", "label": "详情页面模型已生成"},
                {"source": "excel_mcp", "target": "d3_sankey_mcp", "label": "工作簿已登记"},
                {"source": "d3_sankey_mcp", "target": "compose_component_result", "label": "桑基图已生成"},
            ],
        }

    def _build_graph(self):
        if StateGraph is None:
            return None
        graph = StateGraph(ComponentQueryState)
        graph.add_node("parse_component_coordinates", self._parse_coordinates)
        graph.add_node("query_component_vulnerabilities", self._query_component)
        graph.add_node("component_detail_mcp", self._detail_mcp)
        graph.add_node("excel_mcp", self._excel_mcp)
        graph.add_node("d3_sankey_mcp", self._sankey_mcp)
        graph.add_node("compose_component_result", self._compose_result)
        graph.set_entry_point("parse_component_coordinates")
        graph.add_conditional_edges(
            "parse_component_coordinates",
            lambda state: "compose" if state.get("component_error") else "query",
            {"query": "query_component_vulnerabilities", "compose": "compose_component_result"},
        )
        graph.add_conditional_edges(
            "query_component_vulnerabilities",
            lambda state: "compose" if state.get("component_error") else "excel",
            {"excel": "component_detail_mcp", "compose": "compose_component_result"},
        )
        graph.add_edge("component_detail_mcp", "excel_mcp")
        graph.add_edge("excel_mcp", "d3_sankey_mcp")
        graph.add_edge("d3_sankey_mcp", "compose_component_result")
        graph.add_edge("compose_component_result", END)
        return graph.compile()

    @staticmethod
    def _parse_coordinates(state: ComponentQueryState) -> ComponentQueryState:
        coordinates = dict(state.get("component_query") or {})
        if not coordinates:
            coordinates = parse_component_query(state.get("question", "")) or {}
        name = str(coordinates.get("name") or "").strip()
        version = str(coordinates.get("version") or "").strip()
        if not name or not version:
            state["component_error"] = "请输入组件名称和明确版本，例如：查询 Maven org.apache.logging.log4j:log4j-core 2.14.1 的漏洞。"
            return _add_trace(
                state,
                "component_query.parse_coordinates",
                "组件查询需要明确的组件名称和版本。",
                status="warning",
            )
        state["component_query"] = {
            "name": name,
            "version": version.removeprefix("v"),
            "ecosystem": str(coordinates.get("ecosystem") or "").strip(),
            "include_realtime": bool(coordinates.get("include_realtime", True)),
        }
        state["component_error"] = ""
        return _add_trace(
            state,
            "component_query.parse_coordinates",
            f"已识别组件 {name}，版本 {state['component_query']['version']}。",
        )

    @staticmethod
    def _query_component(state: ComponentQueryState) -> ComponentQueryState:
        query = state.get("component_query") or {}
        try:
            result = intelligence_service.query_component_vulnerabilities(
                str(query.get("name") or ""),
                str(query.get("version") or ""),
                ecosystem=str(query.get("ecosystem") or ""),
                include_realtime=bool(query.get("include_realtime", True)),
            )
            state["component_result"] = result
            state["records"] = list(result.get("records") or [])
            state["knowledge_graph"] = dict(result.get("graph") or {})
            state["component_error"] = ""
            return _add_trace(
                state,
                "component_query.query_vulnerabilities",
                f"组件版本核验完成，确认 {int(result.get('total') or 0)} 条漏洞记录。",
                status="completed" if result.get("total") else "warning",
                presentation=tool_call_presentation(
                    "query_component_vulnerabilities",
                    state="completed",
                    title="Component vulnerability query",
                    input_summary={
                        "name": query.get("name", ""),
                        "version": query.get("version", ""),
                        "ecosystem": query.get("ecosystem", "auto"),
                    },
                    output={"verified_records": int(result.get("total") or 0)},
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["component_result"] = {}
            state["records"] = []
            state["knowledge_graph"] = _empty_graph(str(query.get("name") or ""))
            state["component_error"] = sanitize_public_text(str(exc)).strip() or "组件查询失败"
            return _add_trace(
                state,
                "component_query.query_vulnerabilities",
                f"组件版本核验失败：{state['component_error']}",
                status="warning",
                presentation=tool_call_presentation(
                    "query_component_vulnerabilities",
                    state="error",
                    title="Component vulnerability query",
                    input_summary={
                        "name": query.get("name", ""),
                        "version": query.get("version", ""),
                        "ecosystem": query.get("ecosystem", "auto"),
                    },
                    error=state["component_error"],
                ),
            )

    @staticmethod
    def _excel_mcp(state: ComponentQueryState) -> ComponentQueryState:
        query = state.get("component_query") or {}
        try:
            artifact = invoke_excel_mcp(
                {
                    "name": str(query.get("name") or ""),
                    "version": str(query.get("version") or ""),
                    "ecosystem": str(query.get("ecosystem") or ""),
                    "records": list(state.get("records") or []),
                    "generated_at": str((state.get("component_result") or {}).get("generated_at") or now_iso()),
                }
            )
            state["artifacts"] = [*state.get("artifacts", []), artifact]
            return _add_trace(
                state,
                "component_query.excel_mcp",
                "已生成并登记完整 Excel 查询结果。",
                presentation=tool_call_presentation(
                    "export_component_vulnerabilities_excel",
                    state="completed",
                    title="Excel MCP",
                    input_summary={
                        "name": query.get("name", ""),
                        "version": query.get("version", ""),
                        "ecosystem": query.get("ecosystem", "auto"),
                        "verified_records": len(state.get("records") or []),
                    },
                    output={
                        "file_name": artifact.get("file_name", ""),
                        "artifact_id": artifact.get("id", ""),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            return _add_trace(
                state,
                "component_query.excel_mcp",
                f"Excel 查询结果生成失败：{sanitize_public_text(exc)}",
                status="warning",
                presentation=tool_call_presentation(
                    "export_component_vulnerabilities_excel",
                    state="error",
                    title="Excel MCP",
                    input_summary={"name": query.get("name", ""), "version": query.get("version", "")},
                    error=exc,
                ),
            )

    @staticmethod
    def _detail_mcp(state: ComponentQueryState) -> ComponentQueryState:
        result = state.get("component_result") or {}
        query = state.get("component_query") or {}
        try:
            detail = invoke_detail_mcp(
                {
                    "component": result.get("component") or query,
                    "records": list(state.get("records") or []),
                    "generated_at": str(result.get("generated_at") or now_iso()),
                    "response_language": str(state.get("response_language") or "zh-Hans"),
                }
            )
            state["component_detail"] = detail
            return _add_trace(
                state,
                "component_query.component_detail_mcp",
                f"已生成 {len(detail.get('vulnerabilities') or [])} 条组件漏洞详情页面数据。",
                status="completed" if detail.get("vulnerabilities") else "warning",
                presentation=tool_call_presentation(
                    "build_component_vulnerability_detail",
                    state="completed",
                    title="Component Detail MCP",
                    input_summary={
                        "name": query.get("name", ""),
                        "version": query.get("version", ""),
                        "verified_records": len(state.get("records") or []),
                    },
                    output={
                        "renderer": detail.get("renderer", ""),
                        "preview_count": int(detail.get("preview_count") or 0),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["component_detail"] = {}
            return _add_trace(
                state,
                "component_query.component_detail_mcp",
                f"组件详情页面数据生成失败：{sanitize_public_text(exc)}",
                status="warning",
                presentation=tool_call_presentation(
                    "build_component_vulnerability_detail",
                    state="error",
                    title="Component Detail MCP",
                    input_summary={"name": query.get("name", ""), "version": query.get("version", "")},
                    error=exc,
                ),
            )

    @staticmethod
    def _sankey_mcp(state: ComponentQueryState) -> ComponentQueryState:
        try:
            sankey = invoke_sankey_mcp({"graph": state.get("knowledge_graph") or {}})
            state["chart_data"] = {
                "schema_version": int(sankey.get("schema_version") or 1),
                "sankey": {
                    "nodes": list(sankey.get("nodes") or []),
                    "links": list(sankey.get("links") or []),
                },
                "severity_ring": [],
                "risk_bars": [],
            }
            return _add_trace(
                state,
                "component_query.d3_sankey_mcp",
                f"已生成 {len(sankey.get('nodes') or [])} 个节点和 {len(sankey.get('links') or [])} 条连线的桑基图数据。",
                status="completed" if sankey.get("nodes") else "warning",
                presentation=tool_call_presentation(
                    "build_component_sankey",
                    state="completed",
                    title="D3 Sankey MCP",
                    input_summary={
                        "graph_nodes": len((state.get("knowledge_graph") or {}).get("nodes") or []),
                        "graph_edges": len((state.get("knowledge_graph") or {}).get("edges") or []),
                    },
                    output={
                        "sankey_nodes": len(sankey.get("nodes") or []),
                        "sankey_links": len(sankey.get("links") or []),
                    },
                ),
            )
        except Exception as exc:  # noqa: BLE001
            state["chart_data"] = {}
            return _add_trace(
                state,
                "component_query.d3_sankey_mcp",
                f"桑基图数据生成失败：{sanitize_public_text(exc)}",
                status="warning",
                presentation=tool_call_presentation(
                    "build_component_sankey",
                    state="error",
                    title="D3 Sankey MCP",
                    input_summary={
                        "graph_nodes": len((state.get("knowledge_graph") or {}).get("nodes") or []),
                        "graph_edges": len((state.get("knowledge_graph") or {}).get("edges") or []),
                    },
                    error=exc,
                ),
            )

    @staticmethod
    def _compose_result(state: ComponentQueryState) -> ComponentQueryState:
        return _add_trace(
            state,
            "component_query.compose_result",
            "组件查询子图执行完成。" if not state.get("component_error") else "组件查询已返回补充信息。",
            status="completed" if not state.get("component_error") else "warning",
        )


def looks_like_component_query(question: str) -> bool:
    text = " ".join(str(question or "").split())
    if not text:
        return False
    if _COORDINATE.search(text):
        return True
    ecosystem_signal = bool(_detect_ecosystem(text))
    return bool(_QUERY_SIGNAL.search(text) and (_COMPONENT_SIGNAL.search(text) or ecosystem_signal))


def parse_component_query(question: str) -> dict[str, Any] | None:
    text = " ".join(str(question or "").split())
    if not looks_like_component_query(text):
        return None
    match = _COORDINATE.search(text) or _NAME_AND_VERSION.search(text)
    if not match:
        return None
    return {
        "name": match.group("name").strip(),
        "version": match.group("version").strip().removeprefix("v"),
        "ecosystem": _detect_ecosystem(text),
        "include_realtime": True,
    }


def _detect_ecosystem(text: str) -> str:
    lowered = text.lower()
    for canonical, aliases in _ECOSYSTEM_ALIASES:
        if any(re.search(rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", lowered) for alias in aliases):
            return canonical
    return ""


def _add_trace(
    state: ComponentQueryState,
    node: str,
    message: str,
    status: str = "completed",
    presentation: dict[str, Any] | None = None,
) -> ComponentQueryState:
    item = {
        "node": node,
        "status": status,
        "message": sanitize_public_text(message),
        "time": now_iso(),
    }
    if presentation:
        item["presentation"] = presentation
    state["trace"] = [*state.get("trace", []), item]
    event_sink = state.get("event_sink")
    if event_sink is not None:
        try:
            event_sink(dict(item))
        except Exception:  # noqa: BLE001
            pass
    return state


def _empty_graph(query: str = "") -> dict[str, Any]:
    return {"query": query, "nodes": [], "edges": [], "node_count": 0, "edge_count": 0}


component_query_subgraph = ComponentQuerySubgraph()
