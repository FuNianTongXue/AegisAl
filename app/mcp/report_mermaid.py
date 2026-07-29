from __future__ import annotations

import asyncio
import hashlib
import json
import re
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class MermaidDiagram(BaseModel):
    id: str
    title: str
    kind: Literal["flowchart", "pie"]
    source: str


class MermaidReportOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["mermaid"] = "mermaid"
    diagrams: list[MermaidDiagram]
    input_sha256: str
    chart_sha256: str


report_mermaid_mcp = FastMCP(
    "SecFlow Mermaid MCP",
    instructions=(
        "Build deterministic Mermaid diagrams only from verified SecFlow scan JSON and report-chart "
        "data. Do not add findings, links, severities, or relationships that are absent from the input."
    ),
)


@report_mermaid_mcp.tool(
    name="build_report_mermaid",
    description="Build auditable Mermaid flow and severity diagrams for a SecFlow scan report.",
    structured_output=True,
)
def build_report_mermaid(
    report_json: dict[str, Any],
    report_charts: dict[str, Any] | None = None,
    language: str = "zh-Hans",
) -> MermaidReportOutput:
    from app.reports import validate_scan_result_json

    scan_json = validate_scan_result_json(report_json)
    charts = _json_value(report_charts or {})
    input_sha256 = str((scan_json.get("audit") or {}).get("payload_sha256") or "")
    chart_input_sha256 = str(charts.get("input_sha256") or "")
    if chart_input_sha256 and chart_input_sha256 != input_sha256:
        raise ValueError("Report chart input hash does not match scan JSON")

    diagrams = [
        MermaidDiagram(
            id="finding-relationships",
            title=_labels(language)["relationships"],
            kind="flowchart",
            source=_flowchart_source(charts, language),
        )
    ]
    severity_source = _severity_source(charts, language)
    if severity_source:
        diagrams.append(
            MermaidDiagram(
                id="severity-distribution",
                title=_labels(language)["severity"],
                kind="pie",
                source=severity_source,
            )
        )
    return MermaidReportOutput(
        diagrams=diagrams,
        input_sha256=input_sha256,
        chart_sha256=_sha256_json(charts),
    )


def invoke_report_mermaid_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_mermaid_mcp.call_tool("build_report_mermaid", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Mermaid MCP did not return structured output")


async def mermaid_mcp_spec() -> dict[str, Any]:
    tools = await report_mermaid_mcp.list_tools()
    return {
        "id": "report-mermaid",
        "name": report_mermaid_mcp.name,
        "tools": [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": tool.inputSchema,
                "output_schema": tool.outputSchema or {},
            }
            for tool in tools
        ],
    }


def _flowchart_source(charts: dict[str, Any], language: str) -> str:
    labels = _labels(language)
    nodes = [item for item in charts.get("sankey_nodes") or [] if isinstance(item, dict)][:24]
    links = [item for item in charts.get("sankey_links") or [] if isinstance(item, dict)][:36]
    if not nodes:
        return "\n".join(
            [
                "flowchart LR",
                f'  scan["{_escape_label(labels["scan"])}"] --> report["{_escape_label(labels["report"])}"]',
            ]
        )

    identifiers: dict[str, str] = {}
    lines = ["flowchart LR"]
    for index, node in enumerate(nodes):
        raw_id = str(node.get("id") or f"node-{index}")
        mermaid_id = f"n{index}"
        identifiers[raw_id] = mermaid_id
        lines.append(f'  {mermaid_id}["{_escape_label(node.get("label") or raw_id)}"]')
    for link in links:
        source = identifiers.get(str(link.get("source") or ""))
        target = identifiers.get(str(link.get("target") or ""))
        if not source or not target:
            continue
        relation = _escape_label(str(link.get("type") or "related"))
        lines.append(f"  {source} -->|{relation}| {target}")
    return "\n".join(lines)


def _severity_source(charts: dict[str, Any], language: str) -> str:
    labels = _labels(language)
    severity_names = labels["severity_names"]
    rows: list[tuple[str, int]] = []
    for item in charts.get("severity_ring") or []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or item.get("id") or "UNKNOWN").upper()
        try:
            value = max(0, int(item.get("value") or 0))
        except (TypeError, ValueError):
            value = 0
        if value:
            rows.append((str(severity_names.get(severity) or severity), value))
    if not rows:
        return ""
    lines = ["pie showData", f'  title {_escape_label(labels["severity"])}']
    lines.extend(f'  "{_escape_label(name)}" : {value}' for name, value in rows)
    return "\n".join(lines)


def _labels(language: str) -> dict[str, Any]:
    clean = str(language or "").lower()
    if clean.startswith("zh"):
        return {
            "relationships": "扫描事实关系图",
            "severity": "漏洞严重度分布",
            "scan": "已核验扫描 JSON",
            "report": "安全报告",
            "severity_names": {
                "CRITICAL": "严重",
                "HIGH": "高危",
                "MEDIUM": "中危",
                "LOW": "低危",
                "UNKNOWN": "未知",
            },
        }
    return {
        "relationships": "Verified scan relationships",
        "severity": "Vulnerability severity distribution",
        "scan": "Verified scan JSON",
        "report": "Security report",
        "severity_names": {},
    }


def _escape_label(value: Any) -> str:
    clean = re.sub(r"\s+", " ", str(value or "")).strip()[:120]
    return clean.replace("\\", "\\\\").replace('"', "'").replace("|", "/")


def _json_value(value: Any) -> dict[str, Any]:
    rendered = json.loads(json.dumps(value, ensure_ascii=False, default=str))
    return rendered if isinstance(rendered, dict) else {}


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def main() -> None:
    report_mermaid_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
