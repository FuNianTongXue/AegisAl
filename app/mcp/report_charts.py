from __future__ import annotations

import asyncio
from collections import Counter
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class ReportChartMetric(BaseModel):
    id: str
    label: str
    value: int
    severity: str | None = None


class ReportChartNode(BaseModel):
    id: str
    label: str
    type: str
    severity: str | None = None
    column: int


class ReportChartLink(BaseModel):
    source: str
    target: str
    type: str
    value: int = 1
    severity: str | None = None


class ReportCodeLine(BaseModel):
    number: int
    text: str
    is_risk: bool = False


class ReportCodeBlock(BaseModel):
    finding_id: str
    language: str
    file_name: str
    line_start: int
    line_end: int
    risk_line: int | None = None
    source: str = "scan_evidence"
    lines: list[ReportCodeLine]


class ScanReportCharts(BaseModel):
    schema_version: int = 1
    renderer: Literal["d3-report-charts"] = "d3-report-charts"
    severity_ring: list[ReportChartMetric]
    risk_bars: list[ReportChartMetric]
    sankey_nodes: list[ReportChartNode]
    sankey_links: list[ReportChartLink]
    code_blocks: list[ReportCodeBlock]
    source_kind: str
    fact_count: int
    input_schema: str = "legacy-scan-data"
    input_sha256: str = ""


report_chart_mcp = FastMCP(
    "SecFlow Report Chart MCP",
    instructions=(
        "Transform verified dependency and code-scan facts into bounded, auditable chart data and "
        "line-addressable code blocks for SecFlow HTML and PDF reports. Never infer findings that "
        "are absent from the input."
    ),
)


@report_chart_mcp.tool(
    name="build_scan_report_charts",
    description="Build severity, risk-count, and source-to-finding chart data from completed scan facts.",
    structured_output=True,
)
def build_scan_report_charts(
    scan_data: dict[str, Any] | None = None,
    source_kind: str = "assistant_scan",
    report_json: dict[str, Any] | None = None,
) -> ScanReportCharts:
    input_schema = "legacy-scan-data"
    input_sha256 = ""
    if report_json is not None:
        from app.reports import validate_scan_result_json

        validated = validate_scan_result_json(report_json)
        scan_data = validated["payload"]
        source_kind = str(validated.get("source_kind") or source_kind)
        input_schema = str(validated.get("$schema") or "")
        input_sha256 = str((validated.get("audit") or {}).get("payload_sha256") or "")
    scan_data = scan_data or {}
    records, findings = _scan_facts(scan_data, source_kind)
    if report_json is not None:
        facts = validated.get("facts") if isinstance(validated.get("facts"), dict) else {}
        findings = [item for item in facts.get("code_findings") or [] if isinstance(item, dict)]
    severity_counts: Counter[str] = Counter()
    risk_counts: Counter[str] = Counter()
    nodes: list[ReportChartNode] = []
    links: list[ReportChartLink] = []
    known_nodes: set[str] = set()
    code_blocks: list[ReportCodeBlock] = []

    def add_node(node_id: str, label: str, node_type: str, column: int, severity: str | None = None) -> None:
        if not node_id or node_id in known_nodes or len(nodes) >= 220:
            return
        nodes.append(
            ReportChartNode(
                id=node_id,
                label=label[:160],
                type=node_type,
                severity=severity,
                column=column,
            )
        )
        known_nodes.add(node_id)

    for index, record in enumerate(records[:100]):
        severity = _severity(record.get("severity"))
        severity_counts[severity] += 1
        risk_counts["dependency"] += 1
        component = _component_label(record) or "Dependency"
        component_id = f"component:{component.casefold()}"
        finding_id = f"vulnerability:{str(record.get('id') or index)}"
        add_node(component_id, component, "component", 0)
        add_node(finding_id, str(record.get("id") or record.get("title") or "Vulnerability"), "vulnerability", 1, severity)
        if component_id in known_nodes and finding_id in known_nodes and len(links) < 360:
            links.append(ReportChartLink(source=component_id, target=finding_id, type="AFFECTED_BY", severity=severity))

    for index, finding in enumerate(findings[:160]):
        severity = _severity(finding.get("severity"))
        severity_counts[severity] += 1
        scenario = str(finding.get("scenario") or finding.get("title") or "code").strip() or "code"
        risk_counts[scenario] += 1
        sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
        file_name = str(finding.get("file_name") or finding.get("file") or sink.get("file") or "source").strip()
        source_id = f"source:{file_name.casefold()}"
        finding_id = f"finding:{str(finding.get('id') or index)}"
        add_node(source_id, file_name or "source", "source", 0)
        add_node(finding_id, str(finding.get("title") or scenario), "finding", 1, severity)
        if source_id in known_nodes and finding_id in known_nodes and len(links) < 360:
            links.append(ReportChartLink(source=source_id, target=finding_id, type="CONTAINS", severity=severity))
        code_block = _code_block(finding, index)
        if code_block is not None:
            code_blocks.append(code_block)

    severity_labels = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "UNKNOWN": "Unknown",
    }
    severity_ring = [
        ReportChartMetric(id=key.lower(), label=severity_labels[key], value=int(severity_counts.get(key, 0)), severity=key)
        for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    ]
    risk_bars = [
        ReportChartMetric(id=key[:100], label=_risk_label(key), value=int(value))
        for key, value in risk_counts.most_common(12)
    ]
    return ScanReportCharts(
        severity_ring=severity_ring,
        risk_bars=risk_bars,
        sankey_nodes=nodes,
        sankey_links=links,
        code_blocks=code_blocks,
        source_kind=source_kind,
        fact_count=len(records) + len(findings),
        input_schema=input_schema,
        input_sha256=input_sha256,
    )


def invoke_report_chart_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_chart_mcp.call_tool("build_scan_report_charts", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Report Chart MCP did not return structured output")


async def report_mcp_specs() -> list[dict[str, Any]]:
    from app.mcp.report_markdown import markdown_mcp_spec
    from app.mcp.report_mermaid import mermaid_mcp_spec
    from app.mcp.report_pdf import pdf_mcp_spec
    from app.mcp.report_excel import excel_mcp_spec
    from app.mcp.report_sarif import sarif_mcp_spec
    from app.mcp.report_template import template_mcp_spec
    from app.mcp.translation import translation_mcp_spec
    from app.mcp.report_word import word_mcp_spec

    tools = await report_chart_mcp.list_tools()
    chart_spec = {
        "id": "report-chart",
        "name": report_chart_mcp.name,
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
    return [
        await translation_mcp_spec(),
        await template_mcp_spec(),
        chart_spec,
        await sarif_mcp_spec(),
        await mermaid_mcp_spec(),
        await markdown_mcp_spec(),
        await word_mcp_spec(),
        await excel_mcp_spec(),
        await pdf_mcp_spec(),
    ]


def _scan_facts(scan_data: dict[str, Any], source_kind: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if source_kind == "agent_task":
        task = scan_data.get("task") if isinstance(scan_data.get("task"), dict) else scan_data
        result = task.get("result") if isinstance(task.get("result"), dict) else {}
        findings: list[dict[str, Any]] = []
        language_results = result.get("language_results") if isinstance(result.get("language_results"), dict) else {}
        for language_result in language_results.values():
            if not isinstance(language_result, dict):
                continue
            findings.extend(item for item in language_result.get("findings") or [] if isinstance(item, dict))
            findings.extend(item for item in language_result.get("review_findings") or [] if isinstance(item, dict))
        return [], findings
    records = [item for item in scan_data.get("records") or [] if isinstance(item, dict)]
    static_analysis = scan_data.get("static_analysis") if isinstance(scan_data.get("static_analysis"), dict) else {}
    findings = [item for item in static_analysis.get("findings") or [] if isinstance(item, dict)]
    return records, findings


def _severity(value: Any) -> str:
    clean = str(value or "UNKNOWN").strip().upper()
    if clean in {"CRITICAL", "SEVERE"}:
        return "CRITICAL"
    if clean in {"HIGH", "ERROR"}:
        return "HIGH"
    if clean in {"MEDIUM", "MODERATE", "WARNING"}:
        return "MEDIUM"
    if clean in {"LOW", "INFO"}:
        return "LOW"
    return "UNKNOWN"


def _component_label(record: dict[str, Any]) -> str:
    components = [item for item in record.get("components") or [] if isinstance(item, dict)]
    if not components:
        return ""
    component = components[0]
    return str(component.get("name") or component.get("package") or "").strip()


def _risk_label(value: str) -> str:
    return value.replace("_", " ").replace("-", " ").strip().title() or "Code finding"


def _code_block(finding: dict[str, Any], index: int) -> ReportCodeBlock | None:
    raw_lines = finding.get("snippet_lines")
    if not isinstance(raw_lines, list) or not raw_lines:
        return None
    lines: list[ReportCodeLine] = []
    for item in raw_lines:
        if not isinstance(item, dict):
            return None
        try:
            number = int(item.get("number"))
        except (TypeError, ValueError):
            return None
        if number <= 0:
            return None
        lines.append(
            ReportCodeLine(
                number=number,
                text=str(item.get("text") or ""),
                is_risk=bool(item.get("is_risk")),
            )
        )
    sink = finding.get("sink") if isinstance(finding.get("sink"), dict) else {}
    file_name = str(finding.get("file_name") or finding.get("file") or sink.get("file") or "source").strip()
    finding_id = str(finding.get("id") or finding.get("rule_id") or f"finding-{index}").strip()
    return ReportCodeBlock(
        finding_id=finding_id,
        language=str(finding.get("language") or "").strip(),
        file_name=file_name or "source",
        line_start=lines[0].number,
        line_end=lines[-1].number,
        risk_line=next((line.number for line in lines if line.is_risk), None),
        source=str(finding.get("snippet_source") or "scan_evidence"),
        lines=lines,
    )


def main() -> None:
    report_chart_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
