from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
from typing import Any, Literal

import xlsxwriter
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from app.privacy import severity_cn
from app.reports import validate_report_document_json


class ExcelReportOutput(BaseModel):
    schema_version: Literal[1] = 1
    media_type: Literal["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"] = (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    renderer: Literal["xlsxwriter-enterprise-report"] = "xlsxwriter-enterprise-report"
    artifact_base64: str
    input_sha256: str
    output_sha256: str
    artifact_size: int
    sheet_count: int


report_excel_mcp = FastMCP(
    "SecFlow Excel MCP",
    instructions="Render enterprise XLSX reports only from validated SecFlow canonical report JSON.",
)


@report_excel_mcp.tool(
    name="render_excel_report",
    description="Render a styled Excel workbook with summary, findings, inventory, licenses and audit sheets.",
    structured_output=True,
)
def render_excel_report(report_document: dict[str, Any]) -> ExcelReportOutput:
    document = validate_report_document_json(report_document)
    source_hash = str(((document.get("source") or {}).get("audit") or {}).get("payload_sha256") or "")
    payload, sheet_count = _build_xlsx(document)
    return ExcelReportOutput(
        artifact_base64=base64.b64encode(payload).decode("ascii"),
        input_sha256=source_hash,
        output_sha256=hashlib.sha256(payload).hexdigest(),
        artifact_size=len(payload),
        sheet_count=sheet_count,
    )


def invoke_report_excel_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_excel_mcp.call_tool("render_excel_report", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Excel MCP did not return structured output")


async def excel_mcp_spec() -> dict[str, Any]:
    tools = await report_excel_mcp.list_tools()
    return {
        "id": "report-excel",
        "name": report_excel_mcp.name,
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


def _build_xlsx(document: dict[str, Any]) -> tuple[bytes, int]:
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True})
    workbook.set_properties({"title": str((document.get("summary") or {}).get("title") or "SecFlow Security Report"), "company": "SecFlow"})
    formats = _formats(workbook, document.get("template") or {})
    source = document.get("source") or {}
    facts = source.get("facts") or {}
    _summary_sheet(workbook, formats, document)
    _findings_sheet(workbook, formats, facts)
    _inventory_sheet(workbook, formats, facts.get("dependencies") or [])
    _licenses_sheet(workbook, formats, facts.get("licenses") or [])
    _audit_sheet(workbook, formats, document)
    workbook.close()
    return output.getvalue(), 5


def _formats(workbook: xlsxwriter.Workbook, template: dict[str, Any]) -> dict[str, Any]:
    tokens = template.get("style_tokens") if isinstance(template.get("style_tokens"), dict) else {}
    fonts = template.get("fonts") if isinstance(template.get("fonts"), dict) else {}
    body_font = str(fonts.get("body") or "PingFang SC")
    primary = str(tokens.get("primary") or "#112C53")
    accent = str(tokens.get("accent") or "#0BA3C4")
    return {
        "title": workbook.add_format({"bold": True, "font_name": body_font, "font_size": 20, "font_color": "#FFFFFF", "bg_color": primary, "align": "left", "valign": "vcenter"}),
        "section": workbook.add_format({"bold": True, "font_name": body_font, "font_size": 12, "font_color": "#FFFFFF", "bg_color": accent, "valign": "vcenter"}),
        "header": workbook.add_format({"bold": True, "font_name": body_font, "font_color": "#FFFFFF", "bg_color": primary, "border": 1, "border_color": "#D9E3EA", "text_wrap": True}),
        "label": workbook.add_format({"bold": True, "font_name": body_font, "bg_color": "#F3F6F8", "border": 1, "border_color": "#D9E3EA"}),
        "body": workbook.add_format({"font_name": body_font, "border": 1, "border_color": "#D9E3EA", "text_wrap": True, "valign": "top"}),
        "integer": workbook.add_format({"font_name": body_font, "border": 1, "border_color": "#D9E3EA", "num_format": "0"}),
        "critical": workbook.add_format({"font_name": body_font, "font_color": "#FFFFFF", "bg_color": "#C62828", "border": 1}),
        "high": workbook.add_format({"font_name": body_font, "font_color": "#FFFFFF", "bg_color": "#E85D3F", "border": 1}),
        "medium": workbook.add_format({"font_name": body_font, "bg_color": "#F5A900", "border": 1}),
        "low": workbook.add_format({"font_name": body_font, "font_color": "#FFFFFF", "bg_color": "#2E8B57", "border": 1}),
    }


def _summary_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], document: dict[str, Any]) -> None:
    sheet = workbook.add_worksheet("报告总览")
    sheet.hide_gridlines(2)
    sheet.set_column("A:A", 24)
    sheet.set_column("B:F", 20)
    sheet.set_row(0, 34)
    sheet.merge_range("A1:F1", str((document.get("summary") or {}).get("title") or "SecFlow 企业安全报告"), formats["title"])
    statistics = document.get("statistics") if isinstance(document.get("statistics"), dict) else {}
    counts = statistics.get("counts") if isinstance(statistics.get("counts"), dict) else {}
    rows = [
        ("报告 Schema", document.get("$schema")),
        ("生成时间", document.get("generated_at")),
        ("项目", ((document.get("metadata") or {}).get("project_name") or (document.get("metadata") or {}).get("workspace_name") or "-")),
        ("依赖组件", counts.get("dependencies", 0)),
        ("组件漏洞", counts.get("dependency_vulnerabilities", 0)),
        ("代码发现", counts.get("code_findings", 0)),
        ("QA 状态", (document.get("qa") or {}).get("status") or "pending"),
        ("模板", (document.get("template") or {}).get("name") or "-"),
    ]
    for row, (label, value) in enumerate(rows, start=2):
        sheet.write(row, 0, label, formats["label"])
        sheet.merge_range(row, 1, row, 5, _excel_value(value), formats["body"])
    severity = statistics.get("severity") if isinstance(statistics.get("severity"), dict) else {}
    severity_keys = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
    sheet.write_row(12, 0, ["风险等级", *[severity_cn(key) for key in severity_keys]], formats["header"])
    sheet.write_row(13, 0, ["数量", *[int(severity.get(key, 0) or 0) for key in severity_keys]], formats["integer"])
    chart = workbook.add_chart({"type": "column"})
    chart.add_series({"name": "漏洞数量", "categories": "='报告总览'!$B$13:$F$13", "values": "='报告总览'!$B$14:$F$14", "fill": {"color": "#0BA3C4"}})
    chart.set_title({"name": "风险等级分布"})
    chart.set_legend({"none": True})
    sheet.insert_chart("A16", chart, {"x_scale": 1.25, "y_scale": 1.15})


def _findings_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], facts: dict[str, Any]) -> None:
    sheet = workbook.add_worksheet("风险发现")
    headers = ["ID", "类型", "风险等级", "标题", "位置/组件", "行号/版本", "修复建议"]
    sheet.write_row(0, 0, headers, formats["header"])
    rows: list[list[Any]] = []
    for item in facts.get("code_findings") or []:
        if isinstance(item, dict):
            rows.append([item.get("id") or item.get("rule_id") or "", "代码", item.get("severity") or "UNKNOWN", item.get("title") or item.get("message") or "", item.get("file_name") or item.get("file") or item.get("path") or "", item.get("line") or item.get("risk_line") or "", item.get("remediation") or ""])
    for item in facts.get("dependency_vulnerabilities") or []:
        if isinstance(item, dict):
            component = item.get("component") if isinstance(item.get("component"), dict) else {}
            rows.append([item.get("id") or item.get("cve_id") or "", "组件", item.get("severity") or "UNKNOWN", item.get("title") or item.get("summary") or "", component.get("name") or item.get("component_name") or "", component.get("version") or item.get("version") or "", item.get("remediation") or item.get("recommendation") or ""])
    for row_index, row in enumerate(rows, start=1):
        severity = str(row[2] or "UNKNOWN").lower()
        localized_row = [*row]
        localized_row[2] = severity_cn(row[2])
        sheet.write_row(row_index, 0, [_excel_value(value) for value in localized_row], formats["body"])
        if severity in formats:
            sheet.write(row_index, 2, localized_row[2], formats[severity])
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, max(1, len(rows)), len(headers) - 1)
    sheet.set_column("A:A", 22)
    sheet.set_column("B:C", 12)
    sheet.set_column("D:D", 38)
    sheet.set_column("E:E", 34)
    sheet.set_column("F:F", 16)
    sheet.set_column("G:G", 56)


def _inventory_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], dependencies: list[Any]) -> None:
    sheet = workbook.add_worksheet("组件清单")
    headers = ["组件", "版本", "生态", "来源文件", "PURL"]
    sheet.write_row(0, 0, headers, formats["header"])
    for row_index, item in enumerate((item for item in dependencies if isinstance(item, dict)), start=1):
        row = [item.get("name") or item.get("component") or item.get("package") or "", item.get("version") or "", item.get("ecosystem") or item.get("manager") or "", item.get("file") or item.get("source") or "", item.get("purl") or ""]
        sheet.write_row(row_index, 0, [_excel_value(value) for value in row], formats["body"])
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, max(1, len(dependencies)), len(headers) - 1)
    sheet.set_column("A:B", 28)
    sheet.set_column("C:C", 16)
    sheet.set_column("D:E", 42)


def _licenses_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], licenses: list[Any]) -> None:
    sheet = workbook.add_worksheet("许可证")
    headers = ["SPDX ID", "名称", "风险", "证据", "备注"]
    sheet.write_row(0, 0, headers, formats["header"])
    for row_index, item in enumerate((item for item in licenses if isinstance(item, dict)), start=1):
        evidence = item.get("evidence") or item.get("files") or item.get("sources") or ""
        if isinstance(evidence, list):
            evidence = ", ".join(str(value) for value in evidence)
        row = [item.get("spdx_id") or item.get("id") or "", item.get("name") or "", item.get("risk") or item.get("risk_level") or "", evidence, item.get("notes") or item.get("limitations") or ""]
        sheet.write_row(row_index, 0, [_excel_value(value) for value in row], formats["body"])
    sheet.freeze_panes(1, 0)
    sheet.set_column("A:C", 22)
    sheet.set_column("D:E", 48)


def _audit_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], document: dict[str, Any]) -> None:
    sheet = workbook.add_worksheet("审计记录")
    sheet.write_row(0, 0, ["字段", "值"], formats["header"])
    rows = [
        ("Report JSON SHA-256", (document.get("metadata") or {}).get("report_json_sha256") or ""),
        ("Source SHA-256", ((document.get("source") or {}).get("audit") or {}).get("payload_sha256") or ""),
        ("Template SHA-256", (document.get("template") or {}).get("output_sha256") or ""),
        ("QA Status", (document.get("qa") or {}).get("status") or "pending"),
        ("QA Score", (document.get("qa") or {}).get("score") or 0),
        ("Processors", ", ".join(str(value) for value in ((document.get("audit") or {}).get("processors") or []))),
    ]
    for row_index, row in enumerate(rows, start=1):
        sheet.write_row(row_index, 0, [_excel_value(value) for value in row], formats["body"])
    sheet.set_column("A:A", 26)
    sheet.set_column("B:B", 100)


def _excel_value(value: Any) -> str | int | float | bool:
    """Convert canonical JSON values to deterministic Excel cell scalars."""

    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
