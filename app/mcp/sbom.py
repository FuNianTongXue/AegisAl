from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import xlsxwriter
from mcp.server.fastmcp import FastMCP

from app.assistant_artifacts import (
    AssistantArtifact,
    XLSX_MEDIA_TYPE,
)
from app.mcp.artifacts import stage_output_artifact
from app.privacy import severity_cn
from app.sbom import canonical_sbom_json, localized_intelligence_source
from app.storage import now_iso


def __getattr__(name: str) -> Any:
    """Lazy compatibility only; MCP execution never imports Host artifact stores."""

    if name in {"SBOMArtifactStore", "artifact_store"}:
        from app.assistant_artifacts import SBOMArtifactStore, sbom_artifact_store

        return SBOMArtifactStore if name == "SBOMArtifactStore" else sbom_artifact_store
    raise AttributeError(name)


_EXCEL_CELL_LIMIT = 32_000
_CJK_PATTERN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
_CHINA_TIMEZONE = ZoneInfo("Asia/Shanghai")


sbom_excel_mcp = FastMCP(
    "SecFlow SBOM Excel MCP",
    instructions=(
        "Consume canonical CycloneDX-compatible JSON with project-license evidence and optional vulnerability-match JSON, "
        "then create an auditable XLSX workbook without querying or mutating source facts."
    ),
)


@sbom_excel_mcp.tool(
    name="export_project_sbom_excel",
    description="Create an auditable five-sheet XLSX workbook from fixed SBOM, project-license, and vulnerability-match JSON.",
    structured_output=True,
)
def export_project_sbom_excel(
    sbom_json: str,
    matching_json: str = "{}",
    project_name: str = "project",
    generated_at: str = "",
    *,
    output_dir: str,
) -> AssistantArtifact:
    sbom = json.loads(sbom_json)
    matching = json.loads(matching_json or "{}")
    _validate_sbom_payload(sbom)
    if not isinstance(matching, dict):
        raise ValueError("漏洞匹配 JSON 必须是对象")
    timestamp = str(generated_at or (sbom.get("metadata") or {}).get("timestamp") or now_iso())
    content = build_sbom_workbook(sbom, matching)
    file_name = f"SecFlow-{_safe_file_part(project_name)}-SBOM.xlsx"
    reference = stage_output_artifact(
        output_dir,
        file_name=file_name,
        payload=content,
        media_type=XLSX_MEDIA_TYPE,
    )
    return AssistantArtifact(
        file_name=file_name,
        sha256=reference.sha256,
        size=len(content),
        generated_at=timestamp,
        artifacts=[reference.model_dump(mode="json")],
    )


def build_sbom_workbook(sbom: dict[str, Any], matching: dict[str, Any]) -> bytes:
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {"in_memory": True, "constant_memory": False})
    workbook.set_properties(
        {
            "title": "SecFlow Project SBOM",
            "subject": "CycloneDX-compatible software bill of materials, license identification, and vulnerability matching",
            "author": "SecFlow SBOM Agent",
            "comments": "Generated from canonical JSON supplied to the SBOM Excel MCP.",
        }
    )
    formats = _workbook_formats(workbook)
    components = [item for item in sbom.get("components") or [] if isinstance(item, dict)]
    vulnerabilities = [item for item in sbom.get("vulnerabilities") or [] if isinstance(item, dict)]
    licenses = _project_license_records(sbom)
    _write_summary_sheet(workbook, formats, sbom, matching, len(components), len(licenses), len(vulnerabilities))
    _write_components_sheet(workbook, formats, components)
    _write_licenses_sheet(workbook, formats, licenses)
    _write_vulnerabilities_sheet(workbook, formats, vulnerabilities, components)
    _write_audit_sheet(workbook, formats, sbom, matching)
    workbook.close()
    return output.getvalue()


def invoke_sbom_excel_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(sbom_excel_mcp.call_tool("export_project_sbom_excel", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("MCP tool export_project_sbom_excel did not return structured output")


async def sbom_mcp_specs() -> list[dict[str, Any]]:
    tools = await sbom_excel_mcp.list_tools()
    return [
        {
            "id": "sbom-excel",
            "name": sbom_excel_mcp.name,
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
    ]


def _validate_sbom_payload(sbom: Any) -> None:
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("SBOM JSON 必须是 CycloneDX 兼容对象")
    if not isinstance(sbom.get("components"), list):
        raise ValueError("SBOM JSON 缺少 components 数组")


def _workbook_formats(workbook: xlsxwriter.Workbook) -> dict[str, Any]:
    return {
        "title": workbook.add_format(
            {"bold": True, "font_size": 18, "font_color": "#FFFFFF", "bg_color": "#1B2440", "align": "left", "valign": "vcenter"}
        ),
        "section": workbook.add_format(
            {"bold": True, "font_size": 12, "font_color": "#1B2440", "bg_color": "#E8EAED", "border": 0, "valign": "vcenter"}
        ),
        "header": workbook.add_format(
            {"bold": True, "font_color": "#FFFFFF", "bg_color": "#1B2440", "border": 1, "border_color": "#D8DCE3", "text_wrap": True, "valign": "vcenter"}
        ),
        "label": workbook.add_format({"bold": True, "font_color": "#1F2937", "bg_color": "#F7F8FA", "border": 1, "border_color": "#E8EAED"}),
        "value": workbook.add_format({"font_color": "#1F2937", "border": 1, "border_color": "#E8EAED", "text_wrap": True, "valign": "top"}),
        "body": workbook.add_format({"font_color": "#1F2937", "border": 1, "border_color": "#E8EAED", "text_wrap": True, "valign": "top"}),
        "datetime": workbook.add_format(
            {
                "font_color": "#1F2937",
                "border": 1,
                "border_color": "#E8EAED",
                "num_format": "yyyy:mm:dd:hh:mm",
                "valign": "top",
            }
        ),
        "mono": workbook.add_format({"font_name": "SFMono-Regular", "font_size": 9, "font_color": "#1F2937", "border": 1, "border_color": "#E8EAED", "text_wrap": True, "valign": "top"}),
        "warning": workbook.add_format({"font_color": "#9A6700", "bg_color": "#FFF6D8", "border": 1, "border_color": "#E8EAED"}),
        "success": workbook.add_format({"font_color": "#067647", "bg_color": "#E8F8F0", "border": 1, "border_color": "#E8EAED"}),
        "critical": workbook.add_format({"font_color": "#B42318", "bg_color": "#FEE4E2", "border": 1, "border_color": "#E8EAED"}),
        "high": workbook.add_format({"font_color": "#B54708", "bg_color": "#FEF0C7", "border": 1, "border_color": "#E8EAED"}),
        "medium": workbook.add_format({"font_color": "#9A6700", "bg_color": "#FFF6D8", "border": 1, "border_color": "#E8EAED"}),
        "low": workbook.add_format({"font_color": "#067647", "bg_color": "#E8F8F0", "border": 1, "border_color": "#E8EAED"}),
    }


def _write_summary_sheet(
    workbook: xlsxwriter.Workbook,
    formats: dict[str, Any],
    sbom: dict[str, Any],
    matching: dict[str, Any],
    component_count: int,
    license_count: int,
    vulnerability_count: int,
) -> None:
    sheet = workbook.add_worksheet("摘要")
    sheet.hide_gridlines(2)
    sheet.set_column("A:A", 24)
    sheet.set_column("B:B", 58)
    sheet.merge_range("A1:B2", "SecFlow 项目 SBOM", formats["title"])
    sheet.set_row(0, 26)
    metadata = sbom.get("metadata") if isinstance(sbom.get("metadata"), dict) else {}
    project = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    rows = [
        ("项目", project.get("name") or "project"),
        ("SBOM 格式", f"{sbom.get('bomFormat')} {sbom.get('specVersion')}"),
        ("序列号", sbom.get("serialNumber") or ""),
        ("生成时间", metadata.get("timestamp") or ""),
        ("组件总数", None),
        ("项目许可数量", None),
        ("许可识别覆盖", _property_value(metadata.get("properties"), "secflow:licenseCoverage") or "not_requested"),
        ("OSI 接口状态", _property_value(metadata.get("properties"), "secflow:licenseRegistryStatus") or "not_requested"),
        ("版本未解析组件", _matching_or_property(matching, sbom, "unresolved_version_count", "secflow:unresolvedVersionCount")),
        ("是否匹配漏洞", "是" if matching else "否"),
        ("漏洞数量", None),
        ("命中组件", int(matching.get("matched_component_count") or 0)),
        ("匹配覆盖状态", str(matching.get("coverage_status") or "not_requested")),
        ("匹配批次失败", int(matching.get("failed_batch_count") or 0)),
        ("结果 SHA-256", _property_value(metadata.get("properties"), "secflow:resultSha256")),
    ]
    for index, (label, value) in enumerate(rows, start=3):
        sheet.write(index - 1, 0, label, formats["label"])
        if label == "组件总数":
            sheet.write_formula(index - 1, 1, "=COUNTA('SBOM 组件'!A2:A1048576)", formats["value"], component_count)
        elif label == "项目许可数量":
            sheet.write_formula(index - 1, 1, "=COUNTA('项目许可'!A2:A1048576)", formats["value"], license_count)
        elif label == "漏洞数量":
            sheet.write_formula(index - 1, 1, "=COUNTA('漏洞匹配'!A2:A1048576)", formats["value"], vulnerability_count)
        elif label == "生成时间":
            _write_china_datetime(sheet, index - 1, 1, value, formats)
        else:
            sheet.write(index - 1, 1, _safe_cell(value), formats["value"])
    sheet.freeze_panes(2, 0)


def _write_components_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], components: list[dict[str, Any]]) -> None:
    sheet = workbook.add_worksheet("SBOM 组件")
    sheet.hide_gridlines(2)
    headers = ["BOM Ref", "生态", "Group", "组件名称", "版本", "PURL", "来源文件", "来源类型", "置信度", "声明", "版本已解析"]
    widths = [30, 13, 24, 34, 18, 52, 42, 18, 12, 52, 13]
    for column, (header, width) in enumerate(zip(headers, widths, strict=True)):
        sheet.write(0, column, header, formats["header"])
        sheet.set_column(column, column, width)
    for row, component in enumerate(components, start=1):
        properties = _properties(component.get("properties"))
        values = [
            component.get("bom-ref"),
            properties.get("secflow:ecosystem"),
            component.get("group"),
            component.get("name"),
            component.get("version"),
            component.get("purl"),
            properties.get("secflow:sourceFile"),
            properties.get("secflow:sourceType"),
            properties.get("secflow:confidence"),
            properties.get("secflow:declaration"),
            properties.get("secflow:versionResolved"),
        ]
        for column, value in enumerate(values):
            cell_format = formats["warning"] if column in {4, 10} and str(values[10]).lower() != "true" else formats["body"]
            sheet.write(row, column, _safe_cell(value), cell_format)
    if components:
        sheet.add_table(0, 0, len(components), len(headers) - 1, {"name": "SecFlowSBOMComponents", "style": "Table Style Medium 2", "columns": [{"header": value} for value in headers]})
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, max(1, len(components)), len(headers) - 1) if not components else None


def _write_licenses_sheet(
    workbook: xlsxwriter.Workbook,
    formats: dict[str, Any],
    licenses: list[dict[str, Any]],
) -> None:
    sheet = workbook.add_worksheet("项目许可")
    sheet.hide_gridlines(2)
    headers = ["SPDX 标识", "许可名称", "置信度", "识别方式", "证据文件", "清单声明", "OSI 收录", "OSI 批准标记", "OSI 官方链接"]
    widths = [20, 38, 12, 28, 58, 46, 12, 18, 54]
    for column, (header, width) in enumerate(zip(headers, widths, strict=True)):
        sheet.write(0, column, header, formats["header"])
        sheet.set_column(column, column, width)
    for row, item in enumerate(licenses, start=1):
        osi = item.get("osi") if isinstance(item.get("osi"), dict) else {}
        approval_status = str(osi.get("approval_status") or "not_found")
        approval_label = {
            "approved": "接口标记已批准",
            "not_indicated": "接口未提供批准标记",
            "not_found": "OSI 接口未收录",
        }.get(approval_status, approval_status)
        values = [
            item.get("spdx_id"),
            item.get("name"),
            item.get("confidence"),
            "\n".join(str(value) for value in item.get("detection_methods") or []),
            "\n".join(str(value) for value in item.get("source_files") or []),
            "\n".join(str(value) for value in item.get("declarations") or []),
            "是" if osi.get("listed") else "否",
            approval_label,
            osi.get("official_url"),
        ]
        for column, value in enumerate(values):
            cell_format = formats["success"] if column == 6 and osi.get("listed") else formats["body"]
            sheet.write(row, column, _safe_cell(value), cell_format)
    if licenses:
        sheet.add_table(
            0,
            0,
            len(licenses),
            len(headers) - 1,
            {"name": "SecFlowProjectLicenses", "style": "Table Style Medium 2", "columns": [{"header": value} for value in headers]},
        )
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, max(1, len(licenses)), len(headers) - 1) if not licenses else None


def _write_vulnerabilities_sheet(
    workbook: xlsxwriter.Workbook,
    formats: dict[str, Any],
    vulnerabilities: list[dict[str, Any]],
    components: list[dict[str, Any]],
) -> None:
    sheet = workbook.add_worksheet("漏洞匹配")
    sheet.hide_gridlines(2)
    headers = ["漏洞编号", "风险等级", "CVSS", "影响组件", "修复版本", "发布时间", "更新时间", "情报来源", "参考链接", "漏洞描述"]
    widths = [22, 12, 10, 46, 32, 22, 22, 22, 52, 72]
    refs = {str(item.get("bom-ref") or ""): _component_label(item) for item in components}
    for column, (header, width) in enumerate(zip(headers, widths, strict=True)):
        sheet.write(0, column, header, formats["header"])
        sheet.set_column(column, column, width)
    for row, vulnerability in enumerate(vulnerabilities, start=1):
        properties = _properties(vulnerability.get("properties"))
        rating = next(iter(vulnerability.get("ratings") or []), {})
        severity_key = str(rating.get("severity") or "unknown").strip().casefold()
        affected = "; ".join(refs.get(str(item.get("ref") or ""), str(item.get("ref") or "")) for item in vulnerability.get("affects") or [])
        source = vulnerability.get("source") if isinstance(vulnerability.get("source"), dict) else {}
        values = [
            vulnerability.get("id"),
            severity_cn(severity_key),
            rating.get("score") if rating.get("score") is not None else "",
            affected,
            properties.get("secflow:fixedVersions"),
            properties.get("secflow:publishedAt"),
            properties.get("secflow:updatedAt"),
            localized_intelligence_source(source.get("name")),
            "\n".join(str(item.get("url") or "") for item in vulnerability.get("advisories") or []),
            _chinese_vulnerability_description(vulnerability, rating, properties),
        ]
        for column, value in enumerate(values):
            if column == 1:
                cell_format = formats.get(severity_key, formats["body"])
            else:
                cell_format = formats["body"]
            if column in {5, 6}:
                _write_china_datetime(sheet, row, column, value, formats)
            else:
                sheet.write(row, column, _safe_cell(value), cell_format)
    if vulnerabilities:
        sheet.add_table(0, 0, len(vulnerabilities), len(headers) - 1, {"name": "SecFlowSBOMVulnerabilities", "style": "Table Style Medium 2", "columns": [{"header": value} for value in headers]})
    sheet.freeze_panes(1, 0)
    sheet.autofilter(0, 0, max(1, len(vulnerabilities)), len(headers) - 1) if not vulnerabilities else None


def _write_audit_sheet(workbook: xlsxwriter.Workbook, formats: dict[str, Any], sbom: dict[str, Any], matching: dict[str, Any]) -> None:
    sheet = workbook.add_worksheet("来源与审计")
    sheet.hide_gridlines(2)
    sheet.set_column("A:A", 30)
    sheet.set_column("B:B", 90)
    sheet.write_row(0, 0, ["审计字段", "值"], formats["header"])
    canonical = canonical_sbom_json(sbom)
    matching_json = json.dumps(matching, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    source_status = matching.get("source_status") if isinstance(matching.get("source_status"), list) else []
    metadata = sbom.get("metadata") if isinstance(sbom.get("metadata"), dict) else {}
    metadata_properties = _properties(metadata.get("properties"))
    audit_rows: list[tuple[str, Any]] = [
        ("SBOM JSON SHA-256", hashlib.sha256(canonical.encode("utf-8")).hexdigest()),
        ("漏洞匹配 JSON SHA-256", hashlib.sha256(matching_json.encode("utf-8")).hexdigest() if matching else "未执行"),
        ("CycloneDX serialNumber", sbom.get("serialNumber") or ""),
        ("生成工具", "SecFlow SBOM Excel MCP / export_project_sbom_excel"),
        ("匹配覆盖状态", matching.get("coverage_status") or "not_requested"),
        ("匹配来源状态", json.dumps(source_status, ensure_ascii=False, sort_keys=True)),
        ("匹配错误", "\n".join(str(item) for item in matching.get("errors") or []) or "无"),
        ("许可识别覆盖", metadata_properties.get("secflow:licenseCoverage") or "not_requested"),
        ("OSI License API 状态", metadata_properties.get("secflow:licenseRegistryStatus") or "not_requested"),
        ("许可分析 SHA-256", metadata_properties.get("secflow:licenseAnalysisSha256") or "未执行"),
    ]
    audit_rows.extend((f"SBOM JSON {index + 1}", part) for index, part in enumerate(_chunks(canonical)))
    if matching:
        audit_rows.extend((f"漏洞匹配 JSON {index + 1}", part) for index, part in enumerate(_chunks(matching_json)))
    for row, (label, value) in enumerate(audit_rows, start=1):
        sheet.write(row, 0, label, formats["label"])
        sheet.write(row, 1, _safe_cell(value), formats["mono"])
    sheet.freeze_panes(1, 0)


def _project_license_records(sbom: dict[str, Any]) -> list[dict[str, Any]]:
    metadata = sbom.get("metadata") if isinstance(sbom.get("metadata"), dict) else {}
    project = metadata.get("component") if isinstance(metadata.get("component"), dict) else {}
    properties = _properties(project.get("properties"))
    records: list[dict[str, Any]] = []
    for choice in project.get("licenses") or []:
        if not isinstance(choice, dict):
            continue
        license_value = choice.get("license") if isinstance(choice.get("license"), dict) else {}
        license_id = str(license_value.get("id") or "").strip()
        name = str(license_value.get("name") or license_id).strip()
        raw_evidence = properties.get(f"secflow:license:{license_id or name}:evidence", "")
        try:
            evidence = json.loads(raw_evidence) if raw_evidence else {}
        except json.JSONDecodeError:
            evidence = {}
        osi = evidence.get("osi") if isinstance(evidence.get("osi"), dict) else {}
        if not osi.get("official_url") and str(license_value.get("url") or "").startswith("https://"):
            osi = {**osi, "official_url": str(license_value.get("url"))}
        records.append(
            {
                "spdx_id": license_id,
                "name": name,
                "confidence": float(evidence.get("confidence") or 0),
                "source_files": list(evidence.get("source_files") or []),
                "detection_methods": list(evidence.get("detection_methods") or []),
                "declarations": list(evidence.get("declarations") or []),
                "osi": osi,
            }
        )
    return records


def _matching_or_property(matching: dict[str, Any], sbom: dict[str, Any], key: str, property_name: str) -> Any:
    if key in matching:
        return matching.get(key)
    return _property_value(sbom.get("properties"), property_name)


def _property_value(values: Any, name: str) -> str:
    return _properties(values).get(name, "")


def _properties(values: Any) -> dict[str, str]:
    return {
        str(item.get("name") or ""): str(item.get("value") or "")
        for item in values or []
        if isinstance(item, dict) and str(item.get("name") or "")
    }


def _component_label(component: dict[str, Any]) -> str:
    group = str(component.get("group") or "")
    name = str(component.get("name") or "")
    version = str(component.get("version") or "")
    coordinate = f"{group}:{name}" if group else name
    return f"{coordinate}@{version}" if version else coordinate


def _chinese_vulnerability_description(
    vulnerability: dict[str, Any],
    rating: dict[str, Any],
    properties: dict[str, str],
) -> str:
    description = str(vulnerability.get("description") or "").strip()
    if description and _CJK_PATTERN.search(description):
        return description
    identifier = str(vulnerability.get("id") or "该漏洞").strip() or "该漏洞"
    severity = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
    }.get(str(rating.get("severity") or "").casefold(), "未知等级")
    score = rating.get("score")
    score_text = f"CVSS 评分为 {score}。" if score not in {None, ""} else ""
    fixed = str(properties.get("secflow:fixedVersions") or "").strip()
    fixed_text = f"建议升级到已确认的修复版本：{fixed}。" if fixed else "请核验受影响组件版本并持续跟进厂商安全版本。"
    return f"{identifier} 是一个{severity}组件漏洞。{score_text}{fixed_text}"


def _china_datetime(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    parsed: datetime | None = None
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text)
    except ValueError:
        for pattern in ("%Y:%m:%d:%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, pattern)
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(_CHINA_TIMEZONE).replace(tzinfo=None)


def _write_china_datetime(
    sheet: xlsxwriter.worksheet.Worksheet,
    row: int,
    column: int,
    value: Any,
    formats: dict[str, Any],
) -> None:
    parsed = _china_datetime(value)
    if parsed is None:
        sheet.write_blank(row, column, None, formats["datetime"])
        return
    sheet.write_datetime(row, column, parsed, formats["datetime"])


def _safe_cell(value: Any) -> Any:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    text = str(value if value is not None else "")[:_EXCEL_CELL_LIMIT]
    if text.startswith(("=", "+", "-", "@")):
        return f"'{text}"
    return text


def _chunks(value: str) -> list[str]:
    return [value[index : index + _EXCEL_CELL_LIMIT] for index in range(0, len(value), _EXCEL_CELL_LIMIT)] or [""]


def _safe_file_part(value: Any) -> str:
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-")
    return clean[:120] or "project"


def _safe_excel_name(value: str) -> str:
    name = Path(str(value or "SecFlow-project-SBOM.xlsx")).name
    stem = _safe_file_part(Path(name).stem)
    return f"{stem}.xlsx"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the SecFlow SBOM Excel MCP server over stdio.")
    parser.parse_args()
    sbom_excel_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
