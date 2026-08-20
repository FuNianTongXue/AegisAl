from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import math
import os
import re
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from app.mcp.artifacts import MCPArtifactReference, stage_output_artifact


class MermaidDiagram(BaseModel):
    id: str
    title: str
    kind: Literal["flowchart", "pie"]
    source: str
    source_sha256: str
    image_media_type: Literal["image/jpeg"] = "image/jpeg"
    image_base64: str = ""
    artifact_index: int | None = None
    image_sha256: str
    width: int
    height: int
    node_count: int
    render_status: Literal["rendered"] = "rendered"


class MermaidReportOutput(BaseModel):
    schema_version: int = 2
    renderer: Literal["secflow-mermaid-jpeg-v2"] = "secflow-mermaid-jpeg-v2"
    diagrams: list[MermaidDiagram]
    artifacts: list[MCPArtifactReference] = Field(default_factory=list)
    input_sha256: str
    chart_sha256: str
    taint_path_count: int
    taint_node_count: int


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
    sarif: dict[str, Any] | None = None,
    language: str = "zh-Hans",
    *,
    output_dir: str,
) -> MermaidReportOutput:
    from app.reports import validate_scan_result_json

    scan_json = validate_scan_result_json(report_json)
    charts = _json_value(report_charts or {})
    input_sha256 = str((scan_json.get("audit") or {}).get("payload_sha256") or "")
    chart_input_sha256 = str(charts.get("input_sha256") or "")
    if chart_input_sha256 and chart_input_sha256 != input_sha256:
        raise ValueError("Report chart input hash does not match scan JSON")
    sarif_payload = _json_value(sarif or {})
    sarif_input_sha256 = str(sarif_payload.get("input_sha256") or "")
    if sarif_input_sha256 and sarif_input_sha256 != input_sha256:
        raise ValueError("SARIF input hash does not match scan JSON")
    sarif_document = sarif_payload.get("sarif") if isinstance(sarif_payload.get("sarif"), dict) else {}
    taint_paths = _sarif_taint_paths(sarif_document)
    diagrams: list[MermaidDiagram] = []
    for index, path in enumerate(taint_paths, start=1):
        title = _taint_title(path, index, language)
        diagrams.append(
            _rendered_diagram(
                f"taint-flow-{index}",
                title,
                "flowchart",
                _taint_flow_source(path, language),
                charts,
                language,
                taint_path=path,
            )
        )
    if not diagrams:
        flow_source = _flowchart_source(charts, language)
        diagrams.append(
            _rendered_diagram(
                "finding-relationships",
                _labels(language)["relationships"],
                "flowchart",
                flow_source,
                charts,
                language,
            )
        )
    severity_source = _severity_source(charts, language)
    if severity_source:
        diagrams.append(
            _rendered_diagram(
                "severity-distribution",
                _labels(language)["severity"],
                "pie",
                severity_source,
                charts,
                language,
            )
        )
    artifact_references: list[MCPArtifactReference] = []
    staged_diagrams: list[MermaidDiagram] = []
    for diagram in diagrams:
        payload = base64.b64decode(diagram.image_base64, validate=True)
        reference = stage_output_artifact(
            output_dir,
            file_name=f"{diagram.id}.jpg",
            payload=payload,
            media_type=diagram.image_media_type,
        )
        artifact_references.append(reference)
        staged_diagrams.append(
            diagram.model_copy(
                update={"image_base64": "", "artifact_index": len(artifact_references) - 1}
            )
        )
    diagrams = staged_diagrams
    return MermaidReportOutput(
        diagrams=diagrams,
        artifacts=artifact_references,
        input_sha256=input_sha256,
        chart_sha256=_sha256_json(charts),
        taint_path_count=len(taint_paths),
        taint_node_count=sum(len(path.get("locations") or []) for path in taint_paths),
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


def _rendered_diagram(
    diagram_id: str,
    title: str,
    kind: Literal["flowchart", "pie"],
    source: str,
    charts: dict[str, Any],
    language: str,
    *,
    taint_path: dict[str, Any] | None = None,
) -> MermaidDiagram:
    payload, width, height = _render_mermaid_jpeg(kind, charts, language, taint_path=taint_path)
    if not payload.startswith(b"\xff\xd8\xff"):
        raise RuntimeError(f"Mermaid renderer produced an invalid JPEG: {diagram_id}")
    return MermaidDiagram(
        id=diagram_id,
        title=title,
        kind=kind,
        source=source,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
        image_base64=base64.b64encode(payload).decode("ascii"),
        image_sha256=hashlib.sha256(payload).hexdigest(),
        width=width,
        height=height,
        node_count=_diagram_node_count(kind, charts, taint_path),
    )


def _diagram_node_count(
    kind: Literal["flowchart", "pie"],
    charts: dict[str, Any],
    taint_path: dict[str, Any] | None,
) -> int:
    if taint_path is not None:
        return len([item for item in taint_path.get("locations") or [] if isinstance(item, dict)])
    if kind == "pie":
        return sum(
            1
            for item in charts.get("severity_ring") or []
            if isinstance(item, dict) and _positive_chart_value(item.get("value"))
        )
    count = len([item for item in charts.get("sankey_nodes") or [] if isinstance(item, dict)])
    return max(2, min(24, count))


def _positive_chart_value(value: Any) -> bool:
    try:
        return int(value or 0) > 0
    except (TypeError, ValueError):
        return False


def _render_mermaid_jpeg(
    kind: Literal["flowchart", "pie"],
    charts: dict[str, Any],
    language: str,
    *,
    taint_path: dict[str, Any] | None = None,
) -> tuple[bytes, int, int]:
    try:
        from PIL import Image, ImageDraw
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("Pillow is required for Mermaid report image rendering") from exc
    if taint_path:
        width = 1600
        height = _taint_canvas_height(taint_path, width)
    elif kind == "pie":
        width, height = 1000, 560
    else:
        node_count = max(2, min(24, len([item for item in charts.get("sankey_nodes") or [] if isinstance(item, dict)])))
        width, height = 1200, max(430, min(1280, 190 + math.ceil(node_count / 3) * 120))
    image = Image.new("RGB", (width, height), "#F7F8FA")
    draw = ImageDraw.Draw(image)
    title_font = _image_font(30, bold=True)
    body_font = _image_font(20)
    small_font = _image_font(16)
    labels = _labels(language)
    heading = (
        _taint_title(taint_path, int(taint_path.get("path_index") or 1), language)
        if taint_path
        else labels["severity"] if kind == "pie" else labels["relationships"]
    )
    draw.text((48, 34), heading, fill="#172033", font=title_font)
    if taint_path:
        _draw_taint_flow(draw, taint_path, language, body_font, small_font, width)
    elif kind == "pie":
        _draw_severity_pie(draw, charts, language, body_font, small_font)
    else:
        _draw_relationship_flow(draw, charts, language, body_font, small_font, width, height)
    buffer = io.BytesIO()
    image.save(buffer, format="JPEG", quality=90, optimize=True, progressive=True)
    return buffer.getvalue(), width, height


def _sarif_taint_paths(sarif: dict[str, Any]) -> list[dict[str, Any]]:
    paths: list[dict[str, Any]] = []
    runs = [item for item in sarif.get("runs") or [] if isinstance(item, dict)]
    for run in runs:
        for result_index, result in enumerate(run.get("results") or []):
            if not isinstance(result, dict):
                continue
            result_title = str((result.get("message") or {}).get("text") or result.get("ruleId") or "Finding")
            for code_flow_index, code_flow in enumerate(result.get("codeFlows") or []):
                if not isinstance(code_flow, dict):
                    continue
                for thread_flow_index, thread_flow in enumerate(code_flow.get("threadFlows") or []):
                    if not isinstance(thread_flow, dict):
                        continue
                    locations = [
                        _normalized_sarif_location(item, location_index)
                        for location_index, item in enumerate(thread_flow.get("locations") or [])
                        if isinstance(item, dict)
                    ]
                    if not locations:
                        continue
                    paths.append(
                        {
                            "rule_id": str(result.get("ruleId") or "secflow"),
                            "title": result_title,
                            "code_flow_index": code_flow_index,
                            "thread_flow_index": thread_flow_index,
                            "locations": locations,
                            "path_index": len(paths) + 1,
                        }
                    )
    return paths


def _normalized_sarif_location(item: dict[str, Any], index: int) -> dict[str, Any]:
    location = item.get("location") if isinstance(item.get("location"), dict) else {}
    physical = location.get("physicalLocation") if isinstance(location.get("physicalLocation"), dict) else {}
    artifact = physical.get("artifactLocation") if isinstance(physical.get("artifactLocation"), dict) else {}
    region = physical.get("region") if isinstance(physical.get("region"), dict) else {}
    kinds = [str(value) for value in item.get("kinds") or [] if str(value).strip()]
    role = kinds[0] if kinds else str((location.get("properties") or {}).get("secflowRole") or "propagation")
    label = str((location.get("message") or {}).get("text") or (item.get("state") or {}).get("secflowLabel", {}).get("text") or role)
    return {
        "order": int(item.get("executionOrder") or index + 1),
        "role": role,
        "file": str(artifact.get("uri") or "unknown"),
        "line": int(region.get("startLine") or 0),
        "label": label,
        "snippet": str((region.get("snippet") or {}).get("text") or ""),
    }


def _taint_flow_source(path: dict[str, Any], language: str) -> str:
    lines = ["flowchart TD"]
    locations = [item for item in path.get("locations") or [] if isinstance(item, dict)]
    for index, location in enumerate(locations):
        role = _localized_role(str(location.get("role") or "propagation"), language)
        file_name = str(location.get("file") or "unknown")
        line = int(location.get("line") or 0)
        label = str(location.get("label") or role)
        snippet = str(location.get("snippet") or "").strip()
        location_text = f"{file_name}:{line}" if line else file_name
        node_parts = [f"{index + 1}. {role}", location_text, label]
        if snippet and snippet not in label:
            node_parts.append(snippet)
        lines.append(f'  n{index}["{_escape_taint_label(node_parts)}"]')
        if index:
            lines.append(f"  n{index - 1} --> n{index}")
    return "\n".join(lines)


def _draw_taint_flow(
    draw: Any,
    path: dict[str, Any],
    language: str,
    body_font: Any,
    small_font: Any,
    width: int,
) -> None:
    locations = [item for item in path.get("locations") or [] if isinstance(item, dict)]
    box_left, box_right = 70, width - 70
    gap, y = 48, 115
    role_colors = {
        "source": ("#E8F3FF", "#2E77B8"),
        "sink": ("#FFF0F0", "#D9363E"),
        "sanitizer": ("#EAF8F1", "#2D9D78"),
        "propagation": ("#FFFFFF", "#7A91A8"),
    }
    for index, location in enumerate(locations):
        role = str(location.get("role") or "propagation")
        fill, outline = role_colors.get(role, role_colors["propagation"])
        role_text = _localized_role(role, language)
        file_name = str(location.get("file") or "unknown")
        line = int(location.get("line") or 0)
        location_text = f"{file_name}:{line}" if line else file_name
        label = str(location.get("label") or role_text)
        snippet = str(location.get("snippet") or "").strip()
        detail_parts = [label]
        if snippet and snippet not in label:
            detail_parts.append(snippet)
        detail_lines: list[str] = []
        for detail in detail_parts:
            detail_lines.extend(_wrap_taint_text(detail, 128))
        box_height = 76 + max(1, len(detail_lines)) * 24
        draw.rounded_rectangle((box_left, y, box_right, y + box_height), radius=12, fill=fill, outline=outline, width=3)
        draw.text((box_left + 24, y + 16), f"{index + 1}. [{role_text}] {location_text}", fill="#172033", font=body_font)
        detail_y = y + 54
        for detail_line in detail_lines:
            draw.text((box_left + 24, detail_y), detail_line, fill="#52677F", font=small_font)
            detail_y += 24
        if index < len(locations) - 1:
            x = width / 2
            draw.line((x, y + box_height, x, y + box_height + gap - 9), fill="#7A91A8", width=4)
            draw.polygon([(x, y + box_height + gap), (x - 10, y + box_height + gap - 13), (x + 10, y + box_height + gap - 13)], fill="#7A91A8")
        y += box_height + gap


def _taint_canvas_height(path: dict[str, Any], width: int) -> int:
    del width
    height = 150
    for location in path.get("locations") or []:
        if not isinstance(location, dict):
            continue
        label = str(location.get("label") or location.get("role") or "propagation")
        snippet = str(location.get("snippet") or "").strip()
        lines = _wrap_taint_text(label, 128)
        if snippet and snippet not in label:
            lines.extend(_wrap_taint_text(snippet, 128))
        height += 76 + max(1, len(lines)) * 24 + 48
    return max(520, height)


def _wrap_taint_text(value: str, width: int) -> list[str]:
    normalized = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    for raw_line in normalized.split("\n") or [""]:
        expanded = raw_line.expandtabs(4)
        if not expanded:
            lines.append(" ")
            continue
        lines.extend(expanded[index : index + width] for index in range(0, len(expanded), width))
    return lines or ["-"]


def _escape_taint_label(parts: list[str]) -> str:
    clean_parts: list[str] = []
    for part in parts:
        normalized = str(part or "").replace("\r\n", "\n").replace("\r", "\n")
        clean_parts.append(normalized.replace("\n", "<br/>").strip())
    return "<br/>".join(clean_parts).replace("\\", "\\\\").replace('"', "'").replace("|", "/")


def _taint_title(path: dict[str, Any] | None, index: int, language: str) -> str:
    path = path or {}
    title = str(path.get("title") or path.get("rule_id") or "Taint flow")
    if str(language).lower().startswith("zh"):
        return f"污点路径 {index}：{title}"
    return f"Taint path {index}: {title}"


def _localized_role(role: str, language: str) -> str:
    if not str(language).lower().startswith("zh"):
        return role
    return {"source": "污染源", "sink": "危险汇", "sanitizer": "净化节点", "propagation": "传播节点"}.get(role, role)


def _draw_relationship_flow(
    draw: Any,
    charts: dict[str, Any],
    language: str,
    body_font: Any,
    small_font: Any,
    width: int,
    height: int,
) -> None:
    nodes = [dict(item) for item in charts.get("sankey_nodes") or [] if isinstance(item, dict)][:24]
    links = [dict(item) for item in charts.get("sankey_links") or [] if isinstance(item, dict)][:36]
    if not nodes:
        labels = _labels(language)
        nodes = [{"id": "scan", "label": labels["scan"]}, {"id": "report", "label": labels["report"]}]
        links = [{"source": "scan", "target": "report", "type": "生成" if str(language).lower().startswith("zh") else "generates"}]
    columns = min(3, max(2, len(nodes)))
    rows = math.ceil(len(nodes) / columns)
    box_width = min(300, int((width - 120 - (columns - 1) * 70) / columns))
    box_height = 70
    x_gap = (width - 96 - columns * box_width) / max(1, columns - 1)
    y_gap = max(34, (height - 155 - rows * box_height) / max(1, rows - 1))
    positions: dict[str, tuple[float, float, float, float]] = {}
    for index, node in enumerate(nodes):
        column, row = index % columns, index // columns
        x = 48 + column * (box_width + x_gap)
        y = 115 + row * (box_height + y_gap)
        positions[str(node.get("id") or f"node-{index}")] = (x, y, x + box_width, y + box_height)
    for link in links:
        source = positions.get(str(link.get("source") or ""))
        target = positions.get(str(link.get("target") or ""))
        if not source or not target:
            continue
        x1, y1 = source[2], (source[1] + source[3]) / 2
        x2, y2 = target[0], (target[1] + target[3]) / 2
        if x2 <= x1:
            x1, y1 = (source[0] + source[2]) / 2, source[3]
            x2, y2 = (target[0] + target[2]) / 2, target[1]
        draw.line((x1, y1, x2, y2), fill="#7A91A8", width=3)
        angle = math.atan2(y2 - y1, x2 - x1)
        arrow = 11
        points = [
            (x2, y2),
            (x2 - arrow * math.cos(angle - 0.5), y2 - arrow * math.sin(angle - 0.5)),
            (x2 - arrow * math.cos(angle + 0.5), y2 - arrow * math.sin(angle + 0.5)),
        ]
        draw.polygon(points, fill="#7A91A8")
        relation = _short_text(link.get("type") or ("关联" if str(language).lower().startswith("zh") else "related"), 18)
        draw.text(((x1 + x2) / 2 + 5, (y1 + y2) / 2 - 20), relation, fill="#52677F", font=small_font)
    for index, node in enumerate(nodes):
        box = positions[str(node.get("id") or f"node-{index}")]
        draw.rounded_rectangle(box, radius=10, fill="#FFFFFF", outline="#B9CEDB", width=3)
        label = _short_text(node.get("label") or node.get("id") or "-", 34)
        lines = _wrap_label(label, 17)
        total_height = len(lines) * 24
        y = (box[1] + box[3] - total_height) / 2
        for line in lines:
            bounds = draw.textbbox((0, 0), line, font=body_font)
            text_width = bounds[2] - bounds[0]
            draw.text(((box[0] + box[2] - text_width) / 2, y), line, fill="#1B5E86", font=body_font)
            y += 24


def _draw_severity_pie(draw: Any, charts: dict[str, Any], language: str, body_font: Any, small_font: Any) -> None:
    values: list[tuple[str, int, str]] = []
    colors = {"CRITICAL": "#D9363E", "HIGH": "#F06B32", "MEDIUM": "#E5A000", "LOW": "#2D9D78", "UNKNOWN": "#7A91A8"}
    names = _labels(language)["severity_names"]
    for item in charts.get("severity_ring") or []:
        if not isinstance(item, dict):
            continue
        severity = str(item.get("severity") or item.get("id") or "UNKNOWN").upper()
        value = max(0, int(item.get("value") or 0))
        if value:
            values.append((str(names.get(severity) or severity), value, colors.get(severity, colors["UNKNOWN"])))
    if not values:
        values = [("无已确认漏洞" if str(language).lower().startswith("zh") else "No confirmed findings", 1, "#D7E4EB")]
    total = sum(item[1] for item in values)
    box = (80, 120, 500, 540)
    start = -90.0
    for name, value, color in values:
        end = start + (value / total) * 360.0
        draw.pieslice(box, start=start, end=end, fill=color, outline="#FFFFFF", width=3)
        start = end
    draw.ellipse((205, 245, 375, 415), fill="#F7F8FA")
    center = str(total if any(color != "#D7E4EB" for _, _, color in values) else 0)
    bounds = draw.textbbox((0, 0), center, font=body_font)
    draw.text((290 - (bounds[2] - bounds[0]) / 2, 315), center, fill="#172033", font=body_font)
    y = 145
    for name, value, color in values:
        draw.rounded_rectangle((585, y + 4, 613, y + 32), radius=5, fill=color)
        percentage = (value / total * 100) if total else 0
        draw.text((632, y), f"{name}  {value}  {percentage:.1f}%", fill="#26364D", font=small_font)
        y += 58


def _image_font(size: int, *, bold: bool = False) -> Any:
    from PIL import ImageFont

    candidates = [
        Path("/System/Library/Fonts/PingFang.ttc"),
        Path("/System/Library/Fonts/LanguageSupport/PingFang.ttc"),
        *sorted(Path("/System/Library/AssetsV2/com_apple_MobileAsset_Font8").glob("*.asset/AssetData/PingFang.ttc")),
        Path("/System/Library/Fonts/STHeiti Medium.ttc" if bold else "/System/Library/Fonts/STHeiti Light.ttc"),
        Path("/System/Library/Fonts/Supplemental/Arial Unicode.ttf"),
        Path("/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc"),
        Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts" / ("msyhbd.ttc" if bold else "msyh.ttc"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
    ]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return ImageFont.truetype(str(candidate), size=size)
        except (OSError, ValueError):
            continue
    return ImageFont.load_default(size=size)


def _short_text(value: Any, limit: int) -> str:
    clean = " ".join(str(value or "").split())
    return clean if len(clean) <= limit else clean[: max(1, limit - 1)] + "…"


def _wrap_label(value: str, width: int) -> list[str]:
    return [value[index : index + width] for index in range(0, len(value), width)][:3] or ["-"]


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
    clean = re.sub(r"\s+", " ", str(value or "")).strip()
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
