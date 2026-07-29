from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import re
import zipfile
from typing import Any, Literal
from xml.etree import ElementTree

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class WordReportOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["python-docx"] = "python-docx"
    artifact_base64: str
    media_type: Literal[
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    ] = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    file_extension: Literal["docx"] = "docx"
    input_sha256: str
    output_sha256: str
    size: int
    page_preset: Literal["standard_business_brief"] = "standard_business_brief"
    header_template: Literal["memo_masthead"] = "memo_masthead"


report_word_mcp = FastMCP(
    "SecFlow Word MCP",
    instructions=(
        "Render verified SecFlow report JSON into a real DOCX using the standard_business_brief "
        "preset and memo_masthead header. Preserve headings, real lists, explicit table geometry, "
        "evidence line breaks, remediation, Mermaid source, and audit hashes."
    ),
)


@report_word_mcp.tool(
    name="render_word_report",
    description="Render verified SecFlow report JSON as a Microsoft Word DOCX artifact.",
    structured_output=True,
)
def render_word_report(
    report_document: dict[str, Any],
    mermaid: dict[str, Any] | None = None,
) -> WordReportOutput:
    from app.reports import validate_report_document_json

    document = validate_report_document_json(report_document)
    payload = _build_docx(document, mermaid or {})
    if not payload.startswith(b"PK"):
        raise RuntimeError("Word MCP produced an invalid DOCX container")
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    input_sha256 = str((source.get("audit") or {}).get("payload_sha256") or "")
    return WordReportOutput(
        artifact_base64=base64.b64encode(payload).decode("ascii"),
        input_sha256=input_sha256,
        output_sha256=hashlib.sha256(payload).hexdigest(),
        size=len(payload),
    )


def invoke_report_word_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_word_mcp.call_tool("render_word_report", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Word MCP did not return structured output")


async def word_mcp_spec() -> dict[str, Any]:
    tools = await report_word_mcp.list_tools()
    return {
        "id": "report-word",
        "name": report_word_mcp.name,
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


def _build_docx(document: dict[str, Any], mermaid: dict[str, Any]) -> bytes:
    try:
        from docx import Document
        from docx.enum.style import WD_STYLE_TYPE
        from docx.enum.table import WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.oxml import OxmlElement
        from docx.oxml.ns import qn
        from docx.shared import Inches, Pt, RGBColor
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError("python-docx is required for Word export") from exc

    report = document["report"]
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    output = Document()
    section = output.sections[0]
    section.page_width = Inches(8.5)
    section.page_height = Inches(11)
    section.top_margin = Inches(0.8)
    section.bottom_margin = Inches(0.8)
    section.left_margin = Inches(1)
    section.right_margin = Inches(1)

    styles = output.styles
    _configure_style(styles["Normal"], "SF Pro Text", "PingFang SC", 10.5, RGBColor, qn, line_spacing=1.10, after=6)
    _configure_style(styles["Title"], "SF Pro Display", "PingFang SC", 23, RGBColor, qn, color="172033", bold=True, after=4)
    _configure_style(styles["Subtitle"], "SF Pro Text", "PingFang SC", 13, RGBColor, qn, color="52677F", after=12)
    heading_tokens = {
        "Heading 1": (16, "1B5E86", 16, 8),
        "Heading 2": (13, "1B5E86", 12, 6),
        "Heading 3": (11.5, "234F6A", 8, 4),
    }
    for name, (size, color, before, after) in heading_tokens.items():
        _configure_style(
            styles[name], "SF Pro Display", "PingFang SC", size, RGBColor, qn,
            color=color, bold=True, before=before, after=after, keep_with_next=True,
        )
    if "SecFlow Code" not in styles:
        code_style = styles.add_style("SecFlow Code", WD_STYLE_TYPE.PARAGRAPH)
    else:
        code_style = styles["SecFlow Code"]
    _configure_style(code_style, "SFMono-Regular", "PingFang SC", 8, RGBColor, qn, color="DCE6FF", after=0)

    header = section.header.paragraphs[0]
    header.alignment = WD_ALIGN_PARAGRAPH.LEFT
    header_run = header.add_run("SECFLOW  /  SECURITY SCAN REPORT")
    _set_run_font(header_run, "SF Pro Text", "PingFang SC", qn, size=8, color=RGBColor(98, 112, 137), bold=True)
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    footer_run = footer.add_run("SecFlow  |  ")
    _set_run_font(footer_run, "SF Pro Text", "PingFang SC", qn, size=8, color=RGBColor(114, 128, 150))
    _append_page_field(footer, OxmlElement, qn)

    title = output.add_paragraph(style="Title")
    title.add_run(str(report.get("project_name") or "SecFlow"))
    subtitle = output.add_paragraph(style="Subtitle")
    subtitle.add_run(str(report.get("title") or "安全扫描报告"))
    generated_at = str(document.get("generated_at") or "-")
    source_hash = str((document.get("audit") or {}).get("source_payload_sha256") or "-")
    for label, value in (
        ("Generated", generated_at),
        ("Source SHA-256", source_hash),
        ("Status", "Verified scan facts"),
    ):
        paragraph = output.add_paragraph()
        paragraph.paragraph_format.space_after = Pt(2)
        label_run = paragraph.add_run(f"{label}: ")
        _set_run_font(label_run, "SF Pro Text", "PingFang SC", qn, size=9, bold=True)
        value_run = paragraph.add_run(value)
        _set_run_font(value_run, "SF Pro Text", "PingFang SC", qn, size=9)
    _paragraph_bottom_border(output.add_paragraph(), OxmlElement, qn, "1B7899")

    metrics = report.get("metrics") if isinstance(report.get("metrics"), dict) else {}
    metric_table = output.add_table(rows=2, cols=4)
    metric_table.alignment = WD_TABLE_ALIGNMENT.LEFT
    metric_table.autofit = False
    metric_values = [
        ("严重/高危", metrics.get("high_risk", 0)),
        ("中危", metrics.get("medium_risk", 0)),
        ("依赖漏洞", metrics.get("dependency_vulnerabilities", 0)),
        ("代码发现", metrics.get("code_findings", 0)),
    ]
    for column, (label, value) in enumerate(metric_values):
        metric_table.cell(0, column).text = str(value)
        metric_table.cell(1, column).text = label
    _set_table_geometry(metric_table, [2340, 2340, 2340, 2340], OxmlElement, qn)
    _style_table(metric_table, OxmlElement, qn, RGBColor, header_rows=0, centered=True)

    for index, item in enumerate(report.get("sections") or [], start=1):
        if not isinstance(item, dict):
            continue
        output.add_heading(f"{index}. {str(item.get('title') or '').strip()}", level=1)
        _append_markdown(
            output,
            str(item.get("content") or ""),
            styles,
            OxmlElement,
            qn,
            RGBColor,
            WD_ALIGN_PARAGRAPH,
            WD_CELL_VERTICAL_ALIGNMENT,
            WD_TABLE_ALIGNMENT,
        )

    core = output.core_properties
    core.title = str(report.get("title") or "SecFlow 安全扫描报告")
    core.author = "SecFlow"
    core.subject = "Verified security scan report"
    core.keywords = "SecFlow, security, scan, report, MCP"
    buffer = io.BytesIO()
    output.save(buffer)
    return _add_ooxml_font_fallbacks(buffer.getvalue())


_WORDPROCESSINGML_NAMESPACE = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_OOXML_FONT_FALLBACKS = {
    "PingFang SC": "Arial Unicode MS",
    "SF Pro Display": "Arial",
    "SF Pro Text": "Arial",
    "SFMono-Regular": "Menlo",
}


def _add_ooxml_font_fallbacks(payload: bytes) -> bytes:
    """Keep the Apple font choices while giving non-Apple renderers safe aliases."""

    source = io.BytesIO(payload)
    target = io.BytesIO()
    with zipfile.ZipFile(source, mode="r") as archive, zipfile.ZipFile(
        target,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=6,
    ) as output:
        for entry in archive.infolist():
            content = archive.read(entry.filename)
            if entry.filename == "word/fontTable.xml":
                content = _patch_font_table(content)
            output.writestr(entry, content)
    return target.getvalue()


def _patch_font_table(content: bytes) -> bytes:
    namespace = _WORDPROCESSINGML_NAMESPACE
    ElementTree.register_namespace("w", namespace)
    root = ElementTree.fromstring(content)
    name_attribute = f"{{{namespace}}}name"
    value_attribute = f"{{{namespace}}}val"
    fonts = {
        str(node.get(name_attribute) or ""): node
        for node in root.findall(f"{{{namespace}}}font")
    }
    for preferred, fallback in _OOXML_FONT_FALLBACKS.items():
        font = fonts.get(preferred)
        if font is None:
            font = ElementTree.SubElement(root, f"{{{namespace}}}font", {name_attribute: preferred})
        alternative = font.find(f"{{{namespace}}}altName")
        if alternative is None:
            alternative = ElementTree.SubElement(font, f"{{{namespace}}}altName")
        alternative.set(value_attribute, fallback)
        family = font.find(f"{{{namespace}}}family")
        if family is None:
            family = ElementTree.SubElement(font, f"{{{namespace}}}family")
        family.set(value_attribute, "modern" if preferred == "SFMono-Regular" else "swiss")
        pitch = font.find(f"{{{namespace}}}pitch")
        if pitch is None:
            pitch = ElementTree.SubElement(font, f"{{{namespace}}}pitch")
        pitch.set(value_attribute, "fixed" if preferred == "SFMono-Regular" else "variable")
    return ElementTree.tostring(root, encoding="UTF-8", xml_declaration=True)


def _append_markdown(
    document: Any,
    markdown: str,
    styles: Any,
    OxmlElement: Any,
    qn: Any,
    RGBColor: Any,
    WD_ALIGN_PARAGRAPH: Any,
    WD_CELL_VERTICAL_ALIGNMENT: Any,
    WD_TABLE_ALIGNMENT: Any,
) -> None:
    lines = markdown.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped:
            index += 1
            continue
        if stripped.startswith("```"):
            language = stripped[3:].strip()
            code_lines: list[str] = []
            index += 1
            while index < len(lines) and not lines[index].strip().startswith("```"):
                code_lines.append(lines[index])
                index += 1
            _add_code_block(document, code_lines, language, styles, OxmlElement, qn, RGBColor)
            index += 1
            continue
        if stripped.startswith("|"):
            table_lines: list[str] = []
            while index < len(lines) and lines[index].strip().startswith("|"):
                table_lines.append(lines[index].strip())
                index += 1
            _add_markdown_table(
                document, table_lines, OxmlElement, qn, RGBColor,
                WD_CELL_VERTICAL_ALIGNMENT, WD_TABLE_ALIGNMENT,
            )
            continue
        heading = re.match(r"^(#{2,4})\s+(.+)$", stripped)
        if heading:
            document.add_heading(_plain_markdown(heading.group(2)), level=min(3, len(heading.group(1)) - 1))
        elif stripped.startswith("- "):
            paragraph = document.add_paragraph(style="List Bullet")
            paragraph.add_run(_plain_markdown(stripped[2:]))
        elif re.match(r"^\d+[.)]\s+", stripped):
            paragraph = document.add_paragraph(style="List Number")
            paragraph.add_run(_plain_markdown(re.sub(r"^\d+[.)]\s+", "", stripped)))
        elif stripped.startswith("> "):
            from docx.shared import Inches

            paragraph = document.add_paragraph()
            paragraph.paragraph_format.left_indent = Inches(0.25)
            run = paragraph.add_run(_plain_markdown(stripped[2:]))
            run.italic = True
            _shade_paragraph(paragraph, OxmlElement, qn, "EDF7FA")
        elif stripped != "---" and not stripped.startswith("<!--"):
            document.add_paragraph(_plain_markdown(stripped))
        index += 1


def _add_markdown_table(
    document: Any,
    lines: list[str],
    OxmlElement: Any,
    qn: Any,
    RGBColor: Any,
    WD_CELL_VERTICAL_ALIGNMENT: Any,
    WD_TABLE_ALIGNMENT: Any,
) -> None:
    rows = [_split_table_row(line) for line in lines]
    rows = [row for row in rows if row and not all(set(cell) <= {"-", ":", " "} for cell in row)]
    if not rows:
        return
    column_count = max(len(row) for row in rows)
    table = document.add_table(rows=len(rows), cols=column_count)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    table.autofit = False
    for row_index, row in enumerate(rows):
        for column_index in range(column_count):
            cell = table.cell(row_index, column_index)
            cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
            cell.text = _plain_markdown(row[column_index] if column_index < len(row) else "")
    if column_count == 2:
        widths = [2100, 7260]
    else:
        base = 9360 // column_count
        widths = [base] * column_count
        widths[-1] += 9360 - sum(widths)
    _set_table_geometry(table, widths, OxmlElement, qn)
    _style_table(table, OxmlElement, qn, RGBColor, header_rows=1, centered=False)


def _add_code_block(
    document: Any,
    lines: list[str],
    language: str,
    styles: Any,
    OxmlElement: Any,
    qn: Any,
    RGBColor: Any,
) -> None:
    if language.lower() == "mermaid":
        label = document.add_paragraph()
        label_run = label.add_run("Mermaid MCP")
        label_run.bold = True
        label_run.font.color.rgb = RGBColor(27, 120, 153)
    table = document.add_table(rows=1, cols=1)
    table.autofit = False
    _set_table_geometry(table, [9360], OxmlElement, qn)
    cell = table.cell(0, 0)
    _shade_cell(cell, OxmlElement, qn, "111936")
    paragraph = cell.paragraphs[0]
    paragraph.style = styles["SecFlow Code"]
    for offset, line in enumerate(lines):
        if offset:
            paragraph.add_run().add_break()
        paragraph.add_run(line or " ")


def _configure_style(
    style: Any,
    latin: str,
    east_asia: str,
    size: float,
    RGBColor: Any,
    qn: Any,
    *,
    color: str = "26364D",
    bold: bool = False,
    before: float = 0,
    after: float = 0,
    line_spacing: float | None = None,
    keep_with_next: bool = False,
) -> None:
    from docx.shared import Pt

    style.font.name = latin
    style.font.size = Pt(size)
    style.font.bold = bold
    style.font.color.rgb = RGBColor.from_string(color)
    style._element.rPr.rFonts.set(qn("w:ascii"), latin)
    style._element.rPr.rFonts.set(qn("w:hAnsi"), latin)
    style._element.rPr.rFonts.set(qn("w:eastAsia"), east_asia)
    style.paragraph_format.space_before = Pt(before)
    style.paragraph_format.space_after = Pt(after)
    if line_spacing is not None:
        style.paragraph_format.line_spacing = line_spacing
    style.paragraph_format.keep_with_next = keep_with_next


def _set_run_font(
    run: Any,
    latin: str,
    east_asia: str,
    qn: Any,
    *,
    size: float,
    color: Any | None = None,
    bold: bool = False,
) -> None:
    from docx.shared import Pt

    run.font.name = latin
    run.font.size = Pt(size)
    run.bold = bold
    if color is not None:
        run.font.color.rgb = color
    run._element.get_or_add_rPr().rFonts.set(qn("w:ascii"), latin)
    run._element.get_or_add_rPr().rFonts.set(qn("w:hAnsi"), latin)
    run._element.get_or_add_rPr().rFonts.set(qn("w:eastAsia"), east_asia)


def _set_table_geometry(table: Any, widths: list[int], OxmlElement: Any, qn: Any) -> None:
    table.autofit = False
    properties = table._tbl.tblPr
    width = properties.find(qn("w:tblW"))
    if width is None:
        width = OxmlElement("w:tblW")
        properties.append(width)
    width.set(qn("w:w"), str(sum(widths)))
    width.set(qn("w:type"), "dxa")
    grid = table._tbl.tblGrid
    for child in list(grid):
        grid.remove(child)
    for value in widths:
        column = OxmlElement("w:gridCol")
        column.set(qn("w:w"), str(value))
        grid.append(column)
    for row in table.rows:
        for index, cell in enumerate(row.cells):
            cell_width = widths[min(index, len(widths) - 1)]
            tc_width = cell._tc.get_or_add_tcPr().find(qn("w:tcW"))
            if tc_width is None:
                tc_width = OxmlElement("w:tcW")
                cell._tc.get_or_add_tcPr().append(tc_width)
            tc_width.set(qn("w:w"), str(cell_width))
            tc_width.set(qn("w:type"), "dxa")
            _set_cell_margins(cell, OxmlElement, qn)


def _set_cell_margins(cell: Any, OxmlElement: Any, qn: Any) -> None:
    properties = cell._tc.get_or_add_tcPr()
    margins = properties.find(qn("w:tcMar"))
    if margins is None:
        margins = OxmlElement("w:tcMar")
        properties.append(margins)
    for name, value in (("top", 80), ("bottom", 80), ("start", 120), ("end", 120)):
        node = margins.find(qn(f"w:{name}"))
        if node is None:
            node = OxmlElement(f"w:{name}")
            margins.append(node)
        node.set(qn("w:w"), str(value))
        node.set(qn("w:type"), "dxa")


def _style_table(
    table: Any,
    OxmlElement: Any,
    qn: Any,
    RGBColor: Any,
    *,
    header_rows: int,
    centered: bool,
) -> None:
    for row_index, row in enumerate(table.rows):
        for cell in row.cells:
            if row_index < header_rows:
                _shade_cell(cell, OxmlElement, qn, "F2F4F7")
            for paragraph in cell.paragraphs:
                if centered:
                    paragraph.alignment = 1
                for run in paragraph.runs:
                    run.font.size = __import__("docx").shared.Pt(9)
                    if row_index < header_rows:
                        run.bold = True
                    run.font.color.rgb = RGBColor(38, 54, 77)


def _shade_cell(cell: Any, OxmlElement: Any, qn: Any, fill: str) -> None:
    properties = cell._tc.get_or_add_tcPr()
    shading = properties.find(qn("w:shd"))
    if shading is None:
        shading = OxmlElement("w:shd")
        properties.append(shading)
    shading.set(qn("w:fill"), fill)


def _shade_paragraph(paragraph: Any, OxmlElement: Any, qn: Any, fill: str) -> None:
    properties = paragraph._p.get_or_add_pPr()
    shading = OxmlElement("w:shd")
    shading.set(qn("w:fill"), fill)
    properties.append(shading)


def _paragraph_bottom_border(paragraph: Any, OxmlElement: Any, qn: Any, color: str) -> None:
    properties = paragraph._p.get_or_add_pPr()
    borders = OxmlElement("w:pBdr")
    bottom = OxmlElement("w:bottom")
    bottom.set(qn("w:val"), "single")
    bottom.set(qn("w:sz"), "12")
    bottom.set(qn("w:space"), "6")
    bottom.set(qn("w:color"), color)
    borders.append(bottom)
    properties.append(borders)


def _append_page_field(paragraph: Any, OxmlElement: Any, qn: Any) -> None:
    run = paragraph.add_run()
    begin = OxmlElement("w:fldChar")
    begin.set(qn("w:fldCharType"), "begin")
    instruction = OxmlElement("w:instrText")
    instruction.set(qn("xml:space"), "preserve")
    instruction.text = " PAGE "
    end = OxmlElement("w:fldChar")
    end.set(qn("w:fldCharType"), "end")
    run._r.extend([begin, instruction, end])


def _split_table_row(value: str) -> list[str]:
    return [cell.strip().replace("\\|", "|").replace("<br>", "\n") for cell in value.strip().strip("|").split("|")]


def _plain_markdown(value: str) -> str:
    clean = re.sub(r"!\[([^]]*)\]\([^)]+\)", r"\1", str(value or ""))
    clean = re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", clean)
    clean = re.sub(r"`([^`]+)`", r"\1", clean)
    clean = re.sub(r"\*\*([^*]+)\*\*", r"\1", clean)
    return clean.replace("<br>", "\n").strip()


def main() -> None:
    report_word_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
