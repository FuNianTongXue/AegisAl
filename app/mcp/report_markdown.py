from __future__ import annotations

import asyncio
import base64
import hashlib
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class MarkdownReportOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["secflow-markdown"] = "secflow-markdown"
    content: str
    media_type: Literal["text/markdown; charset=utf-8"] = "text/markdown; charset=utf-8"
    input_sha256: str
    output_sha256: str
    size: int
    diagram_count: int


report_markdown_mcp = FastMCP(
    "AegisAl Markdown MCP",
    instructions=(
        "Format an AegisAl report as Markdown from verified scan JSON, approved report text, chart data, "
        "and Mermaid MCP output. Preserve evidence code, line numbers, remediation, and source links."
    ),
)


@report_markdown_mcp.tool(
    name="render_markdown_report",
    description="Render an auditable Markdown report and embed Mermaid MCP diagrams.",
    structured_output=True,
)
def render_markdown_report(
    report_json: dict[str, Any],
    markdown: str,
    mermaid: dict[str, Any] | None = None,
    language: str = "zh-Hans",
) -> MarkdownReportOutput:
    from app.reports import validate_scan_result_json

    scan_json = validate_scan_result_json(report_json)
    input_sha256 = str((scan_json.get("audit") or {}).get("payload_sha256") or "")
    clean = str(markdown or "").strip()
    if not clean:
        raise ValueError("Markdown report content is empty")
    if not clean.startswith("# "):
        raise ValueError("Markdown report must start with a level-one title")

    mermaid_payload = mermaid if isinstance(mermaid, dict) else {}
    mermaid_input_sha256 = str(mermaid_payload.get("input_sha256") or "")
    if mermaid_input_sha256 and mermaid_input_sha256 != input_sha256:
        raise ValueError("Mermaid input hash does not match scan JSON")
    diagrams = [item for item in mermaid_payload.get("diagrams") or [] if isinstance(item, dict)]
    if diagrams:
        section_title = "可验证分析关系图" if str(language).lower().startswith("zh") else "Verified analysis diagrams"
        parts = [clean, "", f"## {section_title}", ""]
        for diagram in diagrams:
            source = str(diagram.get("source") or "").strip()
            image_base64 = str(diagram.get("image_base64") or "").strip()
            if not source or not image_base64:
                continue
            try:
                image_payload = base64.b64decode(image_base64, validate=True)
            except (ValueError, TypeError) as exc:
                raise ValueError("Mermaid MCP image is not valid base64") from exc
            media_type = str(diagram.get("image_media_type") or "image/jpeg")
            if media_type == "image/jpeg":
                valid_image = image_payload.startswith(b"\xff\xd8\xff")
                data_uri_type = "jpeg"
            elif media_type == "image/png":
                valid_image = image_payload.startswith(b"\x89PNG\r\n\x1a\n")
                data_uri_type = "png"
            else:
                raise ValueError("Mermaid MCP image media type is unsupported")
            if not valid_image:
                raise ValueError("Mermaid MCP image signature is invalid")
            if hashlib.sha256(image_payload).hexdigest() != str(diagram.get("image_sha256") or ""):
                raise ValueError("Mermaid MCP image hash verification failed")
            title = str(diagram.get("title") or "Diagram").strip()
            audit_source = base64.b64encode(source.encode("utf-8")).decode("ascii")
            parts.extend(
                [
                    f"### {title}",
                    "",
                    f"![{title}](data:image/{data_uri_type};base64,{image_base64})",
                    f"<!-- secflow-mermaid-source:{diagram.get('source_sha256') or ''}:{audit_source} -->",
                    "",
                ]
            )
        clean = "\n".join(parts).rstrip()
    content = clean + "\n"
    encoded = content.encode("utf-8")
    return MarkdownReportOutput(
        content=content,
        input_sha256=input_sha256,
        output_sha256=hashlib.sha256(encoded).hexdigest(),
        size=len(encoded),
        diagram_count=len(diagrams),
    )


def invoke_report_markdown_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_markdown_mcp.call_tool("render_markdown_report", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Markdown MCP did not return structured output")


async def markdown_mcp_spec() -> dict[str, Any]:
    tools = await report_markdown_mcp.list_tools()
    return {
        "id": "report-markdown",
        "name": report_markdown_mcp.name,
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


def main() -> None:
    report_markdown_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
