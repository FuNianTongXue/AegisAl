from __future__ import annotations

import asyncio
import hashlib
import tempfile
from pathlib import Path
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

from app.mcp.artifacts import MCPArtifactReference, stage_output_artifact


class PDFReportOutput(BaseModel):
    schema_version: int = 1
    renderer: Literal["reportlab"] = "reportlab"
    artifacts: list[MCPArtifactReference] = Field(default_factory=list)
    media_type: Literal["application/pdf"] = "application/pdf"
    file_extension: Literal["pdf"] = "pdf"
    input_sha256: str
    output_sha256: str
    size: int


report_pdf_mcp = FastMCP(
    "SecFlow PDF MCP",
    instructions=(
        "Render verified SecFlow report JSON into a PDF. Preserve evidence code line breaks and line "
        "numbers, remediation, native chart summaries, Chinese labels, and China Standard Time."
    ),
)


@report_pdf_mcp.tool(
    name="render_pdf_report",
    description="Render verified SecFlow report JSON as a PDF artifact.",
    structured_output=True,
)
def render_pdf_report(
    report_document: dict[str, Any],
    mermaid: dict[str, Any] | None = None,
    *,
    output_dir: str,
) -> PDFReportOutput:
    from app.reports import render_report_pdf_file, validate_report_document_json

    document = validate_report_document_json(report_document)
    with tempfile.TemporaryDirectory(prefix="secflow-pdf-mcp-") as temp_dir:
        path = Path(temp_dir) / "report.pdf"
        render_report_pdf_file(path, document)
        payload = path.read_bytes()
    if not payload.startswith(b"%PDF"):
        raise RuntimeError("PDF MCP produced an invalid PDF header")
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    input_sha256 = str((source.get("audit") or {}).get("payload_sha256") or "")
    digest = hashlib.sha256(payload).hexdigest()
    artifacts = [
        stage_output_artifact(
            output_dir,
            file_name="SecFlow-security-report.pdf",
            payload=payload,
            media_type="application/pdf",
        )
    ]
    return PDFReportOutput(
        artifacts=artifacts,
        input_sha256=input_sha256,
        output_sha256=digest,
        size=len(payload),
    )


def invoke_report_pdf_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(report_pdf_mcp.call_tool("render_pdf_report", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("PDF MCP did not return structured output")


async def pdf_mcp_spec() -> dict[str, Any]:
    tools = await report_pdf_mcp.list_tools()
    return {
        "id": "report-pdf",
        "name": report_pdf_mcp.name,
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
    report_pdf_mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
