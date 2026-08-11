from __future__ import annotations

import asyncio
import hashlib
import json
import platform as host_platform
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel


class ReportTemplateOutput(BaseModel):
    schema_version: Literal[1] = 1
    id: str
    name: str
    category: str
    platform: str
    language: str
    fonts: dict[str, str]
    style_tokens: dict[str, Any]
    layout: dict[str, Any]
    output_sha256: str


_TEMPLATES = {
    "security": ("安全审计标准模板", "Security"),
    "web3": ("Web3 安全模板", "Web3"),
    "devsecops": ("DevSecOps 模板", "DevSecOps"),
    "iso27001": ("ISO 27001 模板", "Compliance"),
    "pci-dss": ("PCI DSS 模板", "Compliance"),
    "soc2": ("SOC 2 模板", "Compliance"),
    "enterprise": ("企业品牌模板", "Enterprise"),
}


template_mcp = FastMCP(
    "SecFlow Template MCP",
    instructions="Resolve one immutable cross-format report template and platform font profile from local assets.",
)


@template_mcp.tool(
    name="resolve_report_template",
    description="Resolve a local enterprise report template shared by Markdown, HTML, Word, Excel and PDF renderers.",
    structured_output=True,
)
def resolve_report_template(
    template_id: str = "security",
    platform: str = "auto",
    language: str = "zh-Hans",
) -> ReportTemplateOutput:
    clean_id = str(template_id or "security").strip().lower()
    if clean_id not in _TEMPLATES:
        clean_id = "enterprise"
    resolved_platform = _platform_name(platform)
    name, category = _TEMPLATES[clean_id]
    fonts = _platform_fonts(resolved_platform)
    style_tokens = {
        "primary": "#112C53",
        "accent": "#0BA3C4",
        "critical": "#C62828",
        "high": "#E85D3F",
        "medium": "#F5A900",
        "low": "#2E8B57",
        "surface": "#FFFFFF",
        "surface_muted": "#F3F6F8",
        "text": "#15233A",
        "border": "#D9E3EA",
    }
    layout = {
        "profile": "secure-code-scan-v1",
        "page_size": "A4",
        "cover": True,
        "toc": True,
        "header": True,
        "footer": True,
        "page_numbers": True,
        "logo": "secflow-information-center",
        "chart_palette": ["#C62828", "#E85D3F", "#F5A900", "#2E8B57", "#0BA3C4"],
    }
    signed = {
        "id": clean_id,
        "name": name,
        "category": category,
        "platform": resolved_platform,
        "language": language,
        "fonts": fonts,
        "style_tokens": style_tokens,
        "layout": layout,
    }
    digest = hashlib.sha256(json.dumps(signed, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return ReportTemplateOutput(schema_version=1, output_sha256=digest, **signed)


def invoke_report_template_mcp(arguments: dict[str, Any]) -> dict[str, Any]:
    result = asyncio.run(template_mcp.call_tool("resolve_report_template", arguments))
    if isinstance(result, tuple) and len(result) == 2 and isinstance(result[1], dict):
        return dict(result[1])
    raise RuntimeError("Template MCP did not return structured output")


async def template_mcp_spec() -> dict[str, Any]:
    tools = await template_mcp.list_tools()
    return {
        "id": "report-template",
        "name": template_mcp.name,
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


def _platform_name(value: str) -> str:
    clean = str(value or "auto").strip().lower()
    if clean == "auto":
        clean = host_platform.system().lower()
    if clean.startswith("win"):
        return "windows"
    if clean in {"darwin", "mac", "macos"}:
        return "macos"
    return "generic"


def _platform_fonts(platform: str) -> dict[str, str]:
    if platform == "windows":
        return {
            "body": "Microsoft YaHei",
            "heading": "Microsoft YaHei UI",
            "code": "Cascadia Mono",
            "latin_body": "Segoe UI",
            "latin_heading": "Segoe UI Semibold",
        }
    if platform == "macos":
        return {
            "body": "PingFang SC",
            "heading": "PingFang SC",
            "code": "SFMono-Regular",
            "latin_body": "SF Pro Text",
            "latin_heading": "SF Pro Display",
        }
    return {
        "body": "Noto Sans CJK SC",
        "heading": "Noto Sans CJK SC",
        "code": "Noto Sans Mono",
        "latin_body": "Noto Sans",
        "latin_heading": "Noto Sans",
    }
