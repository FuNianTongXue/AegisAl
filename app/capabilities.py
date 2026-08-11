from __future__ import annotations

import platform
import re
from pathlib import Path
from typing import Any

from app.langgraph.multi_agent_graph import AGENT_MANIFESTS
from app.mcp.code_scan import code_scan_mcp_spec
from app.mcp.component_query import component_mcp_specs
from app.mcp.license_scan import license_scan_mcp_spec
from app.mcp.report_charts import report_mcp_specs
from app.mcp.sbom import sbom_mcp_specs
from app.storage import now_iso


_SKILLS_ROOT = Path(__file__).resolve().parent / "resources" / "skills"


async def built_in_capability_catalog() -> dict[str, Any]:
    """Read installed capabilities from executable registries instead of duplicating them in the UI."""

    mcp_servers = [
        await code_scan_mcp_spec(),
        await license_scan_mcp_spec(),
        *await component_mcp_specs(),
        *await sbom_mcp_specs(),
        *await report_mcp_specs(),
    ]
    normalized_servers: list[dict[str, Any]] = []
    seen: set[str] = set()
    for server in mcp_servers:
        server_id = str(server.get("id") or server.get("name") or "").strip()
        if not server_id or server_id in seen:
            continue
        seen.add(server_id)
        tools = [item for item in server.get("tools") or [] if isinstance(item, dict)]
        normalized_servers.append(
            {
                "id": server_id,
                "name": str(server.get("name") or server_id),
                "transport": str(server.get("transport") or "in-process"),
                "tool_count": len(tools),
                "tools": [
                    {
                        "name": str(item.get("name") or ""),
                        "description": str(item.get("description") or ""),
                    }
                    for item in tools
                ],
            }
        )
    agents = [manifest.as_dict() for manifest in AGENT_MANIFESTS]
    skills = _skill_catalog()
    return {
        "schema_version": "secflow.client-capabilities/v1",
        "generated_at": now_iso(),
        "platform": {
            "system": platform.system(),
            "architecture": platform.machine(),
            "adapter": "windows" if platform.system() == "Windows" else "macos" if platform.system() == "Darwin" else "generic",
        },
        "summary": {
            "agent_count": len(agents),
            "mcp_server_count": len(normalized_servers),
            "mcp_tool_count": sum(item["tool_count"] for item in normalized_servers),
            "skill_count": len(skills),
        },
        "agents": agents,
        "mcp_servers": normalized_servers,
        "skills": skills,
    }


def _skill_catalog() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    if not _SKILLS_ROOT.is_dir():
        return result
    for path in sorted(_SKILLS_ROOT.glob("*/SKILL.md")):
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        frontmatter = content.split("---", 2)[1] if content.startswith("---") and content.count("---") >= 2 else ""
        name_match = re.search(r"(?m)^name:\s*(.+?)\s*$", frontmatter)
        description_match = re.search(r"(?m)^description:\s*(.+?)\s*$", frontmatter)
        result.append(
            {
                "id": path.parent.name,
                "name": name_match.group(1).strip() if name_match else path.parent.name,
                "description": description_match.group(1).strip() if description_match else "",
                "source": "built-in",
            }
        )
    return result
