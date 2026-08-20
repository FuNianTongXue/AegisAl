from __future__ import annotations

import platform
from typing import Any

from app.agent.plugins import AGENT_REGISTRY, AgentRegistry
from app.composition import secflow_runtime
from app.mcp.protocol import MCP_SERVER_REGISTRY, MCPServerDefinition
from app.skills.runtime import SKILL_REGISTRY, SkillRegistry
from app.storage import now_iso


async def built_in_capability_catalog() -> dict[str, Any]:
    """Read installed capabilities from executable registries instead of duplicating them in the UI."""

    runtime = secflow_runtime()
    with runtime.pin() as snapshot:
        agents = AgentRegistry(snapshot.registries.get(AGENT_REGISTRY, {})).catalog()
        skills = SkillRegistry(snapshot.registries.get(SKILL_REGISTRY, {})).catalog()
        mcp_servers = [
            entry.value.as_dict()
            for _, entry in sorted(
                snapshot.registries.get(MCP_SERVER_REGISTRY, {}).items()
            )
            if isinstance(entry.value, MCPServerDefinition)
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
                "transport": str(server.get("transport") or "stdio"),
                "isolation": str(server.get("isolation") or "host-managed-child-process"),
                "plugin_id": str(server.get("plugin_id") or ""),
                "plugin_version": str(server.get("plugin_version") or ""),
                "generation": int(server.get("generation") or 0),
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
