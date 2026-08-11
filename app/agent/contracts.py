from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


AgentStatus = Literal["completed", "waiting", "failed"]


@dataclass(frozen=True)
class AgentManifest:
    """Auditable capability and tool boundary for one specialist agent."""

    agent_id: str
    label: str
    description: str
    capabilities: tuple[str, ...]
    tool_allowlist: tuple[str, ...]
    can_start_tasks: bool = False
    can_mutate_global_analysis: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.agent_id,
            "label": self.label,
            "description": self.description,
            "capabilities": list(self.capabilities),
            "tool_allowlist": list(self.tool_allowlist),
            "can_start_tasks": self.can_start_tasks,
            "can_mutate_global_analysis": self.can_mutate_global_analysis,
        }


@dataclass(frozen=True)
class AgentHandoff:
    source_agent: str
    target_agent: str
    reason: str
    intent: str

    def as_dict(self) -> dict[str, str]:
        return {
            "source_agent": self.source_agent,
            "target_agent": self.target_agent,
            "reason": self.reason,
            "intent": self.intent,
        }


@dataclass
class AgentExecution:
    """Result envelope shared by every specialist agent."""

    agent_id: str
    status: AgentStatus
    answer: dict[str, Any] | None = None
    next_agent: str = "result_aggregator_agent"
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def audit_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent_id,
            "status": self.status,
            "next_agent": self.next_agent,
            "errors": list(self.errors),
        }
