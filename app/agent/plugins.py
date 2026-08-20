"""Agent plugin declarations and factories.

The manifest, routing metadata, and implementation factory travel together as
one registry value. This lets a plugin add or replace an Agent without editing
the LangGraph supervisor's source routing table.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Literal, Mapping

from app.agent.contracts import AgentManifest
from app.agent.specialist_agents import (
    CodeScanAgent,
    GraphSpecialistAgent,
    ProjectContextAgent,
    SBOMAgent,
)
from app.agent.translation_agent import TranslationAgent
from app.plugins import (
    ExecutionMode,
    PluginContext,
    ReadOnlyRegistry,
    Registry,
    RegistryEntry,
    RegistryKeyError,
)


AGENT_REGISTRY = "agents"
AgentFactory = Callable[[AgentManifest], Any]
AgentRole = Literal["supervisor", "context", "specialist", "aggregator", "translation"]


@dataclass(frozen=True, slots=True)
class AgentDefinition:
    manifest: AgentManifest
    factory: AgentFactory
    role: AgentRole
    intents: tuple[str, ...] = ()
    requires_workspace: bool = False
    force_intent: str = ""

    @property
    def agent_id(self) -> str:
        return self.manifest.agent_id

    def instantiate(self) -> Any:
        value = self.factory(self.manifest)
        if value is None:
            raise RuntimeError(f"Agent factory returned no implementation: {self.agent_id}")
        return value

    def as_dict(self) -> dict[str, Any]:
        result = self.manifest.as_dict()
        result.update(
            {
                "role": self.role,
                "intents": list(self.intents),
                "requires_workspace": self.requires_workspace,
                "source": "plugin-registry",
            }
        )
        return result


class AgentRegistry:
    def __init__(
        self,
        registry: Registry | ReadOnlyRegistry | Mapping[str, RegistryEntry],
    ) -> None:
        self._registry = registry

    def _entries(self) -> Mapping[str, RegistryEntry]:
        if isinstance(self._registry, Mapping):
            return self._registry
        return self._registry.entries()

    @staticmethod
    def _validated_definition(key: str, entry: RegistryEntry) -> AgentDefinition:
        if entry.metadata.execution_mode is not ExecutionMode.IN_PROCESS:
            raise TypeError(f"Agent registry contribution is not Host executable: {key!r}")
        if entry.owner.trust.value == "untrusted":
            raise TypeError(f"Untrusted Agent contribution cannot execute in Host: {key!r}")
        value = entry.value
        if not isinstance(value, AgentDefinition):
            raise TypeError(f"Invalid Agent registry contribution: {key!r}")
        return value

    def definition(self, agent_id: str) -> AgentDefinition:
        key = str(agent_id or "").strip()
        if isinstance(self._registry, Mapping):
            entry = self._registry.get(key)
            if entry is None:
                raise RegistryKeyError(f"registry {AGENT_REGISTRY!r} has no key {key!r}")
        else:
            entry = self._registry.get_entry(key)
            if entry is None:
                raise RegistryKeyError(f"registry {AGENT_REGISTRY!r} has no key {key!r}")
        return self._validated_definition(key, entry)

    def instantiate(self, agent_id: str) -> Any:
        return self.definition(agent_id).instantiate()

    def definitions(self, *, role: AgentRole | None = None) -> tuple[AgentDefinition, ...]:
        values = []
        for key, entry in self._entries().items():
            definition = self._validated_definition(key, entry)
            if role is None or definition.role == role:
                values.append((key, definition))
        return tuple(value for _, value in sorted(values, key=lambda pair: pair[0]))

    def catalog(self) -> list[dict[str, Any]]:
        output = []
        for key, entry in self._entries().items():
            definition = self._validated_definition(key, entry)
            item = definition.as_dict()
            item.update(
                {
                    "plugin_id": entry.owner.plugin_id,
                    "plugin_version": entry.owner.version,
                    "generation": entry.owner.generation,
                }
            )
            output.append((key, item))
        return [item for _, item in sorted(output, key=lambda pair: pair[0])]

    def route(self, intent: str) -> AgentDefinition | None:
        for definition in self.definitions(role="specialist"):
            if intent in definition.intents:
                return definition
        return None


SUPERVISOR_MANIFEST = AgentManifest(
    agent_id="supervisor_agent",
    label="Supervisor Agent",
    description="Understand goals, plan capabilities, and make least-privilege handoffs.",
    capabilities=("semantic_planning", "agent_handoff", "termination"),
    tool_allowlist=("plan_assistant_intent", "handoff"),
)
PROJECT_CONTEXT_MANIFEST = AgentManifest(
    agent_id="project_context_agent",
    label="Project Context Agent",
    description="Recover and validate the current user's authorized local source workspace.",
    capabilities=("workspace_recovery", "project_memory"),
    tool_allowlist=("encrypted_project_links", "agent_task_store"),
)
CODE_SCAN_MANIFEST = AgentManifest(
    agent_id="code_scan_agent",
    label="Code Scan Agent",
    description="Create project scan tasks and invoke the code scan state machine.",
    capabilities=("project_scan", "project_rescan", "scan_result_follow_up"),
    tool_allowlist=("task_agent_graph", "mcp__code_scan__scan_language"),
    can_start_tasks=True,
)
COMPONENT_MANIFEST = AgentManifest(
    agent_id="component_agent",
    label="Component Intelligence Agent",
    description="Verify one component version or produce a dated vulnerability catalog.",
    capabilities=("component_vulnerability_query", "component_vulnerability_catalog"),
    tool_allowlist=(
        "mcp__component_detail__build_component_vulnerability_detail",
        "mcp__excel__export_component_vulnerabilities",
        "mcp__excel__export_component_vulnerability_catalog",
        "mcp__d3_sankey__build_component_sankey",
    ),
)
SBOM_MANIFEST = AgentManifest(
    agent_id="sbom_agent",
    label="SBOM Agent",
    description="Generate project SBOM, identify licenses, and match dependency vulnerabilities.",
    capabilities=("project_sbom_export", "license_inventory"),
    tool_allowlist=(
        "sbom_graph",
        "license_scan_mcp",
        "mcp__license_scan__identify_project_licenses",
        "mcp__sbom_excel__export_project_sbom_excel",
    ),
)
INTELLIGENCE_MANIFEST = AgentManifest(
    agent_id="intelligence_agent",
    label="Vulnerability Intelligence Agent",
    description="Query and organize vulnerability facts, date ranges, and security knowledge.",
    capabilities=("vulnerability_lookup", "vulnerability_year_lookup", "security_knowledge"),
    tool_allowlist=("intelligence_query", "knowledge_graph"),
)
REPORT_MANIFEST = AgentManifest(
    agent_id="report_agent",
    label="Report Agent",
    description="Generate confirmed multi-format reports from immutable scan JSON.",
    capabilities=("report_generate", "report_download"),
    tool_allowlist=(
        "report_graph",
        "mcp__report_chart__build_scan_report_charts",
        "mcp__report_template__resolve_report_template",
        "mcp__report_sarif__build_scan_sarif",
        "mcp__report_mermaid__build_report_mermaid",
        "mcp__report_markdown__render_markdown_report",
        "mcp__report_word__render_word_report",
        "mcp__report_excel__render_excel_report",
        "mcp__report_pdf__render_pdf_report",
    ),
)
CONVERSATION_MANIFEST = AgentManifest(
    agent_id="conversation_agent",
    label="Security Conversation Agent",
    description="Handle security questions, clarification, and identity without project tools.",
    capabilities=("llm_direct", "identity", "clarification"),
    tool_allowlist=("configured_llm", "long_term_memory"),
)
RESULT_AGGREGATOR_MANIFEST = AgentManifest(
    agent_id="result_aggregator_agent",
    label="Result Aggregator Agent",
    description="Merge specialist results and finalize the public audit envelope.",
    capabilities=("result_merge", "audit_finalize"),
    tool_allowlist=("public_payload_filter",),
)
TRANSLATION_MANIFEST = AgentManifest(
    agent_id="translation_agent",
    label="Translation Agent",
    description="Translate structured Agent JSON through the translation MCP boundary.",
    capabilities=("json_translation", "response_localization"),
    tool_allowlist=("mcp__translation__translate_json_payload",),
)


def _graph_agent(manifest: AgentManifest) -> GraphSpecialistAgent:
    return GraphSpecialistAgent(manifest)


def _report_agent(manifest: AgentManifest) -> GraphSpecialistAgent:
    return GraphSpecialistAgent(manifest, force_intent="report_operation")


def _translation_agent(_manifest: AgentManifest) -> TranslationAgent:
    return TranslationAgent()


def _supervisor_agent(_manifest: AgentManifest) -> Any:
    from app.langgraph.multi_agent_graph import AssistantMultiAgentSupervisor

    return AssistantMultiAgentSupervisor()


def _aggregator_agent(manifest: AgentManifest) -> "ResultAggregatorAgent":
    return ResultAggregatorAgent(manifest)


class ResultAggregatorAgent:
    """Instantiable implementation used by the supervisor's aggregation node."""

    def __init__(self, manifest: AgentManifest) -> None:
        self.manifest = manifest

    @staticmethod
    def aggregate(answer: dict[str, Any]) -> dict[str, Any]:
        from app.privacy import public_answer_payload

        return public_answer_payload(dict(answer))


BUILTIN_AGENT_DEFINITIONS = (
    AgentDefinition(SUPERVISOR_MANIFEST, _supervisor_agent, "supervisor"),
    AgentDefinition(PROJECT_CONTEXT_MANIFEST, ProjectContextAgent, "context"),
    AgentDefinition(
        CODE_SCAN_MANIFEST,
        CodeScanAgent,
        "specialist",
        intents=("project_scan", "project_rescan", "scan_result_follow_up"),
        requires_workspace=True,
    ),
    AgentDefinition(
        COMPONENT_MANIFEST,
        _graph_agent,
        "specialist",
        intents=("component_vulnerability_query", "component_vulnerability_catalog"),
    ),
    AgentDefinition(
        SBOM_MANIFEST,
        SBOMAgent,
        "specialist",
        intents=("project_sbom_export", "sbom_result_follow_up"),
        requires_workspace=True,
    ),
    AgentDefinition(
        INTELLIGENCE_MANIFEST,
        _graph_agent,
        "specialist",
        intents=("vulnerability_lookup", "vulnerability_year_lookup"),
    ),
    AgentDefinition(
        REPORT_MANIFEST,
        _report_agent,
        "specialist",
        intents=("report_operation",),
        force_intent="report_operation",
    ),
    AgentDefinition(
        CONVERSATION_MANIFEST,
        _graph_agent,
        "specialist",
        intents=("llm_direct", "identity", "clarification"),
    ),
    AgentDefinition(RESULT_AGGREGATOR_MANIFEST, _aggregator_agent, "aggregator"),
    AgentDefinition(TRANSLATION_MANIFEST, _translation_agent, "translation"),
)


def activate_builtin_agents(context: PluginContext) -> None:
    for definition in BUILTIN_AGENT_DEFINITIONS:
        context.register(
            AGENT_REGISTRY,
            definition.agent_id,
            definition,
            executable=True,
            execution_mode=ExecutionMode.IN_PROCESS,
            attributes={
                "role": definition.role,
                "intents": list(definition.intents),
                "tool_allowlist": list(definition.manifest.tool_allowlist),
            },
        )


def builtin_agent_code_fingerprints() -> dict[str, str]:
    """Pin Host Agent implementations, not only their display manifests."""

    app_root = Path(__file__).resolve().parents[1]
    paths = [*sorted((app_root / "agent").rglob("*.py")), app_root / "langgraph" / "multi_agent_graph.py"]
    return {
        path.relative_to(app_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
        if path.is_file()
    }


def default_agent_registry() -> AgentRegistry:
    from app.composition import secflow_runtime

    return AgentRegistry(ReadOnlyRegistry(secflow_runtime().manager.registry(AGENT_REGISTRY)))


AGENT_MANIFESTS = tuple(definition.manifest for definition in BUILTIN_AGENT_DEFINITIONS)


__all__ = [
    "AGENT_MANIFESTS",
    "AGENT_REGISTRY",
    "AgentDefinition",
    "AgentRegistry",
    "BUILTIN_AGENT_DEFINITIONS",
    "builtin_agent_code_fingerprints",
    "CODE_SCAN_MANIFEST",
    "COMPONENT_MANIFEST",
    "CONVERSATION_MANIFEST",
    "INTELLIGENCE_MANIFEST",
    "PROJECT_CONTEXT_MANIFEST",
    "REPORT_MANIFEST",
    "RESULT_AGGREGATOR_MANIFEST",
    "SBOM_MANIFEST",
    "SUPERVISOR_MANIFEST",
    "TRANSLATION_MANIFEST",
    "activate_builtin_agents",
    "default_agent_registry",
]
