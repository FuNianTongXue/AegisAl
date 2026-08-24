"""Application composition built on the AegisAl plugin runtime.

This is the Python equivalent of the DeepSeek Harness composition tree: the
host owns one managed root, while Agent, Skill, and MCP packages contribute
through reversible plugin scopes. LangGraph remains a consumer of those
registries rather than becoming the plugin loader.
"""

from __future__ import annotations

from threading import RLock
from types import MappingProxyType
from typing import Any, Callable, Mapping

from app.agent.plugins import (
    BUILTIN_AGENT_DEFINITIONS,
    activate_builtin_agents,
    builtin_agent_code_fingerprints,
)
from app.mcp.protocol import (
    BUILTIN_MCP_SERVERS,
    MCP_PLUGIN_ID,
    MCPPluginService,
    activate_builtin_mcp,
)
from app.plugins import (
    GenerationLease,
    GenerationSnapshot,
    PluginDependency,
    PluginManager,
    PluginManifest,
    PluginState,
    TrustLevel,
)
from app.skills.runtime import activate_builtin_skills, builtin_skill_fingerprints


RUNTIME_SCHEMA_VERSION = "secflow.runtime/v1"
BUILTIN_SKILLS_PLUGIN = "secflow.skills"
BUILTIN_AGENTS_PLUGIN = "secflow.agents"


class SecFlowRuntime:
    """Own the composed plugin tree and expose generation-pinned snapshots."""

    def __init__(self, *, manager: PluginManager | None = None) -> None:
        self.manager = manager or PluginManager()
        self.mcp = MCPPluginService()
        self._lock = RLock()
        self._booted = False
        self._closed = False

    @property
    def booted(self) -> bool:
        with self._lock:
            return self._booted and not self._closed

    def boot(self) -> "SecFlowRuntime":
        with self._lock:
            if self._closed:
                raise RuntimeError("AegisAl plugin runtime is closed")
            if self._booted:
                return self
            self.manager.discover(
                PluginManifest(
                    plugin_id=MCP_PLUGIN_ID,
                    version="1.3.4",
                    trust=TrustLevel.BUILTIN,
                    config={
                        "local_transport": "stdio",
                        "remote_transport": "streamable-http",
                        "legacy_sse": False,
                        "contracts": {
                            definition.server_id: definition.contract_sha256
                            for definition in BUILTIN_MCP_SERVERS
                        },
                    },
                ),
                lambda context: activate_builtin_mcp(context, self.mcp),
            )
            self.manager.discover(
                PluginManifest(
                    plugin_id=BUILTIN_SKILLS_PLUGIN,
                    version="1.3.4",
                    trust=TrustLevel.BUILTIN,
                    config={
                        "root": "app/resources/skills",
                        "sha256": builtin_skill_fingerprints(),
                    },
                ),
                activate_builtin_skills,
            )
            self.manager.discover(
                PluginManifest(
                    plugin_id=BUILTIN_AGENTS_PLUGIN,
                    version="1.3.4",
                    trust=TrustLevel.BUILTIN,
                    dependencies=(
                        PluginDependency(BUILTIN_SKILLS_PLUGIN, ">=1.3,<2"),
                        PluginDependency(MCP_PLUGIN_ID, ">=1.3,<2"),
                    ),
                    config={
                        "architecture": "supervisor-specialists",
                        "agents": {
                            definition.agent_id: definition.as_dict()
                            for definition in BUILTIN_AGENT_DEFINITIONS
                        },
                        "code_sha256": builtin_agent_code_fingerprints(),
                    },
                ),
                self._activate_agents,
            )
            self.manager.load(BUILTIN_AGENTS_PLUGIN)
            self._booted = True
            return self

    def _activate_agents(self, context: Any) -> Callable[[], None]:
        activate_builtin_agents(context)
        for definition in BUILTIN_AGENT_DEFINITIONS:
            self.mcp.set_agent_allowlist(
                definition.agent_id,
                list(definition.manifest.tool_allowlist),
            )

        def cleanup() -> None:
            for definition in BUILTIN_AGENT_DEFINITIONS:
                self.mcp.remove_agent(definition.agent_id)

        return cleanup

    def pin(
        self, plugin_ids: str | tuple[str, ...] | list[str] | None = None
    ) -> GenerationLease:
        self.boot()
        return self.manager.pin_generation(plugin_ids)

    def snapshot(self) -> GenerationSnapshot:
        self.boot()
        return self.manager.snapshot()

    def task_pin(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        return task_plugin_state(snapshot)

    def validate_task_pin(
        self,
        value: Mapping[str, Any],
        *,
        snapshot: GenerationSnapshot | None = None,
    ) -> None:
        """Validate persisted plugin identity against one immutable generation.

        Callers recovering durable work should pass the snapshot returned by a
        generation lease.  This makes validation and execution refer to the
        same plugin generation even if new plugins are loaded concurrently.
        """

        if value.get("schema_version") != RUNTIME_SCHEMA_VERSION:
            raise ValueError("Task plugin state schema is invalid")
        expected_plugins = value.get("plugins")
        if not isinstance(expected_plugins, Mapping):
            raise ValueError("Task plugin state has no plugin map")
        active_snapshot = snapshot or self.snapshot()
        active = active_snapshot.plugins
        if set(expected_plugins) != set(active):
            raise RuntimeError("Pinned task plugin set changed")
        if int(value.get("runtime_generation") or 0) != active_snapshot.generation:
            raise RuntimeError("Pinned task runtime generation changed")
        for plugin_id, expected_value in expected_plugins.items():
            if not isinstance(expected_value, Mapping):
                raise ValueError(f"Invalid task plugin state for {plugin_id}")
            current = active.get(str(plugin_id))
            if current is None:
                raise RuntimeError(f"Pinned task plugin is unavailable: {plugin_id}")
            expected = (
                str(expected_value.get("version") or ""),
                int(expected_value.get("generation") or 0),
                str(expected_value.get("config_hash") or ""),
            )
            actual = (current.version, current.generation, current.config_hash)
            if expected != actual:
                raise RuntimeError(
                    f"Pinned task plugin changed: {plugin_id}; "
                    f"expected {expected[0]} generation {expected[1]}"
                )

    def close(self, *, timeout: float | None = 30.0) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        statuses = self.manager.statuses()
        if (
            BUILTIN_SKILLS_PLUGIN in statuses
            and statuses[BUILTIN_SKILLS_PLUGIN].state is PluginState.ACTIVE
        ):
            self.manager.unload(BUILTIN_SKILLS_PLUGIN, timeout=timeout, cascade=True)
        statuses = self.manager.statuses()
        if MCP_PLUGIN_ID in statuses and statuses[MCP_PLUGIN_ID].state is PluginState.ACTIVE:
            self.manager.unload(MCP_PLUGIN_ID, timeout=timeout)
        self.mcp.shutdown()


def task_plugin_state(snapshot: GenerationSnapshot) -> dict[str, Any]:
    return {
        "schema_version": RUNTIME_SCHEMA_VERSION,
        "runtime_generation": snapshot.generation,
        "plugins": {
            plugin_id: {
                "version": item.version,
                "generation": item.generation,
                "config_hash": item.config_hash,
            }
            for plugin_id, item in sorted(snapshot.plugins.items())
        },
    }


def invoke_generation_pinned_graph(
    graph: Any,
    graph_input: Any,
    config: Mapping[str, Any],
) -> Any:
    """Invoke one LangGraph step against the checkpoint's immutable plugin set."""

    runtime = secflow_runtime()
    with runtime.pin() as snapshot:
        if isinstance(graph_input, dict):
            pinned_input = dict(graph_input)
            plugin_state = pinned_input.get("plugin_state")
            if plugin_state is None:
                plugin_state = task_plugin_state(snapshot)
                pinned_input["plugin_state"] = plugin_state
            graph_input = pinned_input
        else:
            checkpoint = graph.get_state(dict(config))
            values = checkpoint.values if isinstance(checkpoint.values, dict) else {}
            plugin_state = values.get("plugin_state")
            if plugin_state is None:
                raise RuntimeError("Interrupt checkpoint has no pinned plugin state")
        if not isinstance(plugin_state, Mapping):
            raise ValueError("Interrupt plugin state is invalid")
        runtime.validate_task_pin(plugin_state, snapshot=snapshot)
        return graph.invoke(graph_input, dict(config))


_runtime_lock = RLock()
_runtime: SecFlowRuntime | None = None


def secflow_runtime() -> SecFlowRuntime:
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            _runtime = SecFlowRuntime()
        runtime = _runtime
    return runtime.boot()


def shutdown_secflow_runtime(*, timeout: float | None = 30.0) -> None:
    global _runtime
    with _runtime_lock:
        runtime = _runtime
        _runtime = None
    if runtime is not None:
        runtime.close(timeout=timeout)


def runtime_catalog() -> Mapping[str, Any]:
    snapshot = secflow_runtime().snapshot()
    return MappingProxyType(
        {
            "schema_version": RUNTIME_SCHEMA_VERSION,
            "generation": snapshot.generation,
            "plugins": task_plugin_state(snapshot)["plugins"],
        }
    )


__all__ = [
    "BUILTIN_AGENTS_PLUGIN",
    "BUILTIN_SKILLS_PLUGIN",
    "RUNTIME_SCHEMA_VERSION",
    "SecFlowRuntime",
    "runtime_catalog",
    "invoke_generation_pinned_graph",
    "secflow_runtime",
    "shutdown_secflow_runtime",
    "task_plugin_state",
]
