"""Stable MCP plugin protocol consumed by Agents and LangGraph nodes.

Concrete FastMCP server modules are child-process implementation details. The
business layer sees only namespaced tool IDs and this Host-owned call boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping

from app.mcp.runtime import (
    ArtifactPolicy,
    MCPAuthorizationError,
    MCPAuditRecord,
    MCPConfigurationError,
    MCPRuntimeHost,
    MCPServerConfig,
    MCPToolDescriptor,
    MCPTransport,
    ToolArtifactPolicy,
    ToolExecutionResult,
    builtin_stdio_server_config,
    namespaced_tool_id,
)
from app.plugins import ExecutionMode, PluginContext
from app.assistant_artifacts import component_artifact_store, sbom_artifact_store
from app.storage import DATA_DIR


MCP_SERVER_REGISTRY = "mcp_servers"
MCP_TOOL_REGISTRY = "tools"
MCP_PLUGIN_ID = "secflow.mcp"
_CODE_SCAN_BATCH_MAX_FILES = 5_000
_CODE_SCAN_BATCH_MAX_BYTES = 64 * 1024 * 1024
_CODE_SCAN_PARSE_ERROR_PREVIEW = 2_000


def _sha256_json(value: Any) -> str:
    payload = json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _best_effort_sha256(value: Any) -> str:
    try:
        return _sha256_json(_plain_json(value))
    except (TypeError, ValueError):
        return hashlib.sha256(type(value).__qualname__.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class MCPArtifactContract:
    """Host-owned output contract; plugin callers cannot override it."""

    output_argument: str = "output_dir"
    max_artifact_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_artifacts: int = 1
    allowed_media_types: tuple[str, ...] = ()

    def runtime_policy(self) -> ToolArtifactPolicy:
        return ToolArtifactPolicy(
            output_argument=self.output_argument,
            max_artifact_bytes=self.max_artifact_bytes,
            max_total_bytes=self.max_total_bytes,
            max_artifacts=self.max_artifacts,
            allowed_media_types=frozenset(self.allowed_media_types),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "output_argument": self.output_argument,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_artifacts": self.max_artifacts,
            "allowed_media_types": sorted(self.allowed_media_types),
        }


@dataclass(frozen=True, slots=True)
class MCPToolDeclaration:
    server_id: str
    name: str
    description: str = ""
    artifact_contract: MCPArtifactContract | None = None
    input_schema_sha256: str = ""
    output_schema_sha256: str = ""

    @property
    def tool_id(self) -> str:
        return namespaced_tool_id(self.server_id, self.name)

    def as_dict(self) -> dict[str, Any]:
        value = {
            "id": self.tool_id,
            "server_id": self.server_id,
            "name": self.name,
            "description": self.description,
        }
        if self.artifact_contract is not None:
            value["artifact_contract"] = self.artifact_contract.as_dict()
        if self.input_schema_sha256:
            value["input_schema_sha256"] = self.input_schema_sha256
        if self.output_schema_sha256:
            value["output_schema_sha256"] = self.output_schema_sha256
        value["contract_sha256"] = _sha256_json(value)
        return value


@dataclass(frozen=True, slots=True)
class MCPServerDefinition:
    server_id: str
    label: str
    tools: tuple[MCPToolDeclaration, ...]
    plugin_id: str = MCP_PLUGIN_ID
    plugin_version: str = "1.3.4"
    generation: int = 1
    timeout_seconds: float = 120.0
    max_result_bytes: int = 32 * 1024 * 1024
    connection: MCPServerConfig | None = None

    def __post_init__(self) -> None:
        if self.connection is not None and self.connection.server_id != self.server_id:
            raise MCPConfigurationError("MCP declaration and connection server ids must match")
        if not self.tools:
            raise MCPConfigurationError("MCP server declaration must contain tools")
        for tool in self.tools:
            if tool.server_id != self.server_id:
                raise MCPConfigurationError("MCP tool declaration belongs to another server")

    @property
    def contract_sha256(self) -> str:
        return _sha256_json(
            {
                "server_id": self.server_id,
                "transport": (
                    self.connection.transport.value
                    if self.connection is not None
                    else MCPTransport.STDIO.value
                ),
                "connection_config_hash": (
                    self.connection.config_hash if self.connection is not None else "builtin"
                ),
                "timeout_seconds": self.timeout_seconds,
                "max_result_bytes": self.max_result_bytes,
                "tools": [tool.as_dict() for tool in self.tools],
            }
        )

    def as_dict(self) -> dict[str, Any]:
        transport = (
            self.connection.transport.value
            if self.connection is not None
            else MCPTransport.STDIO.value
        )
        return {
            "id": self.server_id,
            "name": self.label,
            "transport": transport,
            "isolation": (
                "host-managed-child-process"
                if transport == MCPTransport.STDIO.value
                else "remote-tls-boundary"
            ),
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
            "generation": self.generation,
            "contract_sha256": self.contract_sha256,
            "config_hash": self.connection.config_hash if self.connection is not None else "",
            "tools": [tool.as_dict() for tool in self.tools],
        }


_BUILTIN_TOOL_SCHEMA_HASHES: dict[tuple[str, str], tuple[str, str]] = {
    ("code-scan", "scan_language"): ("04dd3d437bbc09c9e325a85fbc0123fc8a46f9d37aadae6dd770108c6304c119", "d1a31ec6d0d39153366b7f5a5b1961fde0ea2fc257f10a14f88af570934b56f4"),
    ("code-scan", "get_scan_capabilities"): ("40929fc0f8856e6104ce66e0e26ed88a6e709644fb250126bff3356a2e2bbd8b", "418f98cc9a6438af4cd4ba9f0e4517350d7c3ae9e36647e8ce91b2523630a56a"),
    ("component-detail", "build_component_vulnerability_detail"): ("81cb10e7b01a5c5dddf6516bfab5342d64812000c9e971a347da5fabb4c97c06", "3db84fbfa6a1e5f4bd75f0242810248820662c503a428a05aa3a8b5064b48a1e"),
    ("excel", "export_component_vulnerabilities"): ("c9d08c39520d707baad5206eb07646ae91a8fc69c9f10c20e8b6f7da8870833f", "bd7ca4bdd6892f1493b19f0f55e0a0db7f5e533921a164c96a4a47dee5f53966"),
    ("excel", "export_component_vulnerability_catalog"): ("d1782e62e257cce9bcac8188c206739e3c84b8a057bda33af651d8606dbb567d", "bd7ca4bdd6892f1493b19f0f55e0a0db7f5e533921a164c96a4a47dee5f53966"),
    ("d3-sankey", "build_component_sankey"): ("e9b9dc18616233be6c67b93dfee3f155a37f9bb8f47ce453f22f9cc48d1f965a", "a1970816ad394dc1f3dbd0a929d8bac02407d1936aceab4ce9b8ae3db70dba85"),
    ("license-scan", "identify_project_licenses"): ("a1ceba71afb355e77387225165f1a037579a473fde7e066f1129246d0f09c0b6", "78a06b9deff7a08c1310534df7d2055556888acbe5ffa5082c2a78d1eae67e61"),
    ("sbom-excel", "export_project_sbom_excel"): ("a67406f4bb2b9d3f04a2b6aae5834d677a2fa19a885785b62d44997dc4ed4830", "bd7ca4bdd6892f1493b19f0f55e0a0db7f5e533921a164c96a4a47dee5f53966"),
    ("translation", "translate_json_payload"): ("9da8296132545b5e68ac5af7b6449554bf3c01ec3d5d5f48656067cf7e73efc8", "03e59151569da5be9156649ace88e0f5c11534fc9c14d5ff5e7d8cc14a18ed6a"),
    ("report-chart", "build_scan_report_charts"): ("faaf22c75f069f5b06f36b1de758f2f4c8e67d12689573b27c7c7a3d67c8c14f", "f9e9f7e2ce8aeaee21d40c032f6dc63b179f7873ec563cddd0223140c83467ab"),
    ("report-template", "resolve_report_template"): ("67bfa46fadf7ea4c720df2c98d5710541e41245487baca69d6663df156b63790", "1a6f21a26788a2d9879966adafc15b366a8eab1cad71d626d135c0b63069d5db"),
    ("report-sarif", "build_scan_sarif"): ("96d64673a48db1fc42b3986b1c8ff893d51b755e5096bc87e504d9685cb4645b", "cbd1604dd4fd9542291cd4fa31059da3c4ce5572ca4e75a151fdf04330087290"),
    ("report-mermaid", "build_report_mermaid"): ("17c55e03677edc68524ef1db7121fd97976ff3dceea2d452aaf629fd1697bff6", "c2b7e3b07709bfc553cef1300284da7b3b3b5a0c6bc7cb15779d16cc42addf06"),
    ("report-markdown", "render_markdown_report"): ("f19d4c3ed8ddb456fd25bc9756980a29f139f203ff861924d7e27c2aa196a483", "0b713541811bc1f1ed81954cfc93895de9b4e27ddfd6b959829379dfacc75450"),
    ("report-word", "render_word_report"): ("bc2002738fe40337cf25e4e7f86f0d3d1b5dab077ca34cb7cedec47d591c38a4", "ed93a6446d99240bcab02c053397e10c4739a03d965c3cf7a0efbd3b9febc975"),
    ("report-excel", "render_excel_report"): ("885399dfe3be0e46f41cc7da879254645a6f78754a1b0771fff9f83ba7ecdcd7", "dc4b635399ce31d624af311e70fd86b3fe3e7578f38f1f1ee28c4f45455feb11"),
    ("report-pdf", "render_pdf_report"): ("7fbfe3ed65dd032c5f8b24582a3c7ad2cc33f049c16bda313ab9ffd5e00a8674", "b04b6da49cd3ef1817113007e22478d985967b3e5b42763ec56e3ba00ea25733"),
}


def _tool(
    server_id: str,
    name: str,
    description: str = "",
    *,
    artifact_contract: MCPArtifactContract | None = None,
) -> MCPToolDeclaration:
    input_hash, output_hash = _BUILTIN_TOOL_SCHEMA_HASHES.get((server_id, name), ("", ""))
    return MCPToolDeclaration(
        server_id=server_id,
        name=name,
        description=description,
        artifact_contract=artifact_contract,
        input_schema_sha256=input_hash,
        output_schema_sha256=output_hash,
    )


def _artifact_contract(
    media_type: str,
    *,
    max_artifacts: int = 1,
    max_artifact_bytes: int = 64 * 1024 * 1024,
    max_total_bytes: int | None = None,
) -> MCPArtifactContract:
    return MCPArtifactContract(
        max_artifact_bytes=max_artifact_bytes,
        max_total_bytes=max_total_bytes or (max_artifacts * max_artifact_bytes),
        max_artifacts=max_artifacts,
        allowed_media_types=(media_type,),
    )


BUILTIN_MCP_SERVERS = (
    MCPServerDefinition(
        "code-scan",
        "AegisAl Code Scan MCP",
        (
            _tool("code-scan", "scan_language", "Scan one selected language in an authorized workspace."),
            _tool("code-scan", "get_scan_capabilities", "Return code scan engine capabilities."),
        ),
        timeout_seconds=86_400.0,
        max_result_bytes=64 * 1024 * 1024,
    ),
    MCPServerDefinition(
        "component-detail",
        "AegisAl Component Detail MCP",
        (_tool("component-detail", "build_component_vulnerability_detail"),),
    ),
    MCPServerDefinition(
        "excel",
        "AegisAl Component Excel MCP",
        (
            _tool(
                "excel",
                "export_component_vulnerabilities",
                artifact_contract=_artifact_contract(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
            ),
            _tool(
                "excel",
                "export_component_vulnerability_catalog",
                artifact_contract=_artifact_contract(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
            ),
        ),
        timeout_seconds=900.0,
    ),
    MCPServerDefinition(
        "d3-sankey",
        "AegisAl D3 Sankey MCP",
        (_tool("d3-sankey", "build_component_sankey"),),
    ),
    MCPServerDefinition(
        "license-scan",
        "AegisAl License MCP",
        (_tool("license-scan", "identify_project_licenses"),),
    ),
    MCPServerDefinition(
        "sbom-excel",
        "AegisAl SBOM Excel MCP",
        (
            _tool(
                "sbom-excel",
                "export_project_sbom_excel",
                artifact_contract=_artifact_contract(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
            ),
        ),
    ),
    MCPServerDefinition(
        "translation",
        "AegisAl Translation MCP",
        (_tool("translation", "translate_json_payload"),),
    ),
    MCPServerDefinition(
        "report-chart",
        "AegisAl Report Chart MCP",
        (_tool("report-chart", "build_scan_report_charts"),),
    ),
    MCPServerDefinition(
        "report-template",
        "AegisAl Template MCP",
        (_tool("report-template", "resolve_report_template"),),
    ),
    MCPServerDefinition(
        "report-sarif",
        "AegisAl SARIF MCP",
        (_tool("report-sarif", "build_scan_sarif"),),
    ),
    MCPServerDefinition(
        "report-mermaid",
        "AegisAl Mermaid MCP",
        (
            _tool(
                "report-mermaid",
                "build_report_mermaid",
                artifact_contract=_artifact_contract(
                    "image/jpeg",
                    max_artifacts=64,
                    max_artifact_bytes=16 * 1024 * 1024,
                    max_total_bytes=128 * 1024 * 1024,
                ),
            ),
        ),
    ),
    MCPServerDefinition(
        "report-markdown",
        "AegisAl Markdown MCP",
        (_tool("report-markdown", "render_markdown_report"),),
    ),
    MCPServerDefinition(
        "report-word",
        "AegisAl Word MCP",
        (
            _tool(
                "report-word",
                "render_word_report",
                artifact_contract=_artifact_contract(
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
                ),
            ),
        ),
    ),
    MCPServerDefinition(
        "report-excel",
        "AegisAl Report Excel MCP",
        (
            _tool(
                "report-excel",
                "render_excel_report",
                artifact_contract=_artifact_contract(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
            ),
        ),
    ),
    MCPServerDefinition(
        "report-pdf",
        "AegisAl PDF MCP",
        (
            _tool(
                "report-pdf",
                "render_pdf_report",
                artifact_contract=_artifact_contract("application/pdf"),
            ),
        ),
    ),
)


class MCPPluginService:
    """Lazy lifecycle owner for declaratively registered MCP servers."""

    def __init__(
        self,
        *,
        artifact_root: Path | None = None,
        trusted_sandbox_launchers: tuple[tuple[str, ...], ...] = (),
    ) -> None:
        self._artifact_root = (artifact_root or (DATA_DIR / "mcp_artifacts")).resolve(
            strict=False
        )
        self._lock = RLock()
        self._trusted_sandbox_launchers = trusted_sandbox_launchers
        self._host: MCPRuntimeHost | None = None
        self._definitions: dict[str, MCPServerDefinition] = {}
        self._allowlists: dict[str, tuple[str, ...]] = {}
        self._code_scan_tokens: dict[str, str] = {}

    def register(self, definition: MCPServerDefinition) -> None:
        with self._lock:
            if definition.server_id in self._definitions:
                raise RuntimeError(f"MCP server is already declared: {definition.server_id}")
            self._definitions[definition.server_id] = definition

    def unregister(self, server_id: str) -> None:
        with self._lock:
            definition = self._definitions.pop(server_id, None)
            host = self._host
            self._code_scan_tokens.pop(server_id, None)
        if definition is not None and host is not None:
            active = {item["id"] for item in host.snapshot().get("servers", [])}
            if server_id in active:
                host.unregister_server(server_id)

    def set_agent_allowlist(self, agent_id: str, tool_ids: tuple[str, ...] | list[str]) -> None:
        allowed = tuple(sorted({item for item in tool_ids if item.startswith("mcp__")}))
        with self._lock:
            self._allowlists[agent_id] = allowed
            host = self._host
        if host is not None:
            host.set_agent_allowlist(agent_id, allowed)

    def remove_agent(self, agent_id: str) -> None:
        with self._lock:
            self._allowlists.pop(agent_id, None)
            host = self._host
        if host is not None:
            host.remove_agent(agent_id)

    def call(
        self,
        *,
        agent_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        timeout_seconds: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ToolExecutionResult:
        definition, tool = self._definition_for_tool(tool_id)
        with self._lock:
            allowlist = self._allowlists.get(agent_id)
        if allowlist is None:
            self._audit_preflight_rejection(
                definition, agent_id, tool_id, arguments, "authorization"
            )
            raise MCPAuthorizationError(f"Agent has no MCP tool allowlist: {agent_id}")
        if tool_id not in allowlist:
            self._audit_preflight_rejection(
                definition, agent_id, tool_id, arguments, "authorization"
            )
            raise MCPAuthorizationError(
                f"Agent {agent_id!r} is not allowed to call {tool_id!r}"
            )
        artifact_policy = (
            tool.artifact_contract.runtime_policy()
            if tool.artifact_contract is not None
            else None
        )
        if artifact_policy is not None:
            if artifact_policy.output_argument in arguments:
                self._audit_preflight_rejection(
                    definition, agent_id, tool_id, arguments, "host_policy"
                )
                raise MCPConfigurationError(
                    f"{artifact_policy.output_argument} is owned by the AegisAl Host"
                )
            if (
                definition.connection is not None
                and definition.connection.transport is MCPTransport.STREAMABLE_HTTP
            ):
                self._audit_preflight_rejection(
                    definition, agent_id, tool_id, arguments, "host_policy"
                )
                raise MCPConfigurationError(
                    "Remote MCP tools cannot receive a local artifact directory; "
                    "declare an HTTPS ResourceLink artifact contract instead"
                )
        host = self._ensure_server(definition)
        payload = dict(arguments)
        if definition.server_id == "code-scan":
            payload.setdefault("capability_token", self._code_scan_tokens[definition.server_id])
        return host.call(
            agent_id=agent_id,
            tool_id=tool_id,
            arguments=payload,
            timeout_seconds=timeout_seconds,
            cancelled=cancelled,
            artifact_policy=artifact_policy,
        )

    def catalog(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                self._definitions[key].as_dict()
                for key in sorted(self._definitions)
            ]

    def runtime_snapshot(self) -> dict[str, Any]:
        with self._lock:
            host = self._host
        return {"servers": [], "tools": []} if host is None else host.snapshot()

    def read_artifact(self, reference: Mapping[str, Any]) -> bytes:
        """Read a Host-imported artifact and revalidate it against its audit reference."""

        relative = str(reference.get("relative_path") or "").replace("\\", "/")
        candidate = self._artifact_root / relative
        try:
            root = self._artifact_root.resolve(strict=True)
            current = root
            for part in Path(relative).parts:
                if part in {"", ".", ".."}:
                    raise ValueError("invalid path segment")
                current = current / part
                if current.is_symlink():
                    raise ValueError("symlink traversal")
            path = candidate.resolve(strict=True)
            path.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError("MCP artifact reference is outside Host storage") from exc
        if not path.is_file() or path.is_symlink():
            raise ValueError("MCP artifact reference is not a regular file")
        declared_size = int(reference.get("size_bytes") or 0)
        if declared_size <= 0 or declared_size > 128 * 1024 * 1024:
            raise ValueError("MCP artifact size is outside Host policy")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ValueError("MCP artifact reference is not a regular file")
            payload = stream.read(declared_size + 1)
        if declared_size != len(payload):
            raise ValueError("MCP artifact size changed after Host import")
        actual_digest = hashlib.sha256(payload).hexdigest()
        declared_digest = str(reference.get("sha256") or "").strip().lower()
        if not declared_digest or not hmac.compare_digest(declared_digest, actual_digest):
            raise ValueError("MCP artifact hash changed after Host import")
        return payload

    def release_artifacts(self, call_id: str) -> None:
        with self._lock:
            host = self._host
        if host is not None:
            host.release_artifacts(call_id)

    @staticmethod
    def _audit_preflight_rejection(
        definition: MCPServerDefinition,
        agent_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        error_type: str,
    ) -> None:
        from app.mcp.audit import persistent_mcp_audit_log

        now = time.time()
        connection = definition.connection
        persistent_mcp_audit_log.write(
            MCPAuditRecord(
                call_id=secrets.token_hex(16),
                agent_id=str(agent_id),
                server_id=definition.server_id,
                tool_id=tool_id,
                transport=(
                    connection.transport.value
                    if connection is not None
                    else MCPTransport.STDIO.value
                ),
                status="rejected",
                started_at=now,
                completed_at=now,
                duration_ms=0,
                input_sha256=_best_effort_sha256(arguments),
                output_sha256="",
                result_size_bytes=0,
                plugin_id=definition.plugin_id,
                plugin_version=definition.plugin_version,
                config_hash=(
                    connection.config_hash
                    if connection is not None
                    else definition.contract_sha256
                ),
                generation=definition.generation,
                error_type=error_type,
            )
        )

    def shutdown(self) -> None:
        with self._lock:
            host = self._host
            self._host = None
            self._definitions.clear()
            self._allowlists.clear()
            self._code_scan_tokens.clear()
        if host is not None:
            host.shutdown()

    def _definition_for_tool(
        self, tool_id: str
    ) -> tuple[MCPServerDefinition, MCPToolDeclaration]:
        with self._lock:
            for definition in self._definitions.values():
                for tool in definition.tools:
                    if tool.tool_id == tool_id:
                        return definition, tool
        raise KeyError(f"MCP tool is not declared by an active plugin: {tool_id}")

    def _host_instance(self) -> MCPRuntimeHost:
        with self._lock:
            if self._host is None:
                from app.mcp.audit import persistent_mcp_audit_log

                self._host = MCPRuntimeHost(
                    audit_sink=persistent_mcp_audit_log.write,
                    artifact_policy=ArtifactPolicy(
                        root=self._artifact_root,
                        inline_binary_limit=64 * 1024,
                    ),
                    trusted_sandbox_launchers=self._trusted_sandbox_launchers,
                )
                for agent_id, allowlist in self._allowlists.items():
                    self._host.set_agent_allowlist(agent_id, allowlist)
            return self._host

    def _ensure_server(self, definition: MCPServerDefinition) -> MCPRuntimeHost:
        host = self._host_instance()
        with self._lock:
            active = {item["id"] for item in host.snapshot().get("servers", [])}
            if definition.server_id in active:
                return host
            environment = _builtin_environment(definition.server_id)
            if definition.connection is not None:
                config = replace(
                    definition.connection,
                    generation=definition.generation,
                    plugin_id=definition.plugin_id,
                    plugin_version=definition.plugin_version,
                    config_hash="",
                )
            elif definition.server_id == "code-scan":
                token = secrets.token_urlsafe(32)
                self._code_scan_tokens[definition.server_id] = token
                environment.update(
                    {
                        "SECFLOW_CODE_SCAN_MCP_TOKEN": token,
                        "SECFLOW_CODE_SCAN_MCP_ALLOWED_TOOLS": "get_scan_capabilities,scan_language",
                    }
                )
                config = builtin_stdio_server_config(
                    definition.server_id,
                    environment=environment,
                    timeout_seconds=definition.timeout_seconds,
                    startup_timeout_seconds=60.0,
                    max_result_bytes=definition.max_result_bytes,
                    generation=definition.generation,
                    plugin_id=definition.plugin_id,
                    plugin_version=definition.plugin_version,
                )
            else:
                config = builtin_stdio_server_config(
                    definition.server_id,
                    environment=environment,
                    timeout_seconds=definition.timeout_seconds,
                    startup_timeout_seconds=60.0,
                    max_result_bytes=definition.max_result_bytes,
                    generation=definition.generation,
                    plugin_id=definition.plugin_id,
                    plugin_version=definition.plugin_version,
                )
            try:
                discovered = host.register_server(config)
                _verify_discovered_tools(definition, discovered)
            except BaseException:
                host.unregister_server(definition.server_id)
                self._code_scan_tokens.pop(definition.server_id, None)
                raise
            return host


def activate_builtin_mcp(context: PluginContext, service: MCPPluginService) -> None:
    # Added before per-server effects so reverse-order cleanup unregisters
    # every server first and then terminates the runtime event-loop thread.
    context.effect(service.shutdown)
    definitions = tuple(
        replace(
            definition,
            plugin_id=context.plugin_id,
            plugin_version=context.manifest.version,
            generation=context.generation,
        )
        for definition in BUILTIN_MCP_SERVERS
    )
    for definition in definitions:
        activate_mcp_server(context, service, definition)


def activate_mcp_server(
    context: PluginContext,
    service: MCPPluginService,
    definition: MCPServerDefinition,
) -> None:
    """Register one declarative stdio or Streamable HTTP MCP contribution."""

    declared_contracts = context.manifest.config.get("contracts")
    if not isinstance(declared_contracts, Mapping):
        raise MCPConfigurationError("MCP plugin manifest must pin its tool contracts")
    pinned_contract = str(declared_contracts.get(definition.server_id) or "")
    if not pinned_contract or not hmac.compare_digest(
        pinned_contract,
        definition.contract_sha256,
    ):
        raise MCPConfigurationError(
            f"MCP plugin contract hash mismatch: {definition.server_id}"
        )
    connection = definition.connection
    mode = (
        ExecutionMode.STREAMABLE_HTTP
        if connection is not None and connection.transport is MCPTransport.STREAMABLE_HTTP
        else ExecutionMode.STDIO
    )
    transport = connection.transport.value if connection is not None else MCPTransport.STDIO.value
    service.register(definition)
    context.effect(lambda server_id=definition.server_id: service.unregister(server_id))
    context.register(
        MCP_SERVER_REGISTRY,
        definition.server_id,
        definition,
        executable=True,
        execution_mode=mode,
        attributes={
            "transport": transport,
            "isolation": (
                "remote-tls"
                if mode is ExecutionMode.STREAMABLE_HTTP
                else "child-process"
            ),
            "contract_sha256": definition.contract_sha256,
        },
    )
    for tool in definition.tools:
        context.register(
            MCP_TOOL_REGISTRY,
            tool.tool_id,
            tool,
            executable=True,
            execution_mode=mode,
            attributes={
                "server_id": definition.server_id,
                "remote_name": tool.name,
                "contract_sha256": tool.as_dict()["contract_sha256"],
            },
        )


def call_mcp_tool(
    *,
    agent_id: str,
    tool_id: str,
    arguments: Mapping[str, Any],
    timeout_seconds: float | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    from app.composition import secflow_runtime

    runtime = secflow_runtime()
    agent_entry = runtime.snapshot().registries.get("agents", {}).get(agent_id)
    if agent_entry is None:
        raise PermissionError(f"MCP caller is not an active Agent plugin: {agent_id}")
    manifest = getattr(agent_entry.value, "manifest", None)
    allowlist = tuple(getattr(manifest, "tool_allowlist", ()) or ())
    runtime.mcp.set_agent_allowlist(agent_id, list(allowlist))
    execution = runtime.mcp.call(
        agent_id=agent_id,
        tool_id=tool_id,
        arguments=arguments,
        timeout_seconds=timeout_seconds,
        cancelled=cancelled,
    )
    result = dict(execution.data or {})
    result["_mcp_runtime"] = {
        "call_id": execution.call_id,
        "server_id": execution.server_id,
        "tool_id": execution.tool_id,
        "transport": execution.audit.transport,
        "input_sha256": execution.input_sha256,
        "output_sha256": execution.output_sha256,
        "result_size_bytes": execution.result_size_bytes,
        "plugin_id": execution.audit.plugin_id,
        "plugin_version": execution.audit.plugin_version,
        "config_hash": execution.audit.config_hash,
        "generation": execution.audit.generation,
        "status": execution.status,
    }
    return result


def read_mcp_artifact(result: Mapping[str, Any], *, index: int = 0) -> bytes:
    artifacts = result.get("artifacts")
    if not isinstance(artifacts, (list, tuple)) or index < 0 or index >= len(artifacts):
        raise ValueError("MCP result has no requested Host artifact")
    reference = artifacts[index]
    if not isinstance(reference, Mapping):
        raise ValueError("MCP artifact reference is invalid")
    from app.composition import secflow_runtime

    return secflow_runtime().mcp.read_artifact(reference)


def release_mcp_artifacts(result: Mapping[str, Any]) -> None:
    runtime_audit = result.get("_mcp_runtime")
    if not isinstance(runtime_audit, Mapping):
        return
    call_id = str(runtime_audit.get("call_id") or "")
    if not call_id:
        return
    from app.composition import secflow_runtime

    secflow_runtime().mcp.release_artifacts(call_id)


def publish_mcp_workbook(
    result: Mapping[str, Any],
    *,
    kind: str,
    default_file_name: str,
    generated_at: str,
    user_id: str,
    session_id: str = "",
    task_id: str = "",
) -> dict[str, Any]:
    """Publish a verified MCP workbook through the existing assistant download API."""

    try:
        payload = read_mcp_artifact(result)
        file_name = Path(str(result.get("file_name") or default_file_name)).name
        if kind not in {"component", "sbom"}:
            raise ValueError(f"Unsupported workbook artifact kind: {kind}")
        store = component_artifact_store if kind == "component" else sbom_artifact_store
        published = store.save(
            payload,
            file_name=file_name,
            generated_at=generated_at,
            user_id=user_id,
            session_id=session_id,
            task_id=task_id,
        )
    finally:
        release_mcp_artifacts(result)
    value = published.model_dump(mode="json")
    runtime_audit = result.get("_mcp_runtime")
    if isinstance(runtime_audit, Mapping):
        value["_mcp_runtime"] = dict(runtime_audit)
    return value


class CodeScanMCPError(RuntimeError):
    pass


class CodeScanMCPClient:
    """Task-graph facade over the composition-owned Code Scan MCP plugin."""

    def __init__(
        self,
        *,
        startup_timeout: float | None = None,
        read_timeout: float | None = None,
        allowed_tools: set[str] | tuple[str, ...] | None = None,
    ) -> None:
        del startup_timeout
        self._read_timeout = max(
            60.0,
            float(
                read_timeout
                or os.getenv("SECFLOW_CODE_SCAN_MCP_READ_TIMEOUT_SECONDS", "86400")
                or 86400
            ),
        )
        self._allowed_tools = frozenset(allowed_tools or {"scan_language"})
        if not self._allowed_tools or self._allowed_tools - {"scan_language"}:
            raise ValueError("Code Scan MCP client requires a supported non-empty tool allowlist")

    @property
    def enabled(self) -> bool:
        return os.getenv("SECFLOW_CODE_SCAN_MCP_TRANSPORT", "stdio").strip().casefold() == "stdio"

    def scan_language(
        self,
        *,
        workspace_path: str,
        language: str,
        source_paths: list[str],
        manifest_files: list[str],
        dependency_scan: dict[str, Any],
        rule_paths: list[str],
        complete_scan: bool,
        cancelled: Callable[[], bool],
    ) -> dict[str, Any]:
        if not self.enabled:
            raise CodeScanMCPError("Code Scan MCP stdio transport is disabled")
        batches = _partition_code_scan_sources(workspace_path, source_paths)
        context_manifests = _code_scan_context_manifests(manifest_files)
        result: dict[str, Any] | None = None
        envelopes: list[dict[str, Any]] = []
        runtime_audits: list[dict[str, Any]] = []
        try:
            for batch_index, batch_paths in enumerate(batches):
                if cancelled():
                    raise CodeScanMCPError("Code Scan MCP call was cancelled")
                payload = call_mcp_tool(
                    agent_id="code_scan_agent",
                    tool_id="mcp__code_scan__scan_language",
                    arguments={
                        "workspace_path": workspace_path,
                        "language": language,
                        "source_paths": batch_paths,
                        "manifest_files": manifest_files if batch_index == 0 else context_manifests,
                        "dependency_scan": dependency_scan,
                        "rule_paths": rule_paths,
                        "complete_scan": bool(complete_scan),
                        "cancel_marker": "",
                    },
                    timeout_seconds=self._read_timeout,
                    cancelled=cancelled,
                )
                batch_result = payload.get("result")
                if not isinstance(batch_result, dict):
                    raise CodeScanMCPError("Code Scan MCP returned no structured scan result")
                result = _merge_code_scan_batch_result(result, batch_result)
                envelopes.append(
                    {
                        key: payload.get(key)
                        for key in (
                            "schema_version",
                            "server",
                            "tool",
                            "process_id",
                            "language",
                            "started_at",
                            "completed_at",
                            "duration_ms",
                            "input_sha256",
                            "output_sha256",
                        )
                    }
                )
                runtime_audit = payload.get("_mcp_runtime")
                runtime_audits.append(dict(runtime_audit) if isinstance(runtime_audit, dict) else {})
        except Exception as exc:  # noqa: BLE001 - normalize the task boundary.
            message = "Code Scan MCP call was cancelled" if cancelled() else str(exc)
            raise CodeScanMCPError(message or type(exc).__name__) from exc
        if result is None or not envelopes:
            raise CodeScanMCPError("Code Scan MCP returned no structured scan result")

        first = envelopes[0]
        last = envelopes[-1]
        runtime_audit = _merge_code_scan_runtime_audits(runtime_audits)
        result["scan_batches"] = len(batches)
        result["scanned_source_files"] = len(source_paths)
        result["_scan_mcp"] = {
            "schema_version": int(first.get("schema_version") or 1),
            "server": str(first.get("server") or "AegisAl Code Scan MCP").replace(
                "SecFlow Code Scan MCP", "AegisAl Code Scan MCP"
            ),
            "tool": "scan_language",
            "transport": str(runtime_audit.get("transport") or "stdio"),
            "endpoint": "managed-child-process",
            "process_id": int(first.get("process_id") or 0),
            "language": str(first.get("language") or language),
            "started_at": str(first.get("started_at") or ""),
            "completed_at": str(last.get("completed_at") or ""),
            "duration_ms": sum(int(item.get("duration_ms") or 0) for item in envelopes),
            "server_input_sha256": _aggregate_digest(envelopes, "input_sha256"),
            "server_output_sha256": _aggregate_digest(envelopes, "output_sha256"),
            "batch_count": len(batches),
            **runtime_audit,
        }
        return result

    def shutdown(self) -> None:
        # The composition root, not an individual task graph, owns MCP lifecycle.
        return None

    def cancel_active_scan(self) -> None:
        # Active calls observe the task's cancellation callback and revoke the child.
        return None


def _partition_code_scan_sources(workspace_path: str, source_paths: list[str]) -> list[list[str]]:
    if not source_paths:
        return [[]]
    max_files = _bounded_environment_int(
        "SECFLOW_CODE_SCAN_BATCH_MAX_FILES",
        _CODE_SCAN_BATCH_MAX_FILES,
        minimum=1,
        maximum=50_000,
    )
    max_bytes = _bounded_environment_int(
        "SECFLOW_CODE_SCAN_BATCH_MAX_BYTES",
        _CODE_SCAN_BATCH_MAX_BYTES,
        minimum=1 * 1024 * 1024,
        maximum=512 * 1024 * 1024,
    )
    workspace = Path(workspace_path).expanduser()
    base = workspace if workspace.is_dir() else workspace.parent
    batches: list[list[str]] = []
    current: list[str] = []
    current_bytes = 0
    for source_path in source_paths:
        size = _code_scan_source_size(base, source_path)
        if current and (len(current) >= max_files or current_bytes + size > max_bytes):
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(source_path)
        current_bytes += size
    if current:
        batches.append(current)
    return batches


def _code_scan_source_size(workspace: Path, relative_path: str) -> int:
    try:
        candidate = (workspace / relative_path).resolve(strict=True)
        candidate.relative_to(workspace.resolve(strict=True))
        if candidate.is_file() and not candidate.is_symlink():
            return max(1, int(candidate.stat().st_size))
    except (OSError, RuntimeError, ValueError):
        pass
    return 1


def _code_scan_context_manifests(manifest_files: list[str]) -> list[str]:
    return [
        item
        for item in manifest_files
        if Path(item).name.casefold() in {"cmakelists.txt", "compile_commands.json"}
    ]


def _merge_code_scan_batch_result(
    current: dict[str, Any] | None,
    incoming: Mapping[str, Any],
) -> dict[str, Any]:
    value = _plain_json(incoming)
    if current is None:
        current = dict(value)
        current["files"] = _parse_error_file_previews(value.get("files"))
        current["syntax_summary"] = _merge_syntax_summaries({}, value.get("syntax_summary"))
        current["diagnostics"] = _bounded_unique_values(value.get("diagnostics"), limit=200)
        current["findings"] = []
        current["review_findings"] = []
        current["finding_count"] = 0
        current["review_finding_count"] = 0
        current["batch_count"] = 0
    else:
        current["status"] = _merged_scan_status(current.get("status"), value.get("status"))
        current["mode"] = _merged_scan_mode(current.get("mode"), value.get("mode"))
        current["cli_status"] = _merged_scan_status(current.get("cli_status"), value.get("cli_status"))
        current["generated_at"] = value.get("generated_at") or current.get("generated_at")
        current["rule_paths"] = _bounded_unique_values(
            [*(current.get("rule_paths") or []), *(value.get("rule_paths") or [])],
            limit=2_000,
        )
        current["files"] = _parse_error_file_previews(
            [*(current.get("files") or []), *(value.get("files") or [])]
        )
        current["diagnostics"] = _bounded_unique_values(
            [*(current.get("diagnostics") or []), *(value.get("diagnostics") or [])],
            limit=200,
        )
        current["scenario_nodes"] = _bounded_unique_mappings(
            [*(current.get("scenario_nodes") or []), *(value.get("scenario_nodes") or [])],
            limit=1_000,
        )
        current["conditional_edges"] = _bounded_unique_mappings(
            [*(current.get("conditional_edges") or []), *(value.get("conditional_edges") or [])],
            limit=1_000,
        )
        current["syntax_summary"] = _merge_syntax_summaries(
            current.get("syntax_summary"),
            value.get("syntax_summary"),
        )
        current["transport_compaction"] = _merge_transport_compaction(
            current.get("transport_compaction"),
            value.get("transport_compaction"),
        )
        current["result_truncated"] = bool(current.get("result_truncated")) or bool(
            value.get("result_truncated")
        )

    finding_limit = _bounded_environment_int(
        "SECFLOW_STATIC_MAX_FINDINGS",
        500,
        minimum=1,
        maximum=5_000,
    )
    for key, count_key, truncated_key in (
        ("findings", "finding_count", "findings_truncated"),
        ("review_findings", "review_finding_count", "review_findings_truncated"),
    ):
        combined = [*(current.get(key) or []), *(value.get(key) or [])]
        unique, truncated = _bounded_unique_mappings_with_truncation(combined, limit=finding_limit)
        current[key] = unique
        current[count_key] = len(unique)
        current[truncated_key] = bool(current.get(truncated_key)) or truncated
    current["batch_count"] = int(current.get("batch_count") or 0) + 1
    return current


def _merge_syntax_summaries(current: Any, incoming: Any) -> dict[str, Any]:
    left = dict(current) if isinstance(current, Mapping) else {}
    right = dict(incoming) if isinstance(incoming, Mapping) else {}
    numeric_fields = {
        "parsed_files",
        "parse_error_files",
        "raw_parse_error_files",
        "recovered_parse_error_files",
        "ast_node_count",
        "cfg_node_count",
        "cfg_edge_count",
        "dfg_edge_count",
        "parse_error_file_name_count",
        "omitted_parse_error_file_names",
    }
    merged = {**left, **right}
    for key in numeric_fields:
        merged[key] = int(left.get(key) or 0) + int(right.get(key) or 0)
    merged["languages"] = _bounded_unique_values(
        [*(left.get("languages") or []), *(right.get("languages") or [])],
        limit=64,
    )
    names = _bounded_unique_values(
        [*(left.get("parse_error_file_names") or []), *(right.get("parse_error_file_names") or [])],
        limit=_CODE_SCAN_PARSE_ERROR_PREVIEW,
    )
    merged["parse_error_file_names"] = names
    merged["parse_error_file_names_truncated"] = (
        bool(left.get("parse_error_file_names_truncated"))
        or bool(right.get("parse_error_file_names_truncated"))
        or int(merged.get("parse_error_files") or 0) > len(names)
    )
    return merged


def _merge_transport_compaction(current: Any, incoming: Any) -> dict[str, Any]:
    left = dict(current) if isinstance(current, Mapping) else {}
    right = dict(incoming) if isinstance(incoming, Mapping) else {}
    numeric_fields = {
        "source_file_count",
        "retained_file_details",
        "omitted_file_details",
        "omitted_parse_error_file_details",
        "graph_previews_omitted",
        "graph_preview_nodes_omitted",
        "graph_preview_edges_omitted",
    }
    merged = {**left, **right}
    for key in numeric_fields:
        merged[key] = int(left.get(key) or 0) + int(right.get(key) or 0)
    merged["parse_error_file_limit"] = max(
        int(left.get("parse_error_file_limit") or 0),
        int(right.get("parse_error_file_limit") or 0),
    )
    merged["parse_error_file_details_truncated"] = bool(
        left.get("parse_error_file_details_truncated")
    ) or bool(right.get("parse_error_file_details_truncated"))
    return merged


def _parse_error_file_previews(value: Any) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in value or []:
        if not isinstance(item, Mapping):
            continue
        syntax = item.get("syntax") if isinstance(item.get("syntax"), Mapping) else {}
        if not syntax.get("parse_error"):
            continue
        result.append(_plain_json(item))
        if len(result) >= _CODE_SCAN_PARSE_ERROR_PREVIEW:
            break
    return result


def _bounded_unique_values(value: Any, *, limit: int) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for item in value or []:
        key = str(item)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
        if len(result) >= limit:
            break
    return result


def _bounded_unique_mappings(value: Any, *, limit: int) -> list[dict[str, Any]]:
    return _bounded_unique_mappings_with_truncation(value, limit=limit)[0]


def _bounded_unique_mappings_with_truncation(
    value: Any,
    *,
    limit: int,
) -> tuple[list[dict[str, Any]], bool]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    truncated = False
    for item in value or []:
        if not isinstance(item, Mapping):
            continue
        normalized = _plain_json(item)
        key = _sha256_json(normalized)
        if key in seen:
            continue
        seen.add(key)
        if len(result) >= limit:
            truncated = True
            continue
        result.append(normalized)
    return result, truncated


def _merged_scan_status(left: Any, right: Any) -> str:
    values = {str(left or "").casefold(), str(right or "").casefold()} - {""}
    if values == {"completed"}:
        return "completed"
    if "failed" in values:
        return "failed"
    if "completed" in values and values <= {"completed", "warning"}:
        return "completed"
    return str(right or left or "warning")


def _merged_scan_mode(left: Any, right: Any) -> str:
    left_value = str(left or "")
    right_value = str(right or "")
    return left_value if left_value == right_value else (right_value or left_value or "bundled-cli")


def _merge_code_scan_runtime_audits(audits: list[dict[str, Any]]) -> dict[str, Any]:
    values = [item for item in audits if item]
    if not values:
        return {"batch_call_ids": [], "result_size_bytes": 0}
    first = values[0]
    return {
        **first,
        "input_sha256": _aggregate_digest(values, "input_sha256"),
        "output_sha256": _aggregate_digest(values, "output_sha256"),
        "result_size_bytes": sum(int(item.get("result_size_bytes") or 0) for item in values),
        "status": "completed" if all(item.get("status") == "completed" for item in values) else "partial",
        "batch_call_ids": [str(item.get("call_id") or "") for item in values if item.get("call_id")],
    }


def _aggregate_digest(values: list[Mapping[str, Any]], key: str) -> str:
    digests = [str(item.get(key) or "") for item in values if str(item.get(key) or "")]
    if not digests:
        return ""
    return digests[0] if len(digests) == 1 else _sha256_json(digests)


def _bounded_environment_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    try:
        value = int(os.getenv(name, str(default)) or default)
    except ValueError:
        value = default
    return max(minimum, min(value, maximum))


def _verify_discovered_tools(
    definition: MCPServerDefinition,
    discovered: tuple[MCPToolDescriptor, ...],
) -> None:
    expected = {tool.tool_id for tool in definition.tools}
    actual = {tool.tool_id for tool in discovered}
    if expected != actual:
        raise RuntimeError(
            f"MCP server tool contract changed for {definition.server_id}: "
            f"expected {sorted(expected)}, got {sorted(actual)}"
        )
    declarations = {tool.tool_id: tool for tool in definition.tools}
    for descriptor in discovered:
        declaration = declarations[descriptor.tool_id]
        input_digest = _sha256_json(_plain_json(descriptor.input_schema))
        output_digest = _sha256_json(_plain_json(descriptor.output_schema))
        if (
            declaration.input_schema_sha256
            and not hmac.compare_digest(declaration.input_schema_sha256, input_digest)
        ):
            raise RuntimeError(f"MCP input schema changed for {descriptor.tool_id}")
        if (
            declaration.output_schema_sha256
            and not hmac.compare_digest(declaration.output_schema_sha256, output_digest)
        ):
            raise RuntimeError(f"MCP output schema changed for {descriptor.tool_id}")


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain_json(item) for item in value]
    return value


def _builtin_environment(server_id: str) -> dict[str, str]:
    common_names = {
        "LANG",
        "LC_ALL",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "VIRTUAL_ENV",
    }
    if server_id == "translation":
        common_names.update(
            {
                "SECFLOW_TRANSLATION_BEAM_SIZE",
                "SECFLOW_TRANSLATION_MODEL_DIR",
            }
        )
    if server_id == "license-scan":
        common_names.add("SECFLOW_OSI_LICENSE_API_TIMEOUT_SECONDS")
    if server_id == "code-scan":
        common_names.update(
            name
            for name in os.environ
            if name.startswith("SECFLOW_SEMGREP_") or name.startswith("SECFLOW_JAVA_FLOW_")
        )
        common_names.update({"SECFLOW_BUNDLED_SEMGREP_BIN", "SECFLOW_STATIC_MAX_FINDINGS"})
    environment = {name: os.environ[name] for name in common_names if name in os.environ}
    if server_id == "excel":
        from app.intelligence import intelligence_service

        environment["SECFLOW_VULNERABILITY_CATALOG_PATH"] = str(
            intelligence_service.catalog_path.resolve(strict=False)
        )
        for name in (
            "SECFLOW_KEYCHAIN_SERVICE",
            "SECFLOW_KEYCHAIN_PATH",
            "SECFLOW_SECURITY_CLI",
            "SECFLOW_DISABLE_KEYCHAIN",
            "SECFLOW_DISABLE_DPAPI",
        ):
            if name in os.environ:
                environment[name] = os.environ[name]
        default_keychain = Path.home() / "Library" / "Keychains" / "login.keychain-db"
        if "SECFLOW_KEYCHAIN_PATH" not in environment and default_keychain.is_file():
            environment["SECFLOW_KEYCHAIN_PATH"] = str(default_keychain)
        configured_key_file = os.getenv("SECFLOW_STORAGE_KEY_FILE", "").strip()
        key_candidates = (
            Path(configured_key_file).expanduser() if configured_key_file else None,
            DATA_DIR / ".secflow-local-storage-key.dpapi",
            DATA_DIR / ".secflow-local-storage.key",
        )
        key_file = next((path for path in key_candidates if path is not None and path.is_file()), None)
        if key_file is not None:
            environment["SECFLOW_STORAGE_KEY_FILE"] = str(key_file.resolve(strict=False))
    return environment


__all__ = [
    "BUILTIN_MCP_SERVERS",
    "MCP_PLUGIN_ID",
    "MCP_SERVER_REGISTRY",
    "MCP_TOOL_REGISTRY",
    "MCPPluginService",
    "MCPArtifactContract",
    "MCPServerDefinition",
    "MCPToolDeclaration",
    "activate_builtin_mcp",
    "activate_mcp_server",
    "call_mcp_tool",
    "CodeScanMCPClient",
    "CodeScanMCPError",
    "namespaced_tool_id",
    "publish_mcp_workbook",
    "release_mcp_artifacts",
    "read_mcp_artifact",
]
