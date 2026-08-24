"""Secure MCP client runtime shared by AegisAl agents and plugins.

The runtime deliberately supports only the two current MCP transports:

* local servers run as child processes over stdio;
* remote servers use Streamable HTTP over verified TLS (optionally mTLS).

Legacy HTTP/SSE and in-process tool execution are rejected at the configuration
boundary.  LangGraph nodes should depend on :class:`ToolBroker`, never on a
concrete MCP server module.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import stat
import sys
import tempfile
import threading
import time
import uuid
from contextlib import AbstractAsyncContextManager, AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field, replace
from datetime import timedelta
from enum import Enum
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Mapping, Protocol, Sequence
from urllib.parse import urlsplit

import httpx
from jsonschema import ValidationError as JSONSchemaValidationError
from jsonschema.validators import validator_for
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamablehttp_client


_SERVER_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{0,126}[a-z0-9]$|^[a-z0-9]$")
_TOOL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_SAFE_HEADER_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_DEFAULT_MAX_RESULT_BYTES = 32 * 1024 * 1024
_DEFAULT_TIMEOUT_SECONDS = 120.0
BUILTIN_STDIO_SERVER_IDS = frozenset(
    {
        "code-scan",
        "component-detail",
        "excel",
        "d3-sankey",
        "license-scan",
        "sbom-excel",
        "translation",
        "report-chart",
        "report-markdown",
        "report-mermaid",
        "report-pdf",
        "report-sarif",
        "report-template",
        "report-excel",
        "report-word",
    }
)


class MCPRuntimeError(RuntimeError):
    """Base class for MCP runtime failures."""


class MCPConfigurationError(MCPRuntimeError, ValueError):
    """Raised when a server configuration weakens the transport boundary."""


class MCPRegistrationError(MCPRuntimeError):
    """Raised when a server cannot be registered atomically."""


class MCPAuthorizationError(MCPRuntimeError, PermissionError):
    """Raised when an agent attempts to use an undeclared tool."""


class MCPToolNotFoundError(MCPRuntimeError, LookupError):
    """Raised when a namespaced tool is not active."""


class MCPToolValidationError(MCPRuntimeError, ValueError):
    """Raised when tool input or structured output violates its JSON Schema."""


class MCPToolExecutionError(MCPRuntimeError):
    """Raised when an MCP server returns an error result."""


class MCPToolTimeoutError(MCPToolExecutionError, TimeoutError):
    """Raised when a call exceeds the Host-enforced timeout."""


class MCPToolCancelledError(MCPToolExecutionError):
    """Raised when an explicit Host cancellation signal wins the call race."""


class MCPResultTooLargeError(MCPToolExecutionError):
    """Raised before oversized MCP output reaches an Agent context."""


class MCPTransport(str, Enum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable-http"


class MCPTrustLevel(str, Enum):
    BUILTIN = "builtin"
    SIGNED_THIRD_PARTY = "signed-third-party"
    UNTRUSTED = "untrusted"
    REMOTE = "remote"


class MCPServerLifecycle(str, Enum):
    REGISTERING = "registering"
    ACTIVE = "active"
    DRAINING = "draining"
    FAILED = "failed"
    DISPOSED = "disposed"


@dataclass(frozen=True, slots=True)
class TLSConfig:
    """Verified TLS settings for a remote Streamable HTTP server.

    Certificate verification has no opt-out.  ``client_cert`` and
    ``client_key`` must be supplied together to enable mTLS.
    """

    ca_file: Path | str | None = None
    client_cert: Path | str | None = None
    client_key: Path | str | None = None
    client_key_password: str | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        cert = _optional_path(self.client_cert)
        key = _optional_path(self.client_key)
        ca_file = _optional_path(self.ca_file)
        if (cert is None) != (key is None):
            raise MCPConfigurationError("mTLS client_cert and client_key must be configured together")
        object.__setattr__(self, "ca_file", ca_file)
        object.__setattr__(self, "client_cert", cert)
        object.__setattr__(self, "client_key", key)

    def create_ssl_context(self) -> ssl.SSLContext:
        ca_file = _existing_file(self.ca_file, "TLS CA bundle")
        context = ssl.create_default_context(cafile=str(ca_file) if ca_file else None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if self.client_cert is not None:
            cert = _existing_file(self.client_cert, "mTLS client certificate")
            key = _existing_file(self.client_key, "mTLS client key")
            assert cert is not None and key is not None
            context.load_cert_chain(str(cert), str(key), password=self.client_key_password)
        return context


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Process isolation declaration for a local stdio server.

    ``launcher_prefix`` is an OS sandbox command ending before the actual MCP
    executable, for example ``("sandbox-exec", "-f", profile, "--")``.  An
    untrusted server is rejected unless this boundary is explicitly supplied
    *and* the Host has registered the exact prefix as trusted.
    All stdio servers still receive a private 0700 runtime directory and a
    minimal environment from the official MCP SDK.
    """

    launcher_prefix: tuple[str, ...] = ()
    environment_allowlist: frozenset[str] = frozenset()
    deny_network: bool = False
    read_only_roots: tuple[Path | str, ...] = ()

    def __post_init__(self) -> None:
        prefix = tuple(str(item).strip() for item in self.launcher_prefix if str(item).strip())
        allowlist = frozenset(str(item).strip() for item in self.environment_allowlist if str(item).strip())
        read_only_roots = tuple(
            Path(item).expanduser().resolve(strict=False)
            for item in self.read_only_roots
            if str(item).strip()
        )
        if any(not path.is_absolute() for path in read_only_roots):
            raise MCPConfigurationError("MCP sandbox read-only roots must be absolute")
        object.__setattr__(self, "launcher_prefix", prefix)
        object.__setattr__(self, "environment_allowlist", allowlist)
        object.__setattr__(self, "deny_network", bool(self.deny_network))
        object.__setattr__(self, "read_only_roots", read_only_roots)


@dataclass(frozen=True, slots=True)
class MCPServerConfig:
    """Immutable connection and policy configuration for one MCP server."""

    server_id: str
    transport: MCPTransport | str
    trust_level: MCPTrustLevel | str
    command: str | None = None
    args: tuple[str, ...] = ()
    cwd: Path | str | None = None
    environment: Mapping[str, str] = field(default_factory=dict, repr=False)
    url: str | None = None
    headers: Mapping[str, str] = field(default_factory=dict, repr=False)
    tls: TLSConfig | None = None
    sandbox: SandboxPolicy = field(default_factory=SandboxPolicy)
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
    startup_timeout_seconds: float = 30.0
    max_result_bytes: int = _DEFAULT_MAX_RESULT_BYTES
    generation: int = 1
    plugin_id: str = "builtin"
    plugin_version: str = "0"
    config_hash: str = ""

    def __post_init__(self) -> None:
        server_id = str(self.server_id or "").strip().lower()
        if not _SERVER_ID_PATTERN.fullmatch(server_id):
            raise MCPConfigurationError(f"Invalid MCP server id: {self.server_id!r}")
        object.__setattr__(self, "server_id", server_id)

        raw_transport = str(getattr(self.transport, "value", self.transport) or "").strip().lower()
        if raw_transport in {"sse", "legacy-sse", "http+sse"}:
            raise MCPConfigurationError("Legacy MCP SSE transport is not supported")
        if raw_transport in {"in-process", "in_process", "inprocess", "python"}:
            raise MCPConfigurationError("In-process MCP execution is not supported")
        try:
            transport = MCPTransport(raw_transport)
        except ValueError as exc:
            raise MCPConfigurationError(f"Unsupported MCP transport: {raw_transport or '<empty>'}") from exc
        object.__setattr__(self, "transport", transport)

        raw_trust = str(getattr(self.trust_level, "value", self.trust_level) or "").strip().lower()
        try:
            trust_level = MCPTrustLevel(raw_trust)
        except ValueError as exc:
            raise MCPConfigurationError(f"Unsupported MCP trust level: {raw_trust or '<empty>'}") from exc
        object.__setattr__(self, "trust_level", trust_level)

        args = tuple(str(item) for item in self.args)
        environment = MappingProxyType({str(key): str(value) for key, value in self.environment.items()})
        headers = MappingProxyType({str(key): str(value) for key, value in self.headers.items()})
        object.__setattr__(self, "args", args)
        object.__setattr__(self, "environment", environment)
        object.__setattr__(self, "headers", headers)
        object.__setattr__(self, "cwd", _optional_path(self.cwd))

        if self.timeout_seconds <= 0 or self.startup_timeout_seconds <= 0:
            raise MCPConfigurationError("MCP timeouts must be positive")
        if self.max_result_bytes <= 0:
            raise MCPConfigurationError("MCP max_result_bytes must be positive")
        if self.generation < 1:
            raise MCPConfigurationError("MCP plugin generation must be positive")

        if transport is MCPTransport.STDIO:
            if not str(self.command or "").strip():
                raise MCPConfigurationError("A local stdio MCP server requires an executable command")
            if self.url is not None or self.tls is not None or headers:
                raise MCPConfigurationError("A stdio MCP server cannot declare HTTP or TLS settings")
            if trust_level is MCPTrustLevel.REMOTE:
                raise MCPConfigurationError("Remote MCP trust level requires Streamable HTTP")
            if trust_level is MCPTrustLevel.UNTRUSTED and not self.sandbox.launcher_prefix:
                raise MCPConfigurationError("Untrusted local MCP servers require an OS sandbox launcher_prefix")
            _validate_working_directory(self.cwd)
            _validate_environment(
                environment,
                self.sandbox.environment_allowlist,
                enforce_allowlist=(
                    trust_level is MCPTrustLevel.UNTRUSTED
                    or bool(self.sandbox.environment_allowlist)
                ),
            )
        else:
            if self.command is not None or args or self.cwd is not None or environment:
                raise MCPConfigurationError("A remote MCP server cannot declare local process settings")
            _validate_https_url(self.url)
            _validate_headers(headers)
            if trust_level is not MCPTrustLevel.REMOTE:
                raise MCPConfigurationError("Streamable HTTP MCP servers must use the remote trust level")
            object.__setattr__(self, "tls", self.tls or TLSConfig())

        payload = {
            "server_id": server_id,
            "transport": transport.value,
            "trust_level": trust_level.value,
            "command": self.command,
            "args": args,
            "cwd": str(self.cwd or ""),
            "environment": _secret_mapping_fingerprints(environment),
            "url": self.url,
            "headers": _secret_mapping_fingerprints(headers),
            "tls": _tls_fingerprints(self.tls),
            "sandbox": {
                "launcher_prefix": self.sandbox.launcher_prefix,
                "environment_allowlist": sorted(self.sandbox.environment_allowlist),
                "deny_network": self.sandbox.deny_network,
                "read_only_roots": [str(path) for path in self.sandbox.read_only_roots],
            },
            "timeout_seconds": self.timeout_seconds,
            "startup_timeout_seconds": self.startup_timeout_seconds,
            "max_result_bytes": self.max_result_bytes,
            "generation": self.generation,
            "plugin_id": self.plugin_id,
            "plugin_version": self.plugin_version,
        }
        computed_hash = _sha256_json(payload)
        if self.config_hash and not hmac.compare_digest(self.config_hash, computed_hash):
            raise MCPConfigurationError("MCP config_hash does not match the Host-computed configuration")
        object.__setattr__(self, "config_hash", computed_hash)


@dataclass(frozen=True, slots=True)
class MCPToolDescriptor:
    tool_id: str
    server_id: str
    name: str
    description: str
    input_schema: Mapping[str, Any]
    output_schema: Mapping[str, Any]
    generation: int
    plugin_id: str
    plugin_version: str


@dataclass(frozen=True, slots=True)
class MCPAuditRecord:
    call_id: str
    agent_id: str
    server_id: str
    tool_id: str
    transport: str
    status: str
    started_at: float
    completed_at: float
    duration_ms: int
    input_sha256: str
    output_sha256: str
    result_size_bytes: int
    plugin_id: str
    plugin_version: str
    config_hash: str
    generation: int
    error_type: str = ""


@dataclass(frozen=True, slots=True)
class ArtifactPolicy:
    """Host-owned artifact staging and import limits."""

    root: Path | str
    max_artifact_bytes: int = 128 * 1024 * 1024
    max_total_bytes_per_call: int = 256 * 1024 * 1024
    max_artifacts_per_call: int = 32
    inline_binary_limit: int = 64 * 1024
    allowed_media_types: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        root = Path(self.root).expanduser().resolve(strict=False)
        if not root.is_absolute():
            raise MCPConfigurationError("Artifact root must be absolute")
        if (
            self.max_artifact_bytes <= 0
            or self.max_total_bytes_per_call <= 0
            or self.max_artifacts_per_call <= 0
        ):
            raise MCPConfigurationError("Artifact limits must be positive")
        if self.inline_binary_limit < 0:
            raise MCPConfigurationError("Artifact inline binary limit cannot be negative")
        object.__setattr__(self, "root", root)
        object.__setattr__(
            self,
            "allowed_media_types",
            frozenset(str(item).strip().lower() for item in self.allowed_media_types if str(item).strip()),
        )


@dataclass(frozen=True, slots=True)
class ToolArtifactPolicy:
    """Per-tool artifact contract supplied only by the AegisAl Host."""

    output_argument: str
    max_artifact_bytes: int
    max_total_bytes: int
    max_artifacts: int
    allowed_media_types: frozenset[str]

    def __post_init__(self) -> None:
        argument = str(self.output_argument or "").strip()
        if not _TOOL_NAME_PATTERN.fullmatch(argument):
            raise MCPConfigurationError("Artifact output argument name is invalid")
        if self.max_artifact_bytes <= 0 or self.max_total_bytes <= 0 or self.max_artifacts <= 0:
            raise MCPConfigurationError("Tool artifact limits must be positive")
        media_types = frozenset(
            str(item).strip().lower()
            for item in self.allowed_media_types
            if str(item).strip()
        )
        if not media_types:
            raise MCPConfigurationError("Tool artifact media types cannot be empty")
        object.__setattr__(self, "output_argument", argument)
        object.__setattr__(self, "allowed_media_types", media_types)


@dataclass(frozen=True, slots=True)
class HostArtifact:
    artifact_id: str
    relative_path: str
    media_type: str
    size_bytes: int
    sha256: str


class ArtifactManager:
    """Allocate private scratch directories and import relative file references."""

    def __init__(self, policy: ArtifactPolicy) -> None:
        self.policy = policy
        self.root = Path(policy.root)
        self.staging_root = self.root / ".staging"
        self.root.mkdir(parents=True, exist_ok=True)
        self.staging_root.mkdir(parents=True, exist_ok=True)
        try:
            self.root.chmod(0o700)
            self.staging_root.chmod(0o700)
        except OSError:
            pass

    def allocate_scratch(self, call_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", call_id):
            raise MCPConfigurationError("Artifact call id is invalid")
        scratch = Path(tempfile.mkdtemp(prefix=f"{call_id}-", dir=self.staging_root))
        try:
            scratch.chmod(0o700)
        except OSError:
            pass
        return scratch

    def materialize(
        self,
        *,
        call_id: str,
        scratch: Path,
        references: Sequence[Mapping[str, Any]],
        contract: ToolArtifactPolicy,
    ) -> tuple[HostArtifact, ...]:
        artifact_limit = min(self.policy.max_artifacts_per_call, contract.max_artifacts)
        if len(references) > artifact_limit:
            raise MCPToolValidationError("MCP artifact count exceeds the Host policy")
        scratch_root = scratch.resolve(strict=True)
        try:
            scratch_root.relative_to(self.staging_root.resolve(strict=True))
        except ValueError as exc:
            raise MCPToolValidationError("MCP artifact scratch is outside the Host staging root") from exc

        target_dir = self.root / call_id
        validated: list[tuple[Path, str, int, str]] = []
        materialized: list[HostArtifact] = []
        total_size = 0
        for raw in references:
            relative = str(raw.get("path") or raw.get("relative_path") or "").replace("\\", "/")
            relative_path = PurePosixPath(relative)
            if not relative or relative_path.is_absolute() or ".." in relative_path.parts:
                raise MCPToolValidationError(f"MCP artifact path must be relative: {relative!r}")
            candidate = scratch_root / Path(*relative_path.parts)
            current = scratch_root
            for part in relative_path.parts:
                current = current / part
                if current.is_symlink():
                    raise MCPToolValidationError(f"MCP artifact cannot traverse a symlink: {relative}")
            source_metadata = candidate.lstat()
            if not stat.S_ISREG(source_metadata.st_mode):
                raise MCPToolValidationError(f"MCP artifact must be a regular file: {relative}")
            if source_metadata.st_nlink != 1:
                raise MCPToolValidationError(f"MCP artifact cannot be a hard link: {relative}")
            source = candidate.resolve(strict=True)
            try:
                source.relative_to(scratch_root)
            except ValueError as exc:
                raise MCPToolValidationError(f"MCP artifact escaped its Host scratch: {relative}") from exc
            if source.is_symlink() or not source.is_file():
                raise MCPToolValidationError(f"MCP artifact must be a regular file: {relative}")
            size = source_metadata.st_size
            max_artifact_bytes = min(
                self.policy.max_artifact_bytes,
                contract.max_artifact_bytes,
            )
            if size > max_artifact_bytes:
                raise MCPResultTooLargeError(f"MCP artifact exceeds the Host size limit: {relative}")
            total_size += size
            if total_size > min(self.policy.max_total_bytes_per_call, contract.max_total_bytes):
                raise MCPResultTooLargeError("MCP artifact total exceeds the Host call limit")
            media_type = str(raw.get("media_type") or "application/octet-stream").strip().lower()
            if media_type not in contract.allowed_media_types:
                raise MCPToolValidationError(f"MCP artifact media type is not allowed: {media_type}")
            if self.policy.allowed_media_types and media_type not in self.policy.allowed_media_types:
                raise MCPToolValidationError(f"MCP artifact media type is not allowed: {media_type}")
            digest = _sha256_file(source)
            declared_digest = str(raw.get("sha256") or "").strip().lower()
            if declared_digest and not hmac.compare_digest(declared_digest, digest):
                raise MCPToolValidationError(f"MCP artifact hash mismatch: {relative}")
            validated.append((source, media_type, size, digest))

        moved: list[Path] = []
        try:
            if validated:
                target_dir.mkdir(parents=True, exist_ok=False)
            for source, media_type, size, digest in validated:
                artifact_id = uuid.uuid4().hex
                safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", source.name) or "artifact.bin"
                target = target_dir / f"{artifact_id}-{safe_name}"
                os.replace(source, target)
                moved.append(target)
                host_relative = target.relative_to(self.root).as_posix()
                materialized.append(
                    HostArtifact(
                        artifact_id=artifact_id,
                        relative_path=host_relative,
                        media_type=media_type,
                        size_bytes=size,
                        sha256=digest,
                    )
                )
        except BaseException:
            for target in moved:
                target.unlink(missing_ok=True)
            try:
                target_dir.rmdir()
            except OSError:
                pass
            raise
        return tuple(materialized)

    def cleanup_scratch(self, scratch: Path | None) -> None:
        if scratch is None:
            return
        try:
            staging_root = self.staging_root.resolve(strict=True)
            if scratch.parent.resolve(strict=True) != staging_root:
                return
            metadata = scratch.lstat()
        except OSError:
            return
        if stat.S_ISLNK(metadata.st_mode):
            scratch.unlink(missing_ok=True)
            return
        if stat.S_ISDIR(metadata.st_mode):
            shutil.rmtree(scratch, ignore_errors=True)

    def release(self, call_id: str) -> None:
        """Delete Host-imported artifacts after their durable consumer commits."""

        if not re.fullmatch(r"[a-f0-9]{32}", str(call_id or "")):
            raise MCPConfigurationError("Artifact call id is invalid")
        target = self.root / call_id
        try:
            if target.parent.resolve(strict=True) != self.root.resolve(strict=True):
                raise MCPConfigurationError("Artifact release target escaped Host storage")
            metadata = target.lstat()
        except FileNotFoundError:
            return
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise MCPConfigurationError("Artifact release target is not a managed directory")
        shutil.rmtree(target)


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    call_id: str
    server_id: str
    tool_id: str
    status: str
    data: Mapping[str, Any] | None
    content: tuple[Mapping[str, Any], ...]
    input_sha256: str
    output_sha256: str
    result_size_bytes: int
    artifacts: tuple[HostArtifact, ...]
    audit: MCPAuditRecord


class _Session(Protocol):
    async def initialize(self) -> Any: ...

    async def list_tools(self, cursor: str | None = None) -> Any: ...

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: timedelta | None = None,
    ) -> Any: ...


SessionConnector = Callable[[MCPServerConfig], AbstractAsyncContextManager[_Session]]
AuditSink = Callable[[MCPAuditRecord], Awaitable[None] | None]
DisconnectHandler = Callable[[str], Awaitable[None]]


@dataclass(slots=True)
class _ServerState:
    config: MCPServerConfig
    connection: _ManagedConnection
    session: _Session
    tools: dict[str, MCPToolDescriptor]
    lifecycle: MCPServerLifecycle = MCPServerLifecycle.REGISTERING
    call_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class _ManagedConnection:
    """Own a transport context in one task from entry through final exit.

    AnyIO cancel scopes, used by the official MCP transports, cannot be entered
    in one asyncio task and exited in another.  The owner task avoids that class
    of shutdown race while still allowing ClientSession requests from callers.
    """

    def __init__(
        self,
        config: MCPServerConfig,
        connector: SessionConnector,
        on_disconnect: DisconnectHandler,
    ) -> None:
        self.config = config
        self._connector = connector
        self._on_disconnect = on_disconnect
        self._ready: asyncio.Future[tuple[_Session, dict[str, MCPToolDescriptor]]] | None = None
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._closing = False

    async def start(self) -> tuple[_Session, dict[str, MCPToolDescriptor]]:
        loop = asyncio.get_running_loop()
        self._ready = loop.create_future()
        self._task = asyncio.create_task(
            self._run(),
            name=f"secflow-mcp-connection-{self.config.server_id}",
        )
        try:
            return await asyncio.wait_for(
                asyncio.shield(self._ready),
                timeout=self.config.startup_timeout_seconds,
            )
        except TimeoutError as exc:
            await self.close(force=True)
            raise MCPRegistrationError(f"MCP server startup timed out: {self.config.server_id}") from exc

    async def close(self, *, force: bool = False) -> None:
        task = self._task
        if task is None:
            return
        self._closing = True
        self._stop.set()
        if force and not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            if not force:
                raise
        except Exception:
            # Connection failures are surfaced at registration/call time.  A
            # close operation remains idempotent and always reaps the process.
            pass
        finally:
            self._task = None

    async def _run(self) -> None:
        assert self._ready is not None
        try:
            async with self._connector(self.config) as session:
                await session.initialize()
                tools = await _discover_tools(
                    session,
                    self.config,
                    timeout=self.config.startup_timeout_seconds,
                )
                if not self._ready.done():
                    self._ready.set_result((session, tools))
                await self._stop.wait()
        except BaseException as exc:
            if not self._ready.done():
                self._ready.set_exception(exc)
            elif not self._closing:
                await self._on_disconnect(self.config.server_id)
            if isinstance(exc, asyncio.CancelledError):
                raise


class MCPRegistry:
    """Atomic registry of active MCP servers and their namespaced tools."""

    def __init__(self) -> None:
        self._servers: dict[str, _ServerState] = {}
        self._tools: dict[str, MCPToolDescriptor] = {}
        self._lock = asyncio.Lock()

    async def commit(self, state: _ServerState) -> tuple[MCPToolDescriptor, ...]:
        async with self._lock:
            if state.config.server_id in self._servers:
                raise MCPRegistrationError(f"MCP server is already registered: {state.config.server_id}")
            collisions = set(state.tools) & set(self._tools)
            if collisions:
                raise MCPRegistrationError(f"MCP tool id collision: {sorted(collisions)[0]}")
            state.lifecycle = MCPServerLifecycle.ACTIVE
            self._servers[state.config.server_id] = state
            self._tools.update(state.tools)
            return tuple(state.tools[key] for key in sorted(state.tools))

    async def resolve(self, tool_id: str) -> tuple[_ServerState, MCPToolDescriptor]:
        async with self._lock:
            descriptor = self._tools.get(tool_id)
            if descriptor is None:
                raise MCPToolNotFoundError(f"MCP tool is not active: {tool_id}")
            state = self._servers.get(descriptor.server_id)
            if state is None or state.lifecycle is not MCPServerLifecycle.ACTIVE:
                raise MCPToolNotFoundError(f"MCP server is not active: {descriptor.server_id}")
            return state, descriptor

    async def detach(self, server_id: str, *, failed: bool = False) -> _ServerState | None:
        async with self._lock:
            state = self._servers.pop(server_id, None)
            if state is None:
                return None
            state.lifecycle = MCPServerLifecycle.FAILED if failed else MCPServerLifecycle.DRAINING
            for tool_id in state.tools:
                self._tools.pop(tool_id, None)
            return state

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            return {
                "servers": [
                    {
                        "id": server_id,
                        "transport": state.config.transport.value,
                        "trust_level": state.config.trust_level.value,
                        "lifecycle": state.lifecycle.value,
                        "generation": state.config.generation,
                        "plugin_id": state.config.plugin_id,
                        "plugin_version": state.config.plugin_version,
                        "config_hash": state.config.config_hash,
                    }
                    for server_id, state in sorted(self._servers.items())
                ],
                "tools": [
                    {
                        "id": descriptor.tool_id,
                        "server_id": descriptor.server_id,
                        "name": descriptor.name,
                        "description": descriptor.description,
                        "input_schema": _thaw_json(descriptor.input_schema),
                        "output_schema": _thaw_json(descriptor.output_schema),
                    }
                    for _, descriptor in sorted(self._tools.items())
                ],
            }

    async def server_ids(self) -> tuple[str, ...]:
        async with self._lock:
            return tuple(self._servers)


class ToolBroker:
    """Central authorization, validation, execution and audit boundary."""

    def __init__(
        self,
        registry: MCPRegistry,
        *,
        audit_sink: AuditSink | None = None,
        artifact_manager: ArtifactManager | None = None,
        max_audit_records: int = 2_000,
    ) -> None:
        self._registry = registry
        self._agent_allowlists: dict[str, frozenset[str]] = {}
        self._allowlist_lock = asyncio.Lock()
        self._audit_sink = audit_sink
        self._artifact_manager = artifact_manager
        self._max_audit_records = max(1, int(max_audit_records))
        self._audit_records: list[MCPAuditRecord] = []

    async def set_agent_allowlist(self, agent_id: str, tool_ids: Sequence[str]) -> None:
        clean_agent_id = str(agent_id or "").strip()
        if not clean_agent_id:
            raise MCPConfigurationError("Agent id is required for an MCP tool allowlist")
        clean_tools = frozenset(str(item).strip() for item in tool_ids if str(item).strip())
        async with self._allowlist_lock:
            self._agent_allowlists[clean_agent_id] = clean_tools

    async def remove_agent(self, agent_id: str) -> None:
        async with self._allowlist_lock:
            self._agent_allowlists.pop(agent_id, None)

    async def call(
        self,
        *,
        agent_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        timeout_seconds: float | None = None,
        cancel_event: asyncio.Event | None = None,
        artifact_policy: ToolArtifactPolicy | None = None,
    ) -> ToolExecutionResult:
        state, descriptor = await self._registry.resolve(tool_id)
        call_id = uuid.uuid4().hex
        started_at = time.time()
        args = dict(arguments)
        logical_args = dict(args)
        input_sha256 = ""
        output_sha256 = ""
        result_size = 0
        status = "failed"
        error_type = ""
        disconnect = False
        phase = "preflight"
        artifact_scratch: Path | None = None
        artifacts: tuple[HostArtifact, ...] = ()

        hard_timeout = state.config.timeout_seconds
        if timeout_seconds is not None:
            if timeout_seconds <= 0:
                raise MCPConfigurationError("MCP call timeout must be positive")
            hard_timeout = min(hard_timeout, float(timeout_seconds))

        try:
            await self._authorize(agent_id, tool_id)
            if artifact_policy is None and "output_dir" in args:
                raise MCPToolValidationError(
                    "Artifact output_dir is Host-managed and this tool has no artifact contract"
                )
            if artifact_policy is not None:
                argument_name = artifact_policy.output_argument
                if argument_name in args:
                    raise MCPToolValidationError(
                        f"Artifact output argument is Host-managed and cannot be supplied: {argument_name}"
                    )
                if self._artifact_manager is None:
                    raise MCPConfigurationError("MCP artifact output requested without a Host ArtifactManager")
                artifact_scratch = self._artifact_manager.allocate_scratch(call_id)
                args[argument_name] = str(artifact_scratch)
                logical_args[argument_name] = "<host-artifact-scratch>"
            input_sha256 = _sha256_json(logical_args)
            _validate_json_schema(args, descriptor.input_schema, f"input for {tool_id}")
            phase = "execution"
            lock_wait_started = time.monotonic()
            try:
                await asyncio.wait_for(state.call_lock.acquire(), timeout=hard_timeout)
            except TimeoutError as exc:
                raise MCPToolTimeoutError(
                    f"MCP tool call timed out waiting for the server after {hard_timeout:g}s: {descriptor.name}"
                ) from exc
            try:
                if state.lifecycle is not MCPServerLifecycle.ACTIVE:
                    raise MCPToolNotFoundError(
                        f"MCP server stopped accepting calls: {state.config.server_id}"
                    )
                remaining_timeout = max(0.001, hard_timeout - (time.monotonic() - lock_wait_started))
                response = await _call_with_policy(
                    state.session,
                    descriptor.name,
                    args,
                    timeout_seconds=remaining_timeout,
                    cancel_event=cancel_event,
                )
            finally:
                state.call_lock.release()
            if bool(getattr(response, "isError", False)):
                raise MCPToolExecutionError(_error_content(response) or f"MCP tool failed: {tool_id}")
            phase = "output"
            structured = getattr(response, "structuredContent", None)
            content = tuple(_content_to_mapping(item) for item in (getattr(response, "content", None) or []))
            raw_output = _canonical_json_bytes({"data": structured, "content": content})
            result_size = len(raw_output)
            output_sha256 = hashlib.sha256(raw_output).hexdigest()
            if result_size > state.config.max_result_bytes:
                raise MCPResultTooLargeError(
                    f"MCP result exceeds {state.config.max_result_bytes} bytes: {tool_id}"
                )
            if descriptor.output_schema:
                if not isinstance(structured, dict):
                    raise MCPToolValidationError(f"Structured output is required for {tool_id}")
                _validate_json_schema(structured, descriptor.output_schema, f"output from {tool_id}")
            elif structured is not None and not isinstance(structured, dict):
                raise MCPToolValidationError(f"Structured output from {tool_id} must be an object")

            normalized_data = dict(structured) if isinstance(structured, dict) else None
            if normalized_data is not None:
                _reject_large_inline_artifacts(
                    normalized_data,
                    limit=(
                        self._artifact_manager.policy.inline_binary_limit
                        if self._artifact_manager is not None
                        else 64 * 1024
                    ),
                )
                raw_artifacts = normalized_data.get("artifacts")
                if raw_artifacts is not None:
                    if artifact_scratch is None or self._artifact_manager is None:
                        raise MCPToolValidationError(
                            "MCP returned artifact references without a Host-allocated scratch directory"
                        )
                    if not isinstance(raw_artifacts, list) or not all(
                        isinstance(item, Mapping) for item in raw_artifacts
                    ):
                        raise MCPToolValidationError("MCP artifacts must be a list of relative references")
                    artifacts = self._artifact_manager.materialize(
                        call_id=call_id,
                        scratch=artifact_scratch,
                        references=raw_artifacts,
                        contract=artifact_policy,
                    )
                    normalized_data["artifacts"] = [
                        {
                            "artifact_id": item.artifact_id,
                            "relative_path": item.relative_path,
                            "media_type": item.media_type,
                            "size_bytes": item.size_bytes,
                            "sha256": item.sha256,
                        }
                        for item in artifacts
                    ]
            output_payload = {"data": normalized_data, "content": content}
            encoded_output = _canonical_json_bytes(output_payload)
            result_size = len(encoded_output)
            if result_size > state.config.max_result_bytes:
                raise MCPResultTooLargeError(
                    f"MCP result exceeds {state.config.max_result_bytes} bytes: {tool_id}"
                )
            output_sha256 = hashlib.sha256(encoded_output).hexdigest()
            status = "completed"
            audit = _audit_record(
                state,
                call_id=call_id,
                agent_id=agent_id,
                tool_id=tool_id,
                status=status,
                started_at=started_at,
                input_sha256=input_sha256,
                output_sha256=output_sha256,
                result_size=result_size,
            )
            await self._record_audit(audit)
            return ToolExecutionResult(
                call_id=call_id,
                server_id=state.config.server_id,
                tool_id=tool_id,
                status=status,
                # The audit hash is already sealed.  Return ordinary JSON
                # containers so LangGraph checkpoints and FastAPI encoders do
                # not need to understand MappingProxyType.
                data=normalized_data,
                content=content,
                input_sha256=input_sha256,
                output_sha256=output_sha256,
                result_size_bytes=result_size,
                artifacts=artifacts,
                audit=audit,
            )
        except MCPAuthorizationError:
            status = "rejected"
            error_type = "authorization"
            if not input_sha256:
                input_sha256 = _best_effort_sha256(logical_args)
            raise
        except MCPConfigurationError:
            status = "rejected"
            error_type = "host_policy"
            raise
        except MCPToolNotFoundError:
            status = "rejected"
            error_type = "server_draining"
            raise
        except MCPToolCancelledError:
            status = "cancelled"
            error_type = "cancelled"
            disconnect = True
            raise
        except MCPToolTimeoutError:
            status = "timed_out"
            error_type = "timeout"
            disconnect = True
            raise
        except MCPToolValidationError:
            status = "rejected" if phase == "preflight" else "failed"
            error_type = "schema_validation"
            disconnect = phase == "output"
            raise
        except MCPResultTooLargeError:
            error_type = "result_too_large"
            disconnect = True
            raise
        except MCPToolExecutionError:
            error_type = "tool_error"
            raise
        except asyncio.CancelledError:
            status = "cancelled"
            error_type = "caller_cancelled"
            disconnect = True
            raise
        except Exception:
            error_type = "transport_error"
            disconnect = True
            raise
        finally:
            if status != "completed":
                audit = _audit_record(
                    state,
                    call_id=call_id,
                    agent_id=agent_id,
                    tool_id=tool_id,
                    status=status,
                    started_at=started_at,
                    input_sha256=input_sha256,
                    output_sha256=output_sha256,
                    result_size=result_size,
                    error_type=error_type,
                )
                await asyncio.shield(self._record_audit(audit))
            if disconnect:
                await asyncio.shield(self._revoke_failed_server(state))
            if self._artifact_manager is not None:
                self._artifact_manager.cleanup_scratch(artifact_scratch)

    @property
    def audit_records(self) -> tuple[MCPAuditRecord, ...]:
        return tuple(self._audit_records)

    async def _authorize(self, agent_id: str, tool_id: str) -> None:
        async with self._allowlist_lock:
            allowlist = self._agent_allowlists.get(agent_id)
        if allowlist is None:
            raise MCPAuthorizationError(f"Agent has no MCP tool allowlist: {agent_id}")
        if tool_id not in allowlist:
            raise MCPAuthorizationError(f"Agent {agent_id!r} is not allowed to call {tool_id!r}")

    async def _record_audit(self, record: MCPAuditRecord) -> None:
        self._audit_records.append(record)
        if len(self._audit_records) > self._max_audit_records:
            del self._audit_records[: len(self._audit_records) - self._max_audit_records]
        if self._audit_sink is not None:
            result = self._audit_sink(record)
            if result is not None:
                await result

    async def _revoke_failed_server(self, state: _ServerState) -> None:
        detached = await self._registry.detach(state.config.server_id, failed=True)
        if detached is not None:
            await detached.connection.close(force=True)


class MCPRuntime:
    """Owns MCP connection lifecycles and exposes the central Tool Broker."""

    def __init__(
        self,
        *,
        connector: SessionConnector | None = None,
        audit_sink: AuditSink | None = None,
        artifact_policy: ArtifactPolicy | None = None,
        trusted_sandbox_launchers: Sequence[Sequence[str]] = (),
    ) -> None:
        self.registry = MCPRegistry()
        self.artifacts = ArtifactManager(artifact_policy) if artifact_policy is not None else None
        self.tools = ToolBroker(
            self.registry,
            audit_sink=audit_sink,
            artifact_manager=self.artifacts,
        )
        self._connector = connector or _default_session_connector
        self._trusted_sandbox_launchers = frozenset(
            tuple(str(item) for item in launcher) for launcher in trusted_sandbox_launchers
        )
        self._closed = False

    async def register_server(self, config: MCPServerConfig) -> tuple[MCPToolDescriptor, ...]:
        if self._closed:
            raise MCPRuntimeError("MCP runtime is closed")
        current_config = replace(config, config_hash="")
        if not hmac.compare_digest(current_config.config_hash, config.config_hash):
            raise MCPConfigurationError(
                f"MCP configuration changed after validation: {config.server_id}"
            )
        if config.trust_level is MCPTrustLevel.UNTRUSTED:
            prefix = config.sandbox.launcher_prefix
            if prefix not in self._trusted_sandbox_launchers:
                raise MCPConfigurationError(
                    "Untrusted MCP sandbox launcher is not approved by the AegisAl Host"
                )
        connection = _ManagedConnection(config, self._connector, self._handle_disconnect)
        try:
            session, discovered = await connection.start()
            state = _ServerState(
                config=config,
                connection=connection,
                session=session,
                tools=discovered,
            )
            return await self.registry.commit(state)
        except BaseException as exc:
            await connection.close(force=True)
            if isinstance(exc, (MCPRuntimeError, asyncio.CancelledError)):
                raise
            raise MCPRegistrationError(f"Failed to register MCP server {config.server_id}: {exc}") from exc

    async def unregister_server(self, server_id: str) -> None:
        state = await self.registry.detach(server_id)
        if state is None:
            return
        async with state.call_lock:
            await state.connection.close()
            state.lifecycle = MCPServerLifecycle.DISPOSED

    async def _handle_disconnect(self, server_id: str) -> None:
        # The connection owner is already unwinding its transport context, so
        # only revoke registry visibility here.  It must never await itself.
        await self.registry.detach(server_id, failed=True)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for server_id in await self.registry.server_ids():
            await self.unregister_server(server_id)

    async def __aenter__(self) -> MCPRuntime:
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self.close()


class MCPRuntimeHost:
    """Thread-safe synchronous facade for existing LangGraph nodes.

    A dedicated event-loop thread owns the runtime and all persistent MCP
    connections.  This is the supported bridge for synchronous graph/worker
    code; callers must not create a new event loop per tool invocation.
    """

    def __init__(
        self,
        *,
        connector: SessionConnector | None = None,
        audit_sink: AuditSink | None = None,
        artifact_policy: ArtifactPolicy | None = None,
        trusted_sandbox_launchers: Sequence[Sequence[str]] = (),
        thread_name: str = "secflow-mcp-runtime",
    ) -> None:
        self._connector = connector
        self._audit_sink = audit_sink
        self._artifact_policy = artifact_policy
        self._trusted_sandbox_launchers = trusted_sandbox_launchers
        self._started = threading.Event()
        self._cancel_all = threading.Event()
        self._state_lock = threading.RLock()
        self._closed = False
        self._startup_error: BaseException | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._runtime: MCPRuntime | None = None
        self._thread = threading.Thread(target=self._run, name=thread_name, daemon=True)
        self._thread.start()
        if not self._started.wait(timeout=10):
            raise MCPRuntimeError("Timed out starting the MCP runtime event-loop thread")
        if self._startup_error is not None:
            raise MCPRuntimeError(f"Failed to start the MCP runtime: {self._startup_error}")

    def register_server(self, config: MCPServerConfig) -> tuple[MCPToolDescriptor, ...]:
        runtime = self._require_runtime()
        return self._submit(runtime.register_server(config))

    def unregister_server(self, server_id: str) -> None:
        runtime = self._require_runtime()
        self._submit(runtime.unregister_server(server_id))

    def set_agent_allowlist(self, agent_id: str, tool_ids: Sequence[str]) -> None:
        runtime = self._require_runtime()
        self._submit(runtime.tools.set_agent_allowlist(agent_id, tool_ids))

    def remove_agent(self, agent_id: str) -> None:
        runtime = self._require_runtime()
        self._submit(runtime.tools.remove_agent(agent_id))

    def call(
        self,
        *,
        agent_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        timeout_seconds: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        artifact_policy: ToolArtifactPolicy | None = None,
    ) -> ToolExecutionResult:
        runtime = self._require_runtime()
        return self._submit(
            self._bridged_call(
                runtime,
                agent_id=agent_id,
                tool_id=tool_id,
                arguments=arguments,
                timeout_seconds=timeout_seconds,
                cancelled=cancelled,
                artifact_policy=artifact_policy,
            )
        )

    def release_artifacts(self, call_id: str) -> None:
        runtime = self._require_runtime()
        if runtime.artifacts is None:
            raise MCPConfigurationError("MCP artifact storage is not configured")

        async def release() -> None:
            assert runtime.artifacts is not None
            runtime.artifacts.release(call_id)

        self._submit(release())

    def snapshot(self) -> dict[str, Any]:
        runtime = self._require_runtime()
        return self._submit(runtime.registry.snapshot())

    @property
    def audit_records(self) -> tuple[MCPAuditRecord, ...]:
        runtime = self._require_runtime()

        async def read() -> tuple[MCPAuditRecord, ...]:
            return runtime.tools.audit_records

        return self._submit(read())

    def shutdown(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._cancel_all.set()
            loop = self._loop
            runtime = self._runtime
        if loop is None or runtime is None:
            return
        if threading.current_thread() is self._thread:
            raise MCPRuntimeError("MCPRuntimeHost.shutdown cannot block its own event-loop thread")
        future = asyncio.run_coroutine_threadsafe(runtime.close(), loop)
        try:
            future.result(timeout=15)
        finally:
            loop.call_soon_threadsafe(loop.stop)
            self._thread.join(timeout=15)
            if self._thread.is_alive():
                raise MCPRuntimeError("MCP runtime event-loop thread did not stop")

    close = shutdown

    def __enter__(self) -> MCPRuntimeHost:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.shutdown()

    async def _bridged_call(
        self,
        runtime: MCPRuntime,
        *,
        agent_id: str,
        tool_id: str,
        arguments: Mapping[str, Any],
        timeout_seconds: float | None,
        cancelled: Callable[[], bool] | None,
        artifact_policy: ToolArtifactPolicy | None,
    ) -> ToolExecutionResult:
        cancel_event = asyncio.Event()
        call_task = asyncio.create_task(
            runtime.tools.call(
                agent_id=agent_id,
                tool_id=tool_id,
                arguments=arguments,
                timeout_seconds=timeout_seconds,
                cancel_event=cancel_event,
                artifact_policy=artifact_policy,
            )
        )

        async def monitor() -> None:
            while not call_task.done():
                should_cancel = self._cancel_all.is_set()
                if not should_cancel and cancelled is not None:
                    try:
                        should_cancel = bool(cancelled())
                    except Exception:
                        should_cancel = True
                if should_cancel:
                    cancel_event.set()
                    return
                await asyncio.sleep(0.05)

        monitor_task = asyncio.create_task(monitor())
        try:
            return await call_task
        finally:
            monitor_task.cancel()
            await _consume_cancelled_task(monitor_task)

    def _submit(self, coroutine: Awaitable[Any]) -> Any:
        loop = self._loop
        if loop is None or self._closed:
            if hasattr(coroutine, "close"):
                coroutine.close()  # type: ignore[attr-defined]
            raise MCPRuntimeError("MCP runtime Host is closed")
        if threading.current_thread() is self._thread:
            if hasattr(coroutine, "close"):
                coroutine.close()  # type: ignore[attr-defined]
            raise MCPRuntimeError("Synchronous MCP Host calls cannot run on its event-loop thread")
        future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        return future.result()

    def _require_runtime(self) -> MCPRuntime:
        with self._state_lock:
            if self._closed or self._runtime is None:
                raise MCPRuntimeError("MCP runtime Host is closed")
            return self._runtime

    def _run(self) -> None:
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            runtime = MCPRuntime(
                connector=self._connector,
                audit_sink=self._audit_sink,
                artifact_policy=self._artifact_policy,
                trusted_sandbox_launchers=self._trusted_sandbox_launchers,
            )
            with self._state_lock:
                self._loop = loop
                self._runtime = runtime
            self._started.set()
            loop.run_forever()
        except BaseException as exc:
            self._startup_error = exc
            self._started.set()
        finally:
            loop = self._loop
            if loop is not None:
                pending = asyncio.all_tasks(loop)
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()


@asynccontextmanager
async def _default_session_connector(config: MCPServerConfig):
    async with AsyncExitStack() as stack:
        if config.transport is MCPTransport.STDIO:
            scratch = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="secflow-mcp-runtime-")))
            try:
                scratch.chmod(0o700)
            except OSError:
                pass
            env = _stdio_environment(config, scratch)
            command, args = _sandboxed_command(config, scratch)
            params = StdioServerParameters(
                command=command,
                args=args,
                env=env,
                cwd=config.cwd,
                encoding="utf-8",
                encoding_error_handler="strict",
            )
            streams = await stack.enter_async_context(stdio_client(params, errlog=sys.stderr))
        elif config.transport is MCPTransport.STREAMABLE_HTTP:
            assert config.url is not None and config.tls is not None
            ssl_context = config.tls.create_ssl_context()

            def verified_client_factory(
                headers: dict[str, str] | None = None,
                timeout: httpx.Timeout | None = None,
                auth: httpx.Auth | None = None,
            ) -> httpx.AsyncClient:
                return httpx.AsyncClient(
                    headers=headers,
                    timeout=timeout or httpx.Timeout(30.0),
                    auth=auth,
                    follow_redirects=False,
                    verify=ssl_context,
                )

            streams = await stack.enter_async_context(
                streamablehttp_client(
                    config.url,
                    headers=dict(config.headers),
                    timeout=config.timeout_seconds,
                    sse_read_timeout=config.timeout_seconds,
                    terminate_on_close=True,
                    httpx_client_factory=verified_client_factory,
                )
            )
        else:  # pragma: no cover - configuration rejects this before connection.
            raise MCPConfigurationError(f"Unsupported MCP transport: {config.transport}")
        session = await stack.enter_async_context(
            ClientSession(
                streams[0],
                streams[1],
                read_timeout_seconds=timedelta(seconds=config.timeout_seconds),
            )
        )
        yield session


async def _discover_tools(
    session: _Session,
    config: MCPServerConfig,
    *,
    timeout: float,
) -> dict[str, MCPToolDescriptor]:
    result: dict[str, MCPToolDescriptor] = {}
    cursor: str | None = None
    while True:
        page = await asyncio.wait_for(session.list_tools(cursor=cursor), timeout=timeout)
        for raw_tool in getattr(page, "tools", ()):
            name = str(getattr(raw_tool, "name", "") or "")
            if not _TOOL_NAME_PATTERN.fullmatch(name):
                raise MCPRegistrationError(f"Invalid MCP tool name from {config.server_id}: {name!r}")
            tool_id = namespaced_tool_id(config.server_id, name)
            if tool_id in result:
                raise MCPRegistrationError(f"Duplicate MCP tool name from {config.server_id}: {name}")
            input_schema = getattr(raw_tool, "inputSchema", None) or {}
            output_schema = getattr(raw_tool, "outputSchema", None) or {}
            if not isinstance(input_schema, dict) or not isinstance(output_schema, dict):
                raise MCPRegistrationError(f"Invalid MCP JSON Schema for {tool_id}")
            _check_schema(input_schema, f"input schema for {tool_id}")
            if output_schema:
                _check_schema(output_schema, f"output schema for {tool_id}")
            result[tool_id] = MCPToolDescriptor(
                tool_id=tool_id,
                server_id=config.server_id,
                name=name,
                description=str(getattr(raw_tool, "description", "") or ""),
                input_schema=_freeze_json(input_schema),
                output_schema=_freeze_json(output_schema),
                generation=config.generation,
                plugin_id=config.plugin_id,
                plugin_version=config.plugin_version,
            )
        cursor = str(getattr(page, "nextCursor", "") or "") or None
        if cursor is None:
            break
    if not result:
        raise MCPRegistrationError(f"MCP server exposed no tools: {config.server_id}")
    return result


async def _call_with_policy(
    session: _Session,
    name: str,
    arguments: dict[str, Any],
    *,
    timeout_seconds: float,
    cancel_event: asyncio.Event | None,
) -> Any:
    call_task = asyncio.create_task(
        session.call_tool(
            name,
            arguments,
            read_timeout_seconds=timedelta(seconds=timeout_seconds),
        )
    )
    cancel_task: asyncio.Task[bool] | None = None
    try:
        if cancel_event is not None:
            cancel_task = asyncio.create_task(cancel_event.wait())
            done, _ = await asyncio.wait(
                {call_task, cancel_task},
                timeout=timeout_seconds,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancel_task in done and cancel_event.is_set():
                call_task.cancel()
                await _consume_cancelled_task(call_task)
                raise MCPToolCancelledError(f"MCP tool call was cancelled: {name}")
            if call_task not in done:
                call_task.cancel()
                await _consume_cancelled_task(call_task)
                raise MCPToolTimeoutError(f"MCP tool call timed out after {timeout_seconds:g}s: {name}")
            return await call_task
        try:
            return await asyncio.wait_for(call_task, timeout=timeout_seconds)
        except TimeoutError as exc:
            raise MCPToolTimeoutError(f"MCP tool call timed out after {timeout_seconds:g}s: {name}") from exc
    finally:
        if cancel_task is not None:
            cancel_task.cancel()
            await _consume_cancelled_task(cancel_task)


async def _consume_cancelled_task(task: asyncio.Task[Any]) -> None:
    try:
        await task
    except (asyncio.CancelledError, Exception):
        pass


def namespaced_tool_id(server_id: str, tool_name: str) -> str:
    namespace = str(server_id).replace("-", "_").replace(".", "_")
    return f"mcp__{namespace}__{tool_name}"


def builtin_stdio_server_config(
    server_id: str,
    *,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    startup_timeout_seconds: float = 30.0,
    max_result_bytes: int = _DEFAULT_MAX_RESULT_BYTES,
    generation: int = 1,
    plugin_id: str | None = None,
    plugin_version: str = "1",
) -> MCPServerConfig:
    """Build the canonical isolated-stdio config for a bundled MCP server."""

    clean_id = str(server_id or "").strip().lower()
    if clean_id not in BUILTIN_STDIO_SERVER_IDS:
        raise MCPConfigurationError(f"Unknown built-in MCP server: {server_id!r}")
    project_root = Path(__file__).resolve().parents[2]
    if getattr(sys, "frozen", False):
        command = sys.executable
        args = ("--mcp-server", clean_id)
    else:
        command = sys.executable
        args = (str(project_root / "mcp_stdio_launcher.py"), "--server", clean_id)
    explicit_environment = {str(key): str(value) for key, value in (environment or {}).items()}
    if not getattr(sys, "frozen", False):
        explicit_environment.setdefault("PYTHONPATH", str(project_root))
    explicit_environment.setdefault("PYTHONUNBUFFERED", "1")
    read_only_roots: tuple[Path, ...] = ()
    deny_network = clean_id == "translation"
    if deny_network:
        bundled_model_dir = (
            project_root
            / "app"
            / "resources"
            / "translation-models"
            / "opus-mt-en-zh-1.9"
        ).resolve(strict=False)
        roots = {
            Path(command).expanduser().resolve(strict=False).parent,
            Path(sys.prefix).expanduser().resolve(strict=False),
            Path(sys.base_prefix).expanduser().resolve(strict=False),
            bundled_model_dir,
        }
        if getattr(sys, "frozen", False):
            # Frozen dependencies live together under PyInstaller's _internal
            # directory. The signed bundle contains no mutable application data.
            roots.add(project_root.resolve(strict=False))
        else:
            # Source deployments keep durable secrets under project_root/data;
            # only application code/resources are readable by Translation MCP.
            roots.add((project_root / "app").resolve(strict=False))
            if str(sys.base_prefix).startswith("/opt/homebrew/"):
                for package in (
                    "gettext",
                    "mpdecimal",
                    "ncurses",
                    "openssl@3",
                    "readline",
                    "sqlite",
                    "xz",
                    "zstd",
                ):
                    dependency = Path("/opt/homebrew/opt") / package
                    if dependency.exists():
                        roots.add(dependency.resolve(strict=False))
        model_override = str(explicit_environment.get("SECFLOW_TRANSLATION_MODEL_DIR") or "").strip()
        if model_override:
            resolved_override = Path(model_override).expanduser().resolve(strict=False)
            if resolved_override != bundled_model_dir:
                raise MCPConfigurationError(
                    "Translation MCP model override must resolve to the bundled model resource"
                )
            roots.add(resolved_override)
        read_only_roots = tuple(sorted(roots, key=str))
    return MCPServerConfig(
        server_id=clean_id,
        transport=MCPTransport.STDIO,
        trust_level=MCPTrustLevel.BUILTIN,
        command=command,
        args=args,
        cwd=project_root,
        environment=explicit_environment,
        sandbox=SandboxPolicy(
            environment_allowlist=frozenset(explicit_environment),
            deny_network=deny_network,
            read_only_roots=read_only_roots,
        ),
        timeout_seconds=timeout_seconds,
        startup_timeout_seconds=startup_timeout_seconds,
        max_result_bytes=max_result_bytes,
        generation=generation,
        plugin_id=plugin_id or f"secflow.{clean_id}",
        plugin_version=plugin_version,
    )


def _sandboxed_command(config: MCPServerConfig, scratch: Path) -> tuple[str, list[str]]:
    assert config.command is not None
    prefix = config.sandbox.launcher_prefix
    if prefix:
        return prefix[0], [*prefix[1:], config.command, *config.args]
    if config.sandbox.deny_network and sys.platform == "darwin":
        sandbox_exec = Path("/usr/bin/sandbox-exec")
        if not sandbox_exec.is_file():
            raise MCPConfigurationError("macOS Translation MCP requires /usr/bin/sandbox-exec")
        profile = _darwin_sandbox_profile(config, scratch)
        return str(sandbox_exec), ["-p", profile, config.command, *config.args]
    if config.sandbox.deny_network:
        raise MCPConfigurationError(
            f"No approved OS network sandbox is available for Translation MCP on {sys.platform}"
        )
    return config.command, list(config.args)


def _darwin_sandbox_profile(config: MCPServerConfig, scratch: Path) -> str:
    read_roots = {
        Path("/System"),
        Path("/usr/lib"),
        Path("/usr/share"),
        Path("/dev"),
        Path("/private/etc"),
        Path("/private/var/db/dyld"),
        Path("/private/var/db/timezone"),
        Path("/Library/Apple"),
        Path("/Library/Frameworks"),
        Path("/Library/Preferences"),
        scratch.resolve(strict=False),
        *config.sandbox.read_only_roots,
    }
    readable = " ".join(
        f'(subpath "{_seatbelt_escape(path)}")'
        for path in sorted(read_roots, key=str)
    )
    literal_reads = {Path("/")}
    if config.cwd is not None:
        literal_reads.add(config.cwd.resolve(strict=False))
    for argument in config.args:
        candidate = Path(argument).expanduser()
        if candidate.is_absolute() and candidate.is_file():
            literal_reads.add(candidate.resolve(strict=False))
    readable_literals = " ".join(
        f'(literal "{_seatbelt_escape(path)}")'
        for path in sorted(literal_reads, key=str)
    )
    writable = _seatbelt_escape(scratch.resolve(strict=False))
    executable_paths = {
        Path(config.command).expanduser().absolute(),
        Path(config.command).expanduser().resolve(strict=False),
    }
    base_executable = str(getattr(sys, "_base_executable", "") or "").strip()
    if base_executable:
        executable_paths.add(Path(base_executable).expanduser().resolve(strict=False))
    python_app = (
        Path(sys.base_prefix).expanduser().resolve(strict=False)
        / "Resources"
        / "Python.app"
        / "Contents"
        / "MacOS"
        / "Python"
    )
    if python_app.is_file():
        executable_paths.add(python_app)
    executable_literals = " ".join(
        f'(literal "{_seatbelt_escape(path)}")'
        for path in sorted(executable_paths, key=str)
    )
    return (
        "(version 1)"
        "(deny default)"
        "(allow process-info*)"
        "(allow process-fork)"
        f"(allow process-exec {executable_literals})"
        "(allow signal (target self))"
        "(allow sysctl-read)"
        "(allow ipc-posix-shm)"
        "(allow file-read-metadata)"
        f"(allow file-read-data {readable_literals})"
        f"(allow file-read* {readable})"
        f'(allow file-write* (subpath "{writable}"))'
        "(deny network*)"
    )


def _seatbelt_escape(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


def _stdio_environment(config: MCPServerConfig, scratch: Path) -> dict[str, str]:
    env = dict(config.environment)
    for key in config.sandbox.environment_allowlist:
        if key in os.environ and key not in env:
            env[key] = os.environ[key]
    data_dir = scratch / "data"
    data_dir.mkdir(mode=0o700)
    home_dir = scratch / "home"
    home_dir.mkdir(mode=0o700)
    temp_dir = scratch / "tmp"
    temp_dir.mkdir(mode=0o700)
    env.update(
        {
            "HOME": str(home_dir),
            "USERPROFILE": str(home_dir),
            "LOGNAME": "secflow-mcp",
            "USER": "secflow-mcp",
            "SHELL": "",
            "TERM": "dumb",
            "TEMP": str(temp_dir),
            "TMP": str(temp_dir),
            "TMPDIR": str(temp_dir),
        }
    )
    env.setdefault("PATH", os.defpath)
    env["SECFLOW_MCP_RUNTIME_DIR"] = str(scratch)
    # Frozen MCP servers otherwise resolve the default relative data directory
    # inside the signed application bundle. Keep plugin state private and
    # ephemeral instead of exposing the host application's durable data.
    env["SECFLOW_DATA_DIR"] = str(data_dir)
    env["SECFLOW_MCP_SERVER_ID"] = config.server_id
    env["SECFLOW_MCP_PLUGIN_ID"] = config.plugin_id
    env["SECFLOW_MCP_PLUGIN_VERSION"] = config.plugin_version
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if config.server_id == "code-scan":
        scan_scratch = scratch / "scan"
        scan_scratch.mkdir(mode=0o700)
        env.setdefault("SECFLOW_SCAN_TEMP_ROOT", str(scan_scratch))
    return env


def _validate_json_schema(value: Any, schema: Mapping[str, Any], label: str) -> None:
    if not schema:
        return
    try:
        mutable_schema = _thaw_json(schema)
        validator_type = validator_for(mutable_schema)
        validator_type.check_schema(mutable_schema)
        validator_type(mutable_schema).validate(value)
    except JSONSchemaValidationError as exc:
        location = ".".join(str(item) for item in exc.absolute_path) or "$"
        raise MCPToolValidationError(f"Invalid {label} at {location}: {exc.message}") from exc
    except Exception as exc:
        raise MCPToolValidationError(f"Invalid {label}: {exc}") from exc


def _check_schema(schema: Mapping[str, Any], label: str) -> None:
    try:
        mutable_schema = _thaw_json(schema)
        validator_for(mutable_schema).check_schema(mutable_schema)
    except Exception as exc:
        raise MCPRegistrationError(f"Invalid {label}: {exc}") from exc


def _content_to_mapping(item: Any) -> Mapping[str, Any]:
    if hasattr(item, "model_dump"):
        value = item.model_dump(mode="json", by_alias=True, exclude_none=True)
        if isinstance(value, dict):
            return _freeze_json(value)
    if isinstance(item, Mapping):
        return _freeze_json(dict(item))
    return _freeze_json({"type": "text", "text": str(item)})


def _error_content(response: Any) -> str:
    parts = []
    for item in getattr(response, "content", None) or []:
        text = str(getattr(item, "text", "") or "").strip()
        if text:
            parts.append(text)
    return " ".join(parts)[:2_000]


def _audit_record(
    state: _ServerState,
    *,
    call_id: str,
    agent_id: str,
    tool_id: str,
    status: str,
    started_at: float,
    input_sha256: str,
    output_sha256: str,
    result_size: int,
    error_type: str = "",
) -> MCPAuditRecord:
    completed_at = time.time()
    config = state.config
    return MCPAuditRecord(
        call_id=call_id,
        agent_id=agent_id,
        server_id=config.server_id,
        tool_id=tool_id,
        transport=config.transport.value,
        status=status,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((completed_at - started_at) * 1_000)),
        input_sha256=input_sha256,
        output_sha256=output_sha256,
        result_size_bytes=result_size,
        plugin_id=config.plugin_id,
        plugin_version=config.plugin_version,
        config_hash=config.config_hash,
        generation=config.generation,
        error_type=error_type,
    )


def _validate_https_url(value: str | None) -> None:
    parsed = urlsplit(str(value or ""))
    if parsed.scheme.casefold() != "https" or not parsed.hostname:
        raise MCPConfigurationError("Remote MCP servers require an absolute https:// URL")
    if parsed.username or parsed.password:
        raise MCPConfigurationError("Remote MCP credentials must not be embedded in the URL")
    if parsed.fragment:
        raise MCPConfigurationError("Remote MCP URL fragments are not supported")


def _validate_headers(headers: Mapping[str, str]) -> None:
    for name, value in headers.items():
        if not _SAFE_HEADER_PATTERN.fullmatch(name) or "\r" in value or "\n" in value:
            raise MCPConfigurationError(f"Invalid remote MCP HTTP header: {name!r}")
        if name.casefold() in {"host", "content-length", "mcp-session-id"}:
            raise MCPConfigurationError(f"Host-managed MCP HTTP header cannot be overridden: {name}")


def _validate_environment(
    environment: Mapping[str, str],
    allowlist: frozenset[str],
    *,
    enforce_allowlist: bool,
) -> None:
    for key, value in environment.items():
        if not key or "=" in key or "\x00" in key or "\x00" in value:
            raise MCPConfigurationError(f"Invalid MCP process environment variable: {key!r}")
        if enforce_allowlist and key not in allowlist:
            raise MCPConfigurationError(f"MCP process environment variable is not allowlisted: {key}")


def _validate_working_directory(value: Path | None) -> None:
    if value is None:
        raise MCPConfigurationError("A local stdio MCP server requires an explicit working directory")
    if not value.is_absolute() or not value.is_dir():
        raise MCPConfigurationError(f"MCP working directory must be an existing absolute directory: {value}")


def _optional_path(value: Path | str | None) -> Path | None:
    if value is None or not str(value).strip():
        return None
    return Path(value).expanduser().resolve(strict=False)


def _existing_file(value: Path | str | None, label: str) -> Path | None:
    path = _optional_path(value)
    if path is not None and (not path.is_file() or not path.is_absolute()):
        raise MCPConfigurationError(f"{label} must be an existing absolute file: {path}")
    return path


def _secret_mapping_fingerprints(values: Mapping[str, str]) -> dict[str, str]:
    """Cover secret-bearing configuration without retaining plaintext values."""

    return {
        key: hashlib.sha256(value.encode("utf-8")).hexdigest()
        for key, value in sorted(values.items())
    }


def _tls_fingerprints(config: TLSConfig | None) -> dict[str, str]:
    if config is None:
        return {}
    return {
        "ca_file": _path_fingerprint(config.ca_file),
        "client_cert": _path_fingerprint(config.client_cert),
        "client_key": _path_fingerprint(config.client_key),
        "client_key_password": (
            hashlib.sha256(config.client_key_password.encode("utf-8")).hexdigest()
            if config.client_key_password
            else ""
        ),
        "verify_mode": "CERT_REQUIRED",
        "check_hostname": "true",
    }


def _path_fingerprint(value: Path | str | None) -> str:
    path = _optional_path(value)
    if path is None:
        return ""
    if not path.is_file():
        return f"missing:{path}"
    return f"sha256:{_sha256_file(path)}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _reject_large_inline_artifacts(value: Any, *, limit: int, path: str = "$") -> None:
    """Prevent large binary artifacts from being smuggled through JSON/Base64."""

    if isinstance(value, Mapping):
        for key, item in value.items():
            child_path = f"{path}.{key}"
            if (
                isinstance(item, str)
                and (str(key).casefold().endswith("_base64") or str(key).casefold() == "base64")
                and len(item.encode("ascii", errors="ignore")) > limit
            ):
                raise MCPResultTooLargeError(
                    f"Inline MCP artifact exceeds {limit} bytes at {child_path}; return a relative artifact reference"
                )
            _reject_large_inline_artifacts(item, limit=limit, path=child_path)
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _reject_large_inline_artifacts(item, limit=limit, path=f"{path}[{index}]")


def _freeze_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    return value


def _canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            default=_json_default,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise MCPToolValidationError(f"MCP payload is not JSON serializable: {exc}") from exc


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _best_effort_sha256(value: Any) -> str:
    try:
        return _sha256_json(value)
    except Exception:
        fallback = f"<{type(value).__module__}.{type(value).__qualname__}>".encode("utf-8")
        return hashlib.sha256(fallback).hexdigest()


def _json_default(value: Any) -> Any:
    if isinstance(value, MappingProxyType):
        return dict(value)
    if isinstance(value, Mapping):
        return dict(value)
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


__all__ = [
    "BUILTIN_STDIO_SERVER_IDS",
    "ArtifactManager",
    "ArtifactPolicy",
    "HostArtifact",
    "MCPAuditRecord",
    "MCPAuthorizationError",
    "MCPConfigurationError",
    "MCPRegistry",
    "MCPRegistrationError",
    "MCPResultTooLargeError",
    "MCPRuntime",
    "MCPRuntimeHost",
    "MCPRuntimeError",
    "MCPServerConfig",
    "MCPServerLifecycle",
    "MCPToolCancelledError",
    "MCPToolDescriptor",
    "MCPToolExecutionError",
    "MCPToolNotFoundError",
    "MCPToolTimeoutError",
    "MCPToolValidationError",
    "MCPTransport",
    "MCPTrustLevel",
    "SandboxPolicy",
    "TLSConfig",
    "ToolArtifactPolicy",
    "ToolBroker",
    "ToolExecutionResult",
    "builtin_stdio_server_config",
    "namespaced_tool_id",
]
