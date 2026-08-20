from __future__ import annotations

import atexit
import os
import secrets
import shutil
import sys
import tempfile
import weakref
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Mapping

from app.mcp.runtime import (
    MCPRuntimeHost,
    MCPServerConfig,
    SandboxPolicy,
    namespaced_tool_id,
)


class CodeScanMCPError(RuntimeError):
    pass


class CodeScanMCPClient:
    def __init__(
        self,
        *,
        startup_timeout: float | None = None,
        read_timeout: float | None = None,
        allowed_tools: set[str] | tuple[str, ...] | None = None,
    ) -> None:
        packaged_default = 60.0 if getattr(sys, "frozen", False) else 15.0
        configured_startup_timeout = startup_timeout
        if configured_startup_timeout is None:
            configured_startup_timeout = float(
                os.getenv("SECFLOW_CODE_SCAN_MCP_STARTUP_TIMEOUT_SECONDS", str(packaged_default))
                or packaged_default
            )
        self._startup_timeout = max(1.0, float(configured_startup_timeout))
        configured_read_timeout = read_timeout or float(
            os.getenv("SECFLOW_CODE_SCAN_MCP_READ_TIMEOUT_SECONDS", "86400") or 86400
        )
        self._read_timeout = max(60.0, configured_read_timeout)
        self._allowed_tools = frozenset(allowed_tools or {"scan_language"})
        unsupported = self._allowed_tools - {"scan_language"}
        if unsupported or not self._allowed_tools:
            raise ValueError("Code Scan MCP client requires a non-empty supported tool allowlist")
        self._lock = RLock()
        self._host: MCPRuntimeHost | None = None
        self._token = ""
        self._runtime_path: Path | None = None
        _ACTIVE_CLIENTS.add(self)

    def __del__(self) -> None:
        try:
            self.shutdown()
        except Exception:
            return

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
        self._require_tool("scan_language")
        if not self.enabled:
            raise CodeScanMCPError("Code Scan MCP stdio transport is disabled")
        try:
            host, token = self._ensure_server()
        except Exception as exc:
            self.shutdown()
            raise CodeScanMCPError(self._failure_message(exc)) from exc
        with self._lock:
            runtime_path = self._runtime_path
        if runtime_path is None:
            self.shutdown()
            raise CodeScanMCPError("Code Scan MCP private runtime is unavailable")
        with tempfile.TemporaryDirectory(
            prefix="secflow-code-scan-cancel-",
            dir=_verified_private_runtime(runtime_path),
        ) as temp_dir:
            marker = Path(temp_dir) / "cancel"
            arguments = {
                "capability_token": token,
                "workspace_path": workspace_path,
                "language": language,
                "source_paths": source_paths,
                "manifest_files": manifest_files,
                "dependency_scan": dependency_scan,
                "rule_paths": rule_paths,
                "complete_scan": bool(complete_scan),
                "cancel_marker": str(marker),
            }
            try:
                execution = host.call(
                    agent_id="code_scan_agent",
                    tool_id=namespaced_tool_id("code-scan", "scan_language"),
                    arguments=arguments,
                    timeout_seconds=self._read_timeout,
                    cancelled=lambda: _mark_cancelled(cancelled, marker),
                )
                payload = _mutable_json(execution.data or {})
            except Exception as exc:  # noqa: BLE001 - normalize transport failures for the task graph.
                if cancelled():
                    self.cancel_active_scan()
                    raise CodeScanMCPError("Code Scan MCP call was cancelled") from exc
                message = self._failure_message(exc)
                self.cancel_active_scan()
                raise CodeScanMCPError(message) from exc
            if cancelled():
                self.cancel_active_scan()
                raise CodeScanMCPError("Code Scan MCP call was cancelled")
        result = payload.get("result")
        if not isinstance(result, dict):
            raise CodeScanMCPError("Code Scan MCP returned no structured scan result")
        result["_scan_mcp"] = {
            "schema_version": int(payload.get("schema_version") or 1),
            "server": str(payload.get("server") or "SecFlow Code Scan MCP"),
            "tool": str(payload.get("tool") or "scan_language"),
            "transport": "stdio",
            "endpoint": "managed-child-process",
            "process_id": int(payload.get("process_id") or 0),
            "language": str(payload.get("language") or language),
            "started_at": str(payload.get("started_at") or ""),
            "completed_at": str(payload.get("completed_at") or ""),
            "duration_ms": int(payload.get("duration_ms") or 0),
            "input_sha256": execution.input_sha256,
            "output_sha256": execution.output_sha256,
            "server_input_sha256": str(payload.get("input_sha256") or ""),
            "server_output_sha256": str(payload.get("output_sha256") or ""),
            "call_id": execution.call_id,
            "result_size_bytes": execution.result_size_bytes,
            "plugin_id": execution.audit.plugin_id,
            "plugin_version": execution.audit.plugin_version,
            "config_hash": execution.audit.config_hash,
            "generation": execution.audit.generation,
            "status": "completed",
        }
        return result

    def capabilities(self) -> dict[str, Any]:
        host, token = self._ensure_server()
        execution = host.call(
            agent_id="code_scan_agent",
            tool_id=namespaced_tool_id("code-scan", "get_scan_capabilities"),
            arguments={"capability_token": token},
            timeout_seconds=self._startup_timeout,
        )
        return _mutable_json(execution.data or {})

    def shutdown(self) -> None:
        self._shutdown_server(grace_seconds=3.0)

    def cancel_active_scan(self) -> None:
        """Immediately stop the managed scan engine and remove its private scratch data."""

        self._shutdown_server(grace_seconds=0.25)

    def _shutdown_server(self, *, grace_seconds: float) -> None:
        del grace_seconds  # MCP stdio performs graceful close then process-tree termination.
        with self._lock:
            host = self._host
            self._host = None
            self._token = ""
            runtime_path = self._runtime_path
            self._runtime_path = None
        try:
            if host is not None:
                host.shutdown()
        finally:
            _remove_private_runtime(runtime_path)

    def _ensure_server(self) -> tuple[MCPRuntimeHost, str]:
        with self._lock:
            if self._host is not None and self._token:
                return self._host, self._token
            token = secrets.token_urlsafe(32)
            runtime_path = Path(tempfile.mkdtemp(prefix="secflow-code-scan-runtime-"))
            command, prefix_args = _server_command()
            environment = _server_environment(
                token,
                allowed_tools=self._allowed_tools,
                runtime_path=runtime_path,
            )
            config = MCPServerConfig(
                server_id="code-scan",
                transport="stdio",
                trust_level="builtin",
                command=command,
                args=(
                    *prefix_args,
                    "--transport",
                    "stdio",
                    "--parent-pid",
                    str(os.getpid()),
                ),
                cwd=_repository_root(),
                environment=environment,
                sandbox=SandboxPolicy(environment_allowlist=frozenset(environment)),
                timeout_seconds=self._read_timeout,
                startup_timeout_seconds=self._startup_timeout,
                max_result_bytes=64 * 1024 * 1024,
                plugin_id="secflow.code-scan",
                plugin_version="1",
            )
            host = MCPRuntimeHost(thread_name="secflow-code-scan-mcp")
            try:
                host.register_server(config)
                host.set_agent_allowlist(
                    "code_scan_agent",
                    [
                        namespaced_tool_id("code-scan", "scan_language"),
                        namespaced_tool_id("code-scan", "get_scan_capabilities"),
                    ],
                )
            except BaseException:
                host.shutdown()
                _remove_private_runtime(runtime_path)
                raise
            self._host = host
            self._token = token
            self._runtime_path = runtime_path
            return host, token

    def _failure_message(self, exc: Exception) -> str:
        detail = str(exc).strip()
        return f"Code Scan MCP stdio call failed: {detail or type(exc).__name__}"

    def _require_tool(self, tool_name: str) -> None:
        if tool_name not in self._allowed_tools:
            raise CodeScanMCPError(f"Code Scan MCP tool is outside this agent capability: {tool_name}")


def _mark_cancelled(cancelled: Callable[[], bool], marker: Path) -> bool:
    if not cancelled():
        return False
    try:
        marker.touch(exist_ok=True)
    except OSError:
        pass
    return True


def _mutable_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _mutable_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mutable_json(item) for item in value]
    return value


def _server_command() -> tuple[str, list[str]]:
    override = os.getenv("SECFLOW_CODE_SCAN_MCP_COMMAND", "").strip()
    if override:
        return override, []
    if getattr(sys, "frozen", False):
        return sys.executable, ["--code-scan-mcp"]
    return sys.executable, ["-m", "app.mcp.code_scan"]


def _server_environment(
    token: str,
    *,
    allowed_tools: set[str] | tuple[str, ...] | frozenset[str] | None = None,
    runtime_path: Path,
) -> dict[str, str]:
    private_runtime = _verified_private_runtime(runtime_path)
    allowed_names = {
        "COMSPEC",
        "DYLD_LIBRARY_PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "LD_LIBRARY_PATH",
        "PATH",
        "PATHEXT",
        "SYSTEMDRIVE",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USERPROFILE",
        "VIRTUAL_ENV",
        "SECFLOW_BUNDLED_SEMGREP_BIN",
        "SECFLOW_STATIC_MAX_FINDINGS",
    }
    allowed_prefixes = (
        "LC_",
        "SECFLOW_JAVA_FLOW_",
        "SECFLOW_SEMGREP_",
    )
    env = {
        key: value
        for key, value in os.environ.items()
        if key in allowed_names or key.startswith(allowed_prefixes)
    }
    env["SECFLOW_CODE_SCAN_MCP_TOKEN"] = token
    env["SECFLOW_CODE_SCAN_MCP_ALLOWED_TOOLS"] = ",".join(sorted(allowed_tools or {"scan_language"}))
    env["SECFLOW_CODE_SCAN_CANCEL_ROOT"] = str(private_runtime)
    env["PYTHONUNBUFFERED"] = "1"
    if getattr(sys, "frozen", False):
        # The MCP server and bundled Semgrep are independent PyInstaller apps.
        # Reusing the parent's archive metadata makes the Semgrep bootloader open
        # the backend archive and silently fall back to an incomplete scan.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    else:
        env["PYTHONPATH"] = str(_repository_root())
    return env


def _verified_private_runtime(path: Path) -> str:
    if path.is_symlink():
        raise CodeScanMCPError("Code Scan MCP private runtime cannot be a symlink")
    try:
        resolved = path.resolve(strict=True)
        system_temp = Path(tempfile.gettempdir()).resolve(strict=True)
        resolved.relative_to(system_temp)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CodeScanMCPError(
            "Code Scan MCP private runtime must be inside the system temporary directory"
        ) from exc
    if not resolved.is_dir() or not resolved.name.startswith("secflow-code-scan-runtime-"):
        raise CodeScanMCPError("Code Scan MCP private runtime is invalid")
    return str(resolved)


def _remove_private_runtime(path: Path | None) -> None:
    if path is None:
        return
    try:
        resolved = path.resolve(strict=False)
        temp_root = Path(tempfile.gettempdir()).resolve(strict=True)
        resolved.relative_to(temp_root)
    except (OSError, RuntimeError, ValueError):
        return
    if not resolved.name.startswith("secflow-code-scan-runtime-"):
        return
    shutil.rmtree(resolved, ignore_errors=True)


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


_ACTIVE_CLIENTS: weakref.WeakSet[CodeScanMCPClient] = weakref.WeakSet()


@atexit.register
def _shutdown_active_clients() -> None:
    for client in list(_ACTIVE_CLIENTS):
        client.shutdown()
