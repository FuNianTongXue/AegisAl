from __future__ import annotations

import asyncio
import atexit
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import weakref
from pathlib import Path
from threading import Event, RLock, Thread
from typing import Any, Callable

from mcp import ClientSession
from mcp.client.sse import sse_client


class CodeScanMCPError(RuntimeError):
    pass


class CodeScanMCPClient:
    def __init__(
        self,
        *,
        startup_timeout: float | None = None,
        sse_read_timeout: float | None = None,
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
        configured_read_timeout = sse_read_timeout or float(
            os.getenv("SECFLOW_CODE_SCAN_MCP_READ_TIMEOUT_SECONDS", "86400") or 86400
        )
        self._sse_read_timeout = max(60.0, configured_read_timeout)
        self._allowed_tools = frozenset(allowed_tools or {"scan_language"})
        unsupported = self._allowed_tools - {"scan_language"}
        if unsupported or not self._allowed_tools:
            raise ValueError("Code Scan MCP client requires a non-empty supported tool allowlist")
        self._lock = RLock()
        self._process: subprocess.Popen[bytes] | None = None
        self._port = 0
        self._token = ""
        self._log_path: Path | None = None
        self._runtime_path: Path | None = None
        _ACTIVE_CLIENTS.add(self)

    def __del__(self) -> None:
        try:
            self.shutdown()
        except Exception:
            return

    @property
    def enabled(self) -> bool:
        return os.getenv("SECFLOW_CODE_SCAN_MCP_TRANSPORT", "sse").strip().casefold() == "sse"

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
            raise CodeScanMCPError("Code Scan MCP SSE transport is disabled")
        endpoint, token = self._ensure_server()
        with tempfile.TemporaryDirectory(prefix="secflow-code-scan-cancel-") as temp_dir:
            marker = Path(temp_dir) / "cancel"
            monitor_stop = Event()
            monitor = Thread(
                target=_monitor_cancellation,
                args=(cancelled, marker, monitor_stop, self.cancel_active_scan),
                daemon=True,
                name=f"secflow-code-scan-cancel-{language}",
            )
            monitor.start()
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
                payload = asyncio.run(self._call_tool(endpoint, "scan_language", arguments))
            except Exception as exc:  # noqa: BLE001 - normalize transport failures for the task graph.
                if cancelled():
                    self.cancel_active_scan()
                    raise CodeScanMCPError("Code Scan MCP call was cancelled") from exc
                raise CodeScanMCPError(self._failure_message(exc)) from exc
            finally:
                monitor_stop.set()
                monitor.join(timeout=0.2)
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
            "transport": "sse",
            "endpoint": "loopback-managed",
            "process_id": int(payload.get("process_id") or 0),
            "language": str(payload.get("language") or language),
            "started_at": str(payload.get("started_at") or ""),
            "completed_at": str(payload.get("completed_at") or ""),
            "duration_ms": int(payload.get("duration_ms") or 0),
            "input_sha256": str(payload.get("input_sha256") or ""),
            "output_sha256": str(payload.get("output_sha256") or ""),
            "status": "completed",
        }
        return result

    def capabilities(self) -> dict[str, Any]:
        endpoint, token = self._ensure_server()
        return asyncio.run(
            self._call_tool(endpoint, "get_scan_capabilities", {"capability_token": token})
        )

    def shutdown(self) -> None:
        self._shutdown_server(grace_seconds=3.0)

    def cancel_active_scan(self) -> None:
        """Immediately stop the managed scan engine and remove its private scratch data."""

        self._shutdown_server(grace_seconds=0.25)

    def _shutdown_server(self, *, grace_seconds: float) -> None:
        with self._lock:
            process = self._process
            self._process = None
            self._port = 0
            self._token = ""
            log_path = self._log_path
            self._log_path = None
            runtime_path = self._runtime_path
            self._runtime_path = None
        try:
            if process is not None and process.poll() is None:
                _signal_server_process(process, force=False)
                try:
                    process.wait(timeout=max(0.05, grace_seconds))
                except subprocess.TimeoutExpired:
                    _signal_server_process(process, force=True)
                    try:
                        process.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        pass
        finally:
            if log_path is not None:
                log_path.unlink(missing_ok=True)
            _remove_private_runtime(runtime_path)

    async def _call_tool(self, endpoint: str, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        async with sse_client(
            endpoint,
            timeout=10,
            sse_read_timeout=self._sse_read_timeout,
        ) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                response = await session.call_tool(tool_name, arguments)
        if response.isError:
            detail = " ".join(
                str(getattr(item, "text", "") or "").strip()
                for item in response.content
                if str(getattr(item, "text", "") or "").strip()
            )
            raise CodeScanMCPError(detail or f"Code Scan MCP tool failed: {tool_name}")
        if isinstance(response.structuredContent, dict):
            return dict(response.structuredContent)
        raise CodeScanMCPError(f"Code Scan MCP tool returned no structured output: {tool_name}")

    def _ensure_server(self) -> tuple[str, str]:
        with self._lock:
            if self._process is not None and self._process.poll() is None and self._port and self._token:
                process = self._process
                port = self._port
                token = self._token
            else:
                self._cleanup_stopped_process()
                port = _reserve_loopback_port()
                token = secrets.token_urlsafe(32)
                runtime_path = Path(tempfile.mkdtemp(prefix="secflow-code-scan-runtime-"))
                command, prefix_args = _server_command()
                args = [
                    *prefix_args,
                    "--transport",
                    "sse",
                    "--host",
                    "127.0.0.1",
                    "--port",
                    str(port),
                    "--parent-pid",
                    str(os.getpid()),
                ]
                env = _server_environment(
                    token,
                    allowed_tools=self._allowed_tools,
                    runtime_path=runtime_path,
                )
                log_handle = tempfile.NamedTemporaryFile(
                    mode="w+b",
                    prefix="secflow-code-scan-mcp-",
                    suffix=".log",
                    delete=False,
                )
                log_path = Path(log_handle.name)
                try:
                    process = subprocess.Popen(
                        [command, *args],
                        cwd=str(_repository_root()),
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=log_handle,
                        stderr=subprocess.STDOUT,
                        start_new_session=sys.platform != "win32",
                    )
                except BaseException:
                    log_handle.close()
                    log_path.unlink(missing_ok=True)
                    _remove_private_runtime(runtime_path)
                    raise
                else:
                    log_handle.close()
                self._process = process
                self._port = port
                self._token = token
                self._log_path = log_path
                self._runtime_path = runtime_path
            deadline = time.monotonic() + self._startup_timeout
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    message = self._read_log()
                    self.shutdown()
                    raise CodeScanMCPError(
                        f"Code Scan MCP SSE service exited during startup: {message or process.returncode}"
                    )
                if _loopback_port_is_open(port):
                    return f"http://127.0.0.1:{port}/sse", token
                time.sleep(0.05)
            message = self._read_log()
            self.shutdown()
            raise CodeScanMCPError(f"Code Scan MCP SSE service startup timed out: {message or 'no log'}")

    def _failure_message(self, exc: Exception) -> str:
        detail = str(exc).strip()
        log = self._read_log()
        if self._process is not None and self._process.poll() is not None:
            self.shutdown()
        return f"Code Scan MCP SSE call failed: {detail or log or type(exc).__name__}"

    def _require_tool(self, tool_name: str) -> None:
        if tool_name not in self._allowed_tools:
            raise CodeScanMCPError(f"Code Scan MCP tool is outside this agent capability: {tool_name}")

    def _read_log(self) -> str:
        path = self._log_path
        if path is None:
            return ""
        try:
            text = path.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""
        return " ".join(text.split())[-1000:]

    def _cleanup_stopped_process(self) -> None:
        if self._process is not None and self._process.poll() is not None:
            self._process = None
        if self._log_path is not None:
            self._log_path.unlink(missing_ok=True)
            self._log_path = None
        _remove_private_runtime(self._runtime_path)
        self._runtime_path = None
        self._port = 0
        self._token = ""


def _monitor_cancellation(
    cancelled: Callable[[], bool],
    marker: Path,
    stop: Event,
    terminate_scan: Callable[[], None],
) -> None:
    while not stop.wait(0.05):
        if cancelled():
            try:
                marker.touch(exist_ok=True)
            except OSError:
                pass
            try:
                terminate_scan()
            except Exception:
                pass
            return


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
    env["SECFLOW_SCAN_TEMP_ROOT"] = str(runtime_path)
    env["PYTHONUNBUFFERED"] = "1"
    if getattr(sys, "frozen", False):
        # The MCP server and bundled Semgrep are independent PyInstaller apps.
        # Reusing the parent's archive metadata makes the Semgrep bootloader open
        # the backend archive and silently fall back to an incomplete scan.
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    else:
        env["PYTHONPATH"] = str(_repository_root())
    return env


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


def _reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _loopback_port_is_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _signal_server_process(process: subprocess.Popen[bytes], *, force: bool) -> None:
    try:
        if sys.platform != "win32":
            import signal

            os.killpg(process.pid, signal.SIGKILL if force else signal.SIGTERM)
        elif force:
            process.kill()
        else:
            process.terminate()
    except (OSError, ProcessLookupError):
        return


_ACTIVE_CLIENTS: weakref.WeakSet[CodeScanMCPClient] = weakref.WeakSet()


@atexit.register
def _shutdown_active_clients() -> None:
    for client in list(_ACTIVE_CLIENTS):
        client.shutdown()
