from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, patch

from app.mcp.runtime import (
    BUILTIN_STDIO_SERVER_IDS,
    ArtifactPolicy,
    MCPAuthorizationError,
    MCPConfigurationError,
    MCPResultTooLargeError,
    MCPRuntime,
    MCPRuntimeHost,
    MCPServerConfig,
    MCPToolCancelledError,
    MCPToolNotFoundError,
    MCPToolTimeoutError,
    MCPToolValidationError,
    SandboxPolicy,
    TLSConfig,
    ToolArtifactPolicy,
    _stdio_environment,
    _sandboxed_command,
    builtin_stdio_server_config,
    namespaced_tool_id,
)


class FakeSession:
    def __init__(self, *, response: Any | None = None, wait: asyncio.Event | None = None) -> None:
        self.initialized = False
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.wait = wait
        self.response = response or SimpleNamespace(
            isError=False,
            structuredContent={"answer": 3},
            content=[SimpleNamespace(model_dump=lambda **_kwargs: {"type": "text", "text": "3"})],
        )

    async def initialize(self) -> None:
        self.initialized = True

    async def list_tools(self, cursor: str | None = None) -> Any:
        return SimpleNamespace(
            tools=[
                SimpleNamespace(
                    name="add",
                    description="Add two integers",
                    inputSchema={
                        "type": "object",
                        "properties": {"left": {"type": "integer"}, "right": {"type": "integer"}},
                        "required": ["left", "right"],
                        "additionalProperties": False,
                    },
                    outputSchema={
                        "type": "object",
                        "properties": {"answer": {"type": "integer"}},
                        "required": ["answer"],
                        "additionalProperties": False,
                    },
                )
            ],
            nextCursor=None,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: Any | None = None,
    ) -> Any:
        self.calls.append((name, dict(arguments or {})))
        if self.wait is not None:
            await self.wait.wait()
        return self.response


class FakeConnector:
    def __init__(self, session: FakeSession) -> None:
        self.session = session
        self.entered = 0
        self.exited = 0

    @asynccontextmanager
    async def __call__(self, _config: MCPServerConfig):
        self.entered += 1
        try:
            yield self.session
        finally:
            self.exited += 1


class ArtifactSession(FakeSession):
    async def list_tools(self, cursor: str | None = None) -> Any:
        return SimpleNamespace(
            tools=[
                SimpleNamespace(
                    name="render",
                    description="Render an artifact",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "value": {"type": "string"},
                            "output_dir": {"type": "string"},
                        },
                        "required": ["value", "output_dir"],
                        "additionalProperties": False,
                    },
                    outputSchema={
                        "type": "object",
                        "properties": {
                            "artifacts": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string"},
                                        "media_type": {"type": "string"},
                                        "sha256": {"type": "string"},
                                    },
                                    "required": ["path", "media_type", "sha256"],
                                },
                            }
                        },
                        "required": ["artifacts"],
                    },
                )
            ],
            nextCursor=None,
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        read_timeout_seconds: Any | None = None,
    ) -> Any:
        args = dict(arguments or {})
        self.calls.append((name, args))
        payload = args["value"].encode()
        output = Path(args["output_dir"]) / "report.txt"
        output.write_bytes(payload)
        return SimpleNamespace(
            isError=False,
            structuredContent={
                "artifacts": [
                    {
                        "path": "report.txt",
                        "media_type": "text/plain",
                        "sha256": hashlib.sha256(payload).hexdigest(),
                    }
                ]
            },
            content=[],
        )


def local_config(root: Path, **overrides: Any) -> MCPServerConfig:
    values = {
        "server_id": "math-tools",
        "transport": "stdio",
        "trust_level": "builtin",
        "command": sys.executable,
        "args": ("-c", "pass"),
        "cwd": root,
        "timeout_seconds": 1.0,
        "startup_timeout_seconds": 1.0,
        "max_result_bytes": 4096,
        "plugin_id": "secflow.math",
        "plugin_version": "1.2.3",
        "generation": 7,
    }
    values.update(overrides)
    return MCPServerConfig(**values)


class MCPRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    async def asyncTearDown(self) -> None:
        self.temp.cleanup()

    async def test_register_call_validates_authorizes_hashes_and_audits(self) -> None:
        session = FakeSession()
        connector = FakeConnector(session)
        runtime = MCPRuntime(connector=connector)
        self.addAsyncCleanup(runtime.close)
        descriptors = await runtime.register_server(local_config(self.root))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])

        result = await runtime.tools.call(
            agent_id="calculator",
            tool_id=tool_id,
            arguments={"left": 1, "right": 2},
        )

        self.assertEqual([item.tool_id for item in descriptors], [tool_id])
        self.assertTrue(session.initialized)
        self.assertEqual(session.calls, [("add", {"left": 1, "right": 2})])
        self.assertEqual(dict(result.data or {}), {"answer": 3})
        self.assertEqual(result.status, "completed")
        self.assertEqual(result.audit.transport, "stdio")
        self.assertEqual(result.audit.plugin_id, "secflow.math")
        self.assertEqual(result.audit.generation, 7)
        self.assertEqual(
            result.input_sha256,
            hashlib.sha256(b'{"left":1,"right":2}').hexdigest(),
        )
        self.assertEqual(len(result.output_sha256), 64)
        self.assertEqual(runtime.tools.audit_records, (result.audit,))
        snapshot = await runtime.registry.snapshot()
        self.assertEqual(snapshot["servers"][0]["lifecycle"], "active")
        self.assertEqual(snapshot["tools"][0]["id"], tool_id)

    async def test_remote_streamable_http_uses_same_broker_without_real_network(self) -> None:
        session = FakeSession()
        runtime = MCPRuntime(connector=FakeConnector(session))
        self.addAsyncCleanup(runtime.close)
        config = MCPServerConfig(
            server_id="remote-math",
            transport="streamable-http",
            trust_level="remote",
            url="https://mcp.example.test/mcp",
            tls=TLSConfig(),
            timeout_seconds=1,
            startup_timeout_seconds=1,
        )
        await runtime.register_server(config)
        tool_id = namespaced_tool_id("remote-math", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])

        result = await runtime.tools.call(
            agent_id="calculator",
            tool_id=tool_id,
            arguments={"left": 1, "right": 2},
        )

        self.assertEqual(result.audit.transport, "streamable-http")
        self.assertEqual(result.data["answer"], 3)

    async def test_allowlist_is_enforced_before_server_execution(self) -> None:
        session = FakeSession()
        runtime = MCPRuntime(connector=FakeConnector(session))
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("reader", [])

        with self.assertRaises(MCPAuthorizationError):
            await runtime.tools.call(
                agent_id="reader",
                tool_id=tool_id,
                arguments={"left": 1, "right": 2},
            )

        self.assertEqual(session.calls, [])
        self.assertEqual(runtime.tools.audit_records[-1].status, "rejected")
        self.assertEqual(runtime.tools.audit_records[-1].error_type, "authorization")
        self.assertEqual(len(runtime.tools.audit_records[-1].input_sha256), 64)

    async def test_input_and_output_json_schema_are_host_enforced(self) -> None:
        session = FakeSession()
        runtime = MCPRuntime(connector=FakeConnector(session))
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])

        with self.assertRaises(MCPToolValidationError):
            await runtime.tools.call(
                agent_id="calculator",
                tool_id=tool_id,
                arguments={"left": "one", "right": 2},
            )
        self.assertEqual(session.calls, [])
        self.assertEqual(runtime.tools.audit_records[-1].status, "rejected")
        self.assertEqual(runtime.tools.audit_records[-1].error_type, "schema_validation")

        session.response = SimpleNamespace(
            isError=False,
            structuredContent={"answer": "three"},
            content=[],
        )
        with self.assertRaises(MCPToolValidationError):
            await runtime.tools.call(
                agent_id="calculator",
                tool_id=tool_id,
                arguments={"left": 1, "right": 2},
            )
        self.assertEqual(runtime.tools.audit_records[-1].status, "failed")

    async def test_result_size_limit_is_host_enforced(self) -> None:
        session = FakeSession(
            response=SimpleNamespace(
                isError=False,
                structuredContent={"answer": 3},
                content=[{"type": "text", "text": "x" * 500}],
            )
        )
        runtime = MCPRuntime(connector=FakeConnector(session))
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root, max_result_bytes=100))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])

        with self.assertRaises(MCPResultTooLargeError):
            await runtime.tools.call(
                agent_id="calculator",
                tool_id=tool_id,
                arguments={"left": 1, "right": 2},
            )

    async def test_server_lock_wait_is_included_in_call_timeout(self) -> None:
        session = FakeSession()
        runtime = MCPRuntime(connector=FakeConnector(session))
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root, timeout_seconds=1.0))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])
        state, _descriptor = await runtime.registry.resolve(tool_id)
        await state.call_lock.acquire()
        try:
            with self.assertRaises(MCPToolTimeoutError):
                await runtime.tools.call(
                    agent_id="calculator",
                    tool_id=tool_id,
                    arguments={"left": 1, "right": 2},
                    timeout_seconds=0.02,
                )
        finally:
            state.call_lock.release()

        self.assertEqual(session.calls, [])
        self.assertEqual(runtime.tools.audit_records[-1].status, "timed_out")

    async def test_explicit_cancellation_revokes_tools_and_closes_process_session(self) -> None:
        never = asyncio.Event()
        session = FakeSession(wait=never)
        connector = FakeConnector(session)
        runtime = MCPRuntime(connector=connector)
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root))
        tool_id = namespaced_tool_id("math-tools", "add")
        await runtime.tools.set_agent_allowlist("calculator", [tool_id])
        cancel = asyncio.Event()
        cancel.set()

        with self.assertRaises(MCPToolCancelledError):
            await runtime.tools.call(
                agent_id="calculator",
                tool_id=tool_id,
                arguments={"left": 1, "right": 2},
                cancel_event=cancel,
            )

        with self.assertRaises(MCPToolNotFoundError):
            await runtime.registry.resolve(tool_id)
        self.assertEqual(connector.exited, 1)
        self.assertEqual(runtime.tools.audit_records[-1].status, "cancelled")

    async def test_real_stdio_server_runs_out_of_process(self) -> None:
        script = self.root / "server.py"
        script.write_text(
            textwrap.dedent(
                """
                import os
                from mcp.server.fastmcp import FastMCP
                from pydantic import BaseModel

                class Output(BaseModel):
                    process_id: int
                    value: str

                server = FastMCP("Runtime integration test")

                @server.tool(structured_output=True)
                def identity(value: str) -> Output:
                    return Output(process_id=os.getpid(), value=value)

                server.run(transport="stdio")
                """
            ),
            encoding="utf-8",
        )
        runtime = MCPRuntime()
        self.addAsyncCleanup(runtime.close)
        config = MCPServerConfig(
            server_id="stdio-integration",
            transport="stdio",
            trust_level="builtin",
            command=sys.executable,
            args=(str(script),),
            cwd=self.root,
            timeout_seconds=5,
            startup_timeout_seconds=5,
        )
        await runtime.register_server(config)
        tool_id = namespaced_tool_id("stdio-integration", "identity")
        await runtime.tools.set_agent_allowlist("integration", [tool_id])

        result = await runtime.tools.call(
            agent_id="integration",
            tool_id=tool_id,
            arguments={"value": "secured"},
        )

        self.assertEqual(result.data["value"], "secured")
        self.assertNotEqual(result.data["process_id"], __import__("os").getpid())

    async def test_stdio_timeout_revokes_tool_and_reaps_child_process(self) -> None:
        script = self.root / "hanging_server.py"
        pid_file = self.root / "server.pid"
        script.write_text(
            textwrap.dedent(
                """
                import os
                import time
                from pathlib import Path
                from mcp.server.fastmcp import FastMCP

                server = FastMCP("Timeout integration test")

                @server.tool()
                def hang(pid_file: str, delay: float) -> str:
                    Path(pid_file).write_text(str(os.getpid()), encoding="utf-8")
                    time.sleep(delay)
                    return "late"

                server.run(transport="stdio")
                """
            ),
            encoding="utf-8",
        )
        runtime = MCPRuntime()
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(
            MCPServerConfig(
                server_id="timeout-integration",
                transport="stdio",
                trust_level="builtin",
                command=sys.executable,
                args=(str(script),),
                cwd=self.root,
                timeout_seconds=2,
                startup_timeout_seconds=5,
            )
        )
        tool_id = namespaced_tool_id("timeout-integration", "hang")
        await runtime.tools.set_agent_allowlist("integration", [tool_id])

        with self.assertRaises(MCPToolTimeoutError):
            await runtime.tools.call(
                agent_id="integration",
                tool_id=tool_id,
                arguments={"pid_file": str(pid_file), "delay": 30.0},
                timeout_seconds=0.2,
            )

        self.assertTrue(pid_file.is_file())
        process_id = int(pid_file.read_text(encoding="utf-8"))
        with self.assertRaises(ProcessLookupError):
            os.kill(process_id, 0)
        with self.assertRaises(MCPToolNotFoundError):
            await runtime.registry.resolve(tool_id)

    async def test_builtin_report_template_is_discovered_through_stdio_launcher(self) -> None:
        runtime = MCPRuntime()
        self.addAsyncCleanup(runtime.close)
        config = builtin_stdio_server_config(
            "report-template",
            timeout_seconds=5,
            startup_timeout_seconds=5,
        )
        await runtime.register_server(config)
        tool_id = namespaced_tool_id("report-template", "resolve_report_template")
        await runtime.tools.set_agent_allowlist("reporter", [tool_id])

        result = await runtime.tools.call(
            agent_id="reporter",
            tool_id=tool_id,
            arguments={"template_id": "security", "platform": "generic", "language": "zh-Hans"},
        )

        self.assertEqual(result.data["id"], "security")
        self.assertEqual(result.audit.transport, "stdio")
        self.assertIn("report-excel", BUILTIN_STDIO_SERVER_IDS)

    async def test_host_artifact_scratch_only_materializes_relative_verified_files(self) -> None:
        artifact_root = self.root / "artifacts"
        session = ArtifactSession()
        runtime = MCPRuntime(
            connector=FakeConnector(session),
            artifact_policy=ArtifactPolicy(
                root=artifact_root,
                allowed_media_types=frozenset({"text/plain"}),
            ),
        )
        self.addAsyncCleanup(runtime.close)
        await runtime.register_server(local_config(self.root, server_id="renderer"))
        tool_id = namespaced_tool_id("renderer", "render")
        await runtime.tools.set_agent_allowlist("reporter", [tool_id])

        result = await runtime.tools.call(
            agent_id="reporter",
            tool_id=tool_id,
            arguments={"value": "verified"},
            artifact_policy=ToolArtifactPolicy(
                output_argument="output_dir",
                max_artifact_bytes=1024,
                max_total_bytes=1024,
                max_artifacts=1,
                allowed_media_types=frozenset({"text/plain"}),
            ),
        )

        self.assertEqual(len(result.artifacts), 1)
        artifact = result.artifacts[0]
        materialized = artifact_root / artifact.relative_path
        self.assertEqual(materialized.read_text(encoding="utf-8"), "verified")
        self.assertEqual(artifact.sha256, hashlib.sha256(b"verified").hexdigest())
        self.assertFalse(any((artifact_root / ".staging").iterdir()))
        supplied_path = session.calls[0][1]["output_dir"]
        self.assertTrue(Path(supplied_path).is_absolute())
        self.assertNotIn(supplied_path, result.input_sha256)

    async def test_untrusted_sandbox_prefix_must_be_host_approved(self) -> None:
        config = local_config(
            self.root,
            trust_level="untrusted",
            sandbox=SandboxPolicy(launcher_prefix=("trusted-sandbox", "--")),
        )
        runtime = MCPRuntime(connector=FakeConnector(FakeSession()))
        self.addAsyncCleanup(runtime.close)
        with self.assertRaises(MCPConfigurationError):
            await runtime.register_server(config)


class MCPRuntimeHostTests(unittest.TestCase):
    def test_sync_facade_keeps_connection_on_dedicated_event_loop(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            session = FakeSession()
            connector = FakeConnector(session)
            host = MCPRuntimeHost(connector=connector)
            try:
                host.register_server(local_config(root))
                tool_id = namespaced_tool_id("math-tools", "add")
                host.set_agent_allowlist("calculator", [tool_id])
                first = host.call(
                    agent_id="calculator",
                    tool_id=tool_id,
                    arguments={"left": 1, "right": 2},
                )
                second = host.call(
                    agent_id="calculator",
                    tool_id=tool_id,
                    arguments={"left": 1, "right": 2},
                )
            finally:
                host.shutdown()

        self.assertEqual(first.data["answer"], 3)
        self.assertEqual(second.data["answer"], 3)
        self.assertEqual(connector.entered, 1)
        self.assertEqual(connector.exited, 1)


class MCPConfigurationTests(unittest.TestCase):
    def test_stdio_environment_uses_private_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {
                "SECFLOW_DATA_DIR": "/host/application-data",
                "SECFLOW_STORAGE_MASTER_KEY": "must-not-enter-mcp-environment",
            },
        ):
            scratch = Path(temp_dir)
            config = builtin_stdio_server_config(
                "translation",
                environment={"SECFLOW_DATA_DIR": "/plugin-requested-data"},
            )

            environment = _stdio_environment(config, scratch)

            self.assertEqual(environment["SECFLOW_DATA_DIR"], str(scratch / "data"))
            self.assertTrue((scratch / "data").is_dir())
            self.assertEqual((scratch / "data").stat().st_mode & 0o777, 0o700)
            self.assertEqual(environment["HOME"], str(scratch / "home"))
            self.assertEqual(environment["USERPROFILE"], str(scratch / "home"))
            self.assertEqual(environment["USER"], "secflow-mcp")
            self.assertEqual(environment["LOGNAME"], "secflow-mcp")
            self.assertNotEqual(environment["HOME"], os.environ.get("HOME"))
            self.assertNotIn("SECFLOW_STORAGE_MASTER_KEY", environment)

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt is a macOS sandbox")
    def test_translation_stdio_uses_network_denied_seatbelt_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            scratch = Path(temp_dir)
            config = builtin_stdio_server_config("translation")

            command, args = _sandboxed_command(config, scratch)

        self.assertEqual(command, "/usr/bin/sandbox-exec")
        self.assertEqual(args[0], "-p")
        self.assertIn("(deny network*)", args[1])
        self.assertIn('(literal "/")', args[1])
        self.assertNotIn(f'(subpath "{Path.cwd().resolve()}")', args[1])
        self.assertIn(f'(subpath "{(Path.cwd() / "app").resolve()}")', args[1])
        self.assertIn(str(Path.cwd().resolve()), args[1])
        self.assertIn(str(scratch.resolve()), args[1])
        self.assertEqual(args[2], config.command)
        self.assertTrue(config.sandbox.deny_network)

    @unittest.skipUnless(sys.platform == "darwin", "Seatbelt is a macOS sandbox")
    def test_translation_seatbelt_denies_network_and_non_scratch_file_reads(self) -> None:
        with (
            tempfile.TemporaryDirectory() as scratch_dir,
            tempfile.TemporaryDirectory() as private_dir,
        ):
            scratch = Path(scratch_dir)
            secret = Path(private_dir) / "host-secret"
            secret.write_text("must-not-be-readable", encoding="utf-8")
            config = builtin_stdio_server_config("translation")
            command, args = _sandboxed_command(config, scratch)
            environment = _stdio_environment(config, scratch)
            probe = """
from pathlib import Path
import socket
import subprocess
import sys

try:
    Path(sys.argv[1]).read_bytes()
except PermissionError:
    print("secret=denied")
else:
    print("secret=allowed")
try:
    socket.create_connection(("127.0.0.1", 9), timeout=0.1)
except PermissionError:
    print("network=denied")
except OSError:
    print("network=allowed")
else:
    print("network=allowed")
try:
    subprocess.run(
        ["/usr/bin/security", "find-generic-password", "-s", "secflow-sandbox-probe"],
        capture_output=True,
        check=False,
    )
except PermissionError:
    print("keychain=denied")
else:
    print("keychain=allowed")
target = Path(sys.argv[2]) / "probe.txt"
target.write_text("ok", encoding="utf-8")
print(f"scratch={target.read_text(encoding='utf-8')}")
"""
            completed = subprocess.run(
                [
                    command,
                    *args[:2],
                    str(config.command),
                    "-c",
                    probe,
                    str(secret),
                    str(scratch),
                ],
                cwd=config.cwd,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            ["secret=denied", "network=denied", "keychain=denied", "scratch=ok"],
        )

    def test_legacy_sse_and_in_process_transports_are_rejected(self) -> None:
        root = Path.cwd()
        for transport in ("sse", "legacy-sse", "in-process"):
            with self.subTest(transport=transport), self.assertRaises(MCPConfigurationError):
                MCPServerConfig(
                    server_id="unsafe",
                    transport=transport,
                    trust_level="builtin",
                    command=sys.executable,
                    cwd=root,
                )

    def test_translation_model_override_cannot_expand_sandbox_read_access(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, self.assertRaises(MCPConfigurationError):
            builtin_stdio_server_config(
                "translation",
                environment={"SECFLOW_TRANSLATION_MODEL_DIR": temp_dir},
            )

    def test_translation_network_policy_fails_closed_without_os_sandbox(self) -> None:
        config = builtin_stdio_server_config("translation")
        with tempfile.TemporaryDirectory() as temp_dir, patch.object(sys, "platform", "unsupported"):
            with self.assertRaisesRegex(MCPConfigurationError, "No approved OS network sandbox"):
                _sandboxed_command(config, Path(temp_dir))

    def test_remote_requires_https_and_never_accepts_embedded_credentials(self) -> None:
        for url in ("http://mcp.example.test/mcp", "https://token@mcp.example.test/mcp"):
            with self.subTest(url=url), self.assertRaises(MCPConfigurationError):
                MCPServerConfig(
                    server_id="remote-tools",
                    transport="streamable-http",
                    trust_level="remote",
                    url=url,
                )

        config = MCPServerConfig(
            server_id="remote-tools",
            transport="streamable-http",
            trust_level="remote",
            url="https://mcp.example.test/mcp",
            headers={"Authorization": "Bearer secret"},
        )
        self.assertIsInstance(config.tls, TLSConfig)

    def test_mtls_certificate_and_key_must_be_paired(self) -> None:
        with self.assertRaises(MCPConfigurationError):
            TLSConfig(client_cert="client.pem")

    def test_mtls_builds_verified_context_with_ca_and_client_chain(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            ca_file = root / "ca.pem"
            cert_file = root / "client.pem"
            key_file = root / "client.key"
            for path in (ca_file, cert_file, key_file):
                path.write_text("test", encoding="utf-8")
            context = Mock()
            with patch("app.mcp.runtime.ssl.create_default_context", return_value=context) as create:
                result = TLSConfig(
                    ca_file=ca_file,
                    client_cert=cert_file,
                    client_key=key_file,
                    client_key_password="secret",
                ).create_ssl_context()

        self.assertIs(result, context)
        create.assert_called_once_with(cafile=str(ca_file.resolve()))
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, __import__("ssl").CERT_REQUIRED)
        context.load_cert_chain.assert_called_once_with(
            str(cert_file.resolve()),
            str(key_file.resolve()),
            password="secret",
        )

    def test_untrusted_local_server_requires_os_sandbox_wrapper(self) -> None:
        root = Path.cwd()
        with self.assertRaises(MCPConfigurationError):
            MCPServerConfig(
                server_id="third-party",
                transport="stdio",
                trust_level="untrusted",
                command="plugin-host",
                cwd=root,
            )

        config = MCPServerConfig(
            server_id="third-party",
            transport="stdio",
            trust_level="untrusted",
            command="plugin-host",
            cwd=root,
            sandbox=SandboxPolicy(launcher_prefix=("sandbox-runner", "--")),
        )
        self.assertEqual(config.sandbox.launcher_prefix, ("sandbox-runner", "--"))

    def test_host_computed_config_hash_covers_secrets_and_sandbox_policy(self) -> None:
        root = Path.cwd()
        first = MCPServerConfig(
            server_id="hashed",
            transport="stdio",
            trust_level="builtin",
            command=sys.executable,
            cwd=root,
            environment={"TOKEN": "one"},
            sandbox=SandboxPolicy(environment_allowlist=frozenset({"TOKEN"})),
        )
        second = MCPServerConfig(
            server_id="hashed",
            transport="stdio",
            trust_level="builtin",
            command=sys.executable,
            cwd=root,
            environment={"TOKEN": "two"},
            sandbox=SandboxPolicy(environment_allowlist=frozenset({"TOKEN"})),
        )

        self.assertNotEqual(first.config_hash, second.config_hash)
        self.assertNotIn("one", first.config_hash)
        with self.assertRaises(MCPConfigurationError):
            MCPServerConfig(
                server_id="hashed",
                transport="stdio",
                trust_level="builtin",
                command=sys.executable,
                cwd=root,
                config_hash="0" * 64,
            )


if __name__ == "__main__":
    unittest.main()
