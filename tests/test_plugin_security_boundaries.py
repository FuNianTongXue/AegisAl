from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from app.assistant_artifacts import ComponentArtifactStore
from app.mcp.protocol import (
    MCPArtifactContract,
    MCPPluginService,
    MCPServerDefinition,
    MCPToolDeclaration,
)
from app.mcp.runtime import (
    ArtifactManager,
    ArtifactPolicy,
    MCPAuthorizationError,
    MCPConfigurationError,
    MCPServerConfig,
    MCPToolValidationError,
    ToolArtifactPolicy,
)


def _artifact_tool(server_id: str = "renderer") -> MCPToolDeclaration:
    return MCPToolDeclaration(
        server_id=server_id,
        name="render",
        artifact_contract=MCPArtifactContract(
            max_artifact_bytes=1024,
            max_total_bytes=1024,
            max_artifacts=1,
            allowed_media_types=("text/plain",),
        ),
    )


def test_service_authorizes_before_lazy_server_start() -> None:
    service = MCPPluginService()
    tool = MCPToolDeclaration(server_id="renderer", name="render")
    service.register(MCPServerDefinition("renderer", "Renderer", (tool,)))
    service.set_agent_allowlist("reader", [])

    with (
        patch.object(service, "_ensure_server") as ensure,
        patch("app.mcp.audit.persistent_mcp_audit_log.write"),
        pytest.raises(MCPAuthorizationError),
    ):
        service.call(agent_id="reader", tool_id=tool.tool_id, arguments={})

    ensure.assert_not_called()


def test_remote_artifact_directory_contract_fails_closed_before_connect() -> None:
    service = MCPPluginService()
    tool = _artifact_tool("remote-renderer")
    connection = MCPServerConfig(
        server_id="remote-renderer",
        transport="streamable-http",
        trust_level="remote",
        url="https://mcp.example.test/v1",
    )
    definition = MCPServerDefinition(
        "remote-renderer",
        "Remote Renderer",
        (tool,),
        connection=connection,
    )
    service.register(definition)
    service.set_agent_allowlist("reporter", [tool.tool_id])

    with (
        patch.object(service, "_ensure_server") as ensure,
        patch("app.mcp.audit.persistent_mcp_audit_log.write"),
        pytest.raises(MCPConfigurationError, match="ResourceLink"),
    ):
        service.call(agent_id="reporter", tool_id=tool.tool_id, arguments={})

    ensure.assert_not_called()


def test_artifact_manager_rejects_hardlinks() -> None:
    with TemporaryDirectory() as directory:
        manager = ArtifactManager(ArtifactPolicy(root=Path(directory) / "artifacts"))
        call_id = "a" * 32
        scratch = manager.allocate_scratch(call_id)
        outside = Path(directory) / "outside.txt"
        outside.write_text("verified", encoding="utf-8")
        os.link(outside, scratch / "result.txt")
        contract = ToolArtifactPolicy(
            output_argument="output_dir",
            max_artifact_bytes=1024,
            max_total_bytes=1024,
            max_artifacts=1,
            allowed_media_types=frozenset({"text/plain"}),
        )

        with pytest.raises(MCPToolValidationError, match="hard link"):
            manager.materialize(
                call_id=call_id,
                scratch=scratch,
                references=(
                    {
                        "path": "result.txt",
                        "media_type": "text/plain",
                        "sha256": hashlib.sha256(b"verified").hexdigest(),
                    },
                ),
                contract=contract,
            )


def test_download_capability_is_bound_to_user() -> None:
    with TemporaryDirectory() as directory, patch.dict(
        os.environ,
        {"SECFLOW_STORAGE_MASTER_KEY": "artifact-owner-boundary-test-key"},
    ):
        store = ComponentArtifactStore(Path(directory))
        artifact = store.save(
            b"PK\x03\x04workbook",
            file_name="result.xlsx",
            generated_at="2026-08-18T00:00:00+00:00",
            user_id="alice",
            session_id="session-a",
            task_id="task-a",
        )

        assert store.resolve(artifact.id, user_id="alice").is_file()
        with pytest.raises(KeyError):
            store.resolve(artifact.id, user_id="bob")
        assert "user_id=alice" in artifact.download_path
