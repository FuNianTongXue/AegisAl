from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from app.assistant_artifacts import ComponentArtifactStore
from app.mcp.protocol import (
    CodeScanMCPClient,
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


def test_large_code_scan_is_batched_and_merged_without_losing_findings() -> None:
    calls: list[dict] = []

    def scan_batch(**kwargs):
        arguments = kwargs["arguments"]
        calls.append(arguments)
        batch_index = len(calls)
        paths = list(arguments["source_paths"])
        files = []
        if batch_index == 2:
            files.append(
                {
                    "file_name": paths[0],
                    "syntax": {
                        "file": paths[0],
                        "language": "java",
                        "parse_error": True,
                        "parser_mode": "native",
                        "parser_error_nodes": 1,
                    },
                }
            )
        return {
            "schema_version": 1,
            "server": "AegisAl Code Scan MCP",
            "tool": "scan_language",
            "process_id": 4321,
            "language": "java",
            "started_at": f"start-{batch_index}",
            "completed_at": f"end-{batch_index}",
            "duration_ms": 10,
            "input_sha256": str(batch_index) * 64,
            "output_sha256": str(batch_index + 3) * 64,
            "result": {
                "status": "completed",
                "mode": "bundled-cli",
                "cli_status": "completed",
                "files": files,
                "syntax_summary": {
                    "languages": ["java"],
                    "parsed_files": len(paths),
                    "parse_error_files": len(files),
                    "ast_node_count": len(paths) * 10,
                },
                "findings": [
                    {"id": f"finding-{path}", "file_name": path, "line": 1}
                    for path in paths
                ],
                "review_findings": [],
                "diagnostics": [f"batch {batch_index}"],
                "transport_compaction": {
                    "source_file_count": len(paths),
                    "retained_file_details": len(files),
                    "omitted_file_details": len(paths) - len(files),
                    "parse_error_file_limit": 500,
                },
            },
            "_mcp_runtime": {
                "call_id": f"call-{batch_index}",
                "transport": "stdio",
                "input_sha256": str(batch_index) * 64,
                "output_sha256": str(batch_index + 3) * 64,
                "result_size_bytes": 1_000,
                "plugin_id": "secflow.mcp",
                "plugin_version": "1.3.3",
                "config_hash": "config",
                "generation": 2,
                "status": "completed",
            },
        }

    with TemporaryDirectory() as directory:
        workspace = Path(directory)
        source_paths = [f"src/File{index}.java" for index in range(5)]
        for relative in source_paths:
            path = workspace / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("class Demo {}\n", encoding="utf-8")
        with (
            patch.dict(os.environ, {"SECFLOW_CODE_SCAN_BATCH_MAX_FILES": "2"}),
            patch("app.mcp.protocol.call_mcp_tool", side_effect=scan_batch),
        ):
            result = CodeScanMCPClient().scan_language(
                workspace_path=str(workspace),
                language="java",
                source_paths=source_paths,
                manifest_files=["pom.xml", "CMakeLists.txt"],
                dependency_scan={"dependencies": []},
                rule_paths=["java.yml"],
                complete_scan=True,
                cancelled=lambda: False,
            )

    assert [len(item["source_paths"]) for item in calls] == [2, 2, 1]
    assert calls[0]["manifest_files"] == ["pom.xml", "CMakeLists.txt"]
    assert calls[1]["manifest_files"] == ["CMakeLists.txt"]
    assert result["scan_batches"] == 3
    assert result["scanned_source_files"] == 5
    assert result["syntax_summary"]["parsed_files"] == 5
    assert result["syntax_summary"]["ast_node_count"] == 50
    assert result["finding_count"] == 5
    assert result["transport_compaction"]["source_file_count"] == 5
    assert {item["id"] for item in result["findings"]} == {
        f"finding-{path}" for path in source_paths
    }
    assert len(result["files"]) == 1
    assert result["_scan_mcp"]["batch_count"] == 3
    assert result["_scan_mcp"]["batch_call_ids"] == ["call-1", "call-2", "call-3"]
    assert result["_scan_mcp"]["result_size_bytes"] == 3_000
