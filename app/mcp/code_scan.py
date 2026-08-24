from __future__ import annotations

import argparse
import ctypes
import hashlib
import hmac
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel

from app.dependencies import attachment_kind, is_allowed_attachment_name
from app.language_support import language_for_file, supported_flow_languages
from app.semgrep_tool import semgrep_tool
from app.source_filter import is_analyzable_source_path, is_symlink_like_source_stub
from app.storage import now_iso


CODE_SCAN_MCP_SCHEMA_VERSION = 1
CODE_SCAN_MCP_SERVER_ID = "code-scan"
CODE_SCAN_MCP_TOOL_NAME = "scan_language"
CODE_SCAN_MCP_PARSE_ERROR_PREVIEW_LIMIT = 500
_SYNTAX_GRAPH_FIELDS = ("ast_graph", "cfg_graph", "dfg_graph")
_SYNTAX_TRANSPORT_FIELDS = (
    "file",
    "language",
    "parser",
    "parser_mode",
    "parse_error",
    "raw_parse_error",
    "recovered_parse_error",
    "parser_error_nodes",
    "preprocessor_definition_count",
    "ast_node_count",
    "control_count",
    "assignment_count",
    "cfg_node_count",
    "cfg_edge_count",
    "dfg_edge_count",
)


class CodeScanMCPOutput(BaseModel):
    schema_version: Literal[1] = CODE_SCAN_MCP_SCHEMA_VERSION
    # Accept the legacy wire label when reading older sidecars, but always emit
    # the current public brand in newly generated payloads.
    server: Literal["AegisAl Code Scan MCP", "SecFlow Code Scan MCP"] = "AegisAl Code Scan MCP"
    tool: Literal["scan_language"] = CODE_SCAN_MCP_TOOL_NAME
    engine: Literal["AegisAl Static Analyzer", "SecFlow Static Analyzer"] = "AegisAl Static Analyzer"
    process_id: int
    language: str
    started_at: str
    completed_at: str
    duration_ms: int
    input_sha256: str
    output_sha256: str
    result: dict[str, Any]


code_scan_mcp = FastMCP(
    "AegisAl Code Scan MCP",
    instructions=(
        "Read only the explicitly authorized workspace paths and run the AegisAl static-rule, "
        "AST, CFG, DFG, interprocedural, and taint engines. Never "
        "execute project code, build scripts, package-manager hooks, or arbitrary commands."
    ),
    host="127.0.0.1",
    port=18791,
    log_level="WARNING",
)


@code_scan_mcp.tool(
    name=CODE_SCAN_MCP_TOOL_NAME,
    description="Scan one dispatched project language using the independent AegisAl analysis engine.",
    structured_output=True,
)
def scan_language(
    capability_token: str,
    workspace_path: str,
    language: str,
    source_paths: list[str],
    manifest_files: list[str],
    dependency_scan: dict[str, Any],
    rule_paths: list[str],
    complete_scan: bool = True,
    cancel_marker: str = "",
) -> CodeScanMCPOutput:
    _validate_capability_token(capability_token)
    _validate_tool_capability(CODE_SCAN_MCP_TOOL_NAME)
    if language not in set(supported_flow_languages()):
        raise ValueError(f"Unsupported scan language: {language}")
    workspace = _resolve_workspace(workspace_path)
    relative_paths = _deduplicate_paths([*manifest_files, *source_paths])
    attachments = _read_authorized_attachments(workspace, relative_paths)
    verified_rules = _validate_rule_paths(rule_paths)
    marker = _validate_cancel_marker(cancel_marker)
    logical_input = {
        "schema_version": CODE_SCAN_MCP_SCHEMA_VERSION,
        "workspace_path": str(workspace),
        "language": language,
        "source_paths": source_paths,
        "manifest_files": manifest_files,
        "dependency_scan": dependency_scan,
        "rule_paths": verified_rules,
        "complete_scan": bool(complete_scan),
    }
    input_sha256 = _json_sha256(logical_input)
    started_at = now_iso()
    started = time.monotonic()
    result = _compact_scan_result_for_transport(
        semgrep_tool.analyze(
            attachments,
            dependency_scan,
            [],
            rule_paths=verified_rules,
            cancelled=lambda: bool(marker and marker.exists()),
            language_hint=language,
            include_all_attachments=bool(complete_scan),
        )
    )
    completed_at = now_iso()
    return CodeScanMCPOutput(
        process_id=os.getpid(),
        language=language,
        started_at=started_at,
        completed_at=completed_at,
        duration_ms=max(0, int((time.monotonic() - started) * 1000)),
        input_sha256=input_sha256,
        output_sha256=_json_sha256(result),
        result=result,
    )


def _compact_scan_result_for_transport(result: dict[str, Any]) -> dict[str, Any]:
    """Bound per-file MCP output while preserving findings and aggregate scan facts."""

    raw_files = result.get("files") if isinstance(result.get("files"), list) else []
    parse_error_files: list[dict[str, Any]] = []
    discovered_parse_error_names: list[str] = []
    graph_previews_omitted = 0
    graph_preview_nodes_omitted = 0
    graph_preview_edges_omitted = 0

    for raw_file in raw_files:
        if not isinstance(raw_file, dict):
            continue
        raw_syntax = raw_file.get("syntax") if isinstance(raw_file.get("syntax"), dict) else {}
        compact_graphs: dict[str, dict[str, Any]] = {}
        for field in _SYNTAX_GRAPH_FIELDS:
            raw_graph = raw_syntax.get(field) if isinstance(raw_syntax.get(field), dict) else {}
            preview_nodes = raw_graph.get("nodes") if isinstance(raw_graph.get("nodes"), list) else []
            preview_edges = raw_graph.get("edges") if isinstance(raw_graph.get("edges"), list) else []
            preview_omitted = bool(preview_nodes or preview_edges)
            if preview_omitted:
                graph_previews_omitted += 1
                graph_preview_nodes_omitted += len(preview_nodes)
                graph_preview_edges_omitted += len(preview_edges)
            compact_graphs[field] = {
                "node_count": int(raw_graph.get("node_count") or 0),
                "edge_count": int(raw_graph.get("edge_count") or 0),
                "preview_omitted": preview_omitted,
            }
        if not bool(raw_syntax.get("parse_error")):
            continue
        file_name = str(raw_file.get("file_name") or raw_syntax.get("file") or "")
        discovered_parse_error_names.append(file_name)
        if len(parse_error_files) >= CODE_SCAN_MCP_PARSE_ERROR_PREVIEW_LIMIT:
            continue

        syntax = {
            field: raw_syntax[field]
            for field in _SYNTAX_TRANSPORT_FIELDS
            if field in raw_syntax
        }
        syntax.update(compact_graphs)
        parse_error_files.append(
            {
                "file_name": file_name,
                "language": str(raw_file.get("language") or raw_syntax.get("language") or ""),
                "syntax": syntax,
            }
        )

    raw_summary = result.get("syntax_summary") if isinstance(result.get("syntax_summary"), dict) else {}
    syntax_summary = dict(raw_summary)
    summary_names = raw_summary.get("parse_error_file_names")
    if isinstance(summary_names, list):
        parse_error_names = [str(item) for item in summary_names]
    else:
        parse_error_names = discovered_parse_error_names
    retained_names = parse_error_names[:CODE_SCAN_MCP_PARSE_ERROR_PREVIEW_LIMIT]
    syntax_summary["parse_error_file_names"] = retained_names
    syntax_summary["parse_error_file_name_count"] = len(parse_error_names)
    syntax_summary["omitted_parse_error_file_names"] = max(0, len(parse_error_names) - len(retained_names))
    syntax_summary["parse_error_file_names_truncated"] = len(parse_error_names) > len(retained_names)

    parse_error_count = max(
        len(discovered_parse_error_names),
        len(parse_error_names),
        int(raw_summary.get("parse_error_files") or 0),
    )
    omitted_file_details = max(0, len(raw_files) - len(parse_error_files))
    omitted_parse_error_details = max(0, parse_error_count - len(parse_error_files))
    result_truncated = bool(omitted_file_details or graph_previews_omitted or omitted_parse_error_details)
    compacted = dict(result)
    compacted["files"] = parse_error_files
    compacted["syntax_summary"] = syntax_summary
    compacted["result_truncated"] = result_truncated
    compacted["transport_compaction"] = {
        "source_file_count": len(raw_files),
        "retained_file_details": len(parse_error_files),
        "omitted_file_details": omitted_file_details,
        "parse_error_file_limit": CODE_SCAN_MCP_PARSE_ERROR_PREVIEW_LIMIT,
        "omitted_parse_error_file_details": omitted_parse_error_details,
        "parse_error_file_details_truncated": bool(omitted_parse_error_details),
        "graph_previews_omitted": graph_previews_omitted,
        "graph_preview_nodes_omitted": graph_preview_nodes_omitted,
        "graph_preview_edges_omitted": graph_preview_edges_omitted,
    }
    return compacted


@code_scan_mcp.tool(
    name="get_scan_capabilities",
    description="Return the independent scan engine capabilities and supported languages.",
    structured_output=True,
)
def get_scan_capabilities(capability_token: str) -> dict[str, Any]:
    _validate_capability_token(capability_token)
    allowed_tools = _allowed_tools()
    status = semgrep_tool.status()
    return {
        "schema_version": CODE_SCAN_MCP_SCHEMA_VERSION,
        "server": code_scan_mcp.name,
        "process_id": os.getpid(),
        "transport": "stdio",
        "read_only": True,
        "supported_languages": list(status.get("supportedLanguages") or []),
        "allowed_tools": sorted(allowed_tools),
        "engines": (
            ["static-rules", "ast", "cfg", "dfg", "taint", "interprocedural"]
            if CODE_SCAN_MCP_TOOL_NAME in allowed_tools
            else []
        ),
        "license_registry": "",
        "semgrep_mode": str(status.get("mode") or "internal"),
    }


async def code_scan_mcp_spec() -> dict[str, Any]:
    tools = await code_scan_mcp.list_tools()
    return {
        "id": CODE_SCAN_MCP_SERVER_ID,
        "name": code_scan_mcp.name,
        "transport": "stdio",
        "endpoint": "managed-child-process",
        "tools": [
            {
                "name": tool.name,
                "description": tool.description or "",
                "input_schema": _public_input_schema(tool.inputSchema),
                "output_schema": tool.outputSchema or {},
            }
            for tool in tools
        ],
    }


def _validate_capability_token(value: str) -> None:
    expected = os.getenv("SECFLOW_CODE_SCAN_MCP_TOKEN", "").strip()
    supplied = str(value or "")
    if not expected or not hmac.compare_digest(supplied, expected):
        raise PermissionError("Code Scan MCP capability token is invalid")


def _allowed_tools() -> set[str]:
    configured = {
        item.strip()
        for item in os.getenv("SECFLOW_CODE_SCAN_MCP_ALLOWED_TOOLS", "scan_language").split(",")
        if item.strip()
    }
    return configured & {CODE_SCAN_MCP_TOOL_NAME}


def _validate_tool_capability(tool_name: str) -> None:
    if tool_name not in _allowed_tools():
        raise PermissionError(f"Code Scan MCP capability does not allow tool: {tool_name}")


def _resolve_workspace(value: str) -> Path:
    clean = str(value or "").strip()
    if not clean or "\x00" in clean:
        raise ValueError("Code Scan MCP workspace path is invalid")
    unresolved = Path(clean).expanduser()
    if unresolved.is_symlink():
        raise ValueError("Code Scan MCP does not accept a symlink workspace")
    try:
        workspace = unresolved.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Code Scan MCP workspace is unavailable") from exc
    if workspace.is_dir() and workspace == Path(workspace.anchor):
        raise ValueError("Code Scan MCP refuses a filesystem root workspace")
    if not workspace.is_dir() and not workspace.is_file():
        raise ValueError("Code Scan MCP workspace must be a file or directory")
    return workspace


def _read_authorized_attachments(workspace: Path, relative_paths: list[str]) -> list[dict[str, Any]]:
    attachments: list[dict[str, Any]] = []
    for relative in relative_paths:
        path, display_name = _resolve_authorized_file(workspace, relative)
        if not is_allowed_attachment_name(path.name):
            continue
        kind = attachment_kind(path.name)
        if kind == "code":
            language = language_for_file(display_name)
            if language not in set(supported_flow_languages()) or not is_analyzable_source_path(display_name):
                continue
            try:
                if path.stat().st_size <= 512 and is_symlink_like_source_stub(
                    display_name,
                    path.read_text(encoding="utf-8", errors="replace"),
                ):
                    continue
            except OSError:
                continue
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise ValueError(f"Code Scan MCP cannot read authorized file: {display_name}") from exc
        attachments.append({"file_name": display_name, "content": content})
    return attachments


def _resolve_authorized_file(workspace: Path, relative: str) -> tuple[Path, str]:
    clean = str(relative or "").replace("\\", "/").strip()
    pure = PurePosixPath(clean)
    if not clean or "\x00" in clean or pure.is_absolute() or ".." in pure.parts:
        raise ValueError("Code Scan MCP received an invalid relative path")
    if workspace.is_file():
        if pure.name != workspace.name or len(pure.parts) != 1:
            raise ValueError("Code Scan MCP single-file scope cannot read sibling files")
        return workspace, workspace.name
    unresolved = workspace.joinpath(*pure.parts)
    if _contains_symlink(workspace, unresolved):
        raise ValueError(f"Code Scan MCP refuses symlink path: {clean}")
    try:
        path = unresolved.resolve(strict=True)
        path.relative_to(workspace)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"Code Scan MCP path escapes or is unavailable: {clean}") from exc
    if not path.is_file():
        raise ValueError(f"Code Scan MCP path is not a regular file: {clean}")
    return path, pure.as_posix()


def _contains_symlink(workspace: Path, target: Path) -> bool:
    current = workspace
    try:
        relative = target.relative_to(workspace)
    except ValueError:
        return True
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            return True
    return False


def _validate_rule_paths(values: list[str]) -> list[str]:
    result: list[str] = []
    for value in values:
        clean = str(value or "").strip()
        if not clean or "\x00" in clean:
            continue
        path = Path(clean).expanduser()
        if path.is_symlink() or path.suffix.casefold() not in {".json", ".yaml", ".yml"}:
            raise ValueError("Code Scan MCP received an invalid rule file")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"Code Scan MCP rule file is unavailable: {path.name}") from exc
        if not resolved.is_file():
            raise ValueError(f"Code Scan MCP rule path is not a file: {path.name}")
        result.append(str(resolved))
    return result


def _validate_cancel_marker(value: str) -> Path | None:
    clean = str(value or "").strip()
    if not clean:
        return None
    if "\x00" in clean:
        raise ValueError("Code Scan MCP cancel marker is invalid")
    configured_root = os.getenv("SECFLOW_CODE_SCAN_CANCEL_ROOT", "").strip()
    if not configured_root:
        raise ValueError("Code Scan MCP cancel root is not configured")
    unresolved_root = Path(configured_root).expanduser()
    unresolved_marker = Path(clean).expanduser()
    if not unresolved_root.is_absolute() or not unresolved_marker.is_absolute():
        raise ValueError("Code Scan MCP cancel marker must use an absolute private path")
    if unresolved_root.is_symlink() or unresolved_marker.is_symlink():
        raise ValueError("Code Scan MCP cancel marker cannot traverse a symlink")
    try:
        cancel_root = unresolved_root.resolve(strict=True)
        marker_parent = unresolved_marker.parent.resolve(strict=True)
        marker = unresolved_marker.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Code Scan MCP cancel marker path is unavailable") from exc
    if (
        not cancel_root.is_dir()
        or not cancel_root.name.startswith("secflow-code-scan-runtime-")
        or marker_parent.is_symlink()
        or not marker_parent.is_dir()
        or marker_parent.parent != cancel_root
        or not marker_parent.name.startswith("secflow-code-scan-cancel-")
        or marker.parent != marker_parent
    ):
        raise ValueError("Code Scan MCP cancel marker must be inside its private runtime directory")
    if marker.name != "cancel":
        raise ValueError("Code Scan MCP cancel marker name is invalid")
    if marker.exists() and not marker.is_file():
        raise ValueError("Code Scan MCP cancel marker must be a regular file")
    return marker


def _deduplicate_paths(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        clean = str(value or "").replace("\\", "/").strip()
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


def _json_sha256(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _public_input_schema(schema: dict[str, Any]) -> dict[str, Any]:
    public = json.loads(json.dumps(schema))
    properties = public.get("properties") if isinstance(public.get("properties"), dict) else {}
    properties.pop("capability_token", None)
    public["required"] = [item for item in public.get("required") or [] if item != "capability_token"]
    return public


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the independent AegisAl Code Scan MCP service.")
    parser.add_argument("--transport", choices=("stdio",), default="stdio")
    parser.add_argument("--parent-pid", type=int)
    args = parser.parse_args(argv)
    if args.parent_pid:
        threading.Thread(
            target=_watch_parent,
            args=(args.parent_pid,),
            daemon=True,
            name="secflow-code-scan-parent-watch",
        ).start()
    code_scan_mcp.run(transport="stdio")


def _watch_parent(parent_pid: int) -> None:
    while True:
        if not _parent_process_is_alive(parent_pid):
            os._exit(0)
        time.sleep(0.5)


def _parent_process_is_alive(parent_pid: int) -> bool:
    if parent_pid <= 1:
        return False
    if sys.platform == "win32":
        synchronize = 0x00100000
        wait_timeout = 0x00000102
        handle = ctypes.windll.kernel32.OpenProcess(synchronize, False, parent_pid)
        if not handle:
            return False
        try:
            return ctypes.windll.kernel32.WaitForSingleObject(handle, 0) == wait_timeout
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    try:
        os.kill(parent_pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


if __name__ == "__main__":
    main()
