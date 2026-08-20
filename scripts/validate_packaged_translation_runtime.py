#!/usr/bin/env python3
"""Smoke-test the packaged Translation MCP through the production sandbox."""

from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from dataclasses import replace
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.mcp.runtime import (
    MCPRuntime,
    SandboxPolicy,
    _sandboxed_command,
    builtin_stdio_server_config,
    namespaced_tool_id,
)


_CJK = re.compile(r"[\u3400-\u9fff]")


def _packaged_config(backend: Path):
    base = builtin_stdio_server_config("translation")
    backend_root = backend.parent.resolve(strict=True)
    environment = {
        "PYINSTALLER_RESET_ENVIRONMENT": "1",
        "PYTHONUNBUFFERED": "1",
    }
    sandbox = SandboxPolicy(
        environment_allowlist=frozenset(environment),
        deny_network=True,
        read_only_roots=tuple({*base.sandbox.read_only_roots, backend_root}),
    )
    config = replace(
        base,
        command=str(backend),
        args=("--mcp-server", "translation"),
        cwd=backend_root,
        environment=environment,
        sandbox=sandbox,
        startup_timeout_seconds=45.0,
        timeout_seconds=120.0,
        config_hash="",
    )
    command, _args = _sandboxed_command(config, backend_root)
    if sys.platform == "darwin" and command != "/usr/bin/sandbox-exec":
        raise RuntimeError("packaged Translation MCP did not select the macOS Seatbelt launcher")
    return config


async def _validate(backend: Path) -> dict[str, object]:
    runtime = MCPRuntime()
    tool_id = namespaced_tool_id("translation", "translate_json_payload")
    try:
        descriptors = await runtime.register_server(_packaged_config(backend))
        if tool_id not in {item.tool_id for item in descriptors}:
            raise RuntimeError("packaged Translation MCP did not publish the expected tool")
        await runtime.tools.set_agent_allowlist("packaged-translation-validator", [tool_id])
        execution = await runtime.tools.call(
            agent_id="packaged-translation-validator",
            tool_id=tool_id,
            arguments={
                "payload": {
                    "summary": (
                        "Remote attackers can execute arbitrary code in Nginx before 1.2.3."
                    )
                },
                "target_language": "zh-Hans",
                "user_id": "packaged-validator",
                "session_id": "packaged-validator",
                "content_scope": "packaged_translation_smoke_test",
            },
        )
    finally:
        await runtime.close()

    data = dict(execution.data or {})
    payload = data.get("payload") if isinstance(data.get("payload"), dict) else {}
    translated = str(payload.get("summary") or "")
    required = {
        "translation_status": "translated",
        "unresolved_fields": 0,
        "offline": True,
        "network_used": False,
        "requires_api_key": False,
        "provider_calls": 0,
        "billable_tokens": 0,
        "token_usage": 0,
        "model_used": False,
        "offline_model_used": True,
        "resource_verified": True,
    }
    mismatches = {
        key: {"expected": expected, "actual": data.get(key)}
        for key, expected in required.items()
        if data.get(key) != expected
    }
    if mismatches:
        raise RuntimeError(f"packaged Translation MCP contract mismatch: {mismatches}")
    if not _CJK.search(translated) or "Remote attackers" in translated:
        raise RuntimeError("packaged Translation MCP did not return a complete Chinese translation")
    if "Nginx" not in translated or "1.2.3" not in translated:
        raise RuntimeError("packaged Translation MCP did not preserve security evidence")
    return {
        "ok": True,
        "transport": execution.audit.transport,
        "sandbox": "macOS Seatbelt" if sys.platform == "darwin" else "configured process sandbox",
        "translation_status": data["translation_status"],
        "provider_calls": data["provider_calls"],
        "billable_tokens": data["billable_tokens"],
        "token_usage": data["token_usage"],
        "resource_verified": data["resource_verified"],
        "model_sha256": data.get("model_sha256"),
        "output_sha256": execution.output_sha256,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backend", type=Path, help="packaged secflow-backend executable")
    args = parser.parse_args()
    backend = args.backend.expanduser().resolve(strict=True)
    if not backend.is_file() or backend.is_symlink():
        parser.error(f"backend must be a regular non-symlink file: {backend}")
    print(json.dumps(asyncio.run(_validate(backend)), ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
