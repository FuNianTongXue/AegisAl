from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.mcp.protocol import call_mcp_tool
from app.storage import now_iso


_OFFLINE_BOOLEAN_CONTRACT = {
    "offline": True,
    "network_used": False,
    "requires_api_key": False,
    "model_used": False,
}
_ZERO_USAGE_CONTRACT = ("provider_calls", "billable_tokens", "token_usage")
_MCP_RUNTIME_CONTRACT = {
    "server_id": "translation",
    "tool_id": "mcp__translation__translate_json_payload",
    "transport": "stdio",
    "status": "completed",
}


def _offline_contract_violations(
    result: dict[str, Any],
    *,
    translation_status: str,
    target_language: str,
) -> list[str]:
    violations: list[str] = []
    if "target_language" not in result:
        violations.append("missing required field: target_language")
    elif type(result["target_language"]) is not str:
        violations.append("field must be a string: target_language")
    elif result["target_language"] != target_language:
        violations.append("field does not match the requested language: target_language")

    for field, expected in _OFFLINE_BOOLEAN_CONTRACT.items():
        if field not in result:
            violations.append(f"missing required field: {field}")
        elif type(result[field]) is not bool:  # bool is intentionally stricter than truthiness.
            violations.append(f"field must be a boolean: {field}")
        elif result[field] is not expected:
            violations.append(f"field violates the offline policy: {field}")

    for field in _ZERO_USAGE_CONTRACT:
        if field not in result:
            violations.append(f"missing required field: {field}")
        elif type(result[field]) is not int:
            violations.append(f"field must be an integer: {field}")
        elif result[field] != 0:
            violations.append(f"field must be zero: {field}")

    if "resource_verified" not in result:
        violations.append("missing required field: resource_verified")
    elif type(result["resource_verified"]) is not bool:
        violations.append("field must be a boolean: resource_verified")
    elif translation_status == "translated" and result["resource_verified"] is not True:
        violations.append("translated output requires a verified bundled resource")
    return violations


def _audit_bool(result: dict[str, Any], field: str, *, unsafe_default: bool) -> bool:
    value = result.get(field)
    return value if type(value) is bool else unsafe_default


def _audit_counter(result: dict[str, Any], field: str) -> int:
    value = result.get(field)
    return value if type(value) is int else -1


def _runtime_contract_violations(result: dict[str, Any]) -> list[str]:
    if "_mcp_runtime" not in result:
        return ["missing required field: _mcp_runtime"]
    runtime = result["_mcp_runtime"]
    if type(runtime) is not dict:
        return ["field must be an object: _mcp_runtime"]

    violations: list[str] = []
    for field, expected in _MCP_RUNTIME_CONTRACT.items():
        if field not in runtime:
            violations.append(f"missing required runtime field: {field}")
        elif type(runtime[field]) is not str:
            violations.append(f"runtime field must be a string: {field}")
        elif runtime[field] != expected:
            violations.append(f"runtime field violates Host policy: {field}")
    return violations


@dataclass(frozen=True)
class TranslationAgentResult:
    payload: dict[str, Any]
    audit: dict[str, Any]


class TranslationAgent:
    """LangGraph-facing adapter with Translation MCP as its only content tool."""

    agent_id = "translation_agent"
    tool_allowlist = ("mcp__translation__translate_json_payload",)

    def translate_json(
        self,
        payload: dict[str, Any],
        *,
        target_language: str,
        user_id: str,
        session_id: str,
        content_scope: str,
    ) -> TranslationAgentResult:
        invoked_at = now_iso()
        result = call_mcp_tool(
            agent_id=self.agent_id,
            tool_id="mcp__translation__translate_json_payload",
            arguments={
                "payload": payload,
                "target_language": target_language,
                "user_id": user_id,
                "session_id": session_id,
                "content_scope": content_scope,
            },
        )
        translated = result.get("payload") if isinstance(result.get("payload"), dict) else {}
        if not translated:
            raise RuntimeError("Translation MCP returned an empty JSON payload")
        translation_status = (
            result["translation_status"]
            if type(result.get("translation_status")) is str
            else "invalid"
        )
        unresolved_fields = _audit_counter(result, "unresolved_fields")
        contract_violations = _offline_contract_violations(
            result,
            translation_status=translation_status,
            target_language=target_language,
        )
        offline_contract_valid = not contract_violations
        runtime_contract_violations = _runtime_contract_violations(result)
        runtime_contract_valid = not runtime_contract_violations
        runtime = (
            result["_mcp_runtime"]
            if type(result.get("_mcp_runtime")) is dict
            else {}
        )
        if (
            translation_status in {"translated", "passthrough"}
            and unresolved_fields == 0
            and offline_contract_valid
            and runtime_contract_valid
        ):
            agent_status = "completed"
        elif (
            translation_status == "fallback"
            and offline_contract_valid
            and runtime_contract_valid
        ):
            agent_status = "partial"
        else:
            agent_status = "failed"
        audit = {
            "server": "SecFlow Translation MCP",
            "tool": "translate_json_payload",
            "transport": str(runtime.get("transport") or ""),
            "endpoint": "managed-child-process",
            "status": agent_status,
            "translation_status": translation_status,
            "target_language": (
                result["target_language"]
                if type(result.get("target_language")) is str
                else ""
            ),
            "candidate_fields": int(result.get("candidate_fields") or 0),
            "translated_fields": int(result.get("translated_fields") or 0),
            "unresolved_fields": unresolved_fields,
            "batch_count": int(result.get("batch_count") or 0),
            "model_used": _audit_bool(result, "model_used", unsafe_default=True),
            "offline_model_used": bool(result.get("offline_model_used")),
            "offline": _audit_bool(result, "offline", unsafe_default=False),
            "network_used": _audit_bool(result, "network_used", unsafe_default=True),
            "requires_api_key": _audit_bool(result, "requires_api_key", unsafe_default=True),
            "provider_calls": _audit_counter(result, "provider_calls"),
            "billable_tokens": _audit_counter(result, "billable_tokens"),
            "token_usage": _audit_counter(result, "token_usage"),
            "engine": str(result.get("engine") or ""),
            "engine_version": str(result.get("engine_version") or ""),
            "model_id": str(result.get("model_id") or ""),
            "model_sha256": str(result.get("model_sha256") or ""),
            "resource_verified": _audit_bool(
                result,
                "resource_verified",
                unsafe_default=False,
            ),
            "offline_contract_valid": offline_contract_valid,
            "runtime_contract_valid": runtime_contract_valid,
            "input_sha256": str(result.get("input_sha256") or ""),
            "output_sha256": str(result.get("output_sha256") or ""),
            "invoked_at": invoked_at,
            "runtime": dict(runtime),
        }
        warnings = [str(item) for item in result.get("errors") or []]
        if not offline_contract_valid:
            warnings.append(
                "Translation MCP violated the offline zero-token execution contract: "
                + "; ".join(contract_violations)
            )
        if not runtime_contract_valid:
            warnings.append(
                "Translation MCP violated the Host runtime envelope: "
                + "; ".join(runtime_contract_violations)
            )
        if warnings:
            audit["warnings"] = warnings
        return TranslationAgentResult(payload=translated, audit=audit)


translation_agent = TranslationAgent()


def translate_answer_json(
    payload: dict[str, Any],
    *,
    target_language: str,
    user_id: str,
    session_id: str,
    content_scope: str,
) -> dict[str, Any]:
    result = translation_agent.translate_json(
        payload,
        target_language=target_language,
        user_id=user_id,
        session_id=session_id,
        content_scope=content_scope,
    )
    translated = dict(result.payload)
    translated["translation"] = dict(result.audit)
    return translated


__all__ = [
    "TranslationAgent",
    "TranslationAgentResult",
    "translate_answer_json",
    "translation_agent",
]
