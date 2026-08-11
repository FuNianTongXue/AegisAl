from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.mcp.translation import invoke_translation_mcp
from app.storage import now_iso


@dataclass(frozen=True)
class TranslationAgentResult:
    payload: dict[str, Any]
    audit: dict[str, Any]


class TranslationAgent:
    """LangGraph-facing adapter with Translation MCP as its only content tool."""

    agent_id = "translation_agent"
    tool_allowlist = ("translation_mcp",)

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
        result = invoke_translation_mcp(
            {
                "payload": payload,
                "target_language": target_language,
                "user_id": user_id,
                "session_id": session_id,
                "content_scope": content_scope,
            }
        )
        translated = result.get("payload") if isinstance(result.get("payload"), dict) else {}
        if not translated:
            raise RuntimeError("Translation MCP returned an empty JSON payload")
        audit = {
            "server": "SecFlow Translation MCP",
            "tool": "translate_json_payload",
            "transport": "in-process",
            "status": "completed",
            "translation_status": str(result.get("translation_status") or "fallback"),
            "target_language": str(result.get("target_language") or target_language),
            "candidate_fields": int(result.get("candidate_fields") or 0),
            "translated_fields": int(result.get("translated_fields") or 0),
            "batch_count": int(result.get("batch_count") or 0),
            "model_used": bool(result.get("model_used")),
            "input_sha256": str(result.get("input_sha256") or ""),
            "output_sha256": str(result.get("output_sha256") or ""),
            "invoked_at": invoked_at,
        }
        if result.get("errors"):
            audit["warnings"] = [str(item) for item in result.get("errors") or []]
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
