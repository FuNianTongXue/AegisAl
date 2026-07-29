from __future__ import annotations

import json
import re
from typing import Any

from app.privacy import sanitize_public_text


_TOOL_STATES = {"completed", "running", "awaiting-approval", "error"}
_SENSITIVE_INPUT_KEY = re.compile(
    r"(?:api[-_]?key|authorization|cookie|credential|password|secret|token)",
    flags=re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[-_]?key|access[-_]?token|refresh[-_]?token|authorization|password|secret|token)"
    r"(\s*[:=]\s*[\"']?)([^\"'\s,;&}]+)",
)
_BEARER_TOKEN = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}")
_API_TOKEN = re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b")


def tool_call_presentation(
    tool_name: str,
    *,
    state: str,
    title: str = "",
    input_summary: dict[str, Any] | None = None,
    output: Any = "",
    error: Any = "",
) -> dict[str, Any]:
    normalized_state = state if state in _TOOL_STATES else "completed"
    return {
        "kind": "tool_call",
        "title": _bounded_text(title, 160),
        "tool_name": _bounded_text(tool_name, 160),
        "state": normalized_state,
        "input": {
            _bounded_text(key, 120): (
                "[REDACTED]" if _SENSITIVE_INPUT_KEY.search(str(key)) else _bounded_value(value, 1_200)
            )
            for key, value in list((input_summary or {}).items())[:24]
        },
        "output": _bounded_value(output, 4_000),
        "error": _bounded_value(error, 4_000),
    }


def prompt_diff_presentation(
    *,
    title: str,
    before: str,
    after: str,
) -> dict[str, Any]:
    return {
        "kind": "prompt_diff",
        "title": _bounded_text(title, 160),
        "before": _bounded_text(before, 24_000),
        "after": _bounded_text(after, 24_000),
    }


def _bounded_value(value: Any, limit: int) -> str:
    if isinstance(value, (dict, list, tuple)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    else:
        text = str(value or "")
    return _bounded_text(text, limit)


def _bounded_text(value: Any, limit: int) -> str:
    clean = _redact_secrets(sanitize_public_text(value)).strip()
    if len(clean) <= limit:
        return clean
    return clean[: max(0, limit - 1)].rstrip() + "…"


def _redact_secrets(value: str) -> str:
    text = _BEARER_TOKEN.sub(r"\1[REDACTED]", value)
    text = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    return _API_TOKEN.sub("[REDACTED]", text)
