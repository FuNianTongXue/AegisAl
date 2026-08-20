from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from app.agent.translation_agent import TranslationAgent, TranslationAgentResult
from app.agent.assistant_service import translate_assistant_answer
from app.agent.translation_policy import translation_audit_is_publishable
from app.langgraph.assistant_graph import KnowledgeSecurityGraph
from app.langgraph.multi_agent_graph import AssistantMultiAgentSupervisor


def _mcp_result(*, translation_status: str, unresolved_fields: int = 0) -> dict[str, object]:
    return {
        "payload": {"summary": "已完成本地翻译。"},
        "translation_status": translation_status,
        "target_language": "zh-Hans",
        "candidate_fields": 1,
        "translated_fields": 1 if translation_status == "translated" else 0,
        "unresolved_fields": unresolved_fields,
        "batch_count": 1,
        "model_used": False,
        "offline_model_used": translation_status == "translated",
        "offline": True,
        "network_used": False,
        "requires_api_key": False,
        "provider_calls": 0,
        "billable_tokens": 0,
        "token_usage": 0,
        "resource_verified": translation_status == "translated",
        "input_sha256": "a" * 64,
        "output_sha256": "b" * 64,
        "errors": [],
        "_mcp_runtime": {
            "server_id": "translation",
            "tool_id": "mcp__translation__translate_json_payload",
            "transport": "stdio",
            "status": "completed",
        },
    }


@pytest.mark.parametrize("translation_status", ["translated", "passthrough"])
def test_translation_agent_marks_only_resolved_results_completed(
    translation_status: str,
) -> None:
    with patch(
        "app.agent.translation_agent.call_mcp_tool",
        return_value=_mcp_result(translation_status=translation_status),
    ):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "completed"
    assert result.audit["translation_status"] == translation_status
    assert result.audit["unresolved_fields"] == 0
    assert result.audit["offline_contract_valid"] is True
    assert result.audit["runtime_contract_valid"] is True
    if translation_status == "translated":
        assert result.audit["resource_verified"] is True
    else:
        assert result.audit["resource_verified"] is False


@pytest.mark.parametrize(
    "field",
    [
        "offline",
        "network_used",
        "requires_api_key",
        "model_used",
        "provider_calls",
        "billable_tokens",
        "token_usage",
        "resource_verified",
    ],
)
@pytest.mark.parametrize("translation_status", ["translated", "passthrough", "fallback"])
def test_translation_agent_fails_closed_when_audit_field_is_missing(
    field: str,
    translation_status: str,
) -> None:
    outcome = _mcp_result(translation_status=translation_status, unresolved_fields=1)
    outcome.pop(field)

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["offline_contract_valid"] is False
    assert field in result.audit["warnings"][-1]


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("offline", False),
        ("offline", 1),
        ("network_used", True),
        ("network_used", 0),
        ("requires_api_key", True),
        ("requires_api_key", 0),
        ("model_used", True),
        ("model_used", 0),
        ("provider_calls", 1),
        ("provider_calls", False),
        ("billable_tokens", 1),
        ("billable_tokens", False),
        ("token_usage", 1),
        ("token_usage", False),
        ("resource_verified", False),
        ("resource_verified", "true"),
    ],
)
def test_translation_agent_rejects_unsafe_values_and_type_coercion(
    field: str,
    unsafe_value: object,
) -> None:
    outcome = _mcp_result(translation_status="translated")
    outcome[field] = unsafe_value

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["offline_contract_valid"] is False
    assert field in result.audit["warnings"][-1] or field == "resource_verified"


@pytest.mark.parametrize("raw_value", [None, False, "0", 0.0, []])
def test_translation_agent_rejects_unresolved_field_type_coercion(raw_value: object) -> None:
    outcome = _mcp_result(translation_status="translated")
    if raw_value is None:
        outcome.pop("unresolved_fields")
    else:
        outcome["unresolved_fields"] = raw_value

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["unresolved_fields"] == -1


def test_translation_agent_rejects_a_mismatched_target_language() -> None:
    outcome = _mcp_result(translation_status="translated")
    outcome["target_language"] = "en"

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["offline_contract_valid"] is False
    assert "target_language" in result.audit["warnings"][-1]


@pytest.mark.parametrize("runtime_value", [None, "stdio", [], 0])
def test_translation_agent_fails_closed_without_a_runtime_envelope(
    runtime_value: object,
) -> None:
    outcome = _mcp_result(translation_status="translated")
    if runtime_value is None:
        outcome.pop("_mcp_runtime")
    else:
        outcome["_mcp_runtime"] = runtime_value

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["offline_contract_valid"] is True
    assert result.audit["runtime_contract_valid"] is False
    assert "_mcp_runtime" in result.audit["warnings"][-1]


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("server_id", "attacker-translation"),
        ("tool_id", "mcp__attacker__translate_json_payload"),
        ("transport", "streamable-http"),
        ("status", "failed"),
        ("server_id", 1),
    ],
)
def test_translation_agent_rejects_forged_runtime_envelope_fields(
    field: str,
    forged_value: object,
) -> None:
    outcome = _mcp_result(translation_status="translated")
    runtime = dict(outcome["_mcp_runtime"])
    runtime[field] = forged_value
    outcome["_mcp_runtime"] = runtime

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["runtime_contract_valid"] is False
    assert field in result.audit["warnings"][-1]


@pytest.mark.parametrize(
    "field",
    ["server_id", "tool_id", "transport", "status"],
)
def test_translation_agent_rejects_missing_runtime_envelope_fields(field: str) -> None:
    outcome = _mcp_result(translation_status="translated")
    runtime = dict(outcome["_mcp_runtime"])
    runtime.pop(field)
    outcome["_mcp_runtime"] = runtime

    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["runtime_contract_valid"] is False
    assert field in result.audit["warnings"][-1]


def test_translation_agent_marks_fallback_with_unresolved_fields_partial() -> None:
    with patch(
        "app.agent.translation_agent.call_mcp_tool",
        return_value=_mcp_result(translation_status="fallback", unresolved_fields=1),
    ):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "partial"
    assert result.audit["translation_status"] == "fallback"
    assert result.audit["unresolved_fields"] == 1
    assert result.audit["offline_contract_valid"] is True
    assert result.audit["runtime_contract_valid"] is True


@pytest.mark.parametrize("translation_status", ["unavailable", "unsupported"])
def test_translation_agent_marks_terminal_translation_failures_failed(
    translation_status: str,
) -> None:
    outcome = _mcp_result(translation_status=translation_status, unresolved_fields=1)
    outcome["errors"] = ["offline translation unavailable"]
    with patch("app.agent.translation_agent.call_mcp_tool", return_value=outcome):
        result = TranslationAgent().translate_json(
            {"summary": "Remote code execution."},
            target_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result.audit["status"] == "failed"
    assert result.audit["translation_status"] == translation_status
    assert result.audit["unresolved_fields"] == 1
    assert result.audit["warnings"] == ["offline translation unavailable"]


def test_assistant_trace_does_not_report_partial_translation_as_completed() -> None:
    translated = {
        "summary": "已保留结构化结果。",
        "fields": {},
        "report": {"content": "English report body"},
        "agent_task": {"result": {"summary": "English task body"}},
        "orchestration": {"handoffs": [{"reason": "English handoff reason"}]},
        "artifacts": [
            {"id": "artifact-1", "file_name": "report.pdf", "media_type": "application/pdf", "content": "English artifact body"}
        ],
        "interrupt": {"kind": "report_download_confirmation", "thread_id": "report-1", "question": "Download English report?"},
        "trace": [],
        "translation": {
            "status": "partial",
            "translation_status": "fallback",
            "target_language": "zh-Hans",
            "candidate_fields": 2,
            "translated_fields": 1,
            "unresolved_fields": 1,
        },
    }
    with patch(
        "app.agent.assistant_service.translate_answer_json",
        return_value=translated,
    ):
        result = translate_assistant_answer(
            {"summary": "Original answer.", "fields": {}, "trace": []},
            response_language="zh-Hans",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result["translation"]["status"] == "partial"
    assert result["translation"]["publication_status"] == "blocked"
    assert result["summary"] == "离线译文暂不可用，请稍后重试。"
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert "Original answer." not in serialized
    assert "已保留结构化结果" not in serialized
    assert "English report body" not in serialized
    assert "English task body" not in serialized
    assert "English handoff reason" not in serialized
    assert "English artifact body" not in serialized
    assert "Download English report?" not in serialized
    assert result["artifacts"] == [
        {"id": "artifact-1", "file_name": "report.pdf", "media_type": "application/pdf"}
    ]
    assert result["interrupt"]["thread_id"] == "report-1"
    assert result["trace"][-1]["node"] == "translation_agent"
    assert result["trace"][-1]["status"] != "completed"


def test_assistant_service_fails_closed_when_translation_raises() -> None:
    with patch(
        "app.agent.assistant_service.translate_answer_json",
        side_effect=RuntimeError("offline resource unavailable"),
    ):
        result = translate_assistant_answer(
            {"summary": "Original answer.", "fields": {"detail": "English detail"}, "trace": []},
            response_language="zh-Hant",
            user_id="user-1",
            session_id="session-1",
            content_scope="test",
        )

    assert result["summary"] == "離線譯文暫不可用，請稍後重試。"
    assert result["translation"]["status"] == "failed"
    assert result["translation"]["publication_status"] == "blocked"
    assert result["fields"] == {}
    assert "Original answer." not in repr(result)
    assert "English detail" not in repr(result)


def _partial_translation_result() -> TranslationAgentResult:
    return TranslationAgentResult(
        payload={
            "mode": "llm_direct",
            "summary": "Original answer.",
            "fields": {"detail": "English detail"},
            "records": [{"summary": "English record"}],
            "report": {"content": "English report body"},
            "orchestration": {"handoffs": [{"reason": "English handoff reason"}]},
            "trace": [],
        },
        audit={
            "status": "partial",
            "translation_status": "fallback",
            "target_language": "zh-Hans",
            "candidate_fields": 3,
            "translated_fields": 1,
            "unresolved_fields": 2,
            "output_sha256": "b" * 64,
        },
    )


def test_assistant_graph_does_not_publish_partial_translation_payload() -> None:
    state = {
        "answer": {"mode": "llm_direct", "summary": "Original answer.", "trace": [{"message": "English trace body"}]},
        "response_language": "zh-Hans",
        "user_id": "user-1",
        "session_id": "session-1",
        "trace": [{"node": "compose", "message": "English state trace body"}],
    }
    with patch(
        "app.langgraph.assistant_graph.translation_agent.translate_json",
        return_value=_partial_translation_result(),
    ):
        result = KnowledgeSecurityGraph._translate_answer(object(), state)

    assert result["answer"]["summary"] == "离线译文暂不可用，请稍后重试。"
    assert result["answer"]["translation"]["publication_status"] == "blocked"
    assert "Original answer." not in repr(result["answer"])
    assert "English record" not in repr(result["answer"])
    assert "English trace body" not in repr(result["answer"])
    assert "English state trace body" not in repr(result["answer"])


def test_multi_agent_graph_does_not_publish_partial_translation_payload() -> None:
    class PartialTranslationAgent:
        @staticmethod
        def translate_json(*_args, **_kwargs):
            return _partial_translation_result()

    supervisor = AssistantMultiAgentSupervisor.__new__(AssistantMultiAgentSupervisor)
    supervisor._translation_agent = PartialTranslationAgent()
    state = {
        "answer": {"mode": "llm_direct", "summary": "Original answer.", "trace": [{"message": "English trace body"}]},
        "response_language": "zh-Hans",
        "user_id": "user-1",
        "session_id": "session-1",
        "visited_agents": [],
        "handoffs": [],
        "trace": [{"node": "aggregate", "message": "English state trace body"}],
    }

    result = supervisor._translation(state)

    assert result["answer"]["summary"] == "离线译文暂不可用，请稍后重试。"
    assert result["answer"]["translation"]["publication_status"] == "blocked"
    assert "Original answer." not in repr(result["answer"])
    assert "English detail" not in repr(result["answer"])
    assert "English report body" not in repr(result["answer"])
    assert "English handoff reason" not in repr(result["answer"])
    assert "English trace body" not in repr(result["answer"])
    assert "English state trace body" not in repr(result["answer"])
    assert "handoffs" not in result["answer"]["orchestration"]


@pytest.mark.parametrize("unsafe_unresolved", [False, "0", 0.0, None])
def test_publish_policy_rejects_coerced_unresolved_field_types(unsafe_unresolved: object) -> None:
    audit = {
        "status": "completed",
        "translation_status": "translated",
        "unresolved_fields": unsafe_unresolved,
        "offline_contract_valid": True,
        "runtime_contract_valid": True,
        "transport": "stdio",
        "network_used": False,
        "provider_calls": 0,
        "billable_tokens": 0,
        "token_usage": 0,
    }

    assert translation_audit_is_publishable(audit) is False
