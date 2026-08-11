from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.main import app
from app.llm import diagnose_chat_completion
from app.model_usage import ModelUsageStore, normalize_model_usage


class ModelUsageTests(unittest.TestCase):
    def test_normalizes_provider_token_shapes(self) -> None:
        self.assertEqual(
            normalize_model_usage({"usage": {"prompt_tokens": 10, "completion_tokens": 4}}),
            {"input_tokens": 10, "output_tokens": 4, "total_tokens": 14},
        )
        self.assertEqual(
            normalize_model_usage({"usage": {"input_tokens": 8, "output_tokens": 3, "total_tokens": 12}}),
            {"input_tokens": 8, "output_tokens": 3, "total_tokens": 12},
        )

    def test_aggregates_real_usage_and_conversation_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            usage = ModelUsageStore(Path(temp_dir) / "usage.sqlite3")
            usage.record(
                user_id="analyst",
                session_id="session-1",
                provider="openai",
                model="gpt-secflow",
                source="assistant_answer",
                input_tokens=100,
                output_tokens=40,
                total_tokens=140,
                created_at="2026-08-02T01:00:00+00:00",
            )
            usage.record(
                user_id="analyst",
                session_id="session-1",
                provider="openai",
                model="gpt-secflow",
                source="intent_planner",
                input_tokens=20,
                output_tokens=10,
                total_tokens=30,
                created_at="2026-08-01T01:00:00+00:00",
            )
            usage.record(
                user_id="other",
                session_id="session-2",
                provider="claude",
                model="claude-test",
                source="assistant_answer",
                input_tokens=999,
                output_tokens=1,
                total_tokens=1000,
                created_at="2026-08-02T01:00:00+00:00",
            )
            snapshot = usage.snapshot(
                "analyst",
                7,
                history=[
                    {
                        "sessionId": "session-1",
                        "timestamp": "2026-08-02T02:00:00+00:00",
                    }
                ],
                now=datetime(2026, 8, 2, 12, 0, tzinfo=timezone.utc),
            )

        self.assertEqual(snapshot["totals"]["total_tokens"], 170)
        self.assertEqual(snapshot["totals"]["call_count"], 2)
        self.assertEqual(snapshot["conversation_count"], 1)
        self.assertEqual(snapshot["message_count"], 2)
        self.assertEqual(snapshot["active_days"], 2)
        self.assertEqual(snapshot["current_streak"], 2)
        self.assertEqual(snapshot["most_used_model"]["model"], "gpt-secflow")
        self.assertEqual(snapshot["most_used_model"]["share"], 100.0)

    def test_api_accepts_only_supported_ranges(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            usage = ModelUsageStore(Path(temp_dir) / "usage.sqlite3")
            with (
                patch("app.api.routes.application.model_usage_service", usage),
                patch("app.api.routes.application.memory_service.get_history", return_value=[]),
            ):
                client = TestClient(app)
                response = client.get("/api/usage/model", params={"user_id": "analyst", "days": 7})
                invalid = client.get("/api/usage/model", params={"user_id": "analyst", "days": 14})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["range_days"], 7)
        self.assertEqual(invalid.status_code, 422)

    def test_business_model_call_records_provider_usage(self) -> None:
        result = {
            "status": "success",
            "answer": "ok",
            "data": {"usage": {"prompt_tokens": 42, "completion_tokens": 8, "total_tokens": 50}},
        }
        with (
            patch("app.llm._diagnose_chat_completion_impl", return_value=result),
            patch("app.llm.model_usage_service.record_result", return_value=True) as record,
        ):
            returned = diagnose_chat_completion(
                {"provider": "openai", "model": "gpt-test"},
                [{"role": "user", "content": "hello"}],
                user_id="analyst",
                session_id="session-1",
                source="assistant_answer",
            )

        self.assertIs(returned, result)
        record.assert_called_once_with(
            result,
            {"provider": "openai", "model": "gpt-test"},
            user_id="analyst",
            session_id="session-1",
            source="assistant_answer",
        )


if __name__ == "__main__":
    unittest.main()
