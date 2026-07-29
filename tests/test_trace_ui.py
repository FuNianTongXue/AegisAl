from __future__ import annotations

import unittest

from app.trace_ui import prompt_diff_presentation, tool_call_presentation


class TracePresentationTests(unittest.TestCase):
    def test_tool_call_presentation_exposes_bounded_display_contract(self) -> None:
        presentation = tool_call_presentation(
            "search_components",
            state="running",
            title="Component query",
            input_summary={"query": "demo@1.0.0", "options": {"limit": 5}},
            output={"matches": 3},
        )

        self.assertEqual(
            set(presentation),
            {"kind", "title", "tool_name", "state", "input", "output", "error"},
        )
        self.assertEqual(presentation["kind"], "tool_call")
        self.assertEqual(presentation["state"], "running")
        self.assertEqual(presentation["input"]["options"], '{"limit":5}')
        self.assertEqual(presentation["output"], '{"matches":3}')

    def test_tool_call_presentation_redacts_credentials_in_all_text_fields(self) -> None:
        presentation = tool_call_presentation(
            "api_request",
            state="not-a-client-state",
            input_summary={
                "api_key": "sk-live-secret-value-123456789",
                "headers": "Authorization: Bearer opaque-token-value-123456",
            },
            output="token=visible-secret-value",
            error="request failed with sk-another-secret-123456789",
        )
        serialized = str(presentation)

        self.assertEqual(presentation["state"], "completed")
        self.assertEqual(presentation["input"]["api_key"], "[REDACTED]")
        self.assertNotIn("opaque-token", serialized)
        self.assertNotIn("visible-secret", serialized)
        self.assertNotIn("another-secret", serialized)
        self.assertIn("[REDACTED]", serialized)

    def test_prompt_diff_presentation_keeps_real_before_after_and_applies_limits(self) -> None:
        presentation = prompt_diff_presentation(
            title="System Prompt Changes",
            before="You are a helpful assistant.",
            after="You are a senior security engineer.\nAPI_KEY=sk-secret-value-123456789",
        )

        self.assertEqual(set(presentation), {"kind", "title", "before", "after"})
        self.assertEqual(presentation["before"], "You are a helpful assistant.")
        self.assertIn("senior security engineer", presentation["after"])
        self.assertNotIn("sk-secret", presentation["after"])


if __name__ == "__main__":
    unittest.main()
