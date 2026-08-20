from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from app import catalog_translation
from app.agent.translation_agent import TranslationAgentResult


class CatalogTranslationBackoffTests(unittest.TestCase):
    def setUp(self) -> None:
        catalog_translation._translation_backoff_until = 0.0

    def tearDown(self) -> None:
        catalog_translation._translation_backoff_until = 0.0

    def test_offline_runtime_failure_opens_backoff_and_prevents_duplicate_calls(self) -> None:
        record = {
            "id": "CVE-2026-81234",
            "title": "Startup translation contention",
            "summary": "A background translation job should not repeatedly occupy the offline worker.",
        }
        unavailable = {
            "payload": {"records": [{"record_key": record["id"], "title": record["title"], "summary": record["summary"]}]},
            "translation_status": "unavailable",
            "candidate_fields": 2,
            "translated_fields": 0,
            "unresolved_fields": 2,
            "batch_count": 1,
            "model_used": False,
            "offline_model_used": False,
            "offline": True,
            "network_used": False,
            "requires_api_key": False,
            "provider_calls": 0,
            "billable_tokens": 0,
            "token_usage": 0,
            "input_sha256": "input",
            "output_sha256": "input",
            "errors": ["offline language pack unavailable"],
        }

        with patch("app.agent.translation_agent.call_mcp_tool", return_value=unavailable) as translator:
            _first_records, first_audit = catalog_translation.translate_records_for_storage([record])
            _second_records, second_audit = catalog_translation.translate_records_for_storage([record])

        self.assertEqual(first_audit["pending_records"], 1)
        self.assertEqual(second_audit["translation_status"], "deferred")
        self.assertGreater(second_audit["retry_after_seconds"], 0)
        translator.assert_called_once()

    def test_failed_agent_audit_cannot_publish_or_store_chinese_candidate_text(self) -> None:
        record = {
            "id": "CVE-2026-81235",
            "title": "Remote execution vulnerability",
            "summary": "A remote attacker may execute arbitrary code.",
        }
        rejected = TranslationAgentResult(
            payload={
                "records": [
                    {
                        "record_key": record["id"],
                        "title": "远程代码执行漏洞",
                        "summary": "远程攻击者可能执行任意代码。",
                    }
                ]
            },
            audit={
                "server": "SecFlow Translation MCP",
                "tool": "translate_json_payload",
                "transport": "stdio",
                "status": "failed",
                "translation_status": "translated",
                "target_language": "zh-Hans",
                "unresolved_fields": 0,
                "offline_contract_valid": False,
                "runtime_contract_valid": True,
                "network_used": True,
                "provider_calls": 1,
                "billable_tokens": 25,
                "token_usage": 25,
            },
        )

        with patch(
            "app.agent.translation_agent.translation_agent.translate_json",
            return_value=rejected,
        ):
            translated, audit = catalog_translation.translate_records_for_storage([record])

        self.assertEqual(translated[0]["title_zh"], "")
        self.assertEqual(translated[0]["summary_zh"], "")
        self.assertEqual(translated[0]["catalog_translation"]["status"], "pending")
        self.assertEqual(audit["pending_records"], 1)
        self.assertEqual(audit["publication_status"], "blocked")


if __name__ == "__main__":
    unittest.main()
