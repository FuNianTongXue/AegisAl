from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from app import catalog_translation


class CatalogTranslationBackoffTests(unittest.TestCase):
    def setUp(self) -> None:
        catalog_translation._translation_backoff_until = 0.0

    def tearDown(self) -> None:
        catalog_translation._translation_backoff_until = 0.0

    def test_provider_payment_failure_opens_backoff_and_prevents_duplicate_calls(self) -> None:
        record = {
            "id": "CVE-2026-81234",
            "title": "Startup translation contention",
            "summary": "A background translation job should not repeatedly occupy the model connection.",
        }
        fallback = Mock(
            payload={"records": [{"record_key": record["id"], "title": record["title"], "summary": record["summary"]}]},
            translation_status="fallback",
            candidate_fields=2,
            translated_fields=0,
            batch_count=1,
            model_used=True,
            input_sha256="input",
            output_sha256="input",
            errors=["HTTP 402 Payment Required"],
        )

        with patch("app.mcp.translation.translate_json_payload", return_value=fallback) as translator:
            _first_records, first_audit = catalog_translation.translate_records_for_storage([record])
            _second_records, second_audit = catalog_translation.translate_records_for_storage([record])

        self.assertEqual(first_audit["pending_records"], 1)
        self.assertEqual(second_audit["translation_status"], "deferred")
        self.assertGreater(second_audit["retry_after_seconds"], 0)
        translator.assert_called_once()


if __name__ == "__main__":
    unittest.main()
