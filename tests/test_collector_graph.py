from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.collectors import collector_graph, collector_service
from app.storage import StateStore, default_state


class CollectorGraphTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp_dir.name) / "state.json")
        state = default_state()
        state["records"] = []
        state["collectors"]["cve"]["api_key"] = "test-api-key"
        state["collectors"]["github_advisory"]["token"] = "test-token"
        self.store.write(state)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_collection_runs_subgraph_and_deduplicates_records(self) -> None:
        records = [
            {
                "id": "CVE-2026-1000",
                "title": "First title",
                "severity": "HIGH",
                "collection": "cve",
                "updated_at": "2026-07-01T00:00:00+00:00",
            },
            {
                "id": "cve-2026-1000",
                "title": "Updated title",
                "severity": "CRITICAL",
                "collection": "cve",
                "updated_at": "2026-07-02T00:00:00+00:00",
            },
        ]
        with (
            patch("app.collector_graph.store", self.store),
            patch.object(collector_service, "_collect_cve", return_value=records),
        ):
            result = collector_graph.invoke("cve")

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["fetched"], 1)
        self.assertEqual(result["inserted"], 1)
        self.assertEqual(self.store.read()["records"][0]["title"], "Updated title")
        self.assertEqual(
            [item["node"] for item in result["trace"]],
            ["validate_config", "fetch_records", "normalize_records", "translate_records", "persist_records", "compose_result"],
        )

    def test_missing_credential_still_allows_api_query(self) -> None:
        state = self.store.read()
        state["collectors"]["cve"]["api_key"] = ""
        self.store.write(state)
        with (
            patch("app.collector_graph.store", self.store),
            patch.object(collector_service, "_collect_cve", return_value=[]) as fetch,
        ):
            result = collector_graph.invoke("cve")

        fetch.assert_called_once()
        self.assertEqual(result["status"], "success")
        self.assertEqual(
            [item["node"] for item in result["trace"]],
            ["validate_config", "fetch_records", "normalize_records", "translate_records", "persist_records", "compose_result"],
        )

    def test_year_collection_keeps_successful_year_when_another_fails(self) -> None:
        def fetch(_config, year=None, max_results=None):
            if year == 2025:
                raise RuntimeError("window unavailable")
            return [
                {
                    "id": "CVE-2026-2000",
                    "title": "Current year issue",
                    "severity": "HIGH",
                    "collection": "cve",
                    "updated_at": "2026-07-03T00:00:00+00:00",
                }
            ]

        with (
            patch("app.collector_graph.store", self.store),
            patch.object(collector_service, "_collect_cve", side_effect=fetch),
        ):
            result = collector_graph.invoke("cve", years=[2025, 2026], max_results=10)

        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["years"], [2026, 2025])
        self.assertEqual(result["fetched"], 1)
        self.assertEqual(len(result["errors"]), 1)


if __name__ == "__main__":
    unittest.main()
