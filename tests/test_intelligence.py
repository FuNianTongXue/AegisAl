from __future__ import annotations

import json
import sqlite3
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from threading import Event, Thread
from unittest.mock import Mock, patch

from app.intelligence import (
    RealtimeIntelligenceService,
    _github_record,
    _merge_records,
    _osv_record,
    _patch_snippets_from_commit_payload,
    _version_in_affected_range,
    build_knowledge_graph,
)
from app.secure_storage import is_encrypted_text, secure_metadata_key
from app.memory import LongTermMemoryService
from app.storage import StateStore, default_state


class RealtimeIntelligenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store = StateStore(Path(self.temp_dir.name) / "state.json")
        state = default_state()
        state["records"] = []
        self.store.write(state)
        self.service = RealtimeIntelligenceService(Path(self.temp_dir.name) / "catalog.sqlite3")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_multi_source_query_enriches_graph_without_persisting(self) -> None:
        nvd = {
            "id": "CVE-2026-1000",
            "title": "Example remote execution",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "summary": "Example issue",
            "affected_versions": ["demo server < 2.0.0"],
            "fixed_versions": [],
            "aliases": ["CVE-2026-1000"],
            "cwes": ["CWE-78"],
            "components": [{"name": "demo-server", "ecosystem": "npm", "affected": ["< 2.0.0"], "fixed": []}],
            "references": ["https://example.test/advisory/CVE-2026-1000"],
            "updated_at": "2026-07-15T00:00:00+00:00",
            "provenance": ["nvd"],
        }
        osv = {
            **nvd,
            "id": "CVE-2026-1000",
            "severity": "HIGH",
            "aliases": ["CVE-2026-1000", "GHSA-1111-2222-3333"],
            "fixed_versions": ["npm / demo-server: 2.0.0"],
            "components": [{"name": "demo-server", "ecosystem": "npm", "affected": ["< 2.0.0"], "fixed": ["2.0.0"]}],
            "provenance": ["osv"],
        }
        github = {
            **nvd,
            "id": "GHSA-1111-2222-3333",
            "severity": "HIGH",
            "aliases": ["CVE-2026-1000", "GHSA-1111-2222-3333"],
            "provenance": ["github_advisory"],
        }

        def query_source(source: str, _query: str, _limit: int):
            return {"nvd": [nvd], "github_advisory": [github], "osv": [osv]}[source]

        with (
            patch("app.intelligence.store", self.store),
            patch("app.intelligence.active_model_from_env", return_value=None),
            patch.object(self.service, "_query_source", side_effect=query_source),
        ):
            result = self.service.query("CVE-2026-1000", sources=["nvd", "github_advisory", "osv"])
            second = self.service.query("CVE-2026-1000", sources=["nvd", "github_advisory", "osv"])

        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["id"], "CVE-2026-1000")
        self.assertNotIn("source", result["records"][0])
        self.assertNotIn("provenance", result["records"][0])
        self.assertNotIn("references", result["records"][0])
        self.assertEqual(result["records"][0]["reference_links"], ["https://example.test/advisory/CVE-2026-1000"])
        self.assertEqual(result["persisted"]["inserted"], 0)
        self.assertEqual(second["persisted"]["inserted"], 0)
        self.assertEqual(len(self.store.read()["records"]), 0)
        self.assertIn("GHSA-1111-2222-3333", result["records"][0]["aliases"])
        edge_types = {edge["type"] for edge in result["graph"]["edges"]}
        self.assertTrue({"ALIAS_OF", "HAS_WEAKNESS", "AFFECTS", "FIXED_BY"}.issubset(edge_types))
        vulnerability_node = next(node for node in result["graph"]["nodes"] if node["type"] == "vulnerability")
        self.assertEqual(vulnerability_node["metadata"]["severity_zh"], "严重")
        self.assertIn("CVE-2026-1000", vulnerability_node["metadata"]["summary_zh"])
        self.assertIn("严重漏洞", vulnerability_node["metadata"]["summary_zh"])
        self.assertEqual(vulnerability_node["metadata"]["affected_versions"], ["demo server < 2.0.0"])
        self.assertEqual(vulnerability_node["metadata"]["fixed_versions"], ["npm / demo-server: 2.0.0"])
        self.assertIn("建议优先升级", vulnerability_node["metadata"]["remediation_zh"])
        self.assertIn("临时降低攻击面", vulnerability_node["metadata"]["mitigation_zh"])
        self.assertEqual(result["persistence"], "api-only")
        dashboard = self.service.dashboard()
        self.assertEqual(dashboard["vulnerability_count"], 0)
        self.assertEqual(dashboard["query_count"], 0)
        self.assertEqual(dashboard["severity"]["CRITICAL"], 0)

    def test_identifier_query_uses_local_catalog_before_api(self) -> None:
        self.service._catalog.upsert(
            [
                {
                    "id": "CVE-2026-7777",
                    "title": "Local catalog issue",
                    "severity": "HIGH",
                    "cvss_score": 8.1,
                    "summary": "本地 catalog 已有漏洞事实。",
                    "aliases": ["CVE-2026-7777"],
                    "components": [{"name": "demo-server", "ecosystem": "npm", "affected": ["< 2.0.0"], "fixed": ["2.0.0"]}],
                    "references": ["https://example.test/CVE-2026-7777"],
                    "published_at": "2026-07-17T00:00:00+00:00",
                    "updated_at": "2026-07-17T00:00:00+00:00",
                }
            ]
        )

        with patch.object(self.service, "_query_source", side_effect=AssertionError("should not call api")):
            result = self.service.query("CVE-2026-7777")

        self.assertEqual(result["records"][0]["id"], "CVE-2026-7777")
        self.assertEqual(result["persistence"], "local-catalog")
        self.assertIn("本地漏洞 catalog 命中", result["trace"][1]["message"])

    def test_catalog_reads_do_not_wait_for_background_writer_lock(self) -> None:
        self.service._catalog.upsert(
            [
                {
                    "id": "CVE-2026-9001",
                    "title": "Concurrent catalog read",
                    "severity": "HIGH",
                    "aliases": ["CVE-2026-9001"],
                    "components": [],
                    "references": [],
                    "published_at": "2026-07-20T00:00:00+00:00",
                    "updated_at": "2026-07-20T00:00:00+00:00",
                }
            ]
        )
        completed = Event()
        observed: dict[str, object] = {}

        def read_snapshot() -> None:
            observed["snapshot"] = self.service._catalog.snapshot()
            observed["metadata"] = self.service._catalog.metadata("baseline_status", "pending")
            observed["finding"] = self.service._catalog.find_by_identifier("CVE-2026-9001")
            completed.set()

        with self.service._catalog._lock:
            reader = Thread(target=read_snapshot)
            reader.start()
            self.assertTrue(completed.wait(1), "catalog read waited for the background writer lock")
        reader.join(timeout=1)

        self.assertEqual(observed["snapshot"]["total"], 1)
        self.assertEqual(observed["metadata"], "pending")
        self.assertEqual(observed["finding"][0]["id"], "CVE-2026-9001")

    def test_incomplete_local_identifier_is_realtime_enriched_and_repaired(self) -> None:
        self.service._catalog.upsert(
            [
                {
                    "id": "CVE-2026-55576",
                    "title": "Incomplete local issue",
                    "severity": "UNKNOWN",
                    "cvss_score": None,
                    "summary": "An incomplete local record.",
                    "aliases": ["CVE-2026-55576", "GHSA-PQX2-5G66-F5W8"],
                    "components": [],
                    "references": [],
                    "published_at": "2026-07-15T00:00:00+00:00",
                    "updated_at": "2026-07-16T00:00:00+00:00",
                }
            ]
        )
        enriched = {
            "id": "CVE-2026-55576",
            "title": "Workflow expression injection",
            "severity": "HIGH",
            "cvss_score": 8.8,
            "summary": "A pull request title can reach a shell command.",
            "aliases": ["CVE-2026-55576", "GHSA-PQX2-5G66-F5W8"],
            "cwes": ["CWE-78", "CWE-94"],
            "components": [],
            "references": ["https://example.test/CVE-2026-55576"],
            "published_at": "2026-07-15T00:00:00+00:00",
            "updated_at": "2026-07-17T00:00:00+00:00",
            "provenance": ["nvd"],
        }

        with patch.object(
            self.service,
            "_query_source",
            side_effect=lambda source, _query, _limit: [enriched] if source == "nvd" else [],
        ):
            result = self.service.query("CVE-2026-55576")

        self.assertEqual(result["records"][0]["severity"], "HIGH")
        self.assertEqual(result["records"][0]["cvss_score"], 8.8)
        self.assertEqual(result["records"][0]["reference_links"], ["https://example.test/CVE-2026-55576"])
        self.assertEqual(result["persistence"], "local-catalog-refreshed")
        repaired = self.service._catalog.find_by_identifier("CVE-2026-55576")[0]
        self.assertEqual(repaired["severity"], "HIGH")
        self.assertEqual(repaired["references"], ["https://example.test/CVE-2026-55576"])

    def test_dependency_query_uses_local_component_index_before_api(self) -> None:
        self.service._catalog.upsert(
            [
                {
                    "id": "CVE-2026-8888",
                    "title": "Local dependency issue",
                    "severity": "CRITICAL",
                    "summary": "本地组件索引已覆盖该依赖。",
                    "aliases": ["CVE-2026-8888"],
                    "components": [
                        {
                            "name": "org.apache.logging.log4j:log4j-core",
                            "ecosystem": "Maven",
                            "affected": [">= 2.0.0, < 2.15.0"],
                            "fixed": ["2.15.0"],
                        }
                    ],
                    "published_at": "2026-07-17T00:00:00+00:00",
                    "updated_at": "2026-07-17T00:00:00+00:00",
                }
            ]
        )
        dependencies = [
            {
                "ecosystem": "Maven",
                "name": "org.apache.logging.log4j:log4j-core",
                "version": "2.14.1",
                "source_file": "pom.xml",
                "source_type": "pom",
                "declaration": "org.apache.logging.log4j:log4j-core:2.14.1",
                "confidence": "high",
            }
        ]

        with patch.object(self.service, "_query_osv_dependency", side_effect=AssertionError("should not call dependency api")):
            result = self.service.query_dependencies(dependencies)

        self.assertEqual(result["records"][0]["id"], "CVE-2026-8888")
        self.assertIn("本地漏洞 catalog 按组件命中", [item["message"] for item in result["trace"]][1])
        self.assertEqual(result["records"][0]["matched_dependencies"][0]["source_file"], "pom.xml")

    def test_dependency_query_returns_when_realtime_lookup_exceeds_budget(self) -> None:
        dependencies = [
            {
                "ecosystem": "Maven",
                "name": "org.example:slow-library",
                "version": "1.0.0",
                "source_file": "pom.xml",
                "source_type": "pom",
                "declaration": "org.example:slow-library:1.0.0",
                "confidence": "high",
            }
        ]

        def slow_lookup(_dependency: dict[str, str], _limit: int):
            time.sleep(1)
            return []

        started_at = time.monotonic()
        with (
            patch.dict("os.environ", {"SECFLOW_DEPENDENCY_TOTAL_BUDGET_SECONDS": "0.1"}),
            patch.object(self.service, "_query_osv_dependency", side_effect=slow_lookup),
        ):
            result = self.service.query_dependencies(dependencies)
        elapsed = time.monotonic() - started_at

        self.assertLess(elapsed, 0.5)
        self.assertEqual(result["status"], "warning")
        self.assertIn("实时补齐超过响应预算", " ".join(item["message"] for item in result["trace"]))

    def test_dependency_without_version_is_not_reported_as_vulnerable(self) -> None:
        dependency = {
            "ecosystem": "Maven",
            "name": "org.example:managed-library",
            "version": "",
            "source_file": "pom.xml",
            "source_type": "pom",
        }
        with patch.object(self.service, "_query_osv_dependency", side_effect=AssertionError("unknown version must not be queried")):
            result = self.service.query_dependencies([dependency])

        self.assertEqual(result["records"], [])
        self.assertEqual(result["status"], "warning")
        self.assertIn("版本未明确", " ".join(item["message"] for item in result["trace"]))

    def test_local_component_match_is_filtered_by_affected_version(self) -> None:
        self.service._catalog.upsert(
            [
                {
                    "id": "CVE-2026-5555",
                    "title": "Old component issue",
                    "severity": "HIGH",
                    "aliases": ["CVE-2026-5555"],
                    "components": [
                        {
                            "ecosystem": "Maven",
                            "name": "cn.hutool:hutool-all",
                            "affected": [">= 0, <= 5.8.11"],
                            "fixed": ["5.8.12"],
                        }
                    ],
                    "published_at": "2026-01-01T00:00:00+00:00",
                    "updated_at": "2026-01-01T00:00:00+00:00",
                }
            ]
        )
        dependency = {
            "ecosystem": "Maven",
            "name": "cn.hutool:hutool-all",
            "version": "5.8.40",
            "source_file": "pom.xml",
            "source_type": "pom",
        }
        with patch.object(self.service, "_query_osv_dependency", return_value=[]):
            result = self.service.query_dependencies([dependency])

        self.assertEqual(result["records"], [])

    def test_maven_version_ranges_are_compared_conservatively(self) -> None:
        self.assertTrue(_version_in_affected_range("5.8.11", ">= 0, <= 5.8.11"))
        self.assertFalse(_version_in_affected_range("5.8.40", ">= 0, <= 5.8.11"))
        self.assertTrue(_version_in_affected_range("3.4.13", "3.4.0 - 3.4.13"))
        self.assertFalse(_version_in_affected_range("4.1.0", ">= 4.0.0-M1, < 4.0.4"))

    def test_legacy_catalog_encryption_migrates_incrementally_after_fast_startup(self) -> None:
        path = Path(self.temp_dir.name) / "legacy-catalog.sqlite3"
        initial = RealtimeIntelligenceService(path)
        initial._catalog.upsert(
            [
                {
                    "id": "CVE-2026-9090",
                    "title": "Legacy catalog issue",
                    "severity": "HIGH",
                    "summary": "用于验证后台加密迁移。",
                    "aliases": ["CVE-2026-9090"],
                    "components": [],
                    "published_at": "2026-07-17T00:00:00+00:00",
                    "updated_at": "2026-07-17T00:00:00+00:00",
                }
            ]
        )
        with sqlite3.connect(path) as connection:
            connection.execute(
                "UPDATE vulnerabilities SET record_json = ? WHERE canonical_id = ?",
                (json.dumps({"id": "CVE-2026-9090", "title": "Legacy catalog issue", "severity": "HIGH"}), "CVE-2026-9090"),
            )
            connection.execute("UPDATE catalog_metadata SET value = '3' WHERE key = 'schema_version'")
            connection.execute(
                "DELETE FROM catalog_metadata WHERE key IN (?, ?)",
                (
                    secure_metadata_key("record_encryption_migration_status"),
                    secure_metadata_key("record_encryption_migration_cursor"),
                ),
            )

        started_at = time.monotonic()
        migrated = RealtimeIntelligenceService(path)
        startup_elapsed = time.monotonic() - started_at
        with sqlite3.connect(path) as connection:
            before = str(connection.execute("SELECT record_json FROM vulnerabilities LIMIT 1").fetchone()[0])

        self.assertLess(startup_elapsed, 0.5)
        self.assertFalse(is_encrypted_text(before))
        self.assertTrue(migrated._catalog.encryption_migration_pending())

        migrated._catalog.migrate_encrypted_catalog_incrementally(Event(), batch_size=1, pause_seconds=0)
        with sqlite3.connect(path) as connection:
            after = str(connection.execute("SELECT record_json FROM vulnerabilities LIMIT 1").fetchone()[0])
        self.assertTrue(is_encrypted_text(after))
        self.assertFalse(migrated._catalog.encryption_migration_pending())
        self.assertEqual(migrated._catalog.find_by_identifier("CVE-2026-9090")[0]["id"], "CVE-2026-9090")

    def test_graph_uses_immediate_chinese_summary_without_per_record_llm_calls(self) -> None:
        record = {
            "id": "CVE-2026-9191",
            "title": "Example issue",
            "severity": "HIGH",
            "summary": "An English vulnerability description.",
            "affected_versions": ["demo < 2.0.0"],
            "fixed_versions": ["demo 2.0.0"],
            "aliases": ["CVE-2026-9191"],
            "cwes": [],
            "components": [],
            "references": [],
        }
        with (
            patch("app.intelligence.active_model_from_env", return_value={"provider": "deepseek"}),
            patch("app.intelligence.diagnose_chat_completion", side_effect=AssertionError("should not call llm")),
        ):
            graph = build_knowledge_graph([record], "dependency-scan")

        summary = graph["nodes"][0]["metadata"]["summary_zh"]
        self.assertIn("CVE-2026-9191", summary)
        self.assertIn("高危漏洞", summary)
        self.assertIn("demo 2.0.0", summary)

    def test_batch_dashboard_counts_vulnerability_batch_not_queries(self) -> None:
        critical = {
            "id": "CVE-2026-1000",
            "title": "Critical issue",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "summary": "Example issue",
            "affected_versions": [],
            "fixed_versions": [],
            "aliases": ["CVE-2026-1000"],
            "cwes": [],
            "components": [],
            "references": [],
            "updated_at": "2026-07-15T00:00:00+00:00",
            "provenance": ["nvd"],
        }
        high = {
            "id": "GHSA-1111-2222-3333",
            "title": "High issue",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "summary": "Example issue",
            "affected_versions": [],
            "fixed_versions": [],
            "aliases": ["CVE-2026-2000", "GHSA-1111-2222-3333"],
            "cwes": [],
            "components": [],
            "references": [],
            "updated_at": "2026-07-15T01:00:00+00:00",
            "provenance": ["github_advisory"],
        }
        duplicate = {
            **critical,
            "severity": "HIGH",
            "aliases": ["CVE-2026-1000", "GHSA-4444-5555-6666"],
            "provenance": ["osv"],
        }

        with (
            patch.object(self.service, "_query_nvd_batch", return_value=[critical]),
            patch.object(self.service, "_query_github_batch", return_value=[high]),
            patch.object(self.service, "_query_osv_batch", return_value=[duplicate]),
            patch.object(self.service, "_query_osv_modified_identifiers", return_value=[]),
        ):
            dashboard = self.service.refresh_dashboard_batch()

        self.assertEqual(dashboard["vulnerability_count"], 2)
        self.assertEqual(dashboard["query_count"], 2)
        self.assertEqual(dashboard["severity"]["CRITICAL"], 1)
        self.assertEqual(dashboard["severity"]["HIGH"], 1)
        self.assertEqual(len(dashboard["recent_records"]), 2)
        self.assertNotIn("provenance", dashboard["recent_records"][0])

    def test_github_batch_stops_when_an_upstream_repeats_a_full_page(self) -> None:
        items = [
            {
                "ghsa_id": f"GHSA-{index:04x}-1111-2222",
                "summary": f"Advisory {index}",
                "description": "Example advisory.",
                "severity": "high",
                "vulnerabilities": [],
            }
            for index in range(100)
        ]
        response = Mock()
        response.json.return_value = items
        response.links = {"next": {"url": "https://example.test/advisories?page=2"}}
        response.raise_for_status.return_value = None
        client = Mock()
        client.get.return_value = response
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)

        with patch("app.intelligence.httpx.Client", return_value=client):
            records = self.service._query_github_batch(
                datetime(2026, 7, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 8, tzinfo=timezone.utc),
                "modified",
            )

        self.assertEqual(len(records), 100)
        self.assertEqual(client.get.call_count, 2)

    def test_github_batch_honors_cancellation_before_requesting(self) -> None:
        stop = Event()
        stop.set()
        client = Mock()
        client.__enter__ = Mock(return_value=client)
        client.__exit__ = Mock(return_value=False)

        with patch("app.intelligence.httpx.Client", return_value=client):
            records = self.service._query_github_batch(
                datetime(2026, 7, 1, tzinfo=timezone.utc),
                datetime(2026, 7, 8, tzinfo=timezone.utc),
                "modified",
                stop,
            )

        self.assertEqual(records, [])
        client.get.assert_not_called()

    def test_dashboard_date_range_filters_persistent_catalog(self) -> None:
        january = {
            "id": "CVE-2026-1000",
            "title": "January issue",
            "severity": "HIGH",
            "aliases": ["CVE-2026-1000"],
            "published_at": "2026-01-15T00:00:00+00:00",
            "updated_at": "2026-07-15T00:00:00+00:00",
        }
        july = {
            "id": "CVE-2026-2000",
            "title": "July issue",
            "severity": "CRITICAL",
            "aliases": ["CVE-2026-2000"],
            "published_at": "2026-07-10T00:00:00+00:00",
            "updated_at": "2026-07-15T00:00:00+00:00",
        }
        missing_publication = {
            "id": "CVE-2020-3000",
            "title": "Updated in July without publication date",
            "severity": "HIGH",
            "aliases": ["CVE-2020-3000"],
            "updated_at": "2026-07-15T00:00:00+00:00",
        }

        with (
            patch.object(self.service, "_query_nvd_batch", return_value=[january, july, missing_publication]),
            patch.object(self.service, "_query_github_batch", return_value=[]),
            patch.object(self.service, "_query_osv_batch", return_value=[]),
            patch.object(self.service, "_query_osv_modified_identifiers", return_value=[]),
        ):
            cumulative = self.service.refresh_dashboard_batch()

        filtered = self.service.dashboard(start_date="2026-07-01", end_date="2026-07-31")
        self.assertEqual(cumulative["vulnerability_count"], 3)
        self.assertEqual(cumulative["scope"], "all")
        self.assertEqual(filtered["vulnerability_count"], 1)
        self.assertEqual(filtered["severity"]["CRITICAL"], 1)
        self.assertEqual(filtered["severity"]["HIGH"], 0)
        self.assertEqual(filtered["scope"], "range")
        self.assertEqual(filtered["range_start"], "2026-07-01")
        self.assertEqual(filtered["range_end"], "2026-07-31")

    def test_dashboard_recent_records_skip_unknown_severity_echo_items(self) -> None:
        unknown_recent = {
            "id": "ECHO-27BC-54E1-5AD4",
            "title": "ECHO-27BC-54E1-5AD4",
            "severity": "UNKNOWN",
            "aliases": ["ECHO-27BC-54E1-5AD4"],
            "published_at": "2026-07-16T00:00:00+00:00",
            "updated_at": "2026-07-16T00:00:00+00:00",
        }
        known_older = {
            "id": "CVE-2026-4000",
            "title": "Known high issue",
            "severity": "HIGH",
            "aliases": ["CVE-2026-4000"],
            "published_at": "2026-07-15T00:00:00+00:00",
            "updated_at": "2026-07-15T00:00:00+00:00",
        }

        with (
            patch.object(self.service, "_query_nvd_batch", return_value=[unknown_recent, known_older]),
            patch.object(self.service, "_query_github_batch", return_value=[]),
            patch.object(self.service, "_query_osv_batch", return_value=[]),
            patch.object(self.service, "_query_osv_modified_identifiers", return_value=[]),
        ):
            dashboard = self.service.refresh_dashboard_batch()

        self.assertEqual(dashboard["vulnerability_count"], 2)
        self.assertEqual(dashboard["severity"]["HIGH"], 1)
        self.assertEqual([record["id"] for record in dashboard["recent_records"]], ["CVE-2026-4000"])
        self.assertNotIn("UNKNOWN", {record["severity"] for record in dashboard["recent_records"]})

    def test_github_advisory_code_blocks_are_split_into_vulnerable_and_fixed_snippets(self) -> None:
        record = _github_record(
            {
                "ghsa_id": "GHSA-1111-2222-3333",
                "cve_id": "CVE-2026-4444",
                "summary": "Example vulnerable API usage",
                "description": (
                    "The vulnerable usage is:\n"
                    "```python\n"
                    "def render(value):\n"
                    "    return template.render(value)\n"
                    "```\n"
                    "The fixed usage is:\n"
                    "```python\n"
                    "def render(value):\n"
                    "    return template.render(escape(value))\n"
                    "```"
                ),
                "severity": "high",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "demo"},
                        "vulnerable_version_range": "< 2.4.1",
                        "first_patched_version": {"identifier": "2.4.1"},
                    }
                ],
            }
        )

        self.assertEqual(record["code_snippets"], ["def render(value):\n    return template.render(value)"])
        self.assertEqual(record["fixed_code_snippets"], ["def render(value):\n    return template.render(escape(value))"])
        merged = _merge_records(
            [
                {
                    **record,
                    "id": "CVE-2026-4444",
                    "aliases": ["CVE-2026-4444", "GHSA-1111-2222-3333"],
                }
            ]
        )
        self.assertEqual(merged[0]["code_snippets"], record["code_snippets"])
        self.assertEqual(merged[0]["fixed_code_snippets"], record["fixed_code_snippets"])

    def test_commit_patch_is_split_into_verified_before_and_after_snippets(self) -> None:
        vulnerable, fixed = _patch_snippets_from_commit_payload(
            {
                "files": [
                    {
                        "filename": "src/main/java/example/TelnetIO.java",
                        "patch": (
                            "@@ -10,5 +10,7 @@ class TelnetIO {\n"
                            "     private static final int DEFAULT_WIDTH = 80;\n"
                            "+    private static final int LARGEST_BELIEVABLE_WIDTH = 500;\n"
                            "     void resize(int width) {\n"
                            "-        if (width < 10) {\n"
                            "+        if (width < 10 || width > LARGEST_BELIEVABLE_WIDTH) {\n"
                            "             width = DEFAULT_WIDTH;\n"
                        ),
                    },
                    {
                        "filename": "tests/exploit_poc.py",
                        "patch": "@@ -1 +1 @@\n-print('old')\n+print('payload')\n",
                    },
                ]
            }
        )

        self.assertEqual(len(vulnerable), 1)
        self.assertEqual(len(fixed), 1)
        self.assertIn("if (width < 10)", vulnerable[0])
        self.assertIn("width > LARGEST_BELIEVABLE_WIDTH", fixed[0])
        self.assertNotIn("payload", "\n".join([*vulnerable, *fixed]).lower())

    def test_exact_query_enriches_explicit_commit_reference_with_patch_snippets(self) -> None:
        nvd = {
            "id": "CVE-2026-56741",
            "title": "JLine remote-telnet denial of service",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "summary": "JLine setTerminalGeometry does not bound client width and terminal dimensions.",
            "affected_versions": ["jline jline3 < 3.30.14"],
            "fixed_versions": ["jline jline3 3.30.14"],
            "aliases": ["CVE-2026-56741"],
            "cwes": ["CWE-400"],
            "components": [],
            "references": ["https://github.com/jline/jline3/commit/733eb353dca7b0ea0252e724445b6defa29c393e"],
            "updated_at": "2026-07-17T22:17:57+00:00",
            "provenance": ["nvd"],
        }
        with (
            patch.object(self.service, "_query_source", side_effect=lambda source, _query, _limit: [nvd] if source == "nvd" else []),
            patch(
                "app.intelligence._fetch_github_commit_patch_snippets",
                return_value=(
                    ["if (width < MIN) width = DEFAULT;"],
                    [
                        "if (++varCount > MAX_VARS) return;",
                        "if (width < MIN || width > MAX) width = DEFAULT;",
                    ],
                ),
            ) as fetch_patch,
        ):
            result = self.service.query("CVE-2026-56741", limit=5)

        fetch_patch.assert_called_once()
        self.assertEqual(result["records"][0]["code_snippets"], ["if (width < MIN) width = DEFAULT;"])
        self.assertEqual(
            result["records"][0]["fixed_code_snippets"][0],
            "if (width < MIN || width > MAX) width = DEFAULT;",
        )

    def test_textual_fixed_commit_is_preserved_as_remediation_fact(self) -> None:
        record = _osv_record(
            {
                "id": "CVE-2026-55576",
                "aliases": ["GHSA-PQX2-5G66-F5W8"],
                "summary": "Workflow expression injection",
                "details": (
                    "A pull request title can reach a shell command. This vulnerability is fixed by commit "
                    "cafc3946059e6337d2089d4fec8b6885ba17c332."
                ),
                "affected": [],
                "references": [],
                "database_specific": {"severity": "HIGH"},
            }
        )

        self.assertEqual(
            record["fixed_versions"],
            ["修复提交 cafc3946059e6337d2089d4fec8b6885ba17c332"],
        )


class LocalMemoryTests(unittest.TestCase):
    def test_conversations_are_grouped_by_session_and_sorted_by_latest_exchange(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange("user-a", "第一轮问题", {"summary": "第一轮回答"}, session_id="session-1")
            service.add_exchange("user-a", "第二轮问题", {"summary": "第二轮回答"}, session_id="session-1")
            service.add_exchange("user-a", "另一个会话", {"summary": "另一个回答"}, session_id="session-2")

            conversations = service.list_conversations("user-a")
            detail = service.get_conversation("user-a", "session-1")

            self.assertEqual({item["id"] for item in conversations}, {"session-1", "session-2"})
            session_one = next(item for item in conversations if item["id"] == "session-1")
            self.assertEqual(session_one["title"], "第一轮问题")
            self.assertEqual(session_one["turn_count"], 2)
            self.assertEqual([item["question"] for item in detail["exchanges"]], ["第一轮问题", "第二轮问题"])
            self.assertEqual(detail["exchanges"][-1]["answer"], "第二轮回答")

    def test_conversations_belong_to_assistant_project_and_support_archive_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange("user-a", "需要归档的对话", {"summary": "归档回答"}, session_id="session-1")
            service.add_exchange("user-a", "保持活动的对话", {"summary": "活动回答"}, session_id="session-2")

            archived = service.archive_conversation("user-a", "session-1", True)

            self.assertEqual(archived["project_id"], "assistant")
            self.assertEqual(archived["project_name"], "智能问答")
            self.assertTrue(archived["archived"])
            self.assertTrue(archived["archived_at"])
            self.assertEqual([item["id"] for item in service.list_conversations("user-a")], ["session-2"])
            self.assertEqual(
                [item["id"] for item in service.list_conversations("user-a", archived=True)],
                ["session-1"],
            )

            restored = service.archive_conversation("user-a", "session-1", False)
            self.assertFalse(restored["archived"])
            self.assertEqual(
                {item["id"] for item in service.list_conversations("user-a")},
                {"session-1", "session-2"},
            )

    def test_delete_conversation_removes_only_that_session_and_rebuilds_memory_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange(
                "user-a",
                "记住 deleted-project-alpha",
                {"summary": "仅属于待删除会话的回答"},
                session_id="delete-me",
            )
            service.add_exchange(
                "user-a",
                "记住 retained-project-beta",
                {"summary": "需要保留的回答"},
                session_id="keep-me",
            )

            result = service.delete_conversation("user-a", "delete-me")

            self.assertTrue(result["deleted"])
            self.assertEqual(result["deleted_turn_count"], 1)
            self.assertEqual([item["id"] for item in service.list_conversations("user-a")], ["keep-me"])
            with self.assertRaises(KeyError):
                service.get_conversation("user-a", "delete-me")
            context = service.build_context("user-a", "project")
            self.assertNotIn("deleted-project-alpha", context["summary"])
            self.assertIn("retained-project-beta", context["summary"])

    def test_conversation_lookup_is_strictly_isolated_by_user(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange("user-a", "A 的问题", {"summary": "A 的回答"}, session_id="shared-session")
            service.add_exchange("user-b", "B 的问题", {"summary": "B 的回答"}, session_id="shared-session")

            self.assertEqual(service.get_conversation("user-a", "shared-session")["title"], "A 的问题")
            self.assertEqual(service.get_conversation("user-b", "shared-session")["title"], "B 的问题")
            with self.assertRaises(KeyError):
                service.get_conversation("user-c", "shared-session")

    def test_punctuation_only_question_does_not_inject_recent_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True
            service.add_exchange(
                "user-a",
                "分析 CVE-2026-55576",
                {"summary": "历史漏洞回答", "mode": "vulnerability_lookup"},
            )

            context = service.build_context("user-a", "？")

            self.assertEqual(context["recentHistory"], [])
            self.assertEqual(context["retrievedMemories"], [])
            self.assertEqual(context["injectedMessages"], [])
            self.assertEqual(context["promptContext"], "")

    def test_user_summaries_are_local_and_isolated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.database_url = "postgresql://must-not-be-used"
            service.local_only = True
            service.add_exchange("user-a", "记住我负责支付系统", {"summary": "已记录支付系统偏好", "mode": "security_knowledge"})
            service.add_exchange("user-b", "记住我负责搜索系统", {"summary": "已记录搜索系统偏好", "mode": "security_knowledge"})

            context_a = service.build_context("user-a", "我的系统是什么？")
            context_b = service.build_context("user-b", "我的系统是什么？")

            self.assertEqual(service.backend, "local-json")
            self.assertIn("支付系统", context_a["summary"])
            self.assertNotIn("搜索系统", context_a["summary"])
            self.assertIn("搜索系统", context_b["summary"])

    def test_concurrent_users_do_not_overwrite_each_other(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")
            service.local_only = True

            def write(user_id: str, system: str) -> None:
                service.add_exchange(user_id, f"记住我负责{system}", {"summary": f"已记录{system}", "mode": "security_knowledge"})

            with ThreadPoolExecutor(max_workers=2) as executor:
                list(executor.map(lambda item: write(*item), [("user-a", "支付系统"), ("user-b", "搜索系统")]))

            self.assertEqual(len(service.get_history("user-a")), 1)
            self.assertEqual(len(service.get_history("user-b")), 1)
            self.assertIn("支付系统", service.build_context("user-a", "系统")["summary"])
            self.assertIn("搜索系统", service.build_context("user-b", "系统")["summary"])


if __name__ == "__main__":
    unittest.main()
