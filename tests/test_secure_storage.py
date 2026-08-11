from __future__ import annotations

import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app.intelligence import _VulnerabilityCatalog
from app.memory import LongTermMemoryService
from app.secure_storage import _load_keychain_key
from app.storage import StateStore, default_state
from app.task_store import AgentTaskStore


TEST_MASTER_KEY = "unit-test-secflow-local-storage-key"


class SecureStorageTests(unittest.TestCase):
    def test_keychain_lookup_timeout_falls_back_without_aborting_startup(self) -> None:
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch(
                "app.secure_storage.subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="security", timeout=5),
            ),
        ):
            self.assertIsNone(_load_keychain_key())

    def test_keychain_create_timeout_falls_back_without_aborting_startup(self) -> None:
        lookup_failed = subprocess.CompletedProcess(args=["security"], returncode=44, stdout="", stderr="")
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch(
                "app.secure_storage.subprocess.run",
                side_effect=[lookup_failed, subprocess.TimeoutExpired(cmd="security", timeout=5)],
            ),
        ):
            self.assertIsNone(_load_keychain_key())

    def test_stores_recover_when_ciphertext_uses_an_unavailable_key(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_store = StateStore(root / "state.json")
            memory_store = LongTermMemoryService(root / "memory.json")
            task_store = AgentTaskStore(root / "tasks.json")

            with patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "retired-key"}):
                state_store.write(default_state())
                memory_store.add_exchange("user-a", "question", {"answer": "answer"})
                task_store.create({"id": "task-a", "user_id": "user-a"})

            with patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "replacement-key"}):
                self.assertEqual(state_store.read()["records"][0]["id"], "CVE-2021-44228")
                self.assertEqual(memory_store.get_history("user-a"), [])
                self.assertEqual(task_store.list("user-a"), [])

    def test_state_store_encrypts_file_and_decrypts_internally(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": TEST_MASTER_KEY},
        ):
            path = Path(temp_dir) / "state.json"
            store = StateStore(path)
            state = default_state()
            state["collectors"]["cve"]["api_key"] = "plain-secret-key"
            state["records"][0]["summary"] = "private vulnerability detail"

            store.write(state)

            raw = path.read_text(encoding="utf-8")
            self.assertIn("__secflow_encrypted__", raw)
            self.assertNotIn("plain-secret-key", raw)
            self.assertNotIn("private vulnerability detail", raw)
            self.assertEqual(store.read()["collectors"]["cve"]["api_key"], "plain-secret-key")

    def test_memory_store_encrypts_local_json(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": TEST_MASTER_KEY},
        ):
            service = LongTermMemoryService(Path(temp_dir) / "memory.json")

            service.add_exchange(
                "user-a",
                "查询 CVE-2026-1234",
                {
                    "answer": "内部分析结果",
                    "sources": [{"name": "hidden-source"}],
                    "fields": {"漏洞编号": "CVE-2026-1234"},
                },
            )

            raw = service.state_path.read_text(encoding="utf-8")
            self.assertIn("__secflow_encrypted__", raw)
            self.assertNotIn("hidden-source", raw)
            self.assertNotIn("CVE-2026-1234", raw)
            history = service.get_history("user-a")
            self.assertEqual(history[0]["question"], "查询 CVE-2026-1234")
            self.assertEqual(history[0]["sources"], [])

    def test_vulnerability_catalog_encrypts_record_json_and_hashes_metadata_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": TEST_MASTER_KEY},
        ):
            path = Path(temp_dir) / "catalog.sqlite3"
            catalog = _VulnerabilityCatalog(path)
            catalog.upsert(
                [
                    {
                        "id": "CVE-2026-9999",
                        "title": "Sensitive source backed record",
                        "severity": "HIGH",
                        "summary": "do not store this sentence in plaintext",
                        "aliases": ["GHSA-abcd-efgh-ijkl"],
                        "published_at": "2026-07-17T00:00:00+00:00",
                        "updated_at": "2026-07-17T01:00:00+00:00",
                    }
                ]
            )
            catalog.set_metadata("nvd_feed_2026", "complete")

            with sqlite3.connect(path) as connection:
                row = connection.execute("select record_json from vulnerabilities").fetchone()
                metadata_keys = [item[0] for item in connection.execute("select key from catalog_metadata").fetchall()]

            record_json = str(row[0])
            self.assertIn("__secflow_encrypted__", record_json)
            self.assertNotIn("Sensitive source backed record", record_json)
            self.assertNotIn("do not store this sentence", record_json)
            self.assertNotIn("nvd_feed_2026", metadata_keys)
            self.assertEqual(catalog.metadata("nvd_feed_2026"), "complete")
            self.assertEqual(catalog.snapshot()["records"][0]["id"], "CVE-2026-9999")


if __name__ == "__main__":
    unittest.main()
