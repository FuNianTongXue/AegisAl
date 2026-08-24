from __future__ import annotations

import base64
import os
import sqlite3
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from app.intelligence import _VulnerabilityCatalog
from app.memory import LongTermMemoryService
from app import secure_storage
from app.secure_storage import _load_keychain_key, decrypt_json_from_text, encrypt_json_to_text
from app.storage import StateStore, default_state
from app.task_store import AgentTaskStore


TEST_MASTER_KEY = "unit-test-secflow-local-storage-key"


class SecureStorageTests(unittest.TestCase):
    def test_keychain_lookup_timeout_falls_back_without_aborting_startup(self) -> None:
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch.dict(os.environ, {"SECFLOW_DISABLE_KEYCHAIN": ""}),
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
            patch.dict(os.environ, {"SECFLOW_DISABLE_KEYCHAIN": ""}),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch(
                "app.secure_storage.subprocess.run",
                side_effect=[lookup_failed, subprocess.TimeoutExpired(cmd="security", timeout=5)],
            ),
        ):
            self.assertIsNone(_load_keychain_key())

    def test_keychain_transient_lookup_failure_never_overwrites_the_item(self) -> None:
        lookup_denied = subprocess.CompletedProcess(
            args=["security"],
            returncode=36,
            stdout="",
            stderr="User interaction is not allowed.",
        )
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch.dict(os.environ, {"SECFLOW_DISABLE_KEYCHAIN": ""}),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch("app.secure_storage.subprocess.run", return_value=lookup_denied) as run,
        ):
            self.assertIsNone(_load_keychain_key())

        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][1], "find-generic-password")

    def test_concurrent_keychain_creator_adopts_the_first_persisted_key(self) -> None:
        winner = b"w" * 32
        encoded_winner = base64.b64encode(winner).decode("ascii")
        lookup_missing = subprocess.CompletedProcess(
            args=["security"], returncode=44, stdout="", stderr="item could not be found"
        )
        duplicate_create = subprocess.CompletedProcess(
            args=["security"], returncode=45, stdout="", stderr="item already exists"
        )
        winner_lookup = subprocess.CompletedProcess(
            args=["security"], returncode=0, stdout=f"{encoded_winner}\n", stderr=""
        )
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch.dict(os.environ, {"SECFLOW_DISABLE_KEYCHAIN": ""}),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch(
                "app.secure_storage.subprocess.run",
                side_effect=[lookup_missing, duplicate_create, winner_lookup],
            ) as run,
        ):
            self.assertEqual(_load_keychain_key(), winner)

        create_command = run.call_args_list[1].args[0]
        self.assertEqual(create_command[1], "add-generic-password")
        self.assertNotIn("-U", create_command)

    def test_missing_keychain_item_reuses_existing_file_key(self) -> None:
        file_key = b"d" * 32
        lookup_missing = subprocess.CompletedProcess(
            args=["security"], returncode=44, stdout="", stderr="item could not be found"
        )
        created = subprocess.CompletedProcess(args=["security"], returncode=0, stdout="", stderr="")
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(
                os.environ,
                {"SECFLOW_DATA_DIR": temp_dir, "SECFLOW_DISABLE_KEYCHAIN": ""},
            ),
            patch("app.secure_storage.sys.platform", "darwin"),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch("app.secure_storage._load_existing_file_key", return_value=file_key),
            patch(
                "app.secure_storage.subprocess.run",
                side_effect=[lookup_missing, created],
            ) as run,
        ):
            self.assertEqual(_load_keychain_key(), file_key)

        create_command = run.call_args_list[1].args[0]
        self.assertEqual(
            create_command[create_command.index("-w") + 1],
            base64.b64encode(file_key).decode("ascii"),
        )

    def test_runtime_key_cache_is_isolated_by_keychain_service(self) -> None:
        production_key = b"p" * 32
        trial_key = b"t" * 32
        with (
            patch.dict(
                os.environ,
                {
                    "SECFLOW_STORAGE_MASTER_KEY": "",
                    "SECFLOW_DATA_DIR": "/tmp/secflow-shared-data",
                    "SECFLOW_KEYCHAIN_SERVICE": "secflow.production",
                },
            ),
            patch.object(secure_storage, "_MASTER_KEY_CACHE", None),
            patch.object(secure_storage, "_MASTER_KEY_CACHE_SOURCE", ""),
            patch(
                "app.secure_storage._load_keychain_key",
                side_effect=[production_key, trial_key],
            ) as load_keychain,
        ):
            self.assertEqual(secure_storage._master_key(), production_key)
            os.environ["SECFLOW_KEYCHAIN_SERVICE"] = "secflow.trial"
            self.assertEqual(secure_storage._master_key(), trial_key)

        self.assertEqual(load_keychain.call_count, 2)

    def test_file_key_creation_adopts_a_concurrent_winner(self) -> None:
        winner = b"f" * 32
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            patch.dict(os.environ, {"SECFLOW_DATA_DIR": temp_dir}),
            patch(
                "app.secure_storage._load_existing_file_key",
                side_effect=[None, winner],
            ),
            patch("app.secure_storage.os.open", side_effect=FileExistsError),
        ):
            self.assertEqual(secure_storage._load_or_create_file_key(), winner)

    def test_invalid_existing_file_key_is_not_silently_replaced(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"SECFLOW_DATA_DIR": temp_dir}
        ):
            key_path = Path(temp_dir) / ".secflow-local-storage.key"
            key_path.write_text("", encoding="utf-8")

            with self.assertRaises(OSError):
                secure_storage._load_or_create_file_key()

            self.assertEqual(key_path.read_text(encoding="utf-8"), "")

    def test_legacy_text_keychain_and_file_values_remain_readable(self) -> None:
        legacy_value = "legacy-secflow-storage-passphrase"
        keychain_result = subprocess.CompletedProcess(
            args=["security"], returncode=0, stdout=f"{legacy_value}\n", stderr=""
        )
        with (
            patch("app.secure_storage.sys.platform", "darwin"),
            patch.dict(os.environ, {"SECFLOW_DISABLE_KEYCHAIN": ""}),
            patch("app.secure_storage.Path.exists", return_value=True),
            patch("app.secure_storage.subprocess.run", return_value=keychain_result),
        ):
            self.assertEqual(_load_keychain_key(), secure_storage._decode_or_derive_key(legacy_value))

        with tempfile.TemporaryDirectory() as temp_dir, patch.dict(
            os.environ, {"SECFLOW_DATA_DIR": temp_dir}
        ):
            key_path = Path(temp_dir) / ".secflow-local-storage.key"
            key_path.write_text(legacy_value, encoding="utf-8")
            self.assertEqual(
                secure_storage._load_existing_file_key(),
                secure_storage._decode_or_derive_key(legacy_value),
            )

    def test_state_store_preserves_ciphertext_until_the_original_key_is_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            state_store = StateStore(root / "state.json")
            memory_store = LongTermMemoryService(root / "memory.json")
            task_store = AgentTaskStore(root / "tasks.json")

            with patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "retired-key"}):
                state_store.write(default_state())
                memory_store.add_exchange("user-a", "question", {"answer": "answer"})
                task_store.create({"id": "task-a", "user_id": "user-a"})
                encrypted_state = state_store.path.read_bytes()

            with patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "replacement-key"}):
                with self.assertRaises(InvalidTag):
                    state_store.read()
                self.assertEqual(state_store.path.read_bytes(), encrypted_state)
                self.assertEqual(memory_store.get_history("user-a"), [])
                self.assertEqual(task_store.list("user-a"), [])

            with patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": "retired-key"}):
                recovered = state_store.read()

            self.assertEqual(recovered["records"][0]["id"], "CVE-2021-44228")
            self.assertEqual(state_store.path.read_bytes(), encrypted_state)

    def test_state_store_does_not_replace_an_unreadable_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            state_store = StateStore(Path(temp_dir) / "state.json")
            unreadable_state = b'{"__secflow_encrypted__":true'
            state_store.path.write_bytes(unreadable_state)

            with self.assertRaises(ValueError):
                state_store.read()

            self.assertEqual(state_store.path.read_bytes(), unreadable_state)

    def test_decryption_retries_an_existing_keychain_key_after_a_cached_fallback_key(self) -> None:
        keychain_key = b"k" * 32
        fallback_key = b"f" * 32
        with patch("app.secure_storage._master_key", return_value=keychain_key):
            encrypted = encrypt_json_to_text({"api_key": "third-party-key"}, "settings-test")

        with (
            patch.dict(os.environ, {"SECFLOW_STORAGE_MASTER_KEY": ""}),
            patch.object(secure_storage, "_MASTER_KEY_CACHE", fallback_key),
            patch.object(secure_storage, "_MASTER_KEY_CACHE_SOURCE", "runtime"),
            patch("app.secure_storage._load_keychain_key", return_value=keychain_key),
            patch("app.secure_storage._load_existing_file_key", return_value=fallback_key),
        ):
            decrypted = decrypt_json_from_text(encrypted, "settings-test")
            self.assertEqual(secure_storage._MASTER_KEY_CACHE, keychain_key)

        self.assertEqual(decrypted, {"api_key": "third-party-key"})

    def test_successful_cached_decryption_does_not_query_recovery_key_providers(self) -> None:
        master_key = b"m" * 32
        with patch("app.secure_storage._master_key", return_value=master_key):
            encrypted = encrypt_json_to_text({"configured": True}, "settings-test")

        with (
            patch("app.secure_storage._master_key", return_value=master_key),
            patch("app.secure_storage._load_keychain_key") as load_keychain_key,
            patch("app.secure_storage._load_existing_file_key") as load_file_key,
        ):
            decrypted = decrypt_json_from_text(encrypted, "settings-test")

        self.assertEqual(decrypted, {"configured": True})
        load_keychain_key.assert_not_called()
        load_file_key.assert_not_called()

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
