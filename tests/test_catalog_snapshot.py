from __future__ import annotations

import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.catalog_snapshot import ComponentCatalogSnapshotStore


class ComponentCatalogSnapshotStoreTests(unittest.TestCase):
    def test_encrypted_snapshot_round_trip_is_content_addressed_and_compact(self) -> None:
        records = [
            {
                "id": f"CVE-2026-{index:05d}",
                "severity": "HIGH",
                "summary": "A repeated vulnerability description that compresses well. " * 10,
                "components": [{"ecosystem": "npm", "name": f"package-{index}"}],
            }
            for index in range(120)
        ]
        fingerprint = "a" * 64
        with TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "catalog-snapshot-test-master-key"},
        ):
            store = ComponentCatalogSnapshotStore(Path(directory), retain=20)
            first_id = store.save(records, result_sha256=fingerprint)
            second_id = store.save(records, result_sha256=fingerprint)
            restored = store.load(first_id, expected_sha256=fingerprint)
            stored_text = (Path(directory) / f"{first_id}.json").read_text(encoding="utf-8")

        self.assertEqual(first_id, second_id)
        self.assertEqual(restored, records)
        self.assertNotIn("CVE-2026-00000", stored_text)
        self.assertLess(len(stored_text.encode("utf-8")), 20_000)

    def test_snapshot_rejects_a_mismatched_result_fingerprint(self) -> None:
        with TemporaryDirectory() as directory, patch.dict(
            os.environ,
            {"SECFLOW_STORAGE_MASTER_KEY": "catalog-snapshot-test-master-key"},
        ):
            store = ComponentCatalogSnapshotStore(Path(directory))
            snapshot_id = store.save([{"id": "CVE-2026-1"}], result_sha256="b" * 64)
            with self.assertRaises(ValueError):
                store.load(snapshot_id, expected_sha256="c" * 64)


if __name__ == "__main__":
    unittest.main()
