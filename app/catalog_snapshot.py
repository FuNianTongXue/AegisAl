from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from threading import RLock
from typing import Any

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


_SNAPSHOT_ID = re.compile(r"^component-catalog-snapshot-[a-f0-9]{32}$")
_SNAPSHOT_PURPOSE_PREFIX = "secflow-component-catalog-snapshot"


class ComponentCatalogSnapshotStore:
    """Encrypted, compressed storage for fixed catalog export rows.

    LangGraph checkpoints are intentionally small and frequently rewritten.
    Keeping thousands of vulnerability rows in a graph state duplicates the
    same payload at every node and makes the SQLite checkpoint file grow by
    tens of megabytes per click.  This store keeps one content-addressed copy;
    the graph persists only its identifier plus the eight-row UI preview.
    """

    def __init__(self, root: Path | None = None, *, retain: int = 200) -> None:
        self.root = root or (DATA_DIR / "component_catalog_snapshots")
        self.retain = max(20, min(int(retain), 1000))
        self._lock = RLock()

    def save(self, records: list[dict[str, Any]], *, result_sha256: str = "") -> str:
        clean_records = [dict(record) for record in records if isinstance(record, dict)]
        fingerprint = str(result_sha256 or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            encoded_records = json.dumps(
                clean_records,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            fingerprint = hashlib.sha256(encoded_records).hexdigest()
        snapshot_id = f"component-catalog-snapshot-{fingerprint[:32]}"
        payload = {
            "schema_version": 1,
            "result_sha256": fingerprint,
            "created_at": now_iso(),
            "records": clean_records,
        }
        encoded = encrypt_json_to_text(payload, self._purpose(snapshot_id), compact=True)
        path = self._path(snapshot_id)
        temporary = self.root / f".{snapshot_id}.tmp"
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True)
            self.root.chmod(0o700)
            temporary.write_text(encoded, encoding="utf-8")
            temporary.chmod(0o600)
            temporary.replace(path)
            self._prune(protected=snapshot_id)
        return snapshot_id

    def load(self, snapshot_id: str, *, expected_sha256: str = "") -> list[dict[str, Any]]:
        clean_id = self._validate_id(snapshot_id)
        path = self._path(clean_id)
        with self._lock:
            if not path.is_file() or path.parent.resolve() != self.root.resolve():
                raise KeyError(clean_id)
            payload = decrypt_json_from_text(path.read_text(encoding="utf-8"), self._purpose(clean_id))
        if not isinstance(payload, dict) or int(payload.get("schema_version") or 0) != 1:
            raise ValueError("组件漏洞固定结果快照格式无效")
        actual_sha256 = str(payload.get("result_sha256") or "").strip().lower()
        expected = str(expected_sha256 or "").strip().lower()
        if expected and actual_sha256 != expected:
            raise ValueError("组件漏洞固定结果快照指纹不匹配")
        return [dict(record) for record in payload.get("records") or [] if isinstance(record, dict)]

    def _path(self, snapshot_id: str) -> Path:
        return self.root / f"{self._validate_id(snapshot_id)}.json"

    @staticmethod
    def _validate_id(snapshot_id: str) -> str:
        clean_id = str(snapshot_id or "").strip()
        if not _SNAPSHOT_ID.fullmatch(clean_id):
            raise KeyError(clean_id)
        return clean_id

    @staticmethod
    def _purpose(snapshot_id: str) -> str:
        return f"{_SNAPSHOT_PURPOSE_PREFIX}:{snapshot_id}"

    def _prune(self, *, protected: str) -> None:
        files = sorted(
            (path for path in self.root.glob("component-catalog-snapshot-*.json") if path.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        stale = [path for path in files if path.stem != protected][self.retain - 1 :]
        for path in stale:
            path.unlink(missing_ok=True)


component_catalog_snapshot_store = ComponentCatalogSnapshotStore()
