"""Append-only, hash-chained audit storage for MCP Host decisions."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict
from pathlib import Path
from threading import RLock
from typing import Any

from app.mcp.runtime import MCPAuditRecord
from app.storage import DATA_DIR


class PersistentMCPAuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (DATA_DIR / "audit" / "mcp.jsonl")
        self._lock = RLock()
        self._last_digest = ""
        self._loaded = False

    def write(self, record: MCPAuditRecord) -> None:
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not self._loaded:
                self._last_digest = self._read_last_digest()
                self._loaded = True
            payload: dict[str, Any] = asdict(record)
            envelope = {
                "schema_version": "secflow.mcp-audit/v1",
                "previous_sha256": self._last_digest,
                "record": payload,
            }
            digest = hashlib.sha256(
                json.dumps(
                    envelope,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ).hexdigest()
            envelope["record_sha256"] = digest
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_APPEND | os.O_CREAT,
                0o600,
            )
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                stream.write(json.dumps(envelope, ensure_ascii=True, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._last_digest = digest

    def _read_last_digest(self) -> str:
        if not self.path.is_file() or self.path.is_symlink():
            return ""
        try:
            last = ""
            with self.path.open("r", encoding="utf-8") as stream:
                for line in stream:
                    if line.strip():
                        last = line
            value = json.loads(last) if last else {}
            digest = str(value.get("record_sha256") or "")
            return digest if len(digest) == 64 else ""
        except (OSError, ValueError, TypeError):
            return ""


persistent_mcp_audit_log = PersistentMCPAuditLog()


__all__ = ["PersistentMCPAuditLog", "persistent_mcp_audit_log"]
