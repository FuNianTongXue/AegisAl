"""Host-owned stores for downloadable assistant artifacts.

MCP processes may create files only in Host-provided scratch directories.  The
Host verifies and imports those files before this module publishes a copy to
the authenticated assistant download API.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from threading import RLock
from typing import Any, Literal
from urllib.parse import urlencode
from uuid import uuid4

from pydantic import BaseModel, Field

from app.secure_storage import decrypt_json_from_text, encrypt_json_to_text
from app.storage import DATA_DIR, now_iso


XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


class AssistantArtifact(BaseModel):
    id: str = ""
    kind: Literal["excel"] = "excel"
    file_name: str
    media_type: str = XLSX_MEDIA_TYPE
    download_path: str = ""
    sha256: str
    size: int
    generated_at: str
    artifacts: list[dict[str, Any]] = Field(default_factory=list)


class WorkbookArtifactStore:
    def __init__(
        self,
        root: Path | None = None,
        *,
        artifact_prefix: str,
        default_name: str,
        retain: int = 100,
    ) -> None:
        self.root = root or (DATA_DIR / "assistant_artifacts")
        self.artifact_prefix = artifact_prefix
        self.default_name = default_name
        self.retain = max(10, min(int(retain), 500))
        self.index_path = self.root / f".{artifact_prefix}-index.enc"
        self._index_purpose = f"secflow-assistant-artifacts:{artifact_prefix}"
        self._id_pattern = re.compile(rf"^{re.escape(artifact_prefix)}-[a-f0-9]{{32}}$")
        self._lock = RLock()

    def save(
        self,
        content: bytes,
        *,
        file_name: str,
        generated_at: str,
        user_id: str = "default",
        session_id: str = "",
        task_id: str = "",
    ) -> AssistantArtifact:
        if not content.startswith(b"PK\x03\x04"):
            raise ValueError("MCP did not produce a valid XLSX workbook")
        owner = str(user_id or "").strip()
        if not owner:
            raise ValueError("Artifact owner user_id is required")
        digest = hashlib.sha256(content).hexdigest()
        artifact_id = f"{self.artifact_prefix}-{uuid4().hex}"
        safe_name = _safe_excel_name(file_name, self.default_name)
        path = self.root / f"{artifact_id}.xlsx"
        temporary = self.root / f".{artifact_id}.{uuid4().hex}.tmp"
        item = {
            "id": artifact_id,
            "user_id": owner,
            "session_id": str(session_id or ""),
            "task_id": str(task_id or ""),
            "file_name": safe_name,
            "media_type": XLSX_MEDIA_TYPE,
            "sha256": digest,
            "size": len(content),
            "generated_at": str(generated_at or now_iso()),
            "storage_name": path.name,
        }
        with self._lock:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                self.root.chmod(0o700)
            except OSError:
                pass
            try:
                descriptor = os.open(
                    temporary,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
            index = self._read_index()
            index.append(item)
            self._write_index(index)
        return AssistantArtifact(
            id=artifact_id,
            file_name=safe_name,
            download_path=f"/api/assistant/artifacts/{artifact_id}?{urlencode({'user_id': owner})}",
            sha256=digest,
            size=len(content),
            generated_at=generated_at,
        )

    def resolve(self, artifact_id: str, *, user_id: str = "default") -> Path:
        clean_id = str(artifact_id or "").strip()
        if not self._id_pattern.fullmatch(clean_id):
            raise KeyError(artifact_id)
        owner = str(user_id or "").strip()
        with self._lock:
            item = next(
                (
                    entry
                    for entry in self._read_index()
                    if entry.get("id") == clean_id and entry.get("user_id") == owner
                ),
                None,
            )
            if item is None:
                raise KeyError(artifact_id)
            path = self.root / Path(str(item.get("storage_name") or "")).name
            if (
                not path.is_file()
                or path.is_symlink()
                or path.parent.resolve() != self.root.resolve()
                or path.stat().st_nlink != 1
            ):
                raise KeyError(artifact_id)
            return path

    def metadata(self, artifact_id: str, *, user_id: str = "default") -> dict[str, Any]:
        clean_id = str(artifact_id or "").strip()
        owner = str(user_id or "").strip()
        with self._lock:
            item = next(
                (
                    dict(entry)
                    for entry in self._read_index()
                    if entry.get("id") == clean_id and entry.get("user_id") == owner
                ),
                None,
            )
        if item is None:
            raise KeyError(artifact_id)
        return item

    def _read_index(self) -> list[dict[str, Any]]:
        if not self.index_path.is_file():
            return []
        try:
            value = decrypt_json_from_text(
                self.index_path.read_text(encoding="utf-8"),
                self._index_purpose,
            )
        except Exception:  # noqa: BLE001 - fail closed on corrupt metadata.
            return []
        return [dict(item) for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _write_index(self, index: list[dict[str, Any]]) -> None:
        temporary = self.index_path.with_name(f"{self.index_path.name}.{uuid4().hex}.tmp")
        temporary.write_text(
            encrypt_json_to_text(index, self._index_purpose, compact=True),
            encoding="utf-8",
        )
        temporary.chmod(0o600)
        os.replace(temporary, self.index_path)


class ComponentArtifactStore(WorkbookArtifactStore):
    def __init__(self, root: Path | None = None, *, retain: int = 100) -> None:
        super().__init__(
            root,
            artifact_prefix="component-xlsx",
            default_name="component-vulnerabilities.xlsx",
            retain=retain,
        )


class SBOMArtifactStore(WorkbookArtifactStore):
    def __init__(self, root: Path | None = None, *, retain: int = 100) -> None:
        super().__init__(
            root,
            artifact_prefix="sbom-xlsx",
            default_name="SecFlow-project-SBOM.xlsx",
            retain=retain,
        )


def _safe_excel_name(value: str, default_name: str) -> str:
    name = Path(str(value or default_name)).name
    clean = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(name).stem).strip("-.")
    return f"{(clean or Path(default_name).stem)[:180]}.xlsx"


component_artifact_store = ComponentArtifactStore()
sbom_artifact_store = SBOMArtifactStore()


__all__ = [
    "AssistantArtifact",
    "ComponentArtifactStore",
    "SBOMArtifactStore",
    "WorkbookArtifactStore",
    "XLSX_MEDIA_TYPE",
    "component_artifact_store",
    "sbom_artifact_store",
]
