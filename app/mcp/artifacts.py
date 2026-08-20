"""Artifact-reference helpers used inside isolated MCP server processes."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from pydantic import BaseModel


class MCPArtifactReference(BaseModel):
    path: str
    media_type: str
    sha256: str


def stage_output_artifact(
    output_dir: str,
    *,
    file_name: str,
    payload: bytes,
    media_type: str,
) -> MCPArtifactReference:
    """Write one result beneath the exact Host-provided scratch directory."""

    supplied_root = Path(str(output_dir or ""))
    if supplied_root.is_symlink():
        raise ValueError("MCP output_dir must not be a symlink")
    root = supplied_root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError("MCP output_dir must be an existing non-symlink directory")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", Path(file_name).name).strip("-.")
    if not safe_name:
        safe_name = "artifact.bin"
    target = root / safe_name
    if target.parent.is_symlink() or target.parent.resolve(strict=True) != root:
        raise ValueError("MCP artifact path escaped output_dir")
    descriptor = os.open(
        target,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return MCPArtifactReference(
        path=safe_name,
        media_type=str(media_type or "application/octet-stream"),
        sha256=hashlib.sha256(payload).hexdigest(),
    )


__all__ = ["MCPArtifactReference", "stage_output_artifact"]
