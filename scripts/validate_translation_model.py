#!/usr/bin/env python3
"""Validate the identity and file integrity of the bundled translation model."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any


MODEL_ID = "opus-mt-en-zh-1.9"
ARCHIVE_SHA256 = "433e7c4f034d87fbe2353161e05f18646d7999452f801a4e1f0378522b9850ab"
CORE_FILES = {
    "model/model.bin": "1a039114d9456b6528fabb65b455b6f156319634a0f984b1f6018f7737d67598",
    "model/config.json": "3a8660f12559a223969532ff191e5e6f50d4ff24164517edbd6a5090dc5144c6",
    "model/shared_vocabulary.json": "c0b6e24705ec0489d5b810de365959c1013aecd644cfeca161b54ea1df6a7dc0",
    "sentencepiece.model": "872224b85a11edc9d769a94949fd387b67ea85b50708db9f91f32f5b497a9af3",
}
REQUIRED_ROLES = {
    "ctranslate2-model",
    "ctranslate2-config",
    "shared-vocabulary",
    "sentencepiece-model",
    "upstream-metadata",
    "upstream-attribution",
    "license",
    "documentation",
}


class ModelValidationError(ValueError):
    """Raised when the translation model bundle is incomplete or modified."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ModelValidationError(f"{label} must be an object")
    return value


def validate_model_bundle(model_dir: str | Path) -> dict[str, Any]:
    root = Path(model_dir)
    if not root.is_dir() or root.is_symlink():
        raise ModelValidationError(f"model directory is missing or unsafe: {root}")

    manifest_path = root / "manifest.json"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise ModelValidationError(f"model manifest is missing or unsafe: {manifest_path}")
    try:
        manifest = _require_mapping(
            json.loads(manifest_path.read_text(encoding="utf-8")), "manifest"
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ModelValidationError(f"unable to read model manifest: {exc}") from exc

    if manifest.get("schema_version") != 1 or manifest.get("model_id") != MODEL_ID:
        raise ModelValidationError("unexpected translation model manifest identity")
    engine = _require_mapping(manifest.get("engine"), "engine")
    tokenizer = _require_mapping(manifest.get("tokenizer"), "tokenizer")
    languages = _require_mapping(manifest.get("languages"), "languages")
    upstream = _require_mapping(manifest.get("upstream"), "upstream")
    if engine != {"name": "CTranslate2", "version": "4.8.1"}:
        raise ModelValidationError("unexpected translation engine version")
    if tokenizer != {"name": "SentencePiece", "version": "0.2.2"}:
        raise ModelValidationError("unexpected tokenizer version")
    if languages != {"source": "en", "target": "zh-Hans"}:
        raise ModelValidationError("unexpected translation language pair")
    if upstream.get("archive_sha256") != ARCHIVE_SHA256:
        raise ModelValidationError("unexpected upstream translation archive digest")
    if upstream.get("license") != "CC-BY-4.0":
        raise ModelValidationError("unexpected translation model license")

    file_entries = manifest.get("files")
    if not isinstance(file_entries, list) or not file_entries:
        raise ModelValidationError("manifest files must be a non-empty array")
    seen_paths: set[str] = set()
    seen_roles: set[str] = set()
    total_size = 0
    root_resolved = root.resolve(strict=True)
    for index, raw_entry in enumerate(file_entries):
        entry = _require_mapping(raw_entry, f"files[{index}]")
        relative = entry.get("path")
        expected_hash = entry.get("sha256")
        expected_size = entry.get("size")
        role = entry.get("role")
        if not isinstance(relative, str) or "\\" in relative:
            raise ModelValidationError(f"files[{index}].path must use safe POSIX syntax")
        pure_path = PurePosixPath(relative)
        if pure_path.is_absolute() or not pure_path.parts or ".." in pure_path.parts:
            raise ModelValidationError(f"unsafe model file path: {relative!r}")
        if relative in seen_paths:
            raise ModelValidationError(f"duplicate model file path: {relative}")
        if not isinstance(expected_hash, str) or len(expected_hash) != 64:
            raise ModelValidationError(f"invalid SHA-256 for {relative}")
        if not isinstance(expected_size, int) or expected_size < 1:
            raise ModelValidationError(f"invalid size for {relative}")
        if not isinstance(role, str) or not role:
            raise ModelValidationError(f"invalid role for {relative}")

        target = root.joinpath(*pure_path.parts)
        if not target.is_file() or target.is_symlink():
            raise ModelValidationError(f"model file is missing or unsafe: {relative}")
        target_resolved = target.resolve(strict=True)
        if root_resolved not in target_resolved.parents:
            raise ModelValidationError(f"model file escapes bundle root: {relative}")
        actual_size = target.stat().st_size
        if actual_size != expected_size:
            raise ModelValidationError(
                f"size mismatch for {relative}: expected {expected_size}, got {actual_size}"
            )
        actual_hash = _sha256(target)
        if actual_hash != expected_hash.lower():
            raise ModelValidationError(f"SHA-256 mismatch for {relative}")
        known_core_hash = CORE_FILES.get(relative)
        if known_core_hash is not None and actual_hash != known_core_hash:
            raise ModelValidationError(f"unrecognized upstream core file: {relative}")
        seen_paths.add(relative)
        seen_roles.add(role)
        total_size += actual_size

    missing_core = set(CORE_FILES) - seen_paths
    if missing_core:
        raise ModelValidationError(
            f"manifest omits required core files: {', '.join(sorted(missing_core))}"
        )
    missing_roles = REQUIRED_ROLES - seen_roles
    if missing_roles:
        raise ModelValidationError(
            f"manifest omits required file roles: {', '.join(sorted(missing_roles))}"
        )

    disk_files = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "manifest.json"
    }
    unlisted = disk_files - seen_paths
    if unlisted:
        raise ModelValidationError(
            f"bundle contains unlisted files: {', '.join(sorted(unlisted))}"
        )
    return {
        "model_id": MODEL_ID,
        "files": len(seen_paths),
        "bytes": total_size,
        "sha256_verified": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_dir", type=Path, help="directory containing manifest.json")
    args = parser.parse_args()
    try:
        result = validate_model_bundle(args.model_dir)
    except ModelValidationError as exc:
        parser.exit(1, f"translation model validation failed: {exc}\n")
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
