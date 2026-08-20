from __future__ import annotations

import json
from pathlib import Path

from scripts.validate_translation_model import (
    ARCHIVE_SHA256,
    CORE_FILES,
    validate_model_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "app" / "resources" / "translation-models" / "opus-mt-en-zh-1.9"


def test_bundled_translation_model_manifest_and_hashes() -> None:
    result = validate_model_bundle(MODEL_DIR)

    assert result["model_id"] == "opus-mt-en-zh-1.9"
    assert result["sha256_verified"] is True
    assert result["bytes"] > 80_000_000


def test_translation_model_manifest_is_offline_inference_only() -> None:
    manifest = json.loads((MODEL_DIR / "manifest.json").read_text(encoding="utf-8"))
    listed_paths = {entry["path"] for entry in manifest["files"]}

    assert manifest["upstream"]["archive_sha256"] == ARCHIVE_SHA256
    assert set(CORE_FILES).issubset(listed_paths)
    assert not (MODEL_DIR / "stanza").exists()
    assert manifest["runtime_policy"] == {
        "network_access": False,
        "requires_api_key": False,
        "uses_llm_tokens": False,
    }
